# -*- coding: utf-8 -*-
import os, logging, sqlite3, threading, time, hashlib, hmac, re, secrets, json, math, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for, make_response
from flask_socketio import SocketIO
from werkzeug.serving import WSGIRequestHandler
from werkzeug.security import check_password_hash, generate_password_hash
from config import HOST, PORT, DEBUG, SECRET_KEY, CPU_THRESHOLD, MEM_THRESHOLD, DISK_THRESHOLD, load_aes_key, DEFAULT_ADMIN_PASSWORD, REPORT_DIR, security_config_warnings, QUEUE_WORKERS, QUEUE_RETRY_DELAY, SERVICE_REVEAL_ROLES
from models import init_db, list_groups, add_group, delete_group, list_servers, add_server, get_server, update_server, delete_server, get_server_hardware, list_server_hardware_snapshots, save_server_hardware, mark_server_hardware_check, delete_server_hardware, add_inspection_task, list_inspection_tasks, get_inspection_task, update_inspection_task, delete_inspection_task, toggle_task_schedule, update_task_last_run, migrate_inspection_tasks_schema, add_user, get_user, list_users, delete_user, update_user, create_inspection_run, claim_next_inspection_run, recover_interrupted_inspection_runs, update_inspection_run_progress, finish_inspection_run, retry_or_fail_inspection_run, get_inspection_run, list_inspection_runs, clear_inspection_results, add_inspection_result, list_service_systems, add_service_system, delete_service_system, list_service_environments, add_service_environment, delete_service_environment, list_services, get_service, add_service, update_service, delete_service, get_service_accounts, count_services_by_server, record_audit, list_audit_logs, list_operation_audits, list_conversation_audits, get_disk_baselines, save_disk_snapshot, prune_disk_snapshots, list_ai_providers, get_ai_provider, get_ai_provider_by_name, add_ai_provider, update_ai_provider, set_default_ai_provider, update_ai_provider_test, delete_ai_provider, list_ai_conversations, get_ai_conversation, add_ai_conversation, rename_ai_conversation, delete_ai_conversation, list_ai_messages, list_ai_actions, ai_usage_summary, ai_usage_today, list_ai_insights, get_ai_insight
from crypto_utils import aes_gcm_encrypt, aes_gcm_decrypt
from inspection import inspect_server, parse_private_key, test_proxy, create_ssh_client, connect_ssh, run_cmd
from disk_audit import compare_disk, split_findings
from report_excel import generate_excel_report
from captcha_utils import generate_captcha, generate_captcha_image
import ai_service
import ai_tools
import ai_client
import ai_codex_tools
import config
import models
import service_discovery
import resource_audit
from resource_history_excel import build_resource_history_excel
from asset_export_excel import (
    SERVER_EXPORT_FIELDS, SERVICE_EXPORT_FIELDS,
    select_export_fields, build_asset_export_excel,
)

# ---------------- Logging ----------------
from config import LOG_DIR
_log_handlers = [logging.StreamHandler()]
try:
    os.makedirs(LOG_DIR, exist_ok=True)
    _log_handlers.insert(
        0, logging.FileHandler(os.path.join(LOG_DIR, "app.log"), encoding="utf-8")
    )
except OSError as exc:
    print(
        f"WARNING: 无法写入日志目录 {LOG_DIR}，本次仅输出到容器标准输出: {exc}",
        file=sys.stderr,
    )
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=_log_handlers,
)
logger = logging.getLogger("ops-app")

# ---------------- Flask/SIO ----------------
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['JSON_AS_ASCII'] = False
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
SESSION_IDLE_SECONDS = 2 * 60 * 60
socketio = SocketIO(app, async_mode="threading")


class VersionlessWSGIRequestHandler(WSGIRequestHandler):
    server_version = os.environ.get("OPS_SERVER_BANNER", "ops-inspection")
    sys_version = ""

    def version_string(self):
        return self.server_version

LOGIN_MAX_FAILURES = 5
LOGIN_FAILURE_WINDOW = 15 * 60
_login_failures = {}
_login_failures_lock = threading.Lock()

# 可视化大屏服务器在线状态（仅保存在内存中，不暴露认证信息）
def _read_positive_int_env(name, default):
    try:
        return max(1, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        logger.warning("%s 配置无效，使用默认值 %s", name, default)
        return default


SERVER_HEALTH_INTERVAL = _read_positive_int_env("OPS_SERVER_HEALTH_INTERVAL", 10 * 60)
SERVER_OFFLINE_AFTER = max(
    _read_positive_int_env("OPS_SERVER_OFFLINE_AFTER", SERVER_HEALTH_INTERVAL * 2),
    SERVER_HEALTH_INTERVAL + 30,
)
# 服务器完整信息（硬件参数）记录策略：首次采集后只保留最近一次参数，
# 后台按周期核对，只有参数真的变化（增减）时才覆盖记录。
SERVER_HARDWARE_INTERVAL = _read_positive_int_env("OPS_SERVER_HARDWARE_INTERVAL", 12 * 60 * 60)
SERVER_HARDWARE_RETRY_INTERVAL = _read_positive_int_env(
    "OPS_SERVER_HARDWARE_RETRY_INTERVAL", SERVER_HEALTH_INTERVAL
)
SERVER_HARDWARE_POLL_INTERVAL = 60
_server_hardware_thread = None
_server_hardware_thread_lock = threading.Lock()

_server_health = {}
_server_health_lock = threading.Lock()
_server_health_thread = None
_server_health_thread_lock = threading.Lock()

# 角色定义
ROLES = {
    'admin': '超级管理员',
    'operator': '系统操作员',
    'viewer': '报告查看员'
}

class CurrentUser:
    """当前用户上下文"""
    def __init__(self):
        self.username = '未登录'
        self.display_name = None
        self.role = 'viewer'
        self.role_text = '报告查看员'
        self.is_authenticated = False
    
    def from_session(self):
        """从session加载用户信息"""
        if 'username' in session and 'role' in session:
            self.username = session['username']
            self.role = session['role']
            self.role_text = ROLES.get(self.role, self.role)
            self.is_authenticated = True
            
            try:
                user_info = get_user(self.username)
                if user_info:
                    self.display_name = user_info.get('display_name')
            except Exception as e:
                logger.error(f'获取用户信息失败: {str(e)}')
        return self

def hash_password(password):
    """使用带盐、抗暴力破解的 scrypt 保存密码。"""
    return generate_password_hash(password, method='scrypt')


def verify_password(stored_hash, password):
    """兼容旧 SHA-256 密码；成功登录后自动升级。"""
    if re.fullmatch(r'[0-9a-f]{64}', stored_hash or ''):
        legacy = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return hmac.compare_digest(stored_hash, legacy), True
    try:
        return check_password_hash(stored_hash, password), False
    except (TypeError, ValueError):
        return False, False


def validate_password_strength(password):
    return (
        len(password) >= 8
        and any(c.islower() for c in password)
        and any(c.isupper() for c in password)
        and any(c.isdigit() for c in password)
    )


def is_safe_display_text(value, max_length=200):
    return len(value or '') <= max_length and not re.search(r'[<>&\x00-\x1f]', value or '')


def is_valid_host(value):
    return bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:-]{0,252}', value or ''))


def is_safe_tech_text(value, max_length=200):
    """路径、命令、端口等技术文本：允许 shell 元字符，仅拒绝控制字符。

    启停命令必然包含 `&&`、`2>&1`、`>` 等字符，因此这里不能用 is_safe_display_text。
    这些字段只做记录与展示，后端永不执行；安全性由"渲染时转义 + 后端不执行"保证，
    不依赖输入过滤。
    """
    return len(value or '') <= max_length and not re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', value or '')


def _login_failure_key(username):
    return request.remote_addr or 'unknown', (username or '').lower()


def _is_login_locked(username):
    key = _login_failure_key(username)
    cutoff = time.time() - LOGIN_FAILURE_WINDOW
    with _login_failures_lock:
        recent = [stamp for stamp in _login_failures.get(key, []) if stamp >= cutoff]
        _login_failures[key] = recent
        return len(recent) >= LOGIN_MAX_FAILURES


def _record_login_failure(username):
    key = _login_failure_key(username)
    with _login_failures_lock:
        _login_failures.setdefault(key, []).append(time.time())


def _clear_login_failures(username):
    with _login_failures_lock:
        _login_failures.pop(_login_failure_key(username), None)


# 敏感凭据二次验证：独立于登录失败计数，避免两者互相影响。
REVEAL_MAX_FAILURES = 5
REVEAL_FAILURE_WINDOW = 15 * 60
REVEAL_HIDE_SECONDS = 60
_reveal_failures = {}
_reveal_failures_lock = threading.Lock()


def _reveal_failure_key():
    return request.remote_addr or 'unknown', (session.get('username') or '').lower()


def _is_reveal_locked():
    key = _reveal_failure_key()
    cutoff = time.time() - REVEAL_FAILURE_WINDOW
    with _reveal_failures_lock:
        recent = [stamp for stamp in _reveal_failures.get(key, []) if stamp >= cutoff]
        _reveal_failures[key] = recent
        return len(recent) >= REVEAL_MAX_FAILURES


def _record_reveal_failure():
    key = _reveal_failure_key()
    with _reveal_failures_lock:
        _reveal_failures.setdefault(key, []).append(time.time())


def _clear_reveal_failures():
    with _reveal_failures_lock:
        _reveal_failures.pop(_reveal_failure_key(), None)


def safe_report_path(path_or_name):
    """只允许访问报告目录中的 PDF/XLSX 文件。"""
    if not path_or_name:
        return None
    candidate = path_or_name if os.path.isabs(path_or_name) else os.path.join(REPORT_DIR, path_or_name)
    candidate = os.path.realpath(candidate)
    report_root = os.path.realpath(REPORT_DIR)
    try:
        if os.path.commonpath([candidate, report_root]) != report_root:
            return None
    except ValueError:
        return None
    if os.path.splitext(candidate)[1].lower() not in {'.pdf', '.xlsx'}:
        return None
    return candidate

def init_default_admin():
    """初始化默认管理员用户"""
    admin_user = get_user('admin')
    if not admin_user:
        # 创建默认admin用户
        hashed_pwd = hash_password(DEFAULT_ADMIN_PASSWORD)
        add_user('admin', hashed_pwd, display_name='admin', role='admin', is_default=1)
        logger.info("默认管理员用户已创建")

def no_cache(f):
    """禁止浏览器缓存装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = make_response(f(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    return decorated_function

def login_required(f):
    """登录装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    """角色权限装饰器"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session:
                return redirect(url_for('login_page'))
            user_role = session['role']
            if user_role not in roles:
                return jsonify({'success': False, 'message': '权限不足'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.context_processor
def inject_user():
    """向模板注入当前用户信息"""
    user = CurrentUser().from_session()
    return {'current_user': user, 'csrf_token': session.get('csrf_token', '')}


SERVICE_STATUS_CLASSES = {
    '运行中': 'status-running',
    '已停止': 'status-stopped',
    '已下线': 'status-offline',
}

@app.context_processor
def inject_service_helpers():
    """向模板注入服务信息表页面使用的展示助手"""
    return {'service_status_class': lambda status: SERVICE_STATUS_CLASSES.get(status, 'status-unknown')}


@app.before_request
def enforce_request_security():
    if 'username' in session:
        now = time.time()
        last_activity_at = float(session.get('last_activity_at', now))
        if now - last_activity_at > SESSION_IDLE_SECONDS:
            session.clear()
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'ok': False, 'message': '登录会话已过期，请重新登录'}), 401
            return redirect(url_for('login_page'))
        session['last_activity_at'] = now
        session.modified = True
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'} and request.endpoint != 'api_login':
        supplied = request.headers.get('X-CSRFToken', '')
        expected = session.get('csrf_token', '')
        if not supplied or not hmac.compare_digest(supplied, expected):
            return jsonify({'success': False, 'ok': False, 'message': 'CSRF 校验失败'}), 403


@app.after_request
def add_security_headers(response):
    response.headers.pop('Server', None)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self' ws: wss:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    )
    return response

# 全局变量存储巡检进度
inspection_progress = {}

def load_progress():
    """从文件加载进度"""
    progress_file = os.path.join(LOG_DIR, "progress.json")
    try:
        if os.path.exists(progress_file):
            with open(progress_file, 'r', encoding='utf-8') as f:
                import json
                return json.load(f)
    except Exception as e:
        logger.error(f"加载进度失败: {e}")
    return {}

def save_progress(progress):
    """保存进度到文件"""
    progress_file = os.path.join(LOG_DIR, "progress.json")
    try:
        import json
        with open(progress_file, 'w', encoding='utf-8') as f:
            json.dump(progress, f, ensure_ascii=False)
    except Exception as e:
        logger.error(f"保存进度失败: {e}")

# 加载保存的进度
inspection_progress = load_progress()

# init db
init_db()
migrate_inspection_tasks_schema()
init_default_admin()

# ---------------- Auth Routes ----------------
@app.route("/login")
def login_page():
    if 'username' in session:
        return redirect(url_for('index'))
    return render_template("login.html")

@app.route("/api/captcha")
def api_captcha():
    """获取验证码图片"""
    captcha_text = generate_captcha()
    session['captcha'] = captcha_text.lower()
    image_buf = generate_captcha_image(captcha_text)
    response = make_response(send_file(image_buf, mimetype='image/png'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    captcha = data.get('captcha', '').strip().lower()
    
    if not username or not password:
        return jsonify({'success': False, 'message': '用户名和密码不能为空'})

    if _is_login_locked(username):
        return jsonify({'success': False, 'message': '登录失败次数过多，请15分钟后重试'}), 429
    
    if not captcha:
        return jsonify({'success': False, 'message': '请输入验证码'})
    
    session_captcha = session.get('captcha', '').lower()
    if captcha != session_captcha:
        session.pop('captcha', None)
        _record_login_failure(username)
        return jsonify({'success': False, 'message': '验证码错误'})
    
    session.pop('captcha', None)
    
    user = get_user(username)
    if not user:
        _record_login_failure(username)
        return jsonify({'success': False, 'message': '用户名或密码错误'})
    
    password_ok, is_legacy = verify_password(user['password'], password)
    if not password_ok:
        _record_login_failure(username)
        return jsonify({'success': False, 'message': '用户名或密码错误'})

    if is_legacy:
        from models import update_user_password
        update_user_password(username, hash_password(password))
    
    _clear_login_failures(username)
    # 使用浏览器会话 Cookie；关闭浏览器后必须重新登录。
    session.permanent = False
    now = time.time()
    session['last_activity_at'] = now
    session['username'] = user['username']
    session['role'] = user['role']
    return jsonify({'success': True, 'message': '登录成功', 'role': user['role']})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({'success': True})

@app.route("/api/update_password", methods=["POST"])
@no_cache
@login_required
def api_update_password():
    data = request.json
    old_password = data.get('oldPassword', '').strip()
    new_password = data.get('newPassword', '').strip()
    
    if not old_password or not new_password:
        return jsonify({'success': False, 'message': '密码不能为空'})
    
    if not validate_password_strength(new_password):
        return jsonify({'success': False, 'message': '密码至少8位，且必须包含大小写字母和数字'})
    
    username = session.get('username')
    user = get_user(username)
    
    if not user:
        return jsonify({'success': False, 'message': '用户不存在'})
    
    old_password_ok, _ = verify_password(user['password'], old_password)
    if not old_password_ok:
        return jsonify({'success': False, 'message': '原密码不正确'})
    
    hashed_new_pwd = hash_password(new_password)
    from models import update_user_password
    success = update_user_password(username, hashed_new_pwd)
    
    if success:
        return jsonify({'success': True, 'message': '密码修改成功'})
    else:
        return jsonify({'success': False, 'message': '修改失败'})

@app.route("/profile")
@no_cache
@login_required
def profile_page():
    return render_template("profile.html")

@app.route("/users")
@no_cache
@login_required
@role_required(['admin'])
def users_page():
    return render_template("users.html")


@app.route("/audit-logs")
@no_cache
@login_required
@role_required(['admin'])
def audit_logs_page():
    """全系统统一审计日志，仅超级管理员可查看。"""
    return render_template("audit_logs.html")

# ---------------- User Management APIs ----------------
@app.route("/api/users", methods=["GET", "POST"])
@no_cache
@login_required
def api_users():
    if request.method == "GET":
        if session.get('role') != 'admin':
            return jsonify([])
        users = list_users()
        # 移除密码字段
        for user in users:
            user.pop('password', None)
        return jsonify(users)
    
    elif request.method == "POST":
        if session.get('role') != 'admin':
            return jsonify({'success': False, 'message': '权限不足'}), 403
        
        data = request.json
        username = data.get('username', '').strip()
        display_name = data.get('display_name', '').strip()
        password = data.get('password', '').strip()
        contact = data.get('contact', '').strip()
        role = data.get('role', '').strip()
        
        if not username:
            return jsonify({'success': False, 'message': '用户名称不能为空'})
        if not password:
            return jsonify({'success': False, 'message': '密码不能为空'})
        if not role:
            return jsonify({'success': False, 'message': '权限角色不能为空'})
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', username):
            return jsonify({'success': False, 'message': '用户名格式无效'})
        if not is_safe_display_text(display_name, 50) or not is_safe_display_text(contact, 100):
            return jsonify({'success': False, 'message': '用户信息包含非法字符'}), 400
        
        if not validate_password_strength(password):
            return jsonify({'success': False, 'message': '密码至少8位，且必须包含大小写字母和数字'})
        
        if role not in ROLES:
            return jsonify({'success': False, 'message': '无效的权限角色'})
        
        hashed_pwd = hash_password(password)
        try:
            user_id = add_user(username, hashed_pwd, display_name, contact, role, 0)
            
            if user_id:
                return jsonify({'success': True, 'message': '用户创建成功'})
            else:
                return jsonify({'success': False, 'message': '用户名已存在'})
        except Exception as e:
            logger.error(f'创建用户失败: {str(e)}')
            return jsonify({'success': False, 'message': f'服务器错误: {str(e)}'}), 500

@app.route("/api/users/<int:user_id>", methods=["PUT", "DELETE"])
@no_cache
@login_required
@role_required(['admin'])
def api_user_detail(user_id):
    if request.method == "PUT":
        data = request.json
        username = data.get('username', '').strip()
        display_name = data.get('display_name', '').strip()
        password = data.get('password', '').strip()
        contact = data.get('contact', '').strip()
        role = data.get('role', '').strip()
        
        if not username:
            return jsonify({'success': False, 'message': '用户名不能为空'})
        
        if not role:
            return jsonify({'success': False, 'message': '角色不能为空'})
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', username):
            return jsonify({'success': False, 'message': '用户名格式无效'})
        if not is_safe_display_text(display_name, 50) or not is_safe_display_text(contact, 100):
            return jsonify({'success': False, 'message': '用户信息包含非法字符'}), 400
        if role not in ROLES:
            return jsonify({'success': False, 'message': '无效的权限角色'}), 400
        
        if password and not validate_password_strength(password):
            return jsonify({'success': False, 'message': '密码至少8位，且必须包含大小写字母和数字'})
        
        try:
            password_hash = hash_password(password) if password else None
            update_user(user_id, username, password_hash, contact, role, display_name)
            return jsonify({'success': True, 'message': '更新成功'})
        except sqlite3.IntegrityError:
            return jsonify({'success': False, 'message': '用户名已存在'})
    
    elif request.method == "DELETE":
        success = delete_user(user_id)
        if success:
            return jsonify({'success': True, 'message': '删除成功'})
        else:
            return jsonify({'success': False, 'message': '无法删除系统默认用户或用户不存在'})

# ---------------- Page Routes ----------------
@app.route("/")
@no_cache
@login_required
def index():
    return render_template("index.html")

@app.route("/inspect")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def inspect_page():
    groups = list_groups()
    return render_template("inspect.html", groups=groups, cpu=CPU_THRESHOLD, mem=MEM_THRESHOLD, disk=DISK_THRESHOLD)

@app.route("/server_inspect")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def server_inspect_page():
    tasks = list_inspection_tasks()
    groups = list_groups()
    runs = list_inspection_runs(50)
    for run in runs:
        run['report_filename'] = os.path.basename(run['report_path']) if run.get('report_path') else None
    return render_template(
        "server_inspect.html", tasks=tasks, groups=groups, runs=runs,
        cpu=CPU_THRESHOLD, mem=MEM_THRESHOLD, disk=DISK_THRESHOLD,
    )

def sanitize_servers_for_client(servers):
    sanitized = []
    for server in servers:
        item = dict(server)
        item.pop('enc_password', None)
        item.pop('enc_private_key', None)
        item.pop('enc_key_passphrase', None)
        sanitized.append(item)
    return sanitized

def attach_server_list_meta(servers):
    """补充列表页需要的附加信息：级联删除提示条数与硬件参数是否已记录。"""
    service_counts = count_services_by_server()
    hardware_snapshots = list_server_hardware_snapshots()
    for server in servers:
        snapshot = hardware_snapshots.get(server["id"]) or {}
        server["service_count"] = service_counts.get(server["id"], 0)
        server["hardware_recorded"] = bool(snapshot.get("collected_at"))
    return servers

def filter_servers_by_keyword(servers, keyword):
    keyword = (keyword or "").strip().lower()
    if not keyword:
        return servers

    def text(value):
        return str(value or "").strip().lower()

    filtered = []
    for server in servers:
        searchable = " ".join([
            text(server.get("name")),
            text(server.get("ip")),
            text(server.get("physical_ip")),
            text(server.get("resource_type")),
            text(server.get("os_type")),
            text(server.get("group_names")),
            text(server.get("rack_number")),
            text(server.get("room_affiliation")),
            text(server.get("rack_level")),
            text(server.get("username")),
            text(server.get("notes")),
        ])
        if keyword in searchable:
            filtered.append(server)
    return filtered


def sanitize_service_for_client(service):
    """剥离账号凭据字段。列表/详情 SQL 本就不取账号列，这里是兜底防线。"""
    item = dict(service)
    for field in ('enc_password', 'accounts', 'service_accounts'):
        item.pop(field, None)
    return item


def sanitize_services_for_client(services):
    return [sanitize_service_for_client(service) for service in services]


def filter_services_by_keyword(services, keyword):
    keyword = (keyword or "").strip().lower()
    if not keyword:
        return services
    searchable_fields = (
        "name", "ip", "server_name", "deploy_dir", "ports", "owner", "version",
        "service_type", "run_mode", "status", "system_names", "environment_names", "notes",
    )
    return [
        service for service in services
        if keyword in " ".join(str(service.get(field) or "").strip().lower() for field in searchable_fields)
    ]


def _requested_export_fields():
    """兼容 fields=a,b 与重复 fields=a&fields=b 两种传参方式。"""
    fields = []
    for value in request.args.getlist('fields'):
        fields.extend(part.strip() for part in str(value).split(',') if part.strip())
    return fields


@app.route("/servers")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def servers_page():
    groups = list_groups()
    # 附加信息：删除确认提示级联影响的服务条数、硬件参数是否已记录。
    servers = attach_server_list_meta(sanitize_servers_for_client(list_servers()))
    return render_template(
        "servers.html", groups=groups, servers=servers, page_mode="list",
        server_export_fields=SERVER_EXPORT_FIELDS,
    )

@app.route("/servers-new")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def new_server_page():
    groups = list_groups()
    return render_template("servers.html", groups=groups, servers=[], page_mode="new")

@app.route("/server-environments")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def server_environments_page():
    return render_template(
        "server_environments.html",
        environments=list_service_environments(),
    )

@app.route("/service-systems")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def service_systems_page():
    return render_template(
        "service_systems.html",
        systems=list_service_systems(),
    )

@app.route("/services")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def services_page():
    return render_template(
        "services.html",
        page_mode="list",
        services=list_services(),
        systems=list_service_systems(),
        environments=list_service_environments(),
        servers=[],
        service=None,
        service_export_fields=SERVICE_EXPORT_FIELDS,
    )

@app.route("/services-new")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def new_service_page():
    return render_template(
        "services.html",
        page_mode="new",
        services=[],
        systems=list_service_systems(),
        environments=list_service_environments(),
        servers=sanitize_servers_for_client(list_servers()),
        service=None,
    )

@app.route("/services/<int:service_id>/edit")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def service_edit_page(service_id):
    service = get_service(service_id)
    if not service:
        return redirect(url_for('services_page'))
    # 账号明细不随页面下发：编辑页的账号区必须二次验证通过后才解锁。
    return render_template(
        "services.html",
        page_mode="edit",
        services=[],
        systems=list_service_systems(),
        environments=list_service_environments(),
        servers=sanitize_servers_for_client(list_servers()),
        service=sanitize_service_for_client(service),
    )

@app.route("/dashboard")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def dashboard_page():
    return redirect(url_for('server_runtime_page'))


@app.route("/dashboard/server-status")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def server_runtime_page():
    start_server_health_monitor()
    return render_template(
        "dashboard.html",
        server_health_interval=SERVER_HEALTH_INTERVAL,
        server_offline_after=SERVER_OFFLINE_AFTER,
        server_offline_minutes=max(1, round(SERVER_OFFLINE_AFTER / 60)),
    )


@app.route("/dashboard/data-center")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def data_center_dashboard_page():
    start_server_health_monitor()
    return render_template(
        "data_center_dashboard.html",
        server_health_interval=SERVER_HEALTH_INTERVAL,
        server_offline_minutes=max(1, round(SERVER_OFFLINE_AFTER / 60)),
    )

@app.route("/reports")
@no_cache
@login_required
def reports_page():
    return render_template("reports.html")


@app.route("/resource-changes")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def resource_changes_page():
    return render_template("resource_changes.html")


@app.route("/resource-change-history")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def resource_change_history_page():
    return render_template("resource_change_history.html")


def _parse_plan_time(value, label):
    text = str(value or '').strip().replace('T', ' ')
    if len(text) == 16:
        text += ':00'
    try:
        moment = datetime.strptime(text, _TIME_FORMAT)
    except (TypeError, ValueError):
        raise ValueError(f'{label}格式无效')
    return moment, moment.strftime(_TIME_FORMAT)


def _new_resource_plan_ticket_no():
    return f"CHG-{datetime.now().strftime('%Y%m%d%H%M%S')}"


def _validate_resource_plan_payload(data):
    try:
        server_id = int(data.get('server_id'))
    except (TypeError, ValueError):
        raise ValueError('请选择服务器')
    server = get_server(server_id)
    if not server:
        raise ValueError('服务器不存在')
    reason = str(data.get('reason') or '').strip()
    if len(reason) < 2 or len(reason) > 500:
        raise ValueError('变更理由必须为 2 至 500 个字符')
    if not is_safe_display_text(reason, 500):
        raise ValueError('变更理由包含非法控制字符')
    ticket_no = str(data.get('ticket_no') or '').strip()
    if len(ticket_no) > 100 or not is_safe_display_text(ticket_no, 100):
        raise ValueError('变更单号不能超过 100 个字符或包含非法字符')
    start_dt, window_start = _parse_plan_time(data.get('window_start'), '开始时间')
    end_dt, window_end = _parse_plan_time(data.get('window_end'), '结束时间')
    if end_dt <= start_dt:
        raise ValueError('结束时间必须晚于开始时间')
    if end_dt - start_dt > timedelta(days=31):
        raise ValueError('单个计划的有效期不能超过 31 天')
    expected = data.get('expected_payload')
    if not isinstance(expected, dict):
        raise ValueError('预期资源配置格式无效')
    hardware = expected.get('hardware') or {}
    for field in ('cpu', 'memory', 'storage'):
        value = str(hardware.get(field) or '').strip()
        if len(value) > 50:
            raise ValueError('预期硬件参数过长')
    criteria = expected.get('disk_expectation')
    if criteria is not None:
        if not isinstance(criteria, dict):
            raise ValueError('预期磁盘配置格式无效')
        for field in ('device_count', 'mount_count'):
            try:
                value = int(criteria.get(field))
            except (TypeError, ValueError):
                raise ValueError('磁盘数量和挂载点数量必须是整数')
            if value < 0 or value > 600:
                raise ValueError('磁盘数量或挂载点数量超出允许范围')
        mounts_supplied = 'mounts' in criteria
        mounts = criteria.get('mounts') or []
        if not isinstance(mounts, list) or len(mounts) > 300:
            raise ValueError('预期挂载点列表格式无效')
        seen = set()
        clean_mounts = []
        for item in mounts:
            mount = str((item or {}).get('mount') or '').strip()
            if not mount.startswith('/') or len(mount) > 200 or mount in seen:
                raise ValueError('挂载点必须是唯一的绝对路径')
            seen.add(mount)
            try:
                size_gb = float((item or {}).get('size_gb'))
            except (TypeError, ValueError):
                raise ValueError(f'挂载点 {mount} 的容量必须是数字')
            if size_gb <= 0:
                raise ValueError(f'挂载点 {mount} 的容量必须大于 0')
            clean_mounts.append({'mount': mount, 'size_gb': round(size_gb, 3)})
        if mounts_supplied and len(clean_mounts) != int(criteria['mount_count']):
            raise ValueError('预期挂载点数量必须与挂载点列表行数一致')
        criteria = {
            'device_count': int(criteria['device_count']),
            'mount_count': int(criteria['mount_count']),
        }
        if mounts_supplied:
            criteria['mounts'] = clean_mounts
    expected = {
        'hardware': {
            field: str(hardware.get(field) or '').strip()
            for field in ('cpu', 'memory', 'storage') if str(hardware.get(field) or '').strip()
        },
        'disk_expectation': criteria,
    }
    if not expected['hardware'] and criteria is None:
        raise ValueError('至少填写一项预期资源配置')
    return server, expected, window_start, window_end, reason, ticket_no


def _summarize_resource_expectation(expected):
    expected = expected or {}
    hardware = expected.get('hardware') or {}
    disk = expected.get('disk_expectation') or {}
    parts = []
    labels = {'cpu': 'CPU', 'memory': '内存', 'storage': '物理磁盘总容量'}
    for field, label in labels.items():
        if hardware.get(field):
            parts.append(f'{label} {hardware[field]}')
    if disk:
        if disk.get('device_count') is not None:
            parts.append(f"物理磁盘 {disk['device_count']} 块")
        if disk.get('mount_count') is not None:
            parts.append(f"挂载点 {disk['mount_count']} 个")
        mounts = [
            f"{item.get('mount')}={item.get('size_gb')}GB"
            for item in (disk.get('mounts') or []) if item.get('mount')
        ]
        if mounts:
            parts.append('挂载明细：' + '、'.join(mounts))
    return '；'.join(parts) or '-'


def _parse_history_date(value, label, end_of_day=False):
    value = str(value or '').strip()
    if not value:
        return ''
    try:
        moment = datetime.strptime(value, '%Y-%m-%d')
    except ValueError:
        raise ValueError(f'{label}格式无效')
    if end_of_day:
        moment = moment.replace(hour=23, minute=59, second=59)
    return moment.strftime(_TIME_FORMAT)


def _resource_history_rows(server_id=None, record_type='', date_from='', date_to=''):
    if record_type not in ('', 'plan', 'event'):
        raise ValueError('记录类型无效')
    start = _parse_history_date(date_from, '开始日期')
    end = _parse_history_date(date_to, '结束日期', end_of_day=True)
    if start and end and start > end:
        raise ValueError('结束日期不能早于开始日期')
    if server_id not in (None, ''):
        try:
            server_id = int(server_id)
        except (TypeError, ValueError):
            raise ValueError('服务器筛选条件无效')
    else:
        server_id = None

    models.expire_resource_change_plans()
    rows = []
    if record_type in ('', 'plan'):
        for item in models.list_resource_change_plans(server_id=server_id):
            if item.get('status') == 'planned':
                continue
            occurred_at = (
                item.get('matched_at') or item.get('cancelled_at')
                or item.get('window_end') or item.get('created_at') or ''
            )
            rows.append({
                'record_id': f"P-{item['id']}", 'source_id': item['id'],
                'record_kind': 'plan', 'record_type': '计划变更',
                'occurred_at': occurred_at, 'server_id': item.get('server_id'),
                'server_name': item.get('server_name') or '',
                'server_ip': item.get('server_ip') or '',
                'summary': _summarize_resource_expectation(item.get('expected_payload')),
                'status': item.get('status') or '', 'reason': item.get('reason') or '',
                'operator': item.get('created_by') or '',
                'ticket_no': item.get('ticket_no') or '',
            })
    if record_type in ('', 'event'):
        for item in models.list_resource_change_events(server_id=server_id, limit=500):
            if item.get('status') in models.RESOURCE_EVENT_OPEN_STATUSES:
                continue
            rows.append({
                'record_id': f"E-{item['id']}", 'source_id': item['id'],
                'record_kind': 'event', 'record_type': '实际变化',
                'occurred_at': item.get('decided_at') or item.get('last_seen_at') or '',
                'server_id': item.get('server_id'),
                'server_name': item.get('server_name') or '',
                'server_ip': item.get('server_ip') or '',
                'summary': '；'.join(item.get('change_detail') or []) or '-',
                'status': item.get('status') or '',
                'reason': item.get('decision_reason') or '',
                'operator': item.get('decided_by') or '', 'ticket_no': '',
            })
    if start:
        rows = [item for item in rows if (item.get('occurred_at') or '') >= start]
    if end:
        rows = [item for item in rows if (item.get('occurred_at') or '') <= end]
    rows.sort(key=lambda item: item.get('occurred_at') or '', reverse=True)
    return rows


@app.route('/api/resource-config', methods=['GET'])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_resource_config():
    history = _resource_history_rows()
    return jsonify({
        'ok': True,
        'servers': sanitize_servers_for_client(list_servers()),
        'baselines': models.list_resource_baselines(),
        'plans': models.list_resource_change_plans(),
        'events': models.list_resource_change_events(limit=300),
        'history': history,
    })


@app.route('/api/resource-config/history/download', methods=['GET'])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_download_resource_history():
    try:
        rows = _resource_history_rows(
            server_id=request.args.get('server_id'),
            record_type=str(request.args.get('type') or '').strip(),
            date_from=request.args.get('date_from'),
            date_to=request.args.get('date_to'),
        )
    except ValueError as exc:
        return jsonify({'ok': False, 'msg': str(exc)}), 400
    record_audit(
        session.get('username'), 'resource.history.download', result='ok',
        target_type='resource_history', target_name='资源配置变更历史',
        detail=f'导出 {len(rows)} 条；筛选={dict(request.args)}',
        client_ip=request.remote_addr or '',
    )
    filename = f'资源配置变更历史_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    return send_file(
        build_resource_history_excel(rows), as_attachment=True,
        download_name=filename,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    )


@app.route('/api/resource-config/plans', methods=['POST'])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_create_resource_plan():
    try:
        server, expected, start, end, reason, ticket = _validate_resource_plan_payload(request.json or {})
        ticket = _new_resource_plan_ticket_no()
        plan_id = models.add_resource_change_plan(
            server['id'], expected, start, end, reason, ticket, session.get('username') or '',
        )
        record_audit(
            session.get('username'), 'resource.plan.create', result='ok',
            target_type='server', target_id=server['id'], target_name=server.get('ip') or '',
            detail=f'计划ID={plan_id}；时间={start}~{end}；理由={reason[:200]}',
            client_ip=request.remote_addr or '',
        )
        return jsonify({'ok': True, 'id': plan_id, 'ticket_no': ticket})
    except ValueError as exc:
        return jsonify({'ok': False, 'msg': str(exc)}), 400


@app.route('/api/resource-config/plans/<int:plan_id>', methods=['PUT', 'DELETE'])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_update_resource_plan(plan_id):
    plans = {item['id']: item for item in models.list_resource_change_plans()}
    plan = plans.get(plan_id)
    if not plan:
        return jsonify({'ok': False, 'msg': '计划不存在'}), 404
    if plan.get('status') != 'planned':
        return jsonify({'ok': False, 'msg': '只有待执行计划可以修改或取消'}), 409
    if request.method == 'DELETE':
        models.finish_resource_change_plan(plan_id, 'cancelled')
        action, detail = 'resource.plan.cancel', f'计划ID={plan_id}'
    else:
        try:
            server, expected, start, end, reason, ticket = _validate_resource_plan_payload(request.json or {})
        except ValueError as exc:
            return jsonify({'ok': False, 'msg': str(exc)}), 400
        if int(server['id']) != int(plan['server_id']):
            return jsonify({'ok': False, 'msg': '计划创建后不能更换服务器'}), 400
        if not models.update_resource_change_plan(plan_id, expected, start, end, reason, ticket):
            return jsonify({'ok': False, 'msg': '计划已执行或已取消'}), 409
        action, detail = 'resource.plan.update', f'计划ID={plan_id}；理由={reason[:200]}'
    record_audit(
        session.get('username'), action, result='ok', target_type='resource_plan',
        target_id=plan_id, target_name=plan.get('server_ip') or '', detail=detail,
        client_ip=request.remote_addr or '',
    )
    return jsonify({'ok': True})


@app.route('/api/resource-config/events/<int:event_id>/decision', methods=['POST'])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_decide_resource_event(event_id):
    data = request.json or {}
    decision = str(data.get('decision') or '').strip()
    reason = str(data.get('reason') or '').strip()
    if decision not in ('normal', 'abnormal', 'resolved'):
        return jsonify({'ok': False, 'msg': '确认结论无效'}), 400
    if len(reason) < 2 or len(reason) > 500:
        return jsonify({'ok': False, 'msg': '确认理由必须为 2 至 500 个字符'}), 400
    if not is_safe_display_text(reason, 500):
        return jsonify({'ok': False, 'msg': '确认理由包含非法控制字符'}), 400
    event = models.get_resource_change_event(event_id)
    if not event:
        return jsonify({'ok': False, 'msg': '变更记录不存在'}), 404
    if decision == 'resolved' and event.get('status') != 'recovered_pending':
        return jsonify({'ok': False, 'msg': '只有已恢复待确认的记录才能关闭'}), 409
    if not models.decide_resource_change_event(
            event_id, decision, reason, session.get('username') or ''):
        return jsonify({'ok': False, 'msg': '该变更已处理，请刷新页面'}), 409
    record_audit(
        session.get('username'), f'resource.event.{decision}', result='ok',
        target_type='resource_event', target_id=event_id,
        target_name=str(event.get('server_id')), detail=reason,
        client_ip=request.remote_addr or '',
    )
    return jsonify({'ok': True})

# --------- APIs: groups & servers ----------
@app.route("/api/groups", methods=["GET", "POST", "DELETE"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_groups():
    if request.method == "GET":
        return jsonify(list_groups())
    elif request.method == "POST":
        data = request.json
        name = data.get("name","").strip()
        if not name:
            return jsonify({"ok": False, "msg": "name required"}), 400
        if not is_safe_display_text(name, 50):
            return jsonify({"ok": False, "msg": "环境项名称包含非法字符"}), 400
        add_group(name)
        return jsonify({"ok": True})
    elif request.method == "DELETE":
        gid = int(request.args.get("id"))
        delete_group(gid)
        return jsonify({"ok": True})

def validate_server_payload(data, require_credentials=True):
    name = str(data.get("name", "")).strip()
    ip = str(data.get("ip", "")).strip()
    resource_type = str(data.get("resource_type", "虚拟机")).strip()
    physical_ip = str(data.get("physical_ip", "")).strip()
    os_type = str(data.get("os_type", "Centos")).strip()
    rack_number = str(data.get("rack_number", "")).strip()
    room_affiliation = str(data.get("room_affiliation", "")).strip()
    rack_level = str(data.get("rack_level", "")).strip()
    try:
        port = int(data.get("port", 22))
    except (TypeError, ValueError):
        raise ValueError("端口格式无效")
    username = str(data.get("username", "")).strip()
    auth_type = data.get("auth_type", "password")
    password = data.get("password", "") or ""
    private_key = data.get("private_key", "") or ""
    key_passphrase = data.get("key_passphrase", "") or ""
    notes = str(data.get("notes", ""))
    group_ids = data.get("group_ids", []) or []
    if not name or not is_safe_display_text(name, 100):
        raise ValueError("服务器名称不能为空或包含非法字符")
    if resource_type not in ("云实例", "虚拟机", "物理机"):
        raise ValueError("资源类型无效")
    if physical_ip and not is_valid_host(physical_ip):
        raise ValueError("物理机IP格式无效")
    if os_type not in ("Centos", "Ubuntu", "Kylin V10", "Windows"):
        raise ValueError("系统类型无效")
    if not is_safe_display_text(rack_number, 100):
        raise ValueError("机柜编号包含非法字符")
    if not is_safe_display_text(room_affiliation, 100):
        raise ValueError("机房归属包含非法字符")
    if not is_safe_display_text(rack_level, 100):
        raise ValueError("机柜层级包含非法字符")
    if not is_valid_host(ip):
        raise ValueError("IP地址或主机名格式无效")
    if not 1 <= port <= 65535:
        raise ValueError("端口必须在1到65535之间")
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', username):
        raise ValueError("用户名格式无效")
    if auth_type not in ("password", "key"):
        raise ValueError("SSH认证方式无效")
    if len(password) > 1024 or len(key_passphrase) > 1024 or len(private_key) > 65536:
        raise ValueError("认证信息过长")
    if require_credentials and auth_type == "password" and not password:
        raise ValueError("密码不能为空")
    if require_credentials and auth_type == "key" and not private_key:
        raise ValueError("SSH私钥不能为空")
    if private_key:
        parse_private_key(private_key, key_passphrase or None)
    if not is_safe_display_text(notes, 500):
        raise ValueError("备注包含非法字符")
    try:
        group_ids = [int(group_id) for group_id in group_ids]
    except (TypeError, ValueError):
        raise ValueError("服务器所属环境格式无效")
    return {
        "name": name, "ip": ip, "resource_type": resource_type,
        "physical_ip": physical_ip, "os_type": os_type, "rack_number": rack_number,
        "room_affiliation": room_affiliation, "rack_level": rack_level,
        "port": port, "username": username, "auth_type": auth_type,
        "password": password, "private_key": private_key,
        "key_passphrase": key_passphrase, "notes": notes, "group_ids": group_ids,
    }

@app.route("/api/servers/test-connection", methods=["POST"])
@login_required
@role_required(['admin', 'operator'])
def api_test_server_connection():
    try:
        data = request.json or {}
        server_id = data.get("id")
        existing = None
        if server_id not in (None, ""):
            try:
                existing = get_server(int(server_id))
            except (TypeError, ValueError):
                raise ValueError("服务器ID无效")
            if not existing:
                raise ValueError("服务器不存在")
        values = validate_server_payload(data, require_credentials=not bool(existing))
        auth_changed = bool(existing) and values["auth_type"] != existing.get("auth_type", "password")
        if auth_changed and not (values["password"] or values["private_key"]):
            raise ValueError("切换认证方式时必须填写新的认证凭据")
        if existing and values["auth_type"] == "password" and not values["password"]:
            values["password"] = aes_gcm_decrypt(load_aes_key(), existing["enc_password"])
        if existing and values["auth_type"] == "key" and not values["private_key"]:
            key = load_aes_key()
            values["private_key"] = aes_gcm_decrypt(key, existing["enc_private_key"])
            values["key_passphrase"] = (
                aes_gcm_decrypt(key, existing["enc_key_passphrase"])
                if existing.get("enc_key_passphrase") else ""
            )
        ssh = create_ssh_client()
        try:
            connect_ssh(
                ssh, values["ip"], values["port"], values["username"],
                password=values["password"] if values["auth_type"] == "password" else None,
                private_key=values["private_key"] if values["auth_type"] == "key" else None,
                key_passphrase=values["key_passphrase"] or None,
                timeout=10,
            )
        finally:
            ssh.close()
        return jsonify({"ok": True, "msg": "SSH连接测试成功"})
    except ValueError as exc:
        return jsonify({"ok": False, "msg": str(exc)}), 400
    except Exception as exc:
        logger.warning("服务器连接测试失败 %s: %s", (request.json or {}).get("ip", ""), exc)
        return jsonify({"ok": False, "msg": "SSH连接失败: " + str(exc)[:240]}), 400

@app.route("/api/servers/export", methods=["GET"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_export_servers():
    gid = request.args.get("group_id")
    try:
        gid = int(gid) if gid else None
        selected_fields = select_export_fields(SERVER_EXPORT_FIELDS, _requested_export_fields())
    except ValueError as exc:
        return jsonify({"ok": False, "msg": str(exc)}), 400

    servers = list_servers(
        gid, "",
        (request.args.get("resource_type") or "").strip(),
        (request.args.get("os_type") or "").strip(),
    )
    servers = filter_servers_by_keyword(servers, request.args.get("keyword"))
    rows = attach_server_list_meta(sanitize_servers_for_client(servers))
    labels = '、'.join(item['label'] for item in selected_fields)
    record_audit(
        session.get('username'), 'server.export', result='ok',
        target_type='server', target_name='服务器列表',
        detail=f'导出 {len(rows)} 条；字段={labels}', client_ip=request.remote_addr or '',
    )
    filename = f'服务器列表_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    return send_file(
        build_asset_export_excel('服务器列表', '服务器列表', rows, selected_fields),
        as_attachment=True, download_name=filename,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    )


@app.route("/api/servers", methods=["GET", "POST", "PUT", "DELETE"])
@login_required
@role_required(['admin', 'operator'])
def api_servers():
    if request.method == "GET":
        gid = request.args.get("group_id")
        try:
            gid = int(gid) if gid else None
        except ValueError:
            return jsonify({"ok": False, "msg": "环境项ID无效"}), 400
        keyword = (request.args.get("keyword") or "").strip()
        resource_type = (request.args.get("resource_type") or "").strip()
        os_type = (request.args.get("os_type") or "").strip()
        servers = list_servers(gid, "", resource_type, os_type)
        servers = filter_servers_by_keyword(servers, keyword)
        sanitized = sanitize_servers_for_client(servers)
        return jsonify(attach_server_list_meta(sanitized))
    elif request.method == "POST":
        try:
            values = validate_server_payload(request.json or {}, require_credentials=True)
        except ValueError as exc:
            return jsonify({"ok": False, "msg": str(exc)}), 400
        key = load_aes_key()
        enc_password = aes_gcm_encrypt(key, values["password"]) if values["auth_type"] == "password" else ""
        enc_private_key = aes_gcm_encrypt(key, values["private_key"]) if values["auth_type"] == "key" else None
        enc_key_passphrase = (
            aes_gcm_encrypt(key, values["key_passphrase"])
            if values["auth_type"] == "key" and values["key_passphrase"] else None
        )
        add_server(
            values["ip"], values["port"], values["username"], enc_password,
            values["group_ids"], values["notes"], auth_type=values["auth_type"], enc_private_key=enc_private_key,
            enc_key_passphrase=enc_key_passphrase, name=values["name"],
            resource_type=values["resource_type"], physical_ip=values["physical_ip"],
            os_type=values["os_type"], rack_number=values["rack_number"],
            room_affiliation=values["room_affiliation"], rack_level=values["rack_level"],
        )
        return jsonify({"ok": True})
    elif request.method == "PUT":
        data = request.json or {}
        try:
            server_id = int(data.get("id"))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "msg": "服务器ID无效"}), 400
        existing = get_server(server_id)
        if not existing:
            return jsonify({"ok": False, "msg": "服务器不存在"}), 404
        try:
            values = validate_server_payload(data, require_credentials=False)
        except ValueError as exc:
            return jsonify({"ok": False, "msg": str(exc)}), 400
        auth_changed = values["auth_type"] != existing.get("auth_type", "password")
        supplied = values["password"] if values["auth_type"] == "password" else values["private_key"]
        if auth_changed and not supplied:
            return jsonify({"ok": False, "msg": "切换认证方式时必须填写新的认证凭据"}), 400
        key = load_aes_key()
        if values["auth_type"] == "password":
            enc_password = aes_gcm_encrypt(key, values["password"]) if values["password"] else existing["enc_password"]
            enc_private_key = None
            enc_key_passphrase = None
        else:
            enc_password = ""
            enc_private_key = aes_gcm_encrypt(key, values["private_key"]) if values["private_key"] else existing["enc_private_key"]
            enc_key_passphrase = (
                aes_gcm_encrypt(key, values["key_passphrase"])
                if values["private_key"] and values["key_passphrase"] else
                (None if values["private_key"] else existing["enc_key_passphrase"])
            )
        update_server(
            server_id, values["ip"], values["port"], values["username"], enc_password,
            values["group_ids"], values["notes"], values["auth_type"],
            enc_private_key, enc_key_passphrase, values["name"], values["resource_type"],
            values["physical_ip"], values["os_type"], values["rack_number"],
            values["room_affiliation"], values["rack_level"],
        )
        # 连接目标变了，旧记录不再代表这台机器，等下次核对重新记录。
        # 旧值不完整时无法判断是否换了机器，此时不动记录。
        old_target = (existing.get("ip"), existing.get("port"), existing.get("username"))
        new_target = (values["ip"], values["port"], values["username"])
        if all(old_target) and new_target != old_target:
            models.reset_resource_configuration(server_id)
        return jsonify({"ok": True})
    elif request.method == "DELETE":
        sid = int(request.args.get("id"))
        delete_server(sid)
        return jsonify({"ok": True})


@app.route("/api/servers/<int:server_id>/credentials/reveal", methods=["POST"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_reveal_server_credentials(server_id):
    """验证当前登录用户密码后，短时返回指定服务器的登录凭据。"""
    server = get_server(server_id)
    if not server:
        return jsonify({"ok": False, "msg": "服务器不存在"}), 404
    if _is_reveal_locked():
        return jsonify({"ok": False, "msg": "验证失败次数过多，请15分钟后重试"}), 429

    username = session.get('username')
    supplied = (request.json or {}).get("password", "") or ""
    user = get_user(username)
    password_ok = bool(supplied) and bool(user) and verify_password(user['password'], supplied)[0]
    target_name = server.get("name") or server.get("ip") or ""
    if not password_ok:
        _record_reveal_failure()
        record_audit(
            username, "server.reveal_credential", result="denied", target_type="server",
            target_id=server_id, target_name=target_name, client_ip=request.remote_addr or '',
        )
        return jsonify({"ok": False, "msg": "当前登录密码不正确"}), 403

    try:
        decrypted = decrypt_server_credentials(load_aes_key(), server)
    except Exception:
        logger.exception("服务器凭据解密失败 server_id=%s", server_id)
        record_audit(
            username, "server.reveal_credential", result="error", target_type="server",
            target_id=server_id, target_name=target_name, detail="凭据解密失败",
            client_ip=request.remote_addr or '',
        )
        return jsonify({"ok": False, "msg": "服务器凭据解密失败，请检查系统密钥"}), 500

    _clear_reveal_failures()
    auth_type = server.get("auth_type") or "password"
    credential = {
        "server_name": server.get("name") or "",
        "server_ip": server.get("ip") or "",
        "username": server.get("username") or "",
        "auth_type": auth_type,
        "password": decrypted.get("password"),
        "private_key": decrypted.get("private_key"),
        "key_passphrase": decrypted.get("key_passphrase"),
    }
    record_audit(
        username, "server.reveal_credential", result="ok", target_type="server",
        target_id=server_id, target_name=target_name,
        detail="认证方式=" + ("SSH私钥" if auth_type == "key" else "密码"),
        client_ip=request.remote_addr or '',
    )
    return jsonify({"ok": True, "expires_in": REVEAL_HIDE_SECONDS, "credential": credential})

def _format_memory_capacity(raw_value, bytes_input=False):
    """将系统可见内存归一化为内存条标称容量，如 60.55 GiB -> 64 GB。"""
    try:
        value = float(str(raw_value).strip().splitlines()[0])
        gib = value / (1024 ** 3) if bytes_input else value / (1024 ** 2)
        standard = 1
        while standard < gib and standard < 4096:
            standard *= 2
        return f"{standard} GB"
    except (TypeError, ValueError, IndexError):
        return "未知"


def _format_storage_capacity(raw_values):
    """按物理磁盘厂商十进制容量归一化后求和。"""
    common_sizes = (64, 80, 120, 128, 160, 240, 250, 256, 320, 480, 500, 512,
                    750, 960, 1000, 1024, 1920, 2000, 2048, 3840, 4000, 4096,
                    7680, 8000, 10000, 12000, 16000, 18000, 20000, 22000, 24000)
    try:
        sizes = [float(line.strip()) / 1_000_000_000 for line in str(raw_values).splitlines() if line.strip()]
        if not sizes:
            return "未知"
        normalized = []
        for size in sizes:
            nearest = min(common_sizes, key=lambda candidate: abs(candidate - size))
            normalized.append(nearest if abs(nearest - size) / max(size, 1) <= 0.08 else round(size))
        total_gb = sum(normalized)
        if total_gb >= 1000:
            value = total_gb / 1000
            return f"{value:.2f}".rstrip('0').rstrip('.') + " TB"
        return f"{int(total_gb)} GB"
    except (TypeError, ValueError):
        return "未知"


# ---------------- 服务器完整信息（硬件参数记录） ----------------
HARDWARE_FIELDS = (('cpu', 'CPU'), ('memory', '内存'), ('storage', '存储空间'), ('gpu', 'GPU'))
# 命令缺失、采集报错时得到的"没有采到值"的占位文本，不允许覆盖已记录的有效参数。
HARDWARE_PLACEHOLDERS = ('', '未知', '采集失败')
_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def _now_text():
    return datetime.now().strftime(_TIME_FORMAT)


def _format_cpu_cores(raw_value):
    """CPU 只接受纯数字输出，命令回显的报错内容按"未知"处理。"""
    lines = str(raw_value or '').strip().splitlines()
    first = lines[0].strip() if lines else ''
    return f"{int(first)} 核" if first.isdigit() else '未知'


def _format_gpu(raw_value):
    """GPU 名称；命令不存在或回显报错时按"未知"处理，避免把 shell 报错当成硬件参数。"""
    text = ' '.join(str(raw_value or '').split())
    if not text:
        return '未检测到'
    if re.search(r'command not found|not found|no such file|permission denied|not recognized',
                 text, re.IGNORECASE):
        return '未知'
    return text[:200]


def collect_server_hardware(raw_server):
    """连接服务器采集一次硬件参数；连接失败时只返回失败原因。"""
    hardware = {'cpu': '未知', 'memory': '未知', 'storage': '未知', 'gpu': '未知'}
    ssh = create_ssh_client()
    try:
        credentials = decrypt_server_credentials(load_aes_key(), raw_server)
        connect_ssh(ssh, raw_server['ip'], raw_server['port'], raw_server['username'],
                    password=credentials.get('password'), private_key=credentials.get('private_key'),
                    key_passphrase=credentials.get('key_passphrase'), timeout=10)
        if raw_server.get('os_type') == 'Windows':
            hardware['cpu'] = _format_cpu_cores(run_cmd(ssh, 'powershell -NoProfile -Command "(Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors"'))
            memory_bytes = run_cmd(ssh, 'powershell -NoProfile -Command "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory"')
            disk_bytes = run_cmd(ssh, 'powershell -NoProfile -Command "Get-CimInstance Win32_DiskDrive | ForEach-Object {$_.Size}"')
            hardware['memory'] = _format_memory_capacity(memory_bytes, bytes_input=True)
            hardware['storage'] = _format_storage_capacity(disk_bytes)
            hardware['gpu'] = _format_gpu(run_cmd(ssh, 'powershell -NoProfile -Command "(Get-CimInstance Win32_VideoController).Name -join \'; \'"'))
        else:
            hardware['cpu'] = _format_cpu_cores(run_cmd(ssh, "c=$(lscpu -p=CPU 2>/dev/null | grep -vc '^#'); if [ \"$c\" -gt 0 ]; then echo $c; else getconf _NPROCESSORS_CONF; fi"))
            memory_kb = run_cmd(ssh, "dmidecode -t memory 2>/dev/null | awk '/^[[:space:]]*Size: [0-9]+ (MB|GB)/{if($3==\"GB\")s+=$2*1048576;else s+=$2*1024} END{if(s>0)print s}'")
            if not memory_kb:
                memory_kb = run_cmd(ssh, "awk '/MemTotal/{print $2}' /proc/meminfo")
            disk_bytes = run_cmd(ssh, "lsblk -bdno SIZE,TYPE 2>/dev/null | awk '$2==\"disk\"{print $1}'")
            hardware['memory'] = _format_memory_capacity(memory_kb)
            hardware['storage'] = _format_storage_capacity(disk_bytes)
            hardware['gpu'] = _format_gpu(run_cmd(ssh, "nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null || lspci 2>/dev/null | grep -Ei 'VGA|3D' | cut -d: -f3-"))
    except Exception as exc:
        return {'error': str(exc)[:200]}
    finally:
        ssh.close()
    return hardware


def _parse_hardware_number(value):
    """把"64 GB""2 TB""16 核"归一化成可比较的数值，无法解析时返回 None。"""
    match = re.fullmatch(r'(\d+(?:\.\d+)?)\s*(核|MB|GB|TB|GIB|TIB)?', str(value or '').strip())
    if not match:
        return None
    number = float(match.group(1))
    unit = (match.group(2) or '').upper()
    return number * 1000 if unit in ('TB', 'TIB') else number


def _hardware_value_changed(old_value, new_value):
    """容量类参数按数值比较（增减都算变化），其余按文本比较。"""
    if old_value == new_value:
        return False
    old_number = _parse_hardware_number(old_value)
    new_number = _parse_hardware_number(new_value)
    if old_number is not None and new_number is not None:
        return old_number != new_number
    return True


def _merge_hardware_values(existing, collected):
    """返回 (合并后的参数, 变化描述)。占位值不会覆盖最近一次的有效参数。"""
    values, changes = {}, []
    for field, label in HARDWARE_FIELDS:
        old_value = str((existing or {}).get(field) or '').strip()
        new_value = str(collected.get(field) or '').strip()
        recorded = bool(old_value) and old_value not in HARDWARE_PLACEHOLDERS
        if new_value in HARDWARE_PLACEHOLDERS:
            values[field] = old_value or '未知'
            continue
        if recorded and not _hardware_value_changed(old_value, new_value):
            values[field] = old_value
            continue
        values[field] = new_value
        if recorded:
            changes.append(f"{label} {old_value} → {new_value}")
    return values, changes


def record_server_hardware(server_id, collected, checked_at=None):
    """把一次采集结果并入记录：参数没变时只更新核对时间，不动最近一次参数。"""
    checked_at = checked_at or _now_text()
    existing = get_server_hardware(server_id) or {}
    values, changes = _merge_hardware_values(existing, collected)
    if not existing.get('collected_at'):
        save_server_hardware(server_id, values, collected_at=checked_at, checked_at=checked_at)
    elif changes:
        save_server_hardware(
            server_id, values, collected_at=checked_at, checked_at=checked_at,
            change_summary='；'.join(changes), changed_at=checked_at,
        )
    else:
        save_server_hardware(
            server_id, values, collected_at=existing.get('collected_at'), checked_at=checked_at,
            change_summary=existing.get('change_summary'), changed_at=existing.get('changed_at'),
        )
    snapshot = get_server_hardware(server_id)
    try:
        disks = models.list_disk_snapshots(server_id, 1)
        current = resource_audit.build_resource_payload(
            hardware=snapshot,
            disk_snapshot=(disks[0].get('payload') if disks else None),
        )
        resource_audit.evaluate_resource_configuration(server_id, current, checked_at)
    except Exception:
        logger.exception('服务器资源配置基线核对失败 server_id=%s', server_id)
    return snapshot


def refresh_server_hardware(raw_server, checked_at=None):
    """采集并写回一次硬件参数；采集失败时保留最近一次参数，只登记失败原因。"""
    checked_at = checked_at or _now_text()
    collected = collect_server_hardware(raw_server)
    if collected.get('error'):
        logger.warning("服务器硬件参数采集失败 %s: %s", raw_server.get('ip'), collected['error'])
        mark_server_hardware_check(raw_server['id'], collected['error'], checked_at)
        return get_server_hardware(raw_server['id'])
    return record_server_hardware(raw_server['id'], collected, checked_at)


def _hardware_record_missing(server_id):
    """尚无记录、且距离上次尝试已过重试间隔时才自动补采一次。"""
    snapshot = get_server_hardware(server_id) or {}
    if snapshot.get('collected_at'):
        return False
    checked_at = snapshot.get('checked_at')
    if not checked_at:
        return True
    retry_before = (datetime.now() - timedelta(seconds=SERVER_HARDWARE_RETRY_INTERVAL)).strftime(_TIME_FORMAT)
    return checked_at <= retry_before


def _server_details_payload(raw_server):
    """组装完整信息弹窗的数据：硬件参数取最近一次记录，不触发实时采集。"""
    group_map = {item['id']: item['name'] for item in list_groups()}
    server = {key: value for key, value in raw_server.items() if key not in ('enc_password', 'enc_private_key', 'enc_key_passphrase')}
    server['group_names'] = ', '.join(group_map.get(group_id, '') for group_id in server.get('group_ids', []) if group_map.get(group_id)) or '未设置环境'
    snapshot = get_server_hardware(raw_server['id']) or {}
    hardware = {field: (snapshot.get(field) or '未知') for field, _ in HARDWARE_FIELDS}
    return {
        'ok': True,
        'server': server,
        'hardware': hardware,
        'hardware_meta': {
            'recorded': bool(snapshot.get('collected_at')),
            'collected_at': snapshot.get('collected_at'),
            'checked_at': snapshot.get('checked_at'),
            'last_error': snapshot.get('last_error') or '',
            'change_summary': snapshot.get('change_summary') or '',
            'changed_at': snapshot.get('changed_at'),
        },
    }


@app.route("/api/servers/<int:server_id>/details", methods=["GET"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_server_details(server_id):
    raw_server = get_server(server_id)
    if not raw_server:
        return jsonify({"ok": False, "msg": "服务器不存在"}), 404
    # 只有"从未记录成功过"的服务器才顺带补采一次，之后一律返回最近一次参数。
    if _hardware_record_missing(server_id):
        refresh_server_hardware(raw_server)
    return jsonify(_server_details_payload(raw_server))


@app.route("/api/servers/<int:server_id>/details/refresh", methods=["POST"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_refresh_server_details(server_id):
    raw_server = get_server(server_id)
    if not raw_server:
        return jsonify({"ok": False, "msg": "服务器不存在"}), 404
    refresh_server_hardware(raw_server)
    payload = _server_details_payload(raw_server)
    payload['refreshed'] = True
    return jsonify(payload)

# --------- APIs: 服务信息表 ----------
SERVICE_TYPES = ("中间件", "应用服务", "数据库", "定时任务", "其他")
SERVICE_RUN_MODES = ("systemd", "docker", "supervisor", "脚本", "k8s", "其他")
SERVICE_STATUSES = ("运行中", "已停止", "已下线")
SERVICE_SECRET_TYPES = ("密码", "密钥", "免密", "其他")
SERVICE_ACCOUNT_LIMIT = 20
SERVICE_ACCOUNT_USERNAME_RE = re.compile(r'[A-Za-z0-9_.@\\$-]{1,64}')

# 审计只记录"改了哪些字段"，绝不记录字段值：启停命令里常内嵌密码。
SERVICE_FIELD_LABELS = {
    "name": "服务名称", "server_id": "IP地址", "service_type": "服务类型",
    "run_mode": "运行方式", "version": "版本号", "deploy_dir": "部署目录",
    "start_command": "启动命令", "stop_command": "停止命令", "restart_command": "重启命令",
    "ports": "端口信息", "config_path": "配置文件路径", "log_path": "日志路径",
    "access_url": "访问地址", "owner": "负责人", "status": "服务状态",
    "auto_start": "开机自启", "notes": "备注",
}


def _clean_id_list(raw_ids, dictionary, label):
    if raw_ids in (None, ""):
        return []
    if not isinstance(raw_ids, list):
        raise ValueError(f"{label}格式无效")
    valid_ids = {item["id"] for item in dictionary}
    cleaned = []
    for raw_id in raw_ids:
        try:
            item_id = int(raw_id)
        except (TypeError, ValueError):
            raise ValueError(f"{label}格式无效")
        if item_id not in valid_ids:
            raise ValueError(f"{label}不存在")
        if item_id not in cleaned:
            cleaned.append(item_id)
    return cleaned


def _clean_accounts(raw_accounts):
    """校验账号行，返回含明文密码的中间结构；密文在落库前才生成。"""
    if raw_accounts in (None, ""):
        return []
    if not isinstance(raw_accounts, list):
        raise ValueError("账号信息格式无效")
    if len(raw_accounts) > SERVICE_ACCOUNT_LIMIT:
        raise ValueError(f"单个服务的账号数量不能超过 {SERVICE_ACCOUNT_LIMIT} 个")

    accounts = []
    for row in raw_accounts:
        if not isinstance(row, dict):
            raise ValueError("账号信息格式无效")
        account_id = row.get("id")
        if account_id in (None, ""):
            account_id = None
        else:
            try:
                account_id = int(account_id)
            except (TypeError, ValueError):
                raise ValueError("账号ID无效")
        purpose = str(row.get("purpose", "") or "").strip()
        username = str(row.get("username", "") or "").strip()
        secret_type = str(row.get("secret_type", "") or "").strip() or "密码"
        # 强制转字符串：客户端可能把纯数字密码发成 JSON number，直接 len() 会抛 TypeError。
        password = str(row.get("password", "") or "")
        remark = str(row.get("remark", "") or "").strip()
        if not is_safe_display_text(purpose, 50):
            raise ValueError("账号用途不能超过50个字符或包含非法字符")
        if not SERVICE_ACCOUNT_USERNAME_RE.fullmatch(username):
            raise ValueError(f"账号 {username or '(未填写)'} 格式无效：只允许字母、数字和 _ . - @ \\ $")
        if secret_type not in SERVICE_SECRET_TYPES:
            raise ValueError("账号类型无效")
        # 密码可能含任意符号，用技术文本校验（只挡控制字符）。
        if not is_safe_tech_text(password, 1024):
            raise ValueError("账号密码过长或包含非法字符")
        if not is_safe_display_text(remark, 200):
            raise ValueError("账号备注包含非法字符")
        accounts.append({
            "id": account_id, "purpose": purpose, "username": username,
            "secret_type": secret_type, "password": password, "remark": remark,
        })
    return accounts


def _encrypt_account_rows(accounts):
    """把明文密码转成落库结构。密码留空且带 id 时表示保留已存密文。"""
    key = load_aes_key()
    rows = []
    for account in accounts:
        enc_password = None
        if account["password"]:
            enc_password = aes_gcm_encrypt(key, account["password"])
        elif account["id"] is None and account["secret_type"] == "密码":
            raise ValueError(f"账号 {account['username']} 未填写密码")
        rows.append({
            "id": account["id"], "purpose": account["purpose"], "username": account["username"],
            "secret_type": account["secret_type"], "enc_password": enc_password,
            "remark": account["remark"],
        })
    return rows


def validate_service_payload(data):
    name = str(data.get("name", "") or "").strip()
    try:
        server_id = int(data.get("server_id"))
    except (TypeError, ValueError):
        raise ValueError("请选择所属服务器")
    service_type = str(data.get("service_type", "") or "").strip() or "应用服务"
    run_mode = str(data.get("run_mode", "") or "").strip() or "systemd"
    version = str(data.get("version", "") or "").strip()
    deploy_dir = str(data.get("deploy_dir", "") or "").strip()
    start_command = str(data.get("start_command", "") or "").strip()
    stop_command = str(data.get("stop_command", "") or "").strip()
    restart_command = str(data.get("restart_command", "") or "").strip()
    ports = str(data.get("ports", "") or "").strip()
    config_path = str(data.get("config_path", "") or "").strip()
    log_path = str(data.get("log_path", "") or "").strip()
    access_url = str(data.get("access_url", "") or "").strip()
    owner = str(data.get("owner", "") or "").strip()
    status = str(data.get("status", "") or "").strip() or "运行中"
    notes = str(data.get("notes", "") or "")
    auto_start = 1 if data.get("auto_start") in (1, "1", True, "true", "on") else 0

    if not name or not is_safe_display_text(name, 100):
        raise ValueError("服务名称不能为空或包含非法字符")
    if not get_server(server_id):
        raise ValueError("所选服务器不存在")
    if service_type not in SERVICE_TYPES:
        raise ValueError("服务类型无效")
    if run_mode not in SERVICE_RUN_MODES:
        raise ValueError("运行方式无效")
    if not is_safe_display_text(version, 50):
        raise ValueError("版本号包含非法字符")
    for label, value in (("部署目录", deploy_dir), ("配置文件路径", config_path), ("日志路径", log_path)):
        if not is_safe_tech_text(value, 200):
            raise ValueError(f"{label}不能超过200个字符或包含非法字符")
    for label, value in (("启动命令", start_command), ("停止命令", stop_command), ("重启命令", restart_command)):
        if not is_safe_tech_text(value, 500):
            raise ValueError(f"{label}不能超过500个字符或包含非法字符")
    if not is_safe_tech_text(ports, 200):
        raise ValueError("端口信息不能超过200个字符或包含非法字符")
    if access_url and (not access_url.lower().startswith(("http://", "https://")) or not is_safe_tech_text(access_url, 200)):
        raise ValueError("访问地址必须以 http:// 或 https:// 开头，且不超过200个字符")
    if not is_safe_display_text(owner, 50):
        raise ValueError("负责人包含非法字符")
    if status not in SERVICE_STATUSES:
        raise ValueError("服务状态无效")
    if not is_safe_display_text(notes, 500):
        raise ValueError("备注包含非法字符")

    system_ids = _clean_id_list(data.get("system_ids"), list_service_systems(), "归属系统")
    environment_ids = _clean_id_list(data.get("environment_ids"), list_service_environments(), "归属环境")

    values = {
        "name": name, "server_id": server_id, "service_type": service_type,
        "run_mode": run_mode, "version": version, "deploy_dir": deploy_dir,
        "start_command": start_command, "stop_command": stop_command,
        "restart_command": restart_command, "ports": ports, "config_path": config_path,
        "log_path": log_path, "access_url": access_url, "owner": owner,
        "status": status, "auto_start": auto_start, "notes": notes,
    }
    return values, system_ids, environment_ids


def _describe_service_changes(existing, values, accounts_provided, account_count,
                              system_ids=(), environment_ids=()):
    def text(value):
        return '' if value is None else str(value)

    changed = [
        label for field, label in SERVICE_FIELD_LABELS.items()
        if text(existing.get(field)) != text(values.get(field))
    ]
    # 归属是多对多，不在 SERVICE_FIELD_LABELS 里；漏掉会让"只改了归属"的编辑被记成"无字段变化"。
    if set(existing.get("system_ids") or ()) != set(system_ids):
        changed.append("归属系统")
    if set(existing.get("environment_ids") or ()) != set(environment_ids):
        changed.append("归属环境")
    if accounts_provided:
        changed.append(f"账号信息({account_count}条)")
    return '、'.join(changed) if changed else '无字段变化'


@app.route("/api/services/export", methods=["GET"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_export_services():
    filters = {}
    try:
        for arg in ("server_id", "system_id", "environment_id"):
            raw = request.args.get(arg)
            if raw:
                filters[arg] = int(raw)
        selected_fields = select_export_fields(SERVICE_EXPORT_FIELDS, _requested_export_fields())
    except ValueError as exc:
        return jsonify({"ok": False, "msg": str(exc)}), 400

    services = list_services(
        server_id=filters.get("server_id"),
        system_id=filters.get("system_id"),
        environment_id=filters.get("environment_id"),
        service_type=(request.args.get("service_type") or "").strip(),
        status=(request.args.get("status") or "").strip(),
    )
    rows = sanitize_services_for_client(
        filter_services_by_keyword(services, request.args.get("keyword"))
    )
    labels = '、'.join(item['label'] for item in selected_fields)
    record_audit(
        session.get('username'), 'service.export', result='ok',
        target_type='service', target_name='服务信息表',
        detail=f'导出 {len(rows)} 条；字段={labels}', client_ip=request.remote_addr or '',
    )
    filename = f'服务信息表_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    return send_file(
        build_asset_export_excel('服务信息表', '服务信息表', rows, selected_fields),
        as_attachment=True, download_name=filename,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    )


@app.route("/api/services", methods=["GET", "POST", "PUT", "DELETE"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_services():
    if request.method == "GET":
        filters = {}
        for arg in ("server_id", "system_id", "environment_id"):
            raw = request.args.get(arg)
            if not raw:
                continue
            try:
                filters[arg] = int(raw)
            except ValueError:
                return jsonify({"ok": False, "msg": f"{arg} 参数无效"}), 400
        services = list_services(
            server_id=filters.get("server_id"),
            system_id=filters.get("system_id"),
            environment_id=filters.get("environment_id"),
            service_type=(request.args.get("service_type") or "").strip(),
            status=(request.args.get("status") or "").strip(),
        )
        services = filter_services_by_keyword(services, request.args.get("keyword"))
        return jsonify(sanitize_services_for_client(services))

    if request.method == "POST":
        data = request.json or {}
        try:
            values, system_ids, environment_ids = validate_service_payload(data)
            accounts = _encrypt_account_rows(_clean_accounts(data.get("accounts")))
            service_id = add_service(values, system_ids, environment_ids, accounts,
                                     created_by=session.get('username') or '')
        except ValueError as exc:
            return jsonify({"ok": False, "msg": str(exc)}), 400
        except sqlite3.IntegrityError:
            return jsonify({"ok": False, "msg": "该服务器下已存在同名服务"}), 400
        record_audit(session.get('username'), "service.create", result="ok", target_type="service",
                     target_id=service_id, target_name=values["name"], client_ip=request.remote_addr or '')
        return jsonify({"ok": True, "id": service_id})

    if request.method == "PUT":
        data = request.json or {}
        try:
            service_id = int(data.get("id"))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "msg": "服务信息ID无效"}), 400
        existing = get_service(service_id)
        if not existing:
            return jsonify({"ok": False, "msg": "服务信息不存在"}), 404
        # 未提交 accounts 键 = 不涉及账号，必须保持账号原状，否则会静默清空凭据。
        accounts_provided = "accounts" in data
        try:
            values, system_ids, environment_ids = validate_service_payload(data)
            accounts = _encrypt_account_rows(_clean_accounts(data.get("accounts"))) if accounts_provided else None
            if not update_service(service_id, values, system_ids, environment_ids, accounts, accounts_provided):
                return jsonify({"ok": False, "msg": "服务信息不存在"}), 404
        except ValueError as exc:
            return jsonify({"ok": False, "msg": str(exc)}), 400
        except sqlite3.IntegrityError:
            return jsonify({"ok": False, "msg": "该服务器下已存在同名服务"}), 400
        record_audit(
            session.get('username'), "service.update", result="ok", target_type="service",
            target_id=service_id, target_name=values["name"], client_ip=request.remote_addr or '',
            detail=_describe_service_changes(existing, values, accounts_provided, len(accounts or []),
                                             system_ids, environment_ids),
        )
        return jsonify({"ok": True})

    try:
        service_id = int(request.args.get("id"))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "msg": "服务信息ID无效"}), 400
    existing = get_service(service_id)
    if not existing:
        return jsonify({"ok": False, "msg": "服务信息不存在"}), 404
    delete_service(service_id)
    record_audit(session.get('username'), "service.delete", result="ok", target_type="service",
                 target_id=service_id, target_name=existing.get("name", ""), client_ip=request.remote_addr or '')
    return jsonify({"ok": True})


@app.route("/api/services/<int:service_id>", methods=["GET"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_service_detail(service_id):
    service = get_service(service_id)
    if not service:
        return jsonify({"ok": False, "msg": "服务信息不存在"}), 404
    return jsonify({"ok": True, "service": sanitize_service_for_client(service)})


@app.route("/api/services/<int:service_id>/accounts/reveal", methods=["POST"])
@no_cache
@login_required
@role_required(SERVICE_REVEAL_ROLES)
def api_reveal_service_accounts(service_id):
    """查看服务账号信息：必须重新验证当前登录用户的密码，成功与失败均留审计。"""
    service = get_service(service_id)
    if not service:
        return jsonify({"ok": False, "msg": "服务信息不存在"}), 404
    if _is_reveal_locked():
        return jsonify({"ok": False, "msg": "验证失败次数过多，请15分钟后重试"}), 429

    username = session.get('username')
    supplied = (request.json or {}).get("password", "") or ""
    user = get_user(username)
    password_ok = bool(supplied) and bool(user) and verify_password(user['password'], supplied)[0]
    if not password_ok:
        _record_reveal_failure()
        record_audit(username, "service.reveal_account", result="denied", target_type="service",
                     target_id=service_id, target_name=service.get("name", ""),
                     client_ip=request.remote_addr or '')
        # 统一文案，不区分用户不存在与密码错误。
        return jsonify({"ok": False, "msg": "当前登录密码不正确"}), 403

    _clear_reveal_failures()
    key = load_aes_key()
    accounts = []
    for row in get_service_accounts(service_id):
        password = None
        item = {
            "id": row["id"], "purpose": row.get("purpose") or "",
            "username": row.get("username") or "", "secret_type": row.get("secret_type") or "密码",
            "remark": row.get("remark") or "", "password": None,
        }
        if row.get("enc_password"):
            try:
                password = aes_gcm_decrypt(key, row["enc_password"])
            except Exception:
                item["error"] = "解密失败"
            item["password"] = password
        accounts.append(item)

    record_audit(username, "service.reveal_account", result="ok", target_type="service",
                 target_id=service_id, target_name=service.get("name", ""),
                 detail=f"共 {len(accounts)} 个账号", client_ip=request.remote_addr or '')
    return jsonify({"ok": True, "expires_in": REVEAL_HIDE_SECONDS, "accounts": accounts})


def _service_dict_api(fetch_list, add_item, delete_item, label):
    if request.method == "GET":
        return jsonify(fetch_list())
    if request.method == "POST":
        name = ((request.json or {}).get("name") or "").strip()
        if not name:
            return jsonify({"ok": False, "msg": "名称不能为空"}), 400
        if not is_safe_display_text(name, 50):
            return jsonify({"ok": False, "msg": f"{label}名称不能超过50个字符或包含非法字符"}), 400
        add_item(name)
        record_audit(session.get('username'), "service_dict.add", result="ok", target_type=label,
                     target_name=name, client_ip=request.remote_addr or '')
        return jsonify({"ok": True})
    try:
        item_id = int(request.args.get("id"))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "msg": f"{label}ID无效"}), 400
    delete_item(item_id)
    record_audit(session.get('username'), "service_dict.delete", result="ok", target_type=label,
                 target_id=item_id, client_ip=request.remote_addr or '')
    return jsonify({"ok": True})


@app.route("/api/service_systems", methods=["GET", "POST", "DELETE"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_service_systems():
    return _service_dict_api(list_service_systems, add_service_system, delete_service_system, "系统项")


@app.route("/api/service_environments", methods=["GET", "POST", "DELETE"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_service_environments():
    return _service_dict_api(list_service_environments, add_service_environment, delete_service_environment, "环境项")


@app.route("/api/audit_logs", methods=["GET"])
@no_cache
@login_required
@role_required(['admin'])
def api_audit_logs():
    advanced_args = {
        "page", "page_size", "username", "action", "result", "keyword",
        "start_time", "end_time",
    }
    # 保留旧接口 `?limit=N` 的响应行为，供已有工具与调用方继续使用。
    if not any(name in request.args for name in advanced_args):
        try:
            limit = int(request.args.get("limit", 200))
        except (TypeError, ValueError):
            limit = 200
        return jsonify({"ok": True, "logs": list_audit_logs(limit)})
    try:
        page = int(request.args.get("page", 1))
        page_size = int(request.args.get("page_size", 50))
        start_time = _operation_audit_time_arg("start_time")
        end_time = _operation_audit_time_arg("end_time", end_of_day=True)
        if start_time and end_time and start_time > end_time:
            raise ValueError("开始时间不能晚于结束时间")
        keyword = str(request.args.get("keyword", "") or "").strip()
        if len(keyword) > 200:
            raise ValueError("关键词不能超过 200 个字符")
        data = models.query_audit_logs(
            username=str(request.args.get("username", "") or "").strip(),
            action=str(request.args.get("action", "") or "").strip(),
            result=str(request.args.get("result", "") or "").strip(),
            keyword=keyword,
            start_time=start_time,
            end_time=end_time,
            page=page,
            page_size=page_size,
        )
    except (TypeError, ValueError) as exc:
        return jsonify({"ok": False, "msg": str(exc) or "查询参数不正确"}), 400
    return jsonify({"ok": True, "logs": data["rows"], **data})

# ------------- Reports -------------
def _probe_server_health(server):
    """执行一次短超时 SSH 探测，并安全更新内存状态。"""
    server_id = server['id']
    now = time.time()
    ok, error = False, ''
    ssh = create_ssh_client()
    try:
        credentials = decrypt_server_credentials(load_aes_key(), server)
        connect_ssh(
            ssh, server['ip'], server['port'], server['username'],
            password=credentials.get('password'),
            private_key=credentials.get('private_key'),
            key_passphrase=credentials.get('key_passphrase'),
            timeout=8,
        )
        ok = True
    except Exception as exc:
        error = str(exc)[:160]
    finally:
        ssh.close()

    with _server_health_lock:
        state = _server_health.setdefault(server_id, {'first_seen': now, 'last_success': None})
        state['last_check'] = now
        state['checking'] = False
        state['last_error'] = '' if ok else error
        if ok:
            state['last_success'] = now


def refresh_server_health():
    servers = list_servers()
    now = time.time()
    active_ids = {server['id'] for server in servers}
    with _server_health_lock:
        for server in servers:
            state = _server_health.setdefault(server['id'], {'first_seen': now, 'last_success': None})
            state['checking'] = True
        for server_id in list(_server_health):
            if server_id not in active_ids:
                _server_health.pop(server_id, None)

    if not servers:
        return
    with ThreadPoolExecutor(max_workers=min(8, len(servers)), thread_name_prefix='health-probe') as pool:
        futures = [pool.submit(_probe_server_health, server) for server in servers]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                logger.exception('服务器健康探测线程异常')


def run_server_health_monitor():
    logger.info('可视化大屏服务器健康监测线程启动')
    while True:
        started = time.time()
        try:
            refresh_server_health()
        except Exception:
            logger.exception('服务器健康监测周期异常')
        time.sleep(max(1, SERVER_HEALTH_INTERVAL - (time.time() - started)))


def start_server_health_monitor():
    global _server_health_thread
    with _server_health_thread_lock:
        if _server_health_thread and _server_health_thread.is_alive():
            return _server_health_thread
        _server_health_thread = threading.Thread(
            target=run_server_health_monitor, daemon=True, name='server-health-monitor'
        )
        _server_health_thread.start()
        return _server_health_thread


def _hardware_refresh_due(snapshot, stale_before, retry_before):
    """没有记录过的服务器按重试间隔核对，记录过的按刷新周期核对。"""
    if not snapshot or not snapshot.get('checked_at'):
        return True
    if not snapshot.get('collected_at'):
        return snapshot['checked_at'] <= retry_before
    return snapshot['checked_at'] <= stale_before


def refresh_stale_server_hardware():
    """后台核对硬件参数：只重新采集"尚未记录"或"记录已过期"的服务器。"""
    servers = list_servers()
    if not servers:
        return 0
    snapshots = list_server_hardware_snapshots()
    now = datetime.now()
    stale_before = (now - timedelta(seconds=SERVER_HARDWARE_INTERVAL)).strftime(_TIME_FORMAT)
    retry_before = (now - timedelta(seconds=SERVER_HARDWARE_RETRY_INTERVAL)).strftime(_TIME_FORMAT)
    targets = [
        server for server in servers
        if _hardware_refresh_due(snapshots.get(server['id']), stale_before, retry_before)
    ]
    if not targets:
        return 0
    with ThreadPoolExecutor(max_workers=min(4, len(targets)), thread_name_prefix='hardware-collect') as pool:
        futures = [pool.submit(refresh_server_hardware, server) for server in targets]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                logger.exception('服务器硬件参数采集线程异常')
    return len(targets)


def run_server_hardware_monitor():
    logger.info('服务器硬件参数核对线程启动')
    while True:
        started = time.time()
        try:
            refresh_stale_server_hardware()
        except Exception:
            logger.exception('服务器硬件参数核对周期异常')
        time.sleep(max(5, SERVER_HARDWARE_POLL_INTERVAL - (time.time() - started)))


def start_server_hardware_monitor():
    global _server_hardware_thread
    with _server_hardware_thread_lock:
        if _server_hardware_thread and _server_hardware_thread.is_alive():
            return _server_hardware_thread
        _server_hardware_thread = threading.Thread(
            target=run_server_hardware_monitor, daemon=True, name='server-hardware-monitor'
        )
        _server_hardware_thread.start()
        return _server_hardware_thread


@app.route("/api/dashboard/status", methods=["GET"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_dashboard_status():
    start_server_health_monitor()
    servers = list_servers()
    now = time.time()
    items = []
    with _server_health_lock:
        states = {key: dict(value) for key, value in _server_health.items()}
    for server in servers:
        state = states.get(server['id'], {})
        last_success = state.get('last_success')
        reference = last_success or state.get('first_seen') or now
        if last_success and now - last_success <= SERVER_OFFLINE_AFTER:
            status = 'online'
        elif now - reference > SERVER_OFFLINE_AFTER:
            status = 'offline'
        else:
            status = 'checking'
        items.append({
            'id': server['id'], 'ip': server['ip'], 'port': server['port'],
            'name': server.get('name') or server['ip'],
            'groups': server.get('group_names') or '未设置环境',
            'room_ids': [group.get('id') for group in server.get('groups', [])],
            'rooms': [group.get('name') for group in server.get('groups', [])],
            'rack_number': server.get('rack_number') or '',
            'room_affiliation': server.get('room_affiliation') or '',
            'rack_level': server.get('rack_level') or '',
            'resource_type': server.get('resource_type') or '',
            'physical_ip': server.get('physical_ip') or '',
            'status': status, 'checking': bool(state.get('checking')),
            'last_success': datetime.fromtimestamp(last_success).strftime('%Y-%m-%d %H:%M:%S') if last_success else None,
        })
    counts = {key: sum(1 for item in items if item['status'] == key) for key in ('online', 'offline', 'checking')}
    return jsonify({'servers': items, 'counts': counts, 'total': len(items),
                    'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'offline_after': SERVER_OFFLINE_AFTER})


@app.route("/api/reports", methods=["GET"])
@no_cache
@login_required
def api_list_reports():
    """获取报告列表"""
    reports = []
    report_dir = os.path.join(os.path.dirname(__file__), 'reports')
    
    if os.path.exists(report_dir):
        for filename in os.listdir(report_dir):
            if filename.endswith('.xlsx') or filename.endswith('.pdf'):
                filepath = os.path.join(report_dir, filename)
                mtime = os.path.getmtime(filepath)
                mtime_str = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                reports.append({
                    'filename': filename,
                    'mtime': mtime_str
                })
    
    # 按时间倒序排列
    reports.sort(key=lambda x: x['mtime'], reverse=True)
    return jsonify(reports)

@app.route("/api/reports/<path:filename>", methods=["DELETE"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_delete_report(filename):
    """删除报告"""
    filepath = safe_report_path(filename)
    if not filepath:
        return jsonify({'message': '非法路径'}), 400
    
    if not os.path.exists(filepath):
        return jsonify({'message': '文件不存在'}), 404
    
    try:
        os.remove(filepath)
        logger.info(f"报告已删除: {filename}")
        return jsonify({'message': '删除成功'}), 200
    except Exception as e:
        logger.error(f"删除报告失败: {e}")
        return jsonify({'message': f'删除失败: {str(e)}'}), 500

@app.route("/download/<path:filename>")
@login_required
def download_report(filename):
    """下载报告文件"""
    filepath = safe_report_path(filename)
    if not filepath or not os.path.exists(filepath):
        return jsonify({"error": "文件不存在"}), 404
    return send_file(filepath, as_attachment=True)

@app.route("/api/preview_report/<path:filename>")
@login_required
def preview_report(filename):
    """在线预览报告文件"""
    filepath = safe_report_path(filename)
    if not filepath or not os.path.exists(filepath):
        return jsonify({"error": "文件不存在"}), 404
    
    ext = filename.split('.')[-1].lower()
    if ext == 'pdf':
        return send_file(filepath, mimetype='application/pdf')
    elif ext == 'xlsx':
        return send_file(filepath, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    return jsonify({"error": "不支持的文件类型"}), 400

# ------------- Inspection Tasks -------------
def parse_inspection_thresholds(data):
    """读取并校验任务级资源告警阈值。"""
    values = {}
    fields = (
        ("cpu_threshold", "CPU", CPU_THRESHOLD),
        ("mem_threshold", "内存", MEM_THRESHOLD),
        ("disk_threshold", "磁盘", DISK_THRESHOLD),
    )
    for field, label, default_value in fields:
        raw_value = data.get(field, default_value)
        if raw_value in (None, ""):
            raw_value = default_value
        try:
            value = float(raw_value)
        except (TypeError, ValueError):
            raise ValueError(f"{label}阈值必须是数字")
        if not math.isfinite(value) or value < 1 or value > 100:
            raise ValueError(f"{label}阈值必须在 1% 到 100% 之间")
        values[field] = value
    return values


@app.route("/api/save_task", methods=["POST"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_save_task():
    data = request.json or {}
    task_name = data.get("task_name", "")
    project_name = data.get("project_name", "")
    inspector = data.get("inspector", "")
    report_format = data.get("report_format", "excel")
    resource_group_id = data.get("resource_group_id")
    check_cpu = data.get("check_cpu", True)
    check_mem = data.get("check_mem", True)
    check_disk = data.get("check_disk", True)
    enable_proxy = data.get("enable_proxy", False)
    proxy_rules = data.get("proxy_rules", [])
    enable_schedule = data.get("enable_schedule", False)
    schedule_time = data.get("schedule_time", "")
    try:
        thresholds = parse_inspection_thresholds(data)
    except ValueError as exc:
        return jsonify({"ok": False, "msg": str(exc)}), 400
    
    if not task_name:
        return jsonify({"ok": False, "msg": "请输入任务名称"}), 400
    if not project_name:
        return jsonify({"ok": False, "msg": "请输入项目名称"}), 400
    if not inspector:
        return jsonify({"ok": False, "msg": "请输入巡检人"}), 400
    
    add_inspection_task(
        name=task_name,
        project_name=project_name,
        inspector=inspector,
        report_format=report_format,
        resource_group_id=resource_group_id,
        check_cpu=check_cpu,
        check_mem=check_mem,
        check_disk=check_disk,
        enable_proxy=enable_proxy,
        proxy_rules=proxy_rules,
        enable_schedule=enable_schedule,
        schedule_time=schedule_time,
        **thresholds,
    )
    
    return jsonify({"ok": True, "msg": "任务保存成功"})


@app.route("/api/task", methods=["GET"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_get_task():
    task_id = request.args.get("id")
    if not task_id:
        return jsonify({"ok": False, "msg": "缺少任务ID"}), 400
    
    task = get_inspection_task(task_id)
    if not task:
        return jsonify({"ok": False, "msg": "任务不存在"}), 404
    
    return jsonify(task)


@app.route("/api/update_task", methods=["POST"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_update_task():
    data = request.json or {}
    task_id = data.get("id")
    task_name = data.get("task_name", "")
    project_name = data.get("project_name", "")
    inspector = data.get("inspector", "")
    report_format = data.get("report_format", "excel")
    resource_group_id = data.get("resource_group_id")
    check_cpu = data.get("check_cpu", True)
    check_mem = data.get("check_mem", True)
    check_disk = data.get("check_disk", True)
    enable_proxy = data.get("enable_proxy", False)
    proxy_rules = data.get("proxy_rules", [])
    enable_schedule = data.get("enable_schedule", False)
    schedule_time = data.get("schedule_time", "")
    try:
        thresholds = parse_inspection_thresholds(data)
    except ValueError as exc:
        return jsonify({"ok": False, "msg": str(exc)}), 400
    
    if not task_id:
        return jsonify({"ok": False, "msg": "缺少任务ID"}), 400
    if not task_name:
        return jsonify({"ok": False, "msg": "请输入任务名称"}), 400
    if not project_name:
        return jsonify({"ok": False, "msg": "请输入项目名称"}), 400
    if not inspector:
        return jsonify({"ok": False, "msg": "请输入巡检人"}), 400
    
    task = get_inspection_task(task_id)
    if not task:
        return jsonify({"ok": False, "msg": "任务不存在"}), 404
    
    update_inspection_task(
        task_id=task_id,
        name=task_name,
        project_name=project_name,
        inspector=inspector,
        report_format=report_format,
        resource_group_id=resource_group_id,
        check_cpu=check_cpu,
        check_mem=check_mem,
        check_disk=check_disk,
        enable_proxy=enable_proxy,
        proxy_rules=proxy_rules,
        enable_schedule=enable_schedule,
        schedule_time=schedule_time,
        **thresholds,
    )
    
    return jsonify({"ok": True, "msg": "任务更新成功"})


@app.route("/api/toggle_schedule", methods=["POST"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_toggle_schedule():
    data = request.json or {}
    task_id = data.get("id")
    
    if not task_id:
        return jsonify({"ok": False, "msg": "缺少任务ID"}), 400
    
    task = get_inspection_task(task_id)
    if not task:
        return jsonify({"ok": False, "msg": "任务不存在"}), 404
    
    state = toggle_task_schedule(task_id)
    if not state:
        return jsonify({"ok": False, "msg": "任务不存在"}), 404
    return jsonify({"ok": True, "msg": "定时状态已切换", **state})

@app.route("/api/run_task", methods=["POST"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_run_task():
    data = request.json or {}
    task_id = data.get("task_id")
    
    task = get_inspection_task(task_id)
    if not task:
        return jsonify({"ok": False, "msg": "任务不存在"}), 404
    
    run_id, inserted = enqueue_inspection(
        task_name=task["name"],
        project_name=task["project_name"],
        inspector=task["inspector"],
        report_format=task["report_format"],
        resource_group_id=task["resource_group_id"],
        check_cpu=task["check_cpu"],
        check_mem=task["check_mem"],
        check_disk=task["check_disk"],
        cpu_threshold=task["cpu_threshold"],
        mem_threshold=task["mem_threshold"],
        disk_threshold=task["disk_threshold"],
        enable_proxy=task["enable_proxy"],
        proxy_rules=task["proxy_rules"],
        task_id=task_id,
        source='saved'
    )
    if not inserted:
        return jsonify({"ok": False, "msg": "任务入队失败"}), 500
    
    return jsonify({"ok": True, "run_id": run_id})

@app.route("/api/delete_task", methods=["POST"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_delete_task():
    data = request.json or {}
    task_id = data.get("task_id")
    
    task = get_inspection_task(task_id)
    if not task:
        return jsonify({"ok": False, "msg": "任务不存在"}), 404
    
    delete_inspection_task(task_id)
    return jsonify({"ok": True, "msg": "任务删除成功"})

# ------------- Start Inspection -------------
@app.route("/api/start_inspection", methods=["POST"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
def api_start_inspection():
    data = request.json or {}
    task_name = data.get("task_name", "").strip()
    project_name = data.get("project_name","")
    inspector = data.get("inspector","")
    report_format = data.get("report_format", "excel")
    
    # 资源巡检参数
    resource_group_id = data.get("resource_group_id")
    check_cpu = data.get("check_cpu", True)
    check_mem = data.get("check_mem", True)
    check_disk = data.get("check_disk", True)
    try:
        thresholds = parse_inspection_thresholds(data)
    except ValueError as exc:
        return jsonify({"ok": False, "msg": str(exc)}), 400
    
    # 网关代理检测参数 - 支持多条规则
    enable_proxy = data.get("enable_proxy", False)
    proxy_rules = data.get("proxy_rules", [])
    
    if not task_name:
        return jsonify({"ok": False, "msg": "请输入任务名称"}), 400

    run_id, inserted = enqueue_inspection(
        task_name=task_name,
        project_name=project_name,
        inspector=inspector,
        report_format=report_format,
        resource_group_id=resource_group_id,
        check_cpu=check_cpu,
        check_mem=check_mem,
        check_disk=check_disk,
        **thresholds,
        enable_proxy=enable_proxy,
        proxy_rules=proxy_rules,
        source='manual'
    )
    if not inserted:
        return jsonify({"ok": False, "msg": "任务入队失败"}), 500
    return jsonify({"ok": True, "run_id": run_id})


_queue_wakeup = threading.Event()
_queue_threads = []


def enqueue_inspection(task_name, project_name, inspector, report_format='excel',
                       resource_group_id=None, check_cpu=True, check_mem=True,
                       check_disk=True, cpu_threshold=CPU_THRESHOLD,
                       mem_threshold=MEM_THRESHOLD, disk_threshold=DISK_THRESHOLD,
                       enable_proxy=False, proxy_rules=None,
                       task_id=None, source='manual', dedupe_key=None):
    run_id = f"{datetime.now().strftime('%Y%m%d%H%M%S%f')}-{secrets.token_hex(3)}"
    payload = {
        'project_name': project_name,
        'inspector': inspector,
        'report_format': report_format,
        'resource_group_id': resource_group_id,
        'check_cpu': bool(check_cpu),
        'check_mem': bool(check_mem),
        'check_disk': bool(check_disk),
        'cpu_threshold': float(cpu_threshold),
        'mem_threshold': float(mem_threshold),
        'disk_threshold': float(disk_threshold),
        'enable_proxy': bool(enable_proxy),
        'proxy_rules': proxy_rules or [],
        'task_id': task_id,
        'task_name': task_name
    }
    inserted = create_inspection_run(
        run_id, task_name, source, payload, task_id=task_id,
        dedupe_key=dedupe_key, max_attempts=2
    )
    if inserted:
        update_progress(run_id, '任务已入队，等待执行', 0)
        _queue_wakeup.set()
    return run_id, inserted

def update_progress(run_id, message, percent, report_path=None):
    """更新巡检进度"""
    previous = inspection_progress.get(run_id) or {}
    logs = list(previous.get("logs") or [])
    if message and (not logs or logs[-1] != message):
        logs.append(message)
    inspection_progress[run_id] = {
        "message": message,
        "percent": percent,
        "report_path": report_path or previous.get("report_path"),
        "logs": logs[-500:]
    }
    update_inspection_run_progress(run_id, message, percent, report_path)
    # 保存进度到文件，防止服务器重启丢失
    save_progress(inspection_progress)

def get_servers_by_group_param(group_param):
    """根据环境项参数获取服务器列表"""
    if group_param == "" or group_param is None:
        return list_servers(None)
    elif str(group_param).isdigit():
        return list_servers(int(group_param))
    else:
        return list_servers(None)


def decrypt_server_credentials(key, server):
    if server.get("auth_type") == "key":
        return {
            "password": None,
            "private_key": aes_gcm_decrypt(key, server["enc_private_key"]),
            "key_passphrase": (
                aes_gcm_decrypt(key, server["enc_key_passphrase"])
                if server.get("enc_key_passphrase") else None
            ),
        }
    return {
        "password": aes_gcm_decrypt(key, server["enc_password"]),
        "private_key": None,
        "key_passphrase": None,
    }

def audit_server_disk(server_id, res):
    """把本次采集到的磁盘明细与历史基线比对，结论挂到 res["disk_findings"]。

    这是"只做加法"的检查：内部任何异常都只降级成一条提示并记日志，
    不会改 res["ok"]，也不会让巡检中断（否则一台好机器会被写成连接失败）。
    """
    try:
        baselines = get_disk_baselines(server_id)
        findings = compare_disk(baselines, res.get("disk_inventory"), res.get("disk_error"))
        snapshot = res.get("disk_inventory")
        resource_result = None
        if snapshot:
            hardware = get_server_hardware(server_id) or {}
            resource_payload = resource_audit.build_resource_payload(
                hardware=hardware, disk_snapshot=snapshot,
            )
            resource_result = resource_audit.evaluate_resource_configuration(
                server_id, resource_payload, datetime.now().strftime(_TIME_FORMAT),
            )
            # 结构变化已经被计划或人工基线认可时，不再让旧的趋势快照重复报结构异常；
            # 只过滤结构类，I/O、只读、阵列、inode 等真实故障始终保留。
            if resource_result.get('status') in ('normal', 'planned'):
                structural_categories = {
                    '磁盘变更', '磁盘容量异常', '磁盘掉盘', '磁盘未挂载', '磁盘消失',
                }
                findings = [
                    item for item in findings
                    if item.get('category') not in structural_categories
                ]
            resource_finding = resource_audit.result_finding(resource_result)
            if resource_finding:
                res["resource_findings"] = [resource_finding]
        res["disk_findings"] = findings
        for item in split_findings(findings)[0]:
            logger.warning("磁盘巡检发现异常 %s: 【%s】%s",
                           res.get("ip"), item.get("category"), item.get("text"))
        if snapshot:
            # 以本系统实际执行时间入库；payload 中的采样时间只作诊断信息，
            # 不能让目标机时钟漂移或测试固定时间破坏快照先后顺序。
            collected_at = datetime.now().strftime(_TIME_FORMAT)
            save_disk_snapshot(server_id, snapshot, collected_at, findings)
    except Exception:
        logger.exception("磁盘巡检比对失败（已忽略，不影响本次巡检结论）")
        res.setdefault("disk_findings", []).append({
            "severity": "info",
            "category": "磁盘检查",
            "text": "本次磁盘比对执行失败，已跳过（详见服务端日志）。",
        })
    finally:
        res.pop("disk_inventory", None)


def attach_open_resource_change(server_id, res):
    """把后台硬件核对产生的待确认变化带进本次巡检报告。"""
    if res.get('resource_findings'):
        return
    event = models.get_open_resource_change_event(server_id)
    if not event:
        return
    finding = resource_audit.result_finding({
        'status': event.get('status'),
        'changes': event.get('change_detail') or [],
        'event_id': event.get('id'),
    })
    if finding:
        res['resource_findings'] = [finding]


def run_inspection(run_id: str, project_name: str, inspector: str, report_format: str = "excel", 
                   resource_group_id=None, check_cpu=True, check_mem=True, check_disk=True,
                   cpu_threshold=CPU_THRESHOLD, mem_threshold=MEM_THRESHOLD,
                   disk_threshold=DISK_THRESHOLD,
                   enable_proxy=False, proxy_rules=None, task_id=None, task_name=None):
    key = load_aes_key()
    proxy_rules = proxy_rules or []
    
    # 资源巡检使用的环境项
    resource_servers = get_servers_by_group_param(resource_group_id)
    resource_total = len(resource_servers)
    rows = []
    proxy_results = []
    
    # 是否执行网关代理检测
    do_proxy_test = enable_proxy and len(proxy_rules) > 0
    
    # 计算总步骤数（服务器巡检 + 网关代理检测）
    total_steps = resource_total
    if do_proxy_test:
        # 每个规则的服务器数量总和
        for rule in proxy_rules:
            servers = get_servers_by_group_param(rule.get('group_id'))
            total_steps += len(servers)
    
    # 初始化进度
    update_progress(run_id, "开始资源巡检...", 0)
    
    current_step = 0
    
    # 服务器资源巡检
    for idx, s in enumerate(resource_servers, start=1):
        try:
            msg = f"连接 {s['ip']}... ({idx}/{resource_total})"
            update_progress(run_id, msg, int(current_step/max(total_steps,1)*100))
            socketio.emit("progress", {
                "run_id": run_id,
                "message": msg,
                "percent": int(current_step/max(total_steps,1)*100)
            })
            
            credentials = decrypt_server_credentials(key, s)
            res = inspect_server(
                s["ip"], s["port"], s["username"],
                check_cpu=check_cpu,
                check_mem=check_mem,
                check_disk=check_disk,
                **credentials,
            )
            # CPU 核数、内存总量属于资源配置基线。每次成功巡检都顺带核对一次，
            # 采集失败仅记录在硬件快照中，不能把原本成功的巡检改成连接失败。
            if res.get("ok") and (check_cpu or check_mem or check_disk):
                try:
                    refresh_server_hardware(s)
                except Exception:
                    logger.exception("巡检期间核对资源配置失败 %s", s.get("ip"))
            if check_disk and res.get("ok"):
                audit_server_disk(s["id"], res)
            if res.get("ok"):
                attach_open_resource_change(s["id"], res)
            rows.append(res)
            add_inspection_result(run_id, res)

            current_step += 1

            # 根据选择的巡检项显示结果
            result_parts = []
            if check_cpu:
                result_parts.append(f"CPU:{res['cpu']}%")
            if check_mem:
                result_parts.append(f"MEM:{res['mem']}%")
            if check_disk:
                result_parts.append(f"DISK:{res['disk']}%")
            
            msg = f"完成 {s['ip']}  {', '.join(result_parts)}"
            update_progress(run_id, msg, int(current_step/max(total_steps,1)*100))
            socketio.emit("progress", {
                "run_id": run_id,
                "message": msg,
                "percent": int(current_step/max(total_steps,1)*100)
            })
        except Exception as e:
            failed_result = {"ip": s["ip"], "ok": False, "error": str(e), "uptime":"", "cpu":0, "mem":0, "disk":0}
            rows.append(failed_result)
            add_inspection_result(run_id, failed_result)
            current_step += 1
            
            msg = f"失败 {s['ip']}: {e}"
            update_progress(run_id, msg, int(current_step/max(total_steps,1)*100))
            socketio.emit("progress", {
                "run_id": run_id,
                "message": msg,
                "percent": int(current_step/max(total_steps,1)*100)
            })
        time.sleep(0.2)

    # 顺手清理过期的磁盘快照（默认保留 90 天，异常不影响巡检）
    if check_disk:
        try:
            prune_disk_snapshots()
        except Exception:
            logger.exception("清理过期磁盘快照失败（已忽略）")

    # 网关代理检测 - 支持多条规则
    if do_proxy_test:
        update_progress(run_id, "开始网关代理检测...", int(current_step/max(total_steps,1)*100))
        socketio.emit("progress", {
            "run_id": run_id,
            "message": "开始网关代理检测...",
            "percent": int(current_step/max(total_steps,1)*100)
        })
        
        rule_index = 0
        for rule in proxy_rules:
            rule_index += 1
            rule_group_id = rule.get('group_id')
            curl_command = rule.get('curl_command', '')
            success_keyword = rule.get('success_keyword', '成功')
            
            proxy_servers = get_servers_by_group_param(rule_group_id)
            proxy_total = len(proxy_servers)
            
            for idx, s in enumerate(proxy_servers, start=1):
                try:
                    msg = f"检测代理 [{rule_index}] {s['ip']}... ({idx}/{proxy_total})"
                    update_progress(run_id, msg, int(current_step/max(total_steps,1)*100))
                    socketio.emit("progress", {
                        "run_id": run_id,
                        "message": msg,
                        "percent": int(current_step/max(total_steps,1)*100)
                    })
                    
                    credentials = decrypt_server_credentials(key, s)
                    res = test_proxy(
                        s["ip"], s["port"], s["username"],
                        curl_cmd=curl_command, success_keyword=success_keyword,
                        **credentials,
                    )
                    proxy_results.append(res)
                    
                    current_step += 1
                    status = "正常" if res["success"] else ("连接失败" if res["error"] else "异常")
                    msg = f"代理检测 [{rule_index}] {s['ip']}: {status}"
                    update_progress(run_id, msg, int(current_step/max(total_steps,1)*100))
                    socketio.emit("progress", {
                        "run_id": run_id,
                        "message": msg,
                        "percent": int(current_step/max(total_steps,1)*100)
                    })
                except Exception as e:
                    proxy_results.append({"ip": s["ip"], "success": False, "output": "", "error": str(e)})
                    current_step += 1
                    
                    msg = f"代理检测失败 [{rule_index}] {s['ip']}: {e}"
                    update_progress(run_id, msg, int(current_step/max(total_steps,1)*100))
                    socketio.emit("progress", {
                        "run_id": run_id,
                        "message": msg,
                        "percent": int(current_step/max(total_steps,1)*100)
                    })
                time.sleep(0.2)

    # 根据格式生成报告
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        if report_format == "pdf":
            # 延迟导入 PDF 生成模块
            from report_pdf import generate_pdf_report
            report_path = generate_pdf_report(
                project_name, inspector, date_str, rows, proxy_results,
                check_cpu, check_mem, check_disk, task_name,
                cpu_threshold=cpu_threshold, mem_threshold=mem_threshold,
                disk_threshold=disk_threshold,
            )
        else:
            report_path = generate_excel_report(
                project_name, inspector, date_str, rows, proxy_results,
                check_cpu, check_mem, check_disk, task_name,
                cpu_threshold=cpu_threshold, mem_threshold=mem_threshold,
                disk_threshold=disk_threshold,
            )
        
        msg = f"报告已生成: {os.path.basename(report_path)}"
        update_progress(run_id, msg, 100, report_path)
        socketio.emit("progress", {
            "run_id": run_id,
            "message": msg,
            "percent": 100,
            "report_path": report_path
        })
        _ai_maybe_auto_insight(run_id)
        return {"success": True, "report_path": report_path, "error": ""}
    except ImportError as e:
        msg = f"PDF报告生成失败: 需要安装 reportlab 库"
        update_progress(run_id, msg, 100)
        socketio.emit("progress", {
            "run_id": run_id,
            "message": msg,
            "percent": 100
        })
        logger.error(f"报告生成失败: {e}")
        return {"success": False, "report_path": None, "error": str(e)}
    except Exception as e:
        msg = f"报告生成失败: {str(e)}"
        update_progress(run_id, msg, 100)
        socketio.emit("progress", {
            "run_id": run_id,
            "message": msg,
            "percent": 100
        })
        logger.error(f"报告生成失败: {e}")
        return {"success": False, "report_path": None, "error": str(e)}


def queue_worker_loop(worker_index):
    logger.info("任务队列工作线程启动: worker-%s", worker_index)
    while True:
        job = claim_next_inspection_run()
        if not job:
            _queue_wakeup.wait(1)
            _queue_wakeup.clear()
            continue
        run_id = job['run_id']
        try:
            payload = json.loads(job['payload'])
            clear_inspection_results(run_id)
            if payload.get('task_id'):
                update_task_last_run(payload['task_id'])
            result = run_inspection(run_id=run_id, **payload)
            if result.get('success'):
                finish_inspection_run(run_id, result.get('report_path'))
            else:
                retry_or_fail_inspection_run(
                    run_id, result.get('error') or '报告生成失败', QUEUE_RETRY_DELAY
                )
                _queue_wakeup.set()
        except Exception as exc:
            logger.exception("队列任务执行异常 [%s]: %s", run_id, exc)
            retry_or_fail_inspection_run(run_id, str(exc), QUEUE_RETRY_DELAY)
            _queue_wakeup.set()


def start_queue_workers():
    if _queue_threads:
        return
    recovered = recover_interrupted_inspection_runs()
    if recovered:
        logger.warning("已恢复 %s 个中断的巡检任务", recovered)
    for index in range(QUEUE_WORKERS):
        worker = threading.Thread(
            target=queue_worker_loop,
            args=(index + 1,),
            daemon=True,
            name=f"inspection-queue-{index + 1}"
        )
        worker.start()
        _queue_threads.append(worker)
    _queue_wakeup.set()
    logger.info("持久化任务队列已启动，工作线程数: %s", QUEUE_WORKERS)

@app.route("/api/inspection_progress")
@no_cache
@login_required
def api_inspection_progress():
    run_id = request.args.get("run_id")
    if run_id:
        run = get_inspection_run(run_id)
        if run:
            live_progress = inspection_progress.get(run_id) or {}
            return jsonify({
                "message": run.get("message") or "",
                "percent": run.get("progress") or 0,
                "report_path": run.get("report_path"),
                "status": run.get("status"),
                "error": run.get("error"),
                "logs": live_progress.get("logs") or []
            })
    if run_id and run_id in inspection_progress:
        return jsonify(inspection_progress[run_id])
    return jsonify({"message": "", "percent": 0})


@app.route("/api/inspection_runs")
@no_cache
@login_required
def api_inspection_runs():
    runs = list_inspection_runs(request.args.get("limit", 50))
    for run in runs:
        run.pop('report_path', None)
    return jsonify(runs)

@app.route("/api/download_report")
@no_cache
@login_required
def api_download_report():
    path = request.args.get("path")
    path = safe_report_path(path)
    if not path or not os.path.exists(path):
        return "Not Found", 404
    return send_file(path, as_attachment=True)

# ---------------- AI 智能运维 ----------------
# 页面、接口、工具执行体。设计见 docs/AI智能运维方案.md。
# 三条底线：Key 只进不出（永不回显明文）、只认结构化 tool_calls、
# 有副作用的动作一律先落 ai_actions 等人工确认。
AI_PROVIDER_DEPLOYMENTS = ("local", "cloud")


def ai_api(f):
    """把 AiServiceError 统一转成 JSON 响应。"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ai_service.AiServiceError as exc:
            return jsonify({'ok': False, 'success': False, 'message': str(exc)}), exc.status
    return wrapper


def _ai_actor():
    return session.get('username', ''), session.get('role', '')


def _ai_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()


def _ai_json(data, status=200):
    return jsonify(data), status


def _ai_provider_public(row, full=False):
    """provider → 前端。任何情况下都不含 enc_api_key。"""
    item = {
        'id': row.get('id'),
        'name': row.get('name') or '',
        'model': row.get('model') or '',
        'deployment': row.get('deployment') or 'cloud',
        'enabled': bool(row.get('enabled')),
        'is_default': bool(row.get('is_default')),
        'supports_tools': bool(row.get('supports_tools')),
        'has_key': bool(row.get('enc_api_key')),
        'last_test_at': row.get('last_test_at'),
        'last_test_ok': None if row.get('last_test_ok') is None else bool(row.get('last_test_ok')),
        'last_test_error': row.get('last_test_error') or '',
    }
    if not full:
        return item
    item.update({
        'base_url': row.get('base_url') or '',
        'temperature': row.get('temperature'),
        'max_tokens': row.get('max_tokens'),
        'timeout': row.get('timeout'),
        'extra_headers': row.get('extra_headers') or '',
        'created_at': row.get('created_at'),
        'updated_at': row.get('updated_at'),
        'created_by': row.get('created_by') or '',
        'key_hint': _ai_key_hint(row),
    })
    return item


def _ai_key_hint(row):
    """只回显掩码；解密失败也绝不把密文或异常细节抛给前端。"""
    if not row.get('enc_api_key'):
        return ''
    try:
        from ai_client import mask_key
        return mask_key(aes_gcm_decrypt(load_aes_key(), row['enc_api_key']))
    except Exception:
        return '（无法解密，请重新保存）'


def _ai_validate_base_url(value):
    from urllib.parse import urlparse
    url = (value or '').strip()
    if not url:
        raise ai_service.AiServiceError('模型地址（base_url）不能为空', 400)
    if any(char in url for char in ' \t\r\n'):
        raise ai_service.AiServiceError('模型地址不能包含空格或换行', 400)
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ai_service.AiServiceError('模型地址只支持 http:// 或 https://', 400)
    if not parsed.hostname:
        raise ai_service.AiServiceError('模型地址缺少主机名', 400)
    if parsed.username or parsed.password:
        raise ai_service.AiServiceError(
            '不要在模型地址里写账号密码（会进日志），改用 API Key 字段', 400)
    return url.rstrip('/')


def _ai_number(data, key, default, minimum, maximum):
    value = data.get(key, default)
    if value in (None, ''):
        value = default
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ai_service.AiServiceError(f'{key} 必须是数字', 400)
    if number < minimum or number > maximum:
        raise ai_service.AiServiceError(f'{key} 的取值范围是 {minimum}~{maximum}', 400)
    return number


def _ai_extra_headers(data):
    raw = data.get('extra_headers')
    if raw in (None, ''):
        return ''
    if isinstance(raw, dict):
        return json.dumps(raw, ensure_ascii=False)
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        raise ai_service.AiServiceError('附加请求头必须是 JSON 对象，例如 {"X-Api-Version":"1"}', 400)
    if not isinstance(parsed, dict):
        raise ai_service.AiServiceError('附加请求头必须是 JSON 对象', 400)
    return json.dumps(parsed, ensure_ascii=False)


def _ai_provider_values(data, existing=None):
    name = str(data.get('name') or (existing or {}).get('name') or '').strip()
    if not name:
        raise ai_service.AiServiceError('请填写配置名称', 400)
    if len(name) > 60:
        raise ai_service.AiServiceError('配置名称最多 60 个字', 400)
    duplicate = get_ai_provider_by_name(name)
    if duplicate and (not existing or duplicate['id'] != existing['id']):
        raise ai_service.AiServiceError(f'配置名称「{name}」已存在', 400)

    model = str(data.get('model') or (existing or {}).get('model') or '').strip()
    if not model:
        raise ai_service.AiServiceError('请填写模型名称（model）', 400)
    if len(model) > 120:
        raise ai_service.AiServiceError('模型名称最多 120 个字符', 400)

    deployment = str(data.get('deployment') or (existing or {}).get('deployment') or 'cloud')
    if deployment not in AI_PROVIDER_DEPLOYMENTS:
        raise ai_service.AiServiceError('部署类型只能是 local 或 cloud', 400)

    values = {
        'name': name,
        'base_url': _ai_validate_base_url(
            data.get('base_url', (existing or {}).get('base_url'))),
        'model': model,
        'deployment': deployment,
        'temperature': _ai_number(data, 'temperature',
                                  (existing or {}).get('temperature', 0.2), 0, 2),
        'max_tokens': int(_ai_number(data, 'max_tokens',
                                     (existing or {}).get('max_tokens', 2048), 16, 32000)),
        'timeout': int(_ai_number(data, 'timeout',
                                  (existing or {}).get('timeout', 120), 5, 1800)),
        'supports_tools': bool(data.get('supports_tools',
                                       (existing or {}).get('supports_tools', 1))),
        'enabled': bool(data.get('enabled', (existing or {}).get('enabled', 1))),
    }
    if 'extra_headers' in data:
        values['extra_headers'] = _ai_extra_headers(data)
    if 'is_default' in data:
        values['is_default'] = bool(data.get('is_default'))
    return values


def _ai_page_config(page='chat'):
    return {
        'enabled': bool(ai_service.enabled()),
        'page': page,
        'role': session.get('role', ''),
        'roles': ai_service.config.AI_ROLES,
        'mask_ip': bool(ai_service.config.AI_MASK_IP),
        'allow_cloud': bool(ai_service.config.AI_ALLOW_CLOUD),
        'traditional_fallback': bool(ai_service.traditional_fallback_enabled()),
        'max_input_chars': int(ai_service.config.AI_INPUT_MAX_CHARS),
        'action_ttl': int(ai_service.config.AI_ACTION_TTL),
        'daily_token_limit': int(ai_service.config.AI_DAILY_TOKEN_LIMIT or 0),
    }


@app.route("/ai")
@app.route("/ai/chat")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def ai_page():
    """AI 会话工作台。"""
    return render_template("ai.html", ai_config=_ai_page_config('chat'))


@app.route("/ai/models")
@no_cache
@login_required
@role_required(['admin'])
def ai_models_page():
    return render_template("ai_models.html", ai_config=_ai_page_config('models'))


@app.route("/ai/usage")
@no_cache
@login_required
@role_required(['admin'])
def ai_usage_page():
    return render_template("ai_usage.html", ai_config=_ai_page_config('usage'))


@app.route("/ai/operation-audit")
@no_cache
@login_required
@role_required(['admin'])
def ai_operation_audit_page():
    """命令操作审计只对管理员开放，与通用审计日志的权限保持一致。"""
    return render_template("operation_audit.html", ai_config=_ai_page_config('operation-audit'))


@app.route("/ai/conversation-audit")
@no_cache
@login_required
@role_required(['admin'])
def ai_conversation_audit_page():
    """AI 会话审计与操作审计保持相同的管理员权限边界。"""
    return render_template("conversation_audit.html", ai_config=_ai_page_config('conversation-audit'))


@app.route("/ai/insights")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def ai_insights_page():
    return render_template("ai_insights.html", ai_config=_ai_page_config('insights'))


def _operation_audit_time_arg(name, end_of_day=False):
    raw = str(request.args.get(name, "") or "").strip()
    if not raw:
        return ""
    normalized = raw.replace("T", " ")
    formats = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d")
    parsed = None
    for fmt in formats:
        try:
            parsed = datetime.strptime(normalized, fmt)
            break
        except ValueError:
            continue
    if parsed is None:
        raise ValueError(f"{name} 时间格式不正确")
    if len(normalized) == 10 and end_of_day:
        parsed = parsed.replace(hour=23, minute=59, second=59)
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


@app.route("/api/ai/operation-audits", methods=["GET"])
@no_cache
@login_required
@role_required(['admin'])
def api_ai_operation_audits():
    try:
        server_id = request.args.get("server_id", "")
        if server_id not in (None, ""):
            server_id = int(server_id)
        page = int(request.args.get("page", 1))
        page_size = int(request.args.get("page_size", 50))
        start_time = _operation_audit_time_arg("start_time")
        end_time = _operation_audit_time_arg("end_time", end_of_day=True)
        if start_time and end_time and start_time > end_time:
            raise ValueError("开始时间不能晚于结束时间")
        data = list_operation_audits(
            username=str(request.args.get("username", "") or "").strip(),
            server_id=server_id,
            start_time=start_time,
            end_time=end_time,
            status=str(request.args.get("status", "") or "").strip(),
            dimension=str(request.args.get("dimension", "time") or "time").strip(),
            page=page,
            page_size=page_size,
        )
    except (TypeError, ValueError) as exc:
        return jsonify({"ok": False, "msg": str(exc) or "查询参数不正确"}), 400
    return jsonify({"ok": True, **data})


@app.route("/api/ai/conversation-audits", methods=["GET"])
@no_cache
@login_required
@role_required(['admin'])
def api_ai_conversation_audits():
    try:
        page = int(request.args.get("page", 1))
        page_size = int(request.args.get("page_size", 50))
        start_time = _operation_audit_time_arg("start_time")
        end_time = _operation_audit_time_arg("end_time", end_of_day=True)
        if start_time and end_time and start_time > end_time:
            raise ValueError("开始时间不能晚于结束时间")
        keyword = str(request.args.get("keyword", "") or "").strip()
        if len(keyword) > 200:
            raise ValueError("问题关键词不能超过 200 个字符")
        data = list_conversation_audits(
            username=str(request.args.get("username", "") or "").strip(),
            keyword=keyword,
            start_time=start_time,
            end_time=end_time,
            dimension=str(request.args.get("dimension", "time") or "time").strip(),
            page=page,
            page_size=page_size,
        )
    except (TypeError, ValueError) as exc:
        return jsonify({"ok": False, "msg": str(exc) or "查询参数不正确"}), 400
    return jsonify({"ok": True, **data})


@app.route("/api/ai/tools", methods=["GET"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
@ai_api
def api_ai_tools():
    ai_service.require_enabled()
    data = ai_service.list_tools(session.get('role', ''))
    data['ok'] = True
    return jsonify(data)


@app.route("/api/ai/skills", methods=["GET", "POST"])
@app.route("/api/ai/skills/", methods=["GET", "POST"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
@ai_api
def api_ai_skills():
    ai_service.require_enabled()
    username, role = _ai_actor()

    if request.method == "GET":
        try:
            limit = max(1, min(int(request.args.get('limit') or 100), 200))
            payload = ai_codex_tools.list_skills(limit=limit)
        except (ValueError, ai_codex_tools.CodexToolError) as exc:
            raise ai_service.AiServiceError(str(exc), 400)
        payload['ok'] = True
        payload['can_create'] = role == 'admin'
        return jsonify(payload)

    if role != 'admin':
        return _ai_json({'ok': False, 'message': '只有超级管理员可以添加 Skill'}, 403)
    data = request.json or {}
    try:
        payload, summary, risk = ai_codex_tools.normalize_create_skill(data, {
            'username': username, 'role': role,
            'mask_ip': bool(ai_service.config.AI_MASK_IP),
        })
        result = ai_codex_tools.execute_create_skill(payload, {
            'username': username, 'role': role,
        })
    except ai_codex_tools.CodexToolError as exc:
        raise ai_service.AiServiceError(str(exc), 400)
    record_audit(username, 'ai_skill_create',
                 result='ok' if result.get('ok') else 'failed',
                 target_type='ai_skill', target_id=payload.get('name'),
                 target_name=payload.get('name'),
                 detail=json.dumps({'summary': summary, 'risk': risk,
                                    'overwrite': bool(payload.get('overwrite')),
                                    'files': result.get('files') or [],
                                    'error': result.get('error') or ''},
                                   ensure_ascii=False),
                 client_ip=_ai_client_ip())
    status = 200 if result.get('ok') else 400
    result['ok'] = bool(result.get('ok'))
    return _ai_json(result, status)


@app.route("/api/ai/skills/<name>", methods=["GET"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
@ai_api
def api_ai_skill_detail(name):
    ai_service.require_enabled()
    try:
        payload = ai_codex_tools.read_skill(
            name, include_content=True,
            limit=max(500, min(int(request.args.get('limit') or 30000), 60000)))
    except (ValueError, ai_codex_tools.CodexToolError) as exc:
        raise ai_service.AiServiceError(str(exc), 400)
    payload['ok'] = True
    return jsonify(payload)


# --------- provider 配置 ---------
@app.route("/api/ai/providers", methods=["GET", "POST"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
@ai_api
def api_ai_providers():
    ai_service.require_enabled()
    username, role = _ai_actor()

    if request.method == "GET":
        full = request.args.get('full') == '1'
        if full and role != 'admin':
            return _ai_json({'ok': False, 'message': '权限不足'}, 403)
        rows = [row for row in list_ai_providers() if full or row.get('enabled')]
        items = [_ai_provider_public(row, full=full) for row in rows]
        fallback = None
        if not rows:
            env_row = ai_service.env_provider()
            if env_row:
                fallback = {'id': None, 'name': env_row['name'], 'model': env_row['model'],
                            'deployment': env_row['deployment'], 'is_env_fallback': True,
                            'base_url': env_row['base_url'], 'enabled': True,
                            'supports_tools': True, 'has_key': bool(ai_service.config.AI_API_KEY)}
            elif ai_service.traditional_fallback_enabled():
                fallback = {'id': None, 'name': '传统运维规则引擎（无大模型降级）',
                            'model': ai_service.TRADITIONAL_MODEL,
                            'deployment': 'local', 'is_env_fallback': False,
                            'is_traditional_fallback': True, 'base_url': '',
                            'enabled': True, 'supports_tools': False, 'has_key': True}
        return jsonify({'ok': True, 'providers': items, 'env_fallback': fallback,
                        'allow_cloud': bool(ai_service.config.AI_ALLOW_CLOUD),
                        'traditional_fallback': bool(ai_service.traditional_fallback_enabled())})

    if role != 'admin':
        return _ai_json({'ok': False, 'message': '权限不足'}, 403)
    data = request.json or {}
    values = _ai_provider_values(data)
    api_key = str(data.get('api_key') or '').strip()
    if api_key:
        values['enc_api_key'] = aes_gcm_encrypt(load_aes_key(), api_key)
    values['created_by'] = username
    provider_id = add_ai_provider(values)
    record_audit(username, 'ai_provider_save', result='ok', target_type='ai_provider',
                 target_id=provider_id, target_name=values['name'],
                 detail=json.dumps({'base_url': values['base_url'], 'model': values['model'],
                                    'updated_key': bool(api_key)}, ensure_ascii=False),
                 client_ip=_ai_client_ip())
    row = get_ai_provider(provider_id)
    return jsonify({'ok': True, 'provider': _ai_provider_public(row, full=True),
                    'message': '已保存'})


@app.route("/api/ai/providers/<int:provider_id>", methods=["PUT", "DELETE"])
@no_cache
@login_required
@role_required(['admin'])
@ai_api
def api_ai_provider_detail(provider_id):
    ai_service.require_enabled()
    username, _ = _ai_actor()
    row = get_ai_provider(provider_id)
    if not row:
        return _ai_json({'ok': False, 'message': '模型配置不存在'}, 404)

    if request.method == "DELETE":
        if len(list_ai_providers()) <= 1 and not ai_service.env_provider():
            return _ai_json({'ok': False, 'message': '至少保留一个模型配置，否则无法对话'}, 400)
        delete_ai_provider(provider_id)
        record_audit(username, 'ai_provider_delete', result='ok', target_type='ai_provider',
                     target_id=provider_id, target_name=row.get('name') or '',
                     detail='', client_ip=_ai_client_ip())
        return jsonify({'ok': True, 'message': '已删除'})

    data = request.json or {}
    values = _ai_provider_values(data, existing=row)
    api_key = str(data.get('api_key') or '').strip()
    if api_key:
        # 留空表示不修改（与"密码留空保留原密文"一致）。
        values['enc_api_key'] = aes_gcm_encrypt(load_aes_key(), api_key)
    update_ai_provider(provider_id, values)
    record_audit(username, 'ai_provider_save', result='ok', target_type='ai_provider',
                 target_id=provider_id, target_name=values['name'],
                 detail=json.dumps({'base_url': values['base_url'], 'model': values['model'],
                                    'updated_key': bool(api_key)}, ensure_ascii=False),
                 client_ip=_ai_client_ip())
    return jsonify({'ok': True, 'provider': _ai_provider_public(get_ai_provider(provider_id),
                                                               full=True),
                    'message': '已保存'})


@app.route("/api/ai/providers/<int:provider_id>/default", methods=["POST"])
@no_cache
@login_required
@role_required(['admin'])
@ai_api
def api_ai_provider_default(provider_id):
    ai_service.require_enabled()
    username, _ = _ai_actor()
    row = get_ai_provider(provider_id)
    if not row:
        return _ai_json({'ok': False, 'message': '模型配置不存在'}, 404)
    set_default_ai_provider(provider_id)
    record_audit(username, 'ai_provider_default', result='ok', target_type='ai_provider',
                 target_id=provider_id, target_name=row.get('name') or '',
                 detail='', client_ip=_ai_client_ip())
    return jsonify({'ok': True, 'message': '已设为默认'})


@app.route("/api/ai/providers/<int:provider_id>/test", methods=["POST"])
@no_cache
@login_required
@role_required(['admin'])
@ai_api
def api_ai_provider_test(provider_id):
    ai_service.require_enabled()
    username, _ = _ai_actor()
    if not get_ai_provider(provider_id):
        return _ai_json({'ok': False, 'message': '模型配置不存在'}, 404)
    provider, client, api_key = ai_service.build_client_for(provider_id)
    result = client.test_connection()
    message = ai_client.redact(result.get('message') or '', [api_key])
    update_ai_provider_test(provider_id, bool(result.get('ok')), message)
    record_audit(username, 'ai_provider_test', result='ok' if result.get('ok') else 'failed',
                 target_type='ai_provider', target_id=provider_id,
                 target_name=provider.get('name') or '', detail=message[:300],
                 client_ip=_ai_client_ip())
    return jsonify({'ok': bool(result.get('ok')), 'message': message,
                    'models': [ai_client.redact(item, [api_key]) for item in result.get('models') or []],
                    'provider': _ai_provider_public(get_ai_provider(provider_id), full=True)})


@app.route("/api/ai/models", methods=["GET"])
@no_cache
@login_required
@role_required(['admin'])
@ai_api
def api_ai_models():
    ai_service.require_enabled()
    provider_id = request.args.get('provider_id')
    provider, client, api_key = ai_service.build_client_for(provider_id)
    try:
        models_found = client.list_models()
    except Exception as exc:
        raise ai_service.AiServiceError(
            ai_client.redact(str(exc), [api_key]) or '拉取模型列表失败', 400)
    return jsonify({'ok': True, 'models': models_found, 'provider_id': provider.get('id')})


# --------- 会话与消息 ---------
def _ai_require_conversation(conversation_id, username, role):
    conversation = get_ai_conversation(conversation_id)
    if not conversation:
        raise ai_service.AiServiceError('会话不存在', 404)
    if conversation.get('username') != username and role != 'admin':
        raise ai_service.AiServiceError('无权访问该会话', 403)
    return conversation


def _ai_message_public(row):
    calls = []
    if row.get('tool_calls'):
        try:
            calls = json.loads(row['tool_calls'])
        except (TypeError, ValueError):
            calls = []
    return {
        'id': row.get('id'),
        'role': row.get('role'),
        'content': row.get('content') or '',
        'status': row.get('status'),
        'error': row.get('error') or '',
        'tool_name': row.get('tool_name') or '',
        'tool_calls': calls,
        'model': row.get('model') or '',
        'created_at': row.get('created_at'),
        'prompt_tokens': row.get('prompt_tokens') or 0,
        'completion_tokens': row.get('completion_tokens') or 0,
        'tokens_estimated': bool(row.get('tokens_estimated')),
        'duration_ms': row.get('duration_ms') or 0,
    }


@app.route("/api/ai/conversations", methods=["GET", "POST"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
@ai_api
def api_ai_conversations():
    ai_service.require_enabled()
    username, role = _ai_actor()

    if request.method == "GET":
        scope = None if (request.args.get('all') == '1' and role == 'admin') else username
        rows = list_ai_conversations(username=scope, limit=100)
        return jsonify({'ok': True, 'conversations': [
            {'id': row['id'], 'title': row.get('title') or '',
             'username': row.get('username') or '',
             'provider_id': row.get('provider_id'), 'model': row.get('model') or '',
             'message_count': row.get('message_count') or 0,
             'pending_count': row.get('pending_count') or 0,
             'updated_at': row.get('updated_at'), 'created_at': row.get('created_at')}
            for row in rows]})

    data = request.json or {}
    provider_id = data.get('provider_id')
    model = ''
    if provider_id not in (None, ''):
        provider = get_ai_provider(provider_id)
        if not provider:
            raise ai_service.AiServiceError('模型配置不存在', 404)
        model = provider.get('model') or ''
    else:
        provider_id = None
    conversation_id = add_ai_conversation(
        str(data.get('title') or '新会话')[:40], username, provider_id=provider_id, model=model)
    return jsonify({'ok': True, 'conversation': {
        'id': conversation_id, 'title': data.get('title') or '新会话',
        'message_count': 0, 'pending_count': 0}})


@app.route("/api/ai/conversations/<int:conversation_id>", methods=["PUT", "DELETE"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
@ai_api
def api_ai_conversation_detail(conversation_id):
    ai_service.require_enabled()
    username, role = _ai_actor()
    _ai_require_conversation(conversation_id, username, role)

    if request.method == "DELETE":
        delete_ai_conversation(conversation_id)
        record_audit(username, 'ai_conversation_delete', result='ok',
                     target_type='ai_conversation', target_id=conversation_id,
                     detail='', client_ip=_ai_client_ip())
        return jsonify({'ok': True, 'message': '已删除'})

    data = request.json or {}
    title = str(data.get('title') or '').strip()
    if not title:
        raise ai_service.AiServiceError('标题不能为空', 400)
    rename_ai_conversation(conversation_id, title[:80])
    return jsonify({'ok': True, 'message': '已重命名'})


@app.route("/api/ai/conversations/<int:conversation_id>/messages", methods=["GET", "POST"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
@ai_api
def api_ai_conversation_messages(conversation_id):
    ai_service.require_enabled()
    username, role = _ai_actor()
    conversation = _ai_require_conversation(conversation_id, username, role)

    if request.method == "GET":
        rows = list_ai_messages(conversation_id)
        return jsonify({
            'ok': True,
            'conversation': {'id': conversation['id'], 'title': conversation.get('title') or '',
                             'provider_id': conversation.get('provider_id'),
                             'model': conversation.get('model') or '',
                             'username': conversation.get('username') or ''},
            'messages': [_ai_message_public(row) for row in rows],
            'actions': ai_service.list_actions(conversation_id, username, role),
            'active_stream_id': ai_service.active_stream_for(conversation_id, username, role),
        })

    data = request.json or {}
    result = ai_service.start_chat(
        conversation_id, data.get('content') or '', username, role,
        provider_id=data.get('provider_id'), client_ip=_ai_client_ip(),
        access_mode=data.get('access_mode'))
    result['conversation_title'] = conversation.get('title') or ''
    return jsonify(result)


@app.route("/api/ai/stream", methods=["GET"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
@ai_api
def api_ai_stream():
    ai_service.require_enabled()
    username, role = _ai_actor()
    stream_id = request.args.get('stream_id') or ''
    if not stream_id:
        conversation_id = request.args.get('conversation_id')
        try:
            conversation_id = int(conversation_id)
        except (TypeError, ValueError):
            return jsonify({'ok': True, 'status': 'idle', 'stream_id': None})
        stream_id = ai_service.active_stream_for(conversation_id, username, role)
        if not stream_id:
            return jsonify({'ok': True, 'status': 'idle', 'stream_id': None})
    try:
        offset = int(request.args.get('offset') or 0)
    except (TypeError, ValueError):
        offset = 0
    return jsonify(ai_service.read_stream(stream_id, offset, username, role))


@app.route("/api/ai/stream/cancel", methods=["POST"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
@ai_api
def api_ai_stream_cancel():
    ai_service.require_enabled()
    username, role = _ai_actor()
    data = request.json or {}
    stream_id = str(data.get('stream_id') or '')
    if not stream_id:
        raise ai_service.AiServiceError('缺少 stream_id', 400)
    return jsonify(ai_service.request_cancel(stream_id, username, role))


# --------- 待确认操作 ---------
@app.route("/api/ai/actions", methods=["GET"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
@ai_api
def api_ai_actions():
    ai_service.require_enabled()
    username, role = _ai_actor()
    conversation_id = request.args.get('conversation_id')
    if conversation_id:
        try:
            conversation_id = int(conversation_id)
        except (TypeError, ValueError):
            raise ai_service.AiServiceError('conversation_id 不合法', 400)
        return jsonify({'ok': True, 'actions': ai_service.list_actions(
            conversation_id, username, role, status=request.args.get('status') or '')})
    return jsonify({'ok': True, 'actions': ai_service.pending_actions(username, role)})


def _ai_after_action(outcome, conversation_id, username, role):
    """动作有结果后自动续跑一轮，让模型基于真实结果说话。"""
    if not conversation_id or outcome.get('handled') or outcome.get('expired'):
        return None
    try:
        resumed = ai_service.start_chat(conversation_id, '', username, role,
                                       resume=True, client_ip=_ai_client_ip(),
                                       access_mode=outcome.get('access_mode'))
        return {'ok': True, 'stream_id': resumed.get('stream_id')}
    except ai_service.AiServiceError as exc:
        # 续跑失败不影响"操作已执行"这个事实，用户也可以继续追问。
        return {'ok': False, 'message': str(exc)}


@app.route("/api/ai/actions/<int:action_id>/approve", methods=["POST"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
@ai_api
def api_ai_action_approve(action_id):
    ai_service.require_enabled()
    username, role = _ai_actor()
    data = request.json or {}
    # These values are passed directly to the executor and are never persisted in
    # ai_actions, ai_messages or audit details.
    secure_input = {
        'password': str(data.get('password') or ''),
        'private_key': str(data.get('private_key') or ''),
        'key_passphrase': str(data.get('key_passphrase') or ''),
    }
    outcome = ai_service.approve_action(
        action_id, username, role, client_ip=_ai_client_ip(), secure_input=secure_input)
    outcome['resume'] = _ai_after_action(outcome, outcome.get('conversation_id'), username, role)
    return jsonify(outcome)


@app.route("/api/ai/actions/<int:action_id>/reject", methods=["POST"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
@ai_api
def api_ai_action_reject(action_id):
    ai_service.require_enabled()
    username, role = _ai_actor()
    data = request.json or {}
    outcome = ai_service.reject_action(action_id, username, role,
                                      reason=str(data.get('reason') or '')[:200],
                                      client_ip=_ai_client_ip())
    outcome['resume'] = _ai_after_action(outcome, outcome.get('conversation_id'), username, role)
    return jsonify(outcome)


# --------- 巡检结果解读 ---------
@app.route("/api/ai/insights", methods=["GET", "POST"])
@no_cache
@login_required
@role_required(['admin', 'operator'])
@ai_api
def api_ai_insights():
    ai_service.require_enabled()
    username, role = _ai_actor()

    if request.method == "GET":
        run_id = request.args.get('run_id') or None
        insight_id = request.args.get('id')
        if insight_id:
            try:
                row = get_ai_insight(int(insight_id))
            except (TypeError, ValueError):
                row = None
            if not row:
                raise ai_service.AiServiceError('解读记录不存在', 404)
            rows = [row]
        else:
            rows = list_ai_insights(run_id=run_id, limit=10)
        return jsonify({'ok': True, 'insights': [
            {'id': row['id'], 'run_id': row.get('run_id'), 'scope': row.get('scope'),
             'model': row.get('model') or '', 'content': row.get('content') or '',
             'status': row.get('status'), 'error': row.get('error') or '',
             'username': row.get('username') or '', 'created_at': row.get('created_at')}
            for row in rows]})

    data = request.json or {}
    run_id = str(data.get('run_id') or '').strip()
    if not run_id:
        runs = list_inspection_runs(1)
        if not runs:
            raise ai_service.AiServiceError('系统里还没有巡检记录', 400)
        run_id = runs[0]['run_id']
    result = ai_service.start_insight(run_id, username, role,
                                     provider_id=data.get('provider_id'),
                                     client_ip=_ai_client_ip())
    return jsonify(result)


# --------- 用量 ---------
@app.route("/api/ai/usage", methods=["GET"])
@no_cache
@login_required
@role_required(['admin'])
@ai_api
def api_ai_usage():
    ai_service.require_enabled()
    try:
        days = max(1, min(int(request.args.get('days') or 30), 365))
    except (TypeError, ValueError):
        days = 30
    by = request.args.get('by') if request.args.get('by') in ('model', 'user') else 'model'
    rows = ai_usage_summary(days=days, by=by)
    return jsonify({
        'ok': True, 'days': days, 'by': by,
        'today_total': ai_usage_today(),
        'daily_limit': int(ai_service.config.AI_DAILY_TOKEN_LIMIT or 0),
        'items': [{'day': row.get('day'), 'target': row.get('target') or '',
                   'prompt_tokens': row.get('prompt_tokens') or 0,
                   'completion_tokens': row.get('completion_tokens') or 0,
                   'calls': row.get('calls') or 0} for row in rows],
    })


# --------- T2 执行体：全部复用既有函数，不新造执行路径 ---------
def _ai_exec_start_inspection(payload, context):
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    task_name = payload.get('task_name') or f"AI巡检-{stamp}"
    run_id, inserted = enqueue_inspection(
        task_name=task_name,
        project_name=payload.get('project_name') or task_name,
        inspector=payload.get('inspector') or context.get('username') or 'AI',
        report_format=payload.get('report_format') or 'excel',
        resource_group_id=payload.get('resource_group_id'),
        check_cpu=True, check_mem=True, check_disk=True,
        enable_proxy=False, proxy_rules=[], source='manual')
    if not inserted:
        return {'ok': False, 'error': '任务入队失败'}
    return {'ok': True, 'result': f'已发起巡检，run_id={run_id}', 'run_id': run_id}


def _ai_exec_refresh_hardware(payload, context):
    server = get_server(payload.get('server_id'))
    if not server:
        return {'ok': False, 'error': '服务器不存在'}
    # 采集失败时 refresh 只登记 last_error、保留旧参数；成功会把 last_error 清空。
    snapshot = refresh_server_hardware(server) or {}
    if snapshot.get('last_error'):
        return {'ok': False, 'error': f"硬件参数采集失败：{snapshot['last_error']}"}
    return {'ok': True,
            'result': f"已重新采集硬件参数（采集时间 {snapshot.get('collected_at') or '未知'}）",
            'cpu': snapshot.get('cpu'), 'memory': snapshot.get('memory'),
            'storage': snapshot.get('storage'), 'gpu': snapshot.get('gpu'),
            'collected_at': snapshot.get('collected_at')}


def _ai_exec_test_connection(payload, context):
    server = get_server(payload.get('server_id'))
    if not server:
        return {'ok': False, 'error': '服务器不存在'}
    _probe_server_health(server)
    with _server_health_lock:
        state = dict(_server_health.get(server['id']) or {})
    if state.get('last_error'):
        return {'ok': False, 'error': f"连接失败：{state['last_error']}"}
    return {'ok': True, 'result': f"SSH 连接成功（{server.get('ip')}:{server.get('port')}）"}


def _ai_exec_restart_service(payload, context):
    """只执行服务台账里人工登记过的 restart_command，模型无法自带命令。"""
    service = get_service(payload.get('service_id'))
    if not service:
        return {'ok': False, 'error': '服务不存在'}
    registered_command = (service.get('restart_command') or '').strip()
    if not registered_command:
        return {'ok': False, 'error': '该服务没有登记重启命令，请先在服务信息表里补充'}
    command = (payload.get('command') or registered_command).strip()
    if command != registered_command:
        return {'ok': False, 'error': '服务的重启命令已发生变化，请重新发起确认'}
    expected_server_id = payload.get('server_id')
    if expected_server_id not in (None, ''):
        try:
            server_changed = int(expected_server_id) != int(service['server_id'])
        except (TypeError, ValueError):
            return {'ok': False, 'error': '确认单中的目标服务器格式不正确，请重新发起确认'}
        if server_changed:
            return {'ok': False, 'error': '服务所属服务器已发生变化，请重新发起确认'}
    server = get_server(service['server_id'])
    if not server:
        return {'ok': False, 'error': '服务所属服务器不存在'}
    ssh = create_ssh_client()
    audit_status, audit_error = 'failed', ''
    try:
        credentials = decrypt_server_credentials(load_aes_key(), server)
        connect_ssh(ssh, server['ip'], server['port'], server['username'],
                    password=credentials.get('password'),
                    private_key=credentials.get('private_key'),
                    key_passphrase=credentials.get('key_passphrase'), timeout=10)
        output = run_cmd(ssh, command, timeout=30)
        audit_status = 'success'
        logger.warning("AI 确认后重启服务: %s (%s) 输出: %s",
                       service.get('name'), server.get('ip'), output[:200])
        return {'ok': True, 'result': f"已执行重启命令，输出：{output[:1000]}"}
    except Exception as exc:
        audit_error = str(exc)[:200]
        return {'ok': False, 'error': str(exc)[:200]}
    finally:
        ssh.close()
        models.record_operation_audit(
            context.get('username') or '', server, command, audit_status,
            error=audit_error, client_ip=context.get('client_ip') or '',
            source_action_id=context.get('source_action_id'))


def _ai_exec_upsert_server(payload, context):
    """Create/update a server while keeping SSH secrets outside AI persistence."""
    if context.get('role') != 'admin':
        return {'ok': False, 'error': '只有超级管理员可以新增或修改服务器'}
    server_id = payload.get('server_id')
    existing = get_server(server_id) if server_id else None
    if server_id and not existing:
        return {'ok': False, 'error': '服务器不存在'}

    secure = context.get('secure_input') if isinstance(context.get('secure_input'), dict) else {}
    credential_mode = payload.get('credential_mode') or 'secure_input_required'
    data = dict(payload)
    data.pop('server_id', None)
    data.pop('credential_mode', None)
    data['password'] = ''
    data['private_key'] = ''
    data['key_passphrase'] = ''
    if credential_mode == 'secure_input_required':
        data['password'] = str(secure.get('password') or '')
        data['private_key'] = str(secure.get('private_key') or '')
        data['key_passphrase'] = str(secure.get('key_passphrase') or '')

    try:
        values = validate_server_payload(data, require_credentials=not bool(existing))
        auth_changed = bool(existing) and values['auth_type'] != existing.get('auth_type', 'password')
        supplied = values['password'] if values['auth_type'] == 'password' else values['private_key']
        if credential_mode == 'secure_input_required' and not supplied:
            raise ValueError('请在确认卡片中填写 SSH 密码或私钥')
        if auth_changed and not supplied:
            raise ValueError('切换认证方式时必须填写新的认证凭据')

        key = load_aes_key()
        if existing and values['auth_type'] == 'password' and not values['password']:
            values['password'] = aes_gcm_decrypt(key, existing['enc_password'])
        if existing and values['auth_type'] == 'key' and not values['private_key']:
            values['private_key'] = aes_gcm_decrypt(key, existing['enc_private_key'])
            values['key_passphrase'] = (
                aes_gcm_decrypt(key, existing['enc_key_passphrase'])
                if existing.get('enc_key_passphrase') else ''
            )

        # Verify the credentials before mutating the asset table.
        ssh = create_ssh_client()
        try:
            connect_ssh(
                ssh, values['ip'], values['port'], values['username'],
                password=values['password'] if values['auth_type'] == 'password' else None,
                private_key=values['private_key'] if values['auth_type'] == 'key' else None,
                key_passphrase=values['key_passphrase'] or None, timeout=10,
            )
        finally:
            ssh.close()

        if values['auth_type'] == 'password':
            enc_password = aes_gcm_encrypt(key, values['password'])
            enc_private_key = None
            enc_key_passphrase = None
        else:
            enc_password = ''
            enc_private_key = aes_gcm_encrypt(key, values['private_key'])
            enc_key_passphrase = (
                aes_gcm_encrypt(key, values['key_passphrase']) if values['key_passphrase'] else None
            )

        if existing:
            old_target = (existing.get('ip'), existing.get('port'), existing.get('username'))
            update_server(
                existing['id'], values['ip'], values['port'], values['username'], enc_password,
                values['group_ids'], values['notes'], values['auth_type'], enc_private_key,
                enc_key_passphrase, values['name'], values['resource_type'], values['physical_ip'],
                values['os_type'], values['rack_number'],
                values['room_affiliation'], values['rack_level'],
            )
            server_id = existing['id']
            if old_target != (values['ip'], values['port'], values['username']):
                delete_server_hardware(server_id)
            verb = '更新'
        else:
            server_id = add_server(
                values['ip'], values['port'], values['username'], enc_password,
                values['group_ids'], values['notes'], auth_type=values['auth_type'],
                enc_private_key=enc_private_key, enc_key_passphrase=enc_key_passphrase,
                name=values['name'], resource_type=values['resource_type'],
                physical_ip=values['physical_ip'], os_type=values['os_type'],
                rack_number=values['rack_number'],
                room_affiliation=values['room_affiliation'], rack_level=values['rack_level'],
            )
            verb = '新增'
        return {
            'ok': True, 'result': f"已{verb}服务器「{values['name']}」，SSH 连接验证成功",
            'server_id': server_id, 'name': values['name'], 'ip': values['ip'],
        }
    except ValueError as exc:
        return {'ok': False, 'error': str(exc)}
    except sqlite3.IntegrityError:
        return {'ok': False, 'error': '服务器数据冲突，请重新查询资产后再试'}
    except Exception as exc:
        # Connection/library errors do not need and must not include submitted credentials.
        return {'ok': False, 'error': ('SSH 验证或服务器保存失败：' + str(exc))[:240]}


def _ai_service_discovery_runner(server, include_system, context):
    """One SSH session, four fixed read-only collectors, sanitized DB draft."""
    ssh = create_ssh_client()
    try:
        credentials = decrypt_server_credentials(load_aes_key(), server)
        connect_ssh(
            ssh, server['ip'], server['port'], server['username'],
            password=credentials.get('password'), private_key=credentials.get('private_key'),
            key_passphrase=credentials.get('key_passphrase'), timeout=10,
        )

        def execute(command, timeout):
            return run_cmd(ssh, command, timeout=timeout)

        discovery = service_discovery.discover(execute, include_system=include_system)
        scan_id = 'scan_' + secrets.token_hex(16)
        models.add_ai_service_discovery_scan(
            scan_id, server['id'], context.get('username') or '',
            discovery.get('candidates') or [], discovery.get('warnings') or [],
            ttl_seconds=config.AI_ACTION_TTL,
        )
        return {'ok': True, 'scan_id': scan_id, **discovery}
    except Exception as exc:
        return {'ok': False, 'error': ('服务发现失败：' + str(exc))[:240]}
    finally:
        ssh.close()


def _ai_exec_import_discovered_services(payload, context):
    if context.get('role') != 'admin':
        return {'ok': False, 'error': '只有超级管理员可以导入服务'}
    models.expire_ai_service_discovery_scans()
    scan = models.get_ai_service_discovery_scan(payload.get('scan_id'))
    if not scan or scan.get('status') != 'ready':
        return {'ok': False, 'error': '服务发现结果不存在、已过期或已导入，请重新扫描'}
    server = get_server(scan.get('server_id'))
    if not server:
        return {'ok': False, 'error': '扫描对应的服务器已不存在'}

    selected = set(payload.get('candidate_ids') or [])
    candidates = [item for item in scan.get('candidates') or []
                  if item.get('candidate_id') in selected]
    if len(candidates) != len(selected):
        return {'ok': False, 'error': '候选服务已变化，请重新扫描'}
    strategy = payload.get('strategy') or 'skip_existing'
    existing_by_name = {
        str(item.get('name') or '').lower(): item
        for item in list_services(server_id=server['id'])
    }
    added = updated = skipped = failed = 0
    failures = []
    discovered_fields = (
        'service_type', 'run_mode', 'version', 'deploy_dir', 'start_command', 'stop_command',
        'restart_command', 'ports', 'config_path', 'log_path', 'access_url', 'status',
        'auto_start', 'notes',
    )
    for candidate in candidates:
        name = str(candidate.get('name') or '').strip()
        existing = existing_by_name.get(name.lower())
        if existing and strategy == 'skip_existing':
            skipped += 1
            continue
        try:
            if existing:
                data = {key: existing.get(key) for key in models.SERVICE_COLUMNS}
                for key in discovered_fields:
                    value = candidate.get(key)
                    if value not in (None, ''):
                        data[key] = value
                data['name'] = existing['name']
                data['server_id'] = server['id']
                data['system_ids'] = existing.get('system_ids') or []
                data['environment_ids'] = server.get('group_ids') or []
                values, system_ids, environment_ids = validate_service_payload(data)
                update_service(existing['id'], values, system_ids, environment_ids,
                               accounts=None, accounts_provided=False)
                updated += 1
            else:
                data = {key: candidate.get(key) for key in models.SERVICE_COLUMNS}
                data['name'] = name
                data['server_id'] = server['id']
                data['system_ids'] = []
                data['environment_ids'] = server.get('group_ids') or []
                values, system_ids, environment_ids = validate_service_payload(data)
                add_service(values, system_ids, environment_ids, accounts=[],
                            created_by=context.get('username') or 'AI')
                added += 1
        except Exception as exc:
            failed += 1
            failures.append({'name': name, 'error': str(exc)[:160]})

    if failed == 0:
        models.finish_ai_service_discovery_scan(scan['id'], 'imported')
    result = f'服务导入完成：新增 {added}，更新 {updated}，跳过 {skipped}，失败 {failed}'
    return {
        'ok': failed == 0, 'result': result, 'server_id': server['id'],
        'added': added, 'updated': updated, 'skipped': skipped, 'failed': failed,
        'failures': failures[:20],
    }


def _ai_remote_runner(server, command, timeout):
    """远程命令执行体；命令授权由会话访问模式控制。"""
    ssh = create_ssh_client()
    try:
        credentials = decrypt_server_credentials(load_aes_key(), server)
        connect_ssh(ssh, server['ip'], server['port'], server['username'],
                    password=credentials.get('password'),
                    private_key=credentials.get('private_key'),
                    key_passphrase=credentials.get('key_passphrase'), timeout=10)
        return {'ok': True, 'output': run_cmd(ssh, command, timeout=timeout)}
    except Exception as exc:
        return {'ok': False, 'error': str(exc)[:200]}
    finally:
        ssh.close()


ai_tools.register_remote_runner(_ai_remote_runner)
ai_tools.register_service_discovery_runner(_ai_service_discovery_runner)
ai_tools.register_action_executor('start_inspection', _ai_exec_start_inspection)
ai_tools.register_action_executor('refresh_server_hardware', _ai_exec_refresh_hardware)
ai_tools.register_action_executor('test_server_connection', _ai_exec_test_connection)
ai_tools.register_action_executor('restart_registered_service', _ai_exec_restart_service)
ai_tools.register_action_executor('upsert_server', _ai_exec_upsert_server)
ai_tools.register_action_executor('import_discovered_services', _ai_exec_import_discovered_services)
ai_tools.register_action_executor('run_remote_command', ai_tools.execute_remote_command)
ai_tools.register_action_executor('create_local_skill', ai_codex_tools.execute_create_skill)
ai_tools.register_action_executor('call_mcp_tool', ai_codex_tools.execute_call_mcp)

# 自动解读在 ai_insights 里留下的"操作人"标记：它不是真实账号，只是标明来源。
AI_AUTO_INSIGHT_ACTOR = '自动解读'


def _ai_maybe_auto_insight(run_id):
    """OPS_AI_ANALYZE_AFTER_INSPECTION=1 时，巡检完成后自动生成一份 AI 解读。

    只往 ai_insights 写一行，**不改已生成的报告文件**（报告要可重复、可复核）。
    这里整体兜住异常：自动解读失败只是少一份解读，绝不能影响巡检结果本身。
    """
    if not (config.AI_ENABLED and config.AI_ANALYZE_AFTER_INSPECTION):
        return None
    try:
        return ai_service.start_insight(run_id, AI_AUTO_INSIGHT_ACTOR, 'operator')
    except Exception as exc:
        logger.warning("巡检完成后自动 AI 解读未启动: %s", exc)
        return None


# ---------------- Scheduler ----------------
_scheduler_thread = None
_scheduler_lock = threading.Lock()
_runtime_started = False
_runtime_lock = threading.Lock()


def dispatch_scheduled_tasks(now=None):
    """启动当前分钟到期、且本分钟尚未执行的任务。"""
    now = now or datetime.now()
    current_time = now.strftime("%H:%M")
    current_minute = now.strftime("%Y-%m-%d %H:%M")
    dispatched = 0

    for task in list_inspection_tasks():
        schedule_time = (task.get("schedule_time") or "").strip()[:5]
        last_run = (task.get("last_run") or "")[:16]
        if not task.get("enable_schedule") or schedule_time != current_time:
            continue
        if last_run == current_minute:
            continue

        dedupe_key = f"scheduled:{task['id']}:{current_minute}"
        run_id, inserted = enqueue_inspection(
            task_name=task["name"],
            project_name=task["project_name"],
            inspector=task["inspector"],
            report_format=task["report_format"],
            resource_group_id=task["resource_group_id"],
            check_cpu=task["check_cpu"],
            check_mem=task["check_mem"],
            check_disk=task["check_disk"],
            cpu_threshold=task["cpu_threshold"],
            mem_threshold=task["mem_threshold"],
            disk_threshold=task["disk_threshold"],
            enable_proxy=task["enable_proxy"],
            proxy_rules=task["proxy_rules"],
            task_id=task["id"],
            source='scheduled',
            dedupe_key=dedupe_key
        )
        if inserted:
            update_task_last_run(task["id"])
            dispatched += 1
            logger.info(f"[调度器] 任务 {task['name']} 已进入持久化队列: {run_id}")
    return dispatched


def run_scheduled_tasks(poll_interval=5):
    """定时任务调度器。短周期轮询可避免启动秒数漂移导致漏跑。"""
    logger.info("调度器线程启动")
    while True:
        try:
            dispatch_scheduled_tasks()
            ai_service.run_maintenance()
        except Exception as e:
            logger.exception(f"定时任务调度器错误: {e}")
        time.sleep(poll_interval)

def start_scheduler():
    """以后台线程启动唯一的调度器实例。"""
    global _scheduler_thread
    with _scheduler_lock:
        if _scheduler_thread and _scheduler_thread.is_alive():
            return _scheduler_thread
        _scheduler_thread = threading.Thread(
            target=run_scheduled_tasks,
            daemon=True,
            name="inspection-scheduler"
        )
        _scheduler_thread.start()
        logger.info("定时任务调度器已启动（线程模式）")
        return _scheduler_thread

def initialize_runtime():
    """Start the process-local workers exactly once.

    The development entry point and Gunicorn both call this function.  The
    production container intentionally uses one Gunicorn worker because the
    scheduler and monitor threads are process-local.
    """
    global _runtime_started
    with _runtime_lock:
        if _runtime_started:
            return False

        logger.info("Starting Ops Inspection System runtime...")
        if DEFAULT_ADMIN_PASSWORD == "Admin@123":
            logger.warning("当前仍使用默认管理员初始密码，请登录后尽快修改")
        insecure_settings = security_config_warnings()
        for warning in insecure_settings:
            logger.warning("安全配置提示: %s", warning)
        if not config.AI_ENABLED:
            logger.info("AI 智能运维：已关闭（OPS_AI_ENABLED=0），页面与接口不可用")
        else:
            logger.info("AI 智能运维：已启用（远程访问由会话访问模式控制，云模型=%s）",
                        "开" if config.AI_ALLOW_CLOUD else "关")
            if config.AI_ALLOW_CLOUD:
                logger.warning("AI 安全提示: 已放开云端模型（OPS_AI_ALLOW_CLOUD=1），"
                               "巡检数据会离开本机，请确认合规")
            ai_service.recover_on_startup()
        start_queue_workers()
        start_scheduler()
        start_server_health_monitor()
        start_server_hardware_monitor()
        _runtime_started = True
        return True


def main():
    logger.info("Starting Ops Inspection System...")
    initialize_runtime()
    
    try:
        socketio.run(
            app, host=HOST, port=PORT, debug=DEBUG,
            allow_unsafe_werkzeug=True, use_reloader=False,
            request_handler=VersionlessWSGIRequestHandler
        )
    except TypeError as e:
        # Python 3.14与Werkzeug兼容性问题回退
        logger.warning(f"SocketIO启动失败，尝试直接使用Flask: {e}")
        app.run(host=HOST, port=PORT, debug=DEBUG, threaded=True,
                request_handler=VersionlessWSGIRequestHandler)

if __name__ == "__main__":
    main()
