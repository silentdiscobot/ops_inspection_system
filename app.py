# -*- coding: utf-8 -*-
import os, logging, sqlite3, threading, time, hashlib, hmac, re, secrets, json
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for, make_response
from flask_socketio import SocketIO
from werkzeug.security import check_password_hash, generate_password_hash
from config import HOST, PORT, DEBUG, SECRET_KEY, CPU_THRESHOLD, MEM_THRESHOLD, DISK_THRESHOLD, load_aes_key, DEFAULT_ADMIN_PASSWORD, REPORT_DIR, security_config_warnings, QUEUE_WORKERS, QUEUE_RETRY_DELAY
from models import init_db, list_groups, add_group, delete_group, list_servers, add_server, delete_server, add_inspection_task, list_inspection_tasks, get_inspection_task, update_inspection_task, delete_inspection_task, toggle_task_schedule, update_task_last_run, migrate_inspection_tasks_schema, add_user, get_user, list_users, delete_user, update_user, create_inspection_run, claim_next_inspection_run, recover_interrupted_inspection_runs, update_inspection_run_progress, finish_inspection_run, retry_or_fail_inspection_run, get_inspection_run, list_inspection_runs, clear_inspection_results, add_inspection_result
from crypto_utils import aes_gcm_encrypt, aes_gcm_decrypt
from inspection import inspect_server, parse_private_key, test_proxy
from report_excel import generate_excel_report
from captcha_utils import generate_captcha, generate_captcha_image

# ---------------- Logging ----------------
from config import LOG_DIR
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "app.log"), encoding="utf-8"),
        logging.StreamHandler()
    ]
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

LOGIN_MAX_FAILURES = 5
LOGIN_FAILURE_WINDOW = 15 * 60
_login_failures = {}
_login_failures_lock = threading.Lock()

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
    return render_template("server_inspect.html", tasks=tasks, groups=groups, runs=runs)

@app.route("/servers")
@no_cache
@login_required
@role_required(['admin', 'operator'])
def servers_page():
    groups = list_groups()
    servers = list_servers()
    return render_template("servers.html", groups=groups, servers=servers)

@app.route("/reports")
@no_cache
@login_required
def reports_page():
    return render_template("reports.html")

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
            return jsonify({"ok": False, "msg": "分组名称包含非法字符"}), 400
        add_group(name)
        return jsonify({"ok": True})
    elif request.method == "DELETE":
        gid = int(request.args.get("id"))
        delete_group(gid)
        return jsonify({"ok": True})

@app.route("/api/servers", methods=["GET", "POST", "DELETE"])
@login_required
@role_required(['admin', 'operator'])
def api_servers():
    if request.method == "GET":
        gid = request.args.get("group_id")
        gid = int(gid) if gid else None
        servers = list_servers(gid)
        for server in servers:
            server.pop('enc_password', None)
            server.pop('enc_private_key', None)
            server.pop('enc_key_passphrase', None)
        return jsonify(servers)
    elif request.method == "POST":
        data = request.json or {}
        ip = data.get("ip", "").strip()
        try:
            port = int(data.get("port", 22))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "msg": "端口格式无效"}), 400
        username = data.get("username", "").strip()
        auth_type = data.get("auth_type", "password")
        password = data.get("password", "")
        private_key = data.get("private_key", "")
        key_passphrase = data.get("key_passphrase", "")
        group_ids = data.get("group_ids", [])  # 支持多分组
        notes = data.get("notes","")
        if not is_valid_host(ip):
            return jsonify({"ok": False, "msg": "IP地址或主机名格式无效"}), 400
        if not 1 <= port <= 65535:
            return jsonify({"ok": False, "msg": "端口必须在1到65535之间"}), 400
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', username):
            return jsonify({"ok": False, "msg": "用户名格式无效"}), 400
        if auth_type not in ("password", "key"):
            return jsonify({"ok": False, "msg": "SSH认证方式无效"}), 400
        if auth_type == "password":
            if not password or len(password) > 1024:
                return jsonify({"ok": False, "msg": "密码不能为空或过长"}), 400
        else:
            if not private_key or len(private_key) > 65536:
                return jsonify({"ok": False, "msg": "SSH私钥不能为空或过长"}), 400
            if len(key_passphrase) > 1024:
                return jsonify({"ok": False, "msg": "私钥口令过长"}), 400
            try:
                parse_private_key(private_key, key_passphrase or None)
            except ValueError as exc:
                return jsonify({"ok": False, "msg": str(exc)}), 400
        if not is_safe_display_text(notes, 500):
            return jsonify({"ok": False, "msg": "备注包含非法字符"}), 400
        key = load_aes_key()
        enc_password = aes_gcm_encrypt(key, password) if auth_type == "password" else ""
        enc_private_key = aes_gcm_encrypt(key, private_key) if auth_type == "key" else None
        enc_key_passphrase = (
            aes_gcm_encrypt(key, key_passphrase)
            if auth_type == "key" and key_passphrase else None
        )
        add_server(
            ip, port, username, enc_password, group_ids, notes,
            auth_type=auth_type, enc_private_key=enc_private_key,
            enc_key_passphrase=enc_key_passphrase,
        )
        return jsonify({"ok": True})
    elif request.method == "DELETE":
        sid = int(request.args.get("id"))
        delete_server(sid)
        return jsonify({"ok": True})

# ------------- Reports -------------
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
        schedule_time=schedule_time
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
        schedule_time=schedule_time
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
    
    toggle_task_schedule(task_id)
    return jsonify({"ok": True, "msg": "定时状态已切换"})

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
                       check_disk=True, enable_proxy=False, proxy_rules=None,
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
    inspection_progress[run_id] = {
        "message": message,
        "percent": percent,
        "report_path": report_path
    }
    update_inspection_run_progress(run_id, message, percent, report_path)
    # 保存进度到文件，防止服务器重启丢失
    save_progress(inspection_progress)

def get_servers_by_group_param(group_param):
    """根据分组参数获取服务器列表"""
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

def run_inspection(run_id: str, project_name: str, inspector: str, report_format: str = "excel", 
                   resource_group_id=None, check_cpu=True, check_mem=True, check_disk=True,
                   enable_proxy=False, proxy_rules=None, task_id=None, task_name=None):
    key = load_aes_key()
    proxy_rules = proxy_rules or []
    
    # 资源巡检使用的分组
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
            report_path = generate_pdf_report(project_name, inspector, date_str, rows, proxy_results, check_cpu, check_mem, check_disk, task_name)
        else:
            report_path = generate_excel_report(project_name, inspector, date_str, rows, proxy_results, check_cpu, check_mem, check_disk, task_name)
        
        msg = f"报告已生成: {os.path.basename(report_path)}"
        update_progress(run_id, msg, 100, report_path)
        socketio.emit("progress", {
            "run_id": run_id,
            "message": msg,
            "percent": 100,
            "report_path": report_path
        })
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
            return jsonify({
                "message": run.get("message") or "",
                "percent": run.get("progress") or 0,
                "report_path": run.get("report_path"),
                "status": run.get("status"),
                "error": run.get("error")
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

# ---------------- Scheduler ----------------
_scheduler_thread = None
_scheduler_lock = threading.Lock()


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

def main():
    logger.info("Starting Ops Inspection System...")
    insecure_settings = security_config_warnings()
    for warning in insecure_settings:
        logger.warning("安全配置提示: %s", warning)
    start_queue_workers()
    start_scheduler()
    
    try:
        socketio.run(
            app, host=HOST, port=PORT, debug=DEBUG,
            allow_unsafe_werkzeug=True, use_reloader=False
        )
    except TypeError as e:
        # Python 3.14与Werkzeug兼容性问题回退
        logger.warning(f"SocketIO启动失败，尝试直接使用Flask: {e}")
        app.run(host=HOST, port=PORT, debug=DEBUG, threaded=True)

if __name__ == "__main__":
    main()
