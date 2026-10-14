# -*- coding: utf-8 -*-
"""
Global configuration for the Ops Inspection System.
"""
import base64
import binascii
import os
import secrets


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_DIR = os.path.join(BASE_DIR, "logs")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(DATA_DIR, exist_ok=True)


def _write_private_file_once(path, payload):
    """Create a persisted secret without replacing an existing deployment key."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if os.path.getsize(path) > 0:
            return
        fd = os.open(path, os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _persistent_session_key():
    configured = (os.environ.get("OPS_SECRET_KEY") or "").strip()
    if configured and configured != "change-me":
        return configured
    path = os.path.join(DATA_DIR, ".ops_session_key")
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        _write_private_file_once(path, secrets.token_hex(32).encode("ascii"))
    with open(path, "r", encoding="ascii") as handle:
        return handle.read().strip()

HOST = os.environ.get("OPS_HOST", "0.0.0.0")
PORT = int(os.environ.get("OPS_PORT", "1999"))
DEBUG = os.environ.get("OPS_DEBUG", "1") == "1"
SECRET_KEY = _persistent_session_key()
DEFAULT_ADMIN_PASSWORD = os.environ.get("OPS_ADMIN_PASSWORD", "Admin@123")
SSH_STRICT_HOST_KEY = os.environ.get("OPS_SSH_STRICT_HOST_KEY", "0" if DEBUG else "1") == "1"
QUEUE_WORKERS = max(1, int(os.environ.get("OPS_QUEUE_WORKERS", "2")))
QUEUE_RETRY_DELAY = max(1, int(os.environ.get("OPS_QUEUE_RETRY_DELAY", "10")))

AES_KEY_ENV = (os.environ.get("OPS_AES_KEY") or "").strip()
AES_KEY_FILE = (os.environ.get("OPS_AES_KEY_FILE") or "").strip() or os.path.join(DATA_DIR, ".ops_aes_key")


def _decode_aes_key(raw):
    if len(raw) in (16, 24, 32):
        return raw
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        text = ""
    if text:
        try:
            decoded = bytes.fromhex(text)
            if len(decoded) in (16, 24, 32):
                return decoded
        except ValueError:
            pass
        try:
            decoded = base64.b64decode(text, validate=True)
            if len(decoded) in (16, 24, 32):
                return decoded
        except (ValueError, TypeError, binascii.Error):
            pass
    raise ValueError("AES 密钥长度必须为 16、24 或 32 字节")

def load_aes_key():
    if AES_KEY_ENV:
        return _decode_aes_key(AES_KEY_ENV.encode("ascii"))
    if not os.path.exists(AES_KEY_FILE) or os.path.getsize(AES_KEY_FILE) == 0:
        legacy_db = os.path.join(DATA_DIR, "ops.db")
        key = (
            b"0123456789abcdef0123456789abcdef"
            if os.path.exists(legacy_db) and os.path.getsize(legacy_db) > 0
            else os.urandom(32)
        )
        _write_private_file_once(AES_KEY_FILE, key)
    if os.path.exists(AES_KEY_FILE):
        with open(AES_KEY_FILE, "rb") as f:
            return _decode_aes_key(f.read())
    raise RuntimeError(f"无法创建或读取 AES 密钥文件: {AES_KEY_FILE}")


def _is_local_url(url: str) -> bool:
    """粗判大模型地址是否指向本机/内网，用于出网合规提示。"""
    from urllib.parse import urlparse
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if host in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
        return True
    return host.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                            "172.2", "172.30.", "172.31."))


def security_config_warnings():
    warnings = []
    if AI_ENABLED:
        if AI_BASE_URL and not _is_local_url(AI_BASE_URL):
            warnings.append(
                "AI 接入的是外部大模型服务（OPS_AI_BASE_URL 非本机/内网地址），"
                "服务器信息与巡检数据会发送到该服务，请确认符合数据出网要求"
            )
        if not AI_VERIFY_TLS:
            warnings.append("OPS_AI_VERIFY_TLS=0，大模型请求不校验 TLS 证书")
    return warnings

CPU_THRESHOLD = float(os.environ.get("OPS_CPU_THRESHOLD", "80"))
MEM_THRESHOLD = float(os.environ.get("OPS_MEM_THRESHOLD", "80"))
DISK_THRESHOLD = float(os.environ.get("OPS_DISK_THRESHOLD", "80"))


def _env_extra(names, defaults):
    """内置白名单 + 环境变量里以逗号分隔的追加项。"""
    extra = os.environ.get(names, "")
    return defaults + tuple(item.strip() for item in extra.split(",") if item.strip())


# ========== 磁盘巡检增强（掉盘 / 磁盘损坏 / 容量异常）==========
# 判定阈值都可以用环境变量调整，现场按实际情况放宽或收紧。
DISK_AUDIT_INODE_THRESHOLD = float(os.environ.get("OPS_DISK_INODE_THRESHOLD", "80"))
DISK_AUDIT_BURST_GB = float(os.environ.get("OPS_DISK_BURST_GB", "20"))
DISK_AUDIT_GROWTH_GB_PER_DAY = float(os.environ.get("OPS_DISK_GROWTH_GB_PER_DAY", "20"))
DISK_AUDIT_GROWTH_PERCENT_PER_DAY = float(os.environ.get("OPS_DISK_GROWTH_PERCENT_PER_DAY", "5"))
DISK_AUDIT_SHRINK_GB_PER_DAY = float(os.environ.get("OPS_DISK_SHRINK_GB_PER_DAY", "20"))
DISK_AUDIT_FULL_WARN_DAYS = float(os.environ.get("OPS_DISK_FULL_WARN_DAYS", "7"))
DISK_AUDIT_SMALL_FS_GB = float(os.environ.get("OPS_DISK_SMALL_FS_GB", "10"))
DISK_AUDIT_BASELINE_MIN_HOURS = float(os.environ.get("OPS_DISK_BASELINE_MIN_HOURS", "12"))
DISK_AUDIT_BASELINE_MAX_HOURS = float(os.environ.get("OPS_DISK_BASELINE_MAX_HOURS", "48"))
DISK_AUDIT_RECENT_MIN_MINUTES = float(os.environ.get("OPS_DISK_RECENT_MIN_MINUTES", "30"))
DISK_AUDIT_KEEP_DAYS = int(os.environ.get("OPS_DISK_SNAPSHOT_KEEP_DAYS", "90"))

# 内核虚拟文件系统、容器与临时挂载不参与"掉盘"判定，否则天天误报。
DISK_AUDIT_EXCLUDE_FSTYPES = _env_extra("OPS_DISK_EXCLUDE_FSTYPES", (
    "tmpfs", "devtmpfs", "devpts", "sysfs", "proc", "cgroup", "cgroup2", "pstore",
    "securityfs", "debugfs", "tracefs", "configfs", "fusectl", "mqueue", "hugetlbfs",
    "bpf", "binfmt_misc", "rpc_pipefs", "nfsd", "autofs", "overlay", "overlayfs",
    "squashfs", "iso9660", "ramfs", "efivarfs",
))
DISK_AUDIT_EXCLUDE_PATHS = _env_extra("OPS_DISK_EXCLUDE_PATHS", (
    "/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/var/lib/kubelet",
    "/var/lib/containers", "/var/lib/containerd",
))

# 允许查看服务账号密码的角色。安全要求高的环境可设为 admin。
SERVICE_REVEAL_ROLES = [
    role.strip()
    for role in os.environ.get("OPS_SERVICE_REVEAL_ROLES", "admin,operator").split(",")
    if role.strip()
]

# ========== AI 智能运维（大模型接入）==========
# 大模型接入：库里的 ai_providers 优先；库里没有时用下面这组环境变量兜底，
# 页面上会显示成一张只读配置，可直接选用但不能编辑。
def _env_flag(name, default=False):
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name, default, minimum=1, maximum=None):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    value = max(minimum, value)
    return min(maximum, value) if maximum else value


def _env_path(name, default):
    value = (os.environ.get(name) or "").strip() or default
    if not os.path.isabs(value):
        value = os.path.join(BASE_DIR, value)
    return os.path.abspath(value)


AI_ENABLED = _env_flag("OPS_AI_ENABLED", True)
AI_ROLES = [
    role.strip()
    for role in os.environ.get("OPS_AI_ROLES", "admin,operator").split(",")
    if role.strip()
]
AI_BASE_URL = os.environ.get("OPS_AI_BASE_URL", "").strip()
AI_API_KEY = os.environ.get("OPS_AI_API_KEY", "").strip()
AI_MODEL = os.environ.get("OPS_AI_MODEL", "").strip()
AI_ALLOW_CLOUD = _env_flag("OPS_AI_ALLOW_CLOUD", True)

AI_CONNECT_TIMEOUT = _env_int("OPS_AI_CONNECT_TIMEOUT", 10, 1, 120)
AI_TIMEOUT = _env_int("OPS_AI_TIMEOUT", 120, 5, 1800)
AI_TOTAL_DEADLINE = _env_int("OPS_AI_TOTAL_DEADLINE", 180, 10, 3600)
AI_MAX_TOKENS = _env_int("OPS_AI_MAX_TOKENS", 2048, 16, 32000)
AI_TEMPERATURE = float(os.environ.get("OPS_AI_TEMPERATURE", "0.2") or 0.2)
AI_MAX_TOOL_ROUNDS = _env_int("OPS_AI_MAX_TOOL_ROUNDS", 6, 1, 20)
AI_MAX_CONTEXT_MESSAGES = _env_int("OPS_AI_MAX_CONTEXT_MESSAGES", 20, 2, 200)
AI_MAX_CONCURRENCY = _env_int("OPS_AI_MAX_CONCURRENCY", 2, 1, 16)
AI_INPUT_MAX_CHARS = _env_int("OPS_AI_INPUT_MAX_CHARS", 4000, 100, 32000)
AI_TOOL_MODE = (os.environ.get("OPS_AI_TOOL_MODE", "auto") or "auto").strip().lower()
AI_TOOL_RESULT_LIMIT = _env_int("OPS_AI_TOOL_RESULT_LIMIT", 4000, 200, 60000)
AI_STREAM_KEEP_SECONDS = _env_int("OPS_AI_STREAM_KEEP_SECONDS", 600, 30, 7200)
AI_TRADITIONAL_FALLBACK = _env_flag("OPS_AI_TRADITIONAL_FALLBACK", True)

# 远程命令的执行权限由每轮会话访问模式控制。
AI_REMOTE_READ_TIMEOUT = _env_int("OPS_AI_REMOTE_READ_TIMEOUT", 15, 3, 120)

# T2：有副作用的操作必须人工确认后才执行。
AI_ACTION_TTL = _env_int("OPS_AI_ACTION_TTL", 600, 30, 86400)

AI_KEEP_DAYS = _env_int("OPS_AI_KEEP_DAYS", 90, 0, 3650)
AI_DAILY_TOKEN_LIMIT = _env_int("OPS_AI_DAILY_TOKEN_LIMIT", 0, 0, 10 ** 9)

AI_VERIFY_TLS = _env_flag("OPS_AI_VERIFY_TLS", True)
AI_CA_BUNDLE = os.environ.get("OPS_AI_CA_BUNDLE", "").strip()
AI_PROXY = os.environ.get("OPS_AI_PROXY", "").strip()
AI_MASK_IP = _env_flag("OPS_AI_MASK_IP", False)
AI_ANALYZE_AFTER_INSPECTION = _env_flag("OPS_AI_ANALYZE_AFTER_INSPECTION", False)
AI_SKILLS_DIR = _env_path("OPS_AI_SKILLS_DIR", os.path.join(BASE_DIR, "skills"))
AI_MCP_CONFIG = _env_path("OPS_AI_MCP_CONFIG", os.path.join(DATA_DIR, "mcp_servers.json"))

SQLITE_PATH = os.path.join(DATA_DIR, "ops.db")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(AI_SKILLS_DIR, exist_ok=True)
