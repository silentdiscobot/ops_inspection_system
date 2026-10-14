# -*- coding: utf-8 -*-
from typing import Optional, List
import sqlite3, json, os
from datetime import datetime, timedelta
from config import (
    SQLITE_PATH,
    CPU_THRESHOLD,
    MEM_THRESHOLD,
    DISK_THRESHOLD,
    DISK_AUDIT_BASELINE_MAX_HOURS,
    DISK_AUDIT_BASELINE_MIN_HOURS,
    DISK_AUDIT_KEEP_DAYS,
    DISK_AUDIT_RECENT_MIN_MINUTES,
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS server_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL,
    resource_type TEXT NOT NULL DEFAULT '虚拟机',
    physical_ip TEXT,
    os_type TEXT NOT NULL DEFAULT 'Centos',
    rack_number TEXT,
    room_affiliation TEXT,
    rack_level TEXT,
    port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL,
    enc_password TEXT NOT NULL,
    auth_type TEXT NOT NULL DEFAULT 'password',
    enc_private_key TEXT,
    enc_key_passphrase TEXT,
    notes TEXT
);
CREATE TABLE IF NOT EXISTS server_group_memberships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE,
    FOREIGN KEY(group_id) REFERENCES server_groups(id) ON DELETE CASCADE,
    UNIQUE(server_id, group_id)
);
CREATE TABLE IF NOT EXISTS server_hardware_snapshots (
    server_id INTEGER PRIMARY KEY,
    cpu TEXT,
    memory TEXT,
    storage TEXT,
    gpu TEXT,
    collected_at TEXT,
    checked_at TEXT NOT NULL,
    last_error TEXT,
    change_summary TEXT,
    changed_at TEXT,
    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS disk_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    snapshot_date TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    findings TEXT,
    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_disk_snapshots_server_date
    ON disk_snapshots(server_id, snapshot_date);
CREATE INDEX IF NOT EXISTS idx_disk_snapshots_collected_at
    ON disk_snapshots(collected_at);
CREATE TABLE IF NOT EXISTS resource_baselines (
    server_id INTEGER PRIMARY KEY,
    payload TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'initial',
    accepted_by TEXT,
    accepted_reason TEXT,
    accepted_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS resource_change_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    expected_payload TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    reason TEXT NOT NULL,
    ticket_no TEXT,
    status TEXT NOT NULL DEFAULT 'planned',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    matched_at TEXT,
    cancelled_at TEXT,
    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_resource_plans_server_status
    ON resource_change_plans(server_id, status, window_start, window_end);
CREATE TABLE IF NOT EXISTS resource_change_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    baseline_payload TEXT NOT NULL,
    observed_payload TEXT NOT NULL,
    change_detail TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    decided_by TEXT,
    decision_reason TEXT,
    decided_at TEXT,
    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_resource_events_server_status
    ON resource_change_events(server_id, status, last_seen_at);
CREATE TABLE IF NOT EXISTS inspection_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    project_name TEXT NOT NULL,
    inspector TEXT NOT NULL,
    report_format TEXT DEFAULT 'excel',
    resource_group_id TEXT,
    check_cpu INTEGER DEFAULT 1,
    check_mem INTEGER DEFAULT 1,
    check_disk INTEGER DEFAULT 1,
    enable_proxy INTEGER DEFAULT 0,
    proxy_rules TEXT,
    enable_schedule INTEGER DEFAULT 0,
    schedule_time TEXT,
    last_run TEXT,
    created_at TEXT NOT NULL,
    cpu_threshold REAL,
    mem_threshold REAL,
    disk_threshold REAL
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT,
    password TEXT NOT NULL,
    contact TEXT,
    role TEXT NOT NULL DEFAULT 'viewer',
    created_at TEXT NOT NULL,
    is_default INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS inspection_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT UNIQUE NOT NULL,
    task_id INTEGER,
    task_name TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'manual',
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    progress INTEGER NOT NULL DEFAULT 0,
    message TEXT,
    report_path TEXT,
    error TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 2,
    next_retry_at TEXT,
    dedupe_key TEXT UNIQUE,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    FOREIGN KEY(task_id) REFERENCES inspection_tasks(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_inspection_runs_queue
ON inspection_runs(status, next_retry_at, created_at);
CREATE TABLE IF NOT EXISTS inspection_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    server_ip TEXT NOT NULL,
    ok INTEGER NOT NULL DEFAULT 0,
    uptime TEXT,
    cpu REAL DEFAULT 0,
    mem REAL DEFAULT 0,
    disk REAL DEFAULT 0,
    error TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES inspection_runs(run_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_inspection_results_run_id
ON inspection_results(run_id);
CREATE TABLE IF NOT EXISTS service_infos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL DEFAULT '',
    server_id INTEGER NOT NULL,
    service_type TEXT NOT NULL DEFAULT '应用服务',
    run_mode TEXT NOT NULL DEFAULT 'systemd',
    version TEXT,
    deploy_dir TEXT,
    start_command TEXT,
    stop_command TEXT,
    restart_command TEXT,
    ports TEXT,
    config_path TEXT,
    log_path TEXT,
    access_url TEXT,
    owner TEXT,
    status TEXT NOT NULL DEFAULT '运行中',
    auto_start INTEGER NOT NULL DEFAULT 0,
    notes TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE,
    UNIQUE(server_id, name)
);
CREATE INDEX IF NOT EXISTS idx_service_infos_server_id ON service_infos(server_id);
CREATE INDEX IF NOT EXISTS idx_service_infos_status ON service_infos(status);
CREATE TABLE IF NOT EXISTS service_systems (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS service_system_memberships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL,
    system_id INTEGER NOT NULL,
    FOREIGN KEY(service_id) REFERENCES service_infos(id) ON DELETE CASCADE,
    FOREIGN KEY(system_id) REFERENCES service_systems(id) ON DELETE CASCADE,
    UNIQUE(service_id, system_id)
);
CREATE TABLE IF NOT EXISTS service_environments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS service_environment_memberships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL,
    environment_id INTEGER NOT NULL,
    FOREIGN KEY(service_id) REFERENCES service_infos(id) ON DELETE CASCADE,
    FOREIGN KEY(environment_id) REFERENCES service_environments(id) ON DELETE CASCADE,
    UNIQUE(service_id, environment_id)
);
CREATE TABLE IF NOT EXISTS service_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL,
    purpose TEXT,
    username TEXT NOT NULL DEFAULT '',
    secret_type TEXT NOT NULL DEFAULT '密码',
    enc_password TEXT,
    remark TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    FOREIGN KEY(service_id) REFERENCES service_infos(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_service_accounts_service_id ON service_accounts(service_id);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    client_ip TEXT,
    action TEXT NOT NULL,
    result TEXT,
    target_type TEXT,
    target_id INTEGER,
    target_name TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_username_created
    ON audit_logs(username, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_result_created
    ON audit_logs(result, created_at DESC);
CREATE TABLE IF NOT EXISTS operation_audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    client_ip TEXT,
    server_id INTEGER,
    server_name TEXT NOT NULL DEFAULT '',
    server_ip TEXT NOT NULL DEFAULT '',
    command TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'success',
    error TEXT,
    source_action_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_operation_audits_created_at
    ON operation_audits(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operation_audits_username_created
    ON operation_audits(username, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operation_audits_server_created
    ON operation_audits(server_id, created_at DESC);
-- ========== AI 智能运维（大模型接入）==========
CREATE TABLE IF NOT EXISTS ai_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    base_url TEXT NOT NULL,
    model TEXT NOT NULL,
    enc_api_key TEXT,
    deployment TEXT NOT NULL DEFAULT 'cloud',
    temperature REAL NOT NULL DEFAULT 0.2,
    max_tokens INTEGER NOT NULL DEFAULT 2048,
    timeout INTEGER NOT NULL DEFAULT 120,
    supports_tools INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    is_default INTEGER NOT NULL DEFAULT 0,
    extra_headers TEXT,
    last_test_at TEXT, last_test_ok INTEGER, last_test_error TEXT,
    created_at TEXT NOT NULL, updated_at TEXT, created_by TEXT
);
CREATE TABLE IF NOT EXISTS ai_conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL DEFAULT '新会话',
    username TEXT NOT NULL,
    provider_id INTEGER,
    model TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(provider_id) REFERENCES ai_providers(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_conversations_user ON ai_conversations(username, updated_at);
CREATE TABLE IF NOT EXISTS ai_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'done',
    error TEXT,
    tool_calls TEXT,
    tool_name TEXT, tool_call_id TEXT, tool_args TEXT,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    tokens_estimated INTEGER NOT NULL DEFAULT 0,
    provider_id INTEGER, model TEXT, duration_ms INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY(conversation_id) REFERENCES ai_conversations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ai_messages_conversation ON ai_messages(conversation_id, id);
CREATE TABLE IF NOT EXISTS ai_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    message_id INTEGER,
    action_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    risk_level TEXT NOT NULL DEFAULT 'medium',
    summary TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    result TEXT, error TEXT,
    requested_by TEXT NOT NULL, decided_by TEXT,
    created_at TEXT NOT NULL, decided_at TEXT, executed_at TEXT, expires_at TEXT,
    FOREIGN KEY(conversation_id) REFERENCES ai_conversations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ai_actions_status ON ai_actions(status, expires_at);
CREATE TABLE IF NOT EXISTS ai_service_discovery_scans (
    id TEXT PRIMARY KEY,
    server_id INTEGER NOT NULL,
    requested_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ready',
    candidates TEXT NOT NULL,
    warnings TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ai_discovery_scans_expiry
ON ai_service_discovery_scans(expires_at, status);
CREATE TABLE IF NOT EXISTS ai_insights (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL DEFAULT 'run',
    run_id TEXT, server_id INTEGER,
    provider_id INTEGER, model TEXT,
    content TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'done', error TEXT,
    username TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_insights_run ON ai_insights(run_id);
"""

def get_conn():
    os.makedirs(os.path.dirname(SQLITE_PATH), exist_ok=True)
    conn = sqlite3.connect(SQLITE_PATH, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA encoding='UTF-8'")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.executescript(SCHEMA_SQL)
    cur.execute("PRAGMA table_info(servers)")
    server_columns = {row[1] for row in cur.fetchall()}
    if 'auth_type' not in server_columns:
        cur.execute("ALTER TABLE servers ADD COLUMN auth_type TEXT NOT NULL DEFAULT 'password'")
    if 'enc_private_key' not in server_columns:
        cur.execute("ALTER TABLE servers ADD COLUMN enc_private_key TEXT")
    if 'enc_key_passphrase' not in server_columns:
        cur.execute("ALTER TABLE servers ADD COLUMN enc_key_passphrase TEXT")
    for column, definition in {
        'name': "TEXT NOT NULL DEFAULT ''",
        'resource_type': "TEXT NOT NULL DEFAULT '虚拟机'",
        'physical_ip': "TEXT",
        'os_type': "TEXT NOT NULL DEFAULT 'Centos'",
        'rack_number': "TEXT",
        'room_affiliation': "TEXT",
        'rack_level': "TEXT",
    }.items():
        if column not in server_columns:
            cur.execute(f"ALTER TABLE servers ADD COLUMN {column} {definition}")
    cur.execute("PRAGMA table_info(operation_audits)")
    operation_audit_columns = {row[1] for row in cur.fetchall()}
    if 'source_action_id' not in operation_audit_columns:
        cur.execute("ALTER TABLE operation_audits ADD COLUMN source_action_id INTEGER")
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_operation_audits_source_action
        ON operation_audits(source_action_id)
        WHERE source_action_id IS NOT NULL
    """)
    cur.execute("PRAGMA journal_mode=WAL")
    _sync_environment_groups(cur)
    _bootstrap_resource_baselines(cur)
    _backfill_operation_audits(cur)
    conn.commit()
    conn.close()

def row_to_dict(cursor, row):
    return {d[0]: row[i] for i, d in enumerate(cursor.description)}


def _backfill_operation_audits(cur):
    """将旧版 AI 确认单中已执行的命令一次性迁入专用审计表。"""
    actions = cur.execute("""
        SELECT id, action_type, payload, status, error, requested_by, decided_by,
               created_at, decided_at, executed_at
        FROM ai_actions
        WHERE action_type IN ('run_remote_command', 'restart_registered_service')
          AND status IN ('executed', 'failed')
        ORDER BY id
    """).fetchall()
    for action in actions:
        (action_id, _action_type, raw_payload, action_status, error, requested_by,
         decided_by, created_at, decided_at, executed_at) = action
        try:
            payload = json.loads(raw_payload or "{}")
        except (TypeError, ValueError):
            continue
        command = str(payload.get("command") or "").strip()
        if not command and _action_type == "restart_registered_service":
            try:
                service_id = int(payload.get("service_id"))
            except (TypeError, ValueError):
                service_id = None
            service = cur.execute(
                "SELECT restart_command, server_id FROM service_infos WHERE id=?",
                (service_id,),
            ).fetchone() if service_id is not None else None
            if service:
                command = str(service[0] or "").strip()
                payload.setdefault("server_id", service[1])
        if not command:
            continue
        try:
            server_id = int(payload.get("server_id"))
        except (TypeError, ValueError):
            server_id = None
        server = cur.execute(
            "SELECT name, ip FROM servers WHERE id=?", (server_id,)
        ).fetchone() if server_id is not None else None
        server_name = server[0] if server else str(payload.get("server_name") or "")
        server_ip = server[1] if server else str(payload.get("server_ip") or "")
        cur.execute("""
            INSERT OR IGNORE INTO operation_audits(
                created_at, username, client_ip, server_id, server_name, server_ip,
                command, status, error, source_action_id
            ) VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, ?)
        """, (
            executed_at or decided_at or created_at or _now_text(),
            decided_by or requested_by or "", server_id, server_name or "", server_ip or "",
            command[:2000], "success" if action_status == "executed" else "failed",
            str(error or "")[:500], action_id,
        ))


def _sync_environment_groups(cur):
    """兼容旧"服务器分组"：以后统一用 service_environments 作为环境字典。

    server_group_memberships 仍保留，避免巡检筛选与服务器关联关系大迁移；
    server_groups 只作为外键镜像表，实际展示与维护都读取 service_environments。
    """
    cur.execute("""
        INSERT OR IGNORE INTO service_environments(id, name)
        SELECT id, name FROM server_groups
    """)
    cur.execute("""
        INSERT OR IGNORE INTO server_groups(id, name)
        SELECT id, name FROM service_environments
    """)


def _bootstrap_resource_baselines(cur):
    """老库升级时用已有有效硬件记录建立一次初始基线，不覆盖后续人工结论。"""
    rows = cur.execute("""
        SELECT h.server_id, h.cpu, h.memory, h.storage, h.collected_at
        FROM server_hardware_snapshots h
        LEFT JOIN resource_baselines b ON b.server_id=h.server_id
        WHERE b.server_id IS NULL AND h.collected_at IS NOT NULL
    """).fetchall()
    now = _now_text()
    for server_id, cpu, memory, storage, collected_at in rows:
        hardware = {
            key: str(value).strip()
            for key, value in (('cpu', cpu), ('memory', memory), ('storage', storage))
            if value and str(value).strip() not in ('未知', '采集失败')
        }
        if not hardware:
            continue
        accepted_at = collected_at or now
        cur.execute("""
            INSERT OR IGNORE INTO resource_baselines(
                server_id, payload, version, source, accepted_by, accepted_reason,
                accepted_at, updated_at)
            VALUES(?, ?, 1, 'initial', '', '由已有硬件记录初始化', ?, ?)
        """, (
            server_id, json.dumps({'hardware': hardware}, ensure_ascii=False),
            accepted_at, now,
        ))


def list_groups():
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM service_environments ORDER BY name")
    rows = cur.fetchall()
    conn.close()
    return rows

def add_group(name: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO service_environments(name) VALUES (?)", (name,))
    cur.execute("SELECT id, name FROM service_environments WHERE name=?", (name,))
    row = cur.fetchone()
    if row:
        cur.execute("INSERT OR IGNORE INTO server_groups(id, name) VALUES (?, ?)", row)
    conn.commit()
    conn.close()

def delete_group(group_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM server_group_memberships WHERE group_id=?", (group_id,))
    cur.execute("DELETE FROM service_environment_memberships WHERE environment_id=?", (group_id,))
    cur.execute("DELETE FROM service_environments WHERE id=?", (group_id,))
    cur.execute("DELETE FROM server_groups WHERE id=?", (group_id,))
    conn.commit()
    conn.close()

def list_servers(group_id: Optional[int] = None, keyword: str = "",
                 resource_type: str = "", os_type: str = ""):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    
    filters = []
    params = []
    if keyword:
        filters.append("(s.name LIKE ? OR s.ip LIKE ? OR s.physical_ip LIKE ? OR s.notes LIKE ?)")
        pattern = f"%{keyword}%"
        params.extend([pattern, pattern, pattern, pattern])
    if resource_type:
        filters.append("s.resource_type = ?")
        params.append(resource_type)
    if os_type:
        filters.append("s.os_type = ?")
        params.append(os_type)

    if group_id is None:
        # 获取所有服务器及其环境项信息
        where_sql = (" WHERE " + " AND ".join(filters)) if filters else ""
        cur.execute("SELECT s.* FROM servers s" + where_sql + """
            ORDER BY
              CASE WHEN s.resource_type = '虚拟机' AND COALESCE(s.physical_ip, '') <> ''
                   THEN s.physical_ip ELSE s.ip END,
              CASE s.resource_type WHEN '物理机' THEN 0 WHEN '虚拟机' THEN 1 ELSE 2 END,
              s.ip
        """, params)
        servers = cur.fetchall()
        
        # 为每个服务器获取所属环境
        for server in servers:
            cur.execute("""
                SELECT g.* FROM service_environments g 
                INNER JOIN server_group_memberships m ON g.id = m.group_id
                WHERE m.server_id = ?
            """, (server['id'],))
            server['groups'] = cur.fetchall()
            server['group_names'] = ', '.join([g['name'] for g in server['groups']]) if server['groups'] else '无'
        conn.close()
        return servers
    else:
        # 获取指定环境项的服务器
        filters.insert(0, "m.group_id = ?")
        params.insert(0, group_id)
        cur.execute("""
            SELECT s.* FROM servers s
            INNER JOIN server_group_memberships m ON s.id = m.server_id
            WHERE """ + " AND ".join(filters) + """
            ORDER BY
              CASE WHEN s.resource_type = '虚拟机' AND COALESCE(s.physical_ip, '') <> ''
                   THEN s.physical_ip ELSE s.ip END,
              CASE s.resource_type WHEN '物理机' THEN 0 WHEN '虚拟机' THEN 1 ELSE 2 END,
              s.ip
        """, params)
        servers = cur.fetchall()
        
        # 为每个服务器获取所属环境
        for server in servers:
            cur.execute("""
                SELECT g.* FROM service_environments g 
                INNER JOIN server_group_memberships m ON g.id = m.group_id
                WHERE m.server_id = ?
            """, (server['id'],))
            server['groups'] = cur.fetchall()
            server['group_names'] = ', '.join([g['name'] for g in server['groups']]) if server['groups'] else '无'
        conn.close()
        return servers

def add_server(ip: str, port: int, username: str, enc_password: str,
               group_ids: Optional[List[int]] = None, notes: str="",
               auth_type: str = "password", enc_private_key: str = None,
               enc_key_passphrase: str = None, name: str = "",
               resource_type: str = "虚拟机", physical_ip: str = "",
               os_type: str = "Centos", rack_number: str = "",
               room_affiliation: str = "", rack_level: str = ""):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO servers(
            ip, port, username, enc_password, auth_type,
            enc_private_key, enc_key_passphrase, notes, name, resource_type,
            physical_ip, os_type, rack_number, room_affiliation, rack_level
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ip, port, username, enc_password, auth_type,
        enc_private_key, enc_key_passphrase, notes, name, resource_type,
        physical_ip, os_type, rack_number, room_affiliation, rack_level
    ))
    server_id = cur.lastrowid
    
    # 添加环境关联
    if group_ids:
        for group_id in group_ids:
            try:
                cur.execute("""
                    INSERT OR IGNORE INTO server_group_memberships(server_id, group_id)
                    VALUES (?, ?)
                """, (server_id, group_id))
            except sqlite3.IntegrityError:
                pass  # 已存在，忽略
    
    conn.commit()
    conn.close()
    return server_id

def get_server(server_id: int):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM servers WHERE id=?", (server_id,))
    server = cur.fetchone()
    if server:
        cur.execute("SELECT group_id FROM server_group_memberships WHERE server_id=?", (server_id,))
        server['group_ids'] = [row['group_id'] for row in cur.fetchall()]
    conn.close()
    return server

def update_server(server_id: int, ip: str, port: int, username: str,
                  enc_password: str, group_ids: Optional[List[int]] = None,
                  notes: str = "", auth_type: str = "password",
                  enc_private_key: str = None, enc_key_passphrase: str = None,
                  name: str = "", resource_type: str = "虚拟机",
                  physical_ip: str = "", os_type: str = "Centos",
                  rack_number: str = "", room_affiliation: str = "",
                  rack_level: str = ""):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        UPDATE servers SET ip=?, port=?, username=?, enc_password=?, auth_type=?,
                           enc_private_key=?, enc_key_passphrase=?, notes=?, name=?,
                           resource_type=?, physical_ip=?, os_type=?, rack_number=?,
                           room_affiliation=?, rack_level=?
        WHERE id=?
    """, (
        ip, port, username, enc_password, auth_type,
        enc_private_key, enc_key_passphrase, notes, name, resource_type,
        physical_ip, os_type, rack_number, room_affiliation, rack_level, server_id
    ))
    if cur.rowcount == 0:
        conn.close()
        return False
    cur.execute("DELETE FROM server_group_memberships WHERE server_id=?", (server_id,))
    for group_id in group_ids or []:
        cur.execute("""
            INSERT OR IGNORE INTO server_group_memberships(server_id, group_id)
            VALUES (?, ?)
        """, (server_id, group_id))
    conn.commit()
    conn.close()
    return True

def delete_server(server_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM servers WHERE id=?", (server_id,))
    conn.commit()
    conn.close()

# ---------------- 服务器硬件参数记录 ----------------
# 完整信息弹窗不再每次实时采集：首次记录后只保留最近一次参数，参数真的变化时才覆盖。
def get_server_hardware(server_id: int):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM server_hardware_snapshots WHERE server_id=?", (server_id,))
    snapshot = cur.fetchone()
    conn.close()
    return snapshot

def list_server_hardware_snapshots():
    """一次取回全部硬件参数记录，供列表页与后台核对线程复用。"""
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM server_hardware_snapshots")
    rows = cur.fetchall()
    conn.close()
    return {row['server_id']: row for row in rows}

def save_server_hardware(server_id: int, values: dict, collected_at: str,
                         checked_at: str, change_summary: str = None,
                         changed_at: str = None):
    """写入一次成功采集的结果；collected_at 只在参数发生变动时前移。"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO server_hardware_snapshots(
            server_id, cpu, memory, storage, gpu, collected_at, checked_at,
            last_error, change_summary, changed_at)
        VALUES(?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
        ON CONFLICT(server_id) DO UPDATE SET
            cpu=excluded.cpu, memory=excluded.memory, storage=excluded.storage,
            gpu=excluded.gpu, collected_at=excluded.collected_at,
            checked_at=excluded.checked_at, last_error=NULL,
            change_summary=excluded.change_summary, changed_at=excluded.changed_at
    """, (
        server_id, values.get('cpu'), values.get('memory'), values.get('storage'),
        values.get('gpu'), collected_at, checked_at, change_summary, changed_at,
    ))
    conn.commit()
    conn.close()

def mark_server_hardware_check(server_id: int, error: str, checked_at: str = None):
    """登记一次失败的核对：只更新核对时间和原因，保留最近一次有效参数。"""
    checked_at = checked_at or _now_text()
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO server_hardware_snapshots(server_id, checked_at, last_error)
        VALUES(?, ?, ?)
        ON CONFLICT(server_id) DO UPDATE SET
            checked_at=excluded.checked_at, last_error=excluded.last_error
    """, (server_id, checked_at, (error or '')[:200]))
    conn.commit()
    conn.close()

def delete_server_hardware(server_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM server_hardware_snapshots WHERE server_id=?", (server_id,))
    conn.commit()
    conn.close()

# ---------------- 磁盘巡检快照（掉盘 / 损坏 / 增长异常） ----------------
def _hours_since(text: str, now: datetime = None):
    if not text:
        return None
    try:
        moment = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None
    return max(0.0, ((now or datetime.now()) - moment).total_seconds() / 3600.0)

def _decode_disk_snapshot(row, now: datetime = None):
    """把库里的 JSON 字段解开，并算出距离现在多少小时。"""
    if not row:
        return None
    item = dict(row)
    for field, fallback in (('payload', {}), ('findings', [])):
        try:
            item[field] = json.loads(item.get(field)) if item.get(field) else fallback
        except (TypeError, ValueError):
            item[field] = fallback
    item['age_hours'] = _hours_since(item.get('collected_at'), now)
    return item

def save_disk_snapshot(server_id: int, payload: dict, collected_at: str, findings=None):
    """写入当天的磁盘快照；同一天重复巡检时覆盖为最近一次的结果。"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO disk_snapshots(server_id, snapshot_date, collected_at, payload, findings)
        VALUES(?, ?, ?, ?, ?)
        ON CONFLICT(server_id, snapshot_date) DO UPDATE SET
            collected_at=excluded.collected_at, payload=excluded.payload,
            findings=excluded.findings
    """, (
        server_id, (collected_at or _now_text())[:10], collected_at,
        json.dumps(payload or {}, ensure_ascii=False),
        json.dumps(findings or [], ensure_ascii=False),
    ))
    conn.commit()
    conn.close()

def list_disk_snapshots(server_id: int, limit: int = 120):
    """按时间倒序取最近的磁盘快照。"""
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM disk_snapshots WHERE server_id=? ORDER BY collected_at DESC LIMIT ?",
        (server_id, max(1, int(limit))),
    )
    rows = cur.fetchall()
    conn.close()
    now = datetime.now()
    return [_decode_disk_snapshot(row, now) for row in rows]

def get_disk_baselines(server_id: int, now: datetime = None, min_hours: float = None,
                       max_hours: float = None, recent_min_minutes: float = None):
    """取两个比对基线。

    prev_day：约一天前（12~48 小时内）的快照，用于掉盘、阵列与增长趋势；
    prev_recent：最近一次（至少半小时前，48 小时内）的快照，用于故障计数与突增；
    last_any：不管多久之前的最近一次快照，只用来措辞（判断是首次还是基线过旧）。
    """
    now = now or datetime.now()
    min_hours = DISK_AUDIT_BASELINE_MIN_HOURS if min_hours is None else min_hours
    max_hours = DISK_AUDIT_BASELINE_MAX_HOURS if max_hours is None else max_hours
    if recent_min_minutes is None:
        recent_min_minutes = DISK_AUDIT_RECENT_MIN_MINUTES
    oldest = (now - timedelta(hours=max_hours)).strftime("%Y-%m-%d %H:%M:%S")
    day_before = (now - timedelta(hours=min_hours)).strftime("%Y-%m-%d %H:%M:%S")
    recent_before = (now - timedelta(minutes=recent_min_minutes)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()

    def pick(condition, params):
        cur.execute(
            "SELECT * FROM disk_snapshots WHERE server_id=? " + condition +
            " ORDER BY collected_at DESC LIMIT 1",
            (server_id,) + params,
        )
        return cur.fetchone()

    prev_day = pick("AND collected_at >= ? AND collected_at <= ?", (oldest, day_before))
    prev_recent = pick("AND collected_at >= ? AND collected_at <= ?", (oldest, recent_before))
    last_any = pick("", ())
    conn.close()
    return {
        'prev_day': _decode_disk_snapshot(prev_day, now),
        'prev_recent': _decode_disk_snapshot(prev_recent, now),
        'last_any': _decode_disk_snapshot(last_any, now),
    }

def prune_disk_snapshots(keep_days: int = None):
    """清理过期快照，默认保留 90 天，返回删除行数。"""
    keep_days = DISK_AUDIT_KEEP_DAYS if keep_days is None else keep_days
    cutoff = (datetime.now() - timedelta(days=keep_days)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM disk_snapshots WHERE collected_at < ?", (cutoff,))
    removed = cur.rowcount
    conn.commit()
    conn.close()
    return removed

def delete_disk_snapshots(server_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM disk_snapshots WHERE server_id=?", (server_id,))
    conn.commit()
    conn.close()


# ---------------- 已确认资源基线 / 计划变更 / 人工确认 ----------------
def _decode_json_field(row, fields):
    if not row:
        return None
    item = dict(row)
    for field, fallback in fields:
        try:
            item[field] = json.loads(item.get(field)) if item.get(field) else fallback
        except (TypeError, ValueError):
            item[field] = fallback
    return item


def get_resource_baseline(server_id: int):
    conn = get_conn()
    conn.row_factory = row_to_dict
    row = conn.execute(
        "SELECT * FROM resource_baselines WHERE server_id=?", (server_id,)
    ).fetchone()
    conn.close()
    return _decode_json_field(row, (('payload', {}),))


def save_resource_baseline(server_id: int, payload: dict, source: str = 'initial',
                           accepted_by: str = '', accepted_reason: str = '',
                           accepted_at: str = None):
    now = accepted_at or _now_text()
    conn = get_conn()
    conn.execute("""
        INSERT INTO resource_baselines(
            server_id, payload, version, source, accepted_by, accepted_reason,
            accepted_at, updated_at)
        VALUES(?, ?, 1, ?, ?, ?, ?, ?)
        ON CONFLICT(server_id) DO UPDATE SET
            payload=excluded.payload,
            version=resource_baselines.version + 1,
            source=excluded.source,
            accepted_by=excluded.accepted_by,
            accepted_reason=excluded.accepted_reason,
            accepted_at=excluded.accepted_at,
            updated_at=excluded.updated_at
    """, (
        server_id, json.dumps(payload or {}, ensure_ascii=False), source,
        accepted_by or '', accepted_reason or '', now, now,
    ))
    conn.commit()
    conn.close()
    return get_resource_baseline(server_id)


def list_resource_baselines():
    conn = get_conn()
    conn.row_factory = row_to_dict
    rows = conn.execute("""
        SELECT b.*, s.ip AS server_ip, s.name AS server_name
        FROM resource_baselines b
        JOIN servers s ON s.id=b.server_id
        ORDER BY s.ip
    """).fetchall()
    conn.close()
    return [_decode_json_field(row, (('payload', {}),)) for row in rows]


def add_resource_change_plan(server_id: int, expected_payload: dict,
                             window_start: str, window_end: str, reason: str,
                             ticket_no: str = '', created_by: str = ''):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO resource_change_plans(
            server_id, expected_payload, window_start, window_end, reason,
            ticket_no, status, created_by, created_at)
        VALUES(?, ?, ?, ?, ?, ?, 'planned', ?, ?)
    """, (
        server_id, json.dumps(expected_payload or {}, ensure_ascii=False),
        window_start, window_end, reason, ticket_no or '', created_by or '', _now_text(),
    ))
    plan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return plan_id


def update_resource_change_plan(plan_id: int, expected_payload: dict,
                                window_start: str, window_end: str, reason: str,
                                ticket_no: str = ''):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        UPDATE resource_change_plans
        SET expected_payload=?, window_start=?, window_end=?, reason=?, ticket_no=?
        WHERE id=? AND status='planned'
    """, (
        json.dumps(expected_payload or {}, ensure_ascii=False), window_start, window_end,
        reason, ticket_no or '', plan_id,
    ))
    changed = cur.rowcount == 1
    conn.commit()
    conn.close()
    return changed


def list_resource_change_plans(server_id=None, status: str = ''):
    conn = get_conn()
    conn.row_factory = row_to_dict
    sql = """
        SELECT p.*, s.ip AS server_ip, s.name AS server_name
        FROM resource_change_plans p
        JOIN servers s ON s.id=p.server_id WHERE 1=1
    """
    params = []
    if server_id is not None:
        sql += " AND p.server_id=?"
        params.append(server_id)
    if status:
        sql += " AND p.status=?"
        params.append(status)
    sql += " ORDER BY p.id DESC"
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [_decode_json_field(row, (('expected_payload', {}),)) for row in rows]


def get_active_resource_plan(server_id: int, now_text: str = None):
    now_text = now_text or _now_text()
    conn = get_conn()
    conn.row_factory = row_to_dict
    conn.execute("""
        UPDATE resource_change_plans SET status='expired'
        WHERE status='planned' AND window_end < ?
    """, (now_text,))
    row = conn.execute("""
        SELECT * FROM resource_change_plans
        WHERE server_id=? AND status='planned'
          AND window_start <= ? AND window_end >= ?
        ORDER BY id DESC LIMIT 1
    """, (server_id, now_text, now_text)).fetchone()
    conn.commit()
    conn.close()
    return _decode_json_field(row, (('expected_payload', {}),))


def finish_resource_change_plan(plan_id: int, status: str = 'matched', at: str = None):
    at = at or _now_text()
    conn = get_conn()
    if status == 'matched':
        conn.execute(
            "UPDATE resource_change_plans SET status=?, matched_at=? WHERE id=? AND status='planned'",
            (status, at, plan_id),
        )
    else:
        conn.execute(
            "UPDATE resource_change_plans SET status=?, cancelled_at=? WHERE id=? AND status='planned'",
            (status, at, plan_id),
        )
    conn.commit()
    conn.close()


def expire_resource_change_plans(now_text: str = None):
    now_text = now_text or _now_text()
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        UPDATE resource_change_plans SET status='expired'
        WHERE status='planned' AND window_end < ?
    """, (now_text,))
    affected = cur.rowcount
    conn.commit()
    conn.close()
    return affected


RESOURCE_EVENT_OPEN_STATUSES = ('pending', 'confirmed_abnormal', 'recovered_pending')


def get_open_resource_change_event(server_id: int):
    conn = get_conn()
    conn.row_factory = row_to_dict
    marks = ','.join('?' for _ in RESOURCE_EVENT_OPEN_STATUSES)
    row = conn.execute(
        f"SELECT * FROM resource_change_events WHERE server_id=? AND status IN ({marks}) "
        "ORDER BY id DESC LIMIT 1",
        (server_id,) + RESOURCE_EVENT_OPEN_STATUSES,
    ).fetchone()
    conn.close()
    return _decode_json_field(
        row, (('baseline_payload', {}), ('observed_payload', {}), ('change_detail', []))
    )


def upsert_resource_change_event(server_id: int, fingerprint: str, baseline_payload: dict,
                                 observed_payload: dict, change_detail, at: str = None):
    at = at or _now_text()
    existing = get_open_resource_change_event(server_id)
    conn = get_conn()
    cur = conn.cursor()
    if existing and existing.get('fingerprint') == fingerprint:
        cur.execute("""
            UPDATE resource_change_events
            SET observed_payload=?, change_detail=?, last_seen_at=?,
                status=CASE WHEN status='recovered_pending' THEN 'pending' ELSE status END
            WHERE id=?
        """, (
            json.dumps(observed_payload or {}, ensure_ascii=False),
            json.dumps(change_detail or [], ensure_ascii=False), at, existing['id'],
        ))
        event_id = existing['id']
    else:
        cur.execute("""
            INSERT INTO resource_change_events(
                server_id, fingerprint, baseline_payload, observed_payload,
                change_detail, status, first_seen_at, last_seen_at)
            VALUES(?, ?, ?, ?, ?, 'pending', ?, ?)
        """, (
            server_id, fingerprint,
            json.dumps(baseline_payload or {}, ensure_ascii=False),
            json.dumps(observed_payload or {}, ensure_ascii=False),
            json.dumps(change_detail or [], ensure_ascii=False), at, at,
        ))
        event_id = cur.lastrowid
    conn.commit()
    conn.close()
    return event_id


def mark_resource_event_recovered(event_id: int, at: str = None):
    conn = get_conn()
    conn.execute("""
        UPDATE resource_change_events SET status='recovered_pending', last_seen_at=?
        WHERE id=? AND status IN ('pending', 'confirmed_abnormal')
    """, (at or _now_text(), event_id))
    conn.commit()
    conn.close()


def list_resource_change_events(status: str = '', server_id=None, limit: int = 200):
    conn = get_conn()
    conn.row_factory = row_to_dict
    sql = """
        SELECT e.*, s.ip AS server_ip, s.name AS server_name
        FROM resource_change_events e
        JOIN servers s ON s.id=e.server_id WHERE 1=1
    """
    params = []
    if status:
        sql += " AND e.status=?"
        params.append(status)
    if server_id is not None:
        sql += " AND e.server_id=?"
        params.append(server_id)
    sql += " ORDER BY e.id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 500)))
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [
        _decode_json_field(row, (
            ('baseline_payload', {}), ('observed_payload', {}), ('change_detail', []),
        )) for row in rows
    ]


def get_resource_change_event(event_id: int):
    conn = get_conn()
    conn.row_factory = row_to_dict
    row = conn.execute(
        "SELECT * FROM resource_change_events WHERE id=?", (event_id,)
    ).fetchone()
    conn.close()
    return _decode_json_field(
        row, (('baseline_payload', {}), ('observed_payload', {}), ('change_detail', []))
    )


def decide_resource_change_event(event_id: int, decision: str, reason: str,
                                 decided_by: str = ''):
    """人工结论与基线更新放在同一事务中，避免出现已确认但基线没更新。"""
    statuses = {
        'normal': 'confirmed_normal',
        'abnormal': 'confirmed_abnormal',
        'resolved': 'resolved',
    }
    if decision not in statuses:
        return False
    conn = get_conn()
    conn.row_factory = row_to_dict
    try:
        cur = conn.cursor()
        row = cur.execute(
            "SELECT * FROM resource_change_events WHERE id=?", (event_id,)
        ).fetchone()
        if not row or row['status'] not in RESOURCE_EVENT_OPEN_STATUSES:
            conn.rollback()
            return False
        now = _now_text()
        new_status = statuses[decision]
        cur.execute("""
            UPDATE resource_change_events
            SET status=?, decided_by=?, decision_reason=?, decided_at=?
            WHERE id=?
        """, (new_status, decided_by or '', reason, now, event_id))
        if decision == 'normal':
            current = json.loads(row['observed_payload'] or '{}')
            cur.execute("""
                INSERT INTO resource_baselines(
                    server_id, payload, version, source, accepted_by,
                    accepted_reason, accepted_at, updated_at)
                VALUES(?, ?, 1, 'manual', ?, ?, ?, ?)
                ON CONFLICT(server_id) DO UPDATE SET
                    payload=excluded.payload,
                    version=resource_baselines.version + 1,
                    source='manual', accepted_by=excluded.accepted_by,
                    accepted_reason=excluded.accepted_reason,
                    accepted_at=excluded.accepted_at, updated_at=excluded.updated_at
            """, (row['server_id'], row['observed_payload'], decided_by or '', reason, now, now))
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def reset_resource_configuration(server_id: int):
    """服务器连接目标改变时，旧机器的硬件与磁盘基线均不再适用。"""
    conn = get_conn()
    for table in ('server_hardware_snapshots', 'disk_snapshots', 'resource_change_events',
                  'resource_change_plans', 'resource_baselines'):
        conn.execute(f"DELETE FROM {table} WHERE server_id=?", (server_id,))
    conn.commit()
    conn.close()

def migrate_from_old_schema():
    """从旧的单分组模式迁移数据到新的多分组模式"""
    conn = get_conn()
    cur = conn.cursor()
    
    try:
        # 检查是否有旧的 group_id 列
        cur.execute("PRAGMA table_info(servers)")
        columns = [row[1] for row in cur.fetchall()]
        
        if 'group_id' in columns:
            print("检测到旧数据格式，开始迁移...")
            # 迁移旧数据
            cur.execute("SELECT id, group_id FROM servers WHERE group_id IS NOT NULL")
            old_data = cur.fetchall()
            
            for server_id, group_id in old_data:
                try:
                    cur.execute("""
                        INSERT OR IGNORE INTO server_group_memberships(server_id, group_id)
                        VALUES (?, ?)
                    """, (server_id, group_id))
                except sqlite3.Error:
                    pass
            
            # 删除旧列
            cur.execute("CREATE TABLE servers_new (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 22, username TEXT NOT NULL, enc_password TEXT NOT NULL, auth_type TEXT NOT NULL DEFAULT 'password', enc_private_key TEXT, enc_key_passphrase TEXT, notes TEXT)")
            cur.execute("INSERT INTO servers_new (id, ip, port, username, enc_password, auth_type, notes) SELECT id, ip, port, username, enc_password, 'password', notes FROM servers")
            cur.execute("DROP TABLE servers")
            cur.execute("ALTER TABLE servers_new RENAME TO servers")
            
            conn.commit()
            print("数据迁移成功！")
    except sqlite3.Error as e:
        print(f"迁移出错: {e}")
    finally:
        conn.close()


def migrate_inspection_tasks_schema():
    """迁移巡检任务表，添加新列"""
    conn = get_conn()
    cur = conn.cursor()
    
    try:
        # 检查 inspection_tasks 表的列
        cur.execute("PRAGMA table_info(inspection_tasks)")
        columns = [row[1] for row in cur.fetchall()]
        
        # 添加缺失的列
        if 'enable_schedule' not in columns:
            print("添加 enable_schedule 列...")
            cur.execute("ALTER TABLE inspection_tasks ADD COLUMN enable_schedule INTEGER DEFAULT 0")
        
        if 'schedule_time' not in columns:
            print("添加 schedule_time 列...")
            cur.execute("ALTER TABLE inspection_tasks ADD COLUMN schedule_time TEXT")
        
        if 'last_run' not in columns:
            print("添加 last_run 列...")
            cur.execute("ALTER TABLE inspection_tasks ADD COLUMN last_run TEXT")

        for column, default_value in (
            ('cpu_threshold', CPU_THRESHOLD),
            ('mem_threshold', MEM_THRESHOLD),
            ('disk_threshold', DISK_THRESHOLD),
        ):
            if column not in columns:
                print(f"添加 {column} 列...")
                cur.execute(f"ALTER TABLE inspection_tasks ADD COLUMN {column} REAL")
            cur.execute(
                f"UPDATE inspection_tasks SET {column} = ? WHERE {column} IS NULL",
                (float(default_value),),
            )
        
        conn.commit()
        print("巡检任务表迁移完成")
    except sqlite3.Error as e:
        print(f"巡检任务表迁移失败: {e}")
    finally:
        conn.close()


# 巡检任务相关操作
def add_inspection_task(name: str, project_name: str, inspector: str, report_format: str = "excel",
                        resource_group_id=None, check_cpu=True, check_mem=True, check_disk=True,
                        enable_proxy=False, proxy_rules=None, enable_schedule=False, schedule_time=None,
                        cpu_threshold=CPU_THRESHOLD, mem_threshold=MEM_THRESHOLD,
                        disk_threshold=DISK_THRESHOLD):
    """添加巡检任务"""
    conn = get_conn()
    cur = conn.cursor()
    proxy_rules_json = json.dumps(proxy_rules or [])
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cur.execute("""
        INSERT INTO inspection_tasks(name, project_name, inspector, report_format, 
                                    resource_group_id, check_cpu, check_mem, check_disk,
                                    enable_proxy, proxy_rules, enable_schedule, schedule_time, created_at,
                                    cpu_threshold, mem_threshold, disk_threshold)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, project_name, inspector, report_format, 
          resource_group_id, 1 if check_cpu else 0, 1 if check_mem else 0, 1 if check_disk else 0,
          1 if enable_proxy else 0, proxy_rules_json, 1 if enable_schedule else 0, schedule_time, created_at,
          float(cpu_threshold), float(mem_threshold), float(disk_threshold)))
    
    conn.commit()
    conn.close()

def list_inspection_tasks():
    """获取所有巡检任务"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM inspection_tasks ORDER BY created_at DESC")
    rows = [row_to_dict(cur, row) for row in cur.fetchall()]
    conn.close()
    
    tasks = []
    for row in rows:
        resource_checks = []
        if row["check_cpu"]:
            resource_checks.append("CPU")
        if row["check_mem"]:
            resource_checks.append("内存")
        if row["check_disk"]:
            resource_checks.append("磁盘")
        
        tasks.append({
            "id": row["id"],
            "name": row["name"],
            "project_name": row["project_name"],
            "inspector": row["inspector"],
            "report_format": row["report_format"],
            "resource_group_id": row["resource_group_id"],
            "check_cpu": bool(row["check_cpu"]),
            "check_mem": bool(row["check_mem"]),
            "check_disk": bool(row["check_disk"]),
            "enable_proxy": bool(row["enable_proxy"]),
            "proxy_rules": json.loads(row["proxy_rules"]) if row["proxy_rules"] else [],
            "enable_schedule": bool(row.get("enable_schedule")),
            "schedule_time": row.get("schedule_time"),
            "last_run": row.get("last_run"),
            "created_at": row.get("created_at"),
            "cpu_threshold": float(row.get("cpu_threshold") or CPU_THRESHOLD),
            "mem_threshold": float(row.get("mem_threshold") or MEM_THRESHOLD),
            "disk_threshold": float(row.get("disk_threshold") or DISK_THRESHOLD),
            "resource_checks": ", ".join(resource_checks)
        })
    return tasks

def get_inspection_task(task_id: int):
    """获取单个巡检任务"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM inspection_tasks WHERE id = ?", (task_id,))
    raw_row = cur.fetchone()
    row = row_to_dict(cur, raw_row) if raw_row else None
    conn.close()
    
    if row:
        return {
            "id": row["id"],
            "name": row["name"],
            "project_name": row["project_name"],
            "inspector": row["inspector"],
            "report_format": row["report_format"],
            "resource_group_id": row["resource_group_id"],
            "check_cpu": bool(row["check_cpu"]),
            "check_mem": bool(row["check_mem"]),
            "check_disk": bool(row["check_disk"]),
            "enable_proxy": bool(row["enable_proxy"]),
            "proxy_rules": json.loads(row["proxy_rules"]) if row["proxy_rules"] else [],
            "enable_schedule": bool(row.get("enable_schedule")),
            "schedule_time": row.get("schedule_time"),
            "last_run": row.get("last_run"),
            "created_at": row.get("created_at"),
            "cpu_threshold": float(row.get("cpu_threshold") or CPU_THRESHOLD),
            "mem_threshold": float(row.get("mem_threshold") or MEM_THRESHOLD),
            "disk_threshold": float(row.get("disk_threshold") or DISK_THRESHOLD),
        }
    return None

def update_inspection_task(task_id: int, name: str, project_name: str, inspector: str, report_format: str = "excel",
                          resource_group_id=None, check_cpu=True, check_mem=True, check_disk=True,
                          enable_proxy=False, proxy_rules=None, enable_schedule=False, schedule_time=None,
                          cpu_threshold=CPU_THRESHOLD, mem_threshold=MEM_THRESHOLD,
                          disk_threshold=DISK_THRESHOLD):
    """更新巡检任务"""
    conn = get_conn()
    cur = conn.cursor()
    proxy_rules_json = json.dumps(proxy_rules or [])
    
    cur.execute("""
        UPDATE inspection_tasks SET name=?, project_name=?, inspector=?, report_format=?,
                                   resource_group_id=?, check_cpu=?, check_mem=?, check_disk=?,
                                   enable_proxy=?, proxy_rules=?, enable_schedule=?, schedule_time=?,
                                   cpu_threshold=?, mem_threshold=?, disk_threshold=?
        WHERE id=?
    """, (name, project_name, inspector, report_format,
          resource_group_id, 1 if check_cpu else 0, 1 if check_mem else 0, 1 if check_disk else 0,
          1 if enable_proxy else 0, proxy_rules_json, 1 if enable_schedule else 0, schedule_time,
          float(cpu_threshold), float(mem_threshold), float(disk_threshold), task_id))
    
    conn.commit()
    conn.close()

def toggle_task_schedule(task_id: int, default_time="05:00"):
    """切换任务定时状态；首次启用且未配置时间时默认每天 05:00。"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT enable_schedule, schedule_time FROM inspection_tasks WHERE id = ?", (task_id,))
    row = cur.fetchone()
    result = None
    if row:
        new_state = 0 if row[0] else 1
        schedule_time = (row[1] or "").strip()
        if new_state and not schedule_time:
            schedule_time = default_time
        cur.execute(
            "UPDATE inspection_tasks SET enable_schedule = ?, schedule_time = ? WHERE id = ?",
            (new_state, schedule_time, task_id),
        )
        conn.commit()
        result = {"enable_schedule": bool(new_state), "schedule_time": schedule_time}
    conn.close()
    return result

def update_task_last_run(task_id: int):
    """更新任务最后运行时间"""
    conn = get_conn()
    cur = conn.cursor()
    last_run = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("UPDATE inspection_tasks SET last_run = ? WHERE id = ?", (last_run, task_id))
    conn.commit()
    conn.close()

def delete_inspection_task(task_id: int):
    """删除巡检任务"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM inspection_tasks WHERE id = ?", (task_id,))
    conn.commit()
    conn.close()


# 用户管理相关操作
def add_user(username: str, password: str, display_name: str = None, contact: str = None, role: str = 'viewer', is_default: int = 0):
    """添加用户"""
    conn = get_conn()
    cur = conn.cursor()
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        cur.execute("""
            INSERT INTO users(username, display_name, password, contact, role, created_at, is_default)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, display_name, password, contact, role, created_at, is_default))
        conn.commit()
        user_id = cur.lastrowid
        conn.close()
        return user_id
    except sqlite3.IntegrityError:
        conn.close()
        return None  # 用户名已存在

def get_user(username: str):
    """根据用户名获取用户"""
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()
    return user

def list_users():
    """获取所有用户"""
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM users ORDER BY created_at DESC")
    users = cur.fetchall()
    conn.close()
    return users

def delete_user(user_id: int):
    """删除用户（不能删除默认admin）"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT is_default FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if row and row[0] == 1:
        conn.close()
        return False  # 不能删除默认用户
    
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    affected = cur.rowcount
    conn.close()
    return affected > 0

def update_user(user_id: int, username: str = None, password: str = None, contact: str = None, role: str = None, display_name: str = None):
    """更新用户信息"""
    conn = get_conn()
    cur = conn.cursor()
    
    updates = []
    params = []
    
    if username:
        updates.append("username = ?")
        params.append(username)
    if display_name is not None:
        updates.append("display_name = ?")
        params.append(display_name)
    if password:
        updates.append("password = ?")
        params.append(password)
    if contact is not None:
        updates.append("contact = ?")
        params.append(contact)
    if role:
        updates.append("role = ?")
        params.append(role)
    
    if updates:
        params.append(user_id)
        cur.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", tuple(params))
        conn.commit()
    
    conn.close()
    return True

def update_user_password(username: str, password: str):
    """更新用户密码"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password = ? WHERE username = ?", (password, username))
    conn.commit()
    affected = cur.rowcount
    conn.close()
    return affected > 0


# 持久化任务队列与执行记录
def create_inspection_run(run_id: str, task_name: str, source: str, payload: dict,
                          task_id=None, dedupe_key=None, max_attempts: int = 2):
    conn = get_conn()
    cur = conn.cursor()
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("""
        INSERT OR IGNORE INTO inspection_runs(
            run_id, task_id, task_name, source, payload, status, progress,
            message, attempts, max_attempts, dedupe_key, created_at
        ) VALUES (?, ?, ?, ?, ?, 'queued', 0, '等待执行', 0, ?, ?, ?)
    """, (run_id, task_id, task_name, source, json.dumps(payload, ensure_ascii=False),
          max_attempts, dedupe_key, created_at))
    inserted = cur.rowcount > 0
    conn.commit()
    conn.close()
    return inserted


def claim_next_inspection_run():
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("""
            SELECT * FROM inspection_runs
            WHERE status='queued' AND attempts < max_attempts
              AND (next_retry_at IS NULL OR next_retry_at <= ?)
            ORDER BY created_at, id
            LIMIT 1
        """, (now,))
        job = cur.fetchone()
        if not job:
            conn.commit()
            return None
        cur.execute("""
            UPDATE inspection_runs
            SET status='running', started_at=?, finished_at=NULL,
                attempts=attempts+1, message='正在执行', error=NULL
            WHERE id=? AND status='queued'
        """, (now, job['id']))
        if cur.rowcount != 1:
            conn.rollback()
            return None
        conn.commit()
        job['status'] = 'running'
        job['started_at'] = now
        job['attempts'] += 1
        return job
    finally:
        conn.close()


def recover_interrupted_inspection_runs():
    conn = get_conn()
    cur = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("""
        UPDATE inspection_runs
        SET status='queued', message='服务重启，等待恢复执行', next_retry_at=?,
            started_at=NULL, finished_at=NULL
        WHERE status='running' AND attempts < max_attempts
    """, (now,))
    recovered = cur.rowcount
    cur.execute("""
        UPDATE inspection_runs
        SET status='failed', message='服务重启后已超过最大重试次数',
            error='interrupted', finished_at=?
        WHERE status='running' AND attempts >= max_attempts
    """, (now,))
    conn.commit()
    conn.close()
    return recovered


def update_inspection_run_progress(run_id: str, message: str, progress: int, report_path=None):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        UPDATE inspection_runs
        SET message=?, progress=?, report_path=COALESCE(?, report_path)
        WHERE run_id=?
    """, (message, max(0, min(100, int(progress))), report_path, run_id))
    conn.commit()
    conn.close()


def finish_inspection_run(run_id: str, report_path=None):
    conn = get_conn()
    cur = conn.cursor()
    finished_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("""
        UPDATE inspection_runs
        SET status='success', progress=100, message='执行完成', report_path=?,
            error=NULL, next_retry_at=NULL, finished_at=?
        WHERE run_id=?
    """, (report_path, finished_at, run_id))
    conn.commit()
    conn.close()


def retry_or_fail_inspection_run(run_id: str, error: str, retry_delay_seconds: int = 10):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT attempts, max_attempts FROM inspection_runs WHERE run_id=?", (run_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return 'missing'
    now = datetime.now()
    if row['attempts'] < row['max_attempts']:
        next_retry = datetime.fromtimestamp(now.timestamp() + retry_delay_seconds).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("""
            UPDATE inspection_runs
            SET status='queued', progress=0, message='执行失败，等待重试', error=?,
                next_retry_at=?, started_at=NULL
            WHERE run_id=?
        """, (error[:2000], next_retry, run_id))
        status = 'queued'
    else:
        cur.execute("""
            UPDATE inspection_runs
            SET status='failed', message='执行失败', error=?, progress=100,
                finished_at=?, next_retry_at=NULL
            WHERE run_id=?
        """, (error[:2000], now.strftime("%Y-%m-%d %H:%M:%S"), run_id))
        status = 'failed'
    conn.commit()
    conn.close()
    return status


def get_inspection_run(run_id: str):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM inspection_runs WHERE run_id=?", (run_id,))
    row = cur.fetchone()
    conn.close()
    return row


def list_inspection_runs(limit: int = 50):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("""
        SELECT id, run_id, task_id, task_name, source, status, progress, message,
               report_path, error, attempts, max_attempts, created_at, started_at, finished_at
        FROM inspection_runs ORDER BY id DESC LIMIT ?
    """, (max(1, min(int(limit), 200)),))
    rows = cur.fetchall()
    conn.close()
    return rows


def clear_inspection_results(run_id: str):
    conn = get_conn()
    conn.execute("DELETE FROM inspection_results WHERE run_id=?", (run_id,))
    conn.commit()
    conn.close()


def add_inspection_result(run_id: str, result: dict):
    conn = get_conn()
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("""
        INSERT INTO inspection_results(
            run_id, server_ip, ok, uptime, cpu, mem, disk, error, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        run_id, result.get('ip', ''), 1 if result.get('ok') else 0,
        result.get('uptime', ''), result.get('cpu', 0), result.get('mem', 0),
        result.get('disk', 0), result.get('error', ''), created_at
    ))
    conn.commit()
    conn.close()


# ---------------- 系统表（服务台账） ----------------
def _now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def list_service_systems():
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM service_systems ORDER BY name")
    rows = cur.fetchall()
    conn.close()
    return rows


def add_service_system(name: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO service_systems(name) VALUES (?)", (name,))
    conn.commit()
    conn.close()


def delete_service_system(system_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM service_systems WHERE id=?", (system_id,))
    conn.commit()
    conn.close()


def list_service_environments():
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM service_environments ORDER BY name")
    rows = cur.fetchall()
    conn.close()
    return rows


def add_service_environment(name: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO service_environments(name) VALUES (?)", (name,))
    cur.execute("SELECT id, name FROM service_environments WHERE name=?", (name,))
    row = cur.fetchone()
    if row:
        cur.execute("INSERT OR IGNORE INTO server_groups(id, name) VALUES (?, ?)", row)
    conn.commit()
    conn.close()


def delete_service_environment(environment_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM server_group_memberships WHERE group_id=?", (environment_id,))
    cur.execute("DELETE FROM service_environment_memberships WHERE environment_id=?", (environment_id,))
    cur.execute("DELETE FROM service_environments WHERE id=?", (environment_id,))
    cur.execute("DELETE FROM server_groups WHERE id=?", (environment_id,))
    conn.commit()
    conn.close()


# 主表可写列。账号凭据单独存于 service_accounts，绝不进入这里的查询结果。
SERVICE_COLUMNS = (
    "name", "server_id", "service_type", "run_mode", "version", "deploy_dir",
    "start_command", "stop_command", "restart_command", "ports", "config_path",
    "log_path", "access_url", "owner", "status", "auto_start", "notes",
)

# 账号列表/详情接口固定使用该查询：只取账号条数，不取任何账号字段。
SERVICE_SELECT_SQL = """
    SELECT si.*, s.ip AS ip, s.name AS server_name, s.os_type AS os_type,
           (SELECT COUNT(*) FROM service_accounts a WHERE a.service_id = si.id) AS account_count
    FROM service_infos si
    INNER JOIN servers s ON s.id = si.server_id
"""


def _decorate_service(cur, service):
    cur.execute("""
        SELECT g.* FROM service_systems g
        INNER JOIN service_system_memberships m ON g.id = m.system_id
        WHERE m.service_id = ? ORDER BY g.name
    """, (service['id'],))
    systems = cur.fetchall()
    cur.execute("""
        SELECT e.* FROM service_environments e
        INNER JOIN service_environment_memberships m ON e.id = m.environment_id
        WHERE m.service_id = ? ORDER BY e.name
    """, (service['id'],))
    environments = cur.fetchall()
    service['systems'] = systems
    service['environments'] = environments
    service['system_ids'] = [item['id'] for item in systems]
    service['environment_ids'] = [item['id'] for item in environments]
    service['system_names'] = ', '.join(item['name'] for item in systems) if systems else '无'
    service['environment_names'] = ', '.join(item['name'] for item in environments) if environments else '无'
    return service


def list_services(server_id=None, system_id=None, environment_id=None,
                  service_type: str = "", status: str = "", keyword: str = ""):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()

    sql = [SERVICE_SELECT_SQL]
    params = []
    if system_id:
        sql.append("INNER JOIN service_system_memberships sm ON sm.service_id = si.id AND sm.system_id = ?")
        params.append(system_id)
    if environment_id:
        sql.append("INNER JOIN service_environment_memberships em ON em.service_id = si.id AND em.environment_id = ?")
        params.append(environment_id)

    filters = []
    for column, value in (("si.server_id", server_id), ("si.service_type", service_type), ("si.status", status)):
        if value:
            filters.append(f"{column} = ?")
            params.append(value)
    if keyword:
        filters.append("(si.name LIKE ? OR si.owner LIKE ? OR si.deploy_dir LIKE ? OR s.ip LIKE ?)")
        pattern = f"%{keyword}%"
        params.extend([pattern, pattern, pattern, pattern])
    if filters:
        sql.append("WHERE " + " AND ".join(filters))
    sql.append("ORDER BY s.ip, si.name")

    cur.execute("\n".join(sql), params)
    services = cur.fetchall()
    for service in services:
        _decorate_service(cur, service)
    conn.close()
    return services


def get_service(service_id: int):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute(SERVICE_SELECT_SQL + " WHERE si.id = ?", (service_id,))
    service = cur.fetchone()
    if service:
        _decorate_service(cur, service)
    conn.close()
    return service


def _replace_service_memberships(cur, service_id, system_ids=None, environment_ids=None):
    cur.execute("DELETE FROM service_system_memberships WHERE service_id=?", (service_id,))
    for system_id in system_ids or []:
        cur.execute("""
            INSERT OR IGNORE INTO service_system_memberships(service_id, system_id) VALUES (?, ?)
        """, (service_id, system_id))
    cur.execute("DELETE FROM service_environment_memberships WHERE service_id=?", (service_id,))
    for environment_id in environment_ids or []:
        cur.execute("""
            INSERT OR IGNORE INTO service_environment_memberships(service_id, environment_id) VALUES (?, ?)
        """, (service_id, environment_id))


def _sync_service_accounts(cur, service_id, accounts):
    """按提交内容同步账号：带 id 的更新、无 id 的新增、未出现的删除。

    账号字典中 enc_password 为 None 表示"保留已存密文"，仅在带 id 时合法。
    任何"密码"类型账号缺少密文都会抛 ValueError，由外层回滚。
    """
    cur.execute("SELECT id FROM service_accounts WHERE service_id=?", (service_id,))
    existing_ids = {row[0] for row in cur.fetchall()}
    kept_ids = set()
    now = _now_text()

    for account in accounts or []:
        account_id = account.get("id")
        values = (account.get("purpose"), account.get("username"), account.get("secret_type"))
        if account_id is None:
            cur.execute("""
                INSERT INTO service_accounts(
                    service_id, purpose, username, secret_type, enc_password, remark, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (service_id,) + values + (account.get("enc_password"), account.get("remark"), now, now))
            continue
        if account_id not in existing_ids:
            raise ValueError("账号数据非法")
        kept_ids.add(account_id)
        if account.get("enc_password") is None:
            cur.execute("""
                UPDATE service_accounts SET purpose=?, username=?, secret_type=?, remark=?, updated_at=?
                WHERE id=? AND service_id=?
            """, values + (account.get("remark"), now, account_id, service_id))
        else:
            cur.execute("""
                UPDATE service_accounts SET purpose=?, username=?, secret_type=?, enc_password=?, remark=?, updated_at=?
                WHERE id=? AND service_id=?
            """, values + (account.get("enc_password"), account.get("remark"), now, account_id, service_id))

    for account_id in existing_ids - kept_ids:
        cur.execute("DELETE FROM service_accounts WHERE id=? AND service_id=?", (account_id, service_id))

    cur.execute("SELECT username, secret_type, enc_password FROM service_accounts WHERE service_id=?", (service_id,))
    for username, secret_type, enc_password in cur.fetchall():
        if secret_type == '密码' and not enc_password:
            raise ValueError(f"账号 {username or '(未填写)'} 未填写密码")


def add_service(values: dict, system_ids=None, environment_ids=None, accounts=None, created_by: str = ""):
    conn = get_conn()
    try:
        cur = conn.cursor()
        now = _now_text()
        columns = list(SERVICE_COLUMNS) + ["created_by", "created_at", "updated_at"]
        params = [values.get(column) for column in SERVICE_COLUMNS] + [created_by, now, now]
        cur.execute(
            f"INSERT INTO service_infos({', '.join(columns)}) VALUES ({', '.join(['?'] * len(columns))})",
            params,
        )
        service_id = cur.lastrowid
        _replace_service_memberships(cur, service_id, system_ids, environment_ids)
        _sync_service_accounts(cur, service_id, accounts)
        conn.commit()
        return service_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def update_service(service_id: int, values: dict, system_ids=None, environment_ids=None,
                   accounts=None, accounts_provided: bool = False):
    conn = get_conn()
    try:
        cur = conn.cursor()
        assignments = ", ".join(f"{column}=?" for column in SERVICE_COLUMNS)
        params = [values.get(column) for column in SERVICE_COLUMNS] + [_now_text(), service_id]
        cur.execute(f"UPDATE service_infos SET {assignments}, updated_at=? WHERE id=?", params)
        if cur.rowcount == 0:
            conn.rollback()
            return False
        _replace_service_memberships(cur, service_id, system_ids, environment_ids)
        # 未提交 accounts 键表示"不涉及账号"，此时必须保持账号原状，
        # 否则编辑页未解锁账号区时的普通保存会静默清空全部凭据。
        if accounts_provided:
            _sync_service_accounts(cur, service_id, accounts)
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def delete_service(service_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM service_infos WHERE id=?", (service_id,))
    conn.commit()
    conn.close()


def get_service_accounts(service_id: int):
    """返回账号明文密文行，仅供二次验证通过后的查看接口和编辑回填使用。"""
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM service_accounts WHERE service_id=? ORDER BY id", (service_id,))
    rows = cur.fetchall()
    conn.close()
    return rows


def count_services_by_server():
    """{server_id: 系统表条数}，用于删除服务器前提示级联影响。"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT server_id, COUNT(*) FROM service_infos GROUP BY server_id")
    counts = {row[0]: row[1] for row in cur.fetchall()}
    conn.close()
    return counts


def record_audit(username: str, action: str, result: str = "", target_type: str = "",
                 target_id=None, target_name: str = "", detail: str = "", client_ip: str = ""):
    """写审计日志。失败只记控制台，绝不阻断主流程；调用方也不得写入任何凭据明文。"""
    try:
        conn = get_conn()
        conn.execute("""
            INSERT INTO audit_logs(created_at, username, client_ip, action, result,
                                   target_type, target_id, target_name, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (_now_text(), username or '', client_ip or '', action, result,
              target_type, target_id, target_name, detail))
        conn.commit()
        conn.close()
    except Exception as exc:  # pragma: no cover - 审计失败不应影响业务
        print(f"审计日志写入失败: {exc}")


def list_audit_logs(limit: int = 200):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (max(1, int(limit)),))
    rows = cur.fetchall()
    conn.close()
    return rows


def query_audit_logs(username: str = "", action: str = "", result: str = "",
                     keyword: str = "", start_time: str = "", end_time: str = "",
                     page: int = 1, page_size: int = 50):
    """分页查询全系统审计日志，并返回页面筛选项与汇总数据。"""
    page = max(1, int(page))
    page_size = max(1, min(100, int(page_size)))
    where, params = [], []
    for column, value in (("username", username), ("action", action), ("result", result)):
        value = str(value or "").strip()
        if value:
            where.append(f"{column} = ?")
            params.append(value)
    if start_time:
        where.append("created_at >= ?")
        params.append(str(start_time))
    if end_time:
        where.append("created_at <= ?")
        params.append(str(end_time))
    keyword = str(keyword or "").strip()
    if keyword:
        # 将用户输入作为普通文本匹配，避免 % / _ 意外扩大查询范围。
        escaped = keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        where.append("(" + " OR ".join(
            f"COALESCE({column}, '') LIKE ? ESCAPE '\\'"
            for column in ("username", "client_ip", "action", "target_type", "target_name", "detail")
        ) + ")")
        params.extend([pattern] * 6)
    where_sql = " WHERE " + " AND ".join(where) if where else ""

    conn = get_conn()
    conn.row_factory = row_to_dict
    total = conn.execute(
        "SELECT COUNT(*) AS count FROM audit_logs" + where_sql, params
    ).fetchone()["count"]
    summary = conn.execute("""
        SELECT COUNT(*) AS total,
               COUNT(DISTINCT username) AS user_count,
               COUNT(DISTINCT action) AS action_count,
               SUM(CASE WHEN LOWER(COALESCE(result, '')) IN
                    ('denied', 'error', 'failed', 'rejected') THEN 1 ELSE 0 END) AS abnormal_count
        FROM audit_logs
    """ + where_sql, params).fetchone()
    offset = (page - 1) * page_size
    rows = conn.execute(
        "SELECT * FROM audit_logs" + where_sql
        + " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
        [*params, page_size, offset],
    ).fetchall()
    usernames = [row["username"] for row in conn.execute("""
        SELECT DISTINCT username FROM audit_logs
        WHERE username <> '' ORDER BY username COLLATE NOCASE
    """).fetchall()]
    actions = [row["action"] for row in conn.execute("""
        SELECT DISTINCT action FROM audit_logs
        WHERE action <> '' ORDER BY action COLLATE NOCASE
    """).fetchall()]
    results = [row["result"] for row in conn.execute("""
        SELECT DISTINCT result FROM audit_logs
        WHERE result <> '' ORDER BY result COLLATE NOCASE
    """).fetchall()]
    conn.close()
    return {
        "rows": rows,
        "total": int(total),
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (int(total) + page_size - 1) // page_size),
        "summary": {
            "total": int(summary.get("total") or 0),
            "user_count": int(summary.get("user_count") or 0),
            "action_count": int(summary.get("action_count") or 0),
            "abnormal_count": int(summary.get("abnormal_count") or 0),
        },
        "filters": {"usernames": usernames, "actions": actions, "results": results},
    }


def record_operation_audit(username: str, server, command: str, status: str,
                           error: str = "", client_ip: str = "", source_action_id=None):
    """记录真正进入远程执行器的命令。

    服务器名称和 IP 作为快照保存，即使资产后续改名或删除，历史审计仍可追溯。
    只保存命令、状态和简短错误，不保存命令输出。
    """
    try:
        server = server or {}
        normalized_status = "success" if status == "success" else "failed"
        conn = get_conn()
        conn.execute("""
            INSERT INTO operation_audits(
                created_at, username, client_ip, server_id, server_name, server_ip,
                command, status, error, source_action_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            _now_text(), str(username or ""), str(client_ip or ""), server.get("id"),
            str(server.get("name") or ""), str(server.get("ip") or ""),
            str(command or "")[:2000], normalized_status, str(error or "")[:500],
            source_action_id,
        ))
        conn.commit()
        conn.close()
    except Exception as exc:  # pragma: no cover - 审计失败不得改变命令执行结果
        print(f"操作审计写入失败: {exc}")


def list_operation_audits(username: str = "", server_id=None, start_time: str = "",
                          end_time: str = "", status: str = "", dimension: str = "time",
                          page: int = 1, page_size: int = 50):
    """按用户、时间、服务器筛选真实执行过的远程命令。"""
    dimension = dimension if dimension in ("user", "time", "server") else "time"
    status = status if status in ("success", "failed") else ""
    page = max(1, int(page))
    page_size = max(1, min(100, int(page_size)))
    where, params = [], []
    if username:
        where.append("username = ?")
        params.append(str(username))
    if server_id not in (None, ""):
        where.append("server_id = ?")
        params.append(int(server_id))
    if start_time:
        where.append("created_at >= ?")
        params.append(str(start_time))
    if end_time:
        where.append("created_at <= ?")
        params.append(str(end_time))
    if status:
        where.append("status = ?")
        params.append(status)
    where_sql = " WHERE " + " AND ".join(where) if where else ""
    order_sql = {
        "time": "created_at DESC, id DESC",
        "user": "username COLLATE NOCASE ASC, created_at DESC, id DESC",
        "server": ("CASE WHEN server_name='' THEN server_ip ELSE server_name END "
                   "COLLATE NOCASE ASC, server_ip ASC, created_at DESC, id DESC"),
    }[dimension]

    conn = get_conn()
    conn.row_factory = row_to_dict
    total = conn.execute(
        "SELECT COUNT(*) AS count FROM operation_audits" + where_sql, params
    ).fetchone()["count"]
    summary = conn.execute("""
        SELECT COUNT(*) AS total,
               COUNT(DISTINCT username) AS user_count,
               COUNT(DISTINCT CASE WHEN server_id IS NULL
                    THEN server_name || '|' || server_ip ELSE CAST(server_id AS TEXT) END) AS server_count,
               SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) AS failed_count
        FROM operation_audits
    """ + where_sql, params).fetchone()
    offset = (page - 1) * page_size
    rows = conn.execute(
        "SELECT * FROM operation_audits" + where_sql
        + f" ORDER BY {order_sql} LIMIT ? OFFSET ?",
        [*params, page_size, offset],
    ).fetchall()
    usernames = [row["username"] for row in conn.execute("""
        SELECT DISTINCT username FROM operation_audits
        WHERE username <> '' ORDER BY username COLLATE NOCASE
    """).fetchall()]
    servers = conn.execute("""
        SELECT server_id, server_name, server_ip, MAX(created_at) AS last_operated_at
        FROM operation_audits
        GROUP BY server_id, server_name, server_ip
        ORDER BY CASE WHEN server_name='' THEN server_ip ELSE server_name END COLLATE NOCASE,
                 server_ip
    """).fetchall()
    conn.close()
    return {
        "rows": rows,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
        "summary": {
            "total": int(summary.get("total") or 0),
            "user_count": int(summary.get("user_count") or 0),
            "server_count": int(summary.get("server_count") or 0),
            "failed_count": int(summary.get("failed_count") or 0),
        },
        "filters": {"usernames": usernames, "servers": servers},
    }


def list_conversation_audits(username: str = "", keyword: str = "",
                             start_time: str = "", end_time: str = "",
                             dimension: str = "time", page: int = 1,
                             page_size: int = 50):
    """查询 AI 会话中用户真实提交的问题，不包含助手和工具消息。"""
    dimension = dimension if dimension in ("user", "time", "question") else "time"
    page = max(1, int(page))
    page_size = max(1, min(100, int(page_size)))
    where = ["m.role = 'user'"]
    params = []
    if username:
        where.append("c.username = ?")
        params.append(str(username))
    if keyword:
        escaped = str(keyword).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        where.append("m.content LIKE ? ESCAPE '\\'")
        params.append(f"%{escaped}%")
    if start_time:
        where.append("m.created_at >= ?")
        params.append(str(start_time))
    if end_time:
        where.append("m.created_at <= ?")
        params.append(str(end_time))
    where_sql = " WHERE " + " AND ".join(where)
    order_sql = {
        "time": "m.created_at DESC, m.id DESC",
        "user": "c.username COLLATE NOCASE ASC, m.created_at DESC, m.id DESC",
        "question": "m.content COLLATE NOCASE ASC, m.created_at DESC, m.id DESC",
    }[dimension]
    base_sql = """
        FROM ai_messages m
        JOIN ai_conversations c ON c.id = m.conversation_id
    """

    conn = get_conn()
    conn.row_factory = row_to_dict
    total = conn.execute(
        "SELECT COUNT(*) AS count " + base_sql + where_sql, params
    ).fetchone()["count"]
    today = datetime.now().strftime("%Y-%m-%d")
    summary = conn.execute("""
        SELECT COUNT(*) AS total,
               COUNT(DISTINCT c.username) AS user_count,
               COUNT(DISTINCT c.id) AS conversation_count,
               SUM(CASE WHEN substr(m.created_at, 1, 10)=? THEN 1 ELSE 0 END) AS today_count
    """ + base_sql + where_sql, [today, *params]).fetchone()
    offset = (page - 1) * page_size
    rows = conn.execute("""
        SELECT m.id, m.created_at, m.content AS question,
               c.id AS conversation_id, c.title AS conversation_title, c.username
    """ + base_sql + where_sql + f" ORDER BY {order_sql} LIMIT ? OFFSET ?",
        [*params, page_size, offset]).fetchall()
    usernames = [row["username"] for row in conn.execute("""
        SELECT DISTINCT c.username
        FROM ai_messages m JOIN ai_conversations c ON c.id=m.conversation_id
        WHERE m.role='user' AND c.username<>''
        ORDER BY c.username COLLATE NOCASE
    """).fetchall()]
    conn.close()
    return {
        "rows": rows,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
        "summary": {
            "total": int(summary.get("total") or 0),
            "user_count": int(summary.get("user_count") or 0),
            "conversation_count": int(summary.get("conversation_count") or 0),
            "today_count": int(summary.get("today_count") or 0),
        },
        "filters": {"usernames": usernames},
    }


def list_inspection_results(run_id: str, abnormal_first: bool = True):
    """取某次巡检的逐台结果。异常（连接失败/超阈值）排在前面。"""
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    order = "ORDER BY ok ASC, disk DESC, id" if abnormal_first else "ORDER BY id"
    cur.execute(f"SELECT * FROM inspection_results WHERE run_id=? {order}", (run_id,))
    rows = cur.fetchall()
    conn.close()
    return rows


def list_recent_disk_findings(days: int = 7, limit: int = 200):
    """取近几天各服务器的磁盘审计发现，供 AI 汇总用（一次查询，避免逐台扫）。"""
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    since = (datetime.now() - timedelta(days=max(1, int(days or 7)))).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("""
        SELECT d.server_id, d.collected_at, d.findings, s.name AS server_name, s.ip AS server_ip
        FROM disk_snapshots d
        LEFT JOIN servers s ON s.id = d.server_id
        WHERE d.collected_at >= ?
        ORDER BY d.collected_at DESC
        LIMIT ?
    """, (since, max(1, min(int(limit), 500))))
    rows = cur.fetchall()
    conn.close()
    result = []
    for row in rows:
        try:
            findings = json.loads(row.get('findings') or '[]')
        except (TypeError, ValueError):
            findings = []
        if not findings:
            continue
        item = dict(row)
        item['findings'] = findings
        result.append(item)
    return result


# ---------------- AI 智能运维：模型接入配置 ----------------
AI_PROVIDER_COLUMNS = (
    "id", "name", "base_url", "model", "deployment", "temperature", "max_tokens",
    "timeout", "supports_tools", "enabled", "is_default", "extra_headers",
    "last_test_at", "last_test_ok", "last_test_error", "created_at", "updated_at",
    "created_by",
)


def list_ai_providers():
    """按"默认优先、启用优先、id 升序"返回模型接入配置（含密文，调用方负责脱敏）。"""
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("""
        SELECT id, name, base_url, model, enc_api_key, deployment, temperature,
               max_tokens, timeout, supports_tools, enabled, is_default, extra_headers,
               last_test_at, last_test_ok, last_test_error, created_at, updated_at, created_by
        FROM ai_providers
        ORDER BY is_default DESC, enabled DESC, id
    """)
    rows = cur.fetchall()
    conn.close()
    return rows


def get_ai_provider(provider_id):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM ai_providers WHERE id=?", (provider_id,))
    row = cur.fetchone()
    conn.close()
    return row


def get_ai_provider_by_name(name: str):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM ai_providers WHERE name=?", (name,))
    row = cur.fetchone()
    conn.close()
    return row


def get_default_ai_provider():
    """取默认可用配置：优先 is_default，其次任意启用项。"""
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM ai_providers WHERE enabled=1
        ORDER BY is_default DESC, id LIMIT 1
    """)
    row = cur.fetchone()
    conn.close()
    return row


def add_ai_provider(values: dict):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO ai_providers(name, base_url, model, enc_api_key, deployment, temperature,
                                 max_tokens, timeout, supports_tools, enabled, is_default,
                                 extra_headers, created_at, created_by)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        values.get('name'), values.get('base_url'), values.get('model'),
        values.get('enc_api_key'), values.get('deployment', 'cloud'),
        values.get('temperature', 0.2), values.get('max_tokens', 2048),
        values.get('timeout', 120), 1 if values.get('supports_tools', True) else 0,
        1 if values.get('enabled', True) else 0,
        1 if values.get('is_default') else 0,
        values.get('extra_headers'), _now_text(), values.get('created_by', ''),
    ))
    provider_id = cur.lastrowid
    conn.commit()
    conn.close()
    if values.get('is_default'):
        set_default_ai_provider(provider_id)
    return provider_id


def update_ai_provider(provider_id: int, values: dict):
    """部分更新；values 里没有 enc_api_key 键时不动密钥（对齐系统表的密码语义）。"""
    fields = [
        'name', 'base_url', 'model', 'enc_api_key', 'deployment', 'temperature',
        'max_tokens', 'timeout', 'extra_headers',
    ]
    assignments, params = [], []
    for field in fields:
        if field in values:
            assignments.append(f"{field}=?")
            params.append(values[field])
    for field in ('supports_tools', 'enabled'):
        if field in values:
            assignments.append(f"{field}=?")
            params.append(1 if values[field] else 0)
    if 'is_default' in values:
        assignments.append("is_default=?")
        params.append(1 if values['is_default'] else 0)

    conn = get_conn()
    cur = conn.cursor()
    if assignments:
        assignments.append("updated_at=?")
        params.append(_now_text())
        params.append(provider_id)
        cur.execute(f"UPDATE ai_providers SET {', '.join(assignments)} WHERE id=?", params)
        conn.commit()
    conn.close()
    if values.get('is_default'):
        set_default_ai_provider(provider_id)


def set_default_ai_provider(provider_id: int):
    """把指定配置设为唯一默认项。"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE ai_providers SET is_default=0 WHERE id<>?", (provider_id,))
    cur.execute("UPDATE ai_providers SET is_default=1 WHERE id=?", (provider_id,))
    conn.commit()
    conn.close()


def update_ai_provider_test(provider_id: int, ok: bool, error: str = ""):
    conn = get_conn()
    conn.execute(
        "UPDATE ai_providers SET last_test_at=?, last_test_ok=?, last_test_error=? WHERE id=?",
        (_now_text(), 1 if ok else 0, (error or '')[:300], provider_id),
    )
    conn.commit()
    conn.close()


def delete_ai_provider(provider_id: int):
    conn = get_conn()
    conn.execute("DELETE FROM ai_providers WHERE id=?", (provider_id,))
    conn.commit()
    conn.close()


# ---------------- AI 智能运维：会话与消息 ----------------
def list_ai_conversations(username: str = None, limit: int = 50):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    sql = """
        SELECT c.*, (SELECT COUNT(*) FROM ai_messages m WHERE m.conversation_id=c.id) AS message_count,
               (SELECT COUNT(*) FROM ai_actions a WHERE a.conversation_id=c.id AND a.status='pending')
                   AS pending_count
        FROM ai_conversations c
        WHERE 1=1
    """
    params = []
    if username:
        sql += " AND c.username=?"
        params.append(username)
    sql += " ORDER BY c.updated_at DESC, c.id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 200)))
    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    return rows


def get_ai_conversation(conversation_id: int):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM ai_conversations WHERE id=?", (conversation_id,))
    row = cur.fetchone()
    conn.close()
    return row


def add_ai_conversation(title: str, username: str, provider_id=None, model: str = ""):
    conn = get_conn()
    cur = conn.cursor()
    now = _now_text()
    cur.execute("""
        INSERT INTO ai_conversations(title, username, provider_id, model, created_at, updated_at)
        VALUES(?, ?, ?, ?, ?, ?)
    """, (title or '新会话', username, provider_id, model or '', now, now))
    conversation_id = cur.lastrowid
    conn.commit()
    conn.close()
    return conversation_id


def rename_ai_conversation(conversation_id: int, title: str):
    conn = get_conn()
    conn.execute(
        "UPDATE ai_conversations SET title=?, updated_at=? WHERE id=?",
        ((title or '新会话')[:80], _now_text(), conversation_id),
    )
    conn.commit()
    conn.close()


def touch_ai_conversation(conversation_id: int, provider_id=None, model: str = None):
    conn = get_conn()
    if model is None:
        conn.execute("UPDATE ai_conversations SET updated_at=? WHERE id=?",
                     (_now_text(), conversation_id))
    else:
        conn.execute(
            "UPDATE ai_conversations SET updated_at=?, provider_id=?, model=? WHERE id=?",
            (_now_text(), provider_id, model, conversation_id),
        )
    conn.commit()
    conn.close()


def delete_ai_conversation(conversation_id: int):
    conn = get_conn()
    conn.execute("DELETE FROM ai_messages WHERE conversation_id=?", (conversation_id,))
    conn.execute("DELETE FROM ai_actions WHERE conversation_id=?", (conversation_id,))
    conn.execute("DELETE FROM ai_conversations WHERE id=?", (conversation_id,))
    conn.commit()
    conn.close()


def list_ai_messages(conversation_id: int, limit: int = None, after_id: int = 0):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    sql = "SELECT * FROM ai_messages WHERE conversation_id=? AND id>? ORDER BY id"
    params = [conversation_id, after_id]
    if limit:
        sql += " DESC LIMIT ?"
        params.append(max(1, int(limit)))
        cur.execute(sql, params)
        rows = list(reversed(cur.fetchall()))
    else:
        cur.execute(sql, params)
        rows = cur.fetchall()
    conn.close()
    return rows


def get_ai_message(message_id: int):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM ai_messages WHERE id=?", (message_id,))
    row = cur.fetchone()
    conn.close()
    return row


def add_ai_message(conversation_id: int, role: str, content: str = "", status: str = "done",
                   tool_calls=None, tool_name: str = "", tool_call_id: str = "",
                   tool_args: str = "", provider_id=None, model: str = ""):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO ai_messages(conversation_id, role, content, status, tool_calls,
                                tool_name, tool_call_id, tool_args, provider_id, model, created_at)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        conversation_id, role, content or '', status,
        json.dumps(tool_calls, ensure_ascii=False) if tool_calls else None,
        tool_name or '', tool_call_id or '', tool_args or '',
        provider_id, model or '', _now_text(),
    ))
    message_id = cur.lastrowid
    conn.commit()
    conn.close()
    return message_id


def finish_ai_message(message_id: int, content: str, status: str = "done", error: str = "",
                      prompt_tokens: int = 0, completion_tokens: int = 0,
                      tokens_estimated: int = 0, duration_ms: int = 0, tool_calls=None):
    conn = get_conn()
    fields = [
        "content=?", "status=?", "error=?", "prompt_tokens=?", "completion_tokens=?",
        "tokens_estimated=?", "duration_ms=?",
    ]
    params = [
        content or '', status, (error or '')[:500] or None, int(prompt_tokens or 0),
        int(completion_tokens or 0), 1 if tokens_estimated else 0, int(duration_ms or 0),
    ]
    if tool_calls is not None:
        fields.append("tool_calls=?")
        params.append(json.dumps(tool_calls, ensure_ascii=False) if tool_calls else None)
    params.append(message_id)
    conn.execute(f"UPDATE ai_messages SET {', '.join(fields)} WHERE id=?", params)
    conn.commit()
    conn.close()


def delete_ai_message(message_id: int):
    conn = get_conn()
    conn.execute("DELETE FROM ai_messages WHERE id=?", (message_id,))
    conn.commit()
    conn.close()


def fail_stale_streaming_messages():
    """服务重启后把没写完的消息标记为中断，避免界面一直转圈。"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        UPDATE ai_messages SET status='failed', error=?
        WHERE status='streaming'
    """, ('服务重启，生成中断',))
    affected = cur.rowcount
    conn.commit()
    conn.close()
    return affected


# ---------------- AI 智能运维：待确认操作 ----------------
def add_ai_action(conversation_id: int, action_type: str, payload: dict, summary: str,
                  risk_level: str = "medium", message_id=None, requested_by: str = "",
                  ttl_seconds: int = 600):
    now = datetime.now()
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO ai_actions(conversation_id, message_id, action_type, payload, risk_level,
                               summary, status, requested_by, created_at, expires_at)
        VALUES(?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
    """, (
        conversation_id, message_id, action_type,
        json.dumps(payload or {}, ensure_ascii=False), risk_level, summary or '',
        requested_by or '', now.strftime("%Y-%m-%d %H:%M:%S"),
        (now + timedelta(seconds=max(30, int(ttl_seconds or 600)))).strftime("%Y-%m-%d %H:%M:%S"),
    ))
    action_id = cur.lastrowid
    conn.commit()
    conn.close()
    return action_id


def get_ai_action(action_id: int):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM ai_actions WHERE id=?", (action_id,))
    row = cur.fetchone()
    conn.close()
    return row


def list_ai_actions(conversation_id: int = None, status: str = "", limit: int = 50):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    sql = "SELECT * FROM ai_actions WHERE 1=1"
    params = []
    if conversation_id:
        sql += " AND conversation_id=?"
        params.append(conversation_id)
    if status:
        sql += " AND status=?"
        params.append(status)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 200)))
    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    return rows


def claim_ai_action(action_id: int, decided_by: str = ""):
    """把待确认操作抢占为 approved；靠 rowcount 保证重复点击只执行一次。"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        UPDATE ai_actions SET status='approved', decided_by=?, decided_at=?
        WHERE id=? AND status='pending'
    """, (decided_by or '', _now_text(), action_id))
    claimed = cur.rowcount == 1
    conn.commit()
    conn.close()
    return claimed


def finish_ai_action(action_id: int, status: str, result: str = "", error: str = "",
                     decided_by: str = ""):
    conn = get_conn()
    fields = ["status=?", "result=?", "error=?"]
    params = [status, (result or '')[:4000] or None, (error or '')[:500] or None]
    if decided_by:
        fields.append("decided_by=?")
        params.append(decided_by)
    if status in ('rejected', 'expired'):
        fields.append("decided_at=?")
        params.append(_now_text())
    else:
        fields.append("executed_at=?")
        params.append(_now_text())
    params.append(action_id)
    conn.execute(f"UPDATE ai_actions SET {', '.join(fields)} WHERE id=?", params)
    conn.commit()
    conn.close()


def expire_ai_actions(now_text: str = None):
    """把超期未确认的操作置为 expired，返回条数。"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        UPDATE ai_actions SET status='expired', decided_at=?
        WHERE status='pending' AND expires_at IS NOT NULL AND expires_at < ?
    """, (now_text or _now_text(), now_text or _now_text()))
    affected = cur.rowcount
    conn.commit()
    conn.close()
    return affected


# ---------------- AI 智能运维：服务发现草稿 ----------------
def add_ai_service_discovery_scan(scan_id: str, server_id: int, requested_by: str,
                                  candidates, warnings=None, ttl_seconds: int = 600):
    """保存清洗后的候选项；原始命令输出和凭据绝不落库。"""
    now = datetime.now()
    conn = get_conn()
    conn.execute("""
        INSERT INTO ai_service_discovery_scans(
            id, server_id, requested_by, status, candidates, warnings, created_at, expires_at)
        VALUES(?, ?, ?, 'ready', ?, ?, ?, ?)
    """, (
        scan_id, int(server_id), requested_by or '',
        json.dumps(candidates or [], ensure_ascii=False),
        json.dumps(warnings or [], ensure_ascii=False),
        now.strftime("%Y-%m-%d %H:%M:%S"),
        (now + timedelta(seconds=max(30, int(ttl_seconds or 600)))).strftime("%Y-%m-%d %H:%M:%S"),
    ))
    conn.commit()
    conn.close()
    return scan_id


def get_ai_service_discovery_scan(scan_id: str):
    conn = get_conn()
    conn.row_factory = row_to_dict
    row = conn.execute(
        "SELECT * FROM ai_service_discovery_scans WHERE id=?", (scan_id,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    try:
        row['candidates'] = json.loads(row.get('candidates') or '[]')
    except (TypeError, ValueError):
        row['candidates'] = []
    try:
        row['warnings'] = json.loads(row.get('warnings') or '[]')
    except (TypeError, ValueError):
        row['warnings'] = []
    return row


def finish_ai_service_discovery_scan(scan_id: str, status: str = 'imported'):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE ai_service_discovery_scans SET status=? WHERE id=? AND status='ready'",
        (status, scan_id),
    )
    changed = cur.rowcount == 1
    conn.commit()
    conn.close()
    return changed


def expire_ai_service_discovery_scans(now_text: str = None):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        UPDATE ai_service_discovery_scans SET status='expired'
        WHERE status='ready' AND expires_at < ?
    """, (now_text or _now_text(),))
    affected = cur.rowcount
    conn.commit()
    conn.close()
    return affected


# ---------------- AI 智能运维：分析记录与用量 ----------------
def add_ai_insight(scope: str, content: str, run_id: str = None, server_id=None,
                   provider_id=None, model: str = "", status: str = "done",
                   error: str = "", username: str = ""):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO ai_insights(scope, run_id, server_id, provider_id, model, content,
                                status, error, username, created_at)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scope, run_id, server_id, provider_id, model or '', content or '',
        status, (error or '')[:500] or None, username or '', _now_text(),
    ))
    insight_id = cur.lastrowid
    conn.commit()
    conn.close()
    return insight_id


def list_ai_insights(run_id: str = None, limit: int = 20):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    if run_id:
        cur.execute("SELECT * FROM ai_insights WHERE run_id=? ORDER BY id DESC LIMIT ?",
                    (run_id, max(1, int(limit))))
    else:
        cur.execute("SELECT * FROM ai_insights ORDER BY id DESC LIMIT ?", (max(1, int(limit)),))
    rows = cur.fetchall()
    conn.close()
    return rows


def get_ai_insight(insight_id: int):
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM ai_insights WHERE id=?", (insight_id,))
    row = cur.fetchone()
    conn.close()
    return row


def ai_usage_summary(days: int = 30, by: str = "model"):
    """按日期聚合用量；by=user 时归集到会话归属人，用于费用分摊。"""
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    since = (datetime.now() - timedelta(days=max(1, int(days or 30)))).strftime("%Y-%m-%d 00:00:00")
    if by == "user":
        group_sql = "c.username"
        join_sql = "LEFT JOIN ai_conversations c ON c.id = m.conversation_id"
    else:
        group_sql = "COALESCE(m.model, '')"
        join_sql = ""
    cur.execute(f"""
        SELECT substr(m.created_at, 1, 10) AS day, {group_sql} AS target,
               SUM(m.prompt_tokens) AS prompt_tokens,
               SUM(m.completion_tokens) AS completion_tokens,
               COUNT(*) AS calls
        FROM ai_messages m {join_sql}
        WHERE m.role='assistant' AND m.created_at >= ?
        GROUP BY day, target ORDER BY day DESC, calls DESC
    """, (since,))
    rows = cur.fetchall()
    conn.close()
    return rows


def ai_usage_today(username: str = None):
    """当日已用 token（含估算），用于限额判断。"""
    conn = get_conn()
    cur = conn.cursor()
    today = datetime.now().strftime("%Y-%m-%d")
    sql = """
        SELECT COALESCE(SUM(m.prompt_tokens + m.completion_tokens), 0)
        FROM ai_messages m
        WHERE m.role='assistant' AND substr(m.created_at, 1, 10) = ?
    """
    params = [today]
    if username:
        sql += " AND m.conversation_id IN (SELECT id FROM ai_conversations WHERE username=?)"
        params.append(username)
    cur.execute(sql, params)
    total = cur.fetchone()[0] or 0
    conn.close()
    return int(total)


def prune_ai_history(keep_days: int = 90):
    """清理过期会话（消息与操作级联），返回删除的会话数。"""
    if not keep_days or int(keep_days) <= 0:
        return 0
    cutoff = (datetime.now() - timedelta(days=int(keep_days))).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM ai_conversations WHERE updated_at < ?", (cutoff,))
    ids = [row[0] for row in cur.fetchall()]
    for conversation_id in ids:
        cur.execute("DELETE FROM ai_messages WHERE conversation_id=?", (conversation_id,))
        cur.execute("DELETE FROM ai_actions WHERE conversation_id=?", (conversation_id,))
        cur.execute("DELETE FROM ai_conversations WHERE id=?", (conversation_id,))
    cur.execute("DELETE FROM ai_insights WHERE created_at < ?", (cutoff,))
    cur.execute("DELETE FROM ai_service_discovery_scans WHERE created_at < ?", (cutoff,))
    conn.commit()
    conn.close()
    return len(ids)


if __name__ == "__main__":
    migrate_from_old_schema()
