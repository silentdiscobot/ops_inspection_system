# -*- coding: utf-8 -*-
from typing import Optional, List
import sqlite3, json, os
from datetime import datetime
from config import SQLITE_PATH

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
    created_at TEXT NOT NULL
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
    }.items():
        if column not in server_columns:
            cur.execute(f"ALTER TABLE servers ADD COLUMN {column} {definition}")
    cur.execute("PRAGMA journal_mode=WAL")
    conn.commit()
    conn.close()

def row_to_dict(cursor, row):
    return {d[0]: row[i] for i, d in enumerate(cursor.description)}

def list_groups():
    conn = get_conn()
    conn.row_factory = row_to_dict
    cur = conn.cursor()
    cur.execute("SELECT * FROM server_groups ORDER BY name")
    rows = cur.fetchall()
    conn.close()
    return rows

def add_group(name: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO server_groups(name) VALUES (?)", (name,))
    conn.commit()
    conn.close()

def delete_group(group_id: int):
    conn = get_conn()
    cur = conn.cursor()
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
        # 获取所有服务器及其分组信息
        where_sql = (" WHERE " + " AND ".join(filters)) if filters else ""
        cur.execute("SELECT s.* FROM servers s" + where_sql + """
            ORDER BY
              CASE WHEN s.resource_type = '虚拟机' AND COALESCE(s.physical_ip, '') <> ''
                   THEN s.physical_ip ELSE s.ip END,
              CASE s.resource_type WHEN '物理机' THEN 0 WHEN '虚拟机' THEN 1 ELSE 2 END,
              s.ip
        """, params)
        servers = cur.fetchall()
        
        # 为每个服务器获取所属分组
        for server in servers:
            cur.execute("""
                SELECT g.* FROM server_groups g 
                INNER JOIN server_group_memberships m ON g.id = m.group_id
                WHERE m.server_id = ?
            """, (server['id'],))
            server['groups'] = cur.fetchall()
            server['group_names'] = ', '.join([g['name'] for g in server['groups']]) if server['groups'] else '无'
        conn.close()
        return servers
    else:
        # 获取指定分组的服务器
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
        
        # 为每个服务器获取所属分组
        for server in servers:
            cur.execute("""
                SELECT g.* FROM server_groups g 
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
               os_type: str = "Centos", rack_number: str = ""):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO servers(
            ip, port, username, enc_password, auth_type,
            enc_private_key, enc_key_passphrase, notes, name, resource_type,
            physical_ip, os_type, rack_number
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ip, port, username, enc_password, auth_type,
        enc_private_key, enc_key_passphrase, notes, name, resource_type,
        physical_ip, os_type, rack_number
    ))
    server_id = cur.lastrowid
    
    # 添加分组关联
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
                  rack_number: str = ""):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        UPDATE servers SET ip=?, port=?, username=?, enc_password=?, auth_type=?,
                           enc_private_key=?, enc_key_passphrase=?, notes=?, name=?,
                           resource_type=?, physical_ip=?, os_type=?, rack_number=?
        WHERE id=?
    """, (
        ip, port, username, enc_password, auth_type,
        enc_private_key, enc_key_passphrase, notes, name, resource_type,
        physical_ip, os_type, rack_number, server_id
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
        
        conn.commit()
        print("巡检任务表迁移完成")
    except sqlite3.Error as e:
        print(f"巡检任务表迁移失败: {e}")
    finally:
        conn.close()


# 巡检任务相关操作
def add_inspection_task(name: str, project_name: str, inspector: str, report_format: str = "excel",
                        resource_group_id=None, check_cpu=True, check_mem=True, check_disk=True,
                        enable_proxy=False, proxy_rules=None, enable_schedule=False, schedule_time=None):
    """添加巡检任务"""
    conn = get_conn()
    cur = conn.cursor()
    proxy_rules_json = json.dumps(proxy_rules or [])
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cur.execute("""
        INSERT INTO inspection_tasks(name, project_name, inspector, report_format, 
                                    resource_group_id, check_cpu, check_mem, check_disk,
                                    enable_proxy, proxy_rules, enable_schedule, schedule_time, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, project_name, inspector, report_format, 
          resource_group_id, 1 if check_cpu else 0, 1 if check_mem else 0, 1 if check_disk else 0,
          1 if enable_proxy else 0, proxy_rules_json, 1 if enable_schedule else 0, schedule_time, created_at))
    
    conn.commit()
    conn.close()

def list_inspection_tasks():
    """获取所有巡检任务"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM inspection_tasks ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    
    tasks = []
    for row in rows:
        resource_checks = []
        if row[6]:
            resource_checks.append("CPU")
        if row[7]:
            resource_checks.append("内存")
        if row[8]:
            resource_checks.append("磁盘")
        
        tasks.append({
            "id": row[0],
            "name": row[1],
            "project_name": row[2],
            "inspector": row[3],
            "report_format": row[4],
            "resource_group_id": row[5],
            "check_cpu": bool(row[6]),
            "check_mem": bool(row[7]),
            "check_disk": bool(row[8]),
            "enable_proxy": bool(row[9]),
            "proxy_rules": json.loads(row[10]) if row[10] else [],
            "enable_schedule": bool(row[11]) if len(row) > 11 else False,
            "schedule_time": row[12] if len(row) > 12 else None,
            "last_run": row[13] if len(row) > 13 else None,
            "created_at": row[14] if len(row) > 14 else None,
            "resource_checks": ", ".join(resource_checks)
        })
    return tasks

def get_inspection_task(task_id: int):
    """获取单个巡检任务"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM inspection_tasks WHERE id = ?", (task_id,))
    row = cur.fetchone()
    conn.close()
    
    if row:
        return {
            "id": row[0],
            "name": row[1],
            "project_name": row[2],
            "inspector": row[3],
            "report_format": row[4],
            "resource_group_id": row[5],
            "check_cpu": bool(row[6]),
            "check_mem": bool(row[7]),
            "check_disk": bool(row[8]),
            "enable_proxy": bool(row[9]),
            "proxy_rules": json.loads(row[10]) if row[10] else [],
            "enable_schedule": bool(row[11]) if len(row) > 11 else False,
            "schedule_time": row[12] if len(row) > 12 else None,
            "last_run": row[13] if len(row) > 13 else None,
            "created_at": row[14] if len(row) > 14 else None
        }
    return None

def update_inspection_task(task_id: int, name: str, project_name: str, inspector: str, report_format: str = "excel",
                          resource_group_id=None, check_cpu=True, check_mem=True, check_disk=True,
                          enable_proxy=False, proxy_rules=None, enable_schedule=False, schedule_time=None):
    """更新巡检任务"""
    conn = get_conn()
    cur = conn.cursor()
    proxy_rules_json = json.dumps(proxy_rules or [])
    
    cur.execute("""
        UPDATE inspection_tasks SET name=?, project_name=?, inspector=?, report_format=?,
                                   resource_group_id=?, check_cpu=?, check_mem=?, check_disk=?,
                                   enable_proxy=?, proxy_rules=?, enable_schedule=?, schedule_time=?
        WHERE id=?
    """, (name, project_name, inspector, report_format,
          resource_group_id, 1 if check_cpu else 0, 1 if check_mem else 0, 1 if check_disk else 0,
          1 if enable_proxy else 0, proxy_rules_json, 1 if enable_schedule else 0, schedule_time, task_id))
    
    conn.commit()
    conn.close()

def toggle_task_schedule(task_id: int):
    """切换任务定时状态"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT enable_schedule FROM inspection_tasks WHERE id = ?", (task_id,))
    row = cur.fetchone()
    if row:
        new_state = 0 if row[0] else 1
        cur.execute("UPDATE inspection_tasks SET enable_schedule = ? WHERE id = ?", (new_state, task_id))
        conn.commit()
    conn.close()

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


if __name__ == "__main__":
    migrate_from_old_schema()
