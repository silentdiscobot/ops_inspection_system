# -*- coding: utf-8 -*-
"""AI 智能运维的工具层。

三层工具，级别决定"能不能自动执行"：
- read  (T0)：只读本系统数据库，模型调用即执行；
- remote(T1)：固定用途的远程只读采集，由本轮访问模式控制；
- action(T2)：有副作用的操作，由会话访问模式决定确认后执行或直接执行。

安全立场（见 docs/AI智能运维方案.md 决策 4/6/7）：
- 只认结构化 tool_calls，正文里的 JSON 永不执行；
- 模型给的参数一律不信任：server_id 必须能在库里查到；任意远程命令统一按变更操作处理；
- 远程执行与动作执行都由 app.py 注册进来，本模块不反向依赖 app，便于单测。
"""
import json
import re

import ai_codex_tools
import config
import models

LEVEL_READ = "read"
LEVEL_REMOTE = "remote"
LEVEL_ACTION = "action"

LEVEL_LABELS = {
    LEVEL_READ: "只读查询",
    LEVEL_REMOTE: "远程只读采集",
    LEVEL_ACTION: "需人工确认",
}

LEVEL_ORDER = {LEVEL_READ: 0, LEVEL_REMOTE: 1, LEVEL_ACTION: 2}

TRUNCATED_MARK = "\n[[已截断]]"
FILTERED_IP_MASK = "x.x.x.x"


class ToolError(Exception):
    """工具执行失败（参数不合法、目标不存在、能力未开启等）。"""


# ---------------- 由 app.py 注册的执行器 ----------------
_remote_runner = None
_service_discovery_runner = None
_action_executors = {}


def register_remote_runner(runner):
    """runner(server_row, command, timeout) -> dict(ok, output, error)"""
    global _remote_runner
    _remote_runner = runner


def register_service_discovery_runner(runner):
    """runner(server_row, include_system, context) -> discovery payload"""
    global _service_discovery_runner
    _service_discovery_runner = runner


def register_action_executor(action_type, executor):
    """executor(payload, context) -> dict(ok, result, error)"""
    _action_executors[action_type] = executor


def has_action_executor(action_type):
    return action_type in _action_executors


# ---------------- 上下文与可见性 ----------------
def default_context(username="", role="viewer", mask_ip=False):
    return {
        "username": username,
        "role": role,
        "mask_ip": bool(mask_ip),
        "client_ip": "",
    }


def available_specs(context=None):
    context = context or default_context()
    specs = []
    for spec in TOOL_SPECS:
        if spec.get("admin_only") and context.get("role") != "admin":
            continue
        specs.append(spec)
    return specs


def openai_tools(context=None):
    """转成 OpenAI 的 tools 参数格式。"""
    tools = []
    for spec in available_specs(context):
        function = {
            "name": spec["name"],
            "description": spec["description"],
            "parameters": spec["parameters"],
        }
        if spec.get("strict"):
            function["strict"] = True
        tools.append({
            "type": "function",
            "function": function,
        })
    return tools


def describe_tools(context=None):
    """给页面展示"我现在能做什么"。"""
    items = []
    for spec in TOOL_SPECS:
        items.append({
            "name": spec["name"],
            "level": spec["level"],
            "level_label": LEVEL_LABELS.get(spec["level"], spec["level"]),
            "title": spec.get("title") or spec["name"],
            "description": spec["description"],
            "source": "内置工具",
            "admin_only": bool(spec.get("admin_only")),
            "enabled_in_env": True,
        })
    return items


# ---------------- 执行入口 ----------------
def spec_for(name):
    return next((item for item in TOOL_SPECS if item["name"] == name), None)


def level_of(name):
    spec = spec_for(name)
    return spec["level"] if spec else "unknown"


def execute(name, args, context=None):
    """执行一个工具。

    返回 dict：
      {"ok", "kind": "result"|"action", "content"/"action_type", ...}
    kind=action 表示"需要人工确认"，此时不产生任何副作用。
    """
    context = context or default_context()
    spec = next((item for item in TOOL_SPECS if item["name"] == name), None)
    if not spec:
        raise ToolError(f"未知工具：{name}")
    if spec.get("admin_only") and context.get("role") != "admin":
        raise ToolError("当前角色无权使用该工具")
    if not isinstance(args, dict):
        raise ToolError("工具参数格式不正确")
    return spec["handler"](args, context)


# ---------------- 通用小工具 ----------------
def _truncate(text, limit=None):
    limit = int(limit or config.AI_TOOL_RESULT_LIMIT)
    value = "" if text is None else str(text)
    return value if len(value) <= limit else value[:limit] + TRUNCATED_MARK


def _dump(payload, limit=None):
    return _truncate(json.dumps(payload, ensure_ascii=False, default=str), limit)


def _mask(ip, context):
    if not context.get("mask_ip"):
        return ip or ""
    return FILTERED_IP_MASK


def _server_brief(row, context):
    return {
        "server_id": row.get("id"),
        "name": row.get("name") or "",
        "ip": _mask(row.get("ip"), context),
        "os_type": row.get("os_type") or "",
        "resource_type": row.get("resource_type") or "",
        "groups": row.get("group_names") or "无",
        "room_affiliation": row.get("room_affiliation") or "",
        "rack_number": row.get("rack_number") or "",
        "rack_level": row.get("rack_level") or "",
    }


def _require_server(args, context):
    raw_id = args.get("server_id")
    try:
        server_id = int(raw_id)
    except (TypeError, ValueError):
        raise ToolError("server_id 必须是数字，且必须来自 list_servers 的返回结果")
    server = models.get_server(server_id)
    if not server:
        raise ToolError(f"服务器不存在：server_id={server_id}（不接受自行编造的 ID/IP）")
    return server


def _require_int(args, key, default=None, minimum=1, maximum=None):
    value = args.get(key, default)
    if value is None or value == "":
        if default is None:
            raise ToolError(f"缺少参数 {key}")
        value = default
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ToolError(f"参数 {key} 必须是整数")
    number = max(minimum, number)
    return min(maximum, number) if maximum else number


# ---------------- T0：只读查询 ----------------
def _tool_list_servers(args, context):
    keyword = str(args.get("keyword") or "").strip()[:64]
    limit = _require_int(args, "limit", 50, 1, 200)
    servers = models.list_servers(keyword=keyword)
    payload = {
        "total": len(servers),
        "keyword": keyword,
        "servers": [_server_brief(row, context) for row in servers[:limit]],
        "truncated": len(servers) > limit,
    }
    return {"ok": True, "kind": "result", "content": _dump(payload),
            "summary": f"查询服务器清单，返回 {min(len(servers), limit)} 台"}


def _tool_list_groups(args, context):
    groups = models.list_groups()
    counts = {}
    for server in models.list_servers():
        for item in server.get("groups") or []:
            counts[item["id"]] = counts.get(item["id"], 0) + 1
    payload = [
        {"group_id": group["id"], "name": group["name"], "server_count": counts.get(group["id"], 0)}
        for group in groups
    ]
    return {"ok": True, "kind": "result", "content": _dump(payload),
            "summary": f"查询分组，共 {len(payload)} 个"}


def _tool_get_server_hardware(args, context):
    server = _require_server(args, context)
    snapshot = models.get_server_hardware(server["id"]) or {}
    payload = {
        "server_id": server["id"],
        "name": server.get("name") or "",
        "ip": _mask(server.get("ip"), context),
        "cpu": snapshot.get("cpu"),
        "memory": snapshot.get("memory"),
        "storage": snapshot.get("storage"),
        "gpu": snapshot.get("gpu"),
        "collected_at": snapshot.get("collected_at"),
        "checked_at": snapshot.get("checked_at"),
        "last_error": snapshot.get("last_error"),
        "change_summary": snapshot.get("change_summary"),
    }
    if not snapshot:
        payload["note"] = "该服务器还没有硬件参数记录"
    return {"ok": True, "kind": "result", "content": _dump(payload),
            "summary": f"读取 {payload['name'] or payload['ip']} 的硬件参数记录"}


def _tool_list_services(args, context):
    keyword = str(args.get("keyword") or "").strip()[:64]
    status = str(args.get("status") or "").strip()[:16]
    server_id = args.get("server_id")
    if server_id not in (None, ""):
        server = _require_server(args, context)
        server_id = server["id"]
    else:
        server_id = None
    limit = _require_int(args, "limit", 50, 1, 200)
    services = models.list_services(server_id=server_id, keyword=keyword, status=status)
    payload = []
    for item in services[:limit]:
        payload.append({
            "service_id": item.get("id"),
            "name": item.get("name"),
            "server": item.get("server_name") or item.get("server_ip") or "",
            "service_type": item.get("service_type"),
            "run_mode": item.get("run_mode"),
            "status": item.get("status"),
            "ports": item.get("ports"),
            "deploy_dir": item.get("deploy_dir"),
            "owner": item.get("owner"),
            "auto_start": bool(item.get("auto_start")),
            "notes": item.get("notes"),
        })
    return {"ok": True, "kind": "result", "content": _dump({"total": len(services), "services": payload}),
            "summary": f"查询服务台账，返回 {len(payload)} 条（不含任何账号凭据）"}


def _tool_list_inspection_runs(args, context):
    limit = _require_int(args, "limit", 10, 1, 50)
    runs = models.list_inspection_runs(limit)
    payload = []
    for run in runs:
        payload.append({
            "run_id": run.get("run_id"),
            "task_name": run.get("task_name"),
            "source": run.get("source"),
            "status": run.get("status"),
            "created_at": run.get("created_at"),
            "started_at": run.get("started_at"),
            "finished_at": run.get("finished_at"),
            "message": run.get("message"),
            "error": run.get("error"),
        })
    return {"ok": True, "kind": "result", "content": _dump(payload),
            "summary": f"查询最近 {len(payload)} 次巡检记录"}


def _tool_get_run_summary(args, context):
    run_id = str(args.get("run_id") or "").strip()
    if run_id:
        run = models.get_inspection_run(run_id)
        if not run:
            raise ToolError(f"巡检记录不存在：{run_id}")
    else:
        runs = models.list_inspection_runs(1)
        if not runs:
            raise ToolError("系统里还没有任何巡检记录")
        run = runs[0]
        run_id = run["run_id"]

    results = models.list_inspection_results(run_id)
    abnormal, abnormal_limit = [], 60
    ok_count = 0
    for item in results:
        if item.get("ok"):
            ok_count += 1
            continue
        if len(abnormal) < abnormal_limit:
            abnormal.append({
                "ip": _mask(item.get("server_ip"), context),
                "cpu": item.get("cpu"), "mem": item.get("mem"), "disk": item.get("disk"),
                "uptime": item.get("uptime"), "error": item.get("error"),
            })
    payload = {
        "run_id": run_id,
        "task_name": run.get("task_name"),
        "source": run.get("source"),
        "status": run.get("status"),
        "created_at": run.get("created_at"),
        "finished_at": run.get("finished_at"),
        "total": len(results),
        "ok": ok_count,
        "failed": len(results) - ok_count,
        "abnormal_servers": abnormal,
        "abnormal_truncated": (len(results) - ok_count) > abnormal_limit,
        "note": "cpu/mem/disk 为百分数；ok=0 表示该台连接失败或超阈值",
    }
    return {"ok": True, "kind": "result", "content": _dump(payload),
            "summary": f"读取巡检 {run_id} 的结果：{len(results)} 台，异常 {len(results) - ok_count} 台"}


def _tool_list_disk_findings(args, context):
    days = _require_int(args, "days", 7, 1, 90)
    server_id = args.get("server_id")
    rows = []
    if server_id not in (None, ""):
        server = _require_server(args, context)
        for snapshot in models.list_disk_snapshots(server["id"], limit=60):
            age_hours = snapshot.get("age_hours")
            if age_hours is None or age_hours > days * 24:
                continue
            rows.append({
                "server_id": server["id"],
                "server_name": server.get("name") or "",
                "server_ip": _mask(server.get("ip"), context),
                "collected_at": snapshot.get("collected_at"),
                "findings": snapshot.get("findings") or [],
            })
    else:
        for item in models.list_recent_disk_findings(days=days, limit=200):
            rows.append({
                "server_id": item.get("server_id"),
                "server_name": item.get("server_name") or "",
                "server_ip": _mask(item.get("server_ip"), context),
                "collected_at": item.get("collected_at"),
                "findings": item.get("findings") or [],
            })

    severity_rank = {"严重": 0, "警告": 1, "提示": 2}
    payload = []
    for row in rows:
        findings = sorted(row["findings"], key=lambda f: severity_rank.get(f.get("severity"), 3))
        payload.append({
            "server_id": row["server_id"],
            "server": row["server_name"] or row["server_ip"],
            "collected_at": row["collected_at"],
            "findings": [
                {"category": f.get("category"), "severity": f.get("severity"), "text": f.get("text")}
                for f in findings
            ],
        })
    return {"ok": True, "kind": "result",
            "content": _dump({"days": days, "servers_with_findings": len(payload), "items": payload}),
            "summary": f"读取近 {days} 天磁盘审计发现，涉及 {len(payload)} 台服务器"}


def _tool_list_audit_logs(args, context):
    if context.get("role") != "admin":
        raise ToolError("只有超级管理员可以查询审计日志")
    limit = _require_int(args, "limit", 50, 1, 200)
    logs = models.list_audit_logs(limit)
    payload = [
        {
            "created_at": item.get("created_at"), "username": item.get("username"),
            "action": item.get("action"), "result": item.get("result"),
            "target": f"{item.get('target_type') or ''}#{item.get('target_id') or ''}",
            "detail": item.get("detail"),
        }
        for item in logs
    ]
    return {"ok": True, "kind": "result", "content": _dump(payload),
            "summary": f"查询审计日志 {len(payload)} 条"}


def _normalize_upsert_server(args, context):
    if context.get("role") != "admin":
        raise ToolError("新增或修改服务器只允许超级管理员确认执行")
    raw_server_id = args.get("server_id")
    if raw_server_id in (None, ""):
        server_id, existing = None, None
    else:
        try:
            server_id = int(raw_server_id)
        except (TypeError, ValueError):
            raise ToolError("server_id 必须来自 list_servers；新增服务器时传 null")
        existing = models.get_server(server_id)
        if not existing:
            raise ToolError(f"服务器不存在：server_id={server_id}")

    def text(key, limit, default=""):
        value = str(args.get(key, default) or "").strip()
        if not value or len(value) > limit or any(ord(char) < 32 for char in value):
            raise ToolError(f"参数 {key} 不能为空、不能含控制字符且不能超过 {limit} 个字符")
        return value

    name = text("name", 100)
    ip = text("ip", 255)
    username = text("username", 64)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
        raise ToolError("username 格式无效")
    port = _require_int(args, "port", 22, 1, 65535)
    resource_type = str(args.get("resource_type") or "虚拟机")
    os_type = str(args.get("os_type") or "Centos")
    auth_type = str(args.get("auth_type") or "password")
    credential_mode = str(args.get("credential_mode") or "secure_input_required")
    if resource_type not in ("云实例", "虚拟机", "物理机"):
        raise ToolError("resource_type 无效")
    if os_type not in ("Centos", "Ubuntu", "Kylin V10", "Windows"):
        raise ToolError("os_type 无效")
    if auth_type not in ("password", "key"):
        raise ToolError("auth_type 无效")
    if credential_mode not in ("keep_existing", "secure_input_required"):
        raise ToolError("credential_mode 无效")
    if not existing and credential_mode != "secure_input_required":
        raise ToolError("新增服务器必须在确认卡片中安全录入 SSH 凭据")
    if existing and auth_type != existing.get("auth_type", "password") \
            and credential_mode != "secure_input_required":
        raise ToolError("切换认证方式时必须安全录入新凭据")
    if not existing:
        duplicate = next((row for row in models.list_servers() if row.get("ip") == ip), None)
        if duplicate:
            raise ToolError(
                f"IP {ip} 已登记为 server_id={duplicate['id']}，请使用该 server_id 发起更新")

    raw_group_ids = args.get("group_ids") or []
    if not isinstance(raw_group_ids, list) or len(raw_group_ids) > 50:
        raise ToolError("group_ids 必须是环境 ID 数组")
    valid_groups = {int(item["id"]) for item in models.list_groups()}
    try:
        group_ids = sorted({int(item) for item in raw_group_ids})
    except (TypeError, ValueError):
        raise ToolError("group_ids 必须全部来自 list_groups")
    if any(item not in valid_groups for item in group_ids):
        raise ToolError("group_ids 中包含不存在的环境 ID")

    optional = {}
    for key, limit in (("physical_ip", 255), ("rack_number", 100),
                       ("room_affiliation", 100), ("rack_level", 100), ("notes", 500)):
        value = str(args.get(key) or "").strip()
        if len(value) > limit or any(ord(char) < 32 and char not in "\t\n\r" for char in value):
            raise ToolError(f"参数 {key} 过长或包含控制字符")
        optional[key] = value

    payload = {
        "server_id": server_id, "name": name, "ip": ip, "port": port,
        "username": username, "auth_type": auth_type, "group_ids": group_ids,
        "resource_type": resource_type, "physical_ip": optional["physical_ip"],
        "os_type": os_type, "rack_number": optional["rack_number"],
        "room_affiliation": optional["room_affiliation"], "rack_level": optional["rack_level"],
        "notes": optional["notes"], "credential_mode": credential_mode,
    }
    verb = "更新" if existing else "新增"
    groups = [item["name"] for item in models.list_groups() if item["id"] in group_ids]
    credential_note = "沿用已保存凭据" if credential_mode == "keep_existing" else "确认时安全录入凭据"
    summary = f"{verb}服务器「{name}」（{ip}:{port}），环境：{'、'.join(groups) or '无'}；{credential_note}"
    return payload, summary, "high"


def _tool_discover_server_services(args, context):
    server = _require_server(args, context)
    if not _service_discovery_runner:
        raise ToolError("服务发现执行器未注册")
    include_system = bool(args.get("include_system_services"))
    result = _service_discovery_runner(server, include_system, context) or {}
    if not result.get("ok"):
        raise ToolError(result.get("error") or "服务发现失败")
    candidates = result.get("candidates") or []
    payload = {
        "scan_id": result.get("scan_id"),
        "server_id": server["id"],
        "server_name": server.get("name") or "",
        "candidate_count": len(candidates),
        "candidates": candidates,
        "warnings": result.get("warnings") or [],
        "note": "候选项来自固定只读采集器；导入前必须调用 import_discovered_services 并等待确认。",
    }
    return {
        "ok": True, "kind": "result", "content": _dump(payload, 20000),
        "summary": f"发现服务器「{server.get('name') or server.get('ip')}」上的 {len(candidates)} 个服务候选项",
    }


def _normalize_import_discovered_services(args, context):
    if context.get("role") != "admin":
        raise ToolError("批量导入服务只允许超级管理员确认执行")
    scan_id = str(args.get("scan_id") or "").strip()
    if not re.fullmatch(r"scan_[0-9a-f]{32}", scan_id):
        raise ToolError("scan_id 格式无效，必须来自 discover_server_services")
    models.expire_ai_service_discovery_scans()
    scan = models.get_ai_service_discovery_scan(scan_id)
    if not scan or scan.get("status") != "ready":
        raise ToolError("服务发现结果不存在、已过期或已导入，请重新扫描")
    if scan.get("requested_by") != context.get("username") and context.get("role") != "admin":
        raise ToolError("无权导入其他用户的扫描结果")
    raw_ids = args.get("candidate_ids")
    if not isinstance(raw_ids, list) or not raw_ids or len(raw_ids) > 200:
        raise ToolError("candidate_ids 必须是 1~200 个候选 ID")
    available = {item.get("candidate_id") for item in scan.get("candidates") or []}
    candidate_ids = []
    for item in raw_ids:
        value = str(item or "").strip()
        if value not in available:
            raise ToolError(f"候选服务不存在：{value}")
        if value not in candidate_ids:
            candidate_ids.append(value)
    strategy = str(args.get("strategy") or "skip_existing")
    if strategy not in ("skip_existing", "update_discovered_fields"):
        raise ToolError("strategy 只允许 skip_existing 或 update_discovered_fields")
    server = models.get_server(scan["server_id"])
    if not server:
        raise ToolError("扫描对应的服务器已不存在")
    payload = {"scan_id": scan_id, "candidate_ids": candidate_ids, "strategy": strategy}
    summary = f"向服务器「{server.get('name') or server.get('ip')}」导入 {len(candidate_ids)} 个服务（策略：{strategy}）"
    return payload, summary, "high"


# ---------------- 远程命令（由访问模式控制） ----------------
def validate_remote_command(command: str) -> str:
    """只做结构与长度校验，不限制命令、参数或 Shell 操作符。"""
    raw = str(command or "").strip()
    if not raw:
        raise ToolError("命令不能为空")
    if len(raw) > 2000:
        raise ToolError("命令不能超过 2000 个字符")
    if "\x00" in raw or "\r" in raw or "\n" in raw:
        raise ToolError("一次只能执行一条单行命令")
    return raw


def _normalize_remote_command(args, context):
    server = _require_server(args, context)
    command = validate_remote_command(args.get("command"))
    if _remote_runner is None:
        raise ToolError("远程执行器未注册，无法执行命令")
    payload = {"server_id": server["id"], "command": command}
    summary = f"在 {server.get('ip')} 上执行远程命令：{command[:300]}"
    return payload, summary, "high"


def execute_remote_command(payload, context):
    server_id = payload.get("server_id")
    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return {"ok": False, "error": "server_id 格式不正确"}
    server = models.get_server(server_id)
    if not server:
        return {"ok": False, "error": f"服务器不存在：server_id={server_id}"}
    command = validate_remote_command(payload.get("command"))
    if _remote_runner is None:
        return {"ok": False, "error": "远程执行器未注册，无法执行命令"}
    try:
        result = _remote_runner(server, command, config.AI_REMOTE_READ_TIMEOUT) or {}
    except Exception as exc:
        models.record_operation_audit(
            context.get("username") or "", server, command, "failed",
            error=str(exc), client_ip=context.get("client_ip") or "",
            source_action_id=context.get("source_action_id"))
        raise
    models.record_operation_audit(
        context.get("username") or "", server, command,
        "success" if result.get("ok") else "failed",
        error=result.get("error") or "", client_ip=context.get("client_ip") or "",
        source_action_id=context.get("source_action_id"))
    if not result.get("ok"):
        return {
            "ok": False, "error": result.get("error") or "命令执行失败",
            "command": command,
        }
    return {
        "ok": True, "result": _truncate(result.get("output") or "", 8000),
        "command": command, "server_id": server["id"],
    }


# ---------------- T2：需人工确认的动作 ----------------
def _normalize_start_inspection(args, context):
    project_name = str(args.get("project_name") or "").strip()[:100]
    inspector = str(args.get("inspector") or context.get("username") or "").strip()[:50]
    report_format = str(args.get("report_format") or "excel").strip().lower()
    if report_format not in ("excel", "pdf"):
        report_format = "excel"

    group_id = args.get("group_id")
    group_name = ""
    if group_id not in (None, ""):
        try:
            group_id = int(group_id)
        except (TypeError, ValueError):
            raise ToolError("group_id 必须是数字，且必须来自 list_groups 的返回结果")
        group = next((item for item in models.list_groups() if item["id"] == group_id), None)
        if not group:
            raise ToolError(f"分组不存在：group_id={group_id}")
        group_name = group["name"]
    else:
        group_id = None

    if not project_name:
        project_name = f"AI 发起的巡检（{inspector or context.get('username') or '系统'}）"

    payload = {
        "project_name": project_name,
        "inspector": inspector or "系统",
        "report_format": report_format,
        "resource_group_id": group_id,
        "check_cpu": True, "check_mem": True, "check_disk": True,
        "enable_proxy": False, "proxy_rules": [],
    }
    scope = f"分组「{group_name}」" if group_id else "全部服务器"
    summary = f"发起一次巡检：{scope}，项目名称「{project_name}」，巡检人「{payload['inspector']}」，格式 {report_format.upper()}"
    return payload, summary, "medium"


def _normalize_refresh_hardware(args, context):
    server = _require_server(args, context)
    payload = {"server_id": server["id"]}
    summary = f"重新采集服务器「{server.get('name') or server.get('ip')}」的硬件参数"
    return payload, summary, "low"


def _normalize_test_connection(args, context):
    server = _require_server(args, context)
    payload = {"server_id": server["id"]}
    summary = f"测试服务器「{server.get('name') or server.get('ip')}」的 SSH 连通性"
    return payload, summary, "low"


def _normalize_restart_service(args, context):
    service_id = _require_int(args, "service_id", None, 1)
    service = models.get_service(service_id)
    if not service:
        raise ToolError(f"服务不存在：service_id={service_id}")
    if not (service.get("restart_command") or "").strip():
        raise ToolError("该服务没有登记重启命令，无法代执行")
    if context.get("role") != "admin":
        raise ToolError("重启服务只允许超级管理员确认执行")
    command = (service.get("restart_command") or "").strip()
    payload = {
        "service_id": service_id,
        "server_id": service.get("server_id"),
        "service_name": service.get("name") or "",
        "server_name": service.get("server_name") or "",
        "server_ip": service.get("ip") or "",
        "command": command,
    }
    target = service.get("server_name") or service.get("ip") or "未知服务器"
    if service.get("server_name") and service.get("ip"):
        target = f"{service.get('server_name')}（{service.get('ip')}）"
    summary = f"重启服务「{service.get('name')}」；目标服务器：{target}"
    return payload, summary, "high"


def _tool_list_local_skills(args, context):
    limit = _require_int(args, "limit", 50, 1, 200)
    payload = ai_codex_tools.list_skills(limit)
    return {"ok": True, "kind": "result", "content": _dump(payload),
            "summary": f"查询本地 skill 清单，返回 {len(payload.get('skills') or [])} 个"}


def _tool_read_local_skill(args, context):
    name = str(args.get("name") or "").strip()
    include_content = args.get("include_content", True)
    limit = _require_int(args, "limit", 12000, 500, 60000)
    try:
        payload = ai_codex_tools.read_skill(name, include_content=include_content, limit=limit)
    except ai_codex_tools.CodexToolError as exc:
        raise ToolError(str(exc))
    return {"ok": True, "kind": "result", "content": _dump(payload),
            "summary": f"读取本地 skill：{payload.get('name')}"}


def _normalize_create_local_skill(args, context):
    try:
        return ai_codex_tools.normalize_create_skill(args, context)
    except ai_codex_tools.CodexToolError as exc:
        raise ToolError(str(exc))


def _tool_list_mcp_servers(args, context):
    try:
        payload = ai_codex_tools.list_mcp_servers()
    except ai_codex_tools.CodexToolError as exc:
        raise ToolError(str(exc))
    return {"ok": True, "kind": "result", "content": _dump(payload),
            "summary": f"查询 MCP server 配置，发现 {payload.get('total') or 0} 个"}


def _tool_list_mcp_tools(args, context):
    if context.get("role") != "admin":
        raise ToolError("只有超级管理员可以查看 MCP server 的工具清单")
    server_name = str(args.get("server_name") or "").strip()
    timeout = _require_int(args, "timeout", 20, 3, 120)
    try:
        payload = ai_codex_tools.mcp_call(server_name, list_only=True, timeout=timeout)
    except ai_codex_tools.CodexToolError as exc:
        raise ToolError(str(exc))
    return {"ok": True, "kind": "result", "content": _dump(payload, 12000),
            "summary": f"读取 MCP server「{server_name}」的工具清单"}


def _normalize_call_mcp_tool(args, context):
    try:
        return ai_codex_tools.normalize_call_mcp(args, context)
    except ai_codex_tools.CodexToolError as exc:
        raise ToolError(str(exc))


def _action_tool(normalizer, title):
    def handler(args, context):
        payload, summary, risk = normalizer(args, context)
        return {
            "ok": True, "kind": "action", "action_type": normalizer.action_type,
            "payload": payload, "summary": summary, "risk": risk,
            "content": _dump({"status": "pending_confirmation", "action": normalizer.action_type,
                              "summary": summary, "risk": risk,
                              "note": "该操作已提交人工确认，确认前不会执行任何动作。"}),
        }
    normalizer.action_type = title
    return handler


def _make_action_handler(normalizer, action_type):
    def handler(args, context):
        payload, summary, risk = normalizer(args, context)
        return {
            "ok": True, "kind": "action", "action_type": action_type,
            "payload": payload, "summary": summary, "risk": risk,
            "content": _dump({
                "status": "pending_confirmation",
                "action": action_type,
                "summary": summary,
                "risk": risk,
                "note": "已提交人工确认，确认前不会执行任何动作。请用一句话告诉用户去点确认。",
            }),
        }
    return handler


# ---------------- 工具清单 ----------------
TOOL_SPECS = [
    {
        "name": "list_servers", "level": LEVEL_READ, "title": "查询服务器清单",
        "description": "查询本系统的服务器资产清单（可选关键字过滤，匹配名称/IP/备注）。返回 server_id、名称、IP、操作系统、资源类型与分组。",
        "parameters": {
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "可选，关键字，匹配名称/IP/备注"},
                "limit": {"type": "integer", "description": "可选，最多返回多少台，默认 50"},
            },
        },
        "handler": _tool_list_servers,
    },
    {
        "name": "list_groups", "level": LEVEL_READ, "title": "查询服务器分组",
        "description": "查询服务器分组字典，返回 group_id、分组名与服务器数量。",
        "parameters": {"type": "object", "properties": {}},
        "handler": _tool_list_groups,
    },
    {
        "name": "get_server_hardware", "level": LEVEL_READ, "title": "查询硬件参数记录",
        "description": "读取某台服务器最近一次记录的 CPU/内存/存储/显卡参数与采集时间（不会实时连服务器）。",
        "parameters": {
            "type": "object",
            "properties": {"server_id": {"type": "integer", "description": "服务器 ID，必须来自 list_servers"}},
            "required": ["server_id"],
        },
        "handler": _tool_get_server_hardware,
    },
    {
        "name": "list_services", "level": LEVEL_READ, "title": "查询服务台账",
        "description": "查询服务信息表（服务名、所属服务器、类型、运行方式、状态、端口、部署目录、负责人）。不含任何账号口令。",
        "parameters": {
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "可选，关键字"},
                "server_id": {"type": "integer", "description": "可选，只看某台服务器上的服务"},
                "status": {"type": "string", "description": "可选，运行状态，如 运行中/已停止/已下线"},
                "limit": {"type": "integer", "description": "可选，默认 50"},
            },
        },
        "handler": _tool_list_services,
    },
    {
        "name": "list_inspection_runs", "level": LEVEL_READ, "title": "查询巡检记录列表",
        "description": "查询最近的巡检执行记录（run_id、任务名、来源、状态、时间、失败原因）。",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "可选，默认 10"}},
        },
        "handler": _tool_list_inspection_runs,
    },
    {
        "name": "get_run_summary", "level": LEVEL_READ, "title": "读取巡检结果明细",
        "description": "读取某次巡检的逐台结果与异常清单（不传 run_id 时取最近一次）。cpu/mem/disk 为百分数，ok=0 表示连接失败或超阈值。",
        "parameters": {
            "type": "object",
            "properties": {"run_id": {"type": "string", "description": "可选，巡检 run_id"}},
        },
        "handler": _tool_get_run_summary,
    },
    {
        "name": "list_disk_findings", "level": LEVEL_READ, "title": "读取磁盘审计发现",
        "description": "读取近几天磁盘巡检的发现项（掉盘、未挂载、只读、I/O 错误、增长异常、即将写满等），含严重级别。",
        "parameters": {
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "可选，最近多少天，默认 7"},
                "server_id": {"type": "integer", "description": "可选，只看某台服务器"},
            },
        },
        "handler": _tool_list_disk_findings,
    },
    {
        "name": "list_audit_logs", "level": LEVEL_READ, "title": "查询审计日志", "admin_only": True,
        "description": "查询系统审计日志（仅超级管理员可用）。",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "可选，默认 50"}},
        },
        "handler": _tool_list_audit_logs,
    },
    {
        "name": "upsert_server", "level": LEVEL_ACTION, "title": "新增或更新服务器",
        "admin_only": True, "always_confirm": True, "strict": True,
        "description": ("新增或更新服务器资产。必须先用 list_groups/list_servers 取得真实 ID。"
                        "不得提供密码或私钥；需要新凭据时使用 secure_input_required，"
                        "用户将在本地确认卡片中安全录入。此操作始终需要人工确认。"),
        "parameters": {
            "type": "object",
            "properties": {
                "server_id": {"type": ["integer", "null"], "description": "更新时为服务器 ID；新增时为 null"},
                "name": {"type": "string", "description": "服务器名称"},
                "ip": {"type": "string", "description": "IP 或主机名"},
                "port": {"type": "integer", "description": "SSH 端口"},
                "username": {"type": "string", "description": "SSH 用户名，不是密码"},
                "auth_type": {"type": "string", "enum": ["password", "key"]},
                "group_ids": {"type": "array", "items": {"type": "integer"}, "description": "环境 ID"},
                "resource_type": {"type": "string", "enum": ["云实例", "虚拟机", "物理机"]},
                "physical_ip": {"type": ["string", "null"]},
                "os_type": {"type": "string", "enum": ["Centos", "Ubuntu", "Kylin V10", "Windows"]},
                "rack_number": {"type": ["string", "null"]},
                "room_affiliation": {"type": ["string", "null"]},
                "rack_level": {"type": ["string", "null"]},
                "notes": {"type": ["string", "null"]},
                "credential_mode": {"type": "string", "enum": ["keep_existing", "secure_input_required"]},
            },
            "required": ["server_id", "name", "ip", "port", "username", "auth_type",
                         "group_ids", "resource_type", "physical_ip", "os_type", "rack_number",
                         "room_affiliation", "rack_level",
                         "notes", "credential_mode"],
            "additionalProperties": False,
        },
        "handler": _make_action_handler(_normalize_upsert_server, "upsert_server"),
    },
    {
        "name": "discover_server_services", "level": LEVEL_REMOTE,
        "title": "发现服务器运行服务", "strict": True,
        "description": ("在已登记服务器上使用后端固定的只读采集器发现 Docker、systemd、PM2"
                        "及监听端口服务。只传 server_id，不接受模型提供 Shell 命令。"),
        "parameters": {
            "type": "object",
            "properties": {
                "server_id": {"type": "integer", "description": "必须来自 list_servers"},
                "include_system_services": {"type": "boolean", "description": "通常为 false，是否包含基础系统服务"},
            },
            "required": ["server_id", "include_system_services"],
            "additionalProperties": False,
        },
        "handler": _tool_discover_server_services,
    },
    {
        "name": "import_discovered_services", "level": LEVEL_ACTION,
        "title": "导入发现的服务", "admin_only": True, "always_confirm": True, "strict": True,
        "description": ("把 discover_server_services 返回的候选服务批量写入服务台账。"
                        "只能引用同一次扫描里的 candidate_id，此操作始终需要人工确认。"),
        "parameters": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "必须来自 discover_server_services"},
                "candidate_ids": {"type": "array", "items": {"type": "string"}},
                "strategy": {"type": "string", "enum": ["skip_existing", "update_discovered_fields"]},
            },
            "required": ["scan_id", "candidate_ids", "strategy"],
            "additionalProperties": False,
        },
        "handler": _make_action_handler(_normalize_import_discovered_services,
                                        "import_discovered_services"),
    },
    {
        "name": "run_remote_command", "level": LEVEL_ACTION, "title": "执行远程命令",
        "description": ("在目标服务器上执行一条远程命令并返回输出。命令不经过只读白名单；"
                        "限制访问和变更访问需要人工确认，完全访问可直接执行。"
                        "仍受账号权限、超时、输出截断和审计约束。"),
        "parameters": {
            "type": "object",
            "properties": {
                "server_id": {"type": "integer", "description": "服务器 ID，必须来自 list_servers"},
                "command": {"type": "string", "description": "要执行的单行远程命令"},
            },
            "required": ["server_id", "command"],
        },
        "handler": _make_action_handler(_normalize_remote_command, "run_remote_command"),
    },
    {
        "name": "start_inspection", "level": LEVEL_ACTION, "title": "发起一次巡检",
        "description": "发起一次服务器资源巡检（会进入巡检队列并生成报告）。是否确认由当前访问模式决定。",
        "parameters": {
            "type": "object",
            "properties": {
                "project_name": {"type": "string", "description": "项目名称，用于报告命名"},
                "inspector": {"type": "string", "description": "巡检人（报告签字人）"},
                "group_id": {"type": "integer", "description": "可选，只巡检某个分组，必须来自 list_groups"},
                "report_format": {"type": "string", "enum": ["excel", "pdf"], "description": "报告格式"},
            },
        },
        "handler": _make_action_handler(_normalize_start_inspection, "start_inspection"),
    },
    {
        "name": "refresh_server_hardware", "level": LEVEL_ACTION, "title": "重新采集硬件参数",
        "description": "重新连接服务器采集一次硬件参数并更新记录。是否确认由当前访问模式决定。",
        "parameters": {
            "type": "object",
            "properties": {"server_id": {"type": "integer", "description": "服务器 ID"}},
            "required": ["server_id"],
        },
        "handler": _make_action_handler(_normalize_refresh_hardware, "refresh_server_hardware"),
    },
    {
        "name": "test_server_connection", "level": LEVEL_ACTION, "title": "测试服务器连通性",
        "description": "对指定服务器做一次 SSH 连通性测试。是否确认由当前访问模式决定。",
        "parameters": {
            "type": "object",
            "properties": {"server_id": {"type": "integer", "description": "服务器 ID"}},
            "required": ["server_id"],
        },
        "handler": _make_action_handler(_normalize_test_connection, "test_server_connection"),
    },
    {
        "name": "restart_registered_service", "level": LEVEL_ACTION, "title": "重启已登记服务",
        "admin_only": True,
        "description": "重启服务信息表里已登记重启命令的服务（高危，仅超级管理员可执行）。",
        "parameters": {
            "type": "object",
            "properties": {"service_id": {"type": "integer", "description": "服务 ID，来自 list_services"}},
            "required": ["service_id"],
        },
        "handler": _make_action_handler(_normalize_restart_service, "restart_registered_service"),
    },
    {
        "name": "list_local_skills", "level": LEVEL_READ, "title": "查询本地 Skills",
        "description": "查询 AI 智能运维可管理的本地 skill 清单。只读取 OPS_AI_SKILLS_DIR 指定目录，不访问其它路径。",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "可选，最多返回多少个，默认 50"}},
        },
        "handler": _tool_list_local_skills,
    },
    {
        "name": "read_local_skill", "level": LEVEL_READ, "title": "读取本地 Skill",
        "description": "读取一个本地 skill 的 SKILL.md 与文件清单。name 必须来自 list_local_skills 或符合本地 skill 命名规则。",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "skill 名称"},
                "include_content": {"type": "boolean", "description": "是否返回 SKILL.md 正文，默认 true"},
                "limit": {"type": "integer", "description": "最多返回多少字符，默认 12000"},
            },
            "required": ["name"],
        },
        "handler": _tool_read_local_skill,
    },
    {
        "name": "create_local_skill", "level": LEVEL_ACTION, "title": "创建本地 Skill",
        "admin_only": True,
        "description": ("创建一个 Codex 风格的本地 skill（目录 + SKILL.md，可带少量附加文件）。"
                        "该操作只写入 OPS_AI_SKILLS_DIR，且只允许超级管理员；是否确认由当前访问模式决定。"),
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "skill 名称，小写字母开头，可含数字、下划线、连字符"},
                "description": {"type": "string", "description": "skill 用途说明"},
                "instructions": {"type": "string", "description": "写入 SKILL.md 的主要说明"},
                "overwrite": {"type": "boolean", "description": "已存在时是否覆盖，默认 false"},
                "files": {
                    "type": "array",
                    "description": "可选附加文件，最多 20 个，路径不能越过 skill 目录",
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "content": {"type": "string"},
                        },
                    },
                },
            },
            "required": ["name", "description", "instructions"],
        },
        "handler": _make_action_handler(_normalize_create_local_skill, "create_local_skill"),
    },
    {
        "name": "list_mcp_servers", "level": LEVEL_READ, "title": "查询 MCP 配置",
        "admin_only": True,
        "description": "查询 OPS_AI_MCP_CONFIG 中预先配置的 MCP server 及扩展工具白名单，不执行工具。",
        "parameters": {"type": "object", "properties": {}},
        "handler": _tool_list_mcp_servers,
    },
    {
        "name": "list_mcp_tools", "level": LEVEL_READ, "title": "查询 MCP 工具清单",
        "admin_only": True,
        "description": "启动一个已配置的 MCP server 并读取 tools/list，只返回 allowed_tools 白名单中已启用且实际存在的工具。",
        "parameters": {
            "type": "object",
            "properties": {
                "server_name": {"type": "string", "description": "MCP server 名称，必须来自 list_mcp_servers"},
                "timeout": {"type": "integer", "description": "超时秒数，默认 20"},
            },
            "required": ["server_name"],
        },
        "handler": _tool_list_mcp_tools,
    },
    {
        "name": "call_mcp_tool", "level": LEVEL_ACTION, "title": "调用 MCP 工具",
        "admin_only": True,
        "description": ("调用 OPS_AI_MCP_CONFIG 中已配置 MCP server 的白名单工具。"
                        "未列入 allowed_tools 的工具默认拒绝；模型不能自带启动命令，"
                        "且只允许超级管理员，是否确认由当前访问模式决定。"),
        "parameters": {
            "type": "object",
            "properties": {
                "server_name": {"type": "string", "description": "MCP server 名称，必须来自 list_mcp_servers"},
                "tool_name": {"type": "string", "description": "工具名称，建议先用 list_mcp_tools 获取"},
                "arguments": {"type": "object", "description": "传给 MCP 工具的 JSON 参数"},
                "timeout": {"type": "integer", "description": "超时秒数，默认 20"},
            },
            "required": ["server_name", "tool_name"],
        },
        "handler": _make_action_handler(_normalize_call_mcp_tool, "call_mcp_tool"),
    },
]

ACTION_TYPES = ("start_inspection", "refresh_server_hardware", "test_server_connection",
                "restart_registered_service", "upsert_server", "import_discovered_services",
                "create_local_skill", "call_mcp_tool")
