# -*- coding: utf-8 -*-
"""Codex-like local capabilities exposed to AI 智能运维.

This module deliberately keeps the powerful parts behind narrow server-side
controls:
- local skills live under one configured root only;
- creating a skill is a T2 action, so the UI must confirm it;
- MCP calls can target only servers already configured by an administrator.
"""
import json
import os
import re
import subprocess
import threading
import time

import config


class CodexToolError(Exception):
    """Raised when a local Codex-style capability is unavailable or unsafe."""


_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
_SAFE_REL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./-]{0,160}$")
_MCP_TOOL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")
_mcp_lock = threading.Lock()


def skills_root():
    return os.path.realpath(getattr(config, "AI_SKILLS_DIR", ""))


def mcp_config_path():
    return os.path.realpath(getattr(config, "AI_MCP_CONFIG", ""))


def ensure_skill_name(name):
    value = (name or "").strip().lower()
    if not _NAME_RE.fullmatch(value):
        raise CodexToolError("skill 名称只能使用小写字母、数字、下划线或连字符，且必须以字母开头")
    return value


def _safe_join(root, *parts):
    root = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(root, *parts))
    try:
        if os.path.commonpath([candidate, root]) != root:
            raise CodexToolError("路径超出允许目录")
    except ValueError:
        raise CodexToolError("路径不合法")
    return candidate


def _front_matter(text):
    if not text.startswith("---"):
        return {}
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    data = {}
    for line in lines[1:80]:
        if line.strip() == "---":
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def _read_text(path, limit):
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read(limit + 1)
    return text[:limit], len(text) > limit


def _dump(payload):
    return json.dumps(payload, ensure_ascii=False, default=str)


def list_skills(limit=50):
    root = skills_root()
    if not os.path.isdir(root):
        return {"root": root, "skills": [], "total": 0, "note": "技能目录尚不存在"}
    rows = []
    for name in sorted(os.listdir(root)):
        if len(rows) >= max(1, min(int(limit or 50), 200)):
            break
        folder = _safe_join(root, name)
        skill_md = os.path.join(folder, "SKILL.md")
        if not os.path.isdir(folder) or not os.path.isfile(skill_md):
            continue
        text, truncated = _read_text(skill_md, 12000)
        meta = _front_matter(text)
        rows.append({
            "name": name,
            "title": meta.get("name") or name,
            "description": meta.get("description") or "",
            "skill_md_bytes": os.path.getsize(skill_md),
            "truncated": truncated,
        })
    return {"root": root, "skills": rows, "total": len(rows)}


def read_skill(name, include_content=True, limit=12000):
    name = ensure_skill_name(name)
    folder = _safe_join(skills_root(), name)
    skill_md = os.path.join(folder, "SKILL.md")
    if not os.path.isfile(skill_md):
        raise CodexToolError(f"skill 不存在：{name}")
    files = []
    for current, dirs, filenames in os.walk(folder):
        dirs[:] = [item for item in dirs if not item.startswith(".")]
        for filename in filenames:
            path = os.path.join(current, filename)
            rel = os.path.relpath(path, folder).replace("\\", "/")
            files.append({"path": rel, "bytes": os.path.getsize(path)})
            if len(files) >= 200:
                break
    text, truncated = _read_text(skill_md, max(500, min(int(limit or 12000), 60000)))
    payload = {
        "name": name,
        "root": folder,
        "files": sorted(files, key=lambda item: item["path"]),
        "metadata": _front_matter(text),
    }
    if include_content:
        payload["skill_md"] = text
        payload["truncated"] = truncated
    return payload


def _safe_extra_files(files):
    result = []
    for item in files or []:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "").strip().replace("\\", "/")
        content = str(item.get("content") or "")
        if not path or path.upper() == "SKILL.md":
            continue
        if ".." in path.split("/") or path.startswith("/") or not _SAFE_REL_RE.fullmatch(path):
            raise CodexToolError(f"附加文件路径不安全：{path}")
        if len(content) > 60000:
            raise CodexToolError(f"附加文件过大：{path}")
        result.append({"path": path, "content": content})
        if len(result) > 20:
            raise CodexToolError("附加文件最多 20 个")
    return result


def normalize_create_skill(args, context):
    if context.get("role") != "admin":
        raise CodexToolError("只有超级管理员可以创建 skill")
    name = ensure_skill_name(args.get("name"))
    description = str(args.get("description") or "").strip()
    instructions = str(args.get("instructions") or "").strip()
    if not description:
        raise CodexToolError("缺少 description")
    if not instructions:
        raise CodexToolError("缺少 instructions")
    if len(description) > 600:
        description = description[:600]
    if len(instructions) > 60000:
        raise CodexToolError("instructions 过长")
    root = skills_root()
    folder = _safe_join(root, name)
    overwrite = bool(args.get("overwrite"))
    if os.path.exists(folder) and not overwrite:
        raise CodexToolError(f"skill 已存在：{name}（如需覆盖请明确 overwrite=true）")
    files = _safe_extra_files(args.get("files"))
    payload = {
        "name": name,
        "description": description,
        "instructions": instructions,
        "files": files,
        "overwrite": overwrite,
    }
    summary = f"创建本地 skill「{name}」到 {root}"
    risk = "medium" if overwrite else "low"
    return payload, summary, risk


def execute_create_skill(payload, context):
    name = ensure_skill_name(payload.get("name"))
    root = skills_root()
    folder = _safe_join(root, name)
    overwrite = bool(payload.get("overwrite"))
    if os.path.exists(folder) and not overwrite:
        return {"ok": False, "error": f"skill 已存在：{name}"}
    os.makedirs(folder, exist_ok=True)
    skill_md = os.path.join(folder, "SKILL.md")
    content = (
        "---\n"
        f'name: "{name}"\n'
        f'description: "{str(payload.get("description") or "").replace(chr(34), chr(39))}"\n'
        "---\n\n"
        "# Instructions\n\n"
        f"{payload.get('instructions') or ''}\n"
    )
    with open(skill_md, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    written = ["SKILL.md"]
    for item in _safe_extra_files(payload.get("files")):
        path = _safe_join(folder, item["path"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(item["content"])
        written.append(item["path"])
    return {"ok": True, "result": f"已创建 skill：{name}", "path": folder, "files": written}


def _load_mcp_config():
    path = mcp_config_path()
    if not os.path.isfile(path):
        return {"path": path, "servers": {}}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception as exc:
        raise CodexToolError(f"MCP 配置读取失败：{exc}")
    servers = data.get("servers") or data.get("mcpServers") or {}
    if not isinstance(servers, dict):
        raise CodexToolError("MCP 配置格式不正确：servers 必须是对象")
    return {"path": path, "servers": servers}


def _allowed_mcp_tools(server_name, server):
    """Normalize the administrator-owned MCP tool allowlist.

    Missing ``allowed_tools`` intentionally means deny-all.  Both a compact
    string list and an object form with display metadata are accepted.
    """
    raw = server.get("allowed_tools")
    if raw is None:
        return []
    entries = []
    if isinstance(raw, dict):
        for name, metadata in raw.items():
            item = dict(metadata) if isinstance(metadata, dict) else {}
            item["name"] = name
            entries.append(item)
    elif isinstance(raw, list):
        entries = [{"name": item} if isinstance(item, str) else item for item in raw]
    else:
        raise CodexToolError(
            f"MCP server {server_name} 的 allowed_tools 必须是数组或对象")

    result, seen = [], set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise CodexToolError(f"MCP server {server_name} 的工具白名单格式不正确")
        name = str(entry.get("name") or "").strip()
        if not _MCP_TOOL_RE.fullmatch(name):
            raise CodexToolError(f"MCP server {server_name} 的白名单工具名不合法：{name}")
        if name in seen:
            continue
        seen.add(name)
        risk = str(entry.get("risk") or "medium").strip().lower()
        if risk not in ("low", "medium", "high"):
            raise CodexToolError(f"MCP 工具 {server_name}/{name} 的 risk 无效")
        result.append({
            "name": name,
            "title": str(entry.get("title") or name).strip()[:100],
            "description": str(entry.get("description") or "").strip()[:500],
            "risk": risk,
            "enabled": bool(entry.get("enabled", True)),
        })
    return result


def _mcp_server(server_name):
    data = _load_mcp_config()
    server = data["servers"].get(server_name)
    if not isinstance(server, dict):
        raise CodexToolError(f"MCP server 不存在：{server_name}")
    return data, server


def _allowed_mcp_tool(server_name, tool_name, include_disabled=False):
    _, server = _mcp_server(server_name)
    if server.get("disabled") and not include_disabled:
        raise CodexToolError(f"MCP server 不存在或已禁用：{server_name}")
    allowed = {item["name"]: item for item in _allowed_mcp_tools(server_name, server)}
    item = allowed.get(tool_name)
    if not item or (not include_disabled and not item.get("enabled")):
        raise CodexToolError(f"MCP 工具未列入启用白名单：{server_name}/{tool_name}")
    return item


def list_mcp_extensions(role="admin"):
    """Static capability catalog for the front-end; does not start a process."""
    data = _load_mcp_config()
    servers = []
    for name, server in sorted(data["servers"].items()):
        if not isinstance(server, dict):
            continue
        disabled = bool(server.get("disabled"))
        tools = []
        for item in _allowed_mcp_tools(name, server):
            available = role == "admin" and not disabled and bool(item.get("enabled"))
            reason = ""
            if role != "admin":
                reason = "仅超级管理员可调用"
            elif disabled:
                reason = "MCP Server 已禁用"
            elif not item.get("enabled"):
                reason = "工具白名单项已禁用"
            tools.append({**item, "available": available, "unavailable_reason": reason})
        servers.append({
            "name": name,
            "title": str(server.get("title") or name).strip()[:100],
            "description": str(server.get("description") or "").strip()[:500],
            "disabled": disabled,
            "available": role == "admin" and not disabled,
            "tools": tools,
            "allowlist_count": len(tools),
        })
    return {"config_path": data["path"], "servers": servers, "total": len(servers)}


def list_mcp_servers():
    data = _load_mcp_config()
    rows = []
    for name, item in sorted(data["servers"].items()):
        if not isinstance(item, dict):
            continue
        allowed = _allowed_mcp_tools(name, item)
        rows.append({
            "name": name,
            "title": item.get("title") or name,
            "args_count": len(item.get("args") or []),
            "disabled": bool(item.get("disabled")),
            "description": item.get("description") or "",
            "allowed_tools": allowed,
            "allowlist_count": len(allowed),
        })
    return {"config_path": data["path"], "servers": rows, "total": len(rows)}


def _mcp_request(proc, request_id, method, params=None, timeout=20):
    body = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        body["params"] = params
    line = json.dumps(body, ensure_ascii=False) + "\n"
    proc.stdin.write(line)
    proc.stdin.flush()
    deadline = time.time() + timeout
    while time.time() < deadline:
        response = proc.stdout.readline()
        if not response:
            break
        try:
            payload = json.loads(response)
        except ValueError:
            continue
        if payload.get("id") == request_id:
            if payload.get("error"):
                raise CodexToolError(str(payload["error"])[:1000])
            return payload.get("result") or {}
    raise CodexToolError(f"MCP 请求超时：{method}")


def _start_mcp_server(server_name, data=None):
    data = data or _load_mcp_config()
    server = data["servers"].get(server_name)
    if not isinstance(server, dict) or server.get("disabled"):
        raise CodexToolError(f"MCP server 不存在或已禁用：{server_name}")
    command = str(server.get("command") or "").strip()
    args = server.get("args") or []
    if not command:
        raise CodexToolError(f"MCP server 缺少 command：{server_name}")
    if not isinstance(args, list) or any(not isinstance(item, str) for item in args):
        raise CodexToolError("MCP server args 必须是字符串数组")
    env = os.environ.copy()
    extra_env = server.get("env") or {}
    if isinstance(extra_env, dict):
        env.update({str(key): str(value) for key, value in extra_env.items()})
    cwd = server.get("cwd") or None
    return subprocess.Popen(
        [command] + args,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )


def mcp_call(server_name, tool_name=None, arguments=None, list_only=False, timeout=20):
    server_name = str(server_name or "").strip()
    if not server_name:
        raise CodexToolError("缺少 server_name")
    timeout = max(3, min(int(timeout or 20), 120))
    data, server = _mcp_server(server_name)
    if server.get("disabled"):
        raise CodexToolError(f"MCP server 不存在或已禁用：{server_name}")
    allowed = {item["name"]: item for item in _allowed_mcp_tools(server_name, server)
               if item.get("enabled")}
    if list_only and not allowed:
        return {
            "ok": True, "server": server_name, "tools": [], "allowlist_count": 0,
            "note": "未配置已启用的 allowed_tools，按默认拒绝策略未启动 MCP Server",
        }
    if not list_only:
        tool_name = str(tool_name or "").strip()
        if not tool_name:
            raise CodexToolError("缺少 tool_name")
        if tool_name not in allowed:
            raise CodexToolError(f"MCP 工具未列入启用白名单：{server_name}/{tool_name}")
    with _mcp_lock:
        proc = _start_mcp_server(server_name, data)
        try:
            _mcp_request(proc, 1, "initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "ops-inspection-ai", "version": "1.0"},
            }, timeout=timeout)
            tools = _mcp_request(proc, 2, "tools/list", {}, timeout=timeout).get("tools") or []
            if list_only:
                visible = []
                for item in tools:
                    if not isinstance(item, dict) or item.get("name") not in allowed:
                        continue
                    metadata = allowed[item["name"]]
                    visible.append({
                        **item,
                        "title": metadata.get("title") or item["name"],
                        "description": metadata.get("description") or item.get("description") or "",
                        "risk": metadata.get("risk") or "medium",
                    })
                return {
                    "ok": True, "server": server_name, "tools": visible,
                    "allowlist_count": len(allowed),
                    "note": "仅返回管理员白名单中已启用且由 MCP Server 实际提供的工具",
                }
            if tool_name not in {item.get("name") for item in tools if isinstance(item, dict)}:
                raise CodexToolError(f"MCP 工具不存在：{tool_name}")
            result = _mcp_request(proc, 3, "tools/call", {
                "name": tool_name,
                "arguments": arguments if isinstance(arguments, dict) else {},
            }, timeout=timeout)
            return {"ok": True, "server": server_name, "tool": tool_name, "result": result}
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            for handle in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    if handle:
                        handle.close()
                except Exception:
                    pass


def normalize_call_mcp(args, context):
    if context.get("role") != "admin":
        raise CodexToolError("只有超级管理员可以调用 MCP 工具")
    server_name = str(args.get("server_name") or "").strip()
    tool_name = str(args.get("tool_name") or "").strip()
    if not server_name or not tool_name:
        raise CodexToolError("缺少 server_name 或 tool_name")
    allowed = _allowed_mcp_tool(server_name, tool_name)
    payload = {
        "server_name": server_name,
        "tool_name": tool_name,
        "arguments": args.get("arguments") if isinstance(args.get("arguments"), dict) else {},
        "timeout": max(3, min(int(args.get("timeout") or 20), 120)),
    }
    summary = f"调用 MCP server「{server_name}」的工具「{allowed.get('title') or tool_name}」"
    return payload, summary, allowed.get("risk") or "medium"


def execute_call_mcp(payload, context):
    try:
        result = mcp_call(
            payload.get("server_name"),
            payload.get("tool_name"),
            payload.get("arguments") or {},
            list_only=False,
            timeout=payload.get("timeout") or 20,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:1000]}
    return {"ok": True, "result": _dump(result)[:4000], "mcp": result}
