# -*- coding: utf-8 -*-
"""Fixed-command service discovery for AI-assisted server onboarding.

The model never supplies a shell command to this module.  Callers provide an
already connected ``execute(command, timeout)`` function and only sanitized,
structured candidates leave this boundary.
"""
import hashlib
import json
import re


SYSTEM_UNITS = {
    "auditd", "chronyd", "containerd", "cron", "crond", "dbus", "docker",
    "firewalld", "getty@tty1",
    "irqbalance", "kdump", "NetworkManager", "network", "polkit", "rsyslog",
    "kubelet", "podman", "serial-getty@ttyS0", "sshd", "systemd-journald", "systemd-logind",
    "systemd-resolved", "systemd-udevd", "systemd-user-sessions", "tuned",
    "user@0", "zabbix-agent", "zabbix-agent2",
}

SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,99}$")
PORT_RE = re.compile(r"(?:(?:0\.0\.0\.0|\[::\]|\*|[0-9a-fA-F:.]+):)(\d{1,5})")
PROCESS_RE = re.compile(r'users:\(\("([^"\\]{1,80})"')


def _text(value, limit=200):
    value = "" if value is None else str(value)
    value = "".join(char for char in value if char in "\t\n\r" or ord(char) >= 32)
    return value.strip()[:limit]


def _candidate_id(source, name):
    digest = hashlib.sha256(f"{source}:{name}".encode("utf-8")).hexdigest()[:20]
    return f"{source}:{digest}"


def _commands(source, name):
    if not SAFE_NAME_RE.fullmatch(name or ""):
        return "", "", ""
    if source == "systemd":
        unit = name if name.endswith(".service") else name + ".service"
        return f"systemctl start {unit}", f"systemctl stop {unit}", f"systemctl restart {unit}"
    if source == "docker":
        return f"docker start {name}", f"docker stop {name}", f"docker restart {name}"
    if source == "pm2":
        return f"pm2 start {name}", f"pm2 stop {name}", f"pm2 restart {name}"
    return "", "", ""


def _service_type(name, version=""):
    text = f"{name} {version}".lower()
    if any(item in text for item in ("mysql", "mariadb", "postgres", "mongo", "oracle", "hivedb")):
        return "数据库"
    if any(item in text for item in (
            "redis", "nginx", "nacos", "kafka", "zookeeper", "rabbitmq", "elastic", "kibana")):
        return "中间件"
    return "应用服务"


def _new_candidate(source, name, **fields):
    start, stop, restart = _commands(source, name)
    value = {
        "candidate_id": _candidate_id(source, name),
        "source": source,
        "name": _text(name, 100),
        "service_type": fields.get("service_type") or _service_type(name, fields.get("version")),
        "run_mode": fields.get("run_mode") or (source if source in ("systemd", "docker") else "其他"),
        "version": _text(fields.get("version"), 50),
        "deploy_dir": _text(fields.get("deploy_dir"), 200),
        "start_command": start,
        "stop_command": stop,
        "restart_command": restart,
        "ports": _text(fields.get("ports"), 200),
        "config_path": "",
        "log_path": _text(fields.get("log_path"), 200),
        "access_url": "",
        "owner": "",
        "status": "运行中",
        "auto_start": bool(fields.get("auto_start")),
        "notes": _text(fields.get("notes") or f"AI 服务发现：{source}", 500),
        "evidence": _text(fields.get("evidence"), 300),
    }
    return value


def _parse_systemd(output, include_system):
    result = []
    for line in (output or "").splitlines():
        match = re.match(r"^\s*([A-Za-z0-9@_.:+-]+\.service)\s+loaded\s+active\s+running\s+(.*)$", line)
        if not match:
            continue
        unit, description = match.groups()
        short = unit[:-8]
        if not include_system and (short in SYSTEM_UNITS or short.startswith("systemd-")):
            continue
        result.append(_new_candidate(
            "systemd", short, run_mode="systemd", auto_start=True,
            notes=f"AI 服务发现：systemd；{_text(description, 180)}",
            evidence=f"运行中的 systemd 单元 {unit}",
        ))
    return result


def _parse_docker(output):
    result = []
    for line in (output or "").splitlines():
        try:
            row = json.loads(line)
        except (TypeError, ValueError):
            continue
        name = _text(row.get("Names"), 100)
        if not SAFE_NAME_RE.fullmatch(name):
            continue
        image = _text(row.get("Image"), 120)
        ports = _text(row.get("Ports"), 200)
        result.append(_new_candidate(
            "docker", name, run_mode="docker", version=image, ports=ports,
            auto_start=True, notes=f"AI 服务发现：Docker 镜像 {image}",
            evidence=f"运行中的容器 {name}；状态 {_text(row.get('Status'), 100)}",
        ))
    return result


def _parse_pm2(output):
    try:
        rows = json.loads(output or "[]")
    except (TypeError, ValueError):
        return []
    if not isinstance(rows, list):
        return []
    result = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        env = row.get("pm2_env") if isinstance(row.get("pm2_env"), dict) else {}
        if env.get("status") != "online":
            continue
        name = _text(row.get("name"), 100)
        if not SAFE_NAME_RE.fullmatch(name):
            continue
        result.append(_new_candidate(
            "pm2", name, run_mode="其他", version=env.get("version"),
            deploy_dir=env.get("pm_cwd"), log_path=env.get("pm_out_log_path"),
            auto_start=True, evidence=f"PM2 应用 {name} 状态 online",
        ))
    return result


def _parse_listeners(output, known_names):
    result = []
    ports_by_name = {}
    for line in (output or "").splitlines():
        process = PROCESS_RE.search(line)
        if not process:
            continue
        name = _text(process.group(1), 100)
        if not SAFE_NAME_RE.fullmatch(name):
            continue
        matches = [port for port in PORT_RE.findall(line) if 0 < int(port) <= 65535]
        if matches:
            ports_by_name.setdefault(name, set()).update(matches)
    for name, ports in ports_by_name.items():
        lowered = name.lower()
        if any(lowered in known or known in lowered for known in known_names):
            continue
        result.append(_new_candidate(
            "process", name, run_mode="其他", ports=", ".join(sorted(ports, key=int)),
            evidence=f"进程 {name} 正在监听 TCP 端口",
        ))
    return result


def discover(execute, include_system=False):
    """Run the bounded collectors and return sanitized candidates and warnings."""
    commands = (
        ("systemd", "systemctl list-units --type=service --state=running --no-legend --no-pager", 20),
        ("docker", "docker ps --no-trunc --format '{{json .}}'", 20),
        ("pm2", "pm2 jlist", 20),
        ("listeners", "ss -lntupH", 20),
    )
    outputs, warnings = {}, []
    for source, command, timeout in commands:
        try:
            outputs[source] = execute(command, timeout) or ""
        except Exception as exc:
            outputs[source] = ""
            warnings.append(f"{source} 采集失败：{_text(exc, 160)}")

    candidates = []
    candidates.extend(_parse_docker(outputs["docker"]))
    candidates.extend(_parse_pm2(outputs["pm2"]))
    candidates.extend(_parse_systemd(outputs["systemd"], bool(include_system)))
    known = {item["name"].lower() for item in candidates}
    candidates.extend(_parse_listeners(outputs["listeners"], known))

    unique = {}
    for item in candidates:
        key = (item["source"], item["name"].lower())
        unique.setdefault(key, item)
    return {
        "candidates": sorted(unique.values(), key=lambda item: (item["source"], item["name"])),
        "warnings": warnings,
    }
