# -*- coding: utf-8 -*-
import io, ipaddress, platform, shlex, subprocess
import paramiko, re
from typing import Dict, Any, Optional
from config import SSH_STRICT_HOST_KEY


def create_ssh_client():
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    if SSH_STRICT_HOST_KEY:
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return ssh


def parse_private_key(private_key: str, passphrase: str = None):
    """Parse common PEM/OpenSSH private key formats without writing to disk."""
    if not private_key or "PRIVATE KEY" not in private_key:
        raise ValueError("SSH私钥格式无效")
    key_classes = [paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key]
    dss_key = getattr(paramiko, "DSSKey", None)
    if dss_key:
        key_classes.append(dss_key)

    password_required = False
    for key_class in key_classes:
        try:
            return key_class.from_private_key(
                io.StringIO(private_key.strip() + "\n"),
                password=passphrase or None,
            )
        except paramiko.PasswordRequiredException:
            password_required = True
        except (paramiko.SSHException, ValueError):
            continue
    if password_required and not passphrase:
        raise ValueError("该SSH私钥需要口令")
    raise ValueError("无法识别SSH私钥，或私钥口令不正确")


def connect_ssh(ssh, ip: str, port: int, username: str, password: str = None,
                private_key: str = None, key_passphrase: str = None,
                timeout: int = 10):
    options = {
        "port": port,
        "username": username,
        "timeout": timeout,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if private_key:
        options["pkey"] = parse_private_key(private_key, key_passphrase)
    else:
        options["password"] = password
    ssh.connect(ip, **options)


def sanitize_curl_command(command: str) -> str:
    """Allow curl HTTP(S) requests while neutralizing shell injection."""
    if any(marker in (command or '') for marker in (';', '\n', '\r', '`', '$(', '&&', '||', '|')):
        raise ValueError('curl 命令包含不允许的 Shell 控制符')
    tokens = shlex.split(command or '')
    if not tokens or tokens[0].rsplit('/', 1)[-1] != 'curl':
        raise ValueError('仅允许执行 curl 命令')

    dangerous_options = {
        '-o', '--output', '-O', '--remote-name', '-T', '--upload-file',
        '-K', '--config', '--trace', '--trace-ascii', '--dump-header'
    }
    if any(token in dangerous_options for token in tokens[1:]):
        raise ValueError('curl 命令包含不允许的文件读写选项')
    if any(token.startswith(('file://', 'ftp://', 'scp://', 'sftp://')) for token in tokens):
        raise ValueError('仅允许 HTTP/HTTPS 地址')
    if any(token.startswith('@') or '=@' in token for token in tokens):
        raise ValueError('不允许读取远程服务器本地文件')
    if not any(token.startswith(('http://', 'https://')) for token in tokens):
        raise ValueError('curl 命令必须包含 HTTP/HTTPS 地址')
    return ' '.join(shlex.quote(token) for token in tokens)

def run_cmd(ssh, cmd: str, timeout: int = 15) -> str:
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", "ignore").strip()
    err = stderr.read().decode("utf-8", "ignore").strip()
    return out or err


def run_local_cmd(cmd: str, timeout: int = 15) -> str:
    completed = subprocess.run(
        ["/bin/sh", "-c", cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False
    )
    return (completed.stdout or completed.stderr).strip()


def compact_uptime(value: str, max_parts: int = 1) -> str:
    """Keep only the largest useful uptime unit for reports."""
    text = (value or "").replace("\n", " ").strip()
    if not text:
        return ""

    # /proc/uptime exposes seconds as its first value.
    if re.fullmatch(r"\d+(?:\.\d+)?(?:\s+\d+(?:\.\d+)?)?", text):
        seconds = float(text.split()[0])
        for size, label in ((31536000, "年"), (604800, "周"), (86400, "天"),
                            (3600, "小时"), (60, "分钟")):
            if seconds >= size:
                return f"{int(seconds // size)}{label}"
        return "不足1分钟"

    # Supports both `uptime -p` and classic macOS/BSD uptime output.
    if text.startswith("up "):
        duration = text[3:]
    else:
        match = re.search(
            r"\bup\s+(.+?)(?:,\s*\d+\s+users?\b|,\s*load averages?:|,\s*load average:|$)",
            text,
            re.IGNORECASE,
        )
        if match:
            duration = match.group(1)
        elif re.search(r"\b\d+\s+users?\b|\bload averages?:", text, re.IGNORECASE):
            return "不足1分钟"
        else:
            duration = text

    parts = [part.strip() for part in duration.split(",") if part.strip()]
    compact = []
    unit_labels = {
        "year": "年", "years": "年", "week": "周", "weeks": "周",
        "day": "天", "days": "天", "hour": "小时", "hours": "小时",
        "minute": "分钟", "minutes": "分钟", "min": "分钟", "mins": "分钟",
    }
    for part in parts:
        clock = re.fullmatch(r"(\d+):(\d+)", part)
        if clock:
            hours = int(clock.group(1))
            if hours:
                compact.append(f"{hours}小时")
            elif int(clock.group(2)):
                compact.append(f"{int(clock.group(2))}分钟")
        else:
            unit = re.fullmatch(r"(\d+)\s+([A-Za-z]+)", part)
            compact.append(
                f"{unit.group(1)}{unit_labels.get(unit.group(2).lower(), unit.group(2))}"
                if unit else part
            )
        if len(compact) >= max_parts:
            break
    return " ".join(compact)

def _parse_cpu_value(output: str) -> Optional[float]:
    """Parse CPU usage from top/mpstat/sar output.

    Different top versions print either ``96.2 id`` or ``96.2%id``.  The
    previous parser only accepted the latter, which made healthy Linux hosts
    appear as 0% CPU usage.
    """
    if not output:
        return None

    number = r"(\d+(?:[.,]\d+)?)"
    idle_matches = re.findall(number + r"\s*%?\s*id(?:le)?\b", output, re.IGNORECASE)
    if idle_matches:
        idle = float(idle_matches[-1].replace(",", "."))
        return round(max(0.0, min(100.0, 100.0 - idle)), 2)

    # `mpstat | grep all` and `sar | grep Average` normally put %idle last.
    for line in reversed(output.splitlines()):
        if re.search(r"\b(?:all|average)\b", line, re.IGNORECASE):
            values = re.findall(number, line)
            if values:
                idle = float(values[-1].replace(",", "."))
                return round(max(0.0, min(100.0, 100.0 - idle)), 2)

    # Last-resort support for older top formats that only expose user CPU.
    user_match = re.search(number + r"\s*%?\s*us\b", output, re.IGNORECASE)
    if user_match:
        return float(user_match.group(1).replace(",", "."))
    return None


def parse_cpu(output: str) -> float:
    value = _parse_cpu_value(output)
    return value if value is not None else 0.0


def parse_proc_cpu(output: str) -> Optional[float]:
    """Calculate CPU usage from two /proc/stat snapshots."""
    snapshots = []
    for line in (output or "").splitlines():
        if not re.match(r"^cpu\s+", line):
            continue
        try:
            values = [float(value) for value in line.split()[1:]]
        except ValueError:
            continue
        if len(values) >= 4:
            snapshots.append(values)
    if len(snapshots) < 2:
        return None
    first, last = snapshots[0], snapshots[-1]
    total_delta = sum(last) - sum(first)
    idle_delta = (last[3] - first[3])
    if len(first) > 4 and len(last) > 4:
        idle_delta += last[4] - first[4]
    if total_delta <= 0:
        return None
    return round(max(0.0, min(100.0, (total_delta - idle_delta) / total_delta * 100.0)), 2)

def parse_mem(output: str) -> float:
    # /proc/meminfo is available on Linux even when `free` is absent or localized.
    meminfo = {}
    for name, value in re.findall(r"^([A-Za-z_()]+):\s+(\d+)", output or "", re.MULTILINE):
        meminfo[name] = float(value)
    total = meminfo.get("MemTotal", 0.0)
    if total:
        available = meminfo.get("MemAvailable")
        if available is None:
            available = (meminfo.get("MemFree", 0.0) + meminfo.get("Buffers", 0.0)
                         + meminfo.get("Cached", 0.0) + meminfo.get("SReclaimable", 0.0)
                         - meminfo.get("Shmem", 0.0))
        return round(max(0.0, min(100.0, (total - available) / total * 100.0)), 2)

    # from `free -m`: Mem:  16095  1024  345 ...
    lines = output.splitlines()
    for line in lines:
        if line.lower().startswith("mem:"):
            parts = [p for p in line.split() if p]
            if len(parts) >= 3:
                total = float(parts[1])
                used = float(parts[2])
                return round(used / total * 100.0, 2)
    return 0.0

def parse_disk(output: str) -> float:
    # from `df -P /` : Use% in the 5th column
    lines = output.splitlines()
    for line in lines[1:]:
        parts = [p for p in line.split() if p]
        if len(parts) >= 5 and parts[5] in ("/", "/root", "/home"):
            usep = parts[4]
            if usep.endswith("%"):
                return float(usep[:-1])
    # fallback: take the max percentage
    maxp = 0.0
    for line in lines[1:]:
        parts = [p for p in line.split() if p]
        if len(parts) >= 5 and parts[4].endswith("%"):
            try:
                maxp = max(maxp, float(parts[4][:-1]))
            except:
                pass
    return maxp


def _local_mem_percent() -> float:
    if platform.system() != "Darwin":
        return parse_mem(run_local_cmd("cat /proc/meminfo 2>/dev/null || free -m"))

    total_text = run_local_cmd("sysctl -n hw.memsize")
    vm_stat = run_local_cmd("vm_stat")
    try:
        total = float(total_text)
        page_match = re.search(r"page size of (\d+) bytes", vm_stat)
        page_size = int(page_match.group(1)) if page_match else 4096
        pages = {}
        for name, value in re.findall(r"Pages ([^:]+):\s+(\d+)", vm_stat):
            pages[name.lower()] = int(value)
        available_pages = sum(
            pages.get(name, 0) for name in ("free", "inactive", "speculative")
        )
        used = max(0.0, total - available_pages * page_size)
        return round(used / total * 100.0, 2) if total else 0.0
    except (TypeError, ValueError):
        return 0.0


def inspect_local_server(ip: str, check_cpu=True, check_mem=True, check_disk=True) -> Dict[str, Any]:
    """Inspect loopback without requiring SSH or enabling Remote Login."""
    res = {
        "ip": ip, "uptime": "", "cpu": 0.0, "mem": 0.0, "disk": 0.0,
        "ok": False, "error": ""
    }
    try:
        uptime = run_local_cmd("uptime -p 2>/dev/null || uptime")
        res["uptime"] = compact_uptime(uptime)

        if check_cpu:
            if platform.system() == "Darwin":
                cpu_out = run_local_cmd(
                    "LANG=C top -l 2 -n 0 2>/dev/null | grep 'CPU usage' | tail -1",
                    timeout=20
                )
            else:
                proc_out = run_local_cmd(
                    "head -n 1 /proc/stat 2>/dev/null; sleep 0.5; "
                    "head -n 1 /proc/stat 2>/dev/null"
                )
                proc_value = parse_proc_cpu(proc_out)
                cpu_out = "" if proc_value is not None else run_local_cmd(
                    "LANG=C top -bn2 -d 0.2 2>/dev/null | "
                    "grep -E 'Cpu\\(s\\)|%Cpu' | tail -1"
                )
            res["cpu"] = proc_value if platform.system() != "Darwin" and proc_value is not None else parse_cpu(cpu_out)
        if check_mem:
            res["mem"] = _local_mem_percent()
        if check_disk:
            res["disk"] = parse_disk(run_local_cmd("df -P /"))
        res["ok"] = True
    except Exception as exc:
        res["error"] = str(exc)
    return res

def inspect_server(ip: str, port: int, username: str, password: str = None,
                   timeout: int = 10, check_cpu: bool = True,
                   check_mem: bool = True, check_disk: bool = True,
                   private_key: str = None, key_passphrase: str = None) -> Dict[str, Any]:
    try:
        if ipaddress.ip_address(ip).is_loopback:
            return inspect_local_server(ip, check_cpu, check_mem, check_disk)
    except ValueError:
        pass

    ssh = create_ssh_client()
    res = {
        "ip": ip,
        "uptime": "",
        "cpu": 0.0,
        "mem": 0.0,
        "disk": 0.0,
        "ok": False,
        "error": ""
    }
    try:
        connect_ssh(
            ssh, ip, port, username, password=password,
            private_key=private_key, key_passphrase=key_passphrase,
            timeout=timeout,
        )
        # uptime - 仅保留最大的时间单位
        uptime = run_cmd(ssh, "cat /proc/uptime 2>/dev/null || uptime -p || uptime")
        res["uptime"] = compact_uptime(uptime)

        # cpu
        if check_cpu:
            proc_out = run_cmd(
                ssh,
                "head -n 1 /proc/stat 2>/dev/null; sleep 0.5; "
                "head -n 1 /proc/stat 2>/dev/null"
            )
            cpu_value = parse_proc_cpu(proc_out)
            if cpu_value is None:
                cpu_out = run_cmd(
                    ssh,
                    "LANG=C top -bn2 -d 0.2 2>/dev/null | "
                    "grep -E 'Cpu\\(s\\)|%Cpu' | tail -1"
                )
                cpu_value = _parse_cpu_value(cpu_out)
            res["cpu"] = cpu_value if cpu_value is not None else 0.0

        # mem
        if check_mem:
            mem_out = run_cmd(ssh, "cat /proc/meminfo 2>/dev/null || free -m")
            res["mem"] = parse_mem(mem_out)

        # disk (root mount)
        if check_disk:
            disk_out = run_cmd(ssh, "df -P /")
            res["disk"] = parse_disk(disk_out)

        res["ok"] = True
    except Exception as e:
        res["error"] = str(e)
    finally:
        try:
            ssh.close()
        except Exception:
            pass
    return res

def test_proxy(ip: str, port: int, username: str, password: str, curl_cmd: str,
               success_keyword: str, timeout: int = 30,
               private_key: str = None, key_passphrase: str = None) -> Dict[str, Any]:
    ssh = create_ssh_client()
    res = {
        "ip": ip,
        "success": False,
        "output": "",
        "error": ""
    }
    try:
        curl_cmd = sanitize_curl_command(curl_cmd)
        connect_ssh(
            ssh, ip, port, username, password=password,
            private_key=private_key, key_passphrase=key_passphrase,
            timeout=timeout,
        )
        output = run_cmd(ssh, curl_cmd, timeout=timeout)
        res["output"] = output
        
        if success_keyword in output:
            res["success"] = True
        
    except Exception as e:
        res["error"] = str(e)
    finally:
        try:
            ssh.close()
        except Exception:
            pass
    return res
