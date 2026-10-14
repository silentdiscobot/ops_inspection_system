# -*- coding: utf-8 -*-
"""磁盘巡检增强：判断掉盘、磁盘损坏与容量增长异常。

目标服务器完全内网、不允许安装任何软件，所以这里只用系统自带的信息源：
/proc/mounts、/proc/partitions、/proc/mdstat、/sys 下的内核计数器、df 与 dmesg。
这些接口在 CentOS/Ubuntu/Kylin/UOS 上都存在，不需要 smartctl 之类的工具。

每次巡检把采集结果整理成"快照"存库，然后跟两个基线比对：
  * 大约一天前的快照：判断掉盘、阵列降级、容量增长趋势；
  * 最近一次（半小时前）的快照：判断故障计数增长、短时突增。

判定原则（避免误报）：
  * 挂载点/设备消失才算问题，采集不到的信息一律不判定；
  * 计数类只认"增长"，计数变小说明重启过，直接忽略；
  * 内核日志只报基线之后新增的行；
  * 本模块全是纯函数，不依赖 Flask / 数据库，便于单测。
"""
import os
import re
from datetime import datetime

from config import (
    DISK_AUDIT_BURST_GB,
    DISK_AUDIT_EXCLUDE_FSTYPES,
    DISK_AUDIT_EXCLUDE_PATHS,
    DISK_AUDIT_FULL_WARN_DAYS,
    DISK_AUDIT_GROWTH_GB_PER_DAY,
    DISK_AUDIT_GROWTH_PERCENT_PER_DAY,
    DISK_AUDIT_INODE_THRESHOLD,
    DISK_AUDIT_SHRINK_GB_PER_DAY,
    DISK_AUDIT_SMALL_FS_GB,
)

SEVERE = "severe"
WARN = "warn"
INFO = "info"

CATEGORY_CHECK = "磁盘检查"
CATEGORY_MISSING = "磁盘掉盘"
CATEGORY_UNMOUNTED = "磁盘未挂载"
CATEGORY_DEVICE_LOST = "磁盘消失"
CATEGORY_CAPACITY = "磁盘容量异常"
CATEGORY_RAID = "磁盘阵列降级"
CATEGORY_READONLY = "磁盘只读"
CATEGORY_FS_ERROR = "文件系统错误"
CATEGORY_IO_ERROR = "磁盘I/O错误"
CATEGORY_DEV_STATE = "磁盘状态异常"
CATEGORY_KERNEL = "内核磁盘错误"
CATEGORY_DF_ERROR = "文件系统异常"
CATEGORY_INODE = "inode使用率过高"
CATEGORY_GROWTH = "磁盘增长异常"
CATEGORY_FULL = "磁盘即将写满"
CATEGORY_BURST = "磁盘短时突增"
CATEGORY_SHRINK = "磁盘容量突降"
CATEGORY_CHANGE = "磁盘变化"

# 采集命令的分段标记，解析时按这些标记切分输出。
DISK_INVENTORY_COMMAND = "\n".join([
    'echo "##UPTIME"; cat /proc/uptime 2>/dev/null',
    'echo "##MOUNTS"; cat /proc/mounts 2>/dev/null',
    'echo "##DF";     df -Pk 2>&1',
    'echo "##DFI";    df -Pi 2>&1',
    'echo "##PARTS";  cat /proc/partitions 2>/dev/null',
    'echo "##LSBLK";  lsblk -P -b -o NAME,TYPE,SIZE,RO,MOUNTPOINT,FSTYPE,UUID 2>/dev/null',
    'echo "##MDSTAT"; cat /proc/mdstat 2>/dev/null',
    ('echo "##DEVSTATE"; for d in /sys/block/sd* /sys/block/vd* /sys/block/nvme* /sys/block/hd*; do '
     '[ -e "$d/device" ] || continue; n=${d##*/}; '
     "printf '%s state=%s ioerr=%s timeout=%s\\n' \"$n\" "
     '"$(cat "$d/device/state" 2>/dev/null)" "$(cat "$d/device/ioerr_cnt" 2>/dev/null)" '
     '"$(cat "$d/device/timeout_cnt" 2>/dev/null)"; done'),
    ('echo "##EXT4"; for e in /sys/fs/ext4/*/; do n=${e%/}; n=${n##*/}; '
     '[ -r "${e}errors_count" ] && printf \'%s errors=%s\\n\' "$n" "$(cat "${e}errors_count" 2>/dev/null)"; done'),
    ('echo "##DM"; for m in /sys/block/dm-*; do [ -r "$m/dm/name" ] || continue; '
     'printf \'%s name=%s\\n\' "${m##*/}" "$(cat "$m/dm/name" 2>/dev/null)"; done'),
    ('echo "##DISKID"; for f in /dev/disk/by-uuid/*; do [ -L "$f" ] && '
     'printf \'uuid %s %s\\n\' "${f##*/}" "$(readlink "$f" 2>/dev/null)"; done; '
     'for f in /dev/disk/by-path/*; do [ -L "$f" ] && '
     'printf \'path %s %s\\n\' "${f##*/}" "$(readlink "$f" 2>/dev/null)"; done'),
    ('echo "##DMESG"; dmesg 2>/dev/null | grep -iE '
     "'I/O error|medium error|Unrecovered read error|blk_update_request|EXT4-fs error|"
     "XFS \\(|failed command|Sense Key' | tail -n 30"),
    'echo "##END"',
])

# 判断"磁盘掉盘"时忽略的设备：光驱、回环设备、内存盘；md 由阵列规则单独判断。
IGNORED_DEVICE_RE = re.compile(r"^(loop|sr|ram|zram|fd|md)")
# mdstat 成员：sdb1[1] / sdb1[1](F) / sdb1[1](S)
_MDSTAT_HEAD_RE = re.compile(r"^(md[\w.-]*)\s*:\s*(\S+)\s*(\S+)?\s*(.*)$")
_MDSTAT_MEMBER_RE = re.compile(r"([\w./-]+)\[(\d+)\](?:\(([A-Z])\))?")
_MDSTAT_FLAGS_RE = re.compile(r"\[(\d+)/(\d+)\]\s*\[([U_]+)\]")
_MDSTAT_PROGRESS_RE = re.compile(r"(resync|recovery|reshape|check|repair)\s*=\s*([0-9.]+)%")
_SECTION_RE = re.compile(r"^##([A-Z0-9]+)\s*$", re.M)
_DF_PERCENT_RE = re.compile(r"^[0-9.]+%$")
_LSBLK_PAIR_RE = re.compile(r'([A-Z:_-]+)="([^"]*)"')
_MOUNT_ESCAPES = (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\"))
_KERNEL_SEVERE_HINTS = (
    "medium error", "unrecover", "critical medium error", "ext4-fs error", "xfs (",
)
_KERNEL_RECENT_SECONDS = 24 * 3600
_BAD_DEVICE_STATES = ("offline", "blocked", "deleted", "cancel", "quiesce")
# 只有两次巡检间隔在 6 小时以内，突增判断才有意义（每天只跑一次时不做突增）。
_BURST_MAX_HOURS = 6.0


# ==================== 文本解析 ====================

def parse_sections(output):
    """按 ##标记 切分复合命令输出，返回 {标记: 正文}。"""
    sections = {}
    if not output:
        return sections
    marks = list(_SECTION_RE.finditer(output))
    for index, mark in enumerate(marks):
        start = mark.end()
        end = marks[index + 1].start() if index + 1 < len(marks) else len(output)
        sections[mark.group(1)] = output[start:end].strip("\n")
    return sections


def unescape_mount(value):
    """还原 /proc/mounts 里的八进制转义（空格、制表符等）。"""
    for token, char in _MOUNT_ESCAPES:
        value = value.replace(token, char)
    return value


def parse_mounts(text):
    """解析 /proc/mounts，返回 [{device, mount, fstype, ro}]。"""
    mounts = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        options = parts[3].split(",")
        mounts.append({
            "device": unescape_mount(parts[0]),
            "mount": unescape_mount(parts[1]),
            "fstype": parts[2].lower(),
            "ro": "ro" in options,
        })
    return mounts


def _parse_df_line(line):
    """解析 df 的一行；从右往左找百分号列，兼容挂载点里带空格的情况。"""
    parts = line.split()
    if len(parts) < 6:
        return None
    anchor = None
    for index in range(len(parts) - 2, 3, -1):
        if not _DF_PERCENT_RE.match(parts[index]):
            continue
        try:
            usage = float(parts[index][:-1])
            total = int(parts[index - 3])
            used = int(parts[index - 2])
            avail = int(parts[index - 1])
        except ValueError:
            continue
        anchor = index
        break
    if anchor is None:
        return None
    return {
        "device": " ".join(parts[:anchor - 3]),
        "mount": " ".join(parts[anchor + 1:]),
        "total_kb": total,
        "used_kb": used,
        "avail_kb": avail,
        "usage": usage,
    }


def _is_df_header(line):
    """识别英文/中文 df 表头，避免把本地化表头当成文件系统异常。"""
    normalized = re.sub(r"\s+", " ", (line or "").strip().lower())
    if not normalized:
        return False
    if normalized.startswith("filesystem "):
        return True
    if normalized.startswith("文件系统"):
        return True
    header_tokens = ("1024-blocks", "1024-块", "mounted on", "挂载点", "已挂载")
    return "filesystem" in normalized and any(token in normalized for token in header_tokens)


def parse_df(text):
    """解析 df -Pk 输出，返回 (数据行, 报错行)。"""
    rows, errors = [], []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or _is_df_header(line):
            continue
        parsed = _parse_df_line(line)
        if parsed is None:
            errors.append(line)
        else:
            rows.append(parsed)
    return rows, errors


def parse_df_inodes(text):
    """解析 df -Pi 输出，返回 {挂载点: inode 使用率}。"""
    return {row["mount"]: row["usage"] for row in parse_df(text)[0]}


def parse_parts(text):
    """解析 /proc/partitions，返回 [{name, size_kb}]。"""
    parts = []
    for line in (text or "").splitlines():
        fields = line.split()
        if len(fields) < 4 or not fields[0].isdigit():
            continue
        try:
            size_kb = int(fields[2])
        except ValueError:
            continue
        parts.append({"name": fields[3], "size_kb": size_kb})
    return parts


def parse_lsblk(text):
    """解析 lsblk -P 输出，返回 [{name, type, size_kb, ro, mount, fstype, uuid}]。"""
    devices = []
    for line in (text or "").splitlines():
        if "NAME=" not in line:
            continue
        fields = dict(_LSBLK_PAIR_RE.findall(line))
        name = (fields.get("NAME") or "").strip()
        if not name:
            continue
        try:
            size_kb = int(fields.get("SIZE") or 0) // 1024
        except ValueError:
            size_kb = 0
        devices.append({
            "name": name,
            "type": (fields.get("TYPE") or "").strip(),
            "size_kb": size_kb,
            "ro": (fields.get("RO") or "0").strip().lower() in ("1", "true", "yes"),
            "mount": (fields.get("MOUNTPOINT") or "").strip(),
            "fstype": (fields.get("FSTYPE") or "").strip().lower(),
            "uuid": (fields.get("UUID") or "").strip(),
        })
    return devices


def parse_devstate(text):
    """解析 /sys/block/*/device 的 state/ioerr_cnt/timeout_cnt 汇总行。"""
    devices = {}
    for line in (text or "").splitlines():
        fields = line.split()
        if not fields:
            continue
        name = fields[0]
        entry = {}
        for token in fields[1:]:
            key, _, value = token.partition("=")
            if key == "state" and value:
                entry["state"] = value
            elif key in ("ioerr", "timeout"):
                if value.isdigit():
                    entry[key] = int(value)
        if entry:
            devices[name] = entry
    return devices


def parse_ext4_errors(text):
    """解析 /sys/fs/ext4/*/errors_count，返回 {块设备: 计数}。"""
    counters = {}
    for line in (text or "").splitlines():
        fields = line.split()
        if len(fields) < 2 or not fields[1].startswith("errors="):
            continue
        value = fields[1].split("=", 1)[1]
        if value.isdigit():
            counters[fields[0]] = int(value)
    return counters


def parse_dm_names(text):
    """解析 /sys/block/dm-*/dm/name，返回 {dm-0: 卷名}。"""
    names = {}
    for line in (text or "").splitlines():
        fields = line.split()
        if len(fields) < 2 or not fields[1].startswith("name="):
            continue
        names[fields[0]] = fields[1].split("=", 1)[1]
    return names


def parse_disk_links(text):
    """解析 /dev/disk/by-uuid、by-path 的软链接，返回 {uuid: {名字: 设备}, path: {...}}。"""
    links = {"uuid": {}, "path": {}}
    for line in (text or "").splitlines():
        fields = line.split()
        if len(fields) != 3 or fields[0] not in links:
            continue
        kind, name, target = fields
        device = os.path.basename(target.rstrip("/"))
        if device:
            links[kind][name] = device
    return links


def parse_uptime(text):
    """/proc/uptime 第一列是开机秒数，用于识别重启与换算日志时间。"""
    fields = (text or "").split()
    if not fields:
        return None
    try:
        return int(float(fields[0]))
    except ValueError:
        return None


def parse_dmesg(text):
    """解析 dmesg 行，返回 [{t, text}]，t 为开机后的秒数。"""
    lines = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line.startswith("["):
            continue
        end = line.find("]")
        if end < 0:
            continue
        try:
            timestamp = float(line[1:end].strip())
        except ValueError:
            continue
        message = line[end + 1:].strip()
        if message:
            lines.append({"t": timestamp, "text": message})
    return lines


def parse_mdstat(text):
    """解析 /proc/mdstat，返回 {阵列名: {...}}。"""
    arrays = {}
    current = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        head = _MDSTAT_HEAD_RE.match(line)
        if head:
            state = head.group(2).lower()
            current = {
                "level": (head.group(3) or "").lower(),
                "state": state,
                "members": [],
                "failed": [],
                "spares": [],
                "groups": [],
                "degraded": state != "active",
                "rebuilding": None,
            }
            for member, _index, mark in _MDSTAT_MEMBER_RE.findall(head.group(4)):
                current["members"].append(member)
                if mark == "F":
                    current["failed"].append(member)
                elif mark == "S":
                    current["spares"].append(member)
            if current["failed"]:
                current["degraded"] = True
            arrays[head.group(1)] = current
            continue
        if current is None:
            continue
        for total, active, flags in _MDSTAT_FLAGS_RE.findall(line):
            current["groups"].append([int(total), int(active), flags])
            if "_" in flags or int(active) < int(total):
                current["degraded"] = True
        progress = _MDSTAT_PROGRESS_RE.search(line)
        if progress:
            current["rebuilding"] = {
                "op": progress.group(1),
                "percent": float(progress.group(2)),
            }
    return arrays


# ==================== 快照组装 ====================

def visible_mounts(mounts):
    """过滤内核虚拟文件系统、容器与临时挂载，只留下要盯的数据盘。"""
    result = []
    for item in mounts or []:
        fstype = (item.get("fstype") or "").lower()
        mount = item.get("mount") or ""
        if not mount or fstype in DISK_AUDIT_EXCLUDE_FSTYPES:
            continue
        if any(mount == prefix or mount.startswith(prefix + "/") for prefix in DISK_AUDIT_EXCLUDE_PATHS):
            continue
        result.append(item)
    return result


def format_size_kb(size_kb):
    """把 KB 换算成便于阅读的容量。"""
    if not size_kb or size_kb <= 0:
        return "未知"
    gb = size_kb / 1024.0 / 1024.0
    if gb >= 1024:
        return "{:.1f} TB".format(gb / 1024.0)
    if gb >= 10:
        return "{:.0f} GB".format(gb)
    return "{:.1f} GB".format(gb)


def _guess_device_type(name):
    """/proc/partitions 不带类型信息，按命名习惯粗略推断。"""
    if name.startswith("md"):
        return "raid"
    if name.startswith("dm-"):
        return "lvm"
    if name.startswith("loop"):
        return "loop"
    if re.match(r"^nvme\d+n\d+p\d+$", name) or re.match(r"^mmcblk\d+p\d+$", name):
        return "part"
    if re.match(r"^(nvme\d+n\d+|mmcblk\d+)$", name):
        return "disk"
    return "part" if name[-1].isdigit() else "disk"


def _devices_from_partitions(sections):
    """lsblk 不可用时退回 /proc/partitions，用 dm 名字还原逻辑卷名。"""
    dm_names = parse_dm_names(sections.get("DM", ""))
    devices = []
    for item in parse_parts(sections.get("PARTS", "")):
        name = item["name"]
        if name.startswith("dm-"):
            devices.append({
                "name": dm_names.get(name, name),
                "type": "lvm",
                "size_kb": item["size_kb"],
                "ro": False, "mount": "", "fstype": "", "uuid": "",
            })
            continue
        devices.append({
            "name": name,
            "type": _guess_device_type(name),
            "size_kb": item["size_kb"],
            "ro": False, "mount": "", "fstype": "", "uuid": "",
        })
    return devices


def _build_devices(sections):
    """整理块设备清单：优先 lsblk（带 UUID），否则退回 /proc/partitions。"""
    devices = parse_lsblk(sections.get("LSBLK", ""))
    source = "lsblk" if devices else "partitions"
    if not devices:
        devices = _devices_from_partitions(sections)

    links = parse_disk_links(sections.get("DISKID", ""))
    by_path = {}
    for path_name, device in sorted(links["path"].items()):
        by_path.setdefault(device, path_name)
    uuid_by_device = {device: uuid for uuid, device in links["uuid"].items()}
    states = parse_devstate(sections.get("DEVSTATE", ""))

    for device in devices:
        name = device["name"]
        device.setdefault("uuid", "")
        if not device["uuid"]:
            device["uuid"] = uuid_by_device.get(name, "")
        device["by_path"] = by_path.get(name, "")
        device.update(states.get(name, {}))
    return devices, source


def build_snapshot(sections, now=None):
    """把复合命令的分段输出整理成可入库的磁盘快照。

    返回 (payload, error)。拿不到任何挂载信息时 payload 为 None 并给出原因；
    其余情况即使某些分段为空也照常返回快照，缺失的信号自然不参与判定。
    """
    mounts = parse_mounts(sections.get("MOUNTS", ""))
    df_rows, df_errors = parse_df(sections.get("DF", ""))
    if not mounts and not df_rows:
        return None, "未能采集磁盘明细（/proc/mounts 与 df 均无有效输出）"

    devices, source = _build_devices(sections)
    truncated = len(devices) > 600
    if truncated:
        devices = devices[:600]

    kernel_lines = parse_dmesg(sections.get("DMESG", ""))
    kernel = {
        "errors_total": len(kernel_lines),
        "errors_last_at": kernel_lines[-1]["t"] if kernel_lines else None,
        "recent": [
            {"t": item["t"], "text": item["text"][:300]} for item in kernel_lines[-5:]
        ],
    }
    visible = visible_mounts(mounts)
    payload = {
        "collected_at": (now or datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "devices_truncated": truncated,
        "uptime_seconds": parse_uptime(sections.get("UPTIME", "")),
        "mounts": [
            {"device": item["device"], "mount": item["mount"],
             "fstype": item["fstype"], "ro": item["ro"]}
            for item in mounts
        ],
        "filesystems": df_rows,
        "inodes": parse_df_inodes(sections.get("DFI", "")),
        "df_errors": df_errors,
        "devices": devices,
        "raid": parse_mdstat(sections.get("MDSTAT", "")),
        "fs_errors": parse_ext4_errors(sections.get("EXT4", "")),
        "kernel": kernel,
        "counts": {
            "mounts": len(visible),
            "all_mounts": len(mounts),
            "disks": len([d for d in devices if d.get("type") == "disk"]),
            "inode_samples": len(parse_df_inodes(sections.get("DFI", ""))),
        },
    }
    return payload, ""


# ==================== 判定规则 ====================

def finding(severity, category, text, mount=None):
    item = {"severity": severity, "category": category, "text": text}
    if mount:
        item["mount"] = mount
    return item


def format_findings(findings):
    """把 finding 转成报告里的一行行文字。"""
    return [
        "【{}】{}".format(item.get("category") or CATEGORY_CHECK, item.get("text") or "")
        for item in findings or []
    ]


def split_findings(findings):
    """按严重程度拆成 (异常, 变更提示) 两组。"""
    alerts, notices = [], []
    for item in findings or []:
        if item.get("severity") in (SEVERE, WARN):
            alerts.append(item)
        else:
            notices.append(item)
    return alerts, notices


def _days_text(days):
    if days < 1:
        return "不到 1 天就会写满"
    return "约 {:.1f} 天后写满".format(days)


def _shorten(text, limit=160):
    text = (text or "").strip()
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _payload(row):
    return (row or {}).get("payload") or {}


def _mount_map(payload):
    return {item["mount"]: item for item in visible_mounts(payload.get("mounts") or [])}


def _filesystem_map(payload):
    visible = set(_mount_map(payload))
    return {
        item["mount"]: item for item in payload.get("filesystems") or []
        if item.get("mount") in visible
    }


def _device_map(payload):
    return {item["name"]: item for item in payload.get("devices") or []}


def _parent_device_name(name):
    """从分区名退回它所属的整盘名：sdb1→sdb、nvme0n1p1→nvme0n1、mmcblk0p1→mmcblk0。

    识别不出来（dm-0、md0 等）时返回 None，调用方按“无法判断”处理。
    """
    name = name or ""
    match = re.match(r"^(nvme\d+n\d+|mmcblk\d+|loop\d+)p\d+$", name)
    if match:
        return match.group(1)
    match = re.match(r"^([a-z]{2,})\d+$", name)
    if match:
        return match.group(1)
    return None


def _renamed_uuids(prev, cur):
    """本次出现、且基线里也存在的 UUID：这些设备只是换了设备名（sdb→sdc），不是掉盘。"""
    prev_uuids = {item.get("uuid") for item in _device_map(prev).values() if item.get("uuid")}
    if not prev_uuids:
        return set()
    return {
        item.get("uuid") for item in cur.get("devices") or []
        if item.get("uuid") in prev_uuids
    }


def _renamed_parent_devices(prev, cur):
    """被换名的分区所属整盘名（改名后的新名字），避免把 sdb→sdc 又报成“新增块设备 sdc”。"""
    kept = _renamed_uuids(prev, cur)
    if not kept:
        return set()
    parents = set()
    for item in cur.get("devices") or []:
        if item.get("uuid") in kept:
            parent = _parent_device_name(item.get("name"))
            if parent:
                parents.add(parent)
    return parents


def _renamed_old_parent_devices(prev, cur):
    """被换名的分区原来所属的整盘名（改名前的旧名字）。

    盘本身没有 UUID（UUID 挂在分区上），所以“sdb 消失”必须靠它下面分区的 UUID
    是否仍在本次出现来判断，否则会把改名报成掉盘。
    """
    kept = _renamed_uuids(prev, cur)
    if not kept:
        return set()
    cur_names = set(_device_map(cur))
    parents = set()
    for item in prev.get("devices") or []:
        if item.get("uuid") in kept:
            parent = _parent_device_name(item.get("name"))
            if parent and parent not in cur_names:
                parents.add(parent)
    return parents


def _is_network_fs(fstype):
    fstype = (fstype or "").lower()
    return fstype.startswith("nfs") or fstype in ("cifs", "smb3", "smbfs", "fuse.sshfs", "glusterfs", "ceph")


def _device_still_present(device_path, devices):
    """挂载点消失后，判断对应块设备是否还在。"""
    device_path = device_path or ""
    if not device_path.startswith("/dev/"):
        return False
    base = os.path.basename(device_path)
    if base in {item.get("name") for item in devices}:
        return True
    if device_path.startswith("/dev/disk/by-uuid/"):
        return base in {item.get("uuid") for item in devices if item.get("uuid")}
    return False


def _check_mounts(prev, cur):
    """规则 1/2/3/7：挂载点消失、设备在但没挂载、文件系统变只读。"""
    findings = []
    prev_mounts = _mount_map(prev)
    current_mounts = _mount_map(cur)
    devices = cur.get("devices") or []
    for mount, old in prev_mounts.items():
        new = current_mounts.get(mount)
        device = old.get("device") or "未知设备"
        if new is None:
            if _is_network_fs(old.get("fstype")):
                findings.append(finding(
                    SEVERE, CATEGORY_UNMOUNTED,
                    "网络挂载 {}（{}）本次不可用，可能是存储端或网络中断，请确认后重新挂载。".format(mount, device),
                    mount,
                ))
            elif _device_still_present(device, devices):
                findings.append(finding(
                    SEVERE, CATEGORY_UNMOUNTED,
                    "挂载点 {}（{}）已消失，但块设备仍在，通常是掉盘只读重挂、卷未激活或人工卸载，请确认数据是否还能访问。".format(mount, device),
                    mount,
                ))
            else:
                findings.append(finding(
                    SEVERE, CATEGORY_MISSING,
                    "挂载点 {}（{}）已消失，且未发现对应块设备，疑似掉盘或分区丢失，请立即检查。".format(mount, device),
                    mount,
                ))
        elif not old.get("ro") and new.get("ro"):
            findings.append(finding(
                SEVERE, CATEGORY_READONLY,
                "文件系统 {} 由可读写（rw）变为只读（ro），内核可能在 I/O 错误后做了保护性重挂载，请尽快备份数据并检查磁盘健康。".format(mount),
                mount,
            ))
    return findings


def _check_devices(prev, cur):
    """规则 3/4/18：块设备消失、容量骤减、容量变化。"""
    findings = []
    if prev.get("devices_truncated") or cur.get("devices_truncated"):
        return findings
    if prev.get("source") != cur.get("source"):
        return findings
    prev_devices = _device_map(prev)
    cur_devices = _device_map(cur)
    renamed = _renamed_uuids(prev, cur)
    renamed_parents = _renamed_old_parent_devices(prev, cur)
    for name, old in prev_devices.items():
        if name in cur_devices or IGNORED_DEVICE_RE.match(name):
            continue
        if old.get("uuid") and old["uuid"] in renamed:
            continue
        if name in renamed_parents:
            continue
        if old.get("type") in ("lvm", "loop", "rom"):
            continue
        findings.append(finding(
            SEVERE, CATEGORY_DEVICE_LOST,
            "块设备 {}（{}，{}）在本次采集里消失，请确认是人为下线还是硬件掉盘。".format(
                name, old.get("type") or "未知类型", format_size_kb(old.get("size_kb"))),
        ))
    for name, old in prev_devices.items():
        new = cur_devices.get(name)
        if not new or old.get("type") in ("lvm", "loop", "rom"):
            continue
        old_size = old.get("size_kb") or 0
        new_size = new.get("size_kb") or 0
        if old_size <= 0 or new_size <= 0 or old_size == new_size:
            continue
        if new_size < old_size * 0.5:
            findings.append(finding(
                SEVERE, CATEGORY_CAPACITY,
                "块设备 {} 容量由 {} 变为 {}（不足一半），疑似分区表损坏或阵列成员丢失，请立即检查。".format(
                    name, format_size_kb(old_size), format_size_kb(new_size)),
            ))
        elif abs(new_size - old_size) > max(old_size * 0.05, 1024 * 1024):
            findings.append(finding(
                INFO, CATEGORY_CHANGE,
                "块设备 {} 容量由 {} 变为 {}（疑似扩容或分区调整），如为人为操作可忽略。".format(
                    name, format_size_kb(old_size), format_size_kb(new_size)),
            ))
    return findings


def _check_raid(prev, cur):
    """规则 5/6：软阵列降级、消失、成员丢失、正在重建。"""
    findings = []
    prev_raid = prev.get("raid") or {}
    for name, array in (cur.get("raid") or {}).items():
        old = prev_raid.get(name) or {}
        if array.get("degraded"):
            detail = "、".join(
                "[{}/{}] [{}]".format(total, active, flags)
                for total, active, flags in array.get("groups") or []
            ) or array.get("state") or "状态异常"
            text = "软阵列 {}（{}）处于降级状态：{}".format(name, array.get("level") or "未知级别", detail)
            if array.get("failed"):
                text += "，失效成员 {}".format("、".join(array["failed"]))
            missing = [item for item in old.get("members") or [] if item not in (array.get("members") or [])]
            if missing:
                text += "，成员 {} 已从阵列中消失".format("、".join(missing))
            if old.get("degraded"):
                text += "（上次巡检已发现，仍未恢复）"
            text += "，请尽快更换故障磁盘并等待重建完成。"
            findings.append(finding(SEVERE, CATEGORY_RAID, text))
        if array.get("rebuilding"):
            findings.append(finding(
                INFO, CATEGORY_CHANGE,
                "软阵列 {} 正在 {}（{}%），通常是成员故障或更换后的自动重建，重建期间请不要重启。".format(
                    name, array["rebuilding"]["op"], array["rebuilding"]["percent"]),
            ))
    for name in prev_raid:
        if name not in (cur.get("raid") or {}):
            findings.append(finding(
                SEVERE, CATEGORY_RAID,
                "软阵列 {} 本次在 /proc/mdstat 中消失，请确认阵列是否被停用或成员盘全部掉线。".format(name),
            ))
    return findings


def _check_counters(prev, cur):
    """规则 8/9/10：ext4 错误计数、I/O 错误与超时计数、设备内核状态。"""
    findings = []
    if not prev:
        return findings
    prev_devices = _device_map(prev)
    for device in cur.get("devices") or []:
        name = device.get("name")
        old = prev_devices.get(name) or {}
        for key, label in (("ioerr", "I/O 错误计数"), ("timeout", "I/O 超时计数")):
            before, after = old.get(key), device.get(key)
            if not isinstance(before, int) or not isinstance(after, int) or after <= before:
                continue
            delta = after - before
            severity = SEVERE if delta >= 10 else WARN
            findings.append(finding(
                severity, CATEGORY_IO_ERROR,
                "块设备 {} 的{}由 {} 增加到 {}（本次新增 {}），内核已记录到该磁盘的读写异常，"
                "建议检查数据完整性并安排更换。".format(name, label, before, after, delta),
            ))
        state = device.get("state")
        if not state or state == "running":
            continue
        if state in _BAD_DEVICE_STATES or old.get("state") != state:
            findings.append(finding(
                SEVERE, CATEGORY_DEV_STATE,
                "块设备 {} 的内核状态为 {}（正常应为 running），说明内核已把该磁盘标记为异常。".format(name, state),
            ))
    prev_fs = prev.get("fs_errors") or {}
    for name, after in (cur.get("fs_errors") or {}).items():
        before = prev_fs.get(name)
        if isinstance(before, int) and after > before:
            findings.append(finding(
                SEVERE, CATEGORY_FS_ERROR,
                "文件系统 {} 的内核错误计数由 {} 增加到 {}，说明 ext4 在读写时遇到了错误，"
                "请尽快备份数据并检查磁盘。".format(name, before, after),
            ))
    return findings


def _kernel_severity(text):
    lowered = (text or "").lower()
    return SEVERE if any(hint in lowered for hint in _KERNEL_SEVERE_HINTS) else WARN


def _check_kernel(prev, cur):
    """规则 11：只看基线之后新增的内核磁盘错误。"""
    findings = []
    kernel = cur.get("kernel") or {}
    recent = kernel.get("recent") or []
    if not recent:
        return findings
    prev_payload = _payload(prev)
    prev_kernel = prev_payload.get("kernel") or {}
    prev_last = prev_kernel.get("errors_last_at")
    prev_boot = prev_payload.get("uptime_seconds")
    cur_boot = cur.get("uptime_seconds")
    rebooted = isinstance(prev_boot, int) and isinstance(cur_boot, int) and cur_boot < prev_boot
    if not prev_kernel or rebooted:
        candidates = [
            item for item in recent
            if cur_boot is None or cur_boot - item.get("t", 0) <= _KERNEL_RECENT_SECONDS
        ]
        suffix = "（近 24 小时内）"
    elif prev_last is None:
        candidates = list(recent)
        suffix = ""
    else:
        candidates = [item for item in recent if item.get("t", 0) > prev_last]
        suffix = ""
    for item in candidates[:3]:
        findings.append(finding(
            _kernel_severity(item.get("text")),
            CATEGORY_KERNEL,
            "内核日志出现磁盘错误{}：{}".format(suffix, _shorten(item.get("text"))),
        ))
    return findings


def _check_df_errors(cur):
    """规则 12：df 读不出来的挂载点，通常意味着文件系统已经坏了。"""
    return [
        finding(
            SEVERE, CATEGORY_DF_ERROR,
            "df 读取挂载点时报错：{}。常见原因是文件系统损坏或存储失联，"
            "请尽快确认该挂载点上的数据是否还能访问。".format(_shorten(line)),
        )
        for line in (cur.get("df_errors") or [])[:3]
    ]


def _check_inode(cur):
    """规则 13：inode 使用率过高。"""
    findings = []
    visible = set(_mount_map(cur))
    for mount, usage in sorted((cur.get("inodes") or {}).items()):
        if mount not in visible or usage is None or usage <= DISK_AUDIT_INODE_THRESHOLD:
            continue
        findings.append(finding(
            WARN, CATEGORY_INODE,
            "挂载点 {} 的 inode 使用率已达 {:g}%（阈值 {:g}%），继续增长会导致无法创建新文件。".format(
                mount, usage, DISK_AUDIT_INODE_THRESHOLD),
            mount,
        ))
    return findings


def _check_growth(prev_row, cur):
    """规则 15/16/17：日均增长超标、即将写满、异常下降。"""
    if not prev_row:
        return []
    days = (prev_row.get("age_hours") or 0) / 24.0
    if days <= 0:
        return []
    prev_fs = _filesystem_map(_payload(prev_row))
    findings = []
    for mount, now_row in sorted(_filesystem_map(cur).items()):
        old = prev_fs.get(mount)
        if not old:
            continue
        old_used, now_used = old.get("used_kb"), now_row.get("used_kb")
        if not isinstance(old_used, int) or not isinstance(now_used, int):
            continue
        delta_gb = (now_used - old_used) / 1024.0 / 1024.0
        daily_gb = delta_gb / days
        size_gb = (now_row.get("total_kb") or 0) / 1024.0 / 1024.0
        if daily_gb <= -DISK_AUDIT_SHRINK_GB_PER_DAY:
            findings.append(finding(
                WARN, CATEGORY_SHRINK,
                "挂载点 {} 近 {:.1f} 天减少了 {:.1f} GB（日均 {:.1f} GB），"
                "请确认是正常清理还是数据丢失。".format(mount, days, abs(delta_gb), abs(daily_gb)),
                mount,
            ))
            continue
        if daily_gb <= 0:
            continue
        over_absolute = size_gb >= DISK_AUDIT_SMALL_FS_GB and daily_gb > DISK_AUDIT_GROWTH_GB_PER_DAY
        over_percent = size_gb > 0 and (daily_gb / size_gb * 100.0) > DISK_AUDIT_GROWTH_PERCENT_PER_DAY
        avail_gb = (now_row.get("avail_kb") or 0) / 1024.0 / 1024.0
        days_to_full = avail_gb / daily_gb if avail_gb > 0 else None
        will_fill = days_to_full is not None and days_to_full <= DISK_AUDIT_FULL_WARN_DAYS
        if not over_absolute and not over_percent and not will_fill:
            continue
        base = "挂载点 {} 近 {:.1f} 天增长 {:.1f} GB（日均 {:.1f} GB，容量 {}，当前使用率 {:g}%）".format(
            mount, days, delta_gb, daily_gb, format_size_kb(now_row.get("total_kb")),
            now_row.get("usage") or 0)
        if over_absolute or over_percent:
            tail = "增长明显高于预期"
            if will_fill:
                tail += "，按当前速度" + _days_text(days_to_full)
            findings.append(finding(
                WARN, CATEGORY_GROWTH,
                base + "，" + tail + "，请确认是否有日志、备份或临时文件异常增长。", mount,
            ))
        else:
            findings.append(finding(
                WARN, CATEGORY_FULL,
                base + "，按当前速度" + _days_text(days_to_full) + "，请提前清理或扩容。", mount,
            ))
    return findings


def _check_burst(recent_row, cur):
    """规则 14：短窗口内突增。"""
    if not recent_row:
        return []
    hours = recent_row.get("age_hours") or 0
    if hours <= 0 or hours > _BURST_MAX_HOURS:
        return []
    prev_fs = _filesystem_map(_payload(recent_row))
    findings = []
    for mount, now_row in sorted(_filesystem_map(cur).items()):
        old = prev_fs.get(mount)
        if not old:
            continue
        old_used, now_used = old.get("used_kb"), now_row.get("used_kb")
        if not isinstance(old_used, int) or not isinstance(now_used, int):
            continue
        delta_gb = (now_used - old_used) / 1024.0 / 1024.0
        if delta_gb <= DISK_AUDIT_BURST_GB:
            continue
        findings.append(finding(
            WARN, CATEGORY_BURST,
            "挂载点 {} 在 {:.0f} 分钟内增长 {:.1f} GB（阈值 {:g} GB），"
            "疑似有大批量写入或日志暴涨，请确认是否为正常业务。".format(
                mount, hours * 60, delta_gb, DISK_AUDIT_BURST_GB),
            mount,
        ))
    return findings


def _check_additions(prev, cur):
    """规则 19：新增挂载点与新增磁盘（提示，不算异常）。"""
    findings = []
    prev_mounts = _mount_map(prev)
    cur_mounts = _mount_map(cur)
    new_devices = []
    if not (prev.get("devices_truncated") or cur.get("devices_truncated")) and prev.get("source") == cur.get("source"):
        prev_names = set(_device_map(prev))
        renamed_parents = _renamed_parent_devices(prev, cur)
        new_devices = [
            item for item in cur.get("devices") or []
            if item["name"] not in prev_names and item.get("type") == "disk"
            and item["name"] not in renamed_parents
            and not IGNORED_DEVICE_RE.match(item["name"])
        ]
    consumed = set()
    for mount in sorted(set(cur_mounts) - set(prev_mounts)):
        entry = cur_mounts[mount]
        base = os.path.basename(entry.get("device") or "")
        extra = ""
        for device in new_devices:
            if base == device["name"] or base.startswith(device["name"]):
                consumed.add(device["name"])
                extra = "，容量 {}".format(format_size_kb(device.get("size_kb")))
        findings.append(finding(
            INFO, CATEGORY_CHANGE,
            "新增挂载点 {}（{}，{}）{}，如为人为操作可忽略。".format(
                mount, entry.get("device") or "未知设备", entry.get("fstype") or "未知类型", extra),
            mount,
        ))
    for device in new_devices:
        if device["name"] in consumed:
            continue
        findings.append(finding(
            INFO, CATEGORY_CHANGE,
            "新增块设备 {}（{}，{}），如为人为操作可忽略。".format(
                device["name"], format_size_kb(device.get("size_kb")), device.get("type")),
        ))
    return findings


def _sort_findings(findings):
    order = {SEVERE: 0, WARN: 1, INFO: 2}
    return sorted(findings, key=lambda item: order.get(item.get("severity"), 3))


def _first_run_text(cur):
    counts = cur.get("counts") or {}
    return (
        "首次采集磁盘基线：数据挂载点 {} 个、物理磁盘 {} 块，已记录，"
        "下次巡检开始比对掉盘、磁盘损坏与容量增长。".format(
            counts.get("mounts", len(_mount_map(cur))), counts.get("disks", 0))
    )


def compare_disk(baselines, current, error=None):
    """把当前快照与历史基线比对，返回 finding 列表。

    baselines: {"prev_day": row|None, "prev_recent": row|None, "last_any": row|None}
    current:   build_snapshot 得到的 payload，采集失败时为 None
    """
    baselines = baselines or {}
    prev_day = baselines.get("prev_day")
    prev_recent = baselines.get("prev_recent")
    if not current:
        reason = error or "未能采集磁盘明细"
        return [finding(INFO, CATEGORY_CHECK, "本次未做磁盘比对：{}。".format(reason))]
    day_payload = _payload(prev_day)
    if not day_payload and not _payload(prev_recent):
        last_any = baselines.get("last_any")
        age = (last_any or {}).get("age_hours")
        if isinstance(age, (int, float)) and age > 48:
            return [finding(
                INFO, CATEGORY_CHECK,
                "最近一次磁盘基线是 {:.0f} 小时前（超过 48 小时），本次只记录新基线，"
                "不做掉盘与增长趋势判断。".format(age),
            )]
        # 只有数据库里完全没有历史记录才是真正首次采集。已有快照但距离现在
        # 不足 recent_min_minutes 时不做趋势比较，也不应再次显示“首次采集”。
        if last_any:
            return []
        return [finding(INFO, CATEGORY_CHECK, _first_run_text(current))]

    findings = []
    compare_row = prev_day if day_payload else prev_recent
    compare_payload = day_payload or _payload(prev_recent)

    findings = []
    findings += _check_mounts(compare_payload, current)
    findings += _check_devices(compare_payload, current)
    findings += _check_raid(compare_payload, current)
    findings += _check_growth(compare_row, current)
    findings += _check_additions(compare_payload, current)
    findings += _check_counters(_payload(prev_recent) or compare_payload, current)
    findings += _check_kernel(prev_recent or prev_day, current)
    findings += _check_burst(prev_recent, current)
    findings += _check_df_errors(current)
    findings += _check_inode(current)
    return _sort_findings(findings)
