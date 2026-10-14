# -*- coding: utf-8 -*-
import re
from datetime import datetime

from config import CPU_THRESHOLD, DISK_THRESHOLD, MEM_THRESHOLD

# 磁盘巡检里这些级别算异常，其余（提示）只进"磁盘变更记录"小节。
ALERT_SEVERITIES = ("severe", "warn")


def build_row_issue_labels(row, check_cpu=True, check_mem=True, check_disk=True,
                           cpu_threshold=CPU_THRESHOLD, mem_threshold=MEM_THRESHOLD,
                           disk_threshold=DISK_THRESHOLD):
    """主表状态列的统一口径，Excel/PDF 必须共用。"""
    issues = []
    if check_cpu and row.get("cpu", 0) >= cpu_threshold:
        issues.append("CPU")
    if check_mem and row.get("mem", 0) >= mem_threshold:
        issues.append("内存")
    if check_disk and row.get("disk", 0) >= disk_threshold:
        issues.append("磁盘")
    findings = (row.get('resource_findings') or []) + (row.get('disk_findings') or [])
    if any(item.get('severity') in ALERT_SEVERITIES for item in findings):
        issues.append("资源配置" if row.get('resource_findings') else "磁盘检查")
    return list(dict.fromkeys(issues))


def build_report_filename(task_name: str, extension: str, now=None) -> str:
    """Build a filesystem-safe report name from the inspection task name."""
    safe_name = re.sub(r'[\\/:*?"<>|\x00-\x1f]+', '_', (task_name or '').strip())
    safe_name = re.sub(r'\s+', '_', safe_name).strip(' ._')[:80] or '巡检报告'
    timestamp = (now or datetime.now()).strftime('%Y%m%d_%H%M%S')
    return f"{safe_name}_{timestamp}.{extension.lstrip('.').lower()}"


def build_abnormal_lines(rows, check_cpu=True, check_mem=True, check_disk=True,
                         proxy_results=None, cpu_threshold=CPU_THRESHOLD,
                         mem_threshold=MEM_THRESHOLD, disk_threshold=DISK_THRESHOLD):
    """汇总"异常问题详情"里的每一行，Excel 与 PDF 报告共用同一套口径。"""
    abnormal_lines = []
    for row in rows:
        ip = row.get('ip', '未知IP')
        reasons = []
        if not row.get("ok"):
            reasons.append(f'连接失败: {row.get("error", "未知错误")}')
        else:
            if check_cpu and row.get("cpu", 0) >= cpu_threshold:
                reasons.append(f'CPU使用率过高 {row["cpu"]}%')
            if check_mem and row.get("mem", 0) >= mem_threshold:
                reasons.append(f'内存使用率过高 {row["mem"]}%')

        if reasons:
            abnormal_lines.append(f"{ip}: {'; '.join(reasons)}")
        if row.get("ok") and check_disk:
            disk_issues = [p for p in row.get("disk_partitions", []) if p.get("usage", 0) >= disk_threshold]
            if disk_issues:
                for partition in disk_issues:
                    abnormal_lines.append(
                        f'{ip}: 磁盘使用率过高 - 文件系统 {partition.get("filesystem", "未知")}, '
                        f'挂载点 {partition.get("mount", "未知")}, 使用率 {partition.get("usage", 0)}%'
                    )
            elif row.get("disk", 0) >= disk_threshold:
                abnormal_lines.append(f'{ip}: 磁盘最高使用率过高 {row["disk"]}%')
            for finding in row.get("disk_findings") or []:
                if finding.get("severity") in ALERT_SEVERITIES:
                    abnormal_lines.append(
                        f'{ip}: 【{finding.get("category", "磁盘检查")}】{finding.get("text", "")}'
                    )
        if row.get("ok"):
            for finding in row.get("resource_findings") or []:
                if finding.get("severity") in ALERT_SEVERITIES:
                    abnormal_lines.append(
                        f'{ip}: 【{finding.get("category", "资源配置变更")}】{finding.get("text", "")}'
                    )

    # 添加网关代理异常
    if proxy_results:
        for result in proxy_results:
            if not result.get("success"):
                ip = result.get("ip", "未知IP")
                if result.get("error"):
                    abnormal_lines.append(f"{ip}: 网关代理连接失败 - {result['error']}")
                else:
                    abnormal_lines.append(f"{ip}: 网关代理异常 - 未检测到成功关键词")
    return abnormal_lines


def build_disk_change_lines(rows, check_disk=True):
    """磁盘巡检的提示类结论：新增挂载点、扩容、首次建基线等。"""
    if not check_disk:
        return []
    lines = []
    for row in rows:
        ip = row.get('ip', '未知IP')
        for finding in row.get("disk_findings") or []:
            if finding.get("severity") not in ALERT_SEVERITIES:
                lines.append(
                    f'{ip}: 【{finding.get("category", "磁盘检查")}】{finding.get("text", "")}'
                )
    return lines
