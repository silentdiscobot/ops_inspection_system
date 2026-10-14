# -*- coding: utf-8 -*-
import os
from typing import Any, Dict, List, Tuple

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.worksheet.page import PageMargins

from config import CPU_THRESHOLD, DISK_THRESHOLD, MEM_THRESHOLD, REPORT_DIR
from report_utils import (
    build_abnormal_lines,
    build_disk_change_lines,
    build_report_filename,
    build_row_issue_labels,
)


FONT_NAME = "Microsoft YaHei"
NAVY = "123B57"
BLUE = "167DB3"
BLUE_DARK = "0E628F"
BLUE_PALE = "EAF6FD"
BLUE_SOFT = "F5FAFD"
TEXT = "263B4D"
MUTED = "708497"
BORDER_COLOR = "D9E7F0"
GREEN = "159A73"
GREEN_PALE = "E8F7F1"
AMBER = "D98B13"
AMBER_PALE = "FFF5DE"
RED = "D94C58"
RED_PALE = "FDECEF"
WHITE = "FFFFFF"


def _fill(color: str) -> PatternFill:
    return PatternFill(fill_type="solid", fgColor=color)


def _font(size: float = 10, color: str = TEXT, bold: bool = False) -> Font:
    return Font(name=FONT_NAME, size=size, color=color, bold=bold)


def _thin_border(color: str = BORDER_COLOR) -> Border:
    side = Side(style="thin", color=color)
    return Border(left=side, right=side, top=side, bottom=side)


def _style_range(ws, row: int, start_col: int = 1, end_col: int = 8,
                 fill: str = WHITE, border: Border = None) -> None:
    for col in range(start_col, end_col + 1):
        cell = ws.cell(row, col)
        cell.fill = _fill(fill)
        cell.border = border or _thin_border()


def _section_band(ws, row: int, title: str, note: str = "") -> None:
    _style_range(ws, row, fill=BLUE_PALE)
    ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=8)
    cell = ws.cell(row, 1)
    cell.value = f"{title}    {note}" if note else title
    cell.font = _font(11, BLUE_DARK, True)
    cell.alignment = Alignment(horizontal="left", vertical="center")
    ws.row_dimensions[row].height = 25


def _table_header(ws, row: int, labels: List[Tuple[str, int, int]]) -> None:
    _style_range(ws, row, fill=BLUE_DARK)
    for label, start_col, end_col in labels:
        if end_col > start_col:
            ws.merge_cells(
                start_row=row, start_column=start_col,
                end_row=row, end_column=end_col,
            )
        cell = ws.cell(row, start_col)
        cell.value = label
        cell.font = _font(9.5, WHITE, True)
        cell.alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[row].height = 24


def _status_style(status: str) -> Tuple[str, str]:
    if status == "正常":
        return GREEN, GREEN_PALE
    if status == "连接失败":
        return RED, RED_PALE
    return AMBER, AMBER_PALE


def _split_issue_line(line: str) -> Tuple[str, str]:
    target, separator, detail = str(line).partition(":")
    if not separator:
        target, separator, detail = str(line).partition("：")
    return (target.strip(), detail.strip()) if separator else ("—", str(line).strip())


def _safe_metric(row: Dict[str, Any], key: str) -> Any:
    if not row.get("ok"):
        return None
    try:
        return float(row.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def generate_excel_report(
    project_name: str,
    inspector: str,
    date_str: str,
    rows: List[Dict[str, Any]],
    proxy_results: List[Dict[str, Any]] = None,
    check_cpu: bool = True,
    check_mem: bool = True,
    check_disk: bool = True,
    task_name: str = None,
    cpu_threshold: float = CPU_THRESHOLD,
    mem_threshold: float = MEM_THRESHOLD,
    disk_threshold: float = DISK_THRESHOLD,
) -> str:
    proxy_results = proxy_results or []
    report_name = (task_name or project_name or "巡检报告").strip()

    status_rows = []
    success_count = warning_count = fail_count = 0
    for row in rows:
        if not row.get("ok", False):
            status = "连接失败"
            fail_count += 1
        else:
            issues = build_row_issue_labels(
                row, check_cpu, check_mem, check_disk,
                cpu_threshold, mem_threshold, disk_threshold,
            )
            if issues:
                status = f"告警（{'、'.join(issues)}）"
                warning_count += 1
            else:
                status = "正常"
                success_count += 1
        status_rows.append((row, status))

    threshold_labels = []
    if check_cpu:
        threshold_labels.append(f"CPU ≥ {cpu_threshold:g}%")
    if check_mem:
        threshold_labels.append(f"内存 ≥ {mem_threshold:g}%")
    if check_disk:
        threshold_labels.append(f"磁盘 ≥ {disk_threshold:g}%")
    threshold_text = "  ·  ".join(threshold_labels) or "未启用资源巡检"

    wb = Workbook()
    wb.properties.title = report_name
    wb.properties.creator = inspector or report_name
    wb.properties.subject = "服务器巡检报告"
    ws = wb.active
    ws.title = "服务器巡检报告"
    ws.sheet_view.showGridLines = False
    ws.sheet_view.zoomScale = 90
    ws.sheet_properties.pageSetUpPr.fitToPage = True

    column_widths = {
        "A": 7, "B": 18, "C": 20, "D": 14,
        "E": 14, "F": 14, "G": 17, "H": 31,
    }
    for col, width in column_widths.items():
        ws.column_dimensions[col].width = width

    # 标题区
    ws.merge_cells("A1:H1")
    ws["A1"] = "服务器巡检报告"
    ws["A1"].font = _font(22, NAVY, True)
    ws["A1"].alignment = Alignment(horizontal="left", vertical="bottom")
    ws.row_dimensions[1].height = 38

    ws.merge_cells("A2:H2")
    ws["A2"] = f"{report_name}  /  自动巡检结果与异常摘要"
    ws["A2"].font = _font(9.5, MUTED)
    ws["A2"].alignment = Alignment(horizontal="left", vertical="top")
    ws.row_dimensions[2].height = 21

    for col in range(1, 9):
        ws.cell(3, col).fill = _fill(BLUE)
    ws.row_dimensions[3].height = 4

    # 基本信息
    info_items = [
        ("项目", project_name or "—"),
        ("巡检人", inspector or "—"),
        ("巡检时间", date_str or "—"),
        ("告警阈值", threshold_text),
    ]
    info_ranges = [(1, 2), (3, 4), (5, 6), (7, 8)]
    _style_range(ws, 5, fill=BLUE_SOFT)
    for (label, value), (start_col, end_col) in zip(info_items, info_ranges):
        ws.merge_cells(start_row=5, start_column=start_col, end_row=5, end_column=end_col)
        cell = ws.cell(5, start_col)
        cell.value = f"{label}  {value}"
        cell.font = _font(9.5, TEXT, label != "告警阈值")
        cell.alignment = Alignment(horizontal="left", vertical="center", shrink_to_fit=True)
    ws.row_dimensions[5].height = 26

    # 四项概览卡片
    cards = [
        ("巡检总数", len(rows), BLUE, BLUE_PALE),
        ("正常", success_count, GREEN, GREEN_PALE),
        ("告警", warning_count, AMBER, AMBER_PALE),
        ("失败", fail_count, RED, RED_PALE),
    ]
    for index, (label, value, color, background) in enumerate(cards):
        start_col = index * 2 + 1
        end_col = start_col + 1
        for row_number in (7, 8):
            _style_range(ws, row_number, start_col, end_col, background)
            ws.merge_cells(
                start_row=row_number, start_column=start_col,
                end_row=row_number, end_column=end_col,
            )
        ws.cell(7, start_col).value = label
        ws.cell(7, start_col).font = _font(9.5, color, True)
        ws.cell(7, start_col).alignment = Alignment(horizontal="center", vertical="center")
        ws.cell(8, start_col).value = f"{value} 台"
        ws.cell(8, start_col).font = _font(18, color, True)
        ws.cell(8, start_col).alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[7].height = 23
    ws.row_dimensions[8].height = 31

    # 服务器巡检明细
    current_row = 10
    _section_band(ws, current_row, "01  服务器巡检明细", f"共 {len(rows)} 台")
    current_row += 1

    headers = [("序号", 1, 1), ("服务器 IP", 2, 2), ("系统运行时间", 3, 3)]
    metric_columns = []
    next_col = 4
    if check_cpu:
        headers.append(("CPU 使用率", next_col, next_col))
        metric_columns.append((next_col, "cpu", cpu_threshold))
        next_col += 1
    if check_mem:
        headers.append(("内存使用率", next_col, next_col))
        metric_columns.append((next_col, "mem", mem_threshold))
        next_col += 1
    if check_disk:
        headers.append(("磁盘使用率", next_col, next_col))
        metric_columns.append((next_col, "disk", disk_threshold))
        next_col += 1
    status_col = next_col
    headers.append(("巡检状态", status_col, 8))
    _table_header(ws, current_row, headers)
    detail_header_row = current_row

    if not status_rows:
        current_row += 1
        _style_range(ws, current_row, fill=WHITE)
        ws.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=8)
        ws.cell(current_row, 1).value = "当前没有可展示的巡检数据"
        ws.cell(current_row, 1).font = _font(10, MUTED)
        ws.cell(current_row, 1).alignment = Alignment(horizontal="center", vertical="center")
        ws.row_dimensions[current_row].height = 29
    else:
        for index, (row_data, status) in enumerate(status_rows, start=1):
            current_row += 1
            base_fill = WHITE if index % 2 else BLUE_SOFT
            _style_range(ws, current_row, fill=base_fill)
            values = [index, row_data.get("ip", ""), row_data.get("uptime", "未知")]
            for _, key, _ in metric_columns:
                values.append(_safe_metric(row_data, key))
            for col, value in enumerate(values, start=1):
                cell = ws.cell(current_row, col)
                cell.value = "—" if value is None else value
                cell.font = _font(9.5, TEXT, col == 2)
                cell.alignment = Alignment(
                    horizontal="left" if col in (2, 3) else "center",
                    vertical="center", wrap_text=col == 3,
                )

            for col, key, threshold in metric_columns:
                cell = ws.cell(current_row, col)
                if cell.value != "—":
                    cell.number_format = '0.0"%"'
                    if float(cell.value) >= float(threshold):
                        cell.font = _font(9.5, AMBER, True)
                        cell.fill = _fill(AMBER_PALE)

            status_base = "正常" if status == "正常" else ("连接失败" if status == "连接失败" else "告警")
            color, background = _status_style(status_base)
            if status_col < 8:
                ws.merge_cells(
                    start_row=current_row, start_column=status_col,
                    end_row=current_row, end_column=8,
                )
            status_cell = ws.cell(current_row, status_col)
            status_cell.value = status
            status_cell.font = _font(9.5, color, True)
            status_cell.fill = _fill(background)
            status_cell.alignment = Alignment(horizontal="center", vertical="center", shrink_to_fit=True)
            ws.row_dimensions[current_row].height = 25

    # 网关代理检测
    if proxy_results:
        current_row += 2
        proxy_success_count = sum(1 for result in proxy_results if result.get("success"))
        proxy_fail_count = len(proxy_results) - proxy_success_count
        _section_band(
            ws, current_row, "02  网关代理检测",
            f"正常 {proxy_success_count} 台  ·  异常 {proxy_fail_count} 台",
        )
        current_row += 1
        _table_header(ws, current_row, [
            ("序号", 1, 1), ("服务器 IP", 2, 3),
            ("代理状态", 4, 5), ("检测结果", 6, 8),
        ])
        for index, result in enumerate(proxy_results, start=1):
            current_row += 1
            base_fill = WHITE if index % 2 else BLUE_SOFT
            _style_range(ws, current_row, fill=base_fill)
            ws.merge_cells(start_row=current_row, start_column=2, end_row=current_row, end_column=3)
            ws.merge_cells(start_row=current_row, start_column=4, end_row=current_row, end_column=5)
            ws.merge_cells(start_row=current_row, start_column=6, end_row=current_row, end_column=8)

            if result.get("success"):
                proxy_status = "正常"
            elif result.get("error"):
                proxy_status = "连接失败"
            else:
                proxy_status = "异常"
            output = result.get("output", "")
            detail = output or result.get("error", "") or "未包含成功关键词"

            ws.cell(current_row, 1).value = index
            ws.cell(current_row, 2).value = result.get("ip", "")
            ws.cell(current_row, 4).value = proxy_status
            ws.cell(current_row, 6).value = detail
            for col in (1, 2, 4, 6):
                cell = ws.cell(current_row, col)
                cell.font = _font(9.2, TEXT, col == 2)
                cell.alignment = Alignment(
                    horizontal="left" if col in (2, 6) else "center",
                    vertical="center", wrap_text=col == 6,
                )
            color, background = _status_style(proxy_status)
            ws.cell(current_row, 4).font = _font(9.2, color, True)
            ws.cell(current_row, 4).fill = _fill(background)
            ws.row_dimensions[current_row].height = 27

    abnormal_lines = build_abnormal_lines(
        rows, check_cpu=check_cpu, check_mem=check_mem, check_disk=check_disk,
        proxy_results=proxy_results, cpu_threshold=cpu_threshold,
        mem_threshold=mem_threshold, disk_threshold=disk_threshold,
    )

    # 异常问题详情
    current_row += 2
    section_number = "03" if proxy_results else "02"
    _section_band(ws, current_row, f"{section_number}  异常问题详情", f"共 {len(abnormal_lines)} 项")
    current_row += 1
    _table_header(ws, current_row, [
        ("序号", 1, 1), ("影响对象", 2, 3), ("问题描述", 4, 8),
    ])
    if abnormal_lines:
        for index, line in enumerate(abnormal_lines, start=1):
            current_row += 1
            target, detail = _split_issue_line(line)
            _style_range(ws, current_row, fill=RED_PALE)
            ws.merge_cells(start_row=current_row, start_column=2, end_row=current_row, end_column=3)
            ws.merge_cells(start_row=current_row, start_column=4, end_row=current_row, end_column=8)
            ws.cell(current_row, 1).value = index
            ws.cell(current_row, 2).value = target
            ws.cell(current_row, 4).value = detail
            ws.cell(current_row, 1).font = _font(9.2, RED, True)
            ws.cell(current_row, 2).font = _font(9.2, TEXT, True)
            ws.cell(current_row, 4).font = _font(9.2, TEXT)
            ws.cell(current_row, 1).alignment = Alignment(horizontal="center", vertical="center")
            ws.cell(current_row, 2).alignment = Alignment(horizontal="left", vertical="center")
            ws.cell(current_row, 4).alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
            ws.row_dimensions[current_row].height = 31
    else:
        current_row += 1
        _style_range(ws, current_row, fill=GREEN_PALE)
        ws.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=8)
        ws.cell(current_row, 1).value = "✓  本次巡检未发现异常问题"
        ws.cell(current_row, 1).font = _font(10, GREEN, True)
        ws.cell(current_row, 1).alignment = Alignment(horizontal="center", vertical="center")
        ws.row_dimensions[current_row].height = 29

    # 磁盘变更记录
    disk_change_lines = build_disk_change_lines(rows, check_disk=check_disk)
    if disk_change_lines:
        current_row += 2
        section_index = 4 if proxy_results else 3
        _section_band(ws, current_row, f"{section_index:02d}  磁盘变更记录", f"共 {len(disk_change_lines)} 项")
        current_row += 1
        _table_header(ws, current_row, [
            ("序号", 1, 1), ("影响对象", 2, 3), ("变更内容", 4, 8),
        ])
        for index, line in enumerate(disk_change_lines, start=1):
            current_row += 1
            target, detail = _split_issue_line(line)
            _style_range(ws, current_row, fill=BLUE_SOFT)
            ws.merge_cells(start_row=current_row, start_column=2, end_row=current_row, end_column=3)
            ws.merge_cells(start_row=current_row, start_column=4, end_row=current_row, end_column=8)
            ws.cell(current_row, 1).value = index
            ws.cell(current_row, 2).value = target
            ws.cell(current_row, 4).value = detail
            ws.cell(current_row, 1).font = _font(9.2, BLUE, True)
            ws.cell(current_row, 2).font = _font(9.2, TEXT, True)
            ws.cell(current_row, 4).font = _font(9.2, TEXT)
            ws.cell(current_row, 1).alignment = Alignment(horizontal="center", vertical="center")
            ws.cell(current_row, 2).alignment = Alignment(horizontal="left", vertical="center")
            ws.cell(current_row, 4).alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
            ws.row_dimensions[current_row].height = 29

    # 签字区
    current_row += 3
    for col in range(1, 9):
        ws.cell(current_row, col).font = _font(9.5, MUTED)
        ws.cell(current_row, col).alignment = Alignment(vertical="bottom")
    ws.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=2)
    ws.merge_cells(start_row=current_row, start_column=4, end_row=current_row, end_column=5)
    ws.merge_cells(start_row=current_row, start_column=7, end_row=current_row, end_column=8)
    ws.cell(current_row, 1).value = "巡检人：________________"
    ws.cell(current_row, 4).value = "审核人：________________"
    ws.cell(current_row, 7).value = "日期：__________________"
    ws.row_dimensions[current_row].height = 31

    # 打印与视图设置
    ws.print_title_rows = f"{detail_header_row}:{detail_header_row}"
    ws.print_area = f"A1:H{current_row}"
    ws.page_setup.orientation = "landscape"
    ws.page_setup.paperSize = ws.PAPERSIZE_A4
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.page_margins = PageMargins(left=0.28, right=0.28, top=0.38, bottom=0.45, header=0.15, footer=0.2)
    ws.oddFooter.center.text = "第 &P 页 / 共 &N 页"
    ws.oddFooter.center.size = 8
    ws.oddFooter.center.color = MUTED
    ws.oddFooter.right.text = report_name
    ws.oddFooter.right.size = 8
    ws.oddFooter.right.color = MUTED

    os.makedirs(REPORT_DIR, exist_ok=True)
    filename = build_report_filename(task_name or project_name, "xlsx")
    output_path = os.path.join(REPORT_DIR, filename)
    wb.save(output_path)
    return output_path
