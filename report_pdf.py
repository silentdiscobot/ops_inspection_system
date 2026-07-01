# -*- coding: utf-8 -*-
import os
from typing import List, Dict, Any
from config import REPORT_DIR, CPU_THRESHOLD, MEM_THRESHOLD, DISK_THRESHOLD
from report_utils import build_report_filename

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

def find_chinese_font():
    """查找系统中可用的中文字体"""
    font_paths = [
        # Windows 常见字体路径
        'C:/Windows/Fonts/simsun.ttc',
        'C:/Windows/Fonts/simhei.ttf',
        'C:/Windows/Fonts/msyh.ttf',
        'C:/Windows/Fonts/msyhbd.ttf',
        'C:/Windows/Fonts/simkai.ttf',
        # macOS 常见字体路径
        '/Library/Fonts/Songti.ttc',
        '/Library/Fonts/Heiti.ttc',
        '/Library/Fonts/Hiragino Sans GB.ttc',
        # Linux wqy-zenhei 可能的路径
        '/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc',
        '/usr/share/fonts/truetype/wqy/wqy-microhei.ttc',
        '/usr/share/fonts/opentype/wqy/wqy-zenhei.ttc',
        '/usr/share/fonts/wqy-zenhei/wqy-zenhei.ttc',
        '/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc',
        '/usr/share/fonts/truetype/noto/NotoSerifCJK-Regular.ttc',
        # 扫描常见字体目录
        '/usr/share/fonts/truetype/freefont/FreeSans.ttf',
        '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
        '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
        # Docker 环境中 fonts-wqy-zenhei 的安装路径
        '/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc',
        '/usr/share/fonts/truetype/wqy/wqy-zenhei/wqy-zenhei.ttc',
    ]

    for path in font_paths:
        if os.path.exists(path):
            return path
    
    # 尝试使用 fc-list 命令查找字体
    try:
        import subprocess
        result = subprocess.run(['fc-list', '--format=%{file}\n'], 
                                capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line:
                # 优先查找中文字体
                if ('wqy' in line.lower() or 'zenhei' in line.lower() or 
                    'songti' in line.lower() or 'heiti' in line.lower() or
                    'noto' in line.lower() or 'cjk' in line.lower()):
                    if os.path.exists(line):
                        return line
                # 查找通用字体作为备选
                elif ('dejavu' in line.lower() or 'freefont' in line.lower()):
                    if os.path.exists(line):
                        return line
    except Exception:
        pass
    
    return None

def generate_pdf_report(project_name: str, inspector: str, date_str: str, rows: List[Dict[str, Any]], proxy_results: List[Dict[str, Any]] = None, check_cpu: bool = True, check_mem: bool = True, check_disk: bool = True, task_name: str = None) -> str:
    """生成PDF格式的巡检报告"""
    if not PDF_AVAILABLE:
        raise ImportError("需要安装 reportlab 库来生成 PDF 报告")
    
    # 注册中文字体
    font_path = find_chinese_font()
    if font_path:
        # 使用 TrueType 字体
        font_name = 'ChineseFont'
        font_bold_name = 'ChineseFont-Bold'
        try:
            # .ttc 是字体集合，需要指定 subfontIndex
            if font_path.lower().endswith('.ttc'):
                pdfmetrics.registerFont(TTFont(font_name, font_path, subfontIndex=0))
            else:
                pdfmetrics.registerFont(TTFont(font_name, font_path))
            # 尝试注册粗体版本
            if 'msyh' in font_path.lower():
                # 微软雅黑有单独的粗体文件
                bold_path = font_path.replace('.ttf', 'bd.ttf')
                if os.path.exists(bold_path):
                    pdfmetrics.registerFont(TTFont(font_bold_name, bold_path))
                else:
                    font_bold_name = font_name
            else:
                font_bold_name = font_name
        except Exception:
            # 如果TTFont加载失败，尝试用不同的方式
            font_name = 'Helvetica'
            font_bold_name = 'Helvetica-Bold'
    else:
        font_name = 'Helvetica'
        font_bold_name = 'Helvetica-Bold'
    
    os.makedirs(REPORT_DIR, exist_ok=True)
    fname = build_report_filename(task_name or project_name, "pdf")
    out_path = os.path.join(REPORT_DIR, fname)
    
    doc = SimpleDocTemplate(out_path, pagesize=A4, leftMargin=20*mm, rightMargin=20*mm, topMargin=20*mm, bottomMargin=20*mm)
    elements = []
    styles = getSampleStyleSheet()
    
    # 标题样式
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        fontSize=18,
        bold=True,
        alignment=1,
        textColor=colors.darkblue,
        fontName=font_name
    )
    
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['BodyText'],
        fontSize=10,
        alignment=1,
        textColor=colors.grey,
        fontName=font_name
    )
    
    heading_style = ParagraphStyle(
        'Heading',
        parent=styles['Heading2'],
        fontSize=12,
        bold=True,
        textColor=colors.darkblue,
        spaceAfter=10,
        fontName=font_name
    )
    
    normal_style = ParagraphStyle(
        'Normal',
        parent=styles['BodyText'],
        fontSize=10,
        leading=14,
        fontName=font_name
    )
    
    bold_style = ParagraphStyle(
        'Bold',
        parent=styles['BodyText'],
        fontSize=10,
        bold=True,
        leading=14,
        fontName=font_name
    )
    
    red_style = ParagraphStyle(
        'Red',
        parent=styles['BodyText'],
        fontSize=10,
        leading=14,
        textColor=colors.red,
        fontName=font_name
    )
    
    green_style = ParagraphStyle(
        'Green',
        parent=styles['BodyText'],
        fontSize=10,
        leading=14,
        textColor=colors.green,
        fontName=font_name
    )
    
    # ========== 标题 ==========
    elements.append(Paragraph("服务器巡检报告", title_style))
    elements.append(Paragraph("Server Inspection Report", subtitle_style))
    elements.append(Spacer(1, 20))
    
    # ========== 基本信息 ==========
    elements.append(Paragraph("基本信息", heading_style))
    
    info_data = [
        ["项目名称", project_name],
        ["巡检人", inspector],
        ["巡检时间", date_str],
        ["检查数量", f"{len(rows)} 台"]
    ]
    
    # 基本信息表格占满可用宽度
    info_page_width = A4[0] - 40*mm
    info_table = Table(info_data, colWidths=[info_page_width * 0.35, info_page_width * 0.65])
    info_table.setStyle(TableStyle([
        ('FONT', (0, 0), (-1, -1), font_name, 10),
        ('FONT', (0, 0), (0, -1), font_name, 10),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 15))
    
    # ========== 服务器巡检记录 ==========
    elements.append(Paragraph("服务器巡检记录", heading_style))
    
    # 动态生成表头
    headers = ["序号", "服务器IP", "系统运行时间"]
    if check_cpu:
        headers.append("CPU使用率")
    if check_mem:
        headers.append("内存使用率")
    if check_disk:
        headers.append("磁盘使用率")
    headers.append("状态")
    table_data = [headers]
    
    success_count = 0
    fail_count = 0
    warning_count = 0
    
    for idx, row in enumerate(rows, start=1):
        is_ok = row.get("ok", False)
        
        if not is_ok:
            status = "连接失败"
            status_color = colors.red
            fail_count += 1
        else:
            issues = []
            if check_cpu and row.get("cpu", 0) > CPU_THRESHOLD:
                issues.append("CPU")
            if check_mem and row.get("mem", 0) > MEM_THRESHOLD:
                issues.append("内存")
            if check_disk and row.get("disk", 0) > DISK_THRESHOLD:
                issues.append("磁盘")
            
            if issues:
                status = f"告警({','.join(issues)})"
                status_color = colors.orange
                warning_count += 1
            else:
                status = "正常"
                status_color = colors.green
                success_count += 1
        
        row_data = [
            str(idx),
            row.get("ip", ""),
            row.get("uptime", "未知"),
        ]
        if check_cpu:
            row_data.append(f'{row.get("cpu", 0)}%')
        if check_mem:
            row_data.append(f'{row.get("mem", 0)}%')
        if check_disk:
            row_data.append(f'{row.get("disk", 0)}%')
        row_data.append(status)
        table_data.append(row_data)
    
    # 计算页面可用宽度，让表格占满整个页面宽度
    page_width = A4[0] - 40*mm  # 减去左右边距
    col_widths = [
        20*mm,   # 序号
        35*mm,   # 服务器IP
        50*mm,   # 系统运行时间（增加宽度）
        25*mm,   # CPU使用率
        25*mm,   # 内存使用率
        25*mm,   # 磁盘使用率
        30*mm    # 状态
    ]
    server_table = Table(table_data, colWidths=col_widths)
    
    table_style = [
        ('FONT', (0, 1), (-1, -1), font_name, 9),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONT', (0, 0), (-1, 0), font_bold_name, 9),  # 表头字体加粗
        ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),  # 浅蓝背景
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.darkblue),     # 深蓝色文字
    ]
    
    # 设置状态列颜色
    for i in range(1, len(table_data)):
        row = table_data[i]
        if row[6] == "正常":
            table_style.append(('TEXTCOLOR', (6, i), (6, i), colors.green))
        elif "告警" in row[6]:
            table_style.append(('TEXTCOLOR', (6, i), (6, i), colors.orange))
        else:
            table_style.append(('TEXTCOLOR', (6, i), (6, i), colors.red))
    
    server_table.setStyle(TableStyle(table_style))
    elements.append(server_table)
    elements.append(Spacer(1, 15))
    
    # ========== 网关代理检测结果 ==========
    if proxy_results:
        elements.append(Paragraph("网关代理检测结果", heading_style))
        elements.append(Spacer(1, 10))
        
        # 网关代理检测表格
        proxy_headers = ["序号", "服务器IP", "代理状态", "检测结果"]
        proxy_table_data = [proxy_headers]
        
        proxy_success_count = 0
        proxy_fail_count = 0
        
        for idx, result in enumerate(proxy_results, start=1):
            if result.get("success"):
                status = "正常"
                proxy_success_count += 1
            elif result.get("error"):
                status = "连接失败"
                proxy_fail_count += 1
            else:
                status = "异常"
                proxy_fail_count += 1
            
            output = result.get("output", "")
            if len(output) > 30:
                output = output[:30] + "..."
            
            row_data = [
                str(idx),
                result.get("ip", ""),
                status,
                output if output else (result.get("error", "无输出") if result.get("error") else "未包含成功关键词")
            ]
            proxy_table_data.append(row_data)
        
        proxy_col_widths = [
            20*mm,   # 序号
            35*mm,   # 服务器IP
            30*mm,   # 代理状态
            95*mm    # 检测结果
        ]
        proxy_table = Table(proxy_table_data, colWidths=proxy_col_widths)
        
        proxy_table_style = [
            ('FONT', (0, 1), (-1, -1), font_name, 9),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONT', (0, 0), (-1, 0), font_bold_name, 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgreen),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.darkgreen),
        ]
        
        # 设置状态列颜色
        for i in range(1, len(proxy_table_data)):
            row = proxy_table_data[i]
            if row[2] == "正常":
                proxy_table_style.append(('TEXTCOLOR', (2, i), (2, i), colors.green))
            elif row[2] == "连接失败":
                proxy_table_style.append(('TEXTCOLOR', (2, i), (2, i), colors.red))
            else:
                proxy_table_style.append(('TEXTCOLOR', (2, i), (2, i), colors.orange))
        
        proxy_table.setStyle(TableStyle(proxy_table_style))
        elements.append(proxy_table)
        elements.append(Spacer(1, 10))
        
        # 网关代理检测汇总
        proxy_summary_data = [
            ["代理检测总数", f"{len(proxy_results)} 台"],
            ["代理正常", f"{proxy_success_count} 台"],
            ["代理异常", f"{proxy_fail_count} 台"]
        ]
        proxy_summary_table = Table(proxy_summary_data, colWidths=[info_page_width * 0.35, info_page_width * 0.65])
        proxy_summary_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), font_name, 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(proxy_summary_table)
        elements.append(Spacer(1, 15))
    
    # ========== 统计汇总 ==========
    elements.append(Paragraph("巡检结果汇总", heading_style))
    
    summary_data = [
        ["巡检总数", f"{len(rows)} 台"],
        ["正常运行", f"{success_count} 台"],
        ["告警警告", f"{warning_count} 台"],
        ["连接失败", f"{fail_count} 台"],
        ["巡检成功率", f"{round(success_count/len(rows)*100, 1) if rows else 0}%"]
    ]
    
    # 统计汇总表格也占满可用宽度
    summary_table = Table(summary_data, colWidths=[info_page_width * 0.35, info_page_width * 0.65])
    summary_table.setStyle(TableStyle([
        ('FONT', (0, 0), (-1, -1), font_name, 10),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 15))
    
    # ========== 异常问题详情 ==========
    elements.append(Paragraph("异常问题详情", heading_style))
    
    abnormal_lines = []
    for row in rows:
        reasons = []
        if not row.get("ok"):
            reasons.append(f'连接失败: {row.get("error", "未知错误")}')
        else:
            if check_cpu and row.get("cpu", 0) > CPU_THRESHOLD:
                reasons.append(f'CPU使用率过高 {row["cpu"]}%')
            if check_mem and row.get("mem", 0) > MEM_THRESHOLD:
                reasons.append(f'内存使用率过高 {row["mem"]}%')
            if check_disk and row.get("disk", 0) > DISK_THRESHOLD:
                reasons.append(f'磁盘使用率过高 {row["disk"]}%')
        
        if reasons:
            abnormal_lines.append(f"{row.get('ip', '未知IP')}: {'; '.join(reasons)}")
    
    # 添加网关代理异常
    if proxy_results:
        for result in proxy_results:
            if not result.get("success"):
                ip = result.get("ip", "未知IP")
                if result.get("error"):
                    abnormal_lines.append(f"{ip}: 网关代理连接失败 - {result['error']}")
                else:
                    abnormal_lines.append(f"{ip}: 网关代理异常 - 未检测到成功关键词")
    
    if abnormal_lines:
        for line in abnormal_lines:
            elements.append(Paragraph(line, red_style))
    else:
        elements.append(Paragraph("本次巡检未发现异常问题", green_style))
    
    elements.append(Spacer(1, 20))
    
    # ========== 签字区域 ==========
    elements.append(Paragraph("签字", heading_style))
    
    sign_data = [
        ["巡检人：", "", "审核人：", "", "日期：", ""]
    ]
    
    # 签字区域表格也占满可用宽度
    sign_col_widths = [
        info_page_width * 0.15,  # 巡检人标签
        info_page_width * 0.2,   # 巡检人签字
        info_page_width * 0.15,  # 审核人标签
        info_page_width * 0.2,   # 审核人签字
        info_page_width * 0.1,   # 日期标签
        info_page_width * 0.2    # 日期
    ]
    sign_table = Table(sign_data, colWidths=sign_col_widths)
    sign_table.setStyle(TableStyle([
        ('FONT', (0, 0), (-1, 0), font_name, 10),
        ('ALIGN', (0, 0), (-1, 0), 'LEFT'),
        ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 20),
        ('LINEBELOW', (0, 0), (0, 0), 1, colors.black),
        ('LINEBELOW', (2, 0), (2, 0), 1, colors.black),
        ('LINEBELOW', (4, 0), (4, 0), 1, colors.black),
    ]))
    elements.append(sign_table)
    
    # 构建文档
    doc.build(elements)
    return out_path
