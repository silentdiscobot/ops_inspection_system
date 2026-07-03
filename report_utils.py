# -*- coding: utf-8 -*-
import re
from datetime import datetime


def build_report_filename(task_name: str, extension: str, now=None) -> str:
    """Build a filesystem-safe report name from the inspection task name."""
    safe_name = re.sub(r'[\\/:*?"<>|\x00-\x1f]+', '_', (task_name or '').strip())
    safe_name = re.sub(r'\s+', '_', safe_name).strip(' ._')[:80] or '巡检报告'
    timestamp = (now or datetime.now()).strftime('%Y%m%d_%H%M%S')
    return f"{safe_name}_{timestamp}.{extension.lstrip('.').lower()}"
