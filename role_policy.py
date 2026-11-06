"""Shared page and API permissions. Unlisted routes are denied for limited roles."""
ROLE_LABELS = {'admin': '系统管理员', 'dashboard_viewer': '大屏查看员',
               'asset_manager': '资产管理员', 'viewer': '报告查看员'}

def normalize_role(role):
    return 'asset_manager' if role == 'operator' else role

def can_access(role, path, method='GET'):
    role = normalize_role(role)
    if role == 'admin':
        return True
    if role not in ROLE_LABELS:
        return False
    if path in {'/', '/profile', '/api/update_password', '/api/logout', '/login', '/api/login', '/api/captcha'}:
        return True
    if role in {'dashboard_viewer', 'asset_manager'}:
        if path in {'/dashboard', '/dashboard/server-status', '/dashboard/data-center', '/api/dashboard/status'}:
            return method in {'GET', 'HEAD'}
    if role == 'asset_manager':
        if path in {'/servers', '/servers-new', '/server-environments', '/service-systems', '/services', '/services-new', '/api/groups', '/api/service_systems', '/api/service_environments'}:
            return True
        if path.startswith('/api/servers') or path.startswith('/api/services'):
            return True
        if path.startswith('/services/') and path.endswith('/edit'):
            return True
    if role == 'viewer':
        if path == '/api/ai/providers' and method in {'GET', 'HEAD'}:
            return True
        if path in {'/ai/insights', '/api/ai/insights', '/api/ai/stream', '/api/ai/stream/cancel'}:
            return True
        if method in {'GET', 'HEAD'} and (path in {'/reports', '/api/reports', '/api/inspection_runs', '/api/download_report'} or path.startswith('/download/') or path.startswith('/api/preview_report/')):
            return True
    return False
