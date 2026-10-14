(function () {
  'use strict';

  var root = document.getElementById('systemAuditRows');
  if (!root) return;

  var state = {page: 1, totalPages: 1, loading: false};
  var resultLabels = {
    ok: '成功', success: '成功', executed: '已执行', pending: '待确认',
    denied: '已拒绝', rejected: '已拦截', failed: '失败', error: '错误'
  };
  var actionLabels = {
    'server.export': '导出服务器列表',
    'server.reveal_credential': '查看服务器凭据',
    'service.create': '新增服务',
    'service.update': '修改服务',
    'service.delete': '删除服务',
    'service.export': '导出服务信息',
    'service.reveal_account': '查看服务账号',
    'service_dict.add': '新增服务字典项',
    'service_dict.delete': '删除服务字典项',
    'resource.history.download': '导出资源变更历史',
    'resource.plan.create': '创建资源变更计划',
    'resource.plan.update': '修改资源变更计划',
    'resource.plan.cancel': '取消资源变更计划',
    'resource.event.normal': '确认正常变更',
    'resource.event.abnormal': '标记异常变更',
    'resource.event.resolved': '关闭资源变更',
    'ai_chat': 'AI 会话',
    'ai_tool_call': 'AI 工具调用',
    'ai_action_request': 'AI 操作申请',
    'ai_action_execute': 'AI 操作执行',
    'ai_action_approve': 'AI 操作批准',
    'ai_action_reject': 'AI 操作拒绝',
    'ai_skill_create': '创建 AI 技能',
    'ai_provider_save': '保存模型配置',
    'ai_provider_delete': '删除模型配置',
    'ai_provider_default': '设置默认模型',
    'ai_provider_test': '测试模型连接',
    'ai_conversation_delete': '删除 AI 会话'
  };

  function element(id) { return document.getElementById(id); }
  function textCell(value, className) {
    var cell = document.createElement('td');
    if (className) cell.className = className;
    cell.textContent = value == null || value === '' ? '-' : String(value);
    return cell;
  }
  function moduleName(action) {
    action = String(action || '');
    if (action.indexOf('server.') === 0 || action.indexOf('server_') === 0) return '服务器管理';
    if (action.indexOf('service') === 0) return '服务管理';
    if (action.indexOf('resource.') === 0) return '资源变更';
    if (action.indexOf('ai_') === 0 || action.indexOf('ai.') === 0) return 'AI 运维';
    if (action.indexOf('user.') === 0) return '用户管理';
    if (action.indexOf('inspection.') === 0) return '服务器巡检';
    return '系统';
  }
  function actionLabel(action) { return actionLabels[action] || action || '未知操作'; }
  function resultLabel(result) { return resultLabels[String(result || '').toLowerCase()] || result || '未标记'; }
  function resultClass(result) {
    result = String(result || '').toLowerCase();
    if (['ok', 'success', 'executed'].indexOf(result) >= 0) return 'is-success';
    if (result === 'pending') return 'is-warning';
    if (['denied', 'rejected', 'failed', 'error'].indexOf(result) >= 0) return 'is-failed';
    return 'is-neutral';
  }
  function params() {
    var query = new URLSearchParams();
    var values = {
      username: element('systemAuditUsername').value,
      action: element('systemAuditAction').value,
      result: element('systemAuditResult').value,
      start_time: element('systemAuditStart').value,
      end_time: element('systemAuditEnd').value,
      keyword: element('systemAuditKeyword').value.trim(),
      page: state.page,
      page_size: 50
    };
    Object.keys(values).forEach(function (key) {
      if (values[key] !== '') query.set(key, values[key]);
    });
    return query.toString();
  }
  function setSelectOptions(select, values, emptyLabel, labeler) {
    var selected = select.value;
    select.replaceChildren();
    var empty = document.createElement('option');
    empty.value = '';
    empty.textContent = emptyLabel;
    select.appendChild(empty);
    (values || []).forEach(function (value) {
      var option = document.createElement('option');
      option.value = value;
      option.textContent = labeler ? labeler(value) : value;
      select.appendChild(option);
    });
    select.value = selected;
    if (select.value !== selected) select.value = '';
  }
  function renderFilters(filters) {
    filters = filters || {};
    setSelectOptions(element('systemAuditUsername'), filters.usernames, '全部用户');
    setSelectOptions(element('systemAuditAction'), filters.actions, '全部操作', function (value) {
      return moduleName(value) + ' · ' + actionLabel(value);
    });
    setSelectOptions(element('systemAuditResult'), filters.results, '全部结果', resultLabel);
  }
  function appendStrongSmall(cell, strongText, smallText) {
    var strong = document.createElement('strong');
    strong.textContent = strongText || '-';
    cell.appendChild(strong);
    if (smallText) {
      var small = document.createElement('small');
      small.textContent = smallText;
      cell.appendChild(small);
    }
  }
  function renderRows(rows) {
    root.replaceChildren();
    if (!rows.length) {
      var emptyRow = document.createElement('tr');
      var emptyCell = textCell('当前筛选条件下没有审计记录', 'empty-row');
      emptyCell.colSpan = 6;
      emptyRow.appendChild(emptyCell);
      root.appendChild(emptyRow);
      return;
    }
    rows.forEach(function (item) {
      var row = document.createElement('tr');
      row.appendChild(textCell(item.created_at));

      var userCell = document.createElement('td');
      userCell.className = 'operation-audit-user';
      appendStrongSmall(userCell, item.username || '系统', item.client_ip || '');
      row.appendChild(userCell);

      var actionCell = document.createElement('td');
      var module = document.createElement('span');
      module.className = 'system-audit-module';
      module.textContent = moduleName(item.action);
      actionCell.appendChild(module);
      appendStrongSmall(actionCell, actionLabel(item.action), item.action || '');
      row.appendChild(actionCell);

      var targetCell = document.createElement('td');
      var targetName = item.target_name || (item.target_id != null ? '#' + item.target_id : '-');
      var targetMeta = item.target_type || '';
      if (item.target_id != null && item.target_name) targetMeta += (targetMeta ? ' · ' : '') + '#' + item.target_id;
      appendStrongSmall(targetCell, targetName, targetMeta);
      row.appendChild(targetCell);

      var statusCell = document.createElement('td');
      var status = document.createElement('span');
      status.className = 'operation-audit-status ' + resultClass(item.result);
      status.textContent = resultLabel(item.result);
      statusCell.appendChild(status);
      row.appendChild(statusCell);
      row.appendChild(textCell(item.detail || '-', 'system-audit-detail'));
      root.appendChild(row);
    });
  }
  function render(data) {
    var summary = data.summary || {};
    element('systemAuditTotal').textContent = summary.total || 0;
    element('systemAuditUsers').textContent = summary.user_count || 0;
    element('systemAuditActions').textContent = summary.action_count || 0;
    element('systemAuditAbnormal').textContent = summary.abnormal_count || 0;
    state.page = data.page || 1;
    state.totalPages = data.total_pages || 1;
    element('systemAuditPageInfo').textContent = '第 ' + state.page + ' / ' + state.totalPages + ' 页，共 ' + (data.total || 0) + ' 条';
    element('systemAuditPrev').disabled = state.page <= 1;
    element('systemAuditNext').disabled = state.page >= state.totalPages;
    renderFilters(data.filters);
    renderRows(data.rows || data.logs || []);
  }
  function load() {
    if (state.loading) return;
    state.loading = true;
    root.innerHTML = '<tr><td colspan="6" class="empty-row">正在加载…</td></tr>';
    fetch('/api/audit_logs?' + params(), {credentials: 'same-origin'})
      .then(function (response) {
        return response.json().catch(function () { return {}; }).then(function (data) {
          if (!response.ok || data.ok === false) throw new Error(data.msg || '加载日志审计失败');
          return data;
        });
      })
      .then(render)
      .catch(function (error) {
        root.replaceChildren();
        var row = document.createElement('tr');
        var cell = textCell(error.message, 'empty-row operation-audit-error');
        cell.colSpan = 6;
        row.appendChild(cell);
        root.appendChild(row);
      })
      .finally(function () { state.loading = false; });
  }

  element('systemAuditFilters').addEventListener('submit', function (event) {
    event.preventDefault(); state.page = 1; load();
  });
  element('systemAuditReset').addEventListener('click', function () {
    element('systemAuditFilters').reset(); state.page = 1; load();
  });
  element('systemAuditPrev').addEventListener('click', function () {
    if (state.page > 1) { state.page -= 1; load(); }
  });
  element('systemAuditNext').addEventListener('click', function () {
    if (state.page < state.totalPages) { state.page += 1; load(); }
  });

  load();
}());
