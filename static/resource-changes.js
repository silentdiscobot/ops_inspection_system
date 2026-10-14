(function() {
  'use strict';
  if (window.__resourceChangesInit) {
    document.removeEventListener('lingtu:page-load', window.__resourceChangesInit);
  }
  var state = {servers: [], baselines: [], plans: [], events: [], history: []};
  var openStatuses = ['pending', 'confirmed_abnormal', 'recovered_pending'];
  var initializedRoot = null;

  function esc(value) {
    var div = document.createElement('div');
    div.textContent = String(value == null ? '' : value);
    return div.innerHTML;
  }
  function api(url, options) {
    options = options || {};
    if (options.body && typeof options.body !== 'string') {
      options.headers = Object.assign({'Content-Type': 'application/json'}, options.headers || {});
      options.body = JSON.stringify(options.body);
    }
    return fetch(url, options).then(function(response) {
      return response.json().catch(function() { return {}; }).then(function(data) {
        if (!response.ok || data.ok === false) throw new Error(data.msg || '请求失败');
        return data;
      });
    });
  }
  function baselineByServer(serverId) {
    return state.baselines.find(function(item) { return Number(item.server_id) === Number(serverId); });
  }
  function formatServer(item) {
    return esc((item.server_name ? item.server_name + ' · ' : '') + (item.server_ip || item.ip || ''));
  }
  function formatServerCell(item) {
    var name = item.server_name || item.name || item.server_ip || item.ip || '-';
    var ip = item.server_ip || item.ip || '';
    return '<div class="resource-server-cell"><strong>' + esc(name) + '</strong>'
      + (ip && ip !== name ? '<small>' + esc(ip) + '</small>' : '') + '</div>';
  }
  function formatChangeList(changes) {
    var rows = Array.isArray(changes) ? changes : [];
    if (!rows.length) return '<span class="resource-muted">未提供变化详情</span>';
    return '<ul class="resource-change-list">' + rows.map(function(item) {
      return '<li>' + esc(item) + '</li>';
    }).join('') + '</ul>';
  }
  function formatConfig(expected) {
    var text = hardwareText(expected);
    if (text === '-') return '<span class="resource-muted">未设置目标配置</span>';
    return '<div class="resource-config-tags">' + text.split('；').map(function(item) {
      return '<span>' + esc(item) + '</span>';
    }).join('') + '</div>';
  }
  function emptyState(colspan, title, description) {
    return '<tr><td colspan="' + colspan + '"><div class="resource-empty-state"><span aria-hidden="true">✓</span>'
      + '<strong>' + esc(title) + '</strong><small>' + esc(description) + '</small></div></td></tr>';
  }
  function statusLabel(status) {
    return ({pending: '待确认', confirmed_abnormal: '已确认异常', recovered_pending: '已恢复待确认',
      confirmed_normal: '已确认正常', resolved: '已关闭', planned: '待执行', matched: '已匹配',
      expired: '已过期', cancelled: '已取消'})[status] || status || '-';
  }
  function statusClass(status) {
    return openStatuses.indexOf(status) >= 0 ? 'resource-status-danger' :
      (status === 'planned' ? 'resource-status-warn' : 'resource-status-ok');
  }
  function hardwareText(expected) {
    var hw = (expected || {}).hardware || {};
    var disk = (expected || {}).disk_expectation || {};
    var parts = [];
    if (hw.cpu) parts.push('CPU ' + hw.cpu);
    if (hw.memory) parts.push('内存 ' + hw.memory);
    if (hw.storage) parts.push('磁盘总容量 ' + hw.storage);
    if (disk.device_count != null) parts.push('物理磁盘 ' + disk.device_count + ' 块');
    if (disk.mount_count != null) parts.push('挂载点 ' + disk.mount_count + ' 个');
    return parts.join('；') || '-';
  }
  function historyFilters() {
    var server = document.getElementById('resourceHistoryServer');
    var type = document.getElementById('resourceHistoryType');
    var from = document.getElementById('resourceHistoryFrom');
    var to = document.getElementById('resourceHistoryTo');
    return {
      server: server ? server.value : '',
      type: type ? type.value : '',
      from: from ? from.value : '',
      to: to ? to.value : ''
    };
  }
  function renderHistory() {
    var historyRows = document.getElementById('resourceHistoryRows');
    if (!historyRows) return;
    var filters = historyFilters();
    var rows = (state.history || []).filter(function(item) {
      var day = String(item.occurred_at || '').slice(0, 10);
      return (!filters.server || Number(item.server_id) === Number(filters.server))
        && (!filters.type || item.record_kind === filters.type)
        && (!filters.from || day >= filters.from)
        && (!filters.to || day <= filters.to);
    });
    var historyCount = document.getElementById('resourceHistoryCount');
    if (historyCount) historyCount.textContent = rows.length;
    historyRows.innerHTML = rows.length ? rows.map(function(item) {
      var reason = esc(item.reason || '-');
      if (item.operator) reason += '<br><small>操作人：' + esc(item.operator) + '</small>';
      return '<tr><td>' + esc(item.occurred_at || '-') + '</td><td>' + formatServer(item) + '</td>'
        + '<td>' + esc(item.record_type || '-') + '</td><td>' + esc(item.summary || '-') + '</td>'
        + '<td><span class="resource-status ' + statusClass(item.status) + '">' + esc(statusLabel(item.status)) + '</span></td>'
        + '<td>' + reason + '</td><td>' + esc(item.ticket_no || '-') + '</td></tr>';
    }).join('') : '<tr><td colspan="7" class="empty-row">当前筛选条件下没有变更历史</td></tr>';
  }
  function render() {
    var eventRows = document.getElementById('resourceEventRows');
    if (eventRows) {
    var activeEvents = state.events.filter(function(item) { return openStatuses.indexOf(item.status) >= 0; });
    var activePlans = state.plans.filter(function(item) { return item.status === 'planned'; });
    document.getElementById('resourcePendingCount').textContent = activeEvents.length;
    document.getElementById('resourcePlanCount').textContent = activePlans.length;
    document.getElementById('resourceBaselineCount').textContent = state.baselines.length;
    document.getElementById('resourceEventTotal').textContent = activeEvents.length + ' 项待处理';
    document.getElementById('resourcePlanTotal').textContent = activePlans.length + ' 项计划';
    document.getElementById('resourceBaselineTotal').textContent = state.baselines.length + ' 台服务器';
    document.getElementById('resourceSummary').classList.toggle('has-pending', activeEvents.length > 0);

    eventRows.innerHTML = activeEvents.length ? activeEvents.map(function(item) {
      var buttons = item.status === 'recovered_pending'
        ? '<button class="btn btn-sm btn-primary" onclick="resourceDecide(' + item.id + ',\'resolved\')">确认已恢复</button>'
        : '<button class="btn btn-sm btn-primary" onclick="resourceDecide(' + item.id + ',\'normal\')">确认正常并更新基线</button> '
          + '<button class="btn btn-sm btn-danger" onclick="resourceDecide(' + item.id + ',\'abnormal\')">确认异常</button>';
      return '<tr><td>' + formatServerCell(item) + '</td><td>' + formatChangeList(item.change_detail) + '</td>'
        + '<td><span class="resource-status ' + statusClass(item.status) + '">' + esc(statusLabel(item.status)) + '</span></td>'
        + '<td><div class="resource-time-cell"><strong>' + esc(item.first_seen_at || '-') + '</strong><small>最近发现 ' + esc(item.last_seen_at || '-') + '</small></div></td>'
        + '<td class="resource-action-cell"><textarea id="resourceReason' + item.id + '" class="form-control resource-reason" rows="2" maxlength="500" placeholder="填写确认理由后选择处理结果"></textarea>'
        + '<div class="resource-inline-actions">' + buttons + '</div></td></tr>';
    }).join('') : emptyState(5, '当前没有待确认变化', '服务器资源配置均处于已确认状态');

    var planRows = document.getElementById('resourcePlanRows');
    planRows.innerHTML = activePlans.length ? activePlans.map(function(item) {
      var actions = '<button class="btn btn-sm btn-primary" onclick="resourceEditPlan(' + item.id + ')">编辑</button> '
        + '<button class="btn btn-sm btn-danger" onclick="resourceCancelPlan(' + item.id + ')">取消</button>';
      return '<tr><td>' + formatServerCell(item) + '</td><td>' + formatConfig(item.expected_payload) + '</td>'
        + '<td><div class="resource-time-cell"><strong>' + esc(item.window_start) + '</strong><small>至 ' + esc(item.window_end) + '</small></div></td>'
        + '<td><div class="resource-description-cell"><strong>' + esc(item.reason) + '</strong>' + (item.ticket_no ? '<small>变更单号：' + esc(item.ticket_no) + '</small>' : '') + '</div></td>'
        + '<td><span class="resource-status ' + statusClass(item.status) + '">' + esc(statusLabel(item.status)) + '</span></td>'
        + '<td>' + actions + '</td></tr>';
    }).join('') : emptyState(6, '暂无待执行计划', '点击页面右上角“登记计划变更”创建计划');

    var baselineRows = document.getElementById('resourceBaselineRows');
    baselineRows.innerHTML = state.baselines.length ? state.baselines.map(function(item) {
      var payload = item.payload || {}, hw = payload.hardware || {}, disk = payload.disk || {};
      return '<tr><td>' + formatServerCell(item) + '</td><td><strong class="resource-value">' + esc(hw.cpu || '-') + '</strong></td><td><strong class="resource-value">' + esc(hw.memory || '-') + '</strong></td>'
        + '<td>' + esc(hw.storage || '-') + '</td><td>' + (disk.devices || []).length + ' 块</td><td>' + (disk.mounts || []).length + ' 个</td>'
        + '<td><div class="resource-version-cell"><span>v' + esc(item.version) + '</span><small>' + esc(item.accepted_at || '-') + '</small></div></td></tr>';
    }).join('') : emptyState(7, '尚未建立配置基线', '完成首次资源巡检并确认结果后会自动生成');
    }

    var historyServer = document.getElementById('resourceHistoryServer');
    if (!historyServer) return;
    var selectedServer = historyServer.value;
    historyServer.innerHTML = '<option value="">全部服务器</option>' + state.servers.map(function(item) {
      return '<option value="' + item.id + '">' + esc((item.name ? item.name + ' · ' : '') + item.ip) + '</option>';
    }).join('');
    historyServer.value = selectedServer;
    renderHistory();
  }
  function load() {
    return api('/api/resource-config').then(function(data) {
      state = data;
      render();
    }).catch(function(error) { uiAlert(error.message, 'error'); });
  }
  function localTime(date) {
    var pad = function(v) { return String(v).padStart(2, '0'); };
    return date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate()) + 'T' + pad(date.getHours()) + ':' + pad(date.getMinutes());
  }
  function planTicketNo(date) {
    var pad = function(v) { return String(v).padStart(2, '0'); };
    return 'CHG-' + date.getFullYear() + pad(date.getMonth() + 1) + pad(date.getDate())
      + pad(date.getHours()) + pad(date.getMinutes()) + pad(date.getSeconds());
  }
  window.resourceFillBaseline = function() {
    var serverId = document.getElementById('resourcePlanServer').value;
    var row = baselineByServer(serverId), payload = row ? row.payload || {} : {}, hw = payload.hardware || {}, disk = payload.disk || {};
    document.getElementById('resourcePlanCpu').value = hw.cpu || '';
    document.getElementById('resourcePlanMemory').value = hw.memory || '';
    document.getElementById('resourcePlanStorage').value = hw.storage || '';
    document.getElementById('resourcePlanDisks').value = (disk.devices || []).length;
    document.getElementById('resourcePlanMountCount').value = (disk.mounts || []).length;
  };
  window.resourceOpenPlan = function() {
    document.getElementById('resourcePlanForm').reset();
    document.getElementById('resourcePlanId').value = '';
    document.getElementById('resourcePlanTitle').textContent = '登记计划变更';
    var select = document.getElementById('resourcePlanServer');
    select.disabled = false;
    select.innerHTML = state.servers.map(function(item) { return '<option value="' + item.id + '">' + esc((item.name ? item.name + ' · ' : '') + item.ip) + '</option>'; }).join('');
    var start = new Date(), end = new Date(start.getTime() + 4 * 60 * 60 * 1000);
    document.getElementById('resourcePlanTicket').value = planTicketNo(start);
    document.getElementById('resourcePlanStart').value = localTime(start);
    document.getElementById('resourcePlanEnd').value = localTime(end);
    resourceFillBaseline();
    document.getElementById('resourcePlanOverlay').hidden = false;
  };
  window.resourceClosePlan = function() { document.getElementById('resourcePlanOverlay').hidden = true; };
  window.resourceEditPlan = function(id) {
    var plan = state.plans.find(function(item) { return item.id === id; });
    if (!plan) return;
    resourceOpenPlan();
    document.getElementById('resourcePlanId').value = id;
    document.getElementById('resourcePlanTitle').textContent = '编辑计划变更';
    var select = document.getElementById('resourcePlanServer'); select.value = plan.server_id; select.disabled = true;
    var expected = plan.expected_payload || {}, hw = expected.hardware || {}, disk = expected.disk_expectation || {};
    document.getElementById('resourcePlanCpu').value = hw.cpu || '';
    document.getElementById('resourcePlanMemory').value = hw.memory || '';
    document.getElementById('resourcePlanStorage').value = hw.storage || '';
    document.getElementById('resourcePlanDisks').value = disk.device_count == null ? 0 : disk.device_count;
    document.getElementById('resourcePlanMountCount').value = disk.mount_count == null ? 0 : disk.mount_count;
    document.getElementById('resourcePlanStart').value = String(plan.window_start || '').replace(' ', 'T').slice(0, 16);
    document.getElementById('resourcePlanEnd').value = String(plan.window_end || '').replace(' ', 'T').slice(0, 16);
    document.getElementById('resourcePlanReason').value = plan.reason || '';
    document.getElementById('resourcePlanTicket').value = plan.ticket_no || '';
  };
  window.resourceSavePlan = function(event) {
    event.preventDefault();
    var id = document.getElementById('resourcePlanId').value;
    if (!id) document.getElementById('resourcePlanTicket').value = planTicketNo(new Date());
    var body = {
      server_id: Number(document.getElementById('resourcePlanServer').value),
      window_start: document.getElementById('resourcePlanStart').value,
      window_end: document.getElementById('resourcePlanEnd').value,
      reason: document.getElementById('resourcePlanReason').value,
      ticket_no: document.getElementById('resourcePlanTicket').value,
      expected_payload: {
        hardware: {cpu: document.getElementById('resourcePlanCpu').value, memory: document.getElementById('resourcePlanMemory').value, storage: document.getElementById('resourcePlanStorage').value},
        disk_expectation: {device_count: Number(document.getElementById('resourcePlanDisks').value), mount_count: Number(document.getElementById('resourcePlanMountCount').value)}
      }
    };
    api('/api/resource-config/plans' + (id ? '/' + id : ''), {method: id ? 'PUT' : 'POST', body: body})
      .then(function() { resourceClosePlan(); return load(); }).then(function() { uiAlert('计划已保存', 'success'); })
      .catch(function(error) { uiAlert(error.message, 'error'); });
  };
  window.resourceCancelPlan = function(id) {
    uiConfirm('确定取消这条计划变更吗？', {type: 'error', okText: '取消计划'}).then(function(ok) {
      if (!ok) return;
      return api('/api/resource-config/plans/' + id, {method: 'DELETE'}).then(load);
    }).catch(function(error) { uiAlert(error.message, 'error'); });
  };
  window.resourceDecide = function(id, decision) {
    var reason = document.getElementById('resourceReason' + id).value.trim();
    if (reason.length < 2) { uiAlert('请填写确认理由', 'error'); return; }
    var labels = {normal: '确认正常并更新基线', abnormal: '确认异常', resolved: '确认已恢复'};
    uiConfirm('确定要“' + labels[decision] + '”吗？\n\n理由：' + reason, {type: decision === 'abnormal' ? 'error' : 'info'}).then(function(ok) {
      if (!ok) return;
      return api('/api/resource-config/events/' + id + '/decision', {method: 'POST', body: {decision: decision, reason: reason}})
        .then(load).then(function() { uiAlert('确认结果已保存', 'success'); });
    }).catch(function(error) { uiAlert(error.message, 'error'); });
  };
  window.resourceFilterHistory = renderHistory;
  window.resourceResetHistory = function() {
    ['resourceHistoryServer', 'resourceHistoryType', 'resourceHistoryFrom', 'resourceHistoryTo'].forEach(function(id) {
      var field = document.getElementById(id);
      if (field) field.value = '';
    });
    renderHistory();
  };
  window.resourceDownloadHistory = function() {
    var filters = historyFilters();
    var params = new URLSearchParams();
    if (filters.server) params.set('server_id', filters.server);
    if (filters.type) params.set('type', filters.type);
    if (filters.from) params.set('date_from', filters.from);
    if (filters.to) params.set('date_to', filters.to);
    window.location.href = '/api/resource-config/history/download' + (params.toString() ? '?' + params.toString() : '');
  };
  function init() {
    var root = document.getElementById('resourceEventRows') || document.getElementById('resourceHistoryRows');
    if (!root || root === initializedRoot) return;
    initializedRoot = root;
    load();
  }
  window.__resourceChangesInit = init;
  document.addEventListener('DOMContentLoaded', init);
  document.addEventListener('lingtu:page-load', init);
  init();
})();
