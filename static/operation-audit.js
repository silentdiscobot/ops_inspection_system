(function () {
  'use strict';

  var root = document.getElementById('operationAuditRows');
  if (!root) return;

  var state = {dimension: 'time', page: 1, totalPages: 1, loading: false};
  var dimensionText = {
    user: '展示结果按用户分组，组内按执行时间倒序排列。',
    time: '按执行时间倒序展示全部明细。',
    server: '展示结果按服务器分组，组内按执行时间倒序排列。'
  };

  function element(id) { return document.getElementById(id); }
  function textCell(value, className) {
    var cell = document.createElement('td');
    if (className) cell.className = className;
    cell.textContent = value == null || value === '' ? '-' : String(value);
    return cell;
  }
  function serverLabel(item) {
    var name = item.server_name || '';
    var ip = item.server_ip || '';
    return name && ip && name !== ip ? name + ' · ' + ip : (name || ip || '未知服务器');
  }
  function params() {
    var query = new URLSearchParams();
    var values = {
      username: element('operationAuditUsername').value,
      server_id: element('operationAuditServer').value,
      start_time: element('operationAuditStart').value,
      end_time: element('operationAuditEnd').value,
      status: element('operationAuditStatus').value,
      dimension: state.dimension,
      page: state.page,
      page_size: 50
    };
    Object.keys(values).forEach(function (key) {
      if (values[key] !== '') query.set(key, values[key]);
    });
    return query.toString();
  }
  function setSelectOptions(select, rows, valueOf, labelOf, emptyLabel) {
    var selected = select.value;
    var seen = Object.create(null);
    select.replaceChildren();
    var empty = document.createElement('option');
    empty.value = '';
    empty.textContent = emptyLabel;
    select.appendChild(empty);
    rows.forEach(function (row) {
      var value = String(valueOf(row));
      if (!value || seen[value]) return;
      seen[value] = true;
      var option = document.createElement('option');
      option.value = value;
      option.textContent = labelOf(row);
      select.appendChild(option);
    });
    select.value = selected;
    if (select.value !== selected) select.value = '';
  }
  function renderFilters(filters) {
    filters = filters || {};
    setSelectOptions(
      element('operationAuditUsername'), filters.usernames || [],
      function (value) { return value; }, function (value) { return value; }, '全部用户'
    );
    setSelectOptions(
      element('operationAuditServer'), filters.servers || [],
      function (row) { return row.server_id; }, serverLabel, '全部服务器'
    );
  }
  function groupLabel(row) {
    if (state.dimension === 'user') return '用户：' + (row.username || '未知用户');
    if (state.dimension === 'server') return '服务器：' + serverLabel(row);
    return '';
  }
  function renderRows(rows) {
    root.replaceChildren();
    if (!rows.length) {
      var emptyRow = document.createElement('tr');
      var emptyCell = textCell('当前筛选条件下没有命令执行记录', 'empty-row');
      emptyCell.colSpan = 5;
      emptyRow.appendChild(emptyCell);
      root.appendChild(emptyRow);
      return;
    }
    var previousGroup = null;
    rows.forEach(function (item) {
      var currentGroup = groupLabel(item);
      if (currentGroup && currentGroup !== previousGroup) {
        var groupRow = document.createElement('tr');
        groupRow.className = 'operation-audit-group-row';
        var groupCell = textCell(currentGroup);
        groupCell.colSpan = 5;
        groupRow.appendChild(groupCell);
        root.appendChild(groupRow);
        previousGroup = currentGroup;
      }
      var row = document.createElement('tr');
      row.appendChild(textCell(item.created_at));
      row.appendChild(textCell(item.username || '未知用户', 'operation-audit-user'));

      var serverCell = document.createElement('td');
      var serverStrong = document.createElement('strong');
      serverStrong.textContent = item.server_name || item.server_ip || '未知服务器';
      serverCell.appendChild(serverStrong);
      if (item.server_name && item.server_ip && item.server_name !== item.server_ip) {
        var serverIp = document.createElement('small');
        serverIp.textContent = item.server_ip;
        serverCell.appendChild(serverIp);
      }
      row.appendChild(serverCell);

      var commandCell = document.createElement('td');
      commandCell.className = 'operation-audit-command-cell';
      var command = document.createElement('code');
      command.textContent = item.command || '-';
      command.title = item.command || '';
      commandCell.appendChild(command);
      if (item.status === 'failed' && item.error) {
        var error = document.createElement('small');
        error.textContent = item.error;
        commandCell.appendChild(error);
      }
      row.appendChild(commandCell);

      var statusCell = document.createElement('td');
      var status = document.createElement('span');
      status.className = 'operation-audit-status ' + (item.status === 'success' ? 'is-success' : 'is-failed');
      status.textContent = item.status === 'success' ? '成功' : '失败';
      statusCell.appendChild(status);
      row.appendChild(statusCell);
      root.appendChild(row);
    });
  }
  function render(data) {
    var summary = data.summary || {};
    element('operationAuditTotal').textContent = summary.total || 0;
    element('operationAuditUsers').textContent = summary.user_count || 0;
    element('operationAuditServers').textContent = summary.server_count || 0;
    element('operationAuditFailed').textContent = summary.failed_count || 0;
    state.page = data.page || 1;
    state.totalPages = data.total_pages || 1;
    element('operationAuditPageInfo').textContent = '第 ' + state.page + ' / ' + state.totalPages + ' 页，共 ' + (data.total || 0) + ' 条';
    element('operationAuditPrev').disabled = state.page <= 1;
    element('operationAuditNext').disabled = state.page >= state.totalPages;
    element('operationAuditContext').textContent = dimensionText[state.dimension];
    renderFilters(data.filters);
    renderRows(data.rows || []);
  }
  function load() {
    if (state.loading) return;
    state.loading = true;
    root.innerHTML = '<tr><td colspan="5" class="empty-row">正在加载…</td></tr>';
    fetch('/api/ai/operation-audits?' + params(), {credentials: 'same-origin'})
      .then(function (response) {
        return response.json().catch(function () { return {}; }).then(function (data) {
          if (!response.ok || data.ok === false) throw new Error(data.msg || '加载操作审计失败');
          return data;
        });
      })
      .then(render)
      .catch(function (error) {
        root.innerHTML = '';
        var row = document.createElement('tr');
        var cell = textCell(error.message, 'empty-row operation-audit-error');
        cell.colSpan = 5;
        row.appendChild(cell);
        root.appendChild(row);
      })
      .finally(function () { state.loading = false; });
  }

  element('operationAuditFilters').addEventListener('submit', function (event) {
    event.preventDefault(); state.page = 1; load();
  });
  element('operationAuditReset').addEventListener('click', function () {
    element('operationAuditFilters').reset(); state.page = 1; load();
  });
  element('operationAuditPrev').addEventListener('click', function () {
    if (state.page > 1) { state.page -= 1; load(); }
  });
  element('operationAuditNext').addEventListener('click', function () {
    if (state.page < state.totalPages) { state.page += 1; load(); }
  });
  document.querySelectorAll('.operation-dimension-btn').forEach(function (button) {
    button.addEventListener('click', function () {
      state.dimension = button.dataset.dimension || 'time';
      state.page = 1;
      document.querySelectorAll('.operation-dimension-btn').forEach(function (item) {
        item.classList.toggle('is-active', item === button);
      });
      load();
    });
  });

  load();
}());
