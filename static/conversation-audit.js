(function () {
  'use strict';

  var root = document.getElementById('conversationAuditRows');
  if (!root) return;
  var state = {dimension: 'time', page: 1, totalPages: 1, loading: false};
  var descriptions = {
    time: '按提问时间倒序展示全部明细。',
    user: '展示结果按用户分组，组内按提问时间倒序排列。',
    question: '展示结果按问题内容分组，可查看提交相同问题的用户和时间。'
  };

  function element(id) { return document.getElementById(id); }
  function textCell(value, className) {
    var cell = document.createElement('td');
    if (className) cell.className = className;
    cell.textContent = value == null || value === '' ? '-' : String(value);
    return cell;
  }
  function requestParams() {
    var query = new URLSearchParams();
    var values = {
      username: element('conversationAuditUsername').value,
      keyword: element('conversationAuditKeyword').value.trim(),
      start_time: element('conversationAuditStart').value,
      end_time: element('conversationAuditEnd').value,
      dimension: state.dimension,
      page: state.page,
      page_size: 50
    };
    Object.keys(values).forEach(function (key) {
      if (values[key] !== '') query.set(key, values[key]);
    });
    return query.toString();
  }
  function renderUserOptions(filters) {
    var select = element('conversationAuditUsername');
    var selected = select.value;
    select.replaceChildren();
    var empty = document.createElement('option');
    empty.value = ''; empty.textContent = '全部用户'; select.appendChild(empty);
    (filters.usernames || []).forEach(function (username) {
      var option = document.createElement('option');
      option.value = username; option.textContent = username; select.appendChild(option);
    });
    select.value = selected;
    if (select.value !== selected) select.value = '';
  }
  function groupLabel(row) {
    if (state.dimension === 'user') return '用户：' + (row.username || '未知用户');
    if (state.dimension === 'question') {
      var question = String(row.question || '空问题').replace(/\s+/g, ' ').trim();
      return '问题：' + (question.length > 100 ? question.slice(0, 100) + '…' : question);
    }
    return '';
  }
  function questionNode(value) {
    var text = String(value || '');
    if (text.length <= 180) {
      var plain = document.createElement('div');
      plain.className = 'conversation-question-text'; plain.textContent = text || '-';
      return plain;
    }
    var details = document.createElement('details');
    details.className = 'conversation-question-details';
    var summary = document.createElement('summary');
    summary.textContent = text.slice(0, 180) + '…';
    var full = document.createElement('div');
    full.textContent = text;
    details.appendChild(summary); details.appendChild(full);
    return details;
  }
  function renderRows(rows) {
    root.replaceChildren();
    if (!rows.length) {
      var emptyRow = document.createElement('tr');
      var emptyCell = textCell('当前筛选条件下没有用户提问记录', 'empty-row');
      emptyCell.colSpan = 4; emptyRow.appendChild(emptyCell); root.appendChild(emptyRow);
      return;
    }
    var previousGroup = null;
    rows.forEach(function (item) {
      var currentGroup = groupLabel(item);
      if (currentGroup && currentGroup !== previousGroup) {
        var groupRow = document.createElement('tr');
        groupRow.className = 'operation-audit-group-row';
        var groupCell = textCell(currentGroup); groupCell.colSpan = 4;
        groupRow.appendChild(groupCell); root.appendChild(groupRow); previousGroup = currentGroup;
      }
      var row = document.createElement('tr');
      row.appendChild(textCell(item.created_at));
      row.appendChild(textCell(item.username || '未知用户', 'operation-audit-user'));
      var conversation = document.createElement('td');
      var title = document.createElement('strong');
      title.textContent = item.conversation_title || '未命名会话';
      var id = document.createElement('small'); id.textContent = '会话 #' + item.conversation_id;
      conversation.appendChild(title); conversation.appendChild(id); row.appendChild(conversation);
      var question = document.createElement('td');
      question.className = 'conversation-question-cell';
      question.appendChild(questionNode(item.question)); row.appendChild(question);
      root.appendChild(row);
    });
  }
  function render(data) {
    var summary = data.summary || {};
    element('conversationAuditTotal').textContent = summary.total || 0;
    element('conversationAuditUsers').textContent = summary.user_count || 0;
    element('conversationAuditConversations').textContent = summary.conversation_count || 0;
    element('conversationAuditToday').textContent = summary.today_count || 0;
    state.page = data.page || 1; state.totalPages = data.total_pages || 1;
    element('conversationAuditPageInfo').textContent = '第 ' + state.page + ' / ' + state.totalPages + ' 页，共 ' + (data.total || 0) + ' 条';
    element('conversationAuditPrev').disabled = state.page <= 1;
    element('conversationAuditNext').disabled = state.page >= state.totalPages;
    element('conversationAuditContext').textContent = descriptions[state.dimension];
    renderUserOptions(data.filters || {}); renderRows(data.rows || []);
  }
  function showError(message) {
    root.replaceChildren();
    var row = document.createElement('tr');
    var cell = textCell(message, 'empty-row operation-audit-error');
    cell.colSpan = 4; row.appendChild(cell); root.appendChild(row);
  }
  function load() {
    if (state.loading) return;
    state.loading = true;
    root.innerHTML = '<tr><td colspan="4" class="empty-row">正在加载…</td></tr>';
    fetch('/api/ai/conversation-audits?' + requestParams(), {credentials: 'same-origin'})
      .then(function (response) {
        return response.json().catch(function () { return {}; }).then(function (data) {
          if (!response.ok || data.ok === false) throw new Error(data.msg || '加载 AI 会话审计失败');
          return data;
        });
      })
      .then(render).catch(function (error) { showError(error.message); })
      .finally(function () { state.loading = false; });
  }

  element('conversationAuditFilters').addEventListener('submit', function (event) {
    event.preventDefault(); state.page = 1; load();
  });
  element('conversationAuditReset').addEventListener('click', function () {
    element('conversationAuditFilters').reset(); state.page = 1; load();
  });
  element('conversationAuditPrev').addEventListener('click', function () {
    if (state.page > 1) { state.page -= 1; load(); }
  });
  element('conversationAuditNext').addEventListener('click', function () {
    if (state.page < state.totalPages) { state.page += 1; load(); }
  });
  document.querySelectorAll('.conversation-dimension-btn').forEach(function (button) {
    button.addEventListener('click', function () {
      state.dimension = button.dataset.dimension || 'time'; state.page = 1;
      document.querySelectorAll('.conversation-dimension-btn').forEach(function (item) {
        item.classList.toggle('is-active', item === button);
      });
      load();
    });
  });
  load();
}());
