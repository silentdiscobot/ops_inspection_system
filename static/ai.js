// AI 智能运维工作台。
// 约定（与后端一致）：
//   1. 生成过程没有 WebSocket（socket.io 在本项目不可用），一律用 /api/ai/stream 轮询增量；
//   2. 模型输出、工具摘要、动作 JSON 全部当作文本处理，只有 AiMarkdown 负责把 Markdown 变标签；
//   3. 有副作用的动作只在这里"申请确认"，真正的执行由后端在人工点击后完成。
(function () {
  'use strict';

  var CFG = window.AI_PAGE_CONFIG || {};
  var POLL_MS = 400;
  var MAX_POLL_ERRORS = 5;

  var state = {
    conversationId: null,
    conversations: [],
    providers: [],
    providerId: null,
    envFallback: null,
    allowCloud: true,
    streamId: null,
    offset: 0,
    liveText: '',
    polling: false,
    pollTimer: null,
    pollErrors: 0,
    kind: 'chat',
    sending: false,
    currentTitle: '',
    dismissedProviderErrors: {}
  };
  var insight = { streamId: null, offset: 0, text: '', timer: null, errors: 0, runId: null };
  var providerEditing = { id: null };
  var skillsState = { items: [], active: null, root: '' };

  // ---------------- 基础工具 ----------------
  function $(id) { return document.getElementById(id); }

  function node(tag, className, text) {
    var el = document.createElement(tag);
    if (className) el.className = className;
    if (text !== undefined && text !== null) el.textContent = String(text);
    return el;
  }

  function aiLogo() {
    var image = node('img', 'ai-logo-icon');
    image.src = '/static/images/logo-robot.png';
    image.alt = '';
    image.setAttribute('aria-hidden', 'true');
    return image;
  }

  function clear(element) {
    if (element) element.innerHTML = '';
    return element;
  }

  function esc(value) {
    return window.AiMarkdown ? window.AiMarkdown.escapeHtml(value) : String(value || '');
  }

  function clearTimer(id) {
    if (id) window.clearTimeout(id);
    return null;
  }

  function api(method, url, payload) {
    var options = { method: method, credentials: 'same-origin', headers: { 'Accept': 'application/json' } };
    if (payload !== undefined) {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(payload);
    }
    return fetch(url, options).then(function (response) {
      return response.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : {}; } catch (error) { data = null; }
        if (!response.ok) {
          var message = (data && (data.message || data.msg)) || ('请求失败（HTTP ' + response.status + '）');
          throw new Error(message);
        }
        if (data === null) throw new Error('服务返回内容无法解析');
        if (data.ok === false && data.message) throw new Error(data.message);
        return data;
      });
    });
  }

  function currentProviderId() {
    var select = $('aiProviderSelect');
    if (select && select.value) return parseInt(select.value, 10) || null;
    return null;
  }

  function currentAccessMode() {
    var select = $('aiAccessMode');
    var value = select ? select.value : 'change';
    return /^(limited|change|full)$/.test(value) ? value : 'change';
  }

  function setStatus(text) {
    var target = $('aiChatStatus');
    if (target) target.textContent = text || '';
  }

  function setHint(text) {
    var target = $('aiComposerHint');
    if (target) target.textContent = text || '';
  }

  function messageBox() { return $('aiMessages'); }

  function nearBottom(box) {
    return box.scrollHeight - box.scrollTop - box.clientHeight < 90;
  }

  function scrollToBottom(force) {
    var box = messageBox();
    if (!box) return;
    if (force || nearBottom(box)) box.scrollTop = box.scrollHeight;
  }

  // ---------------- 工作台布局 ----------------
  // 这一页按"工作台"用：消息区自己滚，提问框钉在卡片底部，整页不滚。
  // 卡片高度不写死数字，而是按它在页面里的真实位置算出来，
  // 这样页头换行、窗口变矮都不会把提问框顶出可视区。
  // 底部留白取 main 的实际 padding-bottom：留少了整页会多出一条滚动条。
  var WORKSPACE_MIN_H = 440;
  var WORKSPACE_MIN_GAP = 24;
  var NARROW_LAYOUT = '(max-width:1099px)';

  function narrowLayout() {
    return !!(window.matchMedia && window.matchMedia(NARROW_LAYOUT).matches);
  }

  function setSideOpen(open) {
    var workspace = $('aiWorkspace');
    var toggle = $('aiSideToggle');
    if (workspace) workspace.classList.toggle('is-side-open', !!open);
    if (toggle) toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  function sideIsOpen() {
    var workspace = $('aiWorkspace');
    return !!(workspace && workspace.classList.contains('is-side-open'));
  }

  function fitWorkspace() {
    var workspace = $('aiWorkspace');
    if (!workspace) return;
    var page = workspace.closest ? workspace.closest('main') : null;
    var gap = WORKSPACE_MIN_GAP;
    if (page) gap = parseFloat(window.getComputedStyle(page).paddingBottom) || gap;
    var room = window.innerHeight - workspace.getBoundingClientRect().top - gap;
    workspace.style.setProperty('--ai-workspace-h',
      Math.floor(Math.max(room, WORKSPACE_MIN_H)) + 'px');
    // 宽屏时侧栏本来就在，别把"展开"状态留着（窗口再变窄会突然弹出来）
    if (!narrowLayout()) setSideOpen(false);
  }

  // ---------------- 提示框（复用玻璃拟态样式） ----------------
  function aiPrompt(message, defaultValue, options) {
    options = options || {};
    return new Promise(function (resolve) {
      var overlay = node('div', 'modal-overlay');
      var dialog = node('div', 'modal-content ai-prompt-modal');
      var header = node('div', 'modal-header');
      header.appendChild(node('h3', null, options.title || '请输入'));
      var closeBtn = node('button', 'modal-close', '×');
      closeBtn.type = 'button';
      header.appendChild(closeBtn);
      var body = node('div', 'modal-body');
      body.appendChild(node('p', 'ai-prompt-text', message));
      var input = node('input', 'form-control');
      input.type = 'text';
      input.value = defaultValue || '';
      body.appendChild(input);
      var footer = node('div', 'modal-footer');
      var cancel = node('button', 'btn btn-secondary', '取消');
      var ok = node('button', 'btn btn-primary', options.okText || '确定');
      cancel.type = 'button'; ok.type = 'button';
      footer.appendChild(cancel); footer.appendChild(ok);
      dialog.appendChild(header); dialog.appendChild(body); dialog.appendChild(footer);
      overlay.appendChild(dialog);
      document.body.appendChild(overlay);

      function done(value) {
        if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
        resolve(value);
      }
      closeBtn.addEventListener('click', function () { done(null); });
      cancel.addEventListener('click', function () { done(null); });
      ok.addEventListener('click', function () { done(input.value); });
      overlay.addEventListener('click', function (event) { if (event.target === overlay) done(null); });
      input.addEventListener('keydown', function (event) {
        if (event.key === 'Enter') { event.preventDefault(); done(input.value); }
        if (event.key === 'Escape') done(null);
      });
      window.setTimeout(function () { input.focus(); input.select(); }, 20);
    });
  }

  function openOverlay(id) {
    var overlay = $(id);
    if (overlay) overlay.style.display = 'flex';
  }

  function closeOverlay(id) {
    var overlay = $(id);
    if (overlay) overlay.style.display = 'none';
  }

  // ---------------- provider ----------------
  function loadProviders() {
    var url = '/api/ai/providers' + (CFG.role === 'admin' ? '?full=1' : '');
    return api('GET', url).then(function (data) {
      state.providers = data.providers || [];
      state.envFallback = data.env_fallback || null;
      state.allowCloud = data.allow_cloud !== false;
      renderProviderSelect();
      renderProviderForm(providerEditing.id);
    });
  }

  function renderProviderSelect() {
    var select = $('aiProviderSelect');
    if (!select) return;
    clear(select);
    if (!state.providers.length) {
      var option = node('option', null, state.envFallback
        ? (state.envFallback.name + (state.envFallback.is_traditional_fallback ? '（无大模型降级）' : '（环境变量配置）'))
        : '还没有可用的模型配置');
      option.value = '';
      select.appendChild(option);
      select.disabled = true;
    } else {
      select.disabled = false;
      state.providers.forEach(function (item) {
        var label = item.name + ' · ' + item.model + (item.is_default ? '（默认）' : '');
        var item_option = node('option', null, label);
        item_option.value = String(item.id);
        select.appendChild(item_option);
      });
      if (state.providerId) select.value = String(state.providerId);
      if (!select.value) {
        var preferred = state.providers.filter(function (item) { return item.is_default; })[0] || state.providers[0];
        select.value = String(preferred.id);
      }
    }
    renderProviderNote();
  }

  function renderProviderNote() {
    var note = $('aiProviderNote');
    if (!note) return;
    note.innerHTML = '';
    var lines = [];
    if (state.envFallback && !state.providers.length) {
      if (state.envFallback.is_traditional_fallback) {
        lines.push('当前没有可用大模型配置，系统会自动使用传统运维规则引擎回答。');
      } else {
        lines.push('当前使用环境变量 OPS_AI_BASE_URL / OPS_AI_API_KEY 指定的模型，'
          + '这种模式不启用工具调用；想让它读系统数据请在「模型配置」里新增一个配置。');
      }
    }
    var selected = state.providers.filter(function (item) {
      return String(item.id) === String(currentProviderId());
    })[0];
    if (selected && !selected.has_key) {
      lines.push('该配置还没有保存 API Key，如果模型服务需要鉴权会直接失败。');
    }
    if (selected && selected.last_test_ok === false && selected.last_test_error) {
      var errorKey = String(selected.id) + '\u0000' + selected.last_test_error;
      if (!state.dismissedProviderErrors[errorKey]) {
        lines.push({
          text: '上次连接测试失败：' + selected.last_test_error,
          dismissKey: errorKey
        });
      }
    }
    if (selected && !selected.supports_tools) {
      lines.push('该配置关闭了工具调用，AI 只能基于系统快照回答，读不到实时数据。');
    }
    if (CFG.maskIp) lines.push('已开启 IP 脱敏（OPS_AI_MASK_IP=1），发给模型的 IP 会被打码。');
    if (selected && selected.deployment === 'cloud' && !state.allowCloud) {
      lines.push('当前禁止使用云端模型（OPS_AI_ALLOW_CLOUD=0），请改用本地/内网模型。');
    }
    if (!lines.length) { note.hidden = true; return; }
    note.hidden = false;
    lines.forEach(function (item) {
      var text = typeof item === 'string' ? item : item.text;
      var line = node('div', 'ai-note-line', text);
      if (item.dismissKey) {
        line.classList.add('is-dismissible');
        var close = node('button', 'ai-note-close', '\u00d7');
        close.type = 'button';
        close.title = '关闭此提示';
        close.setAttribute('aria-label', '关闭上次连接测试失败提示');
        close.addEventListener('click', function () {
          state.dismissedProviderErrors[item.dismissKey] = true;
          renderProviderNote();
        });
        line.appendChild(close);
      }
      note.appendChild(line);
    });
  }

  // ---------------- 会话 ----------------
  function loadConversations() {
    return api('GET', '/api/ai/conversations').then(function (data) {
      state.conversations = data.conversations || [];
      renderConversationList();
    });
  }

  function renderConversationList() {
    var list = $('aiConversationList');
    if (!list) return;
    clear(list);
    if (!state.conversations.length) {
      list.appendChild(node('div', 'empty-state', '还没有会话，点「新建」开始'));
      return;
    }
    state.conversations.forEach(function (item) {
      var button = node('button', 'ai-conversation-item');
      button.type = 'button';
      if (String(item.id) === String(state.conversationId)) button.classList.add('is-active');
      if (item.pending_count) button.classList.add('needs-confirmation');
      var head = node('div', 'ai-conversation-head');
      head.appendChild(node('span', 'ai-conversation-title', item.title || '未命名会话'));
      if (item.pending_count) head.appendChild(node('span', 'ai-confirmation-flag', '需要确认'));
      button.appendChild(head);
      var meta = node('div', 'ai-conversation-meta',
        (item.model || '未指定模型') + ' · ' + (item.message_count || 0) + ' 条');
      button.appendChild(meta);
      if (item.updated_at) button.appendChild(node('div', 'ai-conversation-time', item.updated_at));
      button.addEventListener('click', function () {
        setSideOpen(false);  // 窄屏：选了会话就收起抽屉，把屏幕还给对话
        selectConversation(item.id, { force: !!item.pending_count });
      });
      list.appendChild(button);
    });
  }

  function markActiveConversation() { renderConversationList(); }

  function updateChatTitle(title) {
    if (title) {
      state.currentTitle = title;
      var target = $('aiChatTitle');
      if (target) target.textContent = title;
    }
  }

  function createConversation(options) {
    options = options || {};
    var payload = { title: options.title || '新会话' };
    if (currentProviderId()) payload.provider_id = currentProviderId();
    return api('POST', '/api/ai/conversations', payload).then(function (data) {
      var conversation = data.conversation || {};
      return loadConversations().then(function () {
        state.providerId = payload.provider_id || null;
        if (options.noSelect) return conversation;
        return selectConversation(conversation.id).then(function () { return conversation; });
      });
    });
  }

  function loadConversation(id, options) {
    options = options || {};
    return api('GET', '/api/ai/conversations/' + id + '/messages').then(function (data) {
      var conversation = data.conversation || {};
      updateChatTitle(conversation.title || 'AI 运维助手');
      if (conversation.provider_id) {
        state.providerId = conversation.provider_id;
        var select = $('aiProviderSelect');
        if (select) select.value = String(conversation.provider_id);
        renderProviderNote();
      }
      renderMessages(data.messages || [], data.actions || []);
      if (options.attach && data.active_stream_id) attachStream(data.active_stream_id, 'chat', true);
      return data;
    });
  }

  function selectConversation(id, options) {
    options = options || {};
    if (!options.force && String(id) === String(state.conversationId)
      && messageBox() && messageBox().childNodes.length) {
      markActiveConversation();
      return Promise.resolve();
    }
    stopPolling();
    state.conversationId = id;
    state.offset = 0;
    state.liveText = '';
    state.streamId = null;
    setStatus('');
    setHint('');
    markActiveConversation();
    var box = clear(messageBox());
    if (box) box.appendChild(node('div', 'loading', '加载会话内容...'));
    return loadConversation(id, { attach: true }).then(function () {
      var input = $('aiInput');
      if (input) input.focus();
    }).catch(function (error) {
      uiAlert(error.message, 'error');
    });
  }

  function newConversation() {
    // 窄屏里「新建」在会话抽屉上，点了就是要去打字，抽屉顺手收掉
    setSideOpen(false);
    stopPolling();
    state.conversationId = null;
    state.liveText = '';
    state.streamId = null;
    setStatus('');
    return createConversation({ title: '新会话' });
  }

  function renameConversation() {
    if (!state.conversationId) { uiAlert('请先选择一个会话', 'error'); return; }
    aiPrompt('会话标题', state.currentTitle || '', { title: '重命名会话' }).then(function (value) {
      var title = (value || '').trim();
      if (!title) return;
      return api('PUT', '/api/ai/conversations/' + state.conversationId, { title: title })
        .then(function () {
          updateChatTitle(title);
          return loadConversations();
        })
        .catch(function (error) { uiAlert(error.message, 'error'); });
    });
  }

  function deleteConversation() {
    if (!state.conversationId) { uiAlert('请先选择一个会话', 'error'); return; }
    uiConfirm('删除该会话及全部对话记录？此操作不可恢复。', { type: 'error', okText: '删除' })
      .then(function (confirmed) {
        if (!confirmed) return null;
        return api('DELETE', '/api/ai/conversations/' + state.conversationId).then(function () {
          var next = state.conversations.filter(function (item) {
            return String(item.id) !== String(state.conversationId);
          })[0];
          state.conversationId = null;
          clear(messageBox());
          return loadConversations().then(function () {
            if (next) return selectConversation(next.id);
            showWelcome();
            updateChatTitle('AI 运维助手');
            return null;
          });
        }).catch(function (error) { uiAlert(error.message, 'error'); });
      });
  }

  // ---------------- 消息渲染 ----------------
  function buildWelcome() {
    var wrap = node('div', 'ai-welcome');
    var welcomeIcon = node('div', 'ai-welcome-icon');
    welcomeIcon.appendChild(aiLogo());
    wrap.appendChild(welcomeIcon);
    wrap.appendChild(node('h3', 'ai-welcome-title', '我是运维助手，数据只从系统里读'));
    var list = node('ul', 'ai-welcome-list');
    [
      '只会引用工具查到的真实数据，查不到就直说「数据不足」',
      '访问与变更是否需要确认，由发送按钮左侧的访问模式决定'
    ].forEach(function (text) { list.appendChild(node('li', null, text)); });
    wrap.appendChild(list);
    var samples = node('div', 'ai-samples');
    [
      '现在一共有多少台服务器？',
      '最近一次巡检结果怎么样，有哪些异常？',
      '哪些服务器磁盘快满了？',
      '帮我重新采集 10.0.0.11 的硬件参数'
    ].forEach(function (text) {
      var button = node('button', 'ai-sample', text);
      button.type = 'button';
      button.addEventListener('click', function () {
        var input = $('aiInput');
        input.value = text;
        autoGrow(input);
        input.focus();
      });
      samples.appendChild(button);
    });
    wrap.appendChild(samples);
    return wrap;
  }

  function showWelcome() {
    var box = clear(messageBox());
    if (box) box.appendChild(buildWelcome());
  }

  function isPending(action) { return (action.status || 'pending') === 'pending'; }

  function renderMessages(rows, actions) {
    var box = clear(messageBox());
    if (!box) return;
    var visible = rows.filter(function (row) {
      if (row.role === 'system') return false;
      // 生成中的助手消息由流式区块渲染，避免出现两个空气泡
      if (row.role === 'assistant' && row.status === 'streaming') return false;
      return true;
    });
    if (!visible.length && !actions.filter(isPending).length) {
      box.appendChild(buildWelcome());
      return;
    }
    visible.forEach(function (row) { box.appendChild(buildMessage(row)); });
    var pending = actions.filter(isPending);
    if (pending.length) box.appendChild(buildActionPanel(pending));
    scrollToBottom(true);
  }

  function buildMessage(row) {
    if (row.role === 'user') {
      var user = node('div', 'ai-msg ai-msg-user');
      var userBody = node('div', 'ai-msg-body');
      userBody.appendChild(node('div', 'ai-bubble', row.content || ''));
      if (row.created_at) userBody.appendChild(node('div', 'ai-meta', row.created_at));
      user.appendChild(userBody);
      return user;
    }
    if (row.role === 'tool') return buildToolResult(row);

    var wrap = node('div', 'ai-msg ai-msg-ai');
    var avatar = node('div', 'ai-avatar');
    avatar.appendChild(aiLogo());
    wrap.appendChild(avatar);
    var body = node('div', 'ai-msg-body');
    var bubble = node('div', 'ai-bubble ai-md');

    if (row.content) {
      bubble.innerHTML = window.AiMarkdown.render(row.content);
    } else if (row.status === 'failed') {
      bubble.appendChild(node('div', 'ai-error-text', row.error || '生成失败'));
    } else if (row.status === 'canceled') {
      bubble.appendChild(node('div', 'ai-muted-text', '（已停止生成）'));
    } else {
      bubble.appendChild(node('div', 'ai-muted-text', '（没有返回内容）'));
    }
    body.appendChild(bubble);

    var meta = [];
    if (row.model) meta.push(row.model);
    if (row.status === 'failed') meta.push('失败');
    if (row.status === 'canceled') meta.push('已停止');
    if (row.prompt_tokens || row.completion_tokens) {
      meta.push('tokens ' + ((row.prompt_tokens || 0) + (row.completion_tokens || 0))
        + (row.tokens_estimated ? '（估算）' : ''));
    }
    if (row.duration_ms) meta.push((row.duration_ms / 1000).toFixed(1) + 's');
    if (row.created_at) meta.push(row.created_at);
    if (meta.length) body.appendChild(node('div', 'ai-meta', meta.join(' · ')));
    if (row.status === 'failed' && row.error && row.content) {
      body.appendChild(node('div', 'ai-error-text', row.error));
    }
    wrap.appendChild(body);
    return wrap;
  }

  function buildToolResult(row) {
    var details = node('details', 'ai-tool');
    var summary = node('summary', 'ai-tool-summary');
    var label = row.tool_name || 'tool';
    summary.appendChild(node('span', 'ai-tool-name', '🔧 ' + label));
    summary.appendChild(node('span', 'ai-tool-state' + (row.status === 'pending' ? ' is-pending' : ''),
      row.status === 'pending' ? '需要确认' : '已执行'));
    details.appendChild(summary);
    if (row.status === 'pending') {
      details.appendChild(node('div', 'ai-tool-hint',
        'AI 只提交了确认单，没有执行任何命令。确认入口在下方卡片里。'));
    }
    var payload = row.content || '';
    var pretty = payload;
    try { pretty = JSON.stringify(JSON.parse(payload), null, 2); } catch (error) { pretty = payload; }
    details.appendChild(node('pre', 'ai-tool-pre', pretty));
    return details;
  }

  function riskLabel(level) {
    if (level === 'high') return '高风险';
    if (level === 'medium') return '中风险';
    return '低风险';
  }

  function buildActionPanel(actions) {
    var panel = node('div', 'ai-action-panel');
    panel.appendChild(node('div', 'ai-action-panel-title', '需要你的确认'));
    actions.forEach(function (action) { panel.appendChild(buildActionCard(action)); });
    return panel;
  }

  function buildActionCard(action) {
    var card = node('div', 'ai-action-card ai-risk-' + (action.risk_level || 'medium'));
    var head = node('div', 'ai-action-head');
    head.appendChild(node('span', 'ai-risk-tag', riskLabel(action.risk_level)));
    head.appendChild(node('strong', 'ai-action-summary', action.summary || action.action_type || '操作'));
    card.appendChild(head);
    var meta = ['类型：' + (action.action_type || '-')];
    if (action.requested_by) meta.push('发起人：' + action.requested_by);
    if (action.expires_at) meta.push('过期时间：' + action.expires_at);
    card.appendChild(node('div', 'ai-action-meta', meta.join(' · ')));

    var payload = action.payload || {};
    var display = action.display || {};
    var isRemoteCommand = action.action_type === 'run_remote_command';
    var isServiceRestart = action.action_type === 'restart_registered_service';
    var targetText = display.target || '';
    if (!targetText && isServiceRestart) {
      var targetParts = [];
      if (payload.service_name) targetParts.push('服务：' + payload.service_name);
      var serverText = payload.server_name || '';
      if (payload.server_ip) serverText += (serverText ? '（' + payload.server_ip + '）' : payload.server_ip);
      if (serverText) targetParts.push('目标服务器：' + serverText);
      targetText = targetParts.join(' · ');
    }
    if (targetText) {
      card.appendChild(node('div', 'ai-action-target', targetText));
    }

    var displayCommand = display.command ||
      ((isRemoteCommand || isServiceRestart) ? payload.command : '');
    if (displayCommand) {
      var commandBox = node('div', 'ai-action-command');
      commandBox.appendChild(node('div', 'ai-action-command-label', display.command_label ||
        (isServiceRestart ? '即将执行的已登记重启命令' : '即将执行的命令')));
      commandBox.appendChild(node('code', 'ai-action-command-code', String(displayCommand)));
      card.appendChild(commandBox);
    }

    if ((display.fields || []).length) {
      var detailBox = node('div', 'ai-action-details');
      display.fields.forEach(function (item) {
        var row = node('div', 'ai-action-detail-row');
        row.appendChild(node('span', 'ai-action-detail-label', item.label || '详情'));
        row.appendChild(node('span', 'ai-action-detail-value', String(item.value == null ? '' : item.value)));
        detailBox.appendChild(row);
      });
      card.appendChild(detailBox);
    }

    var hiddenKeys = {};
    (display.hidden_keys || []).forEach(function (key) { hiddenKeys[key] = true; });
    var keys = Object.keys(payload).filter(function (key) {
      if (hiddenKeys[key]) return false;
      // 兼容旧后端返回的数据。
      if (isRemoteCommand) return key !== 'server_id' && key !== 'command';
      if (isServiceRestart) {
        return ['service_id', 'server_id', 'service_name', 'server_name', 'server_ip', 'command']
          .indexOf(key) === -1;
      }
      return true;
    });
    if (keys.length) {
      var payloadLabels = {
        keyword: '查询关键字', limit: '返回数量上限', status: '状态', days: '最近天数',
        run_id: '巡检记录', name: '名称', include_content: '读取正文', timeout: '超时时间',
        server_name: '服务器', tool_name: '工具', arguments: '调用参数', overwrite: '覆盖现有内容'
      };
      var lines = keys.map(function (key) {
        var value = payload[key];
        if (/password|passwd|private_key|passphrase|secret|token|api_key/i.test(key)) value = '***';
        if (typeof value === 'boolean') value = value ? '是' : '否';
        if (value && typeof value === 'object') value = JSON.stringify(value);
        return (payloadLabels[key] || key) + '：' + value;
      });
      card.appendChild(node('pre', 'ai-action-payload', lines.join('\n')));
    }

    if (action.action_type === 'upsert_server'
      && payload.credential_mode === 'secure_input_required') {
      var secureBox = node('div', 'ai-secure-credentials');
      secureBox.appendChild(node('div', 'ai-secure-title', '🔐 SSH 凭据仅用于本次确认，不会发送给 AI 或写入审批记录'));
      var fields = {};
      if ((payload.auth_type || 'password') === 'key') {
        var keyLabel = node('label', 'ai-secure-field');
        keyLabel.appendChild(node('span', '', 'SSH 私钥'));
        fields.private_key = document.createElement('textarea');
        fields.private_key.className = 'form-control';
        fields.private_key.rows = 5;
        fields.private_key.placeholder = '粘贴 PEM/OpenSSH 私钥';
        fields.private_key.autocomplete = 'off';
        keyLabel.appendChild(fields.private_key);
        secureBox.appendChild(keyLabel);
        var phraseLabel = node('label', 'ai-secure-field');
        phraseLabel.appendChild(node('span', '', '私钥口令（可选）'));
        fields.key_passphrase = document.createElement('input');
        fields.key_passphrase.type = 'password';
        fields.key_passphrase.className = 'form-control';
        fields.key_passphrase.autocomplete = 'new-password';
        phraseLabel.appendChild(fields.key_passphrase);
        secureBox.appendChild(phraseLabel);
      } else {
        var passwordLabel = node('label', 'ai-secure-field');
        passwordLabel.appendChild(node('span', '', 'SSH 密码'));
        fields.password = document.createElement('input');
        fields.password.type = 'password';
        fields.password.className = 'form-control';
        fields.password.autocomplete = 'new-password';
        fields.password.placeholder = '请输入 SSH 密码';
        passwordLabel.appendChild(fields.password);
        secureBox.appendChild(passwordLabel);
      }
      card._secureCredentialFields = fields;
      card.appendChild(secureBox);
    }

    var buttons = node('div', 'ai-action-buttons');
    var approve = node('button', 'btn btn-danger btn-sm', '确认');
    approve.type = 'button';
    approve.addEventListener('click', function () { approveAction(action, approve); });
    var reject = node('button', 'btn btn-secondary btn-sm', '拒绝');
    reject.type = 'button';
    reject.addEventListener('click', function () { rejectAction(action, reject); });
    buttons.appendChild(approve);
    buttons.appendChild(reject);
    card.appendChild(buttons);
    return card;
  }

  // ---------------- 流式生成 ----------------
  function ensureLiveMessage() {
    var box = messageBox();
    if (!box) return null;
    var existing = $('aiLiveMessage');
    if (existing) return existing;
    var wrap = node('div', 'ai-msg ai-msg-ai');
    wrap.id = 'aiLiveMessage';
    var avatar = node('div', 'ai-avatar');
    avatar.appendChild(aiLogo());
    wrap.appendChild(avatar);
    var body = node('div', 'ai-msg-body');
    var events = node('div', 'ai-tool-events');
    events.id = 'aiLiveEvents';
    var bubble = node('div', 'ai-bubble ai-md');
    bubble.id = 'aiLiveBubble';
    var meta = node('div', 'ai-live-meta');
    meta.id = 'aiLiveMeta';
    body.appendChild(events);
    body.appendChild(bubble);
    body.appendChild(meta);
    wrap.appendChild(body);
    box.appendChild(wrap);
    return wrap;
  }

  function renderLive(data) {
    var box = messageBox();
    if (!box) return;
    var pinned = nearBottom(box);
    ensureLiveMessage();

    var events = $('aiLiveEvents');
    if (events) {
      clear(events);
      (data.tool_events || []).forEach(function (event) {
        var chip = node('div', 'ai-tool-chip ai-chip-' + (event.status || 'ok'));
        chip.appendChild(node('span', 'ai-chip-level', event.level_label || ''));
        chip.appendChild(node('span', 'ai-chip-title', event.title || event.name || ''));
        chip.appendChild(node('span', 'ai-chip-summary', event.summary || ''));
        chip.appendChild(node('span', 'ai-chip-time', event.at || ''));
        events.appendChild(chip);
      });
      events.hidden = !(data.tool_events || []).length;
    }

    var bubble = $('aiLiveBubble');
    if (bubble) {
      if (state.liveText) {
        bubble.innerHTML = window.AiMarkdown.render(state.liveText);
      } else {
        bubble.innerHTML = '<span class="ai-typing"><i></i><i></i><i></i></span>'
          + '<span class="ai-muted-text">正在调用工具与组织结论…</span>';
      }
    }

    var meta = $('aiLiveMeta');
    if (meta) {
      var parts = [];
      if (state.liveText) parts.push('已生成 ' + state.liveText.length + ' 字');
      if (data.rounds) parts.push('第 ' + data.rounds + ' 轮');
      if (data.model) parts.push(data.model);
      meta.textContent = parts.join(' · ');
    }
    scrollToBottom(pinned || false);
  }

  function renderLivePending(actions) {
    if (!actions || !actions.length) return;
    var wrap = ensureLiveMessage();
    if (!wrap) return;
    var box = wrap.querySelector('.ai-msg-body');
    if (!box || box.querySelector('.ai-action-inline')) return;
    var panel = buildActionPanel(actions.filter(isPending));
    panel.classList.add('ai-action-inline');
    box.appendChild(panel);
  }

  function attachStream(streamId, kind, isResume) {
    if (!streamId) return;
    stopPolling();
    ensureLiveMessage();
    state.streamId = streamId;
    state.kind = kind || 'chat';
    state.offset = 0;
    state.liveText = '';
    state.pollErrors = 0;
    state.polling = true;
    var cancel = $('aiCancel');
    if (cancel) { cancel.hidden = false; cancel.disabled = false; cancel.textContent = '停止生成'; }
    setStatus('正在生成…');
    if (!isResume) setHint('模型正在读取系统数据…');
    state.pollTimer = window.setTimeout(pollOnce, 60);
  }

  function pollOnce() {
    if (!state.polling || !state.streamId) return;
    var url = '/api/ai/stream?stream_id=' + encodeURIComponent(state.streamId)
      + '&offset=' + state.offset;
    api('GET', url).then(function (data) {
      state.pollErrors = 0;
      if (data.status === 'idle') { finishStream({ status: 'done' }); return; }
      if (data.content) state.liveText += data.content;
      state.offset = data.total || state.offset;
      renderLive(data);
      renderLivePending(data.pending_actions || []);
      if (data.status === 'streaming') {
        state.pollTimer = window.setTimeout(pollOnce, POLL_MS);
        return;
      }
      finishStream(data);
    }).catch(function (error) {
      state.pollErrors += 1;
      if (state.pollErrors >= MAX_POLL_ERRORS) {
        finishStream({ status: 'failed', error: '轮询生成结果失败：' + error.message });
        return;
      }
      state.pollTimer = window.setTimeout(pollOnce, POLL_MS * 2);
    });
  }

  function stopPolling() {
    state.polling = false;
    state.pollTimer = clearTimer(state.pollTimer);
  }

  function finishStream(data) {
    stopPolling();
    state.streamId = null;
    var cancel = $('aiCancel');
    if (cancel) { cancel.hidden = true; cancel.disabled = false; }
    setStatus('');
    setHint('');
    var live = $('aiLiveMessage');
    if (live && live.parentNode) live.parentNode.removeChild(live);
    if (data && data.status === 'failed' && data.error) uiAlert(data.error, 'error');
    if (data && data.status === 'canceled') uiAlert('已停止生成', 'info');
    if (!state.conversationId) return;
    loadConversation(state.conversationId, { attach: false })
      .then(function () { return loadConversations(); })
      .catch(function (error) { uiAlert(error.message, 'error'); });
  }

  function cancelGeneration() {
    if (!state.streamId) return;
    var cancel = $('aiCancel');
    if (cancel) { cancel.disabled = true; cancel.textContent = '正在停止…'; }
    api('POST', '/api/ai/stream/cancel', { stream_id: state.streamId })
      .catch(function (error) { uiAlert(error.message, 'error'); });
  }

  // ---------------- 发送 ----------------
  function appendUserBubble(text) {
    var box = messageBox();
    if (!box) return;
    var welcome = box.querySelector('.ai-welcome');
    if (welcome) welcome.parentNode.removeChild(welcome);
    var wrap = node('div', 'ai-msg ai-msg-user');
    var body = node('div', 'ai-msg-body');
    body.appendChild(node('div', 'ai-bubble', text));
    wrap.appendChild(body);
    box.appendChild(wrap);
    scrollToBottom(true);
  }

  function sendMessage(presetText) {
    var input = $('aiInput');
    var content = (typeof presetText === 'string' ? presetText : (input ? input.value : '')).trim();
    if (!content) { uiAlert('请输入内容', 'error'); return; }
    if (state.sending || state.polling) { uiAlert('正在生成中，请稍候或先点「停止生成」', 'error'); return; }
    if (CFG.maxInputChars && content.length > CFG.maxInputChars) {
      uiAlert('提问最长 ' + CFG.maxInputChars + ' 字，请精简后再发', 'error');
      return;
    }

    var run = function () {
      if (!state.conversationId) {
        createConversation({ title: '新会话' }).then(function () {
          if (state.conversationId) sendMessage(content);
          else uiAlert('会话创建失败', 'error');
        }).catch(function (error) { uiAlert(error.message, 'error'); });
        return;
      }
      state.sending = true;
      var sendBtn = $('aiSend');
      if (sendBtn) sendBtn.disabled = true;
      if (input && typeof presetText !== 'string') { input.value = ''; autoGrow(input); }
      appendUserBubble(content);
      setStatus('正在生成…');
      api('POST', '/api/ai/conversations/' + state.conversationId + '/messages', {
        content: content,
        provider_id: currentProviderId(),
        access_mode: currentAccessMode()
      }).then(function (data) {
        updateChatTitle(data.conversation_title || state.currentTitle);
        if (data.fallback) setHint('已切换传统运维规则引擎，未调用大模型');
        else if (data.tools_enabled === false) setHint('该模型未开启工具调用，只能基于系统快照回答');
        attachStream(data.stream_id, 'chat', false);
        loadConversations().catch(function () {});
      }).catch(function (error) {
        uiAlert(error.message, 'error');
        setStatus('');
        return loadConversation(state.conversationId, { attach: true }).catch(function () {});
      }).finally(function () {
        state.sending = false;
        if (sendBtn) sendBtn.disabled = false;
      });
    };
    run();
  }

  function autoGrow(input) {
    if (!input) return;
    input.style.height = 'auto';
    input.style.height = Math.min(200, Math.max(64, input.scrollHeight)) + 'px';
  }

  // ---------------- 会话内确认操作 ----------------
  function approveAction(action, button) {
    var high = action.risk_level === 'high';
    var message = '将确认：' + (action.summary || action.action_type)
      + '\n\n确认前请自行核对目标正确。结果会写入审计日志。';
    uiConfirm(message, { type: high ? 'error' : 'info', okText: '确认' })
      .then(function (confirmed) {
        if (!confirmed) return null;
        var requestBody = {};
        if (action.action_type === 'upsert_server'
          && action.payload && action.payload.credential_mode === 'secure_input_required') {
          var card = button && button.closest ? button.closest('.ai-action-card') : null;
          var fields = card && card._secureCredentialFields ? card._secureCredentialFields : {};
          if ((action.payload.auth_type || 'password') === 'key') {
            requestBody.private_key = fields.private_key ? fields.private_key.value : '';
            requestBody.key_passphrase = fields.key_passphrase ? fields.key_passphrase.value : '';
            if (!requestBody.private_key.trim()) {
              uiAlert('请先填写 SSH 私钥', 'error');
              return null;
            }
          } else {
            requestBody.password = fields.password ? fields.password.value : '';
            if (!requestBody.password) {
              uiAlert('请先填写 SSH 密码', 'error');
              return null;
            }
          }
        }
        if (button) { button.disabled = true; button.textContent = '处理中…'; }
        return api('POST', '/api/ai/actions/' + action.id + '/approve', requestBody).then(function (data) {
          if (data.ok) uiAlert(data.result || '已执行', 'success');
          else uiAlert(data.msg || data.error || '执行失败', 'error');
          if (data.resume && data.resume.stream_id) {
            attachStream(data.resume.stream_id, 'chat', true);
          } else if (data.resume && data.resume.ok === false) {
            setHint('操作已完成，但 AI 续跑失败：' + (data.resume.message || ''));
          }
          return refreshAfterAction();
        }).catch(function (error) {
          uiAlert(error.message, 'error');
          if (button) { button.disabled = false; button.textContent = '确认'; }
        });
      });
  }

  function rejectAction(action, button) {
    aiPrompt('拒绝原因（可留空，AI 会看到你拒绝了这次操作）', '', {
      title: '拒绝操作', okText: '拒绝'
    }).then(function (reason) {
      if (reason === null) return null;
      if (button) { button.disabled = true; button.textContent = '处理中…'; }
      return api('POST', '/api/ai/actions/' + action.id + '/reject', { reason: reason })
        .then(function (data) {
          uiAlert('已拒绝，未执行任何操作', 'success');
          if (data.resume && data.resume.stream_id) attachStream(data.resume.stream_id, 'chat', true);
          return refreshAfterAction();
        }).catch(function (error) {
          uiAlert(error.message, 'error');
          if (button) { button.disabled = false; button.textContent = '拒绝'; }
        });
    });
  }

  function refreshAfterAction() {
    return loadConversations().then(function () {
      if (state.conversationId) return loadConversation(state.conversationId, { attach: false });
      return null;
    });
  }

  // ---------------- Skills 管理 ----------------
  function openSkillsDialog() {
    openOverlay('aiSkillsOverlay');
    loadSkills();
  }

  function loadSkills() {
    var list = clear($('aiSkillsList'));
    var detail = clear($('aiSkillDetail'));
    var root = $('aiSkillsRoot');
    if (root) root.textContent = '';
    if (list) list.appendChild(node('div', 'loading', '加载中...'));
    if (detail) detail.appendChild(buildSkillEmpty('选择左侧 Skill', '查看说明文件、附加文件和用途信息'));
    return api('GET', '/api/ai/skills?limit=200').then(function (data) {
      skillsState.items = data.skills || [];
      skillsState.root = data.root || '';
      renderSkillsList(data);
      if (skillsState.items.length) return selectSkill(skillsState.items[0].name);
      clear(detail);
      if (detail) detail.appendChild(buildSkillEmpty('还没有安装 Skill', '超级管理员可以在下方添加第一个 Skill'));
      return null;
    }).catch(function (error) {
      clear(list);
      if (list) list.appendChild(node('div', 'error-state', error.message));
    });
  }

  function buildSkillEmpty(title, text) {
    var wrap = node('div', 'ai-skill-empty');
    wrap.appendChild(node('div', 'ai-skill-empty-icon', 'S'));
    wrap.appendChild(node('div', 'ai-skill-empty-title', title));
    wrap.appendChild(node('div', 'ai-skill-empty-text', text));
    return wrap;
  }

  function renderSkillsList(data) {
    var list = clear($('aiSkillsList'));
    var root = $('aiSkillsRoot');
    if (root) root.textContent = skillsState.root ? ('目录：' + skillsState.root) : '';
    if (!list) return;
    if (data.note) list.appendChild(node('div', 'ai-form-note', data.note));
    if (!skillsState.items.length) {
      list.appendChild(node('div', 'empty-state', '还没有安装 Skill'));
      return;
    }
    skillsState.items.forEach(function (item) {
      var button = node('button', 'ai-skill-item');
      button.type = 'button';
      if (item.name === skillsState.active) button.classList.add('is-active');
      var head = node('div', 'ai-skill-item-head');
      head.appendChild(node('strong', null, item.title || item.name));
      head.appendChild(node('code', 'ai-tool-row-name', item.name));
      button.appendChild(head);
      button.appendChild(node('div', 'ai-skill-item-desc', item.description || '未填写用途说明'));
      button.appendChild(node('div', 'ai-skill-item-meta',
        'SKILL.md：' + (item.skill_md_bytes || 0) + ' bytes' + (item.truncated ? ' · 列表预览已截断' : '')));
      button.addEventListener('click', function () { selectSkill(item.name); });
      list.appendChild(button);
    });
  }

  function selectSkill(name) {
    skillsState.active = name;
    renderSkillsList({ skills: skillsState.items });
    var detail = clear($('aiSkillDetail'));
    if (detail) detail.appendChild(node('div', 'loading', '读取中...'));
    return api('GET', '/api/ai/skills/' + encodeURIComponent(name) + '?limit=30000')
      .then(function (data) {
        clear(detail);
        detail.appendChild(node('div', 'ai-skill-section-label', '内容预览'));
        var head = node('div', 'ai-skill-detail-head');
        head.appendChild(node('strong', null, (data.metadata && data.metadata.name) || data.name));
        head.appendChild(node('code', 'ai-tool-row-name', data.name));
        detail.appendChild(head);
        var files = (data.files || []).map(function (item) {
          return item.path + '（' + item.bytes + ' bytes）';
        }).join('\n');
        detail.appendChild(node('div', 'ai-skill-files', files || '没有附加文件'));
        var pre = node('pre', 'ai-skill-md');
        pre.textContent = data.skill_md || '';
        detail.appendChild(pre);
        if (data.truncated) detail.appendChild(node('div', 'ai-tool-row-reason', '内容较长，已截断显示'));
      }).catch(function (error) {
        clear(detail);
        detail.appendChild(node('div', 'error-state', error.message));
      });
  }

  function saveSkill(event) {
    if (event && event.preventDefault) event.preventDefault();
    var payload = {
      name: (($('aiSkillName') || {}).value || '').trim(),
      description: (($('aiSkillDescription') || {}).value || '').trim(),
      instructions: (($('aiSkillInstructions') || {}).value || '').trim(),
      overwrite: !!(($('aiSkillOverwrite') || {}).checked)
    };
    if (!payload.name || !payload.description || !payload.instructions) {
      uiAlert('请填写名称、用途说明和说明内容', 'error');
      return;
    }
    var button = $('aiSkillSave');
    if (button) { button.disabled = true; button.textContent = '添加中…'; }
    api('POST', '/api/ai/skills', payload).then(function () {
      uiAlert('Skill 已添加', 'success');
      setValue('aiSkillName', '');
      setValue('aiSkillDescription', '');
      setValue('aiSkillInstructions', '');
      setChecked('aiSkillOverwrite', false);
      return loadSkills();
    }).then(function () {
      if (payload.name) return selectSkill(payload.name);
      return null;
    }).catch(function (error) {
      uiAlert(error.message, 'error');
    }).finally(function () {
      if (button) { button.disabled = false; button.textContent = '添加 Skill'; }
    });
  }

  // ---------------- 能力清单 ----------------
  function openToolsDialog() {
    openOverlay('aiToolsOverlay');
    var box = clear($('aiToolsBody'));
    if (box) box.appendChild(node('div', 'loading', '加载中...'));
    api('GET', '/api/ai/tools').then(function (data) {
      clear(box);
      var summary = node('div', 'ai-tools-summary');
      summary.appendChild(node('span', 'ai-tag', '工具模式：' + (data.tool_mode || 'auto')));
      summary.appendChild(node('span', 'ai-tag is-on', '变更操作：由访问模式控制'));
      var extensionData = data.extensions || {};
      summary.appendChild(node('span', 'ai-tag',
        'MCP 扩展：' + (extensionData.total || 0) + ' 个 Server'));
      if (data.mask_ip) summary.appendChild(node('span', 'ai-tag is-on', 'IP 已脱敏'));
      box.appendChild(summary);

      var groups = {};
      var codexItems = [];
      var codexNames = {
        list_local_skills: true,
        read_local_skill: true,
        create_local_skill: true,
        list_mcp_servers: true,
        list_mcp_tools: true,
        call_mcp_tool: true
      };
      function renderToolRows(section, items) {
        items.forEach(function (tool) {
          var row = node('div', 'ai-tool-row' + (tool.available ? '' : ' is-off'));
          var head = node('div', 'ai-tool-row-head');
          head.appendChild(node('strong', null, tool.title || tool.name));
          head.appendChild(node('code', 'ai-tool-row-name', tool.name));
          if (tool.source) head.appendChild(node('span', 'ai-tool-source', tool.source));
          if (tool.risk) head.appendChild(node('span', 'ai-risk-tag', riskLabel(tool.risk)));
          head.appendChild(node('span', 'ai-tag' + (tool.available ? ' is-on' : ' is-off'),
            tool.available ? '可用' : '不可用'));
          row.appendChild(head);
          row.appendChild(node('div', 'ai-tool-row-desc', tool.description || ''));
          if (!tool.available && tool.unavailable_reason) {
            row.appendChild(node('div', 'ai-tool-row-reason', tool.unavailable_reason));
          }
          section.appendChild(row);
        });
      }
      (data.tools || []).forEach(function (tool) {
        if (codexNames[tool.name]) {
          codexItems.push(tool);
          return;
        }
        (groups[tool.level] = groups[tool.level] || []).push(tool);
      });
      if (codexItems.length) {
        var codexSection = node('div', 'ai-tools-group');
        codexSection.appendChild(node('h4', 'ai-tools-group-title',
          'Codex 风格能力（' + codexItems.length + '）'));
        renderToolRows(codexSection, codexItems);
        box.appendChild(codexSection);
      }
      ['read', 'remote', 'action'].forEach(function (level) {
        var items = groups[level] || [];
        if (!items.length) return;
        var section = node('div', 'ai-tools-group');
        section.appendChild(node('h4', 'ai-tools-group-title',
          (items[0].level_label || level) + '（' + items.length + '）'));
        renderToolRows(section, items);
        box.appendChild(section);
      });

      if (extensionData.error) {
        box.appendChild(node('div', 'ai-tool-row-reason',
          'MCP 扩展配置读取失败：' + extensionData.error));
      }
      (extensionData.servers || []).forEach(function (server) {
        var section = node('div', 'ai-tools-group ai-mcp-group');
        var title = 'MCP / 扩展白名单：' + (server.title || server.name)
          + '（' + (server.allowlist_count || 0) + '）';
        section.appendChild(node('h4', 'ai-tools-group-title', title));
        if (server.description) {
          section.appendChild(node('div', 'ai-mcp-server-desc', server.description));
        }
        var extensionTools = (server.tools || []).map(function (tool) {
          var item = Object.assign({}, tool);
          item.source = 'MCP · ' + server.name;
          return item;
        });
        if (extensionTools.length) {
          renderToolRows(section, extensionTools);
        } else {
          section.appendChild(node('div', 'ai-tool-row is-off',
            '未配置 allowed_tools；该 Server 默认禁止全部工具调用。'));
        }
        box.appendChild(section);
      });
    }).catch(function (error) {
      clear(box);
      box.appendChild(node('div', 'error-state', error.message));
    });
  }

  // ---------------- 模型配置 ----------------
  function renderProviderForm(id) {
    var list = $('aiProviderList');
    var form = $('aiProviderForm');
    if (!list) return;
    clear(list);
    if (!state.providers.length) {
      list.appendChild(node('div', 'empty-state', '还没有模型配置'));
    }
    state.providers.forEach(function (item) {
      var row = node('button', 'ai-provider-item');
      row.type = 'button';
      if (String(item.id) === String(id)) row.classList.add('is-active');
      var head = node('div', 'ai-provider-item-head');
      head.appendChild(node('strong', null, item.name));
      if (item.is_default) head.appendChild(node('span', 'ai-tag is-on', '默认'));
      if (!item.enabled) head.appendChild(node('span', 'ai-tag is-off', '已停用'));
      head.appendChild(node('span', 'ai-tag', item.deployment === 'local' ? '本地' : '云端'));
      row.appendChild(head);
      row.appendChild(node('div', 'ai-provider-item-meta',
        item.model + (item.base_url ? ' · ' + item.base_url : '')));
      row.appendChild(node('div', 'ai-provider-item-meta',
        'API Key：' + (item.has_key ? '已保存（不可回显）' : '未保存')
        + (item.last_test_ok === true ? ' · 连接正常' : (item.last_test_ok === false ? ' · 连接失败' : ''))));
      row.addEventListener('click', function () { fillProviderForm(item.id); });
      list.appendChild(row);
    });
    if (form) form.hidden = CFG.role !== 'admin';
    // 非管理员只看得到列表（后端返回的字段里本来就没有地址与参数）。
    fillProviderForm(CFG.role === 'admin' ? id : null);
  }

  function fillProviderForm(id) {
    providerEditing.id = id || null;
    var item = state.providers.filter(function (row) { return String(row.id) === String(id); })[0];
    setValue('aiPfName', item ? item.name : '');
    setValue('aiPfBaseUrl', item ? item.base_url : '');
    setValue('aiPfModel', item ? item.model : '');
    setValue('aiPfDeployment', item ? item.deployment : 'local');
    setValue('aiPfApiKey', '');
    setValue('aiPfTemperature', item && item.temperature !== null ? item.temperature : '0.2');
    setValue('aiPfMaxTokens', item && item.max_tokens ? item.max_tokens : '2048');
    setValue('aiPfTimeout', item && item.timeout ? item.timeout : '120');
    setValue('aiPfHeaders', item ? (item.extra_headers || '') : '');
    setChecked('aiPfSupportsTools', item ? !!item.supports_tools : true);
    setChecked('aiPfEnabled', item ? !!item.enabled : true);
    setChecked('aiPfDefault', item ? !!item.is_default : !state.providers.length);
    var hint = $('aiPfHint');
    if (hint) {
      hint.textContent = item
        ? '（API Key ' + (item.key_hint || (item.has_key ? '已保存' : '未保存'))
          + '；留空表示不修改）'
        : '（新建配置）';
    }
    var del = $('aiPfDelete');
    if (del) del.hidden = !item;
    var def = $('aiPfSetDefault');
    if (def) def.hidden = !item || !!item.is_default;
    var list = $('aiProviderList');
    if (list) {
      Array.prototype.forEach.call(list.children, function (child) {
        child.classList.remove('is-active');
      });
      if (item) {
        var index = state.providers.indexOf(item);
        if (list.children[index]) list.children[index].classList.add('is-active');
      }
    }
  }

  function setValue(id, value) {
    var el = $(id);
    if (el) el.value = value === null || value === undefined ? '' : String(value);
  }

  function setChecked(id, value) {
    var el = $(id);
    if (el) el.checked = !!value;
  }

  function collectProviderPayload() {
    var payload = {
      name: ($('aiPfName') || {}).value,
      base_url: ($('aiPfBaseUrl') || {}).value,
      model: ($('aiPfModel') || {}).value,
      deployment: ($('aiPfDeployment') || {}).value,
      temperature: ($('aiPfTemperature') || {}).value,
      max_tokens: ($('aiPfMaxTokens') || {}).value,
      timeout: ($('aiPfTimeout') || {}).value,
      supports_tools: !!($('aiPfSupportsTools') || {}).checked,
      enabled: !!($('aiPfEnabled') || {}).checked,
      is_default: !!($('aiPfDefault') || {}).checked
    };
    var headers = (($('aiPfHeaders') || {}).value || '').trim();
    if (headers) payload.extra_headers = headers;
    var apiKey = (($('aiPfApiKey') || {}).value || '').trim();
    if (apiKey) payload.api_key = apiKey;
    return payload;
  }

  function saveProvider() {
    var payload = collectProviderPayload();
    var editing = providerEditing.id;
    var request = editing
      ? api('PUT', '/api/ai/providers/' + editing, payload)
      : api('POST', '/api/ai/providers', payload);
    request.then(function (data) {
      uiAlert('已保存', 'success');
      providerEditing.id = data.provider ? data.provider.id : editing;
      return loadProviders();
    }).catch(function (error) { uiAlert(error.message, 'error'); });
  }

  function testProvider() {
    if (!providerEditing.id) { uiAlert('请先保存配置，再测试连接', 'error'); return; }
    var button = $('aiPfTest');
    if (button) { button.disabled = true; button.textContent = '测试中…'; }
    api('POST', '/api/ai/providers/' + providerEditing.id + '/test').then(function (data) {
      uiAlert(data.message || (data.ok ? '连接成功' : '连接失败'), data.ok ? 'success' : 'error');
      return loadProviders();
    }).catch(function (error) {
      uiAlert(error.message, 'error');
      return loadProviders();
    }).finally(function () {
      if (button) { button.disabled = false; button.textContent = '测试连接'; }
    });
  }

  function fetchModels() {
    if (!providerEditing.id) { uiAlert('请先保存配置，再拉取模型列表', 'error'); return; }
    var button = $('aiPfModels');
    if (button) { button.disabled = true; button.textContent = '拉取中…'; }
    api('GET', '/api/ai/models?provider_id=' + providerEditing.id).then(function (data) {
      var models = data.models || [];
      var list = $('aiModelOptions');
      if (list) {
        clear(list);
        models.forEach(function (name) {
          var option = node('option');
          option.value = name;
          list.appendChild(option);
        });
      }
      uiAlert(models.length ? ('拉到 ' + models.length + ' 个模型，已在模型名称输入框里给出候选')
        : '接口没有返回模型列表，请手动填写模型名称', 'info');
    }).catch(function (error) {
      uiAlert(error.message, 'error');
    }).finally(function () {
      if (button) { button.disabled = false; button.textContent = '拉取模型'; }
    });
  }

  function deleteProvider() {
    if (!providerEditing.id) return;
    uiConfirm('删除该模型配置？已保存的 API Key 也会一并删除。', { type: 'error', okText: '删除' })
      .then(function (confirmed) {
        if (!confirmed) return null;
        return api('DELETE', '/api/ai/providers/' + providerEditing.id).then(function () {
          uiAlert('已删除', 'success');
          providerEditing.id = null;
          return loadProviders();
        }).catch(function (error) { uiAlert(error.message, 'error'); });
      });
  }

  function setDefaultProvider() {
    if (!providerEditing.id) return;
    api('POST', '/api/ai/providers/' + providerEditing.id + '/default').then(function () {
      uiAlert('已设为默认模型', 'success');
      return loadProviders();
    }).catch(function (error) { uiAlert(error.message, 'error'); });
  }

  // ---------------- 巡检解读 ----------------
  function loadInsightPage() {
    var result = clear($('aiInsightResult'));
    if (result) result.appendChild(node('div', 'ai-insight-placeholder',
      '请先选择巡检单，然后生成解读；也可从下方查看历史解读。'));
    var select = clear($('aiInsightRun'));
    if (select) {
      var loadingOption = node('option', null, '单击选择巡检单');
      loadingOption.value = '';
      loadingOption.selected = true;
      select.appendChild(loadingOption);
      select.disabled = true;
    }
    loadInsightHistory();
    api('GET', '/api/inspection_runs?limit=30').then(function (runs) {
      if (!select) return;
      clear(select);
      var placeholder = node('option', null, '单击选择巡检单');
      placeholder.value = '';
      placeholder.selected = true;
      select.appendChild(placeholder);
      if (!runs.length) {
        var emptyOption = node('option', null, '还没有巡检记录');
        emptyOption.disabled = true;
        select.appendChild(emptyOption);
        return;
      }
      runs.forEach(function (run) {
        var option = node('option', null,
          (run.task_name || run.run_id) + ' · ' + (run.status || '') + ' · ' + (run.created_at || ''));
        option.value = run.run_id;
        select.appendChild(option);
      });
    }).catch(function (error) {
      if (select) {
        clear(select);
        var failedOption = node('option', null, '巡检单加载失败：' + error.message);
        failedOption.value = '';
        select.appendChild(failedOption);
      }
    }).finally(function () {
      if (select) select.disabled = false;
    });
  }

  function loadInsightHistory() {
    var box = clear($('aiInsightHistory'));
    if (box) box.appendChild(node('div', 'loading', '加载中...'));
    api('GET', '/api/ai/insights').then(function (data) {
      var items = data.insights || [];
      clear(box);
      if (!items.length) {
        box.appendChild(node('div', 'empty-state', '还没有 AI 解读记录'));
        return;
      }
      items.forEach(function (item) {
        var row = node('div', 'ai-insight-item');
        row.appendChild(node('div', 'ai-insight-item-head',
          (item.run_id || '未知巡检') + ' · ' + (item.model || '') + ' · ' + (item.created_at || '')));
        var button = node('button', 'btn btn-outline btn-sm', '查看');
        button.type = 'button';
        button.addEventListener('click', function () { showInsight(item.id); });
        row.appendChild(button);
        box.appendChild(row);
      });
    }).catch(function (error) {
      clear(box);
      box.appendChild(node('div', 'error-state', error.message));
    });
  }

  function showInsight(id) {
    var box = clear($('aiInsightResult'));
    if (box) box.appendChild(node('div', 'loading', '加载中...'));
    api('GET', '/api/ai/insights?id=' + id).then(function (data) {
      var item = (data.insights || [])[0];
      if (!item) throw new Error('解读记录不存在');
      clear(box);
      box.appendChild(node('div', 'ai-insight-meta',
        '巡检：' + (item.run_id || '-') + ' · 模型：' + (item.model || '-') + ' · ' + (item.created_at || '')));
      if (item.status !== 'done' && item.error) {
        box.appendChild(node('div', 'ai-error-text', item.error));
      }
      var body = node('div', 'ai-md ai-insight-body');
      body.innerHTML = window.AiMarkdown.render(item.content || '');
      box.appendChild(body);
    }).catch(function (error) {
      clear(box);
      box.appendChild(node('div', 'error-state', error.message));
    });
  }

  function generateInsight() {
    var select = $('aiInsightRun');
    var runId = select ? select.value : '';
    if (!runId) { uiAlert('请先选择一次巡检记录', 'error'); return; }
    var button = $('aiInsightGenerate');
    if (button) { button.disabled = true; button.textContent = '生成中…'; }
    var box = clear($('aiInsightResult'));
    if (box) box.appendChild(node('div', 'loading', '正在生成解读...'));
    insight.text = '';
    insight.offset = 0;
    insight.errors = 0;
    insight.runId = runId;
    api('POST', '/api/ai/insights', { run_id: runId, provider_id: currentProviderId() })
      .then(function (data) {
        insight.streamId = data.stream_id;
        insight.timer = window.setTimeout(pollInsight, 60);
      })
      .catch(function (error) {
        uiAlert(error.message, 'error');
        if (box) { clear(box); box.appendChild(node('div', 'error-state', error.message)); }
        if (button) { button.disabled = false; button.textContent = '生成解读'; }
      });
  }

  function pollInsight() {
    if (!insight.streamId) return;
    api('GET', '/api/ai/stream?stream_id=' + encodeURIComponent(insight.streamId) + '&offset=' + insight.offset)
      .then(function (data) {
        insight.errors = 0;
        if (data.content) insight.text += data.content;
        insight.offset = data.total || insight.offset;
        var box = $('aiInsightResult');
        if (box) box.innerHTML = window.AiMarkdown.render(insight.text
          || '正在读取巡检数据…');
        if (data.status === 'streaming') {
          insight.timer = window.setTimeout(pollInsight, POLL_MS);
          return;
        }
        stopInsightPolling();
        var button = $('aiInsightGenerate');
        if (button) { button.disabled = false; button.textContent = '生成解读'; }
        if (data.status === 'failed' && data.error) uiAlert(data.error, 'error');
        loadInsightHistory();
      }).catch(function (error) {
        insight.errors += 1;
        if (insight.errors >= MAX_POLL_ERRORS) {
          stopInsightPolling();
          var box = $('aiInsightResult');
          if (box) { clear(box); box.appendChild(node('div', 'error-state', error.message)); }
          var button = $('aiInsightGenerate');
          if (button) { button.disabled = false; button.textContent = '生成解读'; }
          return;
        }
        insight.timer = window.setTimeout(pollInsight, POLL_MS * 2);
      });
  }

  function stopInsightPolling() {
    insight.timer = clearTimer(insight.timer);
    insight.streamId = null;
  }

  // ---------------- 用量 ----------------
  function loadUsage(by) {
    var box = clear($('aiUsageBody'));
    if (box) box.appendChild(node('div', 'loading', '加载中...'));
    api('GET', '/api/ai/usage?days=30&by=' + encodeURIComponent(by || 'model')).then(function (data) {
      clear(box);
      var head = node('div', 'ai-tools-summary');
      head.appendChild(node('span', 'ai-tag', '近 ' + data.days + ' 天'));
      head.appendChild(node('span', 'ai-tag is-on', '今日 tokens：' + (data.today_total || 0)));
      if (data.daily_limit) {
        head.appendChild(node('span', 'ai-tag', '每日上限：' + data.daily_limit));
      }
      box.appendChild(head);

      var toggles = node('div', 'ai-usage-toggles');
      [['model', '按模型'], ['user', '按用户']].forEach(function (pair) {
        var button = node('button', 'btn btn-outline btn-sm' + (by === pair[0] ? ' is-active' : ''), pair[1]);
        button.type = 'button';
        button.addEventListener('click', function () { loadUsage(pair[0]); });
        toggles.appendChild(button);
      });
      box.appendChild(toggles);

      if (!(data.items || []).length) {
        box.appendChild(node('div', 'empty-state', '这段时间还没有调用记录'));
        return;
      }
      var table = node('table', 'data-table ai-usage-table');
      var thead = node('thead');
      var headRow = node('tr');
      ['日期', by === 'user' ? '用户' : '模型', '调用次数', '输入 tokens', '输出 tokens'].forEach(function (text) {
        headRow.appendChild(node('th', null, text));
      });
      thead.appendChild(headRow);
      table.appendChild(thead);
      var tbody = node('tbody');
      data.items.forEach(function (item) {
        var row = node('tr');
        row.appendChild(node('td', null, item.day || ''));
        row.appendChild(node('td', null, item.target || ''));
        row.appendChild(node('td', null, item.calls || 0));
        row.appendChild(node('td', null, item.prompt_tokens || 0));
        row.appendChild(node('td', null, item.completion_tokens || 0));
        tbody.appendChild(row);
      });
      table.appendChild(tbody);
      var wrapper = node('div', 'table-wrapper');
      wrapper.appendChild(table);
      box.appendChild(wrapper);
    }).catch(function (error) {
      clear(box);
      box.appendChild(node('div', 'error-state', error.message));
    });
  }

  // ---------------- 事件绑定 ----------------
  function bindStaticHandlers() {
    var send = $('aiSend');
    if (send) send.addEventListener('click', function () { sendMessage(); });

    var cancel = $('aiCancel');
    if (cancel) cancel.addEventListener('click', cancelGeneration);

    var input = $('aiInput');
    if (input) {
      input.addEventListener('input', function () { autoGrow(input); });
      input.addEventListener('keydown', function (event) {
        if (event.key !== 'Enter' || event.shiftKey) return;
        if (event.isComposing || event.keyCode === 229) return;
        event.preventDefault();
        sendMessage();
      });
    }

    bindClick('aiNewConversation', newConversation);
    bindClick('aiRenameConversation', renameConversation);
    bindClick('aiDeleteConversation', deleteConversation);
    bindClick('aiOpenSkills', openSkillsDialog);
    bindClick('aiOpenTools', openToolsDialog);
    bindClick('aiSideToggle', function () { setSideOpen(!sideIsOpen()); });

    var providerSelect = $('aiProviderSelect');
    if (providerSelect) {
      providerSelect.addEventListener('change', function () {
        state.providerId = currentProviderId();
        renderProviderNote();
      });
    }

    var accessSelect = $('aiAccessMode');
    if (accessSelect) {
      var savedAccess = localStorage.getItem('aiAccessMode') || 'change';
      if (/^(limited|change|full)$/.test(savedAccess)) accessSelect.value = savedAccess;
      accessSelect.addEventListener('change', function () {
        localStorage.setItem('aiAccessMode', currentAccessMode());
      });
    }

    bindClose('aiSkillsClose', 'aiSkillsOverlay');
    bindClick('aiSkillsRefresh', loadSkills);
    var skillForm = $('aiSkillForm');
    if (skillForm) skillForm.addEventListener('submit', saveSkill);
    bindClose('aiToolsClose', 'aiToolsOverlay');
    bindClick('aiInsightGenerate', generateInsight);
    bindClick('aiInsightRefresh', loadInsightHistory);

    if (CFG.role === 'admin') {
      bindClick('aiPfNew', function () {
        providerEditing.id = null;
        fillProviderForm(null);
      });
      bindClick('aiPfSave', saveProvider);
      bindClick('aiPfTest', testProvider);
      bindClick('aiPfModels', fetchModels);
      bindClick('aiPfDelete', deleteProvider);
      bindClick('aiPfSetDefault', setDefaultProvider);
    }

    if ($('aiWorkspace')) {
      fitWorkspace();
      window.addEventListener('resize', fitWorkspace);
      window.addEventListener('orientationchange', fitWorkspace);
    }
  }

  function bindClick(id, handler) {
    var el = $(id);
    if (el) el.addEventListener('click', handler);
  }

  function bindClose(buttonId, overlayId) {
    var el = $(buttonId);
    if (el) el.addEventListener('click', function () { closeOverlay(overlayId); });
  }

  // ---------------- 启动 ----------------
  function boot() {
    bindStaticHandlers();
    if (!CFG.enabled) return;
    if (CFG.page === 'models') {
      loadProviders().catch(function (error) { uiAlert(error.message, 'error'); });
      return;
    }
    if (CFG.page === 'usage') {
      loadUsage('model');
      return;
    }
    if (CFG.page === 'insights') {
      loadProviders().catch(function () { return null; });
      loadInsightPage();
      return;
    }
    Promise.all([loadProviders(), loadConversations()])
      .then(function () {
        var params = new URLSearchParams(location.search);
        var wanted = parseInt(params.get('conversation'), 10);
        var target = null;
        if (wanted) {
          target = state.conversations.filter(function (item) { return item.id === wanted; })[0] || null;
        }
        if (!target) target = state.conversations[0] || null;
        if (target) return selectConversation(target.id);
        showWelcome();
        updateChatTitle('AI 运维助手');
        return null;
      })
      .catch(function (error) {
        uiAlert(error.message, 'error');
      });
  }

  function cleanup() {
    stopPolling();
    stopInsightPolling();
    state.sending = false;
  }

  // shell 局部换页时先清理上一个实例，避免定时器叠加。
  if (window.__aiPageCleanup) {
    try { window.__aiPageCleanup(); } catch (error) { /* 忽略旧实例清理异常 */ }
  }
  window.__aiPageCleanup = cleanup;
  document.addEventListener('lingtu:before-unmount', cleanup);

  boot();
})();
