// 为所有修改请求自动添加 CSRF 令牌。
(function configureRequestSecurity() {
  var meta = document.querySelector('meta[name="csrf-token"]');
  if (!meta) return;
  var token = meta.getAttribute('content');
  if (window.axios) {
    window.axios.defaults.headers.common['X-CSRFToken'] = token;
  }
  if (window.fetch) {
    var originalFetch = window.fetch;
    window.fetch = function(input, options) {
      var requestOptions = options ? Object.assign({}, options) : {};
      var method = (requestOptions.method || 'GET').toUpperCase();
      if (['POST', 'PUT', 'PATCH', 'DELETE'].indexOf(method) !== -1) {
        var headers = new Headers(requestOptions.headers || {});
        headers.set('X-CSRFToken', token);
        requestOptions.headers = headers;
      }
      return originalFetch.call(window, input, requestOptions);
    };
  }
})();

// 全局玻璃拟态提示框，替代浏览器原生 alert / confirm。
(function initGlassDialogs() {
  function inferType(message) {
    var text = String(message || '');
    if (/失败|错误|异常|至少|请输入|不允许|必须/.test(text)) return 'error';
    if (/成功|完成|已保存|已删除|已更新/.test(text)) return 'success';
    return 'info';
  }

  function showDialog(options) {
    options = options || {};
    return new Promise(function(resolve) {
      var type = options.type || 'info';
      var isConfirm = !!options.confirm;
      var overlay = document.createElement('div');
      overlay.className = 'glass-dialog-overlay';

      var dialog = document.createElement('div');
      dialog.className = 'glass-dialog glass-dialog-' + type;
      dialog.setAttribute('role', 'alertdialog');
      dialog.setAttribute('aria-modal', 'true');

      var icon = document.createElement('div');
      icon.className = 'glass-dialog-icon';
      icon.textContent = type === 'success' ? '✓' : (type === 'error' ? '!' : (isConfirm ? '?' : 'i'));

      var content = document.createElement('div');
      content.className = 'glass-dialog-content';
      var title = document.createElement('div');
      title.className = 'glass-dialog-title';
      title.textContent = options.title || (isConfirm ? '请确认' : (type === 'success' ? '操作成功' : (type === 'error' ? '提示' : '系统提示')));
      var message = document.createElement('div');
      message.className = 'glass-dialog-message';
      message.textContent = String(options.message || '');
      content.appendChild(title);
      content.appendChild(message);

      var actions = document.createElement('div');
      actions.className = 'glass-dialog-actions';
      var cancelButton = null;
      if (isConfirm) {
        cancelButton = document.createElement('button');
        cancelButton.type = 'button';
        cancelButton.className = 'glass-dialog-btn glass-dialog-btn-secondary';
        cancelButton.textContent = options.cancelText || '取消';
        actions.appendChild(cancelButton);
      }
      var okButton = document.createElement('button');
      okButton.type = 'button';
      okButton.className = 'glass-dialog-btn glass-dialog-btn-primary';
      okButton.textContent = options.okText || (isConfirm ? '确认' : '知道了');
      actions.appendChild(okButton);

      dialog.appendChild(icon);
      dialog.appendChild(content);
      dialog.appendChild(actions);
      overlay.appendChild(dialog);
      document.body.appendChild(overlay);

      var settled = false;
      function close(result) {
        if (settled) return;
        settled = true;
        document.removeEventListener('keydown', onKeydown);
        overlay.classList.add('is-closing');
        window.setTimeout(function() {
          if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
          resolve(result);
        }, 160);
      }
      function onKeydown(event) {
        if (event.key === 'Escape') close(false);
        if (event.key === 'Enter') close(true);
      }
      okButton.addEventListener('click', function() { close(true); });
      if (cancelButton) cancelButton.addEventListener('click', function() { close(false); });
      overlay.addEventListener('click', function(event) {
        if (event.target === overlay && isConfirm) close(false);
      });
      document.addEventListener('keydown', onKeydown);
      window.setTimeout(function() {
        overlay.classList.add('is-visible');
        okButton.focus();
      }, 10);
    });
  }

  window.uiAlert = function(message, type, title) {
    return showDialog({ message: message, type: type || inferType(message), title: title });
  };
  window.uiConfirm = function(message, options) {
    options = options || {};
    options.message = message;
    options.confirm = true;
    options.type = options.type || 'info';
    return showDialog(options);
  };
  window.alert = function(message) { return window.uiAlert(message); };
})();

function showSidebar() {
  var sidebar = document.getElementById('sidebar');
  sidebar.classList.remove('collapsed');
}

// 初始化selected类 - 兼容低版本浏览器
function initSelectedStates() {
  // 初始化format-option的selected状态
  var formatOptions = document.querySelectorAll('.format-option');
  for (var i = 0; i < formatOptions.length; i++) {
    var radio = formatOptions[i].querySelector('input[type="radio"]');
    if (radio && radio.checked) {
      formatOptions[i].classList.add('selected');
    }
  }
  
  // 初始化inspect-format-option的selected状态
  var inspectFormatOptions = document.querySelectorAll('.inspect-format-option');
  for (var j = 0; j < inspectFormatOptions.length; j++) {
    var radio = inspectFormatOptions[j].querySelector('input[type="radio"]');
    if (radio && radio.checked) {
      inspectFormatOptions[j].classList.add('selected');
    }
  }
  
  // 初始化inspect-checkbox-item的selected状态
  var checkboxItems = document.querySelectorAll('.inspect-checkbox-item');
  for (var k = 0; k < checkboxItems.length; k++) {
    var checkbox = checkboxItems[k].querySelector('input[type="checkbox"]');
    if (checkbox && checkbox.checked) {
      checkboxItems[k].classList.add('selected');
    }
  }
}

// 监听radio和checkbox变化更新selected类
function initSelectionListeners() {
  // 监听所有radio按钮
  var radios = document.querySelectorAll('input[type="radio"]');
  for (var i = 0; i < radios.length; i++) {
    radios[i].addEventListener('change', function() {
      var name = this.name;
      var container = this.closest('.format-option, .inspect-format-option');
      
      // 移除同组其他项的selected类
      var siblings = document.querySelectorAll('input[name="' + name + '"]');
      for (var j = 0; j < siblings.length; j++) {
        var siblingContainer = siblings[j].closest('.format-option, .inspect-format-option');
        if (siblingContainer) {
          siblingContainer.classList.remove('selected');
        }
      }
      
      // 添加当前项的selected类
      if (container) {
        container.classList.add('selected');
      }
    });
  }
  
  // 监听所有checkbox按钮
  var checkboxes = document.querySelectorAll('input[type="checkbox"]');
  for (var k = 0; k < checkboxes.length; k++) {
    checkboxes[k].addEventListener('change', function() {
      var container = this.closest('.inspect-checkbox-item');
      if (container) {
        if (this.checked) {
          container.classList.add('selected');
        } else {
          container.classList.remove('selected');
        }
      }
    });
  }
}

// 全局辅助函数
function log(msg) {
  var el = document.getElementById('logBox');
  if (el) {
    el.textContent += msg + "\n";
    el.scrollTop = el.scrollHeight;
  }
}

function setProgress(v) {
  var bar = document.getElementById('progressBar');
  var percent = document.getElementById('progressPercent');
  if (bar) {
    bar.style.width = v + "%";
  }
  if (percent) {
    percent.textContent = v + "%";
  }
}

// 文档加载完成后执行
function initAppPage() {
  console.log('DOM loaded - app.js initialized');
  
  // 初始化selected状态 - 兼容低版本浏览器
  initSelectedStates();
  initSelectionListeners();
  
  // 网关代理检测启用/禁用切换
  var enableProxyCheck = document.getElementById('enableProxyCheck');
  var proxyConfig = document.getElementById('proxyConfig');
  if (enableProxyCheck && proxyConfig) {
    enableProxyCheck.addEventListener('change', function() {
      proxyConfig.style.display = this.checked ? 'block' : 'none';
      console.log('Proxy check enabled:', this.checked);
    });
  } else {
    console.log('Proxy check elements not found');
  }
  
  // 定时配置
  var enableSchedule = document.getElementById('enableSchedule');
  var scheduleConfig = document.getElementById('scheduleConfig');
  if (enableSchedule && scheduleConfig) {
    enableSchedule.addEventListener('change', function() {
      scheduleConfig.style.display = this.checked ? 'block' : 'none';
      console.log('Schedule enabled:', this.checked);
    });
  } else {
    console.log('Schedule elements not found');
  }
  
  // 添加代理检测规则
  var addProxyRuleBtn = document.getElementById('addProxyRule');
  var proxyRulesList = document.getElementById('proxyRulesList');
  if (addProxyRuleBtn && proxyRulesList) {
    addProxyRuleBtn.addEventListener('click', function() {
      var rules = proxyRulesList.querySelectorAll('.inspect-proxy-rule-row');
      var newIndex = rules.length;
      
      var newRule;
      if (rules.length > 0) {
        var firstRule = rules[0];
        newRule = firstRule.cloneNode(true);
        newRule.setAttribute('data-index', newIndex);
        
        newRule.querySelector('.proxy-group-select').value = '';
        newRule.querySelector('.proxy-curl-command').value = '';
        newRule.querySelector('.proxy-success-keyword').value = '成功';
      } else {
        newRule = document.createElement('div');
        newRule.className = 'inspect-proxy-rule-row';
        newRule.setAttribute('data-index', newIndex);
        newRule.innerHTML = [
          '<div class="inspect-proxy-rule-item">',
          '<label class="inspect-proxy-label">服务器</label>',
          '<select class="inspect-proxy-select proxy-group-select">',
          '<option value="">全部</option>',
          '</select>',
          '</div>',
          '<div class="inspect-proxy-rule-item inspect-proxy-rule-item-large">',
          '<label class="inspect-proxy-label">CURL命令</label>',
          '<input type="text" class="inspect-proxy-input proxy-curl-command" placeholder="curl -s http://127.0.0.1:8080/api/health">',
          '</div>',
          '<div class="inspect-proxy-rule-item">',
          '<label class="inspect-proxy-label">关键词</label>',
          '<input type="text" class="inspect-proxy-input-short proxy-success-keyword" value="成功" placeholder="成功">',
          '</div>',
          '<button type="button" class="inspect-btn inspect-btn-delete remove-proxy-rule" style="display: inline-flex;">',
          '删除',
          '</button>'
        ].join('');
      }
      
      proxyRulesList.appendChild(newRule);
      updateRemoveButtons();
    });
  } else {
    console.log('Add proxy rule button or list not found');
  }
  
  // 删除代理检测规则
  if (proxyRulesList) {
    proxyRulesList.addEventListener('click', function(e) {
      if (e.target.classList.contains('remove-proxy-rule')) {
        var rule = e.target.closest('.inspect-proxy-rule-row');
        if (rule) {
          rule.remove();
          updateRemoveButtons();
        }
      }
    });
  }
  
  function updateRemoveButtons() {
    var rules = proxyRulesList ? proxyRulesList.querySelectorAll('.inspect-proxy-rule-row') : null;
    if (rules) {
      for (var i = 0; i < rules.length; i++) {
        var rule = rules[i];
        var removeBtn = rule.querySelector('.remove-proxy-rule');
        if (removeBtn) {
          removeBtn.style.display = 'inline-flex';
        }
      }
    }
  }
  
  // 巡检页面逻辑
  var btnStart = document.getElementById('btnStart');
  var btnSaveTask = document.getElementById('btnSaveTask');
  
  if (btnStart) {
    console.log('btnStart found, adding click handler');
    var currentRun = null;
    var pollInterval = null;
    var lastMessage = '';
    
    function pollProgress() {
      if (!currentRun) return;
      
      axios.get('/api/inspection_progress', { params: { run_id: currentRun } })
        .then(function(resp) {
          var data = resp.data;
          if (data.message && data.message !== lastMessage) {
            log(data.message);
            lastMessage = data.message;
          }
          if (typeof data.percent === 'number') {
            setProgress(data.percent);
          }
          if (data.report_path) {
            var box = document.getElementById('downloadBox');
            box.innerHTML = '<a href="/api/download_report?path=' + encodeURIComponent(data.report_path) + '" class="btn btn-primary">下载巡检报告</a>';
            if (pollInterval) {
              clearInterval(pollInterval);
              pollInterval = null;
            }
          } else if (data.status === 'failed') {
            log('执行失败：' + (data.error || '未知错误'));
            if (pollInterval) {
              clearInterval(pollInterval);
              pollInterval = null;
            }
          }
        })
        .catch(function(error) {
          console.error('获取进度失败:', error);
        });
    }

    btnStart.addEventListener('click', function() {
      console.log('开始巡检按钮被点击');
      
      var taskName = document.getElementById('taskName').value.trim();
      var projectName = document.getElementById('projectName').value.trim();
      var inspector = document.getElementById('inspector').value.trim();
      var formatRadio = document.querySelector('input[name="reportFormat"]:checked');
      var format = formatRadio ? formatRadio.value : 'excel';
      
      var resourceGroup = document.getElementById('resourceGroup').value;
      var checkCpu = document.getElementById('checkCpu').checked;
      var checkMem = document.getElementById('checkMem').checked;
      var checkDisk = document.getElementById('checkDisk').checked;
      
      var enableProxy = document.getElementById('enableProxyCheck').checked;
      var proxyRules = [];
      if (enableProxy) {
        var ruleElements = document.querySelectorAll('.inspect-proxy-rule-row');
        for (var i = 0; i < ruleElements.length; i++) {
          var rule = ruleElements[i];
          var groupId = rule.querySelector('.proxy-group-select').value;
          var curlCmd = rule.querySelector('.proxy-curl-command').value.trim();
          var keyword = rule.querySelector('.proxy-success-keyword').value.trim() || '成功';
          if (curlCmd) {
            proxyRules.push({
              group_id: groupId,
              curl_command: curlCmd,
              success_keyword: keyword
            });
          }
        }
      }
      
      if (!taskName) {
        alert('请输入任务名称');
        return;
      }
      if (!projectName) {
        alert('请输入项目名称');
        return;
      }
      if (!inspector) {
        alert('请输入巡检人');
        return;
      }
      
      if (!checkCpu && !checkMem && !checkDisk) {
        alert('请至少选择一个资源巡检项');
        return;
      }
      
      if (enableProxy && proxyRules.length === 0) {
        alert('请至少添加一条网关代理检测规则');
        return;
      }
      
      document.getElementById('logBox').textContent = '';
      setProgress(0);
      document.getElementById('downloadBox').innerHTML = '';
      lastMessage = '';
      
      document.getElementById('progressCard').style.display = 'block';
      
      axios.post('/api/start_inspection', { 
        task_name: taskName,
        project_name: projectName, 
        inspector: inspector, 
        report_format: format,
        resource_group_id: resourceGroup,
        check_cpu: checkCpu,
        check_mem: checkMem,
        check_disk: checkDisk,
        enable_proxy: enableProxy,
        proxy_rules: proxyRules
      })
      .then(function(resp) {
        currentRun = resp.data.run_id;
        log('已开始巡检，运行ID: ' + currentRun);
        log('报告格式: ' + (format === 'excel' ? 'Excel' : 'PDF'));
        
        var resourceItems = [];
        if (checkCpu) resourceItems.push('CPU');
        if (checkMem) resourceItems.push('内存');
        if (checkDisk) resourceItems.push('磁盘');
        log('资源巡检项: ' + resourceItems.join(', '));
        log('资源巡检分组: ' + (resourceGroup ? '指定分组' : '全部服务器'));
        
        if (enableProxy) {
          log('网关代理检测: 已启用');
          log('检测规则数量: ' + proxyRules.length);
        }
        
        pollInterval = setInterval(pollProgress, 1000);
      })
      .catch(function(error) {
        var errorMsg = error.response && error.response.data && error.response.data.msg ? error.response.data.msg : error.message;
        log('错误：' + errorMsg);
      });
    });
  } else {
    console.log('btnStart not found');
  }
  
  if (btnSaveTask) {
    console.log('btnSaveTask found, adding click handler');
    btnSaveTask.addEventListener('click', function() {
      console.log('保存任务按钮被点击');
      
      var taskName = document.getElementById('taskName').value.trim();
      var projectName = document.getElementById('projectName').value.trim();
      var inspector = document.getElementById('inspector').value.trim();
      var formatRadio = document.querySelector('input[name="reportFormat"]:checked');
      var format = formatRadio ? formatRadio.value : 'excel';
      
      var resourceGroup = document.getElementById('resourceGroup').value;
      var checkCpu = document.getElementById('checkCpu').checked;
      var checkMem = document.getElementById('checkMem').checked;
      var checkDisk = document.getElementById('checkDisk').checked;
      
      var enableProxy = document.getElementById('enableProxyCheck').checked;
      var proxyRules = [];
      if (enableProxy) {
        var ruleElements = document.querySelectorAll('.inspect-proxy-rule-row');
        for (var i = 0; i < ruleElements.length; i++) {
          var rule = ruleElements[i];
          var groupId = rule.querySelector('.proxy-group-select').value;
          var curlCmd = rule.querySelector('.proxy-curl-command').value.trim();
          var keyword = rule.querySelector('.proxy-success-keyword').value.trim() || '成功';
          if (curlCmd) {
            proxyRules.push({
              group_id: groupId,
              curl_command: curlCmd,
              success_keyword: keyword
            });
          }
        }
      }
      
      var enableSchedule = document.getElementById('enableSchedule').checked;
      var scheduleTime = enableSchedule ? document.getElementById('scheduleTime').value : '';
      
      if (!taskName) {
        alert('请输入任务名称');
        return;
      }
      if (!projectName) {
        alert('请输入项目名称');
        return;
      }
      if (!inspector) {
        alert('请输入巡检人');
        return;
      }
      
      axios.post('/api/save_task', {
        task_name: taskName,
        project_name: projectName,
        inspector: inspector,
        report_format: format,
        resource_group_id: resourceGroup,
        check_cpu: checkCpu,
        check_mem: checkMem,
        check_disk: checkDisk,
        enable_proxy: enableProxy,
        proxy_rules: proxyRules,
        enable_schedule: enableSchedule,
        schedule_time: scheduleTime
      })
      .then(function(resp) {
        if (resp.data.ok) {
          alert('任务保存成功！');
        } else {
          alert('保存失败: ' + resp.data.msg);
        }
      })
      .catch(function(error) {
        var errorMsg = error.response && error.response.data && error.response.data.msg ? error.response.data.msg : error.message;
        alert('保存失败: ' + errorMsg);
      });
    });
  } else {
    console.log('btnSaveTask not found');
  }
  
}
document.addEventListener('DOMContentLoaded', initAppPage);
document.addEventListener('lingtu:page-load', initAppPage);

// 执行巡检任务
var currentRun = null;
var pollInterval = null;
var lastMessage = '';
var renderedLogCount = 0;

function runTask(taskId) {
  var logBox = document.getElementById('logBox');
  var progressBar = document.getElementById('progressBar');
  var progressPercent = document.getElementById('progressPercent');
  var downloadBox = document.getElementById('downloadBox');
  
  if (logBox) logBox.textContent = '';
  if (progressBar) progressBar.style.width = '0%';
  if (progressPercent) progressPercent.textContent = '0%';
  if (downloadBox) downloadBox.innerHTML = '';
  lastMessage = '';
  renderedLogCount = 0;
  
  console.log('Running task:', taskId);
  axios.post('/api/run_task', { task_id: taskId })
    .then(function(resp) {
      console.log('Run task response:', resp.data);
      if (resp.data.ok) {
        currentRun = resp.data.run_id;
        log('已开始执行任务，运行ID: ' + currentRun);
        pollInterval = setInterval(pollTaskProgress, 1000);
      } else {
        log('错误：' + (resp.data.msg || '未知错误'));
      }
    })
    .catch(function(error) {
      console.error('Run task error:', error);
      var errorMsg = error.response && error.response.data && error.response.data.msg ? error.response.data.msg : (error.response && error.response.statusText ? error.response.statusText : (error.message ? error.message : '网络错误'));
      log('错误：' + errorMsg);
    });
}

function pollTaskProgress() {
  if (!currentRun) return;
  
  axios.get('/api/inspection_progress', { params: { run_id: currentRun } })
    .then(function(resp) {
      var data = resp.data;
      if (Array.isArray(data.logs)) {
        for (var i = renderedLogCount; i < data.logs.length; i++) {
          log(data.logs[i]);
        }
        renderedLogCount = data.logs.length;
      } else if (data.message && data.message !== lastMessage) {
        log(data.message);
      }
      lastMessage = data.message || lastMessage;
      if (typeof data.percent === 'number') {
        document.getElementById('progressBar').style.width = data.percent + '%';
        document.getElementById('progressPercent').textContent = data.percent + '%';
      }
      if (data.report_path) {
        var box = document.getElementById('downloadBox');
        box.innerHTML = '<a href="/api/download_report?path=' + encodeURIComponent(data.report_path) + '" class="btn btn-primary">下载巡检报告</a>';
        if (pollInterval) {
          clearInterval(pollInterval);
          pollInterval = null;
        }
      } else if (data.status === 'failed') {
        log('执行失败：' + (data.error || '未知错误'));
        if (pollInterval) {
          clearInterval(pollInterval);
          pollInterval = null;
        }
      }
    })
    .catch(function(error) {
      console.error('获取进度失败:', error);
    });
}

// 删除巡检任务
async function deleteTask(taskId) {
  if (!(await uiConfirm('确定要删除该任务吗？', { type: 'error', okText: '删除' }))) return;
  
  axios.post('/api/delete_task', { task_id: taskId })
    .then(function(resp) {
      if (resp.data.ok) {
        alert('任务删除成功！');
        location.reload();
      } else {
        alert('删除失败: ' + resp.data.msg);
      }
    })
    .catch(function(error) {
      var errorMsg = error.response && error.response.data && error.response.data.msg ? error.response.data.msg : error.message;
      alert('删除失败: ' + errorMsg);
    });
}

// 切换定时任务状态
function toggleSchedule(taskId) {
  console.log('toggleSchedule called with id:', taskId);
  axios.post('/api/toggle_schedule', { id: taskId })
    .then(function(resp) {
      if (resp.data.ok) {
        location.reload();
      } else {
        alert('操作失败: ' + resp.data.msg);
      }
    })
    .catch(function(error) {
      var errorMsg = error.response && error.response.data && error.response.data.msg ? error.response.data.msg : error.message;
      alert('操作失败: ' + errorMsg);
    });
}

var currentEditTaskId = null;

// 加载任务详情
function loadTask(taskId) {
  console.log('loadTask called with id:', taskId);
  axios.get('/api/task', { params: { id: taskId } })
    .then(function(resp) {
      var task = resp.data;
      currentEditTaskId = taskId;
      
      document.getElementById('editTaskName').value = task.name || '';
      document.getElementById('editProjectName').value = task.project_name || '';
      document.getElementById('editInspector').value = task.inspector || '';
      
      if (task.report_format === 'pdf') {
        document.getElementById('editFormatPdf').checked = true;
      } else {
        document.getElementById('editFormatExcel').checked = true;
      }
      
      document.getElementById('editResourceGroup').value = task.resource_group_id || '';
      document.getElementById('editCheckCpu').checked = task.check_cpu || false;
      document.getElementById('editCheckMem').checked = task.check_mem || false;
      document.getElementById('editCheckDisk').checked = task.check_disk || false;
      
      document.getElementById('editEnableProxy').checked = task.enable_proxy || false;
      var editProxyConfig = document.getElementById('editProxyConfig');
      editProxyConfig.style.display = task.enable_proxy ? 'block' : 'none';
      
      var editProxyRulesList = document.getElementById('editProxyRulesList');
      editProxyRulesList.innerHTML = '';
      if (task.proxy_rules && task.proxy_rules.length > 0) {
        for (var i = 0; i < task.proxy_rules.length; i++) {
          addEditProxyRule(task.proxy_rules[i], i);
        }
      }
      
      document.getElementById('editEnableSchedule').checked = task.enable_schedule || false;
      var editScheduleConfig = document.getElementById('editScheduleConfig');
      editScheduleConfig.style.display = task.enable_schedule ? 'block' : 'none';
      document.getElementById('editScheduleTime').value = task.schedule_time || '';
      
      document.getElementById('taskEditSection').style.display = 'block';
      document.getElementById('taskEditSection').scrollIntoView({ behavior: 'smooth', block: 'start' });
    })
    .catch(function(error) {
      var errorMsg = error.response && error.response.data && error.response.data.msg ? error.response.data.msg : error.message;
      alert('加载任务失败: ' + errorMsg);
    });
}

function addEditProxyRule(rule, index) {
  var editProxyRulesList = document.getElementById('editProxyRulesList');
  var newIndex = index !== null ? index : editProxyRulesList.querySelectorAll('.inspect-proxy-rule-row').length;
  
  var groups = [];
  var groupsData = document.getElementById('groupsData');
  if (groupsData) {
    try {
      groups = JSON.parse(groupsData.textContent);
    } catch (e) {
      console.error('解析分组数据失败', e);
    }
  }
  
  var groupOptions = '<option value="">全部</option>';
  for (var i = 0; i < groups.length; i++) {
    var g = groups[i];
    var selected = rule && rule.group_id == g.id ? 'selected' : '';
    groupOptions += '<option value="' + g.id + '" ' + selected + '>' + g.name + '</option>';
  }
  
  var ruleDiv = document.createElement('div');
  ruleDiv.className = 'inspect-proxy-rule-row';
  ruleDiv.dataset.index = newIndex;
  
  var curlValue = rule ? rule.curl_command : '';
  var keywordValue = rule ? rule.success_keyword : '成功';
  
  ruleDiv.innerHTML = [
    '<div class="inspect-proxy-rule-item">',
    '<label class="inspect-proxy-label">服务器</label>',
    '<select class="inspect-proxy-select proxy-group-select">',
    groupOptions,
    '</select>',
    '</div>',
    '<div class="inspect-proxy-rule-item inspect-proxy-rule-item-large">',
    '<label class="inspect-proxy-label">CURL命令</label>',
    '<input type="text" class="inspect-proxy-input proxy-curl-command" value="' + curlValue + '" placeholder="curl -s http://127.0.0.1:8080/api/health">',
    '</div>',
    '<div class="inspect-proxy-rule-item">',
    '<label class="inspect-proxy-label">关键词</label>',
    '<input type="text" class="inspect-proxy-input-short proxy-success-keyword" value="' + keywordValue + '" placeholder="成功">',
    '</div>',
    '<button type="button" class="inspect-btn inspect-btn-delete remove-proxy-rule" style="display: inline-flex;">删除</button>'
  ].join('');
  
  editProxyRulesList.appendChild(ruleDiv);
  
  var removeBtn = ruleDiv.querySelector('.remove-proxy-rule');
  removeBtn.addEventListener('click', function() {
    ruleDiv.remove();
  });
}

function initTaskEdit() {
  var editEnableProxy = document.getElementById('editEnableProxy');
  if (editEnableProxy) {
    editEnableProxy.addEventListener('change', function() {
      var config = document.getElementById('editProxyConfig');
      config.style.display = this.checked ? 'block' : 'none';
    });
  }
  
  var editEnableSchedule = document.getElementById('editEnableSchedule');
  if (editEnableSchedule) {
    editEnableSchedule.addEventListener('change', function() {
      var config = document.getElementById('editScheduleConfig');
      config.style.display = this.checked ? 'block' : 'none';
    });
  }
  
  var editAddProxyRule = document.getElementById('editAddProxyRule');
  if (editAddProxyRule) {
    editAddProxyRule.addEventListener('click', function() {
      addEditProxyRule(null, null);
    });
  }
  
  var btnSaveEdit = document.getElementById('btnSaveEdit');
  if (btnSaveEdit) {
    btnSaveEdit.addEventListener('click', function() {
      if (!currentEditTaskId) {
        alert('请先选择要编辑的任务');
        return;
      }
      
      var taskName = document.getElementById('editTaskName').value.trim();
      var projectName = document.getElementById('editProjectName').value.trim();
      var inspector = document.getElementById('editInspector').value.trim();
      var formatRadio = document.querySelector('input[name="editReportFormat"]:checked');
      var format = formatRadio ? formatRadio.value : 'excel';
      
      var resourceGroup = document.getElementById('editResourceGroup').value;
      var checkCpu = document.getElementById('editCheckCpu').checked;
      var checkMem = document.getElementById('editCheckMem').checked;
      var checkDisk = document.getElementById('editCheckDisk').checked;
      
      var enableProxy = document.getElementById('editEnableProxy').checked;
      var proxyRules = [];
      if (enableProxy) {
        var ruleElements = document.querySelectorAll('#editProxyRulesList .inspect-proxy-rule-row');
        for (var i = 0; i < ruleElements.length; i++) {
          var rule = ruleElements[i];
          var groupId = rule.querySelector('.proxy-group-select').value;
          var curlCmd = rule.querySelector('.proxy-curl-command').value.trim();
          var keyword = rule.querySelector('.proxy-success-keyword').value.trim() || '成功';
          if (curlCmd) {
            proxyRules.push({
              group_id: groupId,
              curl_command: curlCmd,
              success_keyword: keyword
            });
          }
        }
      }
      
      var enableSchedule = document.getElementById('editEnableSchedule').checked;
      var scheduleTime = enableSchedule ? document.getElementById('editScheduleTime').value : '';
      
      if (!taskName) {
        alert('请输入任务名称');
        return;
      }
      if (!projectName) {
        alert('请输入项目名称');
        return;
      }
      if (!inspector) {
        alert('请输入巡检人');
        return;
      }
      
      axios.post('/api/update_task', {
        id: currentEditTaskId,
        task_name: taskName,
        project_name: projectName,
        inspector: inspector,
        report_format: format,
        resource_group_id: resourceGroup,
        check_cpu: checkCpu,
        check_mem: checkMem,
        check_disk: checkDisk,
        enable_proxy: enableProxy,
        proxy_rules: proxyRules,
        enable_schedule: enableSchedule,
        schedule_time: scheduleTime
      })
      .then(function(resp) {
        console.log('Response received:', resp.data);
        if (resp.data.ok) {
          alert('任务修改成功！');
          location.reload();
        } else {
          alert('修改失败: ' + (resp.data.msg || '未知错误'));
        }
      })
      .catch(function(error) {
        console.error('Error:', error);
        var errorMsg = error.response && error.response.data && error.response.data.msg ? error.response.data.msg : (error.response && error.response.statusText ? error.response.statusText : (error.message ? error.message : '网络错误'));
        alert('修改失败: ' + errorMsg);
      });
    });
  }
  
  var btnCancelEdit = document.getElementById('btnCancelEdit');
  if (btnCancelEdit) {
    btnCancelEdit.addEventListener('click', function() {
      document.getElementById('taskEditSection').style.display = 'none';
      currentEditTaskId = null;
    });
  }
}

document.addEventListener('DOMContentLoaded', function() {
  initTaskEdit();
});
document.addEventListener('lingtu:page-load', initTaskEdit);
document.addEventListener('lingtu:before-unmount', function() {
  if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
});
