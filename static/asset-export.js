(function () {
  'use strict';

  function getDialog(dialogId) {
    return document.getElementById(dialogId + 'Overlay');
  }

  function getFieldBoxes(dialogId) {
    var dialog = getDialog(dialogId);
    return dialog ? Array.prototype.slice.call(dialog.querySelectorAll('.asset-export-option input[type="checkbox"]')) : [];
  }

  function setError(dialogId, message) {
    var error = document.getElementById(dialogId + 'Error');
    if (!error) return;
    error.textContent = message || '';
    error.hidden = !message;
  }

  window.updateAssetExportCount = function (dialogId) {
    var count = getFieldBoxes(dialogId).filter(function (box) { return box.checked; }).length;
    var output = document.getElementById(dialogId + 'Count');
    if (output) output.textContent = String(count);
    setError(dialogId, '');
  };

  window.openAssetExportDialog = function (dialogId) {
    var dialog = getDialog(dialogId);
    if (!dialog) return;
    setError(dialogId, '');
    window.updateAssetExportCount(dialogId);
    dialog.style.display = 'flex';
  };

  window.closeAssetExportDialog = function (dialogId) {
    var dialog = getDialog(dialogId);
    if (dialog) dialog.style.display = 'none';
  };

  window.selectAssetExportFields = function (dialogId, selected) {
    getFieldBoxes(dialogId).forEach(function (box) { box.checked = selected; });
    window.updateAssetExportCount(dialogId);
  };

  function appendValue(params, queryName, elementId) {
    var element = document.getElementById(elementId);
    var value = element ? String(element.value || '').trim() : '';
    if (value) params.set(queryName, value);
  }

  function appendCurrentFilters(params, entity) {
    if (entity === 'servers') {
      appendValue(params, 'group_id', 'filterGroup');
      appendValue(params, 'resource_type', 'filterResourceType');
      appendValue(params, 'os_type', 'filterOsType');
      appendValue(params, 'keyword', 'serverKeyword');
      return;
    }
    appendValue(params, 'system_id', 'filterSystem');
    appendValue(params, 'environment_id', 'filterEnvironment');
    appendValue(params, 'service_type', 'filterServiceType');
    appendValue(params, 'status', 'filterStatus');
    appendValue(params, 'keyword', 'serviceKeyword');
  }

  window.submitAssetExport = function (dialogId) {
    var dialog = getDialog(dialogId);
    if (!dialog) return;
    var fields = getFieldBoxes(dialogId)
      .filter(function (box) { return box.checked; })
      .map(function (box) { return box.value; });
    if (!fields.length) {
      setError(dialogId, '请至少选择一个导出字段');
      return;
    }

    var entity = dialog.getAttribute('data-export-entity');
    var params = new URLSearchParams();
    fields.forEach(function (field) { params.append('fields', field); });
    appendCurrentFilters(params, entity);
    window.closeAssetExportDialog(dialogId);
    window.location.href = '/api/' + entity + '/export?' + params.toString();
  };
})();
