// 极简 Markdown 渲染器：只用于把大模型输出变成 HTML。
// 安全前提：先把整段文本做 HTML 转义，再插入受控标签；任何原始 < > " ' 都不可能进入 DOM。
// CSP 允许内联样式，因此不生成 style 属性，只挂语义 class。
(function () {
  'use strict';

  function escapeHtml(text) {
    return String(text === null || text === undefined ? '' : text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // 入参必须是已转义文本。
  function inline(text) {
    var out = text;
    out = out.replace(/`([^`\n]+)`/g, '<code>$1</code>');
    out = out.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
    out = out.replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>');
    // 只认 http/https，避免 javascript: 之类的伪协议。
    out = out.replace(/\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)/g,
      '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
    return out;
  }

  function splitRow(line) {
    var trimmed = line.trim().replace(/^\|/, '').replace(/\|$/, '');
    return trimmed.split('|').map(function (cell) { return cell.trim(); });
  }

  function isDivider(line) {
    return /^[\s|:-]+$/.test(line) && line.indexOf('-') !== -1;
  }

  function render(markdown) {
    var text = escapeHtml(markdown).replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    var lines = text.split('\n');
    var html = [];
    var index = 0;

    while (index < lines.length) {
      var line = lines[index];

      // 围栏代码块
      if (/^\s*```/.test(line)) {
        var buffer = [];
        index += 1;
        while (index < lines.length && !/^\s*```/.test(lines[index])) {
          buffer.push(lines[index]);
          index += 1;
        }
        index += 1;
        html.push('<pre class="ai-code"><code>' + buffer.join('\n') + '</code></pre>');
        continue;
      }

      // 空行
      if (!line.trim()) {
        index += 1;
        continue;
      }

      // 标题
      var heading = line.match(/^(#{1,6})\s+(.*)$/);
      if (heading) {
        var level = Math.min(6, heading[1].length + 1); // h1 留给页面标题，模型标题从 h2 起
        html.push('<h' + level + ' class="ai-md-heading">' + inline(heading[2]) + '</h' + level + '>');
        index += 1;
        continue;
      }

      // 表格：当前行含 |，下一行是分隔行
      if (line.indexOf('|') !== -1 && index + 1 < lines.length && isDivider(lines[index + 1])) {
        var header = splitRow(line);
        index += 2;
        var body = [];
        while (index < lines.length && lines[index].indexOf('|') !== -1 && lines[index].trim()) {
          body.push(splitRow(lines[index]));
          index += 1;
        }
        var table = ['<div class="ai-md-table-wrap"><table class="ai-md-table"><thead><tr>'];
        header.forEach(function (cell) { table.push('<th>' + inline(cell) + '</th>'); });
        table.push('</tr></thead><tbody>');
        body.forEach(function (row) {
          table.push('<tr>');
          for (var i = 0; i < header.length; i += 1) {
            table.push('<td>' + inline(row[i] === undefined ? '' : row[i]) + '</td>');
          }
          table.push('</tr>');
        });
        table.push('</tbody></table></div>');
        html.push(table.join(''));
        continue;
      }

      // 引用
      if (/^&gt;\s?/.test(line)) {
        var quotes = [];
        while (index < lines.length && /^&gt;\s?/.test(lines[index])) {
          quotes.push(lines[index].replace(/^&gt;\s?/, ''));
          index += 1;
        }
        html.push('<blockquote class="ai-md-quote">' + inline(quotes.join('<br>')) + '</blockquote>');
        continue;
      }

      // 分隔线
      if (/^\s*([-*_])\s*\1\s*\1[\s\-*_]*$/.test(line)) {
        html.push('<hr class="ai-md-hr">');
        index += 1;
        continue;
      }

      // 无序列表
      if (/^\s*[-*+]\s+/.test(line)) {
        html.push('<ul class="ai-md-list">');
        while (index < lines.length && /^\s*[-*+]\s+/.test(lines[index])) {
          html.push('<li>' + inline(lines[index].replace(/^\s*[-*+]\s+/, '')) + '</li>');
          index += 1;
        }
        html.push('</ul>');
        continue;
      }

      // 有序列表
      if (/^\s*\d+[.)]\s+/.test(line)) {
        html.push('<ol class="ai-md-list">');
        while (index < lines.length && /^\s*\d+[.)]\s+/.test(lines[index])) {
          html.push('<li>' + inline(lines[index].replace(/^\s*\d+[.)]\s+/, '')) + '</li>');
          index += 1;
        }
        html.push('</ol>');
        continue;
      }

      // 普通段落：连续的普通行合成一段
      var paragraph = [];
      while (index < lines.length && lines[index].trim() &&
             !/^\s*```/.test(lines[index]) &&
             !/^#{1,6}\s+/.test(lines[index]) &&
             !/^\s*[-*+]\s+/.test(lines[index]) &&
             !/^\s*\d+[.)]\s+/.test(lines[index]) &&
             !/^&gt;\s?/.test(lines[index]) &&
             !(lines[index].indexOf('|') !== -1 && index + 1 < lines.length && isDivider(lines[index + 1]))) {
        paragraph.push(lines[index]);
        index += 1;
      }
      html.push('<p class="ai-md-p">' + inline(paragraph.join('<br>')) + '</p>');
    }

    return html.join('');
  }

  window.AiMarkdown = { render: render, escapeHtml: escapeHtml };
})();
