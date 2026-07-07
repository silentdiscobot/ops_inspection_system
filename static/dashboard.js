(function () {
  'use strict';
  var nodes = [], topologyPage = 0, pageSize = 12, pageTimer = null, disposed = false;
  var clockTimer = null, statusTimer = null, animationFrame = null;
  var canvas = document.getElementById('networkCanvas'), ctx = canvas.getContext('2d');

  function escapeHtml(value) {
    var div = document.createElement('div'); div.textContent = value == null ? '' : value; return div.innerHTML;
  }
  function clock() {
    var now = new Date();
    document.getElementById('wallTime').textContent = now.toLocaleTimeString('zh-CN', {hour12:false});
    document.getElementById('wallDate').textContent = now.toLocaleDateString('zh-CN', {year:'numeric', month:'2-digit', day:'2-digit', weekday:'short'});
  }
  function nodePosition(index, total) {
    var angle = (Math.PI * 2 * index / Math.max(total, 1)) - Math.PI / 2;
    var radiusX = total > 8 ? 40 : 36, radiusY = total > 8 ? 38 : 32;
    return {x: 50 + Math.cos(angle) * radiusX, y: 51 + Math.sin(angle) * radiusY};
  }
  function renderTopology() {
    var universe = document.getElementById('serverNodes'); universe.innerHTML = '';
    var pages = Math.max(1, Math.ceil(nodes.length / pageSize));
    if (topologyPage >= pages) topologyPage = 0;
    var visibleNodes = nodes.slice(topologyPage * pageSize, topologyPage * pageSize + pageSize);
    visibleNodes.forEach(function(server, index) {
      var pos = nodePosition(index, visibleNodes.length), node = document.createElement('div');
      node.className = 'server-node ' + server.status; node.style.left = pos.x + '%'; node.style.top = pos.y + '%';
      node.innerHTML = '<i class="node-halo"></i><span class="server-glyph"><i></i><b></b></span><label><i></i>' + escapeHtml(server.ip) + '</label><small>' + (server.status === 'online' ? 'ONLINE' : server.status === 'offline' ? 'OFFLINE' : 'SCANNING') + '</small>';
      universe.appendChild(node);
    });
    var pager = document.getElementById('topologyPager'); pager.hidden = pages <= 1;
    document.getElementById('topologyPage').textContent = (topologyPage + 1) + ' / ' + pages;
  }
  function turnTopology(direction) {
    var pages = Math.max(1, Math.ceil(nodes.length / pageSize)); topologyPage = (topologyPage + direction + pages) % pages; renderTopology();
  }
  function resetTopologyTimer() {
    clearInterval(pageTimer); pageTimer = setInterval(function(){ if (nodes.length > pageSize) turnTopology(1); }, 8000);
  }
  function render(data) {
    var count = data.counts || {}, total = data.total || 0, online = count.online || 0, offline = count.offline || 0, checking = count.checking || 0;
    var rate = total ? Math.round(online / total * 100) : 0;
    ['totalCount','onlineCount','offlineCount'].forEach(function(id, i){ document.getElementById(id).textContent = [total, online, offline][i]; });
    document.getElementById('onlineRate').textContent = rate + '%'; document.getElementById('ringRate').textContent = rate;
    document.getElementById('legendOnline').textContent = online; document.getElementById('legendOffline').textContent = offline; document.getElementById('legendChecking').textContent = checking;
    document.getElementById('statusRing').style.setProperty('--rate', rate * 3.6 + 'deg');
    document.getElementById('lastUpdated').textContent = '数据同步 ' + data.updated_at;
    nodes = data.servers || [];
    var list = document.getElementById('nodeList'); list.innerHTML = '';
    document.getElementById('emptyUniverse').hidden = nodes.length !== 0;
    renderTopology(); resetTopologyTimer();
    nodes.slice(0, 200).forEach(function(server) {
      var row = document.createElement('div'); row.className = 'node-row ' + server.status;
      row.innerHTML = '<i></i><div><strong>' + escapeHtml(server.name) + '</strong><span>' + escapeHtml(server.ip) + ':' + server.port + ' · ' + escapeHtml(server.groups) + '</span></div><b>' + (server.status === 'online' ? '正常' : server.status === 'offline' ? '掉线' : '探测中') + '</b>';
      list.appendChild(row);
    });
    var summary = document.getElementById('nodeListSummary'); summary.hidden = nodes.length <= 200;
    summary.textContent = nodes.length > 200 ? '已显示前 200 个节点，共 ' + nodes.length + ' 个' : '';
  }
  function fetchStatus() {
    fetch('/api/dashboard/status', {credentials:'include'}).then(function(res){ if (!res.ok) throw new Error('status ' + res.status); return res.json(); }).then(render).catch(function(){ document.getElementById('lastUpdated').textContent = '状态同步暂时中断，正在重试'; });
  }
  function syncFullscreenButton() {
    var active = document.fullscreenElement === document.getElementById('opsWall');
    document.getElementById('fullscreenBtn').classList.toggle('active', active);
    document.querySelector('#fullscreenBtn span').textContent = active ? '退出' : '全屏';
  }
  function toggleFullscreen() {
    var wall = document.getElementById('opsWall');
    if (document.fullscreenElement) { document.exitFullscreen(); }
    else if (wall.requestFullscreen) { wall.requestFullscreen(); }
  }
  function draw() {
    if (disposed) return;
    var dpr = window.devicePixelRatio || 1, rect = canvas.getBoundingClientRect();
    if (canvas.width !== rect.width * dpr || canvas.height !== rect.height * dpr) { canvas.width = rect.width*dpr; canvas.height=rect.height*dpr; ctx.setTransform(dpr,0,0,dpr,0,0); }
    ctx.clearRect(0,0,rect.width,rect.height); var t = Date.now()/1000;
    for (var i=0;i<46;i++) { var x=(i*137.5)%rect.width, y=(i*71+t*(5+i%3))%rect.height; ctx.fillStyle='rgba(151,220,255,'+(0.08+(i%5)*0.025)+')'; ctx.beginPath(); ctx.arc(x,y,0.7+(i%3)*0.4,0,Math.PI*2); ctx.fill(); }
    animationFrame = requestAnimationFrame(draw);
  }
  document.getElementById('topologyPrev').addEventListener('click', function(){ turnTopology(-1); resetTopologyTimer(); });
  document.getElementById('topologyNext').addEventListener('click', function(){ turnTopology(1); resetTopologyTimer(); });
  document.getElementById('fullscreenBtn').addEventListener('click', toggleFullscreen);
  document.addEventListener('fullscreenchange', syncFullscreenButton);
  document.addEventListener('lingtu:before-unmount', function cleanupDashboard() {
    disposed = true;
    clearInterval(clockTimer); clearInterval(statusTimer); clearInterval(pageTimer);
    if (animationFrame) cancelAnimationFrame(animationFrame);
    document.removeEventListener('fullscreenchange', syncFullscreenButton);
  }, {once:true});
  clock(); clockTimer = setInterval(clock,1000);
  fetchStatus(); statusTimer = setInterval(fetchStatus,10000); draw();
}());
