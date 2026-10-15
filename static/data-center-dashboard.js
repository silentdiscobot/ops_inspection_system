(function () {
  'use strict';
  var allServers = [], selectedRoom = '', statusTimer = null, clockTimer = null, disposed = false, lastStatusFingerprint = '';
  var sceneFrame = null, sceneLastTime = 0, autoView = true, dragging = false, dragMode = '', dragX = 0, dragY = 0, sceneRotX = 22, sceneRotY = -22, scenePanX = 0, scenePanY = 0;
  var rackScene = [], rackZones = [], rackHitAreas = [], rackCabinetAreas = [], rackRowDropAreas = [], dragDistance = 0;
  var rackLayout = {rows:[]}, activeZoneKey = '', rackDrag = null, selectedRackName = '', editView = false;
  var RACK_SLOT_CAPACITY = 15;
  var STATUS = {
    online: {key:'normal', label:'正常'},
    checking: {key:'warning', label:'警告'},
    offline: {key:'error', label:'报错'}
  };

  function byId(id) { return document.getElementById(id); }
  function escapeHtml(value) {
    var node = document.createElement('div'); node.textContent = value == null ? '' : value; return node.innerHTML;
  }
  function naturalParts(value) {
    return String(value || '').toUpperCase().split(/(\d+)/).map(function(part) { return /^\d+$/.test(part) ? Number(part) : part; });
  }
  function naturalCompare(a, b) {
    var left = naturalParts(a), right = naturalParts(b), length = Math.max(left.length, right.length);
    for (var i = 0; i < length; i++) {
      if (left[i] === undefined) return -1;
      if (right[i] === undefined) return 1;
      if (left[i] === right[i]) continue;
      if (typeof left[i] === typeof right[i]) return left[i] < right[i] ? -1 : 1;
      return String(left[i]).localeCompare(String(right[i]), 'zh-CN');
    }
    return 0;
  }
  function rowCode(index) { return String.fromCharCode(65 + Math.max(0, Math.min(25, index))); }
  function idealColumns(count) {
    if(count<=4)return Math.max(1,count);
    if(count<=10)return 5;
    if(count<=18)return 6;
    return 7;
  }
  function densityProfile(count) {
    if(count<=2)return {rackScale:1.28,spacingX:1.25,rowSpacing:1.72,maxScale:136,minZoneWidth:2.05};
    if(count<=6)return {rackScale:1.16,spacingX:1.14,rowSpacing:1.62,maxScale:120,minZoneWidth:2.25};
    if(count<=12)return {rackScale:1.04,spacingX:1.04,rowSpacing:1.48,maxScale:106,minZoneWidth:2.4};
    if(count<=24)return {rackScale:.9,spacingX:.92,rowSpacing:1.32,maxScale:94,minZoneWidth:2.55};
    return {rackScale:.78,spacingX:.82,rowSpacing:1.16,maxScale:82,minZoneWidth:2.7};
  }
  function rackLocation(value, level) {
    var text = String(value || '').trim();
    var levelMatch = String(level || '').trim().match(/(?:U\s*)?0*(\d+)/i);
    var explicitU = levelMatch ? Math.max(1, Number(levelMatch[1])) : null;
    if (!text) return {rack:'未分配', u:explicitU};
    if (explicitU !== null) return {rack:text, u:explicitU};
    var match = text.match(/^(.*?)(?:[-_\/\s]+)?U\s*0*(\d+)$/i);
    if (match && match[1].replace(/[-_\/\s]+$/, '').trim()) {
      return {rack:match[1].replace(/[-_\/\s]+$/, '').trim(), u:Math.max(1, Number(match[2]))};
    }
    return {rack:text, u:null};
  }
  function roomKey(name) { return encodeURIComponent(name); }
  function roomNames(server) {
    if (server.room_affiliation) return [server.room_affiliation];
    return server.rooms && server.rooms.length ? server.rooms : ['未分配机房'];
  }
  function statusOf(server) { return STATUS[server.status] || STATUS.checking; }
  function physicalIpOf(server) { return String(server&&server.physical_ip||'').trim(); }
  function isPhysicalServer(server) { return String(server&&server.resource_type||'').trim()==='物理机'&&!!physicalIpOf(server); }
  function layoutStorageKey(zoneKey) { return 'lingtu:data-center:rack-layout:' + zoneKey; }
  function loadRackLayout(names, zoneKey) {
    var saved = null;
    try { saved = JSON.parse(localStorage.getItem(layoutStorageKey(zoneKey)) || 'null'); } catch (error) { saved = null; }
    var valid = {};
    names.forEach(function(name) { valid[name] = true; });
    var seen = {}, rows = [];
    if (saved && Array.isArray(saved.rows)) rows = saved.rows;
    else if (saved && (Array.isArray(saved.front) || Array.isArray(saved.back))) rows = [saved.back || [], saved.front || []];
    rows = rows.map(function(row) {
      return Array.isArray(row) ? row.filter(function(name) { if (!valid[name] || seen[name]) return false; seen[name] = true; return true; }) : [];
    });
    if (!saved) {
      rows = [];var columns=idealColumns(names.length);
      names.forEach(function(name,index) { var rowIndex=Math.floor(index/columns); if(!rows[rowIndex]) rows[rowIndex]=[]; rows[rowIndex].push(name); seen[name]=true; });
    } else {
      names.forEach(function(name) {
        if (seen[name]) return;
        if (!rows.length) rows.push([]);
        var shortest=0; for(var i=1;i<rows.length;i++) if(rows[i].length<rows[shortest].length) shortest=i;
        rows[shortest].push(name); seen[name]=true;
      });
    }
    return {rows:rows.length ? rows : [[]]};
  }
  function zoneByKey(key) { return rackZones.find(function(zone) { return zone.key === key; }); }
  function activateZone(key) {
    var zone=zoneByKey(key)||rackZones[0];
    if(!zone)return;
    activeZoneKey=zone.key;rackLayout=zone.layout;updateRowEditor();
  }
  function saveRackLayout(zoneKey) {
    var zone=zoneByKey(zoneKey||activeZoneKey);if(!zone)return;
    try { localStorage.setItem(layoutStorageKey(zone.key), JSON.stringify(zone.layout)); } catch (error) {}
  }
  function rackByName(identifier) {
    return rackScene.find(function(rack) { return rack.id === identifier; });
  }
  function updateRackInspector(identifier) {
    var rack=rackByName(identifier);if(rack){selectedRackName=rack.id;activateZone(rack.roomKey);}
  }
  function currentServers() {
    var physicalServers=allServers.filter(isPhysicalServer);
    return physicalServers.filter(function(server) { return roomNames(server).some(function(name) { return roomKey(name) === selectedRoom; }); });
  }
  function updateClock() {
    var now = new Date();
    byId('dcTime').textContent = now.toLocaleTimeString('zh-CN', {hour12:false});
    byId('dcDate').textContent = now.toLocaleDateString('zh-CN', {year:'numeric', month:'2-digit', day:'2-digit', weekday:'short'});
  }
  function renderRooms() {
    var counts = {},physicalServers=allServers.filter(isPhysicalServer);
    physicalServers.forEach(function(server) { roomNames(server).forEach(function(name) { counts[name] = (counts[name] || 0) + 1; }); });
    var names = Object.keys(counts).sort(naturalCompare), host = byId('dcRoomSwitcher');
    if (!names.some(function(name) { return roomKey(name) === selectedRoom; })) selectedRoom = names.length ? roomKey(names[0]) : '';
    var html = '';
    names.forEach(function(name) {
      var key = roomKey(name);
      html += '<button type="button" role="tab" data-room="' + key + '" class="' + (selectedRoom === key ? 'active' : '') + '"><span>' + escapeHtml(name) + '</span><b>' + counts[name] + '</b></button>';
    });
    host.innerHTML = html;
    host.querySelectorAll('button').forEach(function(button) {
      button.addEventListener('click', function() { selectedRoom = button.dataset.room; renderView(); });
    });
  }
  function arrangeRack(servers) {
    var used = {}, arranged = [];
    servers.slice().sort(function(a,b) {
      var au = rackLocation(a.rack_number, a.rack_level).u, bu = rackLocation(b.rack_number, b.rack_level).u;
      if (au !== null && bu !== null) return au - bu;
      if (au !== null) return -1;
      if (bu !== null) return 1;
      return naturalCompare(a.name || a.ip, b.name || b.ip);
    }).forEach(function(server) {
      var requested = rackLocation(server.rack_number, server.rack_level).u;
      if (requested === null || requested > RACK_SLOT_CAPACITY || used[requested]) return;
      used[requested] = true;
      arranged.push({server:server, u:requested, requested:requested, slot:requested});
    });
    return arranged.sort(function(a,b) { return a.slot - b.slot; });
  }
  function rackCard(name, servers, index) {
    var arranged = arrangeRack(servers), counts = {normal:0,warning:0,error:0};
    servers.forEach(function(server) { counts[statusOf(server).key]++; });
    var units = '';
    for (var u = RACK_SLOT_CAPACITY; u >= 1; u--) units += '<i><span>' + (u % 5 === 0 || u === 1 ? u : '') + '</span></i>';
    var blocks = arranged.map(function(item) {
      var server = item.server, state = statusOf(server), bottom = ((item.slot - 1) / RACK_SLOT_CAPACITY * 100).toFixed(3);
      return '<button type="button" class="dc-server-unit ' + state.key + '" style="--unit-bottom:' + bottom + '%;--unit-delay:' + ((index + item.u) % 5 * -.3) + 's" data-server-id="' + server.id + '" title="' + escapeHtml(physicalIpOf(server) + ' · U' + item.u + ' · ' + state.label) + '"><span class="dc-unit-led"></span><b>' + escapeHtml(physicalIpOf(server)) + '</b><em>U' + item.u + '</em></button>';
    }).join('');
    return '<article class="dc-rack" style="--rack-index:' + index + '"><div class="dc-rack-cap"><i></i></div><div class="dc-rack-top"><span>' + escapeHtml(name) + '</span><i></i></div><div class="dc-rack-side"><i></i><i></i><i></i><i></i><b></b></div><div class="dc-rack-body"><div class="dc-u-scale">' + units + '</div><div class="dc-rack-rail left"></div><div class="dc-rack-rail right"></div><div class="dc-server-stack">' + blocks + '</div></div><div class="dc-rack-base"><i></i><i></i></div><div class="dc-rack-shadow"></div><footer><div><strong>' + escapeHtml(name) + '</strong><span>' + servers.length + ' 台设备</span></div><p><i class="normal"></i>' + counts.normal + '<i class="warning"></i>' + counts.warning + '<i class="error"></i>' + counts.error + '</p></footer></article>';
  }
  function renderRacks(servers) {
    var racks = {};
    servers.forEach(function(server) {
      var location=rackLocation(server.rack_number,server.rack_level),rooms=roomNames(server);
      var room=rooms.find(function(name){return roomKey(name)===selectedRoom;})||rooms[0];
      var key=roomKey(room)+'::'+location.rack;
      if(!racks[key])racks[key]={room:room,roomKey:roomKey(room),name:location.rack,servers:[]};
      racks[key].servers.push(server);
    });
    var keys = Object.keys(racks).sort(function(a,b) {
      var roomOrder=naturalCompare(racks[a].room,racks[b].room);if(roomOrder)return roomOrder;
      if (racks[a].name === '未分配') return 1; if (racks[b].name === '未分配') return -1; return naturalCompare(racks[a].name,racks[b].name);
    });
    rackScene = keys.map(function(key) {
      var entry=racks[key],arranged = arrangeRack(entry.servers), counts = {normal:0,warning:0,error:0};
      arranged.forEach(function(item) { counts[statusOf(item.server).key]++; });
      return {id:key,name:entry.name,room:entry.room,roomKey:entry.roomKey,servers:entry.servers,arranged:arranged,counts:counts};
    });
    var zoneMap={};
    rackScene.forEach(function(rack){if(!zoneMap[rack.roomKey])zoneMap[rack.roomKey]={key:rack.roomKey,name:rack.room,racks:[]};zoneMap[rack.roomKey].racks.push(rack);});
    rackZones=Object.keys(zoneMap).map(function(key){var zone=zoneMap[key],names=zone.racks.map(function(rack){return rack.name;});zone.layout=loadRackLayout(names,zone.key);return zone;}).sort(function(a,b){return naturalCompare(a.name,b.name);});
    byId('dcAutoViewLabel').textContent='自动巡航';
    byId('dcAutoView').title='自动进行360°环绕';
    if(!zoneByKey(activeZoneKey))activeZoneKey=rackZones[0]?rackZones[0].key:'';
    activateZone(activeZoneKey);
    if (!selectedRackName || !rackByName(selectedRackName)) selectedRackName = rackScene[0] ? rackScene[0].id : '';
    updateRackInspector(selectedRackName);
    byId('dcRackGrid').innerHTML = '';
    byId('dcEmpty').hidden = servers.length !== 0;
    byId('dcRackCount').textContent = rackScene.length;
    byId('dcScrollGuide').hidden = true;
  }
  function renderAlerts(servers) {
    var alerts = servers.filter(function(server) { return statusOf(server).key !== 'normal'; }).sort(function(a,b) {
      return (a.status === 'offline' ? 0 : 1) - (b.status === 'offline' ? 0 : 1);
    });
    byId('dcAlertBadge').textContent = alerts.length;
    byId('dcAlertList').innerHTML = alerts.length ? alerts.map(function(server) {
      var state = statusOf(server), location = rackLocation(server.rack_number, server.rack_level);
      return '<button type="button" class="dc-alert-item ' + state.key + '" data-server-id="' + server.id + '"><i></i><div><strong>' + escapeHtml(server.name || physicalIpOf(server)) + '</strong><span>' + escapeHtml(physicalIpOf(server)) + ' · ' + escapeHtml(location.rack) + (location.u ? ' / U' + location.u : '') + '</span></div><b>' + state.label + '</b></button>';
    }).join('') : '<div class="dc-all-clear"><span>✓</span><strong>运行平稳</strong><small>当前机房暂无警告或报错</small></div>';
    byId('dcAlertList').querySelectorAll('.dc-alert-item').forEach(function(button) {
      button.addEventListener('click', function() {
        var server = allServers.find(function(item) { return String(item.id) === button.dataset.serverId; });
        if (server) showDetail(server);
      });
    });
  }
  function renderSummary(servers) {
    var counts = {normal:0,warning:0,error:0}, mounted = 0;
    servers.forEach(function(server) { counts[statusOf(server).key]++; if (server.rack_number) mounted++; });
    var health = servers.length ? Math.round(counts.normal / servers.length * 100) : 0;
    byId('dcNormalCount').textContent = counts.normal; byId('dcWarningCount').textContent = counts.warning; byId('dcErrorCount').textContent = counts.error;
    byId('dcServerCount').textContent = servers.length; byId('dcMountedCount').textContent = mounted; byId('dcUnassignedCount').textContent = servers.length - mounted;
    byId('dcHealthRate').textContent = health; byId('dcHealthGauge').style.setProperty('--health', health * 3.6 + 'deg');
    var active = byId('dcRoomSwitcher').querySelector('button.active span');
    byId('dcRoomName').textContent = active ? active.textContent : '暂无机房';
    byId('dcRoomSubline').textContent = '机房资产实时切片';
  }
  function renderView() {
    renderRooms();
    var servers = currentServers(); renderSummary(servers); renderRacks(servers); renderAlerts(servers);
  }
  function showDetail(server) {
    var state = statusOf(server), location = rackLocation(server.rack_number, server.rack_level), panel = byId('dcServerPopover');
    var status = byId('dcDetailStatus'); status.className = 'dc-detail-status ' + state.key; status.querySelector('span').textContent = state.label;
    byId('dcDetailName').textContent = server.name || physicalIpOf(server);
    byId('dcDetailAddress').textContent = physicalIpOf(server);
    byId('dcDetailRoom').textContent = roomNames(server).join('、');
    byId('dcDetailRack').textContent = location.rack + (location.u ? ' / U' + location.u : ' / 自动顺位');
    byId('dcDetailType').textContent = server.resource_type || '-';
    byId('dcDetailLastSeen').textContent = server.last_success || (server.status === 'checking' ? '首次探测中' : '暂无成功记录');
    panel.hidden = false;
  }
  function fetchStatus() {
    byId('dcRefreshBtn').classList.add('loading');
    fetch('/api/dashboard/status', {credentials:'include'}).then(function(response) {
      if (!response.ok) throw new Error('status ' + response.status); return response.json();
    }).then(function(data) {
      if (disposed) return;
      var nextServers=data.servers||[],fingerprint=JSON.stringify(nextServers.filter(isPhysicalServer).map(function(server){return [server.id,server.status,server.physical_ip,server.resource_type,server.room_affiliation,server.rack_number,server.rack_level,server.name];}));
      allServers = nextServers;
      if(fingerprint!==lastStatusFingerprint){
        lastStatusFingerprint=fingerprint;
        var roomStillExists = allServers.some(function(server) { return isPhysicalServer(server)&&roomNames(server).some(function(name) { return roomKey(name) === selectedRoom; }); });
        if (!roomStillExists) selectedRoom = '';
        renderView();
      }
      byId('dcUpdatedAt').textContent = '同步于 ' + data.updated_at;
    }).catch(function() { byId('dcUpdatedAt').textContent = '同步中断，系统将在稍后重试'; })
      .finally(function() { byId('dcRefreshBtn').classList.remove('loading'); });
  }
  function toggleFullscreen() {
    if (document.fullscreenElement) document.exitFullscreen();
    else if (byId('dataCenterWall').requestFullscreen) byId('dataCenterWall').requestFullscreen();
  }
  function syncFullscreen() {
    var active = document.fullscreenElement === byId('dataCenterWall');
    byId('dcFullscreenBtn').classList.toggle('active', active);
    byId('dcFullscreenBtn').querySelector('span').textContent = active ? '退出' : '全屏';
  }
  function applySceneView() {
    byId('dcRackGrid').style.setProperty('--scene-rx', sceneRotX.toFixed(2) + 'deg');
    byId('dcRackGrid').style.setProperty('--scene-ry', sceneRotY.toFixed(2) + 'deg');
  }
  function setAutoView(enabled) {
    autoView = enabled;
    byId('dcAutoView').classList.toggle('active', enabled);
  }
  function updateRowEditor() {
    var zone=zoneByKey(activeZoneKey);
    if(zone)rackLayout=zone.layout;
    if(!rackLayout.rows.length) rackLayout.rows=[[]];
    var count=rackLayout.rows.length,button=byId('dcAddRackRow');
    byId('dcLayoutRoomName').textContent=zone?zone.name:'暂无机房';
    byId('dcLayoutRowCount').textContent=count;
    button.disabled=count>=8||!rackLayout.rows[count-1].length;
    button.title=count>=8?'最多支持 8 排':(!rackLayout.rows[count-1].length?'请先在当前空排放入机柜':'在前排后新增一排');
  }
  function setEditView(enabled) {
    editView = enabled;
    var scene = document.querySelector('.dc-perspective'), button = byId('dcEditView');
    scene.classList.toggle('edit-mode', enabled); button.classList.toggle('active', enabled); byId('dcLayoutEditor').hidden=!enabled;
    button.textContent = enabled ? '完成编辑' : '编辑视角';
    if (enabled) { setAutoView(false); sceneRotX = 34; sceneRotY = -16; scenePanX = 0; scenePanY = 0; applySceneView(); }
    if (!enabled && rackDrag) { rackDrag = null; scene.classList.remove('dragging-cabinet'); }
    updateRowEditor();
  }
  function canvasPoint(event) {
    var canvas = byId('dcRackCanvas'), rect = canvas.getBoundingClientRect();
    return {x:event.clientX - rect.left, y:event.clientY - rect.top};
  }
  function cabinetAt(x, y) {
    for (var i=rackCabinetAreas.length-1;i>=0;i--) {
      var area=rackCabinetAreas[i];
      if (x>=area.x&&x<=area.x+area.w&&y>=area.y&&y<=area.y+area.h) return area;
    }
    return null;
  }
  function dropRowAt(y, offsetY, zoneKey) {
    var effectiveY=y-offsetY,best=0,distance=Infinity;
    rackRowDropAreas.forEach(function(area){if(area.zoneKey!==zoneKey)return;var next=Math.abs(effectiveY-area.y);if(next<distance){distance=next;best=area.row;}});
    return best;
  }
  function rackInsertionAt(zoneKey, targetRow, x, ignoredId) {
    var areas = rackCabinetAreas.filter(function(area) { return area.zoneKey === zoneKey && area.row === targetRow && area.id !== ignoredId; }).sort(function(a,b) { return a.anchorX-b.anchorX; });
    var index = 0;
    while (index < areas.length && x > areas[index].anchorX) index++;
    var rowArea = rackRowDropAreas.find(function(area) { return area.zoneKey === zoneKey && area.row === targetRow; });
    var markerX = rowArea ? rowArea.x : x;
    if (areas.length) {
      if (index === 0) markerX = areas[0].anchorX - Math.max(22, areas[0].w * .42);
      else if (index === areas.length) markerX = areas[areas.length-1].anchorX + Math.max(22, areas[areas.length-1].w * .42);
      else markerX = (areas[index-1].anchorX + areas[index].anchorX) / 2;
    }
    return {index:index, x:markerX};
  }
  function commitRackDrop(identifier, targetRow, targetIndex) {
    var rack=rackByName(identifier),zone=rack&&zoneByKey(rack.roomKey);if(!rack||!zone)return;
    zone.layout.rows = zone.layout.rows.map(function(row) { return row.filter(function(item) { return item !== rack.name; }); });
    while (zone.layout.rows.length <= targetRow) zone.layout.rows.push([]);
    var index = Math.max(0, Math.min(Number(targetIndex) || 0, zone.layout.rows[targetRow].length));
    zone.layout.rows[targetRow].splice(index,0,rack.name);
    saveRackLayout(zone.key); updateRackInspector(rack.id); updateRowEditor();
  }
  function setupSceneControls() {
    var scene = document.querySelector('.dc-perspective'), rackCanvas = byId('dcRackCanvas');
    scene.addEventListener('pointerdown', function(event) {
      if (event.target.closest('button') || event.button !== 0) return;
      var point=canvasPoint(event), cabinet=cabinetAt(point.x,point.y);
      if (editView && cabinet) {
        var rowArea=rackRowDropAreas.find(function(area){return area.zoneKey===cabinet.zoneKey&&area.row===cabinet.row;});
        var insertion=rackInsertionAt(cabinet.zoneKey,cabinet.row,point.x,cabinet.id);
        activateZone(cabinet.zoneKey);
        rackDrag={id:cabinet.id,name:cabinet.name,zoneKey:cabinet.zoneKey,fromRow:cabinet.row,x:point.x,y:point.y,startY:point.y,rowOffsetY:point.y-(rowArea?rowArea.y:point.y),targetRow:cabinet.row,targetIndex:insertion.index,insertionX:insertion.x};
        dragging=false; dragDistance=0; setAutoView(false); scene.classList.add('dragging-cabinet'); scene.setPointerCapture(event.pointerId); return;
      }
      dragging = true; dragMode = editView ? 'pan' : 'orbit'; dragDistance = 0; dragX = event.clientX; dragY = event.clientY; setAutoView(false);
      scene.classList.add('dragging'); scene.setPointerCapture(event.pointerId);
    });
    scene.addEventListener('pointermove', function(event) {
      if (rackDrag) {
        var point=canvasPoint(event); dragDistance+=Math.abs(point.x-rackDrag.x)+Math.abs(point.y-rackDrag.y);
        rackDrag.x=point.x; rackDrag.y=point.y; rackDrag.targetRow=dropRowAt(point.y,rackDrag.rowOffsetY,rackDrag.zoneKey);
        var insertion=rackInsertionAt(rackDrag.zoneKey,rackDrag.targetRow,point.x,rackDrag.id);rackDrag.targetIndex=insertion.index;rackDrag.insertionX=insertion.x;
        rackCanvas.style.cursor='grabbing'; return;
      }
      if (!dragging) return;
      dragDistance += Math.abs(event.clientX - dragX) + Math.abs(event.clientY - dragY);
      if (dragMode === 'pan') {
        var rect=rackCanvas.getBoundingClientRect();
        scenePanX=Math.max(-rect.width*.42,Math.min(rect.width*.42,scenePanX+event.clientX-dragX));
        scenePanY=Math.max(-rect.height*.32,Math.min(rect.height*.32,scenePanY+event.clientY-dragY));
      } else {
        sceneRotY = (sceneRotY + (event.clientX - dragX) * .28 + 720) % 360;
        var minPitch=-10,maxPitch=46;
        sceneRotX = Math.max(minPitch, Math.min(maxPitch, sceneRotX - (event.clientY - dragY) * .12));
      }
      dragX = event.clientX; dragY = event.clientY; applySceneView();
    });
    function stopDrag(event) {
      if (rackDrag) {
        if (dragDistance>6) commitRackDrop(rackDrag.id,rackDrag.targetRow,rackDrag.targetIndex); else updateRackInspector(rackDrag.id);
        rackDrag=null; scene.classList.remove('dragging-cabinet'); rackCanvas.style.cursor=editView?'move':'grab';
        if (scene.hasPointerCapture(event.pointerId)) scene.releasePointerCapture(event.pointerId); return;
      }
      if (!dragging) return; dragging = false; dragMode = ''; scene.classList.remove('dragging');
      if (scene.hasPointerCapture(event.pointerId)) scene.releasePointerCapture(event.pointerId);
    }
    scene.addEventListener('pointerup', stopDrag); scene.addEventListener('pointercancel', stopDrag);
    byId('dcAutoView').addEventListener('click', function() { if(editView) setEditView(false);setAutoView(!autoView); });
    byId('dcResetView').addEventListener('click', function() { sceneRotX = editView ? 34 : 22; sceneRotY = editView ? -16 : -22; scenePanX = 0; scenePanY = 0; setAutoView(false); applySceneView(); });
    byId('dcEditView').addEventListener('click', function() { setEditView(!editView); });
    byId('dcAddRackRow').addEventListener('click', function() { var zone=zoneByKey(activeZoneKey);if(!zone||zone.layout.rows.length>=8||!zone.layout.rows[zone.layout.rows.length-1].length)return;zone.layout.rows.push([]);rackLayout=zone.layout;saveRackLayout(zone.key);updateRowEditor(); });
    rackCanvas.addEventListener('click', function(event) {
      if (dragDistance > 6) return;
      var rect = rackCanvas.getBoundingClientRect(), x = event.clientX - rect.left, y = event.clientY - rect.top;
      for (var i = rackHitAreas.length - 1; i >= 0; i--) {
        var hit = rackHitAreas[i];
        if (x >= hit.x && x <= hit.x + hit.w && y >= hit.y && y <= hit.y + hit.h) { showDetail(hit.server); return; }
      }
      var cabinet=cabinetAt(x,y); if(cabinet) updateRackInspector(cabinet.id);
    });
    rackCanvas.addEventListener('pointermove', function(event) {
      if (dragging || rackDrag) return;
      var rect = rackCanvas.getBoundingClientRect(), x = event.clientX - rect.left, y = event.clientY - rect.top;
      var overServer = rackHitAreas.some(function(hit) { return x >= hit.x && x <= hit.x + hit.w && y >= hit.y && y <= hit.y + hit.h; });
      var overCabinet=cabinetAt(x,y); if(overCabinet&&overCabinet.id!==selectedRackName) updateRackInspector(overCabinet.id);
      rackCanvas.style.cursor = overServer && !editView ? 'pointer' : (editView && overCabinet ? 'grab' : 'move');
    });
  }
  function roundedRect(context, x, y, width, height, radius) {
    radius = Math.min(radius, width / 2, height / 2);
    context.beginPath(); context.moveTo(x + radius, y); context.arcTo(x + width, y, x + width, y + height, radius);
    context.arcTo(x + width, y + height, x, y + height, radius); context.arcTo(x, y + height, x, y, radius);
    context.arcTo(x, y, x + width, y, radius); context.closePath();
  }
  function polygon(context, points) {
    context.beginPath(); context.moveTo(points[0][0], points[0][1]);
    for (var i=1;i<points.length;i++) context.lineTo(points[i][0], points[i][1]);
    context.closePath();
  }
  function drawRackCabinet(context, rack, x, baseY, width, height, depthX, depthY, scale, rowKey, rowIndex) {
    var topY = baseY - height, right = x + width, direction = depthX >= 0 ? 1 : -1;
    context.save();
    context.globalAlpha = .24; context.fillStyle = '#3b82a7'; context.beginPath();
    context.ellipse(x + width / 2 + depthX * .55, baseY + 9, width * .67, 12 * scale, 0, 0, Math.PI * 2); context.fill();
    context.globalAlpha = 1;

    var topGradient = context.createLinearGradient(x, topY + depthY, right, topY);
    topGradient.addColorStop(0, '#8bc8e3'); topGradient.addColorStop(1, '#326f91');
    polygon(context, [[x,topY],[x+depthX,topY+depthY],[right+depthX,topY+depthY],[right,topY]]);
    context.fillStyle = topGradient; context.fill(); context.strokeStyle = 'rgba(224,250,255,.9)'; context.lineWidth = 1; context.stroke();

    var sidePoints = direction > 0 ? [[right,topY],[right+depthX,topY+depthY],[right+depthX,baseY+depthY],[right,baseY]] : [[x,topY],[x+depthX,topY+depthY],[x+depthX,baseY+depthY],[x,baseY]];
    var sideGradient = context.createLinearGradient(x,topY,right+depthX,baseY);
    sideGradient.addColorStop(0,'#2d6988'); sideGradient.addColorStop(1,'#123d58');
    polygon(context, sidePoints); context.fillStyle = sideGradient; context.fill(); context.strokeStyle = 'rgba(60,140,178,.85)'; context.stroke();
    for (var vent=0;vent<5;vent++) {
      var vy = topY + height * (.16 + vent * .16); context.strokeStyle='rgba(168,226,247,.22)'; context.lineWidth=1;
      context.beginPath(); context.moveTo(sidePoints[0][0] + depthX * .2, vy + depthY * .2); context.lineTo(sidePoints[1][0] - depthX * .16, vy + depthY * .84); context.stroke();
    }

    var bodyGradient = context.createLinearGradient(x,topY,right,baseY);
    bodyGradient.addColorStop(0,'#245975'); bodyGradient.addColorStop(.15,'#123c55'); bodyGradient.addColorStop(.52,'#082c42'); bodyGradient.addColorStop(1,'#184a63');
    context.fillStyle=bodyGradient; roundedRect(context,x,topY,width,height,3); context.fill();
    context.strokeStyle='#4b92b2'; context.lineWidth=Math.max(2,3*scale); context.stroke();
    context.strokeStyle='rgba(201,241,255,.38)'; context.lineWidth=1; roundedRect(context,x+5*scale,topY+24*scale,width-10*scale,height-34*scale,2); context.stroke();

    context.fillStyle='rgba(5,28,42,.76)'; roundedRect(context,x+7*scale,topY+29*scale,width-14*scale,height-42*scale,2); context.fill();
    var innerTop=topY+31*scale, innerHeight=height-47*scale;
    context.lineWidth=.6; context.strokeStyle='rgba(123,199,226,.15)';
    for (var line=0;line<=42;line+=3) { var ly=innerTop+innerHeight*(line/42); context.beginPath(); context.moveTo(x+8*scale,ly); context.lineTo(right-8*scale,ly); context.stroke(); }
    context.fillStyle='#effcff'; context.font='700 '+Math.max(9,11*scale)+'px Consolas'; context.textAlign='center'; context.textBaseline='middle'; context.fillText(rack.name,x+width/2,topY+14*scale);
    context.fillStyle='#7fe5ff'; context.beginPath(); context.arc(right-10*scale,topY+13*scale,2.1*scale,0,Math.PI*2); context.fill();

    rack.arranged.forEach(function(item) {
      var server=item.server,state=statusOf(server), unitHeight=Math.max(5,7*scale);
      var unitY=innerTop+innerHeight-(item.u/42)*innerHeight-unitHeight/2;
      var color=state.key==='normal'?'#24c996':state.key==='warning'?'#f0b134':'#ed5b67';
      context.save(); context.shadowColor=color; context.shadowBlur=state.key==='error'?11:7; context.fillStyle=color;
      roundedRect(context,x+12*scale,unitY,width-24*scale,unitHeight,1.5); context.fill(); context.restore();
      context.fillStyle='rgba(255,255,255,.92)'; context.beginPath(); context.arc(x+17*scale,unitY+unitHeight/2,1.3*scale,0,Math.PI*2); context.fill();
      if (width>88) { context.fillStyle='#fff'; context.font='600 '+Math.max(4,5*scale)+'px "Segoe UI"'; context.textAlign='left'; context.fillText(String(server.name||server.ip).slice(0,10),x+22*scale,unitY+unitHeight/2); context.textAlign='right'; context.fillText('U'+item.u,right-14*scale,unitY+unitHeight/2); }
      rackHitAreas.push({x:x+10*scale,y:unitY-2,w:width-20*scale,h:unitHeight+4,server:server});
    });

    context.fillStyle='#315f76'; context.fillRect(x-4*scale,baseY-7*scale,width+8*scale,9*scale);
    context.fillStyle='#1c455a'; context.fillRect(x+7*scale,baseY+2*scale,12*scale,6*scale); context.fillRect(right-19*scale,baseY+2*scale,12*scale,6*scale);
    context.fillStyle='rgba(255,255,255,.96)'; roundedRect(context,x+width*.06,baseY+12*scale,width*.88,31*scale,6*scale); context.fill();
    context.strokeStyle='rgba(57,151,200,.22)'; context.lineWidth=1; roundedRect(context,x+width*.06,baseY+12*scale,width*.88,31*scale,6*scale); context.stroke();
    context.fillStyle='#174e6c'; context.font='700 '+Math.max(8,10*scale)+'px Consolas'; context.textAlign='center'; context.fillText(rack.name,x+width/2,baseY+22*scale);
    context.fillStyle='#547e94'; context.font='600 '+Math.max(5.5,6.5*scale)+'px "Segoe UI"'; context.fillText('设备 '+rack.servers.length+'  ·  正常 '+rack.counts.normal+'  ·  异常 '+(rack.counts.warning+rack.counts.error),x+width/2,baseY+34*scale);
    if (selectedRackName===rack.id) { context.strokeStyle='#27a7dc'; context.lineWidth=2; roundedRect(context,x-3*scale,topY-3*scale,width+6*scale,height+9*scale,5*scale); context.stroke(); }
    rackCabinetAreas.push({x:Math.min(x,x+depthX)-4,y:topY+Math.min(0,depthY)-4,w:width+Math.abs(depthX)+8,h:height+Math.abs(depthY)+50*scale,name:rack.name,row:rowKey,index:rowIndex});
    context.restore();
  }
  function buildProjector(rect, halfX, halfZ, maxColumns, rowCount, maxScale, maxRackScale, sceneHeight) {
    var yaw=sceneRotY*Math.PI/180,pitch=sceneRotX*Math.PI/180,cosY=Math.cos(yaw),sinY=Math.sin(yaw),cosP=Math.cos(pitch),sinP=Math.sin(pitch);
    var cameraDistance=10+maxColumns*.35+Math.max(0,rowCount-2)*.38;
    var fitHeight=Math.max(sceneHeight||0,1.86*(maxRackScale||1)),fitAngles=[0,45,90,135,180,225,270,315],fitWidth=0,fitVertical=0;
    fitAngles.forEach(function(degrees){var fy=degrees*Math.PI/180,fc=Math.cos(fy),fs=Math.sin(fy),samples=[];
      [-halfX,halfX].forEach(function(x){[-halfZ,halfZ].forEach(function(z){[0,fitHeight].forEach(function(y){var rx=x*fc-z*fs,rz=x*fs+z*fc,ry=y*cosP-rz*sinP,depth=y*sinP+rz*cosP,p=Math.max(.72,Math.min(1.32,cameraDistance/(cameraDistance-depth)));samples.push({x:rx*p,y:-ry*p});});});});
      var xs=samples.map(function(point){return point.x;}),ys=samples.map(function(point){return point.y;});fitWidth=Math.max(fitWidth,Math.max.apply(Math,xs)-Math.min.apply(Math,xs));fitVertical=Math.max(fitVertical,Math.max.apply(Math,ys)-Math.min.apply(Math,ys));
    });
    var sideMargin=editView?40:18,topMargin=editView?56:22,bottomMargin=editView?52:38;
    var scale=Math.min((rect.width-sideMargin*2)/Math.max(.1,fitWidth),(rect.height-topMargin-bottomMargin)/Math.max(.1,fitVertical),maxScale*(editView?.93:1));
    scale=Math.max(10,scale);
    var targetY=fitHeight*.44,targetDepth=targetY*sinP,targetPerspective=Math.max(.72,Math.min(1.32,cameraDistance/(cameraDistance-targetDepth))),targetProjectedY=-targetY*cosP*targetPerspective;
    var originX=rect.width/2+scenePanX;
    var originY=rect.height*.52-targetProjectedY*scale+scenePanY;
    function project(point) {
      var rx=point.x*cosY-point.z*sinY,rz=point.x*sinY+point.z*cosY;
      var ry=point.y*cosP-rz*sinP,depth=point.y*sinP+rz*cosP;
      var perspective=Math.max(.72,Math.min(1.32,cameraDistance/(cameraDistance-depth)));
      return {x:originX+rx*scale*perspective,y:originY-ry*scale*perspective,z:depth,p:perspective};
    }
    return {project:project,yaw:yaw,pitch:pitch,scale:scale};
  }
  function worldPoint(model, x, y, z) { var scale=model.rackScale||1;return {x:model.x+x*scale,y:y*scale,z:model.z+z*scale}; }
  function projectedBounds(points) {
    var xs=points.map(function(point){return point.x;}),ys=points.map(function(point){return point.y;});
    var minX=Math.min.apply(Math,xs),maxX=Math.max.apply(Math,xs),minY=Math.min.apply(Math,ys),maxY=Math.max.apply(Math,ys);
    return {x:minX,y:minY,w:maxX-minX,h:maxY-minY};
  }
  function paintPolygon(context, points, fill, stroke, lineWidth) {
    polygon(context,points.map(function(point){return [point.x,point.y];}));
    if(fill){context.fillStyle=fill;context.fill();} if(stroke){context.strokeStyle=stroke;context.lineWidth=lineWidth||1;context.stroke();}
  }
  function drawRoomShell(context,projector,zone) {
    var project=projector.project,cx=zone.centerX,h=zone.roomHeight,halfX=zone.platformHalfX,halfZ=zone.platformHalfZ,backZ=-halfZ*.98,frontZ=halfZ*.92;
    var back=[project({x:cx-halfX,y:.02,z:backZ}),project({x:cx+halfX,y:.02,z:backZ}),project({x:cx+halfX,y:h,z:backZ}),project({x:cx-halfX,y:h,z:backZ})];
    var left=[project({x:cx-halfX,y:.02,z:backZ}),project({x:cx-halfX,y:.02,z:frontZ}),project({x:cx-halfX,y:h,z:frontZ}),project({x:cx-halfX,y:h,z:backZ})];
    var right=[project({x:cx+halfX,y:.02,z:backZ}),project({x:cx+halfX,y:.02,z:frontZ}),project({x:cx+halfX,y:h,z:frontZ}),project({x:cx+halfX,y:h,z:backZ})];
    var ceiling=[project({x:cx-halfX,y:h,z:backZ}),project({x:cx+halfX,y:h,z:backZ}),project({x:cx+halfX,y:h,z:frontZ}),project({x:cx-halfX,y:h,z:frontZ})];
    var wallGradient=context.createLinearGradient(back[0].x,back[0].y,back[2].x,back[2].y);wallGradient.addColorStop(0,'rgba(218,241,250,.72)');wallGradient.addColorStop(.55,'rgba(176,218,235,.44)');wallGradient.addColorStop(1,'rgba(112,181,211,.24)');
    paintPolygon(context,back,wallGradient,'rgba(62,153,194,.48)',1);
    paintPolygon(context,left,'rgba(121,194,222,.16)','rgba(63,154,194,.34)',.9);paintPolygon(context,right,'rgba(89,171,205,.13)','rgba(55,145,185,.3)',.9);
    var ceilingGradient=context.createLinearGradient(ceiling[0].x,ceiling[0].y,ceiling[2].x,ceiling[2].y);ceilingGradient.addColorStop(0,'rgba(244,252,255,.56)');ceilingGradient.addColorStop(.55,'rgba(175,224,241,.28)');ceilingGradient.addColorStop(1,'rgba(101,185,216,.12)');paintPolygon(context,ceiling,ceilingGradient,'rgba(66,160,200,.38)',1);
    context.save();context.strokeStyle='rgba(66,158,198,.19)';context.lineWidth=.65;
    for(var panel=1;panel<6;panel++){var px=cx-halfX+(halfX*2)*(panel/6),pa=project({x:px,y:.04,z:backZ+.006}),pb=project({x:px,y:h-.04,z:backZ+.006});context.beginPath();context.moveTo(pa.x,pa.y);context.lineTo(pb.x,pb.y);context.stroke();}
    for(var level=1;level<5;level++){var py=h*(level/5),la=project({x:cx-halfX+.02,y:py,z:backZ+.008}),lb=project({x:cx+halfX-.02,y:py,z:backZ+.008});context.beginPath();context.moveTo(la.x,la.y);context.lineTo(lb.x,lb.y);context.stroke();}context.restore();
    var busA=project({x:cx-halfX*.78,y:h*.72,z:backZ+.018}),busB=project({x:cx+halfX*.78,y:h*.72,z:backZ+.018});context.save();context.strokeStyle='rgba(42,146,190,.7)';context.lineWidth=2.2;context.shadowColor='rgba(52,174,216,.34)';context.shadowBlur=8;context.beginPath();context.moveTo(busA.x,busA.y);context.lineTo(busB.x,busB.y);context.stroke();context.restore();
    [-.94,.94].forEach(function(side){var bottom=project({x:cx+halfX*side,y:.02,z:backZ+.025}),top=project({x:cx+halfX*side,y:h,z:backZ+.025});context.save();context.strokeStyle='rgba(45,130,170,.82)';context.lineWidth=4;context.shadowColor='rgba(56,165,207,.28)';context.shadowBlur=7;context.beginPath();context.moveTo(bottom.x,bottom.y);context.lineTo(top.x,top.y);context.stroke();context.restore();});
    [-.48,.28].forEach(function(zRatio){var strip=[project({x:cx-halfX*.68,y:h-.018,z:halfZ*zRatio-.055}),project({x:cx+halfX*.68,y:h-.018,z:halfZ*zRatio-.055}),project({x:cx+halfX*.68,y:h-.018,z:halfZ*zRatio+.055}),project({x:cx-halfX*.68,y:h-.018,z:halfZ*zRatio+.055})];context.save();context.shadowColor='rgba(255,255,255,.9)';context.shadowBlur=12;paintPolygon(context,strip,'rgba(240,252,255,.92)','rgba(98,194,225,.62)',.7);context.restore();});
    var title=project({x:cx,y:h*.88,z:backZ+.025});context.save();context.textAlign='center';context.textBaseline='middle';context.fillStyle='#176f98';context.font='800 11px "Microsoft YaHei"';context.fillText(String(zone.name||'未分配机房'),title.x,title.y);context.fillStyle='rgba(44,132,172,.72)';context.font='700 7px Consolas';context.fillText(zone.racks.length+' CABINETS · '+zone.rowCount+' ROWS',title.x,title.y+12);context.restore();
  }
  function drawRoomEnvironment(context, projector, zone, floorHalfZ) {
    var project=projector.project,floorHalfX=zone.platformHalfX||zone.halfX,centerX=zone.centerX,rowZs=zone.rowZs;
    function zx(x){return centerX+x;}
    var floor=[project({x:zx(-floorHalfX),y:.025,z:-floorHalfZ}),project({x:zx(floorHalfX),y:.025,z:-floorHalfZ}),project({x:zx(floorHalfX),y:.025,z:floorHalfZ}),project({x:zx(-floorHalfX),y:.025,z:floorHalfZ})];
    var floorBottom=[project({x:zx(-floorHalfX),y:-.09,z:-floorHalfZ}),project({x:zx(floorHalfX),y:-.09,z:-floorHalfZ}),project({x:zx(floorHalfX),y:-.09,z:floorHalfZ}),project({x:zx(-floorHalfX),y:-.09,z:floorHalfZ})];
    context.save();context.shadowColor='rgba(22,91,128,.32)';context.shadowBlur=18;
    paintPolygon(context,[floor[3],floor[2],floorBottom[2],floorBottom[3]],'#3c809d','rgba(105,191,222,.72)',1.1);
    paintPolygon(context,[floor[0],floor[3],floorBottom[3],floorBottom[0]],'#245b75','rgba(82,158,190,.58)',1);
    paintPolygon(context,[floor[1],floor[2],floorBottom[2],floorBottom[1]],'#1a4b66','rgba(75,151,183,.52)',1);context.restore();
    var floorGradient=context.createLinearGradient(0,Math.min(floor[0].y,floor[1].y),0,Math.max(floor[2].y,floor[3].y));
    floorGradient.addColorStop(0,'rgba(221,244,253,.82)');floorGradient.addColorStop(.48,'rgba(151,211,235,.54)');floorGradient.addColorStop(1,'rgba(87,174,211,.4)');
    context.save();context.shadowColor='rgba(35,143,190,.2)';context.shadowBlur=14;paintPolygon(context,floor,floorGradient,'rgba(45,151,199,.76)',1.45);context.restore();
    var innerFloor=[project({x:zx(-floorHalfX*.94),y:.034,z:-floorHalfZ*.91}),project({x:zx(floorHalfX*.94),y:.034,z:-floorHalfZ*.91}),project({x:zx(floorHalfX*.94),y:.034,z:floorHalfZ*.91}),project({x:zx(-floorHalfX*.94),y:.034,z:floorHalfZ*.91})];
    context.save();context.setLineDash([7,5]);paintPolygon(context,innerFloor,null,'rgba(77,174,213,.48)',.8);context.setLineDash([]);context.restore();

    rowZs.forEach(function(rowZ,index){
      var platformDepth=rowZs.length>3?.3:.4;
      var platform=[project({x:zx(-floorHalfX*.82),y:.055,z:rowZ-platformDepth}),project({x:zx(floorHalfX*.82),y:.055,z:rowZ-platformDepth}),project({x:zx(floorHalfX*.82),y:.055,z:rowZ+platformDepth}),project({x:zx(-floorHalfX*.82),y:.055,z:rowZ+platformDepth})];
      var platformBottom=[project({x:zx(-floorHalfX*.82),y:.012,z:rowZ-platformDepth}),project({x:zx(floorHalfX*.82),y:.012,z:rowZ-platformDepth}),project({x:zx(floorHalfX*.82),y:.012,z:rowZ+platformDepth}),project({x:zx(-floorHalfX*.82),y:.012,z:rowZ+platformDepth})];
      var platformGradient=context.createLinearGradient(platform[0].x,platform[0].y,platform[2].x,platform[2].y);
      platformGradient.addColorStop(0,'#d9f1fa');platformGradient.addColorStop(.52,'#9dcfe3');platformGradient.addColorStop(1,'#6caecb');
      paintPolygon(context,[platform[3],platform[2],platformBottom[2],platformBottom[3]],'#4c91ac','rgba(88,175,207,.65)',.8);
      context.save();context.shadowColor='rgba(29,135,184,.3)';context.shadowBlur=10;paintPolygon(context,platform,platformGradient,'rgba(38,131,176,.72)',1.2);context.restore();
      var label=project({x:zx(-floorHalfX*.77),y:.015,z:rowZ});
      context.save();context.translate(label.x,label.y);context.fillStyle='#27799e';context.font='800 8px Consolas';context.textAlign='center';context.textBaseline='middle';context.fillText(rowCode(index)+' ROW',0,0);context.restore();
    });

    var aisleMiddle=Math.floor(rowZs.length/2),aisleZ=rowZs.length>1?(rowZs[aisleMiddle-1]+rowZs[aisleMiddle])/2:0;
    var aisle=[project({x:zx(-floorHalfX*.84),y:-.005,z:aisleZ-.24}),project({x:zx(floorHalfX*.84),y:-.005,z:aisleZ-.24}),project({x:zx(floorHalfX*.84),y:-.005,z:aisleZ+.24}),project({x:zx(-floorHalfX*.84),y:-.005,z:aisleZ+.24})];
    var aisleGradient=context.createLinearGradient(aisle[0].x,aisle[0].y,aisle[2].x,aisle[2].y);aisleGradient.addColorStop(0,'rgba(235,249,254,.58)');aisleGradient.addColorStop(.5,'rgba(133,205,233,.3)');aisleGradient.addColorStop(1,'rgba(235,249,254,.58)');
    paintPolygon(context,aisle,aisleGradient,'rgba(48,151,201,.38)',.9);
    context.save();context.strokeStyle='rgba(38,148,198,.46)';context.lineWidth=1.1;
    for(var marker=-floorHalfX*.58;marker<=floorHalfX*.58;marker+=.72){var a=project({x:zx(marker-.13),y:.01,z:aisleZ-.08}),b=project({x:zx(marker),y:.01,z:aisleZ+.08}),c=project({x:zx(marker+.13),y:.01,z:aisleZ-.08});context.beginPath();context.moveTo(a.x,a.y);context.lineTo(b.x,b.y);context.lineTo(c.x,c.y);context.stroke();}
    context.restore();

    [[-floorHalfX*.82,-floorHalfZ*.84],[floorHalfX*.82,-floorHalfZ*.84],[-floorHalfX*.82,floorHalfZ*.84],[floorHalfX*.82,floorHalfZ*.84]].forEach(function(position){var beacon=project({x:zx(position[0]),y:.04,z:position[1]});context.save();context.fillStyle='#29aede';context.shadowColor='#29aede';context.shadowBlur=9;context.beginPath();context.arc(beacon.x,beacon.y,2.1,0,Math.PI*2);context.fill();context.restore();});
  }
  function drawSharedRoomStage(context,projector,zones) {
    if(!zones.length)return;
    var project=projector.project,minX=Math.min.apply(Math,zones.map(function(zone){return zone.centerX-zone.platformHalfX;}))-.38,maxX=Math.max.apply(Math,zones.map(function(zone){return zone.centerX+zone.platformHalfX;}))+.38;
    var halfZ=Math.max.apply(Math,zones.map(function(zone){return zone.platformHalfZ;}))+.34;
    var underlay=[project({x:minX,y:-.205,z:-halfZ}),project({x:maxX,y:-.205,z:-halfZ}),project({x:maxX,y:-.205,z:halfZ}),project({x:minX,y:-.205,z:halfZ})];
    var glow=context.createLinearGradient(underlay[0].x,underlay[0].y,underlay[2].x,underlay[2].y);glow.addColorStop(0,'rgba(210,241,252,.08)');glow.addColorStop(.5,'rgba(86,190,227,.16)');glow.addColorStop(1,'rgba(198,236,250,.07)');
    context.save();context.shadowColor='rgba(47,159,205,.18)';context.shadowBlur=28;paintPolygon(context,underlay,glow,'rgba(77,166,205,.18)',1);context.restore();
    zones.forEach(function(zone){var center=project({x:zone.centerX,y:-.19,z:0}),radius=Math.max(42,zone.platformHalfX*projector.scale*.72),pool=context.createRadialGradient(center.x,center.y,2,center.x,center.y,radius);pool.addColorStop(0,'rgba(101,202,235,.18)');pool.addColorStop(.55,'rgba(80,177,216,.07)');pool.addColorStop(1,'rgba(80,177,216,0)');context.save();context.fillStyle=pool;context.beginPath();context.ellipse(center.x,center.y,radius,radius*.34,0,0,Math.PI*2);context.fill();context.restore();});
    for(var i=0;i<zones.length-1;i++){
      var left=zones[i],right=zones[i+1],bridgeLeft=left.centerX+left.platformHalfX*.94,bridgeRight=right.centerX-right.platformHalfX*.94;
      if(bridgeRight<=bridgeLeft)continue;
      var bridge=[project({x:bridgeLeft,y:.018,z:-.22}),project({x:bridgeRight,y:.018,z:-.22}),project({x:bridgeRight,y:.018,z:.22}),project({x:bridgeLeft,y:.018,z:.22})];
      var bridgeGradient=context.createLinearGradient(bridge[0].x,bridge[0].y,bridge[1].x,bridge[1].y);bridgeGradient.addColorStop(0,'rgba(110,197,228,.36)');bridgeGradient.addColorStop(.5,'rgba(225,247,254,.72)');bridgeGradient.addColorStop(1,'rgba(110,197,228,.36)');paintPolygon(context,bridge,bridgeGradient,'rgba(67,160,201,.46)',.8);
      var bridgeMid=project({x:(bridgeLeft+bridgeRight)/2,y:.03,z:0});context.save();context.fillStyle='#3ea6cf';context.shadowColor='#65c8e9';context.shadowBlur=6;context.beginPath();context.arc(bridgeMid.x,bridgeMid.y,1.8,0,Math.PI*2);context.fill();context.restore();
    }
  }
  function drawOpenRackFloor(context,projector,zones) {
    if(!zones.length)return;
    var project=projector.project,minX=Math.min.apply(Math,zones.map(function(zone){return zone.centerX-zone.platformHalfX;}))-.26,maxX=Math.max.apply(Math,zones.map(function(zone){return zone.centerX+zone.platformHalfX;}))+.26;
    var halfZ=Math.max.apply(Math,zones.map(function(zone){return zone.platformHalfZ;}))+.18;
    var floor=[project({x:minX,y:-.025,z:-halfZ}),project({x:maxX,y:-.025,z:-halfZ}),project({x:maxX,y:-.025,z:halfZ}),project({x:minX,y:-.025,z:halfZ})];
    var floorGradient=context.createLinearGradient(floor[0].x,floor[0].y,floor[3].x,floor[3].y);floorGradient.addColorStop(0,'rgba(229,247,253,.62)');floorGradient.addColorStop(.52,'rgba(168,218,237,.42)');floorGradient.addColorStop(1,'rgba(100,184,217,.28)');
    context.save();context.shadowColor='rgba(44,154,202,.18)';context.shadowBlur=18;paintPolygon(context,floor,floorGradient,'rgba(53,158,203,.48)',1.1);context.restore();
    context.save();context.strokeStyle='rgba(49,153,198,.17)';context.lineWidth=.75;
    for(var gx=minX;gx<=maxX+.01;gx+=.48){var ga=project({x:gx,y:-.01,z:-halfZ}),gb=project({x:gx,y:-.01,z:halfZ});context.beginPath();context.moveTo(ga.x,ga.y);context.lineTo(gb.x,gb.y);context.stroke();}
    for(var gz=-halfZ;gz<=halfZ+.01;gz+=.42){var za=project({x:minX,y:-.01,z:gz}),zb=project({x:maxX,y:-.01,z:gz});context.beginPath();context.moveTo(za.x,za.y);context.lineTo(zb.x,zb.y);context.stroke();}context.restore();
    zones.forEach(function(zone){
      zone.rowZs.forEach(function(rowZ,rowIndex){var padDepth=zone.rowZs.length>3?.25:.31,pad=[project({x:zone.centerX-zone.platformHalfX*.82,y:.006,z:rowZ-padDepth}),project({x:zone.centerX+zone.platformHalfX*.82,y:.006,z:rowZ-padDepth}),project({x:zone.centerX+zone.platformHalfX*.82,y:.006,z:rowZ+padDepth}),project({x:zone.centerX-zone.platformHalfX*.82,y:.006,z:rowZ+padDepth})];var padGradient=context.createLinearGradient(pad[0].x,pad[0].y,pad[2].x,pad[2].y);padGradient.addColorStop(0,'rgba(196,232,245,.58)');padGradient.addColorStop(.55,'rgba(105,181,213,.38)');padGradient.addColorStop(1,'rgba(68,151,188,.46)');paintPolygon(context,pad,padGradient,'rgba(44,143,184,.48)',.8);var label=project({x:zone.centerX-zone.platformHalfX*.76,y:.025,z:rowZ});context.save();context.fillStyle='#347f9f';context.font='800 7px Consolas';context.textAlign='left';context.textBaseline='middle';context.fillText(rowCode(rowIndex)+' ROW',label.x,label.y);context.restore();});
      var outline=[project({x:zone.centerX-zone.platformHalfX*.9,y:.014,z:-zone.platformHalfZ*.9}),project({x:zone.centerX+zone.platformHalfX*.9,y:.014,z:-zone.platformHalfZ*.9}),project({x:zone.centerX+zone.platformHalfX*.9,y:.014,z:zone.platformHalfZ*.9}),project({x:zone.centerX-zone.platformHalfX*.9,y:.014,z:zone.platformHalfZ*.9})];context.save();context.setLineDash([7,6]);paintPolygon(context,outline,null,'rgba(43,145,188,.3)',.8);context.setLineDash([]);var roomLabel=project({x:zone.centerX-zone.platformHalfX*.82,y:.035,z:-zone.platformHalfZ*.76});context.fillStyle='#2b789a';context.font='800 8px "Microsoft YaHei"';context.textAlign='left';context.fillText(zone.name,roomLabel.x,roomLabel.y);context.restore();
    });
    var railLeft=project({x:minX,y:.06,z:-halfZ*.94}),railRight=project({x:maxX,y:.06,z:-halfZ*.94});context.save();context.strokeStyle='rgba(42,153,198,.48)';context.lineWidth=1.3;context.shadowColor='rgba(57,179,218,.25)';context.shadowBlur=6;context.beginPath();context.moveTo(railLeft.x,railLeft.y);context.lineTo(railRight.x,railRight.y);context.stroke();context.restore();
  }
  function drawRack3D(context, model, projector) {
    var rack=model.rack,w=.72,h=1.78,d=.52,project=projector.project;
    var world=[worldPoint(model,-w/2,0,-d/2),worldPoint(model,w/2,0,-d/2),worldPoint(model,w/2,h,-d/2),worldPoint(model,-w/2,h,-d/2),worldPoint(model,-w/2,0,d/2),worldPoint(model,w/2,0,d/2),worldPoint(model,w/2,h,d/2),worldPoint(model,-w/2,h,d/2)];
    var points=world.map(project),faces=[
      {key:'back',indexes:[0,1,2,3],fill:'#17465f'},{key:'left',indexes:[0,4,7,3],fill:'#1b5875'},
      {key:'right',indexes:[1,5,6,2],fill:'#286e8d'},{key:'front',indexes:[4,5,6,7],fill:'#0d354d'},
      {key:'top',indexes:[3,2,6,7],fill:'#75bad8'}
    ];
    faces.forEach(function(face){face.points=face.indexes.map(function(index){return points[index];});face.depth=face.points.reduce(function(total,point){return total+point.z;},0)/face.points.length;});
    faces.sort(function(a,b){return a.depth-b.depth;});
    var selected=selectedRackName===rack.id;
    var footprint=[project(worldPoint(model,-w*.64,0,-d*.62)),project(worldPoint(model,w*.64,0,-d*.62)),project(worldPoint(model,w*.64,0,d*.62)),project(worldPoint(model,-w*.64,0,d*.62))];
    context.save();context.globalAlpha=.16;context.shadowColor='rgba(39,126,174,.24)';context.shadowBlur=12;paintPolygon(context,footprint,'#287da7');context.restore();
    var basePlate=[project(worldPoint(model,-w*.6,.015,-d*.62)),project(worldPoint(model,w*.6,.015,-d*.62)),project(worldPoint(model,w*.6,.015,d*.62)),project(worldPoint(model,-w*.6,.015,d*.62))];
    context.save();context.shadowColor='rgba(40,151,203,.24)';context.shadowBlur=8;paintPolygon(context,basePlate,'#225f7b','rgba(102,198,229,.72)',.8);context.restore();
    faces.forEach(function(face){
      var gradient=context.createLinearGradient(face.points[0].x,face.points[0].y,face.points[2].x,face.points[2].y);
      if(face.key==='front'){gradient.addColorStop(0,'#255f78');gradient.addColorStop(.1,'#123d54');gradient.addColorStop(.48,'#061f2e');gradient.addColorStop(.86,'#0d3448');gradient.addColorStop(1,'#1c526b');}
      else if(face.key==='top'){gradient.addColorStop(0,'#9bd0e3');gradient.addColorStop(.28,'#679eb6');gradient.addColorStop(.62,'#386f89');gradient.addColorStop(1,'#214e65');}
      else if(face.key==='right'){gradient.addColorStop(0,'#397c97');gradient.addColorStop(.25,'#235e77');gradient.addColorStop(.65,'#123e54');gradient.addColorStop(1,'#082a3b');}
      else if(face.key==='left'){gradient.addColorStop(0,'#2d718c');gradient.addColorStop(.26,'#1c566e');gradient.addColorStop(.68,'#10394f');gradient.addColorStop(1,'#07283a');}
      else{gradient.addColorStop(0,'#205a70');gradient.addColorStop(.52,'#123e51');gradient.addColorStop(1,'#082837');}
      paintPolygon(context,face.points,gradient,'#5ca4bf',1.1);
    });

    var frontFacing=Math.cos(projector.yaw)>.06,backFacing=Math.cos(projector.yaw)<-.06;
    if(frontFacing){
      var frontZ=d/2+.012;
      var door=[project(worldPoint(model,-w*.43,.16,frontZ)),project(worldPoint(model,w*.43,.16,frontZ)),project(worldPoint(model,w*.43,h-.17,frontZ)),project(worldPoint(model,-w*.43,h-.17,frontZ))];
      var doorGradient=context.createLinearGradient(door[0].x,door[0].y,door[2].x,door[2].y);
      doorGradient.addColorStop(0,'#173f50');doorGradient.addColorStop(.13,'#0b2a3a');doorGradient.addColorStop(.5,'#03151f');doorGradient.addColorStop(.87,'#092738');doorGradient.addColorStop(1,'#133a4d');
      paintPolygon(context,door,doorGradient,'#66afc9',1.25);
      var innerDoor=[project(worldPoint(model,-w*.38,.22,frontZ+.006)),project(worldPoint(model,w*.38,.22,frontZ+.006)),project(worldPoint(model,w*.38,h-.24,frontZ+.006)),project(worldPoint(model,-w*.38,h-.24,frontZ+.006))];
      paintPolygon(context,innerDoor,'#041620','#39738b',.9);
      context.save();context.strokeStyle='#0b2a38';context.lineWidth=.55;
      for(var brush=1;brush<12;brush++){var brushX=-w*.38+(w*.76)*(brush/12),brushA=project(worldPoint(model,brushX,.24,frontZ+.009)),brushB=project(worldPoint(model,brushX,h-.26,frontZ+.009));context.beginPath();context.moveTo(brushA.x,brushA.y);context.lineTo(brushB.x,brushB.y);context.stroke();}
      context.restore();
      var leftPillar=[project(worldPoint(model,-w*.49,.1,frontZ+.018)),project(worldPoint(model,-w*.405,.14,frontZ+.018)),project(worldPoint(model,-w*.405,h-.15,frontZ+.018)),project(worldPoint(model,-w*.49,h-.1,frontZ+.018))];
      var rightPillar=[project(worldPoint(model,w*.405,.14,frontZ+.018)),project(worldPoint(model,w*.49,.1,frontZ+.018)),project(worldPoint(model,w*.49,h-.1,frontZ+.018)),project(worldPoint(model,w*.405,h-.15,frontZ+.018))];
      var pillarGradient=context.createLinearGradient(leftPillar[0].x,leftPillar[0].y,rightPillar[1].x,rightPillar[1].y);pillarGradient.addColorStop(0,'#326f88');pillarGradient.addColorStop(.3,'#174b63');pillarGradient.addColorStop(.72,'#0d374c');pillarGradient.addColorStop(1,'#2a657e');
      paintPolygon(context,leftPillar,pillarGradient,'#70b2ca',.75);paintPolygon(context,rightPillar,pillarGradient,'#4f96b1',.75);
      var upperFrame=[project(worldPoint(model,-w*.45,h-.17,frontZ+.022)),project(worldPoint(model,w*.45,h-.17,frontZ+.022)),project(worldPoint(model,w*.48,h-.065,frontZ+.022)),project(worldPoint(model,-w*.48,h-.065,frontZ+.022))];
      var lowerFrame=[project(worldPoint(model,-w*.48,.065,frontZ+.022)),project(worldPoint(model,w*.48,.065,frontZ+.022)),project(worldPoint(model,w*.45,.17,frontZ+.022)),project(worldPoint(model,-w*.45,.17,frontZ+.022))];
      paintPolygon(context,upperFrame,pillarGradient,'#73b7ce',.75);paintPolygon(context,lowerFrame,pillarGradient,'#397c96',.75);
      context.strokeStyle='#285d73';context.lineWidth=.65;
      for(var rail=0;rail<=RACK_SLOT_CAPACITY;rail++){var railY=.2+(h-.4)*(rail/RACK_SLOT_CAPACITY),left=project(worldPoint(model,-w*.37,railY,frontZ+.008)),right=project(worldPoint(model,w*.37,railY,frontZ+.008));context.beginPath();context.moveTo(left.x,left.y);context.lineTo(right.x,right.y);context.stroke();}
      context.save();context.fillStyle='#91d2e6';context.font='700 5.5px Consolas';context.textAlign='center';context.textBaseline='middle';
      for(var slotNumber=1;slotNumber<=RACK_SLOT_CAPACITY;slotNumber++){var slotRatioLabel=(slotNumber-1)/(RACK_SLOT_CAPACITY-1),slotLabel=project(worldPoint(model,-w*.405,.22+(h-.52)*slotRatioLabel+.036,frontZ+.032));context.fillText(String(slotNumber),slotLabel.x,slotLabel.y);}
      context.restore();
      rack.arranged.forEach(function(item){
        var slotRatio=RACK_SLOT_CAPACITY===1?0:(item.slot-1)/(RACK_SLOT_CAPACITY-1);
        var y=.22+(h-.52)*slotRatio,unitH=.072,state=statusOf(item.server),color=state.key==='normal'?'#24c996':state.key==='warning'?'#e9a52a':'#eb5967';
        var unit=[project(worldPoint(model,-w*.36,y,frontZ+.03)),project(worldPoint(model,w*.36,y,frontZ+.03)),project(worldPoint(model,w*.36,y+unitH,frontZ+.03)),project(worldPoint(model,-w*.36,y+unitH,frontZ+.03))];
        var moduleGradient=context.createLinearGradient(unit[0].x,unit[0].y,unit[2].x,unit[2].y);moduleGradient.addColorStop(0,'#214a5d');moduleGradient.addColorStop(.38,'#0a2737');moduleGradient.addColorStop(1,'#041822');
        context.save();context.shadowColor=color;context.shadowBlur=state.key==='error'?9:6;paintPolygon(context,unit,moduleGradient,color,1.05);context.restore();
        var bevel=[project(worldPoint(model,-w*.36,y+unitH,frontZ+.03)),project(worldPoint(model,w*.36,y+unitH,frontZ+.03)),project(worldPoint(model,w*.36,y+unitH,frontZ+.065)),project(worldPoint(model,-w*.36,y+unitH,frontZ+.065))];
        paintPolygon(context,bevel,'rgba(99,168,191,.2)','rgba(158,211,228,.27)',.4);
        var accent=[project(worldPoint(model,-w*.36,y+.012,frontZ+.07)),project(worldPoint(model,-w*.315,y+.012,frontZ+.07)),project(worldPoint(model,-w*.315,y+unitH-.012,frontZ+.07)),project(worldPoint(model,-w*.36,y+unitH-.012,frontZ+.07))];
        context.save();context.shadowColor=color;context.shadowBlur=6;paintPolygon(context,accent,color);context.restore();
        context.strokeStyle='rgba(118,188,211,.38)';context.lineWidth=.55;
        for(var vent=0;vent<3;vent++){var ventY=y+.028+vent*.022,va=project(worldPoint(model,-w*.2,ventY,frontZ+.075)),vb=project(worldPoint(model,w*.13,ventY,frontZ+.075));context.beginPath();context.moveTo(va.x,va.y);context.lineTo(vb.x,vb.y);context.stroke();}
        var screwWorld=[[-w*.31,y+.025],[w*.31,y+.025],[-w*.31,y+unitH-.025],[w*.31,y+unitH-.025]];
        screwWorld.forEach(function(position){var screw=project(worldPoint(model,position[0],position[1],frontZ+.08));context.fillStyle='rgba(213,244,252,.85)';context.beginPath();context.arc(screw.x,screw.y,Math.max(.7,screw.p*.9),0,Math.PI*2);context.fill();});
        var led1=project(worldPoint(model,w*.25,y+unitH*.48,frontZ+.085)),led2=project(worldPoint(model,w*.3,y+unitH*.48,frontZ+.085));
        context.save();context.shadowColor=color;context.shadowBlur=5;context.fillStyle=color;context.beginPath();context.arc(led1.x,led1.y,Math.max(1,led1.p*1.2),0,Math.PI*2);context.fill();context.fillStyle='rgba(213,244,252,.9)';context.beginPath();context.arc(led2.x,led2.y,Math.max(.7,led2.p*.85),0,Math.PI*2);context.fill();context.restore();
        var hit=projectedBounds(unit);hit.x-=3;hit.y-=3;hit.w+=6;hit.h+=6;hit.server=item.server;rackHitAreas.push(hit);
      });
        var handle=[project(worldPoint(model,w*.29,h*.42,frontZ+.035)),project(worldPoint(model,w*.39,h*.42,frontZ+.035)),project(worldPoint(model,w*.39,h*.61,frontZ+.035)),project(worldPoint(model,w*.29,h*.61,frontZ+.035))];
        paintPolygon(context,handle,'rgba(7,35,48,.94)','rgba(130,221,246,.7)',.7);
      [[-w*.4,.19],[w*.4,.19],[-w*.4,h-.2],[w*.4,h-.2]].forEach(function(position){var rivet=project(worldPoint(model,position[0],position[1],frontZ+.04));context.fillStyle='rgba(181,224,238,.78)';context.beginPath();context.arc(rivet.x,rivet.y,Math.max(.7,rivet.p*.9),0,Math.PI*2);context.fill();});
    } else if(backFacing){
      var backZ=-d/2-.014;
      var backDoor=[project(worldPoint(model,-w*.43,.16,backZ)),project(worldPoint(model,w*.43,.16,backZ)),project(worldPoint(model,w*.43,h-.17,backZ)),project(worldPoint(model,-w*.43,h-.17,backZ))];
      var backGradient=context.createLinearGradient(backDoor[0].x,backDoor[0].y,backDoor[2].x,backDoor[2].y);backGradient.addColorStop(0,'#153c4e');backGradient.addColorStop(.48,'#041824');backGradient.addColorStop(1,'#102f40');
      paintPolygon(context,backDoor,backGradient,'#5498b2',1);
      rack.arranged.forEach(function(item){
        var slotRatio=(item.slot-1)/(RACK_SLOT_CAPACITY-1),y=.22+(h-.52)*slotRatio,unitH=.072,state=statusOf(item.server),color=state.key==='normal'?'#24c996':state.key==='warning'?'#e9a52a':'#eb5967';
        var rearUnit=[project(worldPoint(model,-w*.36,y,backZ-.018)),project(worldPoint(model,w*.36,y,backZ-.018)),project(worldPoint(model,w*.36,y+unitH,backZ-.018)),project(worldPoint(model,-w*.36,y+unitH,backZ-.018))];
        var rearGradient=context.createLinearGradient(rearUnit[0].x,rearUnit[0].y,rearUnit[2].x,rearUnit[2].y);rearGradient.addColorStop(0,'#173a4a');rearGradient.addColorStop(.5,'#071e2a');rearGradient.addColorStop(1,'#102f3e');
        context.save();context.shadowColor=color;context.shadowBlur=4;paintPolygon(context,rearUnit,rearGradient,color,.85);context.restore();
        var powerPort=project(worldPoint(model,-w*.23,y+unitH*.5,backZ-.035)),networkPort=project(worldPoint(model,w*.08,y+unitH*.5,backZ-.035)),rearLed=project(worldPoint(model,w*.28,y+unitH*.5,backZ-.04));
        context.fillStyle='#0a1015';context.fillRect(powerPort.x-2.2,powerPort.y-1.4,4.4,2.8);context.strokeStyle='#6b9bad';context.lineWidth=.45;context.strokeRect(networkPort.x-2.2,networkPort.y-1.5,4.4,3);
        context.save();context.fillStyle=color;context.shadowColor=color;context.shadowBlur=4;context.beginPath();context.arc(rearLed.x,rearLed.y,1,0,Math.PI*2);context.fill();context.restore();
        var rearHit=projectedBounds(rearUnit);rearHit.server=item.server;rackHitAreas.push(rearHit);
      });
    }

    if(Math.abs(Math.sin(projector.yaw))>.16){
      var sideSign=Math.sin(projector.yaw)>0?1:-1,sideX=sideSign*(w/2+.014);
      var sidePanel=[project(worldPoint(model,sideX,.14,-d*.43)),project(worldPoint(model,sideX,.14,d*.43)),project(worldPoint(model,sideX,h-.14,d*.43)),project(worldPoint(model,sideX,h-.14,-d*.43))];
      var sidePanelGradient=context.createLinearGradient(sidePanel[0].x,sidePanel[0].y,sidePanel[2].x,sidePanel[2].y);sidePanelGradient.addColorStop(0,'#2a657d');sidePanelGradient.addColorStop(.2,'#17495f');sidePanelGradient.addColorStop(.56,'#092b3d');sidePanelGradient.addColorStop(1,'#1d5269');
      paintPolygon(context,sidePanel,sidePanelGradient,'#5da0b9',.9);
      context.save();context.strokeStyle='#2c657b';context.lineWidth=.65;
      for(var sideGroove=1;sideGroove<9;sideGroove++){var grooveY=.18+(h-.36)*(sideGroove/9),grooveA=project(worldPoint(model,sideX+sideSign*.004,grooveY,-d*.35)),grooveB=project(worldPoint(model,sideX+sideSign*.004,grooveY,d*.35));context.beginPath();context.moveTo(grooveA.x,grooveA.y);context.lineTo(grooveB.x,grooveB.y);context.stroke();}
      context.restore();
      rack.arranged.forEach(function(item){
        var slotRatio=(item.slot-1)/(RACK_SLOT_CAPACITY-1),y=.22+(h-.52)*slotRatio,unitH=.072,state=statusOf(item.server),color=state.key==='normal'?'#24c996':state.key==='warning'?'#e9a52a':'#eb5967';
        var sideUnit=[project(worldPoint(model,sideX+sideSign*.012,y,-d*.3)),project(worldPoint(model,sideX+sideSign*.012,y,d*.36)),project(worldPoint(model,sideX+sideSign*.012,y+unitH,d*.36)),project(worldPoint(model,sideX+sideSign*.012,y+unitH,-d*.3))];
        var sideUnitGradient=context.createLinearGradient(sideUnit[0].x,sideUnit[0].y,sideUnit[2].x,sideUnit[2].y);sideUnitGradient.addColorStop(0,'#173b4b');sideUnitGradient.addColorStop(.5,'#061b26');sideUnitGradient.addColorStop(1,'#123543');
        context.save();context.shadowColor=color;context.shadowBlur=4;paintPolygon(context,sideUnit,sideUnitGradient,color,.8);context.restore();
        var depthRailA=project(worldPoint(model,sideX+sideSign*.018,y+unitH*.35,-d*.2)),depthRailB=project(worldPoint(model,sideX+sideSign*.018,y+unitH*.35,d*.25));context.strokeStyle='rgba(132,192,212,.55)';context.lineWidth=.5;context.beginPath();context.moveTo(depthRailA.x,depthRailA.y);context.lineTo(depthRailB.x,depthRailB.y);context.stroke();
        var sideHit=projectedBounds(sideUnit);sideHit.server=item.server;rackHitAreas.push(sideHit);
      });
      [[.18,-d*.35],[h-.18,-d*.35],[.18,d*.35],[h-.18,d*.35]].forEach(function(position){var sideScrew=project(worldPoint(model,sideX+sideSign*.02,position[0],position[1]));context.fillStyle='#b6ddea';context.beginPath();context.arc(sideScrew.x,sideScrew.y,.8,0,Math.PI*2);context.fill();});
    }

    var edges=[[0,1],[1,2],[2,3],[3,0],[4,5],[5,6],[6,7],[7,4],[0,4],[1,5],[2,6],[3,7]];
    context.save();context.strokeStyle=selected?'#27aee0':'rgba(76,169,205,.82)';context.lineWidth=selected?1.8:1;context.shadowColor=selected?'rgba(68,191,232,.7)':'rgba(45,171,215,.32)';context.shadowBlur=selected?7:3.5;
    edges.forEach(function(edge){context.beginPath();context.moveTo(points[edge[0]].x,points[edge[0]].y);context.lineTo(points[edge[1]].x,points[edge[1]].y);context.stroke();});context.restore();

    var baseLabel=project(worldPoint(model,0,-.06,0)),cabinetBounds=projectedBounds(points),labelWidth=Math.max(44,Math.min(104,cabinetBounds.w*1.18)),compactLabel=labelWidth<62,labelHeight=compactLabel?28:31,positionCode=rowCode(model.row)+(model.index+1);
    context.save();context.fillStyle='rgba(255,255,255,.95)';roundedRect(context,baseLabel.x-labelWidth/2,baseLabel.y+8,labelWidth,labelHeight,Math.min(6,labelHeight/3));context.fill();context.strokeStyle=selected?'rgba(39,167,220,.68)':'rgba(57,151,200,.22)';context.lineWidth=selected?1.5:1;context.stroke();
    var maxRackChars=Math.max(3,Math.floor((labelWidth-(compactLabel?8:24))/6.2)),rackText=String(rack.name),shortRack=rackText.length>maxRackChars?rackText.slice(0,Math.max(2,maxRackChars-1))+'…':rackText;
    context.fillStyle='#124968';context.font='800 '+(compactLabel?9:10)+'px Consolas';context.textAlign='center';context.textBaseline='middle';context.fillText(compactLabel?positionCode:positionCode+' · '+shortRack,baseLabel.x,baseLabel.y+16);
    var hiddenCount=Math.max(0,rack.servers.length-rack.arranged.length),deviceText='容量 '+rack.arranged.length+'/'+RACK_SLOT_CAPACITY+(hiddenCount?' · 未展示 '+hiddenCount:'');
    context.fillStyle='#416f89';context.font='700 '+(compactLabel?6:7)+'px "Microsoft YaHei","Segoe UI"';context.fillText(compactLabel?shortRack:deviceText,baseLabel.x,baseLabel.y+(compactLabel?27:30));context.restore();
    var bounds=projectedBounds(points.concat([{x:baseLabel.x-labelWidth/2,y:baseLabel.y+8},{x:baseLabel.x+labelWidth/2,y:baseLabel.y+8+labelHeight}]));bounds.id=rack.id;bounds.name=rack.name;bounds.zoneKey=rack.roomKey;bounds.row=model.row;bounds.index=model.index;bounds.anchorX=baseLabel.x;bounds.anchorY=baseLabel.y;rackCabinetAreas.push(bounds);
  }
  function drawRackScene() {
    var canvas=byId('dcRackCanvas'),context=canvas.getContext('2d'),rect=canvas.getBoundingClientRect(),dpr=Math.min(2.25,Math.max(1.5,window.devicePixelRatio||1));
    if(canvas.width!==Math.round(rect.width*dpr)||canvas.height!==Math.round(rect.height*dpr)){canvas.width=Math.round(rect.width*dpr);canvas.height=Math.round(rect.height*dpr);}
    context.setTransform(dpr,0,0,dpr,0,0);context.clearRect(0,0,rect.width,rect.height);rackHitAreas=[];rackCabinetAreas=[];rackRowDropAreas=[];
    if(!rackScene.length||rect.width<20||rect.height<20)return;
    var sceneZones=[],maxColumns=1,maxRows=1,globalProfile=densityProfile(rackScene.length),gap=rackZones.length>1?1.15:0,totalWidth=0;
    rackZones.forEach(function(zone){
      var rows=zone.layout.rows.map(function(row){return row.map(function(name){return zone.racks.find(function(rack){return rack.name===name;});}).filter(Boolean);});
      var columns=Math.max.apply(Math,[1].concat(rows.map(function(row){return row.length;}))),rowCount=Math.max(1,rows.length),profile=densityProfile(zone.racks.length);
      var zoneWidth=Math.max(2.7,columns*1.08+1.25);
      sceneZones.push({key:zone.key,name:zone.name,racks:zone.racks,layout:zone.layout,rows:rows,columns:columns,rowCount:rowCount,width:zoneWidth,halfX:zoneWidth/2,rowZs:[],profile:profile});
      totalWidth+=zoneWidth;maxColumns=Math.max(maxColumns,columns);maxRows=Math.max(maxRows,rowCount);
    });
    totalWidth+=gap*Math.max(0,sceneZones.length-1);
    var cursor=-totalWidth/2,sceneHalfZ=.5;
    sceneZones.forEach(function(zone){zone.centerX=cursor+zone.width/2;cursor+=zone.width+gap;zone.rowSpacing=Math.min(1.7,5/Math.max(1,zone.rowCount-1));zone.floorHalfZ=Math.max(1.25,Math.min(4.1,(zone.rowCount-1)*zone.rowSpacing/2+.85));zone.platformHalfX=zone.halfX*1.16;zone.platformHalfZ=zone.floorHalfZ*1.14;zone.roomHeight=Math.max(2.35,1.78*zone.profile.rackScale+.34);var rackHalfZ=(zone.rowCount-1)*zone.rowSpacing/2+.36;sceneHalfZ=Math.max(sceneHalfZ,Math.min(zone.platformHalfZ,rackHalfZ+.72));});
    var maxRackScale=Math.max.apply(Math,sceneZones.map(function(zone){return zone.profile.rackScale;})),sceneHeight=1.86*maxRackScale,projector=buildProjector(rect,totalWidth/2+.72,sceneHalfZ,maxColumns,maxRows,globalProfile.maxScale,maxRackScale,sceneHeight),models=[];
    sceneZones.forEach(function(zone){
      zone.rows.forEach(function(racks,rowIndex){var rowZ=((zone.rowCount-1)/2-rowIndex)*zone.rowSpacing;zone.rowZs.push(rowZ);racks.forEach(function(rack,index){models.push({rack:rack,zone:zone,row:rowIndex,index:index,rackScale:zone.profile.rackScale,x:zone.centerX+(index-(racks.length-1)/2)*zone.profile.spacingX,z:rowZ});});});
      var zoneCorners=[projector.project({x:zone.centerX-zone.platformHalfX,y:0,z:-zone.platformHalfZ}),projector.project({x:zone.centerX+zone.platformHalfX,y:0,z:-zone.platformHalfZ}),projector.project({x:zone.centerX+zone.platformHalfX,y:0,z:zone.platformHalfZ}),projector.project({x:zone.centerX-zone.platformHalfX,y:0,z:zone.platformHalfZ})];
      var zoneBounds=projectedBounds(zoneCorners);zone.left=Math.max(8,zoneBounds.x);zone.right=Math.min(rect.width-8,zoneBounds.x+zoneBounds.w);
      zone.rowZs.forEach(function(rowZ,rowIndex){var anchor=projector.project({x:zone.centerX,y:0,z:rowZ});rackRowDropAreas.push({zoneKey:zone.key,roomName:zone.name,row:rowIndex,x:anchor.x,y:anchor.y,left:zone.left,right:zone.right});});
    });
    drawOpenRackFloor(context,projector,sceneZones);
    models.forEach(function(model){model.depth=projector.project({x:model.x,y:1.4,z:model.z}).z;});models.sort(function(a,b){return a.depth-b.depth;});
    models.forEach(function(model){if(!rackDrag||model.rack.id!==rackDrag.id)drawRack3D(context,model,projector);});
    if(editView){
      sceneZones.forEach(function(zone){var visualRows=rackRowDropAreas.filter(function(area){return area.zoneKey===zone.key;}).sort(function(a,b){return a.y-b.y;});
        visualRows.forEach(function(area,lane){var previous=lane?visualRows[lane-1].y:area.y-(visualRows[1]?visualRows[1].y-area.y:72),next=visualRows[lane+1]?visualRows[lane+1].y:area.y+(lane?visualRows[lane].y-visualRows[lane-1].y:72),laneTop=Math.max(38,(previous+area.y)/2),laneBottom=Math.min(rect.height-12,(area.y+next)/2),active=rackDrag&&rackDrag.zoneKey===area.zoneKey&&rackDrag.targetRow===area.row;context.save();context.setLineDash([6,5]);context.strokeStyle=active?'rgba(25,140,191,.82)':'rgba(55,145,190,.25)';context.lineWidth=active?1.8:1;context.fillStyle=active?'rgba(83,192,232,.13)':'rgba(255,255,255,.025)';context.fillRect(area.left,laneTop,Math.max(36,area.right-area.left),Math.max(28,laneBottom-laneTop));context.strokeRect(area.left,laneTop,Math.max(36,area.right-area.left),Math.max(28,laneBottom-laneTop));context.setLineDash([]);context.fillStyle=active?'#126f99':'#4f839e';context.font='800 8px "Microsoft YaHei"';context.textAlign='left';context.textBaseline='top';context.fillText(area.roomName+' · '+rowCode(area.row)+'排',area.left+7,laneTop+7);context.restore();});
      });
    }
    if(rackDrag){var targetArea=rackRowDropAreas.find(function(area){return area.zoneKey===rackDrag.zoneKey&&area.row===rackDrag.targetRow;});context.save();context.strokeStyle='#168fc5';context.fillStyle='rgba(38,166,216,.2)';context.lineWidth=2;context.setLineDash([4,3]);context.beginPath();context.moveTo(rackDrag.insertionX,(targetArea?targetArea.y:rackDrag.y)-112);context.lineTo(rackDrag.insertionX,(targetArea?targetArea.y:rackDrag.y)+18);context.stroke();context.setLineDash([]);context.beginPath();context.moveTo(rackDrag.insertionX-6,(targetArea?targetArea.y:rackDrag.y)-108);context.lineTo(rackDrag.insertionX+6,(targetArea?targetArea.y:rackDrag.y)-108);context.lineTo(rackDrag.insertionX,(targetArea?targetArea.y:rackDrag.y)-99);context.closePath();context.fill();context.globalAlpha=.94;context.shadowColor='rgba(34,139,190,.3)';context.shadowBlur=16;context.fillStyle='rgba(255,255,255,.97)';roundedRect(context,rackDrag.x-55,rackDrag.y-20,110,40,8);context.fill();context.strokeStyle='#2d9ed2';context.lineWidth=2;context.stroke();context.fillStyle='#174e6c';context.font='700 11px Consolas';context.textAlign='center';context.textBaseline='middle';context.fillText(rackDrag.name,rackDrag.x,rackDrag.y-4);context.fillStyle='#628ba1';context.font='600 8px "Segoe UI"';context.fillText((targetArea?targetArea.roomName+' · ':'')+'位置 '+rowCode(rackDrag.targetRow)+(rackDrag.targetIndex+1),rackDrag.x,rackDrag.y+10);context.restore();}
  }
  function drawScene() {
    if (disposed) return;
    var canvas = byId('dcSceneCanvas'), context = canvas.getContext('2d'), rect = canvas.getBoundingClientRect(), dpr = Math.min(2,Math.max(1.35,window.devicePixelRatio || 1));
    if (canvas.width !== Math.round(rect.width * dpr) || canvas.height !== Math.round(rect.height * dpr)) {
      canvas.width = Math.round(rect.width * dpr); canvas.height = Math.round(rect.height * dpr); context.setTransform(dpr,0,0,dpr,0,0);
    }
    context.clearRect(0,0,rect.width,rect.height);
    var now = Date.now() / 1000, delta = sceneLastTime ? Math.min(.05, now - sceneLastTime) : 0, count = Math.max(34, Math.floor(rect.width / 32));
    sceneLastTime = now;
    for (var i=0;i<count;i++) {
      var x = (i * 83.7 + now * (7 + i % 4)) % rect.width, y = (i * 47.3 + Math.sin(now + i) * 18 + rect.height) % rect.height;
      context.fillStyle = 'rgba(65,211,255,' + (.1 + (i % 5) * .035) + ')'; context.beginPath(); context.arc(x,y,.6 + (i%3)*.45,0,Math.PI*2); context.fill();
      if (i % 4 === 0) { context.strokeStyle='rgba(43,154,221,.055)'; context.beginPath(); context.moveTo(x,y); context.lineTo((x+110)%rect.width,(y+52)%rect.height); context.stroke(); }
    }
    if (autoView && !dragging && !rackDrag) { sceneRotY = (sceneRotY + delta * 2 + 360) % 360; applySceneView(); }
    drawRackScene();
    sceneFrame = requestAnimationFrame(drawScene);
  }

  byId('dcDetailClose').addEventListener('click', function() { byId('dcServerPopover').hidden = true; });
  byId('dcRefreshBtn').addEventListener('click', fetchStatus);
  byId('dcFullscreenBtn').addEventListener('click', toggleFullscreen);
  document.addEventListener('fullscreenchange', syncFullscreen);
  document.addEventListener('keydown', function(event) { if (event.key === 'Escape') byId('dcServerPopover').hidden = true; });
  document.addEventListener('lingtu:before-unmount', function cleanup() {
    disposed = true; clearInterval(clockTimer); clearInterval(statusTimer); if (sceneFrame) cancelAnimationFrame(sceneFrame); document.removeEventListener('fullscreenchange', syncFullscreen);
  }, {once:true});
  setupSceneControls(); applySceneView(); drawScene();
  var healthRefreshMs=Math.max(60000,Number(byId('dataCenterWall').dataset.healthInterval||300)*1000);
  updateClock(); clockTimer = setInterval(updateClock, 1000); fetchStatus(); statusTimer = setInterval(fetchStatus, healthRefreshMs);
}());
