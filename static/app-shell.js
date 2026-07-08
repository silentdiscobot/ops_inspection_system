(function () {
  'use strict';
  var cache = new Map();
  var CACHE_MS = 120000;
  var navigating = false;
  var mounted = false;

  function eligible(link) {
    if (!link || link.target || link.hasAttribute('download')) return false;
    var url = new URL(link.href, location.href);
    return url.origin === location.origin && !url.search && !url.hash && url.pathname !== '/profile';
  }
  function fetchPage(path) {
    var saved = cache.get(path);
    if (saved && Date.now() - saved.time < CACHE_MS) return Promise.resolve(saved.html);
    return fetch(path, {credentials:'same-origin', headers:{'X-Lingtu-Shell':'1'}}).then(function(response) {
      if (!response.ok || new URL(response.url).pathname !== path) throw new Error('full navigation required');
      return response.text();
    }).then(function(html) { cache.set(path, {time:Date.now(), html:html}); return html; });
  }
  function copyScript(source) {
    return new Promise(function(resolve, reject) {
      var script = document.createElement('script');
      Array.prototype.forEach.call(source.attributes || [], function(attr) {
        if (attr.name !== 'src') script.setAttribute(attr.name, attr.value);
      });
      if (source.src) {
        script.src = source.src; script.onload = resolve;
        script.onerror = function() { console.warn('页面脚本加载失败，已保留当前页面', source.src); resolve(); };
      } else { script.text = source.textContent; }
      document.getElementById('pageScripts').appendChild(script);
      if (!source.src) resolve();
    });
  }
  function updateCsrf(parsed) {
    var incoming = parsed.querySelector('meta[name="csrf-token"]');
    var current = document.querySelector('meta[name="csrf-token"]');
    if (incoming && current) current.content = incoming.content;
  }
  function updateStylesheet(parsed) {
    var incoming = parsed.querySelector('link[href*="/static/styles.css"]');
    var current = document.querySelector('link[href*="/static/styles.css"]');
    if (incoming && current && incoming.href !== current.href) current.href = incoming.href;
  }
  function mount(path, html, push) {
    var parsed = new DOMParser().parseFromString(html, 'text/html');
    var incomingMain = parsed.querySelector('main');
    if (!incomingMain) { location.href = path; return Promise.resolve(); }
    var scripts = Array.prototype.slice.call(incomingMain.querySelectorAll('script'));
    var extra = parsed.getElementById('pageScripts');
    if (extra) scripts = scripts.concat(Array.prototype.slice.call(extra.querySelectorAll('script')));
    scripts.forEach(function(script) { script.remove(); });
    document.dispatchEvent(new CustomEvent('lingtu:before-unmount'));
    mounted = true;
    document.querySelector('main').innerHTML = incomingMain.innerHTML;
    document.getElementById('pageScripts').innerHTML = '';
    document.body.className = parsed.body.className;
    document.title = parsed.title;
    updateCsrf(parsed);
    updateStylesheet(parsed);
    if (push) history.pushState({lingtuShell:true}, '', path);
    window.scrollTo(0, 0);
    return scripts.reduce(function(chain, script) {
      return chain.then(function() { return copyScript(script); });
    }, Promise.resolve()).then(function() {
      document.dispatchEvent(new CustomEvent('lingtu:page-load'));
    });
  }
  function navigate(path, push) {
    if (navigating || (push && path === location.pathname)) return;
    navigating = true;
    mounted = false;
    fetchPage(path).then(function(html) { return mount(path, html, push); })
      .catch(function(error) {
        console.warn('局部页面切换失败', error);
        if (!mounted) location.href = path;
      })
      .finally(function() { navigating = false; });
  }
  document.addEventListener('click', function(event) {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    var link = event.target.closest && event.target.closest('.sidebar a[href]');
    if (!eligible(link)) return;
    var path = new URL(link.href, location.href).pathname;
    if (path === location.pathname) return;
    event.preventDefault(); navigate(path, true);
  });
  document.addEventListener('pointerover', function(event) {
    var link = event.target.closest && event.target.closest('.sidebar a[href]');
    if (eligible(link)) fetchPage(new URL(link.href, location.href).pathname).catch(function() {});
  });
  function prefetchMenus() {
    document.querySelectorAll('.sidebar a[href]').forEach(function(link) {
      if (eligible(link)) fetchPage(new URL(link.href, location.href).pathname).catch(function() {});
    });
  }
  if ('requestIdleCallback' in window) requestIdleCallback(prefetchMenus, {timeout: 1500});
  else setTimeout(prefetchMenus, 300);
  window.addEventListener('popstate', function() { navigate(location.pathname, false); });
}());
