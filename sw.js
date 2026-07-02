/* Sky Matrix service worker — makes the app launch & run offline.
   Upload this file to the GitHub repo ROOT, next to index.html.
   Navigation is network-first (so a freshly uploaded index.html loads when online,
   and the cached copy loads when offline). Libraries/assets are cache-first. */
const CACHE = 'skymatrix-v5';
const ASSETS = [
  './',
  './app.html',
  'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/tesseract.js/2.1.5/tesseract.min.js'
];

self.addEventListener('install', function (e) {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(function (c) {
    return Promise.all(ASSETS.map(function (u) { return c.add(u).catch(function () {}); }));
  }));
});

self.addEventListener('activate', function (e) {
  e.waitUntil(caches.keys().then(function (ks) {
    return Promise.all(ks.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); }));
  }).then(function () { return self.clients.claim(); }));
});

self.addEventListener('fetch', function (e) {
  var req = e.request;
  if (req.method !== 'GET') return;
  // pw.json is the live admin-password source of truth — ALWAYS network-first,
  // never served stale from cache (a stale hash here = the right password being rejected).
  if (req.url.indexOf('pw.json') !== -1) {
    e.respondWith(fetch(req).catch(function () { return caches.match(req); }));
    return;
  }
  var isNav = req.mode === 'navigate' || req.destination === 'document';
  if (isNav) {
    // network-first so the newest app loads online; cached index offline
    e.respondWith(
      fetch(req).then(function (res) {
        var cp = res.clone();
        caches.open(CACHE).then(function (c) { c.put('./app.html', cp).catch(function () {}); });
        return res;
      }).catch(function () {
        return caches.match(req).then(function (c) { return c || caches.match('./app.html'); });
      })
    );
    return;
  }
  // cache-first for libraries / assets, with a background network refresh
  e.respondWith(
    caches.match(req).then(function (cached) {
      var net = fetch(req).then(function (res) {
        if (res && res.status === 200 && req.url.indexOf('http') === 0) {
          var cp = res.clone();
          caches.open(CACHE).then(function (c) { c.put(req, cp).catch(function () {}); });
        }
        return res;
      }).catch(function () { return cached; });
      return cached || net;
    })
  );
});
