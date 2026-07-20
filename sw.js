/* Sky Matrix service worker — makes the app launch & run offline.
   Upload this file to the GitHub repo ROOT, next to index.html.
   Navigation is network-first (so a freshly uploaded index.html loads when online,
   and the cached copy loads when offline). Libraries/assets are cache-first. */
const CACHE = 'skymatrix-v12';
const SHARE_CACHE = 'sm-share';
const ASSETS = [
  './',
  './app.html',
  './manifest.webmanifest',
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
    return Promise.all(ks.filter(function (k) { return k !== CACHE && k !== SHARE_CACHE; }).map(function (k) { return caches.delete(k); }));
  }).then(function () { return self.clients.claim(); }));
});

self.addEventListener('fetch', function (e) {
  var req = e.request;
  // Web Share Target: an OFP shared into Sky Matrix arrives as a POST to /share-target.
  // There is no server, so we capture the file here, stash it, and redirect the app to pick it up.
  if (req.method === 'POST' && req.url.indexOf('/share-target') !== -1) {
    e.respondWith((function () {
      return req.formData().then(function (form) {
        var f = form.get('ofp');
        if (!f) return Response.redirect('app.html', 303);
        return caches.open(SHARE_CACHE).then(function (c) {
          var headers = { 'Content-Type': f.type || 'application/octet-stream', 'X-Filename': (f.name || 'shared-ofp.pdf') };
          return c.put('shared-ofp', new Response(f, { headers: headers }));
        }).then(function () { return Response.redirect('app.html?shared=1', 303); });
      }).catch(function () { return Response.redirect('app.html', 303); });
    })());
    return;
  }
  if (req.method !== 'GET') return;
  // pw.json is the live admin-password source of truth — ALWAYS network-first,
  // never served stale from cache (a stale hash here = the right password being rejected).
  if (req.url.indexOf('pw.json') !== -1) {
    e.respondWith(fetch(req).catch(function () { return caches.match(req); }));
    return;
  }
  var isNav = req.mode === 'navigate' || req.destination === 'document';
  if (isNav) {
    // network-first with {cache:'reload'} — bypass Safari's HTTP cache so the SAME bookmark always loads the
    // freshest uploaded app.html when online (no need to re-bookmark); the cached copy is served offline.
    e.respondWith(
      fetch(req.url, { cache: 'reload', credentials: 'same-origin' }).then(function (res) {
        // Only overwrite the cached app with a GOOD response for the APP ITSELF — never cache a 404/500 error page,
        // and never let another same-scope page (admin.html / subadmin.html) overwrite app.html in the cache.
        var isApp = false;
        try { var p = new URL(req.url, self.location.href).pathname; isApp = /(^|\/)(app\.html)$/.test(p) || /\/$/.test(p); } catch (err) { isApp = false; }
        if (isApp && res && res.ok && res.status === 200) { var cp = res.clone(); caches.open(CACHE).then(function (c) { c.put('./app.html', cp).catch(function () {}); }); }
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
