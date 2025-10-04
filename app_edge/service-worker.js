const CACHE = "tribe-v1";
const ASSETS = ["/", "/icons/icon-192.png", "/icons/icon-512.png", "/offline.html"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
  ));
  self.clients.claim();
});

self.addEventListener("fetch", e => {
  const { request } = e;
  if (request.mode === "navigate") {
    e.respondWith(fetch(request).catch(() => caches.match("/offline.html")));
  } else {
    e.respondWith(
      caches.match(request).then(hit => hit || fetch(request).then(resp => {
        const copy = resp.clone();
        caches.open(CACHE).then(c => c.put(request, copy));
        return resp;
      }).catch(() => caches.match(request)))
    );
  }
});
