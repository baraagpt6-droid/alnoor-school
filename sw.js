/* مدرسة النور 1.2.1 — precache + cache-first. Vendor runtime libraries are served locally. */
const CACHE_VERSION = "alnoor-school-v1.2.1";
const APP_SHELL = [
  "./", "./index.html", "./styles.fixed.css", "./manifest.json",
  "./logo.png", "./logo-192.png", "./logo-512.png", "./apple-touch-icon.png",
  "./curriculum.json", "./vendor/react.production.min.js", "./vendor/react-dom.production.min.js",
  "./vendor/babel.min.js", "./vendor/three.min.js", "./vendor/qrcode.min.js"
];
const RUNTIME_CACHE = `${CACHE_VERSION}-runtime`;
self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_VERSION);
    await cache.addAll(APP_SHELL.map((path) => new Request(new URL(path, self.registration.scope), { cache: "reload" })));
    await self.skipWaiting();
  })());
});
self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((key) => key.startsWith("alnoor-school-") && key !== CACHE_VERSION && key !== RUNTIME_CACHE).map((key) => caches.delete(key)));
    await self.clients.claim();
  })());
});
self.addEventListener("message", (event) => { if (event.data?.type === "SKIP_WAITING") self.skipWaiting(); });
self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  event.respondWith((async () => {
    const cache = await caches.open(CACHE_VERSION);
    const cached = await cache.match(request, { ignoreSearch: true });
    if (cached) return cached;
    try {
      const response = await fetch(request);
      if (response && response.ok) await cache.put(request, response.clone());
      return response;
    } catch (error) {
      if (request.mode === "navigate") return (await cache.match(new URL("./index.html", self.registration.scope))) || Response.error();
      return Response.error();
    }
  })());
});
