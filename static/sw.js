const C="fin-v8";
self.addEventListener("install",e=>e.waitUntil(caches.open(C).then(c=>c.addAll(["/","/manifest.json"]))));
self.addEventListener("fetch",e=>{if(e.request.url.includes("/api/"))return;
e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)))});
