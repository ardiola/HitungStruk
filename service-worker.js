const CACHE_NAME = "struk-tagihan-v1";
const STATIC_ASSETS = ["/", "/index.html", "/manifest.webmanifest"];

self.addEventListener("install", (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS)),
    );
    self.skipWaiting();
});

self.addEventListener("activate", (event) => {
    event.waitUntil(
        caches
            .keys()
            .then((keys) =>
                Promise.all(
                    keys
                        .filter((key) => key !== CACHE_NAME)
                        .map((key) => caches.delete(key)),
                ),
            )
            .then(() => self.clients.claim()),
    );
});

self.addEventListener("fetch", (event) => {
    const request = event.request;
    const url = new URL(request.url);

    if (request.method !== "GET") {
        return;
    }
    if (url.origin !== self.location.origin) {
        return;
    }
    if (url.pathname.startsWith("/api/")) {
        return;
    }

    event.respondWith(
        caches.match(request).then((cachedResponse) => {
            if (cachedResponse) {
                return cachedResponse;
            }
            return fetch(request).then((networkResponse) => {
                if (networkResponse && networkResponse.status === 200) {
                    const clonedResponse = networkResponse.clone();
                    caches.open(CACHE_NAME).then((cache) => {
                        cache.put(request, clonedResponse);
                    });
                }
                return networkResponse;
            });
        }),
    );
});
