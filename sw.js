/* Authenticator Service Worker — offline-first App-Shell, keine Netzwerkquellen. */
'use strict';

const VERSION      = 'auth-sw-v1';
const SHELL_CACHE  = `shell-${VERSION}`;
const ASSET_CACHE  = `assets-${VERSION}`;

// Alles, was zum Starten der App gebraucht wird (same-origin, passend zur CSP).
const SHELL = [
  './',
  './index.html',
  './authcore.js',
  './authstorage.js',
  './authformats.js',
  './qrcodegen.js',
  './importui.js',
  './about.js',
  './manifest.webmanifest',
  './icons/icon.svg',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/icon-maskable-512.png'
];

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(SHELL_CACHE);
    // Einzeln hinzufügen, damit ein 404 nicht den ganzen Install killt.
    await Promise.all(SHELL.map(async url => {
      try {
        const res = await fetch(new Request(url, { cache: 'reload', credentials: 'same-origin' }));
        if (res.ok) await cache.put(url, res);
      } catch { /* Datei existiert evtl. (noch) nicht – ignorieren */ }
    }));
  })());
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    // Alte Caches aufräumen
    const keys = await caches.keys();
    await Promise.all(
      keys
        .filter(k => k !== SHELL_CACHE && k !== ASSET_CACHE)
        .map(k => caches.delete(k))
    );
    await self.clients.claim();
  })());
});

self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', event => {
  const req = event.request;

  // Nur GET und same-origin. CSP verbietet ohnehin cross-origin.
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Navigationsanfragen: Netzwerk-first, Cache als Fallback → App startet offline.
  if (req.mode === 'navigate') {
    event.respondWith((async () => {
      try {
        const fresh = await fetch(req);
        const cache = await caches.open(SHELL_CACHE);
        cache.put('./index.html', fresh.clone()).catch(() => {});
        return fresh;
      } catch {
        const cache = await caches.open(SHELL_CACHE);
        return (await cache.match('./index.html')) ||
               (await cache.match('./')) ||
               new Response('Offline', { status: 503, headers: { 'Content-Type': 'text/plain' } });
      }
    })());
    return;
  }

  // Übrige Assets: Cache-first, im Hintergrund aktualisieren.
  event.respondWith((async () => {
    const cache = await caches.open(ASSET_CACHE);
    const cached = await cache.match(req);
    if (cached) {
      // Revalidate leise
      fetch(req).then(res => { if (res.ok) cache.put(req, res); }).catch(() => {});
      return cached;
    }
    try {
      const res = await fetch(req);
      if (res.ok) cache.put(req, res.clone()).catch(() => {});
      return res;
    } catch {
      return new Response('', { status: 504, statusText: 'Offline' });
    }
  })());
});