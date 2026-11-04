// Decrypts a private design packet inside the viewer's browser.
// The gate page hands over the key after the right PIN; requests under ./app/ are then
// fetched as scrambled files from ./x/ and unscrambled here. Nothing readable is ever on the server.
const SCOPE = new URL(self.registration.scope).pathname;          // e.g. /tbc-packets/p/abc123/
const APP = SCOPE + 'app/';
let state = null;                                                    // { key: CryptoKey, files: {...} }
const plain = new Map();                                             // small in-memory cache of decrypted files

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

function db() {
  return new Promise((res, rej) => { const r = indexedDB.open('tbc-packet', 1); r.onupgradeneeded = () => r.result.createObjectStore('keys'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
}
async function idb(mode, fn) { const d = await db(); return new Promise((res, rej) => { const tx = d.transaction('keys', mode); const q = fn(tx.objectStore('keys')); tx.oncomplete = () => res(q && q.result); tx.onerror = () => rej(tx.error); }); }
// stored as plain key bytes (works in every browser); older saves may hold a key object
async function toState(rec) {
  if (!rec) return null;
  const key = rec.keyBytes ? await crypto.subtle.importKey('raw', rec.keyBytes, 'AES-GCM', false, ['decrypt']) : rec.key;
  return key ? { key, files: rec.files } : null;
}
async function load() {
  if (!state) { try { state = await toState(await idb('readonly', s => s.get(SCOPE))); } catch (e) { state = null; } }
  return state;
}

self.addEventListener('message', e => {
  const m = e.data || {};
  // reply on the private channel the page opened (falls back to the page itself)
  const reply = msg => { if (e.ports && e.ports[0]) e.ports[0].postMessage(msg); else if (e.source) e.source.postMessage(msg); };
  if (m.type === 'unlock') {
    e.waitUntil((async () => {
      try {
        state = await toState({ keyBytes: m.keyBytes, key: m.key, files: m.files });
        plain.clear();
        let saved = true;
        try { await idb('readwrite', s => s.put({ keyBytes: m.keyBytes, files: m.files }, SCOPE)); } catch (err) { saved = false; }
        reply({ type: 'unlocked', ok: !!state, saved });   // works this visit even if the browser won't let us remember it
      } catch (err) { reply({ type: 'unlocked', ok: false, error: String(err && err.name || err) }); }
    })());
  } else if (m.type === 'status') {
    e.waitUntil(load().then(s => reply({ type: 'status', unlocked: !!s }), () => reply({ type: 'status', unlocked: false })));
  } else if (m.type === 'lock') {
    state = null; plain.clear();
    e.waitUntil(idb('readwrite', s => s.delete(SCOPE)).catch(() => {}).then(() => reply({ type: 'locked' })));
  }
});

async function decrypt(rel) {
  if (plain.has(rel)) return plain.get(rel);
  const s = await load(); if (!s) return null;
  const f = s.files[rel]; if (!f) return undefined;
  const r = await fetch(SCOPE + 'x/' + f.n + '.bin', { cache: 'no-cache' });
  if (!r.ok) throw new Error('missing ' + rel);
  const buf = new Uint8Array(await r.arrayBuffer());
  const out = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, s.key, buf.slice(12));
  const entry = { body: out, type: f.t };
  if (out.byteLength < 40 * 1024 * 1024) plain.set(rel, entry);
  return entry;
}

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.origin !== location.origin || !url.pathname.startsWith(APP)) return;
  e.respondWith((async () => {
    let rel = decodeURIComponent(url.pathname.slice(APP.length)) || 'index.html';
    if (rel.endsWith('/')) rel += 'index.html';
    let f;
    try { f = await decrypt(rel); } catch (err) { return new Response('Could not load this file.', { status: 502 }); }
    if (f === null) return Response.redirect(SCOPE, 302);              // locked: back to the PIN screen
    if (f === undefined) return new Response('Not found', { status: 404 });
    const headers = { 'Content-Type': f.type, 'Cache-Control': 'no-store', 'Accept-Ranges': 'bytes', 'X-Robots-Tag': 'noindex' };
    const range = e.request.headers.get('Range');                     // videos ask for byte ranges (Safari needs this)
    const total = f.body.byteLength;
    if (range) {
      const m = /bytes=(\d*)-(\d*)/.exec(range);
      let start = m && m[1] ? +m[1] : 0, end = m && m[2] ? +m[2] : total - 1;
      if (m && !m[1] && m[2]) { start = Math.max(0, total - +m[2]); end = total - 1; }
      end = Math.min(end, total - 1);
      return new Response(f.body.slice(start, end + 1), { status: 206, headers: { ...headers, 'Content-Range': `bytes ${start}-${end}/${total}`, 'Content-Length': String(end - start + 1) } });
    }
    return new Response(f.body, { status: 200, headers: { ...headers, 'Content-Length': String(total) } });
  })());
});
