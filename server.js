/**
 * GHEE KHTAM FIGHT — local server: static delivery + room signalling.
 *
 * Usage:
 *   node server.js [port] [--root dir] [--host 0.0.0.0]
 *
 * Delivery engineering (measured, reversible):
 *   - Brotli/gzip for text assets (bundles 1.1 MB → ~300 KB on the wire)
 *   - immutable year-long caching for content-hashed files, revalidate for HTML
 *   - ETag / 304 revalidation
 *   - /healthz with build identity
 *
 * Room signalling API:
 *   GET    /api/ice
 *   POST   /api/room                                 {offer}         → {code, secret}
 *   GET    /api/room?code=CODE                                       → {offer, ice}
 *   POST   /api/room?code=CODE&action=answer         {answer}        → {ok}
 *   GET    /api/room?code=CODE&secret=S&wait=25                       → {answer|null}
 *   DELETE /api/room?code=CODE&secret=S                              → {ok}
 *   POST   /api/room?action=signal&sid=…&kind=…&n=…  {desc}          → {ok}
 *   GET    /api/room?action=signal&sid=…&kind=…&n=…&wait=R            → {desc|null}
 *
 * ICE config (for internet play behind strict NATs):
 *   ICE_SERVERS='[{"urls":"stun:…"},{"urls":"turn:…","username":"u","credential":"p"}]'
 *   or TURN_URL=turn:host:3478 TURN_USERNAME=u TURN_CREDENTIAL=p
 */
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { readFileSync, existsSync } from 'node:fs';
import { join, extname, resolve, basename } from 'node:path';
import { randomBytes, randomInt, createHash } from 'node:crypto';
import { gzipSync, brotliCompressSync, constants as zc } from 'node:zlib';

const args = process.argv.slice(2);
const PORT = Number(process.argv.slice(2).find((a) => /^\d+$/.test(a)) || process.env.PORT || 8090);
const rootIdx = args.indexOf('--root');
const ROOT = resolve(rootIdx >= 0 ? args[rootIdx + 1] : 'enhanced');
const hostIdx = args.indexOf('--host');
const HOST = hostIdx >= 0 ? process.argv[hostIdx + 1] : (process.env.HOST || (process.env.PORT ? '0.0.0.0' : '127.0.0.1'));

const ROOM_TTL_MS = 15 * 60 * 1000;
const SIGNAL_TTL_MS = 10 * 60 * 1000;
const MAX_ANSWER_WAIT_S = 30;
const MAX_BODY_BYTES = 256 * 1024;

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.mp3': 'audio/mpeg', '.ogg': 'audio/ogg',
  '.glb': 'model/gltf-binary', '.gltf': 'model/gltf+json', '.bin': 'application/octet-stream',
  '.wasm': 'application/wasm', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.hdr': 'application/octet-stream',
};
const TEXT_TYPES = /^(text\/|application\/(json|manifest\+json|wasm)|image\/svg)/;

/* ---------------------------------------------------------------- build info */

function buildInfo() {
  try {
    const v = JSON.parse(readFileSync(join(ROOT, 'version.json'), 'utf8'));
    return { root: basename(ROOT), version: v.version, files: v.files, bytes: v.bytes, generatedAt: v.generatedAt };
  } catch {
    return { root: basename(ROOT), version: '1.0.0' };
  }
}
const BUILD = buildInfo();

/* ---------------------------------------------------------------- ice config */

function icePayload() {
  let servers = [];
  try {
    if (process.env.ICE_SERVERS) servers = JSON.parse(process.env.ICE_SERVERS);
  } catch { /* ignore malformed env */ }
  if (!servers.length) {
    servers = [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' },
    ];
  }
  if (process.env.TURN_URL) {
    servers.push({
      urls: process.env.TURN_URL,
      username: process.env.TURN_USERNAME || '',
      credential: process.env.TURN_CREDENTIAL || '',
    });
  }
  return { iceServers: servers, relay: servers.some((s) => String(s.urls || '').startsWith('turn')) };
}

/* ---------------------------------------------------------------- state */

const rooms = new Map();
const signals = new Map();
const buckets = new Map();
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const compressionCache = new Map();

function newCode() {
  for (let attempt = 0; attempt < 50; attempt++) {
    let code = '';
    for (let i = 0; i < 4; i++) code += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
    if (!rooms.has(code)) return code;
  }
  return randomBytes(4).toString('hex').slice(0, 4).toUpperCase();
}
const newSecret = () => randomBytes(16).toString('hex');
const now = () => Date.now();

/* ---------------------------------------------------------------- helpers */

function sendJson(res, status, payload) {
  const body = Buffer.from(JSON.stringify(payload));
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': body.length, 'cache-control': 'no-store' });
  res.end(body);
}

function readJson(req) {
  return new Promise((resolvePromise, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) { reject(Object.assign(new Error('body_too_large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) { resolvePromise({}); return; }
      try { resolvePromise(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(Object.assign(new Error('bad_json'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}

function validDescription(d) {
  return d && typeof d === 'object' && typeof d.type === 'string' && typeof d.sdp === 'string' && d.sdp.length > 0 && d.sdp.length <= 200_000;
}

function rateLimited(ip) {
  const b = buckets.get(ip);
  const t = now();
  if (!b || t > b.reset) { buckets.set(ip, { count: 1, reset: t + 60_000 }); return false; }
  b.count++;
  return b.count > 300;
}

function finishWaiters(list, payload) {
  for (const w of list) {
    if (w.done) continue;
    w.done = true;
    clearTimeout(w.timer);
    try { sendJson(w.res, 200, payload); } catch { /* client gone */ }
  }
  list.length = 0;
}

/* ---------------------------------------------------------------- api */

async function handleApi(req, res, url) {
  const ip = req.socket.remoteAddress || 'unknown';
  if (rateLimited(ip)) { sendJson(res, 429, { error: 'rate_limited' }); return; }
  const p = url.pathname;
  const q = url.searchParams;

  if (p === '/api/flags' && req.method === 'GET') { sendJson(res, 200, { support: true, budget: true }); return; }
  if (p === '/api/ice' && req.method === 'GET') { sendJson(res, 200, icePayload()); return; }

  if (q.get('action') === 'signal') {
    const sid = q.get('sid') || '';
    const kind = q.get('kind') || '';
    const n = Number(q.get('n') || 0);
    if (!/^[A-Za-z0-9_-]{8,96}$/.test(sid)) { sendJson(res, 400, { error: 'bad_sid' }); return; }
    if (!/^(offer|answer)$/.test(kind)) { sendJson(res, 400, { error: 'bad_kind' }); return; }
    if (!Number.isInteger(n) || n < 0 || n > 9999) { sendJson(res, 400, { error: 'bad_n' }); return; }
    const key = `${sid}|${kind}|${n}`;

    if (req.method === 'POST') {
      const body = await readJson(req);
      if (!validDescription(body.desc)) { sendJson(res, 400, { error: 'bad_desc' }); return; }
      const slot = signals.get(key) || { desc: null, at: now(), waiters: [] };
      slot.desc = body.desc; slot.at = now();
      signals.set(key, slot);
      if (slot.waiters.length) finishWaiters(slot.waiters, { desc: slot.desc });
      sendJson(res, 200, { ok: true });
      return;
    }
    if (req.method === 'GET') {
      const wait = Math.min(30, Math.max(0, Number(q.get('wait') || 0)));
      const slot = signals.get(key);
      if (slot?.desc) { sendJson(res, 200, { desc: slot.desc }); return; }
      const list = slot ? slot.waiters : (signals.set(key, { desc: null, at: now(), waiters: [] }), signals.get(key).waiters);
      const waiter = { res, timer: null, done: false };
      list.push(waiter);
      waiter.timer = setTimeout(() => { if (waiter.done) return; waiter.done = true; sendJson(res, 200, { desc: null }); }, wait * 1000);
      req.on('close', () => { waiter.done = true; clearTimeout(waiter.timer); });
      return;
    }
    sendJson(res, 405, { error: 'method_not_allowed' });
    return;
  }

  if (p === '/api/room' && req.method === 'POST' && !q.get('code')) {
    const body = await readJson(req);
    if (!validDescription(body.offer)) { sendJson(res, 400, { error: 'bad_offer' }); return; }
    const code = newCode();
    const secret = newSecret();
    rooms.set(code, { secret, offer: body.offer, answer: null, createdAt: now(), pollWaiters: [] });
    sendJson(res, 200, { code, secret });
    return;
  }

  if (p === '/api/room') {
    const code = (q.get('code') || '').toUpperCase();
    if (!/^[A-Z0-9]{4}$/.test(code)) { sendJson(res, 400, { error: 'bad_code' }); return; }
    const room = rooms.get(code);
    if (!room) { sendJson(res, 404, { error: 'room_not_found' }); return; }

    if (req.method === 'GET') {
      const wait = Math.min(MAX_ANSWER_WAIT_S, Math.max(0, Number(q.get('wait') || 0)));
      if (q.has('secret')) {
        if (q.get('secret') !== room.secret) { sendJson(res, 403, { error: 'bad_secret' }); return; }
        if (room.answer) { sendJson(res, 200, { answer: room.answer }); return; }
        const waiter = { res, timer: null, done: false };
        room.pollWaiters.push(waiter);
        waiter.timer = setTimeout(() => {
          if (waiter.done) return;
          waiter.done = true;
          sendJson(res, 200, { answer: null });
        }, Math.max(1, wait) * 1000);
        req.on('close', () => { waiter.done = true; clearTimeout(waiter.timer); });
        return;
      }
      sendJson(res, 200, { offer: room.offer, ice: icePayload() });
      return;
    }

    if (req.method === 'POST' && q.get('action') === 'answer') {
      const body = await readJson(req);
      if (!validDescription(body.answer)) { sendJson(res, 400, { error: 'bad_answer' }); return; }
      room.answer = body.answer;
      if (room.pollWaiters.length) finishWaiters(room.pollWaiters, { answer: room.answer });
      sendJson(res, 200, { ok: true });
      return;
    }

    if (req.method === 'DELETE') {
      if (q.get('secret') !== room.secret) { sendJson(res, 403, { error: 'bad_secret' }); return; }
      finishWaiters(room.pollWaiters, { answer: null, closed: true });
      rooms.delete(code);
      sendJson(res, 200, { ok: true });
      return;
    }

    sendJson(res, 405, { error: 'method_not_allowed' });
    return;
  }

  sendJson(res, 404, { error: 'not_found' });
}

/* ---------------------------------------------------------------- static + delivery */

const HASHED = /-[A-Za-z0-9_-]{8}\.(?:js|css|mp3|glb|gltf)$/;
const IMMUTABLE = /\.(?:png|webp|woff2|wasm)$/;

function encode(body, type, acceptEncoding) {
  if (!TEXT_TYPES.test(type) || body.length < 1024) return { body, enc: null };
  const acceptsBr = /\bbr\b/.test(acceptEncoding || '');
  const acceptsGzip = /\bgzip\b/.test(acceptEncoding || '');
  if (acceptsBr) return { body: brotliCompressSync(body, { params: { [zc.BROTLI_PARAM_QUALITY]: 5 } }), enc: 'br' };
  if (acceptsGzip) return { body: gzipSync(body, { level: 6 }), enc: 'gzip' };
  return { body, enc: null };
}

function cachedEncode(key, body, type, acceptEncoding) {
  const entry = compressionCache.get(key);
  if (entry && entry.rawLength === body.length && entry.enc === (/\bbr\b/.test(acceptEncoding || '') ? 'br' : /\bgzip\b/.test(acceptEncoding || '') ? 'gzip' : null)) return entry;
  const { body: out, enc } = encode(body, type, acceptEncoding);
  const result = { body: out, enc, rawLength: body.length };
  if (compressionCache.size > 400) compressionCache.clear();
  compressionCache.set(key, result);
  return result;
}

async function handleStatic(req, res, url) {
  let path = decodeURIComponent(url.pathname);
  if (path === '/' || path === '') path = '/index.html';
  if (path === '/healthz') {
    sendJson(res, 200, { ok: true, uptime: Math.round(process.uptime()), build: buildInfo(), rooms: rooms.size, signals: signals.size });
    return;
  }
  const file = resolve(join(ROOT, path));
  if (!file.startsWith(ROOT)) { res.writeHead(403).end('forbidden'); return; }
  const st = await stat(file).catch(() => null);
  if (!st || !st.isFile()) { res.writeHead(404, { 'content-type': 'text/plain' }).end('404'); return; }

  const type = MIME[extname(file).toLowerCase()] || 'application/octet-stream';
  const etag = `"${createHash('sha1').update(`${st.size}:${st.mtimeMs}`).digest('hex').slice(0, 20)}"`;
  if (req.headers['if-none-match'] === etag) { res.writeHead(304, { etag }); res.end(); return; }

  const raw = await readFile(file);
  const { body, enc } = cachedEncode(file, raw, type, req.headers['accept-encoding']);

  const isHtml = path.endsWith('.html') || path === '/';
  const cacheControl = isHtml
    ? 'no-cache'
    : HASHED.test(path) || IMMUTABLE.test(path)
      ? 'public, max-age=31536000, immutable'
      : 'public, max-age=3600';

  const headers = {
    'content-type': type,
    'content-length': body.length,
    'cache-control': cacheControl,
    etag,
    'x-content-type-options': 'nosniff',
  };
  if (enc) { headers['content-encoding'] = enc; headers.vary = 'accept-encoding'; }
  res.writeHead(200, headers);
  res.end(req.method === 'HEAD' ? undefined : body);
}

/* ---------------------------------------------------------------- server */

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (url.pathname.startsWith('/api/')) { await handleApi(req, res, url); return; }
    await handleStatic(req, res, url);
  } catch (err) {
    const status = Number.isInteger(err?.status) ? err.status : 500;
    if (!res.headersSent) sendJson(res, status, { error: err?.message || 'server_error' });
    else { try { res.end(); } catch { /* ignore */ } }
  }
});

setInterval(() => {
  const t = now();
  for (const [code, room] of rooms) if (t - room.createdAt > ROOM_TTL_MS) rooms.delete(code);
  for (const [key, slot] of signals) if (t - slot.at > SIGNAL_TTL_MS && !slot.waiters.length) signals.delete(key);
  for (const [ip, b] of buckets) if (t > b.reset + 120_000) buckets.delete(ip);
}, 60_000).unref();

server.listen(PORT, HOST, () => {
  const ice = icePayload();
  console.log(`GHEE KHTAM FIGHT (${BUILD.root}${BUILD.version ? ' · ' + BUILD.version : ''}) → http://${HOST === '0.0.0.0' ? '127.0.0.1' : HOST}:${PORT}/`);
  console.log(`delivery: brotli/gzip · immutable hashed assets · etag · /healthz`);
  console.log(`signalling: /api/ice · /api/room · ICE servers: ${ice.iceServers.length}${ice.relay ? ' (TURN relay)' : ' (STUN only)'}`);
  if (HOST === '0.0.0.0') console.log(`LAN mode: share http://<your-lan-ip>:${PORT}/ with the other player`);
});
