"use strict";
/* Kingpin account + cloud-save server. No dependencies, needs Node 18+.

   Run:   node server.js        then open http://localhost:3000
   It serves index.html AND the API from one origin, so there is no CORS setup.

   Storage: Render's free disk is wiped on every restart/redeploy, which deletes accounts. To keep them, create a free
            Upstash Redis database and set UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN. Without them the server
            falls back to a local file (fine on your own PC, or on a host with a persistent disk: set DATA_FILE).

   Env:   PORT          (default 3000)
          DATA_FILE     where accounts are stored (default ./data/kingpin-db.json)
          GAME_FILE     the game page to serve   (default ./index.html)
          ADMIN_USER    username that gets the admin panel (default "smiley")
          TRUST_PROXY=1 read the client IP from X-Forwarded-For (use behind a reverse proxy)

   Passwords are hashed with scrypt (per-user salt). Login tokens are random, stored only as
   SHA-256 hashes, and expire after 90 days. Accounts have no email, so there is no password reset. */

const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");

const PORT = +process.env.PORT || 3000;
const DB_FILE = process.env.DATA_FILE || path.join(__dirname, "data", "kingpin-db.json");
const PAGE = process.env.GAME_FILE || path.join(__dirname, "index.html");
const TRUST_PROXY = process.env.TRUST_PROXY === "1";
const REDIS_URL = (process.env.UPSTASH_REDIS_REST_URL || "").replace(/\/$/, ""), REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || "";
const useRedis = !!(REDIS_URL && REDIS_TOKEN);
const TOKEN_MS = 90 * 864e5, MAX_TOKENS = 10, MAX_SAVE = useRedis ? 700 * 1024 : 2 * 1024 * 1024;   // Upstash free tier caps a request at 1 MB
const NAME_RE = /^[A-Za-z0-9_]{3,16}$/;
const ADMIN_KEY = (process.env.ADMIN_USER || "smiley").toLowerCase();   // the one account that gets the in-game admin panel
const isAdminKey = k => k === ADMIN_KEY;
/* ---------- player raids: base snapshots, raid tickets, loot inbox, shield */
const BTYPES = new Set(["corner","chop","loan","racket","casino","hideout","front","wash","resto","club","farm","lab","fent","hub","armory","fence","tower","sand","turret","mgnest","bunker"]);
const SHIELD_MS = 12 * 36e5, PROF_MAX_AGE = 14 * 864e5, STEAL_DIRTY = 0.35, STEAL_CASH = 0.10;
const tickets = new Map();   // raid ticket -> { att, tgt, exp }  (in memory; a restart just voids open raids)
const num = (v, max) => { v = +v; return Number.isFinite(v) && v >= 0 ? Math.min(v, max) : 0; };
function cleanProf(p) {      // the public "base snapshot" other players raid; sanitised, never trusted blindly
  if (!p || typeof p !== "object" || !Array.isArray(p.b)) return null;
  const b = [];
  for (const q of p.b.slice(0, 400)) {
    if (!q || !BTYPES.has(q.t)) continue;
    const x = Math.floor(+q.x), y = Math.floor(+q.y), l = Math.floor(+q.l);
    if (x >= 0 && x < 64 && y >= 0 && y < 64 && l >= 1 && l <= 9) b.push({ t: q.t, x, y, l });
  }
  return { lvl: Math.max(1, Math.min(9, Math.floor(+p.lvl) || 1)), terr: Math.max(0, Math.min(99, Math.floor(+p.terr) || 0)),
           pw: num(p.pw, 1e9), dirty: num(p.dirty, 1e15), cash: num(p.cash, 1e15), sh: num(p.sh, 1e15), b, t: Date.now() };
}
const pending = u => (u.inbox || []).reduce((a, i) => ({ dirty: a.dirty + i.dirty, cash: a.cash + i.cash }), { dirty: 0, cash: 0 });
function lootable(u) {       // what a raider could still take: last reported stash minus thefts the victim hasn't applied yet
  const p = u.prof; if (!p) return { dirty: 0, cash: 0 };
  const pe = pending(u); return { dirty: Math.max(0, p.dirty - pe.dirty), cash: Math.max(0, p.cash - pe.cash) };
}
const shieldOf = u => Math.max(u.shield || 0, (u.prof && u.prof.sh) || 0);

const NAME_HINT = "Use 3–16 letters, numbers or underscores.";

/* ---------- storage: in-memory object, persisted to Upstash Redis (one key per account) or a local file */
let db = { users: {} };
const persisted = new Map();            // account key -> last JSON written (so only changed accounts are re-sent)
let dirty = false, timer = null, chain = Promise.resolve();
async function redis(cmds) {            // Upstash REST pipeline: POST [["SET","k","v"],["GET","k"]] -> [{result}, ...]
  const r = await fetch(REDIS_URL + "/pipeline", { method: "POST", headers: { Authorization: "Bearer " + REDIS_TOKEN, "Content-Type": "application/json" }, body: JSON.stringify(cmds) });
  if (!r.ok) throw new Error("Redis HTTP " + r.status);
  const out = await r.json(); const bad = out.find(x => x && x.error); if (bad) throw new Error("Redis: " + bad.error);
  return out;
}
async function loadDb() {
  if (useRedis) {
    const keys = (await redis([["KEYS", "kp:user:*"]]))[0].result || [];
    for (let i = 0; i < keys.length; i += 50) {
      const part = keys.slice(i, i + 50), vals = await redis(part.map(k => ["GET", k]));
      part.forEach((k, j) => { try { const u = JSON.parse(vals[j].result), key = k.slice(8); db.users[key] = u; persisted.set(key, vals[j].result); } catch (e) {} });
    }
    console.log("Loaded " + Object.keys(db.users).length + " account(s) from Redis");
    if (!keys.length && fs.existsSync(DB_FILE)) {        // one-time move of an existing file database into Redis
      try { db = JSON.parse(fs.readFileSync(DB_FILE, "utf8")); db.users = db.users || {}; markDirty(); console.log("Migrating file database to Redis"); } catch (e) {}
    }
  } else {
    try { db = JSON.parse(fs.readFileSync(DB_FILE, "utf8")); db.users = db.users || {}; } catch (e) { /* first run */ }
    console.warn("WARNING: no Redis configured, saving to " + DB_FILE + ". On Render's free plan this file is erased on every restart.");
  }
}
function markDirty() { dirty = true; if (!timer) timer = setTimeout(flush, 400); }
function flush() { timer = null; chain = chain.then(doFlush, doFlush); return chain; }
async function doFlush() {
  if (!dirty) return; dirty = false;
  if (!useRedis) { fs.mkdirSync(path.dirname(DB_FILE), { recursive: true }); const tmp = DB_FILE + ".tmp"; fs.writeFileSync(tmp, JSON.stringify(db)); fs.renameSync(tmp, DB_FILE); return; }
  const cmds = [];
  for (const k in db.users) { const v = JSON.stringify(db.users[k]); if (persisted.get(k) !== v) cmds.push({ k, v }); }
  for (let i = 0; i < cmds.length;) {   // batches stay under the ~1 MB request limit
    const batch = []; let size = 0;
    while (i < cmds.length && (!batch.length || size + cmds[i].v.length < 800 * 1024)) { size += cmds[i].v.length; batch.push(cmds[i++]); }
    try { await redis(batch.map(c => ["SET", "kp:user:" + c.k, c.v])); batch.forEach(c => persisted.set(c.k, c.v)); }
    catch (e) { console.error("Redis save failed, will retry:", e.message); dirty = true; if (!timer) timer = setTimeout(flush, 5000); return; }
  }
}
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => { setTimeout(() => process.exit(0), 6000).unref(); flush().finally(() => process.exit(0)); });

/* ---------- passwords and tokens */
const scrypt = (pw, salt) => new Promise((ok, no) => crypto.scrypt(pw, salt, 64, (e, k) => e ? no(e) : ok(k)));
async function hashPw(pw) { const salt = crypto.randomBytes(16); return salt.toString("hex") + ":" + (await scrypt(pw, salt)).toString("hex"); }
async function checkPw(pw, stored) {
  const [s, h] = stored.split(":"), k = await scrypt(pw, Buffer.from(s, "hex")), a = Buffer.from(h, "hex");
  return a.length === k.length && crypto.timingSafeEqual(a, k);
}
let dummy; const dummyHash = async () => dummy || (dummy = await hashPw("not-a-real-password")); // keeps unknown-user logins as slow as real ones
const sha = t => crypto.createHash("sha256").update(t).digest("hex");
function issueToken(key, user) {
  const raw = crypto.randomBytes(32).toString("base64url"), now = Date.now();
  user.tokens = (user.tokens || []).filter(t => t.exp > now);
  user.tokens.push({ h: sha(raw), exp: now + TOKEN_MS });
  if (user.tokens.length > MAX_TOKENS) user.tokens = user.tokens.slice(-MAX_TOKENS);
  return key + "." + raw;
}
function auth(req) {
  const m = /^Bearer ([a-z0-9_]+)\.([\w-]+)$/.exec(req.headers.authorization || "");
  if (!m) return null;
  const user = db.users[m[1]]; if (!user) return null;
  const h = sha(m[2]), now = Date.now(), tok = (user.tokens || []).find(t => t.h === h && t.exp > now);
  return tok ? { user, tok, key: m[1] } : null;
}

/* ---------- helpers */
const hits = new Map();
function limited(ip, bucket, max, windowMs) {
  const k = bucket + "|" + ip, now = Date.now(); let h = hits.get(k);
  if (!h || h.r < now) { h = { n: 0, r: now + windowMs }; hits.set(k, h); }
  return ++h.n > max;
}
setInterval(() => { const n = Date.now(); for (const [k, h] of hits) if (h.r < n) hits.delete(k); }, 60e3).unref();
const clientIp = req => TRUST_PROXY ? ((req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress) : req.socket.remoteAddress;
function send(res, code, obj) {
  const s = JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "Content-Length": Buffer.byteLength(s) });
  res.end(s);
}
const tooMany = res => send(res, 429, { error: "Too many attempts. Wait a few minutes and try again." });
function readBody(req) {
  return new Promise((ok, no) => {
    let n = 0; const chunks = [];
    req.on("data", d => { n += d.length; if (n > MAX_SAVE + 8192) { no(Object.assign(new Error("big"), { code: 413 })); req.destroy(); return; } chunks.push(d); });
    req.on("end", () => { try { ok(JSON.parse(Buffer.concat(chunks).toString() || "{}")); } catch (e) { no(Object.assign(new Error("bad"), { code: 400 })); } });
    req.on("error", no);
  });
}
function parseSave(data, t) {
  if (typeof data !== "string" || data.length > MAX_SAVE) return null;
  let o; try { o = JSON.parse(data); } catch (e) { return null; }
  if (!o || typeof o !== "object" || !o.u) return null;        // same shape check the game does on load
  const tt = +t; return { data, t: Number.isFinite(tt) && tt > 0 ? tt : (+o.t || Date.now()) };
}

/* ---------- API */
async function api(req, res, url, p) {
  const ip = clientIp(req), m = req.method;

  if (p === "/api/check" && m === "GET") {
    if (limited(ip, "chk", 120, 60e3)) return send(res, 429, { error: "Too many requests. Wait a moment." });
    const u = (url.searchParams.get("u") || "").trim();
    if (!NAME_RE.test(u)) return send(res, 200, { valid: false, available: false, reason: NAME_HINT });
    return send(res, 200, { valid: true, available: !db.users[u.toLowerCase()] });
  }

  if (p === "/api/register" && m === "POST") {
    if (limited(ip, "auth", 20, 10 * 60e3)) return tooMany(res);
    const b = await readBody(req), u = String(b.username || "").trim(), pw = typeof b.password === "string" ? b.password : "";
    if (!NAME_RE.test(u)) return send(res, 400, { error: NAME_HINT });
    if (pw.length < 6 || pw.length > 128) return send(res, 400, { error: "Password must be 6–128 characters." });
    const save = b.data == null ? null : parseSave(b.data, b.t);
    if (b.data != null && !save) return send(res, 400, { error: "That save file is not valid." });
    const hash = await hashPw(pw), key = u.toLowerCase();
    if (db.users[key]) return send(res, 409, { error: "That username is taken. Try another." });   // re-checked after the await: no race
    const user = db.users[key] = { name: u, pw: hash, created: Date.now(), tokens: [], save: save ? { ...save, ver: 1, updated: Date.now() } : null };
    const token = issueToken(key, user); markDirty();
    return send(res, 201, { token, admin: isAdminKey(key), user: { name: u }, ver: user.save ? 1 : 0, t: user.save ? user.save.t : 0 });
  }

  if (p === "/api/login" && m === "POST") {
    if (limited(ip, "auth", 20, 10 * 60e3)) return tooMany(res);
    const b = await readBody(req), key = String(b.username || "").trim().toLowerCase(), pw = typeof b.password === "string" ? b.password : "";
    const user = db.users[key], ok = await checkPw(pw, user ? user.pw : await dummyHash());
    if (!user || !ok) return send(res, 401, { error: "Wrong username or password." });
    const token = issueToken(key, user); markDirty();
    const s = user.save;
    return send(res, 200, { token, admin: isAdminKey(key), user: { name: user.name }, ver: s ? s.ver : 0, t: s ? s.t : 0, data: s ? s.data : null });
  }

  if (p === "/api/save") {
    const a = auth(req); if (!a) return send(res, 401, { error: "Please log in again." });
    const cur = a.user.save, curVer = cur ? cur.ver : 0;
    if (m === "GET") return send(res, 200, { admin: isAdminKey(a.key), ver: curVer, t: cur ? cur.t : 0, data: cur ? cur.data : null });
    if (m === "PUT") {
      if (limited(ip, "put", 240, 60e3)) return tooMany(res);
      const b = await readBody(req), s = parseSave(b.data, b.t);
      if (!s) return send(res, 400, { error: "That save file is not valid." });
      // Optimistic concurrency: the client says which version it built on. If another device saved since, tell it.
      if (!b.force && Number(b.baseVer) !== curVer) return send(res, 409, { error: "conflict", ver: curVer, t: cur ? cur.t : 0, data: cur ? cur.data : null });
      a.user.save = { data: s.data, t: s.t, ver: curVer + 1, updated: Date.now() };
      const pr = cleanProf(b.prof); if (pr) a.user.prof = pr;
      markDirty();
      return send(res, 200, { ver: curVer + 1 });
    }
  }

  if (p === "/api/opponent" && m === "GET") {          // pick a real base to raid and hand out a one-time ticket
    const a = auth(req); if (!a) return send(res, 401, { error: "Please log in again." });
    if (limited(ip, "opp", 90, 60e3)) return tooMany(res);
    const lvl = +url.searchParams.get("lvl") || 1, pw = +url.searchParams.get("pw") || 0, now = Date.now(), cand = [];
    for (const k in db.users) {
      const u = db.users[k], pr = u.prof;
      if (k === a.key || !pr || now - pr.t > PROF_MAX_AGE || shieldOf(u) > now || pr.b.length < 3) continue;
      cand.push({ k, u, pr });
    }
    let pool = cand.filter(c => Math.abs(c.pr.lvl - lvl) <= 2 && (pw <= 0 || (c.pr.pw >= pw * .35 && c.pr.pw <= pw * 3)));
    if (!pool.length) pool = cand.filter(c => Math.abs(c.pr.lvl - lvl) <= 3);
    if (!pool.length) return send(res, 200, { opponent: null });
    const c = pool[Math.floor(Math.random() * pool.length)], lt = lootable(c.u), ticket = crypto.randomBytes(12).toString("base64url");
    for (const [t, v] of tickets) if (v.exp < now) tickets.delete(t);
    tickets.set(ticket, { att: a.key, tgt: c.k, exp: now + 20 * 60e3 });
    return send(res, 200, { opponent: { ticket, n: c.u.name, lvl: c.pr.lvl, terr: c.pr.terr, pw: c.pr.pw, b: c.pr.b,
      l: Math.floor(lt.dirty * STEAL_DIRTY), lc: Math.floor(lt.cash * STEAL_CASH) } });
  }

  if (p === "/api/raid" && m === "POST") {              // attacker reports the result; server decides the loot and records the theft
    const a = auth(req); if (!a) return send(res, 401, { error: "Please log in again." });
    const b = await readBody(req), tk = tickets.get(String(b.ticket || "")), now = Date.now();
    if (!tk || tk.att !== a.key || tk.exp < now || !db.users[tk.tgt]) return send(res, 410, { error: "That raid expired." });
    tickets.delete(String(b.ticket));
    const v = db.users[tk.tgt], pct = Math.max(0, Math.min(100, Math.floor(+b.pct) || 0)), stars = Math.max(0, Math.min(3, Math.floor(+b.stars) || 0));
    const lt = lootable(v), dirty = Math.floor(lt.dirty * STEAL_DIRTY * pct / 100), cash = Math.floor(lt.cash * STEAL_CASH * pct / 100);
    if (pct >= 15) {                                     // a real hit: log it for the victim and start their 12h shield
      v.shield = now + SHIELD_MS;
      v.inbox = (v.inbox || []).concat({ id: crypto.randomBytes(6).toString("hex"), from: a.user.name, t: now, stars, pct, dirty, cash }).slice(-30);
      markDirty();
    }
    return send(res, 200, { dirty, cash, victim: v.name });
  }

  if (p === "/api/inbox" && m === "GET") {
    const a = auth(req); if (!a) return send(res, 401, { error: "Please log in again." });
    return send(res, 200, { items: a.user.inbox || [], shield: shieldOf(a.user) });
  }
  if (p === "/api/inbox/ack" && m === "POST") {         // victim applied the thefts: clear them and report the new stash in one step
    const a = auth(req); if (!a) return send(res, 401, { error: "Please log in again." });
    const b = await readBody(req), ids = new Set(Array.isArray(b.ids) ? b.ids.map(String) : []);
    a.user.inbox = (a.user.inbox || []).filter(i => !ids.has(i.id));
    const pr = cleanProf(b.prof); if (pr) a.user.prof = pr;
    markDirty(); return send(res, 200, { ok: true, shield: shieldOf(a.user) });
  }

  if (p === "/api/me" && m === "GET") {
    const a = auth(req); if (!a) return send(res, 401, { error: "Please log in again." });
    return send(res, 200, { name: a.user.name, admin: isAdminKey(a.key) });
  }

  if (p === "/api/logout" && m === "POST") {
    const a = auth(req);
    if (a) { a.user.tokens = a.user.tokens.filter(t => t !== a.tok); markDirty(); }
    return send(res, 200, { ok: true });
  }

  send(res, 404, { error: "Not found" });
}

/* ---------- http server */
const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");     // token auth in a header (no cookies), so this is safe
  res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }
  try {
    const url = new URL(req.url, "http://x"), p = url.pathname;
    if (p.startsWith("/api/")) return await api(req, res, url, p);
    if (p === "/" || p === "/index.html") {
      if (!fs.existsSync(PAGE)) { res.writeHead(404, { "Content-Type": "text/plain" }); return res.end("index.html not found next to server.js"); }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      return fs.createReadStream(PAGE).pipe(res);
    }
    send(res, 404, { error: "Not found" });
  } catch (e) {
    if (e && (e.code === 400 || e.code === 413)) return send(res, e.code, { error: e.code === 413 ? "Save is too large." : "Bad request." });
    console.error(e); send(res, 500, { error: "Server error. Try again." });
  }
});
loadDb().then(() => server.listen(PORT, () => console.log("Kingpin server running on http://localhost:" + PORT)))
  .catch(e => { console.error("Could not load the account database:", e.message); process.exit(1); });
