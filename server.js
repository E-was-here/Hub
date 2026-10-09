"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PUBLIC = path.join(__dirname, "public");
const DATA = path.join(__dirname, "data");
const GAMES_FILE = path.join(DATA, "games.json");
const PORT = +process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const CHECK_EVERY_MS = 30000;
if (ADMIN_PASSWORD.length < 8) {
  console.error("Set ADMIN_PASSWORD (8+ characters) in .env before starting.");
  process.exit(1);
}

/* ---------- Games list ---------- */
const DEFAULT_GAMES = [{
  id: "dentifrice", name: "Dentifrice", description: "Grand jeu scout",
  link: "/dentifrice/", checkUrl: "http://scouts-dentifrice:3000/dentifrice/api/state",
}];

function validLink(s) {
  if (/^\/(?!\/)/.test(s)) return true;                 // relative link on this site
  try { const u = new URL(s); return u.protocol === "http:" || u.protocol === "https:"; } catch (e) { return false; }
}
function validUrl(s) { try { const u = new URL(s); return u.protocol === "http:" || u.protocol === "https:"; } catch (e) { return false; } }

// Returns { games } or { error }
function clean(list) {
  if (!Array.isArray(list)) return { error: "Invalid list" };
  if (list.length > 50) return { error: "Too many games (max 50)" };
  const out = [], ids = new Set();
  for (let i = 0; i < list.length; i++) {
    const g = list[i] || {};
    const name = String(g.name || "").trim(), description = String(g.description || "").trim();
    const link = String(g.link || "").trim(), checkUrl = String(g.checkUrl || "").trim();
    const label = `Game ${i + 1}`;
    if (!name || name.length > 60) return { error: `${label}: name required (60 characters max)` };
    if (description.length > 200) return { error: `${label}: description too long (200 max)` };
    if (link.length > 300 || !validLink(link)) return { error: `${label}: link must start with / or http(s)://` };
    if (checkUrl && (checkUrl.length > 300 || !validUrl(checkUrl))) return { error: `${label}: check URL must start with http(s)://` };
    let id = /^[A-Za-z0-9_-]{1,40}$/.test(g.id || "") ? g.id : crypto.randomBytes(6).toString("hex");
    if (ids.has(id)) id = crypto.randomBytes(6).toString("hex");
    ids.add(id);
    out.push({ id, name, description, link, checkUrl });
  }
  return { games: out };
}

function loadGames() {
  try {
    const r = clean(JSON.parse(fs.readFileSync(GAMES_FILE, "utf8")));
    if (r.games) return r.games;
    console.error("games.json invalid:", r.error);
  } catch (e) {
    if (e.code !== "ENOENT") console.error("games.json unreadable:", e.message);
  }
  return DEFAULT_GAMES;
}
function saveGames() {
  fs.mkdirSync(DATA, { recursive: true });
  fs.writeFileSync(GAMES_FILE + ".tmp", JSON.stringify(games, null, 2));
  fs.renameSync(GAMES_FILE + ".tmp", GAMES_FILE);
}
let games = loadGames();
if (!fs.existsSync(GAMES_FILE)) saveGames();

/* ---------- Status checks ---------- */
const status = {};   // id -> { online: true | false | null, at }
async function check(g) {
  const target = g.checkUrl || (/^https?:/i.test(g.link) ? g.link : "");
  if (!target) return { online: null, at: Date.now() };   // relative link and no check URL: unknown
  try {
    const r = await fetch(target, { signal: AbortSignal.timeout(4000), redirect: "manual", cache: "no-store" });
    if (r.body) r.body.cancel().catch(() => {});
    return { online: r.status < 500, at: Date.now() };
  } catch (e) { return { online: false, at: Date.now() }; }
}
async function checkAll() {
  const list = games.slice();
  const res = await Promise.all(list.map(check));
  list.forEach((g, i) => { status[g.id] = res[i]; });
}

/* ---------- Auth (HTTP Basic, over HTTPS via the proxy) ---------- */
const sha = s => crypto.createHash("sha256").update(String(s)).digest();
const failures = new Map();
const clientIp = req => (req.headers["x-forwarded-for"] || "").split(",").pop().trim() || req.socket.remoteAddress;

function send(res, code, body) {
  const isObj = typeof body === "object";
  res.writeHead(code, { "Content-Type": isObj ? "application/json; charset=utf-8" : "text/plain; charset=utf-8",
    "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
  res.end(isObj ? JSON.stringify(body) : body);
}

function checkAuth(req, res) {
  if (req.headers["x-forwarded-proto"] === "http") { send(res, 403, "Admin requires HTTPS"); return false; }
  const ip = clientIp(req), f = failures.get(ip) || { count: 0, until: 0 };
  if (f.until > Date.now()) { send(res, 429, "Too many failed attempts. Try again in a few minutes."); return false; }
  const h = req.headers.authorization || "";
  if (h.startsWith("Basic ")) {
    const dec = Buffer.from(h.slice(6), "base64").toString("utf8");
    const k = dec.indexOf(":");
    if (k >= 0) {
      const okU = crypto.timingSafeEqual(sha(dec.slice(0, k)), sha(ADMIN_USER));
      const okP = crypto.timingSafeEqual(sha(dec.slice(k + 1)), sha(ADMIN_PASSWORD));
      if (okU && okP) { failures.delete(ip); return true; }
    }
    f.count++;
    if (f.count >= 5) { f.until = Date.now() + 5 * 60000; f.count = 0; }
    failures.set(ip, f);
    console.log(new Date().toISOString(), "FAILED LOGIN", ip);
  }
  res.writeHead(401, { "WWW-Authenticate": 'Basic realm="Hub admin", charset="UTF-8"', "Content-Type": "text/plain" });
  res.end("Authentication required");
  return false;
}

/* ---------- HTTP ---------- */
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp", ".svg": "image/svg+xml", ".ico": "image/x-icon" };

function serveStatic(res, urlPath) {
  let rel;
  try { rel = decodeURIComponent(urlPath); } catch (e) { return send(res, 400, "Bad request"); }
  let p = path.normalize(path.join(PUBLIC, rel));
  if (p !== PUBLIC && !p.startsWith(PUBLIC + path.sep)) return send(res, 403, "Forbidden");
  fs.stat(p, (err, st) => {
    if (!err && st.isDirectory()) p = path.join(p, "index.html");
    fs.readFile(p, (err2, data) => {
      if (err2) return send(res, 404, "Not found");
      res.writeHead(200, { "Content-Type": MIME[path.extname(p).toLowerCase()] || "application/octet-stream",
        "Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff" });
      res.end(data);
    });
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", c => {
      size += c.length;
      if (size > 30000) { reject(new Error("Body too large")); req.destroy(); } else chunks.push(c);
    });
    req.on("end", () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString() || "{}")); } catch (e) { reject(new Error("Invalid JSON")); }
    });
    req.on("error", reject);
  });
}

const publicList = () => games.map(g => ({ id: g.id, name: g.name, description: g.description, link: g.link,
  online: status[g.id] ? status[g.id].online : null }));
const adminList = () => games.map(g => ({ ...g, online: status[g.id] ? status[g.id].online : null }));

const server = http.createServer(async (req, res) => {
  try {
    const p = new URL(req.url, "http://x").pathname;

    if (p === "/admin") { res.writeHead(301, { Location: "/admin/" }); return res.end(); }
    if (p.startsWith("/admin/")) {
      if (!checkAuth(req, res)) return;

      if (p === "/admin/api/games" && req.method === "GET") return send(res, 200, { games: adminList() });

      if (p === "/admin/api/save") {
        if (req.method !== "POST") return send(res, 405, { error: "POST only" });
        const host = req.headers["x-forwarded-host"] || req.headers.host;   // anti-CSRF
        if (req.headers.origin) {
          let oh = null;
          try { oh = new URL(req.headers.origin).host; } catch (e) {}
          if (oh !== host) return send(res, 403, { error: "Bad origin" });
        }
        if (!(req.headers["content-type"] || "").startsWith("application/json")) return send(res, 415, { error: "JSON required" });
        let body;
        try { body = await readBody(req); } catch (e) { return send(res, 400, { error: e.message }); }
        const r = clean(body.games);
        if (r.error) return send(res, 400, { error: r.error });
        games = r.games;
        saveGames();
        await checkAll();
        console.log(new Date().toISOString(), clientIp(req), `SAVE ${games.length} game(s)`);
        return send(res, 200, { ok: true });
      }

      if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, "Method not allowed");
      return serveStatic(res, p);
    }

    if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, "Method not allowed");
    if (p === "/api/games") return send(res, 200, { games: publicList() });
    return serveStatic(res, p);
  } catch (e) {
    console.error(e);
    send(res, 500, "Server error");
  }
});

checkAll();
setInterval(checkAll, CHECK_EVERY_MS);
server.listen(PORT, () => console.log(`Hub running on port ${PORT} (${games.length} game(s))`));