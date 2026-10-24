const enc = new TextEncoder();

const KEY_RE = /^[A-Za-z0-9-]{1,64}$/;
const TOKEN_RE = /^[A-Za-z0-9_-]{8,128}$/;
const ID_RE = /^[A-Za-z0-9_-]{43}$/;
const DIGITS_RE = /^\d{1,25}$/;
const SESSION_TTL = 1800;
const LIMITS = {
  start: [8, 600],
  callback: [20, 600],
  captcha: [20, 600],
  generate: [10, 600],
  adminfail: [10, 600],
};

const now = () => Date.now() / 1000;

function settings(env) {
  const siteUrl = String(env.SITE_URL || "").replace(/\/+$/, "");
  const url = new URL(siteUrl);
  const secure = siteUrl.startsWith("https://");
  return {
    siteUrl,
    host: url.host,
    hostname: url.hostname,
    secure,
    sidName: secure ? "__Host-xsid" : "xsid",
    didName: secure ? "__Host-xdid" : "xdid",
    keySeconds: Number(env.KEY_HOURS || 24) * 3600,
    minCheckpoint: Number(env.MIN_CHECKPOINT_SECONDS ?? 15),
    ipCheck: String(env.WORKINK_IP_CHECK ?? "1") === "1",
    resetCooldown: Number(env.HWID_RESET_COOLDOWN || 86400),
    linkId: String(env.WORKINK_LINK_ID || "").trim(),
    workinkApi: env.WORKINK_API_BASE || "https://work.ink/_api/v2/token/isValid/",
    turnstileUrl: env.TURNSTILE_VERIFY_URL || "https://challenges.cloudflare.com/turnstile/v0/siteverify",
  };
}

function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function toB64Url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const randomId = () => toB64Url(crypto.getRandomValues(new Uint8Array(32)));

async function sha256Bytes(text) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}

async function sha256Hex(text) {
  return toHex(await sha256Bytes(text));
}

async function hmacHex(secret, text) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(text))));
}

function newKey() {
  const hex = toHex(crypto.getRandomValues(new Uint8Array(8))).toUpperCase();
  return hex.match(/.{4}/g).join("-");
}

function parseIPv4(text) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((n) => n <= 255) ? parts : null;
}

function parseIPv6(input) {
  let text = input.split("%")[0];
  const tail = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (tail) {
    const v4 = parseIPv4(tail[2]);
    if (!v4) return null;
    text = tail[1] + ((v4[0] << 8) | v4[1]).toString(16) + ":" + ((v4[2] << 8) | v4[3]).toString(16);
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  let groups;
  if (halves.length === 1) {
    if (head.length !== 8) return null;
    groups = head;
  } else {
    const fill = 8 - head.length - rest.length;
    if (fill < 1) return null;
    groups = [...head, ...Array(fill).fill("0"), ...rest];
  }
  const nums = groups.map((g) => (/^[0-9a-f]{1,4}$/i.test(g) ? parseInt(g, 16) : NaN));
  return nums.some(Number.isNaN) ? null : nums;
}

function parseIp(text) {
  const raw = String(text || "").trim();
  const v4 = parseIPv4(raw);
  if (v4) return { v: 4, parts: v4 };
  const v6 = parseIPv6(raw);
  if (!v6) return null;
  if (v6.slice(0, 5).every((n) => n === 0) && v6[5] === 0xffff) {
    return { v: 4, parts: [v6[6] >> 8, v6[6] & 255, v6[7] >> 8, v6[7] & 255] };
  }
  return { v: 6, parts: v6 };
}

function sameNetwork(a, b) {
  const x = parseIp(a);
  const y = parseIp(b);
  if (!x || !y || x.v !== y.v) return true;
  for (let i = 0; i < 4; i++) if (x.parts[i] !== y.parts[i]) return false;
  return true;
}

function toMs(value) {
  if (typeof value === "number") return value < 1e12 ? value * 1000 : value;
  if (typeof value === "string") {
    if (/^\d+(\.\d+)?$/.test(value)) return toMs(Number(value));
    const t = Date.parse(value);
    return Number.isNaN(t) ? 0 : t;
  }
  return 0;
}

function readCookies(request) {
  const out = {};
  for (const part of (request.headers.get("Cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

function cookieHeader(c, name, value, maxAge) {
  return `${name}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax${c.secure ? "; Secure" : ""}`;
}

function reply(data, status = 200, extra) {
  const headers = new Headers({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  if (extra) for (const [k, v] of extra) headers.append(k, v);
  return new Response(JSON.stringify(data), { status, headers });
}

function secured(resp, c) {
  const headers = new Headers(resp.headers);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  if (c.secure) headers.set("Strict-Transport-Security", "max-age=31536000");
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
}

function sendBack(c, code, extra) {
  const query = code ? `/?e=${code}${extra ? `&lid=${extra}` : ""}#free-key` : "/#free-key";
  return new Response(null, { status: 302, headers: { Location: c.siteUrl + query, "Cache-Control": "no-store" } });
}

async function readJson(request, max = 8192) {
  if (Number(request.headers.get("Content-Length") || 0) > max) return null;
  if (!request.body) return {};
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    all.set(chunk, at);
    at += chunk.byteLength;
  }
  try {
    const body = JSON.parse(new TextDecoder().decode(all));
    return body && typeof body === "object" && !Array.isArray(body) ? body : {};
  } catch {
    return {};
  }
}

function postGuard(request, c) {
  const origin = request.headers.get("Origin");
  if (!origin || origin !== c.siteUrl) return reply({ error: "origin" }, 403);
  if (request.headers.get("Sec-Fetch-Site") === "cross-site") return reply({ error: "origin" }, 403);
  const type = (request.headers.get("Content-Type") || "").split(";")[0].trim().toLowerCase();
  if (type !== "application/json") return reply({ error: "bad_request" }, 415);
  return null;
}

const sql = (env, text, ...args) => env.DB.prepare(text).bind(...args);

async function limited(env, bucket, ident) {
  const [limit, window] = LIMITS[bucket];
  const win = Math.floor(now() / window);
  const row = await sql(
    env,
    "INSERT INTO rate(bucket, ident, win, n, exp) VALUES(?, ?, ?, 1, ?) ON CONFLICT(bucket, ident, win) DO UPDATE SET n = n + 1 RETURNING n",
    bucket, ident, win, (win + 1) * window
  ).first();
  return row.n > limit;
}

function clientIp(request) {
  const ip = parseIp(request.headers.get("CF-Connecting-IP"));
  return ip ? request.headers.get("CF-Connecting-IP").trim() : "0.0.0.0";
}

async function getSession(request, env, c) {
  const sid = readCookies(request)[c.sidName];
  if (!sid || !ID_RE.test(sid)) return null;
  return sql(env, "SELECT * FROM sessions WHERE sid = ? AND created_at > ?", await sha256Hex(sid), now() - SESSION_TTL).first();
}

async function netHash(env, ip, ua) {
  return hmacHex(String(env.HASH_SECRET || ""), `${ip}|${ua.slice(0, 200)}`);
}

async function csp(html) {
  const hashes = [];
  for (const m of html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)) {
    hashes.push(`'sha256-${btoa(String.fromCharCode(...(await sha256Bytes(m[1]))))}'`);
  }
  return [
    "default-src 'none'",
    `script-src ${hashes.join(" ")} https://challenges.cloudflare.com`,
    "style-src 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self' https://challenges.cloudflare.com",
    "frame-src https://challenges.cloudflare.com",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
}

async function page(request, env) {
  const res = await env.ASSETS.fetch(new Request(new URL("/", request.url)));
  if (!res.ok) return reply({ error: "not_found" }, 404);
  const html = await res.text();
  return new Response(request.method === "HEAD" ? null : html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
      "Content-Security-Policy": await csp(html),
    },
  });
}

async function banner(request, env) {
  const res = await env.ASSETS.fetch(new Request(new URL("/banner.webp", request.url)));
  if (!res.ok) return reply({ error: "not_found" }, 404);
  const headers = new Headers(res.headers);
  headers.set("Cache-Control", "public, max-age=3600");
  return new Response(res.body, { status: 200, headers });
}

async function apiState(request, env, c) {
  const out = { stage: "none" };
  const sess = await getSession(request, env, c);
  if (sess) out.stage = sess.stage;
  const did = readCookies(request)[c.didName];
  if (did && ID_RE.test(did)) {
    const row = await sql(
      env,
      "SELECT key, expires_at FROM keys WHERE source = 'web' AND device_id = ? AND expires_at > ? ORDER BY created_at DESC LIMIT 1",
      await sha256Hex(did), now()
    ).first();
    if (row) {
      out.key = row.key;
      out.expires_at = row.expires_at;
    }
  }
  return reply(out);
}

async function apiStart(request, env, c, ip) {
  if (await limited(env, "start", ip)) return reply({ error: "rate_limited" }, 429);
  let did = readCookies(request)[c.didName];
  if (!did || !ID_RE.test(did)) did = randomId();
  const sid = randomId();
  const didHash = await sha256Hex(did);
  await env.DB.batch([
    sql(env, "DELETE FROM sessions WHERE device_id = ?", didHash),
    sql(
      env,
      "INSERT INTO sessions(sid, device_id, net_id, stage, created_at) VALUES(?, ?, ?, 'started', ?)",
      await sha256Hex(sid), didHash, await netHash(env, ip, request.headers.get("User-Agent") || ""), now()
    ),
  ]);
  return reply({ url: env.WORKINK_START_URL }, 200, [
    ["Set-Cookie", cookieHeader(c, c.sidName, sid, SESSION_TTL)],
    ["Set-Cookie", cookieHeader(c, c.didName, did, 31536000)],
  ]);
}

async function checkWorkink(env, c, token) {
  try {
    const res = await fetch(c.workinkApi + encodeURIComponent(token), {
      headers: { Accept: "application/json", "User-Agent": "ExodusKeys/1.0" },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    const body = await res.json();
    if (!body || !body.valid) return null;
    return body.info || body;
  } catch {
    return null;
  }
}

async function dropWorkinkToken(c, token) {
  try {
    await fetch(c.workinkApi + encodeURIComponent(token) + "?deleteToken=1", {
      headers: { "User-Agent": "ExodusKeys/1.0" },
      signal: AbortSignal.timeout(5000),
    });
  } catch {}
}

async function callback(request, env, ctx, c, ip) {
  if (await limited(env, "callback", ip)) return sendBack(c, "rate_limited");
  const token = (new URL(request.url).searchParams.get("token") || "").trim();
  if (!TOKEN_RE.test(token)) return sendBack(c, "invalid");
  const sess = await getSession(request, env, c);
  const t = now();
  if (!sess || sess.stage !== "started") return sendBack(c, "session");
  if (t - sess.created_at < c.minCheckpoint) return sendBack(c, "fast");

  const info = await checkWorkink(env, c, token);
  if (!info) return sendBack(c, "invalid");
  if (!c.linkId) {
    const seen = String(info.linkId ?? "");
    return sendBack(c, "setup", /^[\w-]{1,64}$/.test(seen) ? seen : "");
  }
  if (String(info.linkId) !== c.linkId) return sendBack(c, "invalid");
  const created = toMs(info.createdAt) / 1000;
  if (created < sess.created_at - 20 || t - created > SESSION_TTL) return sendBack(c, "invalid");
  if (c.ipCheck && info.byIp && !sameNetwork(info.byIp, ip)) return sendBack(c, "ip");

  const used = await sql(env, "INSERT OR IGNORE INTO used_tokens(token, used_at) VALUES(?, ?)", await sha256Hex(token), t).run();
  if (used.meta.changes !== 1) return sendBack(c, "used");
  const moved = await sql(
    env,
    "UPDATE sessions SET stage = 'verified', verified_at = ? WHERE sid = ? AND stage = 'started'",
    t, sess.sid
  ).run();
  if (moved.meta.changes !== 1) return sendBack(c, "session");
  ctx.waitUntil(dropWorkinkToken(c, token));
  return sendBack(c);
}

async function checkTurnstile(env, c, token, ip) {
  if (!env.TURNSTILE_SECRET) return false;
  try {
    const res = await fetch(c.turnstileUrl, {
      method: "POST",
      body: new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: token, remoteip: ip }),
      signal: AbortSignal.timeout(8000),
    });
    const out = await res.json();
    return Boolean(out && out.success && out.hostname === c.hostname);
  } catch {
    return false;
  }
}

async function apiCaptcha(request, env, c, ip) {
  if (await limited(env, "captcha", ip)) return reply({ error: "rate_limited" }, 429);
  const body = await readJson(request);
  if (body === null) return reply({ error: "bad_request" }, 413);
  const token = body.token;
  if (typeof token !== "string" || token.length < 1 || token.length > 2048) return reply({ error: "bad_request" }, 400);
  const sess = await getSession(request, env, c);
  if (!sess || sess.stage !== "verified") return reply({ error: "stage" }, 409);
  if (!(await checkTurnstile(env, c, token, ip))) return reply({ error: "captcha" }, 400);
  const moved = await sql(env, "UPDATE sessions SET stage = 'captcha' WHERE sid = ? AND stage = 'verified'", sess.sid).run();
  if (moved.meta.changes !== 1) return reply({ error: "stage" }, 409);
  return reply({ ok: true });
}

async function apiGenerate(request, env, c, ip) {
  if (await limited(env, "generate", ip)) return reply({ error: "rate_limited" }, 429);
  const sess = await getSession(request, env, c);
  const t = now();
  if (!sess || sess.stage !== "captcha" || t - (sess.verified_at || 0) > 900) return reply({ error: "stage" }, 409);
  const claimed = await sql(env, "UPDATE sessions SET stage = 'issuing' WHERE sid = ? AND stage = 'captcha'", sess.sid).run();
  if (claimed.meta.changes !== 1) return reply({ error: "stage" }, 409);

  const expiresAt = t + c.keySeconds;
  for (let attempt = 0; attempt < 3; attempt++) {
    const key = newKey();
    try {
      await env.DB.batch([
        sql(env, "DELETE FROM keys WHERE source = 'web' AND (device_id = ? OR net_id = ?)", sess.device_id, sess.net_id),
        sql(
          env,
          "INSERT INTO keys(key, source, created_at, expires_at, device_id, net_id) VALUES(?, 'web', ?, ?, ?, ?)",
          key, t, expiresAt, sess.device_id, sess.net_id
        ),
        sql(env, "UPDATE sessions SET stage = 'done' WHERE sid = ?", sess.sid),
      ]);
      return reply({ key, expires_at: expiresAt });
    } catch (err) {
      console.error("generate failed", err);
    }
  }
  return reply({ error: "server" }, 500);
}

async function validate(request, env, c) {
  const params = new URL(request.url).searchParams;
  const key = (params.get("key") || "").trim();
  const hwid = (params.get("hwid") || "").trim();
  if (!KEY_RE.test(key) || hwid.length > 256) return reply({ valid: false });

  let row = await sql(env, "SELECT * FROM keys WHERE key = ?", key).first();
  if (!row) return reply({ valid: false });
  if (row.expires_at !== null && now() > row.expires_at) return reply({ valid: false, reason: "expired" });

  if (!row.hwid && hwid) {
    await sql(env, "UPDATE keys SET hwid = ? WHERE key = ? AND hwid IS NULL", hwid, key).run();
    row = await sql(env, "SELECT * FROM keys WHERE key = ?", key).first();
  }
  if (row.hwid && hwid !== row.hwid) return reply({ valid: false, reason: "hwid_mismatch" });
  return reply({ valid: true, lifetime: row.expires_at === null, expires_at: row.expires_at || 0 });
}

const publicRow = (row) => ({
  key: row.key,
  source: row.source,
  created_by: row.created_by,
  created_at: row.created_at,
  expires_at: row.expires_at,
  hwid: row.hwid,
  redeemed_by: row.redeemed_by,
  redeemed_at: row.redeemed_at,
  last_reset: row.last_reset,
});

async function admin(request, env, c, ip, action) {
  const secret = String(env.BOT_API_SECRET || "");
  if (secret.length < 32) return reply({ error: "not_configured" }, 503);
  const supplied = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  const [a, b] = await Promise.all([sha256Bytes(supplied), sha256Bytes(secret)]);
  if (!crypto.subtle.timingSafeEqual(a, b)) {
    if (await limited(env, "adminfail", ip)) return reply({ error: "rate_limited" }, 429);
    return reply({ error: "unauthorized" }, 401);
  }
  const body = await readJson(request, action === "import" ? 600000 : 8192);
  if (body === null) return reply({ error: "too_large" }, 413);
  const t = now();

  if (action === "ping") return reply({ ok: true });

  if (action === "create") {
    const source = body.source;
    const seconds = body.seconds === null || body.seconds === undefined ? null : Number(body.seconds);
    const by = body.created_by === undefined || body.created_by === null ? null : String(body.created_by);
    if (source !== "prem" && source !== "free") return reply({ error: "bad_request" }, 400);
    if (seconds !== null && !(seconds >= 60 && seconds <= 315360000)) return reply({ error: "bad_request" }, 400);
    if (source === "free" && seconds === null) return reply({ error: "bad_request" }, 400);
    if (by !== null && !DIGITS_RE.test(by)) return reply({ error: "bad_request" }, 400);
    const expiresAt = seconds === null ? null : t + seconds;
    for (let attempt = 0; attempt < 3; attempt++) {
      const key = newKey();
      const made = await sql(
        env,
        "INSERT OR IGNORE INTO keys(key, source, created_by, created_at, expires_at) VALUES(?, ?, ?, ?, ?)",
        key, source, by, t, expiresAt
      ).run();
      if (made.meta.changes === 1) return reply({ key, expires_at: expiresAt });
    }
    return reply({ error: "server" }, 500);
  }

  if (action === "get" || action === "revoke") {
    const key = String(body.key || "").trim();
    if (!KEY_RE.test(key)) return reply({ found: false });
    if (action === "get") {
      const row = await sql(env, "SELECT * FROM keys WHERE key = ?", key).first();
      return reply(row ? { found: true, info: publicRow(row) } : { found: false });
    }
    const gone = await sql(env, "DELETE FROM keys WHERE key = ?", key).run();
    return reply({ deleted: gone.meta.changes > 0 });
  }

  if (action === "list") {
    const kind = ["all", "prem", "web", "free"].includes(body.kind) ? body.kind : "all";
    const live = "(expires_at IS NULL OR expires_at > ?)";
    const counts = { prem: 0, web: 0, free: 0 };
    const tally = await sql(env, `SELECT source, COUNT(*) AS n FROM keys WHERE ${live} GROUP BY source`, t).all();
    for (const row of tally.results) if (row.source in counts) counts[row.source] = row.n;
    const rows = kind === "all"
      ? await sql(env, `SELECT * FROM keys WHERE ${live} ORDER BY created_at DESC LIMIT 3000`, t).all()
      : await sql(env, `SELECT * FROM keys WHERE ${live} AND source = ? ORDER BY created_at DESC LIMIT 3000`, t, kind).all();
    return reply({ keys: rows.results.map(publicRow), counts });
  }

  if (action === "redeem") {
    const key = String(body.key || "").trim();
    const user = String(body.user_id || "");
    if (!KEY_RE.test(key) || !DIGITS_RE.test(user)) return reply({ status: "invalid" });
    const row = await sql(env, "SELECT * FROM keys WHERE key = ?", key).first();
    if (!row || (row.expires_at !== null && t > row.expires_at)) return reply({ status: "invalid" });
    if (row.redeemed_by && row.redeemed_by !== user) return reply({ status: "taken" });
    await sql(env, "UPDATE keys SET redeemed_by = ?, redeemed_at = ? WHERE key = ?", user, new Date().toISOString(), key).run();
    return reply({ status: "ok" });
  }

  if (action === "reset_hwid") {
    const user = String(body.user_id || "");
    if (!DIGITS_RE.test(user)) return reply({ status: "none" });
    const owned = (await sql(env, "SELECT key, hwid, last_reset FROM keys WHERE redeemed_by = ?", user).all()).results;
    if (!owned.length) return reply({ status: "none" });
    const bound = owned.filter((row) => row.hwid);
    const wait = Math.max(0, ...bound.map((row) => (row.last_reset || 0) + c.resetCooldown - t));
    if (wait > 0) return reply({ status: "cooldown", wait });
    if (bound.length) {
      await env.DB.batch(bound.map((row) => sql(env, "UPDATE keys SET hwid = NULL, last_reset = ? WHERE key = ?", t, row.key)));
    }
    return reply({ status: "ok" });
  }

  if (action === "import") {
    const list = Array.isArray(body.keys) ? body.keys.slice(0, 500) : [];
    const stmts = [];
    for (const k of list) {
      if (!k || !KEY_RE.test(String(k.key || ""))) continue;
      const source = ["prem", "web", "free"].includes(k.source) ? k.source : "prem";
      const expires = k.expires_at === null || k.expires_at === undefined ? null : Number(k.expires_at);
      const by = k.created_by === null || k.created_by === undefined ? null : String(k.created_by);
      const user = k.redeemed_by === null || k.redeemed_by === undefined ? null : String(k.redeemed_by);
      if ((by && !DIGITS_RE.test(by)) || (user && !DIGITS_RE.test(user))) continue;
      stmts.push(sql(
        env,
        "INSERT OR IGNORE INTO keys(key, source, created_by, created_at, expires_at, hwid, redeemed_by, redeemed_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
        String(k.key), source, by, Number(k.created_at) || t, Number.isFinite(expires) ? expires : null,
        k.hwid ? String(k.hwid).slice(0, 256) : null, user, k.redeemed_at ? String(k.redeemed_at).slice(0, 40) : null
      ));
    }
    if (stmts.length) await env.DB.batch(stmts);
    return reply({ imported: stmts.length });
  }

  return reply({ error: "not_found" }, 404);
}

async function route(request, env, ctx) {
  const c = settings(env);
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const open = path.startsWith("/admin/") || path === "/validate";

  if (url.host !== c.host && !open) {
    if (method === "GET" || method === "HEAD") return Response.redirect(c.siteUrl + path + url.search, 301);
    return reply({ error: "not_found" }, 404);
  }

  const ip = clientIp(request);

  if (method === "GET" || method === "HEAD") {
    if (path === "/" || path === "/index.html") return page(request, env);
    if (path === "/banner.webp") return banner(request, env);
    if (path === "/api/config") return reply({ sitekey: env.TURNSTILE_SITE_KEY || "", hours: c.keySeconds / 3600 });
    if (path === "/api/state") return apiState(request, env, c);
    if (path === "/callback") return callback(request, env, ctx, c, ip);
    if (path === "/validate") return validate(request, env, c);
  }

  if (method === "POST") {
    if (path.startsWith("/admin/")) return admin(request, env, c, ip, path.slice(7));
    const blocked = postGuard(request, c);
    if (blocked) return blocked;
    if (path === "/api/start") return apiStart(request, env, c, ip);
    if (path === "/api/captcha") return apiCaptcha(request, env, c, ip);
    if (path === "/api/generate") return apiGenerate(request, env, c, ip);
  }

  return reply({ error: "not_found" }, 404);
}

async function cleanup(env) {
  const t = now();
  await env.DB.batch([
    sql(env, "DELETE FROM keys WHERE source IN ('web', 'free') AND expires_at IS NOT NULL AND expires_at < ?", t - 3600),
    sql(env, "DELETE FROM sessions WHERE created_at < ?", t - 86400),
    sql(env, "DELETE FROM used_tokens WHERE used_at < ?", t - 7 * 86400),
    sql(env, "DELETE FROM rate WHERE exp < ?", t),
  ]);
}

export default {
  async fetch(request, env, ctx) {
    let c;
    try {
      c = settings(env);
      return secured(await route(request, env, ctx), c);
    } catch (err) {
      console.error(err);
      const fallback = reply({ error: "server" }, 500);
      return c ? secured(fallback, c) : fallback;
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(cleanup(env));
  },
};
