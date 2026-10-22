import { t, normalizeLang, SUPPORTED_LANGS } from "./i18n.js";
import { layout, renderLoginPage, renderNotFoundPage, statCard, barChart, esc, formatDate, formatNumber, icon } from "./admin-ui.js";

const BOT_VERSION = "1.0.0";
const SESSION_TTL = 86400000;
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCKOUT = 900000;
const REPORT_THRESHOLD = 5;
const BROADCAST_BATCH_SIZE = 40;
const BROADCAST_INITIAL_LIMIT = 40;
const MEDIA_CODE_LEN = 6;
const PROCESSING_LOCK_TTL = 300;
const MAX_CSRF_BODY_SIZE = 1000000;
const MAX_INLINE_TARGETS = 10;
const MAX_REPLY_LENGTH = 4000;
const TG_API_TIMEOUT = 1800;

const RATE_LIMITS = {
  whisper_hour: 30,
  peek_hour: 60,
  report_day: 10,
  reply_hour: 30,
  inline_sec: 10,
  webhook_ip_sec: 100,
  login_ip_hour: 20
};

const DEFAULT_SETTINGS = {
  force_start: "0", ads_enabled: "0", maintenance_mode: "0",
  ads_text: "", ads_url: "", ads_image_url: "",
  whisper_ttl_days: "7", max_whisper_length: "4000",
  require_start_for_reply: "1", announce_replies: "1",
  default_theme: "dark", language: "fa",
  auto_backup_enabled: "0", auto_backup_days: "7",
  log_retention_days: "30", commands_synced: "0",
  reply_keyboard_enabled: "0", max_reports_before_ban: "5",
  ban_duration_hours: "24", vip_rate_limit: "100",
  force_join_channels: "",
  vip_media_enabled: "0", vip_bypass_ads: "0", vip_bypass_forcejoin: "0",
  media_photo_enabled: "1", media_video_enabled: "1", media_document_enabled: "1",
  media_audio_enabled: "1", media_voice_enabled: "1", media_animation_enabled: "1", media_sticker_enabled: "1"
};

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' https: data:; connect-src 'self'; frame-ancestors 'none'",
  "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
};

const ALLOWED_TABLES = ["users", "admins", "web_admins", "whispers", "pending_whispers", "user_media", "peepers", "replies", "blocks", "reports", "settings", "user_settings", "admin_logs", "broadcasts", "processed_updates", "login_attempts", "sessions_log"];

let SCHEMA_CHECKED = false;

function b64urlEncode(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (str.length % 4)) % 4);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function classifyTargetToken(token) {
  if (typeof token !== "string" || token.length === 0) {
    return { valid: false, type: null, value: null };
  }
  if (token.startsWith("@")) {
    const username = token.slice(1);
    if (!/^[A-Za-z][A-Za-z0-9_]{4,31}$/.test(username)) {
      return { valid: false, type: null, value: null };
    }
    return { valid: true, type: "username", value: username };
  }
  if (!/^\d+$/.test(token)) {
    return { valid: false, type: null, value: null };
  }
  if (!/^[1-9]\d{4,14}$/.test(token)) {
    return { valid: false, type: null, value: null };
  }
  return { valid: true, type: "numeric_id", value: token };
}

function parseTargetsAndText(parts) {
  const arr = [...parts];
  const endTargets = [];
  while (arr.length > 0) {
    const last = arr[arr.length - 1];
    const res = classifyTargetToken(last);
    if (res.valid) { endTargets.unshift(last); arr.pop(); } else break;
  }
  const startTargets = [];
  while (arr.length > 0) {
    const first = arr[0];
    const res = classifyTargetToken(first);
    if (res.valid) { startTargets.push(first); arr.shift(); } else break;
  }
  return { targets: [...startTargets, ...endTargets], text: arr.join(" ").trim() };
}

async function ensureSchema(env) {
  if (SCHEMA_CHECKED) return;
  if (env.CACHE) {
    try {
      const cached = await env.CACHE.get("schema:checked_v14");
      if (cached === "1") { SCHEMA_CHECKED = true; return; }
    } catch (e) {}
  }
  let allOk = true;
  try {
    const info = await env.DB.prepare("PRAGMA table_info(users)").all();
    const columns = (info.results || []).map(c => c.name);
    if (!columns.includes("banned_until")) {
      try { await env.DB.prepare("ALTER TABLE users ADD COLUMN banned_until INTEGER DEFAULT 0").run(); }
      catch (e) { if (!/duplicate/i.test(e.message)) allOk = false; }
    }
    if (!columns.includes("is_vip")) {
      try { await env.DB.prepare("ALTER TABLE users ADD COLUMN is_vip INTEGER DEFAULT 0").run(); }
      catch (e) { if (!/duplicate/i.test(e.message)) allOk = false; }
    }
    if (!columns.includes("reports_count")) {
      try { await env.DB.prepare("ALTER TABLE users ADD COLUMN reports_count INTEGER DEFAULT 0").run(); }
      catch (e) { if (!/duplicate/i.test(e.message)) allOk = false; }
    }
    try {
      await env.DB.prepare("CREATE TABLE IF NOT EXISTS web_admins (username TEXT PRIMARY KEY, password_hash TEXT, created_at INTEGER DEFAULT (unixepoch()))").run();
      await env.DB.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)").run();
    } catch (e) { allOk = false; }

    try {
      const allSettings = { ...DEFAULT_SETTINGS };
      const currentSettings = await env.DB.prepare("SELECT key FROM settings").all();
      const currentKeys = (currentSettings.results || []).map(r => r.key);
      for (const [k, v] of Object.entries(allSettings)) {
        if (!currentKeys.includes(k)) {
          await env.DB.prepare("INSERT INTO settings (key, value) VALUES (?, ?)").bind(k, v).run();
        }
      }
    } catch (e) { console.error("Settings sync error:", e.message); }

    if (allOk) {
      SCHEMA_CHECKED = true;
      if (env.CACHE) await env.CACHE.put("schema:checked_v14", "1", { expirationTtl: 3600 });
    }
  } catch (e) {
    console.error("Schema check error:", e.message);
  }
}

function safeParseIds(str) {
  if (!str) return [];
  try {
    const parsed = JSON.parse(str);
    if (Array.isArray(parsed)) return parsed.map(String);
    if (typeof parsed === 'number' || typeof parsed === 'string') return [String(parsed)];
    return [];
  } catch (e) {
    if (typeof str === 'string' && str.includes(',')) return str.split(',').map(s => s.trim());
    return [String(str)];
  }
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      if (path === "/webhook" || path.startsWith("/admin")) {
        await ensureSchema(env);
      }
      if (path === "/webhook" && request.method === "POST") return await handleWebhook(request, env, ctx);
      if (path === "/" || path === "") return new Response(`Begobem v${BOT_VERSION}`, { headers: SECURITY_HEADERS });
      if (path === "/health") {
        return jsonResponse({ version: BOT_VERSION, db: await checkDatabase(env), queue: !!env.BROADCAST_QUEUE, cache: !!env.CACHE, ts: Date.now() });
      }
      if (path.startsWith("/admin")) return await handleAdminRoutes(request, env, url, ctx);
      return htmlResponse(renderNotFoundPage(), 404);
    } catch (err) {
      console.error("fetch error:", err.message, err.stack);
      return new Response("Internal Error", { status: 500, headers: SECURITY_HEADERS });
    }
  },

  async scheduled(event, env, ctx) {
    try {
      await ensureSchema(env);
      await runScheduledTasks(env);
    } catch (err) {
      console.error("scheduled error:", err.message, err.stack);
    }
  },

  async queue(batch, env) {
    const affectedBroadcasts = new Set();
    for (const msg of batch.messages) {
      try {
        const { chat_id, text, broadcast_id } = msg.body;
        const result = await tgApi(env, "sendMessage", { chat_id, text });
        if (result.ok) {
          await env.DB.prepare("UPDATE broadcasts SET recipients = recipients + 1, cursor_offset = cursor_offset + 1 WHERE id = ?").bind(broadcast_id).run();
          affectedBroadcasts.add(broadcast_id);
          msg.ack();
          continue;
        }
        const code = result.error_code;
        if (code === 429) {
          const retryAfter = result.parameters?.retry_after || 5;
          msg.retry({ delaySeconds: Math.min(retryAfter, 30) });
          continue;
        }
        if (code === 403 || code === 400) {
          await env.DB.prepare("UPDATE broadcasts SET cursor_offset = cursor_offset + 1 WHERE id = ?").bind(broadcast_id).run();
          affectedBroadcasts.add(broadcast_id);
          msg.ack();
          continue;
        }
        msg.retry({ delaySeconds: 10 });
      } catch (err) {
        console.error("queue error:", err.message);
        msg.retry({ delaySeconds: 15 });
      }
    }
    for (const broadcastId of affectedBroadcasts) {
      const status = await env.DB.prepare("SELECT cursor_offset, total_count, status FROM broadcasts WHERE id = ?").bind(broadcastId).first();
      if (status && status.cursor_offset >= status.total_count && status.status !== "done") {
        await env.DB.prepare("UPDATE broadcasts SET status = 'done' WHERE id = ?").bind(broadcastId).run();
      }
    }
  }
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...SECURITY_HEADERS }
  });
}

function htmlResponse(html, status = 200, extra = {}) {
  return new Response(html, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", ...SECURITY_HEADERS, ...extra }
  });
}

function redirect(location, extra = {}) {
  return new Response(null, { status: 302, headers: { Location: location, ...SECURITY_HEADERS, ...extra } });
}

async function checkDatabase(env) {
  try { await env.DB.prepare("SELECT 1").first(); return true; }
  catch { return false; }
}

function generateToken(len = 16) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(bytes, b => chars[b % chars.length]).join("");
}

function generateId() { return crypto.randomUUID(); }

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function hmacSign(secret, data) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function createSession(env, username, ip) {
  const csrf = generateToken(24);
  const jsonStr = JSON.stringify({ exp: Date.now() + SESSION_TTL, nonce: generateToken(12), csrf, ip, username });
  const payload = b64urlEncode(jsonStr);
  const sig = await hmacSign(env.SESSION_SECRET, payload);
  return { cookie: `${payload}.${sig}`, csrf, username };
}

async function verifySession(env, cookieValue, currentIp) {
  if (!cookieValue) return null;
  const parts = cookieValue.split(".");
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const expected = await hmacSign(env.SESSION_SECRET, payload);
  if (!safeEqual(sig, expected)) return null;
  try {
    const data = JSON.parse(b64urlDecode(payload));
    if (data.exp <= Date.now()) return null;
    const bindIp = env.BIND_SESSION_IP !== "0";
    if (bindIp && data.ip && data.ip !== "unknown" && currentIp !== "unknown" && data.ip !== currentIp) return null;
    return { csrf: data.csrf, nonce: data.nonce, ip: data.ip, username: data.username };
  } catch { return null; }
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const m = cookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return m ? m[1] : null;
}

function sessionCookieHeader(value, maxAge = 86400) {
  return `begobem_session=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

function clearSessionCookieHeader() {
  return "begobem_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0";
}

async function verifyCsrf(request, session, url) {
  if (!session) return false;
  if (url) {
    const csrfParam = url.searchParams.get("csrf");
    if (csrfParam) return safeEqual(csrfParam, session.csrf);
  }
  const header = request.headers.get("X-CSRF-Token");
  if (header) return safeEqual(header, session.csrf);
  const contentLength = parseInt(request.headers.get("content-length") || "0", 10);
  if (contentLength > MAX_CSRF_BODY_SIZE) return false;
  try {
    const form = await request.clone().formData();
    return safeEqual(String(form.get("csrf") || ""), session.csrf);
  } catch { return false; }
}

async function rateLimit(env, key, max, windowSec) {
  try {
    if (!env.CACHE) return true;
    const now = Math.floor(Date.now() / 1000);
    const bucket = `rl:${key}:${Math.floor(now / windowSec)}`;
    const cur = parseInt(await env.CACHE.get(bucket) || "0", 10);
    if (cur >= max) return false;
    await env.CACHE.put(bucket, String(cur + 1), { expirationTtl: windowSec });
    return true;
  } catch (e) { return false; }
}

async function checkLoginLockout(env, ip) {
  try {
    const row = await env.DB.prepare("SELECT attempts, locked_until FROM login_attempts WHERE ip = ?").bind(ip).first();
    if (!row) return { locked: false };
    if (row.locked_until && row.locked_until > Date.now()) {
      return { locked: true, remaining: Math.ceil((row.locked_until - Date.now()) / 1000) };
    }
  } catch (e) {}
  return { locked: false };
}

async function recordLoginFailure(env, ip) {
  try {
    const now = Date.now();
    const existing = await env.DB.prepare("SELECT attempts FROM login_attempts WHERE ip = ?").bind(ip).first();
    const attempts = (existing?.attempts || 0) + 1;
    const lockedUntil = attempts >= LOGIN_MAX_ATTEMPTS ? now + LOGIN_LOCKOUT : 0;
    await env.DB.prepare(
      `INSERT INTO login_attempts (ip, attempts, locked_until, updated_at) VALUES (?, ?, ?, ?)
       ON CONFLICT(ip) DO UPDATE SET attempts = ?, locked_until = ?, updated_at = ?`
    ).bind(ip, attempts, lockedUntil, now, attempts, lockedUntil, now).run();
  } catch (e) {}
}

async function clearLoginFailures(env, ip) {
  try { await env.DB.prepare("DELETE FROM login_attempts WHERE ip = ?").bind(ip).run(); } catch(e) {}
}

async function verifyAdminPassword(env, username, input) {
  if (username === "admin") {
    if (env.ADMIN_PASSWORD_HASH && env.ADMIN_PASSWORD_SALT) {
      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey("raw", enc.encode(input), "PBKDF2", false, ["deriveBits"]);
      const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: enc.encode(env.ADMIN_PASSWORD_SALT), iterations: 100000, hash: "SHA-256" }, key, 256);
      const hash = btoa(String.fromCharCode(...new Uint8Array(bits)));
      return safeEqual(hash, env.ADMIN_PASSWORD_HASH);
    }
    return safeEqual(input, env.ADMIN_PASSWORD || "");
  } else {
    try {
      const row = await env.DB.prepare("SELECT password_hash FROM web_admins WHERE username = ?").bind(username).first();
      if (!row) return false;
      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey("raw", enc.encode(input), "PBKDF2", false, ["deriveBits"]);
      const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: enc.encode(username), iterations: 100000, hash: "SHA-256" }, key, 256);
      const hash = btoa(String.fromCharCode(...new Uint8Array(bits)));
      return safeEqual(hash, row.password_hash);
    } catch (e) { return false; }
  }
}

async function isAdminUser(env, userId) {
  try {
    if (env.CACHE) {
      const cached = await env.CACHE.get(`admin:${userId}`);
      if (cached !== null) return cached === "1";
    }
    const row = await env.DB.prepare("SELECT 1 FROM admins WHERE user_id = ?").bind(userId).first();
    const isAdmin = !!row;
    if (env.CACHE) await env.CACHE.put(`admin:${userId}`, isAdmin ? "1" : "0", { expirationTtl: 60 });
    return isAdmin;
  } catch (e) { return false; }
}

async function invalidateAdminCache(env, userId) {
  if (env.CACHE) await env.CACHE.delete(`admin:${userId}`);
}

async function getSetting(env, key) {
  try {
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(key).first();
    return row?.value ?? DEFAULT_SETTINGS[key] ?? "";
  } catch (e) { return DEFAULT_SETTINGS[key] ?? ""; }
}

async function setSetting(env, key, value) {
  try {
    await env.DB.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(key, value, value).run();
    if (env.CACHE) await env.CACHE.delete("settings:all");
  } catch (e) {}
}

async function getAllSettings(env) {
  try {
    if (env.CACHE) {
      const cached = await env.CACHE.get("settings:all");
      if (cached) try { return { ...DEFAULT_SETTINGS, ...JSON.parse(cached) }; } catch {}
    }
    const rows = await env.DB.prepare("SELECT key, value FROM settings").all();
    const map = { ...DEFAULT_SETTINGS };
    for (const r of rows.results || []) map[r.key] = r.value;
    if (env.CACHE) await env.CACHE.put("settings:all", JSON.stringify(map), { expirationTtl: 300 });
    return map;
  } catch (e) { return DEFAULT_SETTINGS; }
}

async function getUserLang(env, userId) {
  try {
    if (env.CACHE) {
      const cached = await env.CACHE.get(`lang:${userId}`);
      if (cached) return normalizeLang(cached);
    }
    const row = await env.DB.prepare("SELECT lang FROM user_settings WHERE user_id = ?").bind(userId).first();
    const lang = row?.lang ? normalizeLang(row.lang) : normalizeLang(env.DEFAULT_LANG || "fa");
    if (env.CACHE) await env.CACHE.put(`lang:${userId}`, lang, { expirationTtl: 300 });
    return lang;
  } catch (e) { return normalizeLang(env.DEFAULT_LANG || "fa"); }
}

async function invalidateLangCache(env, userId) {
  if (env.CACHE) await env.CACHE.delete(`lang:${userId}`);
}

async function getDetailedStats(env) {
  try {
    if (env.CACHE) {
      const cached = await env.CACHE.get("stats:detailed");
      if (cached) try { return JSON.parse(cached); } catch {}
    }
    const now = Math.floor(Date.now() / 1000);
    const dayAgo = now - 86400;
    const todayStart = Math.floor(new Date().setHours(0, 0, 0, 0) / 1000);
    const weekAgo = now - 7 * 86400;
    const q = async (sql, ...args) => (await env.DB.prepare(sql).bind(...args).first())?.c || 0;
    const stats = {
      users: await q("SELECT COUNT(*) as c FROM users"),
      whispers: await q("SELECT COUNT(*) as c FROM whispers"),
      replies: await q("SELECT COUNT(*) as c FROM replies"),
      peepers: await q("SELECT COUNT(*) as c FROM peepers"),
      reports: await q("SELECT COUNT(*) as c FROM reports"),
      today: await q("SELECT COUNT(*) as c FROM whispers WHERE created_at >= ?", todayStart),
      active24: await q("SELECT COUNT(*) as c FROM users WHERE last_seen >= ?", dayAgo),
      active_week: await q("SELECT COUNT(*) as c FROM users WHERE last_seen >= ?", weekAgo),
      active_whispers: await q("SELECT COUNT(*) as c FROM whispers WHERE status = 'active'"),
      expired_whispers: await q("SELECT COUNT(*) as c FROM whispers WHERE status = 'expired'"),
      reported_whispers: await q("SELECT COUNT(*) as c FROM whispers WHERE status = 'reported'"),
      viewed: await q("SELECT COUNT(*) as c FROM whispers WHERE viewed_by != '[]'"),
      missing_inline_feedback: await q("SELECT COUNT(*) as c FROM whispers WHERE inline_message_id IS NULL AND created_at >= ?", dayAgo)
    };
    if (env.CACHE) await env.CACHE.put("stats:detailed", JSON.stringify(stats), { expirationTtl: 60 });
    return stats;
  } catch (e) {
    return { users: 0, whispers: 0, replies: 0, peepers: 0, reports: 0, today: 0, active24: 0, active_week: 0, active_whispers: 0, expired_whispers: 0, reported_whispers: 0, viewed: 0, missing_inline_feedback: 0 };
  }
}

async function invalidateStatsCache(env) {
  if (env.CACHE) await env.CACHE.delete("stats:detailed");
}

async function logAdminAction(env, actor, action, details) {
  let adminId = 0, ip = null;
  if (typeof actor === "number") adminId = actor;
  else if (actor && typeof actor === "object") ip = actor.ip || null;
  try {
    await env.DB.prepare("INSERT INTO admin_logs (admin_id, ip, action, details) VALUES (?, ?, ?, ?)")
      .bind(adminId, ip, action, details).run();
  } catch (e) {
    if (ip !== null) {
      try {
        await env.DB.prepare("INSERT INTO admin_logs (admin_id, action, details) VALUES (?, ?, ?)")
          .bind(adminId, action, `${ip} | ${details}`).run();
      } catch (e2) {}
    }
  }
}

async function handleAdminRoutes(request, env, url, ctx) {
  const path = url.pathname;
  const method = request.method;
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";

  if (path === "/admin/login" || path === "/admin/login/") {
    if (method === "GET") return htmlResponse(renderLoginPage("", BOT_VERSION));
    if (method === "POST") return await processLogin(request, env, ip);
    return new Response("Method Not Allowed", { status: 405, headers: SECURITY_HEADERS });
  }

  if (path === "/admin/logout") return redirect("/admin/login", { "Set-Cookie": clearSessionCookieHeader() });

  const session = await verifySession(env, getCookie(request, "begobem_session"), ip);

  if (path === "/admin" || path === "/admin/") return session ? redirect("/admin/dashboard") : redirect("/admin/login");
  if (!session) return redirect("/admin/login");

  if (method === "POST" && !await verifyCsrf(request, session, url)) {
    return htmlResponse(`<div class="alert alert-error">CSRF token mismatch</div>`, 403);
  }

  try {
    if (path === "/admin/dashboard") return await renderDashboard(env, session);
    if (path === "/admin/stats") return await renderStats(env, session);
    if (path === "/admin/users") {
      if (method === "GET") return await renderUsers(env, url, session);
      if (method === "POST") return await handleUsersPost(request, env, session);
    }
    if (path === "/admin/whispers") return await renderWhispers(env, url, session);
    if (path === "/admin/replies") return await renderReplies(env, url, session);
    if (path === "/admin/peepers") return await renderPeepers(env, url, session);
    if (path === "/admin/reports") return await renderReports(env, url, session);
    if (path === "/admin/blocks") return await renderBlocks(env, url, session);
    if (path === "/admin/media") {
      if (method === "GET") return await renderMedia(env, url, session);
      if (method === "POST") return await handleMediaPost(request, env, session);
    }
    if (path === "/admin/settings") {
      if (method === "GET") return await renderSettings(env, session);
      if (method === "POST") return await handleSettingsPost(request, env, session);
    }
    if (path === "/admin/ads") {
      if (method === "GET") return await renderAds(env, session, url);
      if (method === "POST") return await handleAdsPost(request, env, session);
    }
    if (path === "/admin/admins") {
      if (method === "GET") return await renderAdmins(env, url, session);
      if (method === "POST") return await handleAdminsPost(request, env, session);
    }
    if (path === "/admin/webhook") {
      if (method === "GET") return await renderWebhook(env, url, session);
      if (method === "POST") return await handleWebhookPost(request, env, url, session);
    }
    if (path === "/admin/broadcast") {
      if (method === "GET") return await renderBroadcast(env, session);
      if (method === "POST") return await handleBroadcastPost(request, env, ctx, session);
    }
    if (path === "/admin/logs") {
      if (method === "GET") return await renderLogs(env, url, session);
      if (method === "POST") return await handleLogsPost(request, env, session);
    }
    if (path === "/admin/logs/download") return await downloadLogs(env);
    if (path === "/admin/backup") {
      if (method === "GET") return await renderBackup(env, url, session);
      if (method === "POST") return await handleBackupPost(request, env, session, url);
    }
    if (path === "/admin/backup/download") return await downloadBackup(env, url);
    if (path === "/admin/cleanup") {
      if (method === "GET") return await renderCleanup(env, url, session);
      if (method === "POST") return await handleCleanupPost(request, env, session);
    }
    if (path === "/admin/transfer") {
      if (method === "GET") return await renderTransfer(env, url, session);
      if (method === "POST") return await handleTransferPost(request, env, session);
    }
    if (path === "/admin/sessions") return await renderSessions(env, session);
    return htmlResponse(renderNotFoundPage(), 404);
  } catch (err) {
    console.error("admin route error:", err.message, err.stack);
    return htmlResponse(`<div class="alert alert-error">خطا: ${esc(err.message)}</div>`, 500);
  }
}

async function processLogin(request, env, ip) {
  if (!await rateLimit(env, `login:${ip}`, RATE_LIMITS.login_ip_hour, 3600)) {
    return htmlResponse(renderLoginPage("تعداد تلاش ورود بیش از حد مجاز است.", BOT_VERSION));
  }
  const lockout = await checkLoginLockout(env, ip);
  if (lockout.locked) return htmlResponse(renderLoginPage(`دسترسی قفل است. ${lockout.remaining} ثانیه صبر کنید.`, BOT_VERSION));

  const form = await request.formData();
  const username = String(form.get("username") || "admin").trim();
  const password = String(form.get("password") || "");

  if (!await verifyAdminPassword(env, username, password)) {
    await recordLoginFailure(env, ip);
    return htmlResponse(renderLoginPage("نام کاربری یا رمز عبور اشتباه است.", BOT_VERSION));
  }
  await clearLoginFailures(env, ip);
  try {
    const ua = (request.headers.get("User-Agent") || "").slice(0, 200);
    await env.DB.prepare("INSERT INTO sessions_log (ip, user_agent) VALUES (?, ?)").bind(ip, ua).run();
  } catch (e) {}
  const session = await createSession(env, username, ip);
  return redirect("/admin/dashboard", { "Set-Cookie": sessionCookieHeader(session.cookie) });
}

async function handleUsersPost(request, env, session) {
  const form = await request.formData();
  const action = String(form.get("action") || "");
  const userId = parseInt(String(form.get("user_id") || ""), 10);
  if (isNaN(userId)) return redirect("/admin/users");

  if (action === "ban") {
    const bannedUntil = Math.floor(Date.now() / 1000) + (24 * 3600 * 365);
    await env.DB.prepare("UPDATE users SET banned_until = ?, reports_count = 0 WHERE user_id = ?").bind(bannedUntil, userId).run();
    await logAdminAction(env, session, "manual_ban", String(userId));
  } else if (action === "unban") {
    await env.DB.prepare("UPDATE users SET banned_until = 0, reports_count = 0 WHERE user_id = ?").bind(userId).run();
    await logAdminAction(env, session, "manual_unban", String(userId));
  } else if (action === "send_dm") {
    const message = String(form.get("message") || "").trim();
    if (message) {
      await tgApi(env, "sendMessage", { chat_id: userId, text: message });
      await logAdminAction(env, session, "manual_dm", `to:${userId}`);
    }
  }
  return redirect("/admin/users?saved=1");
}

async function handleSettingsPost(request, env, session) {
  const form = await request.formData();
  const action = String(form.get("action") || "");
  if (action === "toggle") {
    const key = String(form.get("key") || "");
    const allowed = [
      "force_start", "ads_enabled", "maintenance_mode", "require_start_for_reply",
      "announce_replies", "reply_keyboard_enabled", "vip_media_enabled",
      "vip_bypass_ads", "vip_bypass_forcejoin", "media_photo_enabled",
      "media_video_enabled", "media_document_enabled", "media_audio_enabled",
      "media_voice_enabled", "media_animation_enabled", "media_sticker_enabled"
    ];
    if (allowed.includes(key)) {
      const cur = await getSetting(env, key);
      await setSetting(env, key, cur === "1" ? "0" : "1");
    }
  } else if (action === "numeric") {
    const key = String(form.get("key") || "");
    const value = String(form.get("value") || "");
    const allowed = ["whisper_ttl_days", "max_whisper_length", "log_retention_days", "auto_backup_days", "max_reports_before_ban", "ban_duration_hours", "vip_rate_limit"];
    if (allowed.includes(key) && /^\d+$/.test(value) && parseInt(value, 10) >= 0) await setSetting(env, key, value);
  } else if (action === "lang") {
    const lang = String(form.get("lang") || "fa");
    if (SUPPORTED_LANGS.includes(lang)) await setSetting(env, "language", lang);
  } else if (action === "force_join") {
    const channels = String(form.get("force_join_channels") || "").trim();
    await setSetting(env, "force_join_channels", channels);
  }
  await logAdminAction(env, session, "settings_update", action);
  return redirect("/admin/settings?saved=1");
}

async function handleAdsPost(request, env, session) {
  const form = await request.formData();
  const adsText = String(form.get("ads_text") || "").slice(0, 200);
  const adsUrl = String(form.get("ads_url") || "").slice(0, 500);
  const adsImageUrl = String(form.get("ads_image_url") || "").slice(0, 500);
  const testImage = form.get("test_image") === "1";
  let error = "";
  if (adsImageUrl && !/^https:\/\//.test(adsImageUrl)) error = "URL تصویر باید https باشد.";
  else if (adsImageUrl && testImage) {
    const adminRow = await env.DB.prepare("SELECT user_id FROM admins ORDER BY added_at ASC LIMIT 1").first();
    if (adminRow) {
      const r = await tgApi(env, "sendPhoto", { chat_id: adminRow.user_id, photo: adsImageUrl, caption: "🧪 تست" });
      if (!r.ok) error = `تست ناموفق: ${r.description || ""}`;
    }
  }
  if (!error) {
    await setSetting(env, "ads_text", adsText);
    await setSetting(env, "ads_url", adsUrl);
    await setSetting(env, "ads_image_url", adsImageUrl);
  }
  await logAdminAction(env, session, "ads_update", error ? `error:${error}` : "ok");
  return redirect(`/admin/ads${error ? "?error=" + encodeURIComponent(error) : "?saved=1"}`);
}

async function handleAdminsPost(request, env, session) {
  const form = await request.formData();
  const action = String(form.get("action") || "");
  if (action === "add_tg") {
    const userId = parseInt(String(form.get("user_id") || ""), 10);
    if (!isNaN(userId) && userId > 0) {
      try {
        await env.DB.prepare("INSERT OR IGNORE INTO admins (user_id, added_at) VALUES (?, unixepoch())").bind(userId).run();
        await invalidateAdminCache(env, userId);
        await logAdminAction(env, session, "admin_add", String(userId));
      } catch (e) {}
    }
  } else if (action === "remove_tg") {
    const userId = parseInt(String(form.get("user_id") || ""), 10);
    if (!isNaN(userId)) {
      try {
        await env.DB.prepare("DELETE FROM admins WHERE user_id = ?").bind(userId).run();
        await invalidateAdminCache(env, userId);
        await logAdminAction(env, session, "admin_remove", String(userId));
      } catch (e) {}
    }
  } else if (action === "add_web") {
    const username = String(form.get("web_username") || "").trim();
    const password = String(form.get("web_password") || "").trim();
    if (username && username !== "admin" && password.length >= 4) {
      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
      const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: enc.encode(username), iterations: 100000, hash: "SHA-256" }, key, 256);
      const hash = btoa(String.fromCharCode(...new Uint8Array(bits)));
      await env.DB.prepare("INSERT OR REPLACE INTO web_admins (username, password_hash) VALUES (?, ?)").bind(username, hash).run();
      await logAdminAction(env, session, "web_admin_add", username);
    }
  } else if (action === "remove_web") {
    const username = String(form.get("web_username") || "").trim();
    if (username) {
      if (username === "admin") {
        return redirect("/admin/admins?error=" + encodeURIComponent("مدیر پیش‌فرض admin قابل حذف نیست"));
      }
      const count = await env.DB.prepare("SELECT COUNT(*) as c FROM web_admins").first();
      if ((count?.c || 0) <= 1) {
        return redirect("/admin/admins?error=" + encodeURIComponent("نمی‌توانید آخرین مدیر وب را حذف کنید"));
      }
      await env.DB.prepare("DELETE FROM web_admins WHERE username = ?").bind(username).run();
      await logAdminAction(env, session, "web_admin_remove", username);
    }
  }
  return redirect("/admin/admins?saved=1");
}

async function handleWebhookPost(request, env, url, session) {
  const form = await request.formData();
  const action = String(form.get("action") || "");
  if (action === "set") {
    const whPayload = {
      url: `${url.origin}/webhook`,
      allowed_updates: ["message", "callback_query", "inline_query", "chosen_inline_result"]
    };
    if (env.WEBHOOK_SECRET) whPayload.secret_token = env.WEBHOOK_SECRET;

    const r = await tgApi(env, "setWebhook", whPayload);
    if (r.ok) {
      await tgApi(env, "setMyCommands", {
        commands: [
          { command: "start", description: "شروع" },
          { command: "help", description: "راهنما" },
          { command: "upload", description: "ارسال مدیا" },
          { command: "my_media", description: "مدیریت مدیا" },
          { command: "najva", description: "ساخت نجوا در PV" },
          { command: "settings", description: "تنظیمات" },
          { command: "blocklist", description: "لیست بلاک" },
          { command: "my_stats", description: "آمار من" },
          { command: "privacy", description: "حریم خصوصی" },
          { command: "setvip", description: "ارتقا به VIP (فقط ادمین)" }
        ]
      });
      await setSetting(env, "commands_synced", "1");
    }
    await logAdminAction(env, session, "webhook_set", r.ok ? "ok" : `error:${r.description}`);
    return redirect(`/admin/webhook${r.ok ? "?saved=1" : "?error=" + encodeURIComponent(r.description || "")}`);
  }
  if (action === "delete") {
    await tgApi(env, "deleteWebhook", { drop_pending_updates: false });
    await logAdminAction(env, session, "webhook_delete", "ok");
    return redirect("/admin/webhook?saved=1");
  }
  if (action === "test_send") {
    const adminRow = await env.DB.prepare("SELECT user_id FROM admins ORDER BY added_at ASC LIMIT 1").first();
    if (adminRow) {
      const r = await tgApi(env, "sendMessage", { chat_id: adminRow.user_id, text: "🧪 پیام تست — اتصال برقرار است." });
      return redirect(`/admin/webhook${r.ok ? "?tested=1" : "?error=" + encodeURIComponent(r.description || "")}`);
    }
    return redirect("/admin/webhook?error=" + encodeURIComponent("مدیری تعریف نشده"));
  }
  return redirect("/admin/webhook");
}

async function handleLogsPost(request, env, session) {
  const form = await request.formData();
  const action = String(form.get("action") || "");
  if (action === "clear") {
    await env.DB.prepare("DELETE FROM admin_logs").run();
    await logAdminAction(env, session, "logs_clear", "all");
    return redirect("/admin/logs?deleted=1");
  }
  return redirect("/admin/logs");
}

async function downloadLogs(env) {
  const rows = await env.DB.prepare("SELECT * FROM admin_logs ORDER BY created_at DESC").all();
  const filename = `begobem-logs-${new Date().toISOString().slice(0, 10)}.json`;
  return new Response(JSON.stringify(rows.results || [], null, 2), {
    status: 200,
    headers: { "Content-Type": "application/json; charset=utf-8", "Content-Disposition": `attachment; filename="${filename}"`, ...SECURITY_HEADERS }
  });
}

async function handleBroadcastPost(request, env, ctx, session) {
  const form = await request.formData();
  const text = String(form.get("text") || "").trim();
  const scheduleAt = String(form.get("schedule_at") || "").trim();
  if (!text || text.length > 4000) return redirect("/admin/broadcast?error=" + encodeURIComponent("متن خالی یا طولانی"));

  const totalRow = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
  const total = totalRow?.c || 0;
  const broadcastId = generateId();
  const scheduledTime = scheduleAt ? Math.floor(new Date(scheduleAt).getTime() / 1000) : 0;

  await env.DB.prepare(
    `INSERT INTO broadcasts (id, text, sent_by, sent_at, recipients, status, cursor_offset, total_count)
     VALUES (?, ?, 0, unixepoch(), 0, ?, 0, ?)`
  ).bind(broadcastId, text, scheduledTime > 0 ? "scheduled" : "sending", total).run();

  if (!scheduledTime) {
    if (env.BROADCAST_QUEUE) ctx.waitUntil(enqueueBroadcast(env, broadcastId, text));
    else ctx.waitUntil(processBroadcastBatch(env, broadcastId, text, 0, BROADCAST_INITIAL_LIMIT));
  }

  await logAdminAction(env, session, "broadcast_start", `id:${broadcastId} total:${total}`);
  return redirect("/admin/broadcast?saved=1");
}

async function enqueueBroadcast(env, broadcastId, text) {
  try {
    const perPage = 500;
    let offset = 0;
    while (true) {
      const rows = await env.DB.prepare(`SELECT user_id FROM users ORDER BY user_id LIMIT ? OFFSET ?`).bind(perPage, offset).all();
      const list = rows.results || [];
      if (list.length === 0) break;
      for (let i = 0; i < list.length; i += 100) {
        const batch = list.slice(i, i + 100).map(u => ({
          body: { chat_id: u.user_id, text, broadcast_id: broadcastId },
          contentType: "json"
        }));
        await env.BROADCAST_QUEUE.sendBatch(batch);
      }
      offset += perPage;
      if (list.length < perPage) break;
    }
  } catch (err) {
    console.error("enqueueBroadcast error:", err.message);
    await env.DB.prepare("UPDATE broadcasts SET status = 'failed' WHERE id = ?").bind(broadcastId).run();
    throw err;
  }
}

async function processBroadcastBatch(env, broadcastId, text, startOffset, maxCount) {
  const rows = await env.DB.prepare(`SELECT user_id FROM users ORDER BY user_id LIMIT ? OFFSET ?`).bind(maxCount, startOffset).all();
  const list = rows.results || [];
  if (list.length === 0) {
    await env.DB.prepare("UPDATE broadcasts SET status = 'done' WHERE id = ?").bind(broadcastId).run();
    return;
  }
  let sent = 0;
  for (let i = 0; i < list.length; i += 10) {
    const batch = list.slice(i, i + 10);
    const results = await Promise.allSettled(batch.map(u => tgApi(env, "sendMessage", { chat_id: u.user_id, text })));
    for (const r of results) if (r.status === "fulfilled" && r.value.ok) sent++;
    if (i + 10 < list.length) await sleep(300);
  }
  await env.DB.prepare(
    "UPDATE broadcasts SET recipients = recipients + ?, cursor_offset = cursor_offset + ? WHERE id = ?"
  ).bind(sent, list.length, broadcastId).run();
  const b = await env.DB.prepare("SELECT cursor_offset, total_count FROM broadcasts WHERE id = ?").bind(broadcastId).first();
  if (b && b.cursor_offset >= b.total_count) {
    await env.DB.prepare("UPDATE broadcasts SET status = 'done' WHERE id = ?").bind(broadcastId).run();
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function handleBackupPost(request, env, session, url) {
  const form = await request.formData();
  const action = String(form.get("action") || "");

  if (action === "export") {
    const tables = form.getAll("tables").map(String).filter(t => ALLOWED_TABLES.includes(t));
    const params = new URLSearchParams();
    tables.forEach(t => params.append("t", t));
    await logAdminAction(env, session, "backup_export", `tables:${tables.length}`);
    return redirect(`/admin/backup/download?${params.toString()}`);
  }

  if (action === "import") {
    const file = form.get("backup_file");
    const mode = String(form.get("mode") || "merge");
    if (!file || typeof file === "string") return redirect("/admin/backup?error=" + encodeURIComponent("فایل ارسال نشد"));
    if (file.size > 50 * 1024 * 1024) return redirect("/admin/backup?error=" + encodeURIComponent("حجم فایل بیش از ۵۰ مگابایت"));

    try {
      const text = await file.text();
      const data = JSON.parse(text);
      if (!data.tables) throw new Error("ساختار فایل نامعتبر");

      if (mode === "replace") {
        const tablesToBackup = Object.keys(data.tables).filter(t => ALLOWED_TABLES.includes(t));
        const safety = await generateBackup(env, tablesToBackup);
        if (env.CACHE) {
          await env.CACHE.put(`safety_backup:${Date.now()}`, JSON.stringify(safety), { expirationTtl: 3600 });
        }
      }

      const result = await restoreBackup(env, data, mode);
      await logAdminAction(env, session, "backup_restore", `mode:${mode} result:${JSON.stringify(result)}`);
      if (env.CACHE) await env.CACHE.delete("settings:all");
      await invalidateStatsCache(env);
      const summary = encodeURIComponent(JSON.stringify(result));
      return redirect(`/admin/backup?restored=1&summary=${summary}`);
    } catch (err) {
      await logAdminAction(env, session, "backup_restore_failed", err.message);
      return redirect(`/admin/backup?error=${encodeURIComponent("خطا: " + err.message)}`);
    }
  }

  if (action === "auto_toggle") {
    const cur = await getSetting(env, "auto_backup_enabled");
    await setSetting(env, "auto_backup_enabled", cur === "1" ? "0" : "1");
    await logAdminAction(env, session, "auto_backup_toggle", cur === "1" ? "off" : "on");
    return redirect("/admin/backup?saved=1");
  }
  return redirect("/admin/backup");
}

async function downloadBackup(env, url) {
  const types = url.searchParams.getAll("t").filter(t => ALLOWED_TABLES.includes(t));
  const tables = types.length > 0 ? types : ALLOWED_TABLES.filter(t => t !== "login_attempts" && t !== "processed_updates" && t !== "sessions_log");
  const backup = await generateBackup(env, tables);
  const filename = `begobem-backup-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`;
  return new Response(JSON.stringify(backup, null, 2), {
    status: 200,
    headers: { "Content-Type": "application/json; charset=utf-8", "Content-Disposition": `attachment; filename="${filename}"`, "Cache-Control": "no-store", ...SECURITY_HEADERS }
  });
}

async function generateBackup(env, tables) {
  const data = { version: BOT_VERSION, exported_at: Math.floor(Date.now() / 1000), tables: {} };
  for (const table of tables) {
    if (!ALLOWED_TABLES.includes(table)) continue;
    try {
      const rows = await env.DB.prepare(`SELECT * FROM ${table}`).all();
      data.tables[table] = rows.results || [];
    } catch (err) {
      data.tables[table] = { error: err.message };
    }
  }
  return data;
}

async function restoreBackup(env, data, mode = "merge") {
  if (!data || !data.tables) throw new Error("ساختار نامعتبر");
  const result = {};
  for (const [table, rows] of Object.entries(data.tables)) {
    if (!ALLOWED_TABLES.includes(table)) continue;
    if (!Array.isArray(rows)) continue;
    if (rows.length === 0) { result[table] = { inserted: 0, failed: 0 }; continue; }

    const columns = Object.keys(rows[0]);
    if (columns.length === 0) { result[table] = { inserted: 0, failed: 0 }; continue; }
    if (!columns.every(c => /^[a-z_0-9]+$/.test(c))) { result[table] = { error: "invalid columns" }; continue; }

    if (mode === "replace") {
      try { await env.DB.prepare(`DELETE FROM ${table}`).run(); } catch {}
    }

    const placeholders = columns.map(() => "?").join(",");
    const colList = columns.join(",");
    const prefix = mode === "merge" ? "INSERT OR IGNORE" : "INSERT OR REPLACE";
    const stmt = `${prefix} INTO ${table} (${colList}) VALUES (${placeholders})`;
    let inserted = 0, failed = 0;

    for (let i = 0; i < rows.length; i += 25) {
      const batch = rows.slice(i, i + 25);
      const prepared = batch.map(row =>
        env.DB.prepare(stmt).bind(...columns.map(c => row[c] === undefined ? null : row[c]))
      );
      try {
        await env.DB.batch(prepared);
        inserted += prepared.length;
      } catch (batchErr) {
        console.error(`batch insert failed for ${table}:`, batchErr.message);
        failed += prepared.length;
      }
    }
    result[table] = { inserted, failed };
  }
  return result;
}

async function handleCleanupPost(request, env, session) {
  const form = await request.formData();
  const action = String(form.get("action") || "");
  const now = Math.floor(Date.now() / 1000);

  if (action === "full_cleanup") {
    const ttl = parseInt(await getSetting(env, "whisper_ttl_days") || "7", 10);
    const logRetention = parseInt(await getSetting(env, "log_retention_days") || "30", 10);
    const expired = await env.DB.prepare("SELECT id, inline_message_id FROM whispers WHERE status = 'active' AND created_at < ?").bind(now - ttl * 86400).all();
    await env.DB.prepare("UPDATE whispers SET status = 'expired' WHERE status = 'active' AND created_at < ?").bind(now - ttl * 86400).run();
    for (const w of (expired.results || [])) {
      if (w.inline_message_id) {
        await tgApi(env, "editMessageReplyMarkup", {
          inline_message_id: w.inline_message_id,
          reply_markup: { inline_keyboard: [[{ text: "⏳", callback_data: "expired" }]] }
        });
      }
    }
    await env.DB.prepare("DELETE FROM whispers WHERE created_at < ? AND status != 'active'").bind(now - 30 * 86400).run();
    await env.DB.prepare("DELETE FROM peepers WHERE peeked_at < ?").bind(now - 30 * 86400).run();
    await env.DB.prepare("DELETE FROM replies WHERE created_at < ?").bind(now - 30 * 86400).run();
    await env.DB.prepare("DELETE FROM processed_updates WHERE created_at < ?").bind(now - 7 * 86400).run();
    await env.DB.prepare("DELETE FROM pending_whispers WHERE created_at < unixepoch() - 3600").run();
    await env.DB.prepare(
      "DELETE FROM user_media WHERE created_at < ? AND code NOT IN (SELECT media_code FROM whispers WHERE status = 'active' AND media_code IS NOT NULL)"
    ).bind(now - 30 * 86400).run();
    await env.DB.prepare("DELETE FROM login_attempts WHERE updated_at < ? AND locked_until < ?").bind(Date.now() - 86400000, Date.now()).run();
    await env.DB.prepare("DELETE FROM admin_logs WHERE created_at < ?").bind(now - logRetention * 86400).run();
    await env.DB.prepare("DELETE FROM broadcasts WHERE status = 'done' AND sent_at < ?").bind(now - 30 * 86400).run();
    await env.DB.prepare("DELETE FROM sessions_log WHERE logged_in_at < ?").bind(now - logRetention * 86400).run();
    try { await env.DB.prepare("ANALYZE").run(); } catch {}
  } else if (action === "delete_old_whispers") {
    const days = parseInt(String(form.get("days") || "30"), 10);
    await env.DB.prepare("DELETE FROM whispers WHERE created_at < ? AND status != 'active'").bind(now - days * 86400).run();
  } else if (action === "delete_old_peepers") {
    const days = parseInt(String(form.get("days") || "30"), 10);
    await env.DB.prepare("DELETE FROM peepers WHERE peeked_at < ?").bind(now - days * 86400).run();
  } else if (action === "delete_old_replies") {
    const days = parseInt(String(form.get("days") || "30"), 10);
    await env.DB.prepare("DELETE FROM replies WHERE created_at < ?").bind(now - days * 86400).run();
  } else if (action === "delete_inactive_users") {
    const days = parseInt(String(form.get("days") || "180"), 10);
    await env.DB.prepare("DELETE FROM users WHERE last_seen < ?").bind(now - days * 86400).run();
  } else if (action === "delete_old_logs") {
    const days = parseInt(String(form.get("days") || "30"), 10);
    await env.DB.prepare("DELETE FROM admin_logs WHERE created_at < ?").bind(now - days * 86400).run();
  } else if (action === "delete_finished_broadcasts") {
    const days = parseInt(String(form.get("days") || "30"), 10);
    await env.DB.prepare("DELETE FROM broadcasts WHERE status = 'done' AND sent_at < ?").bind(now - days * 86400).run();
  } else if (action === "delete_pending") {
    await env.DB.prepare("DELETE FROM pending_whispers WHERE created_at < unixepoch() - 3600").run();
  } else if (action === "delete_processed") {
    await env.DB.prepare("DELETE FROM processed_updates WHERE created_at < ?").bind(now - 7 * 86400).run();
  } else if (action === "delete_login_attempts") {
    await env.DB.prepare("DELETE FROM login_attempts WHERE updated_at < ? AND locked_until < ?").bind(Date.now() - 86400000, Date.now()).run();
  } else if (action === "expire_whispers") {
    const ttl = parseInt(await getSetting(env, "whisper_ttl_days") || "7", 10);
    const expired = await env.DB.prepare("SELECT id, inline_message_id FROM whispers WHERE status = 'active' AND created_at < ?").bind(now - ttl * 86400).all();
    await env.DB.prepare("UPDATE whispers SET status = 'expired' WHERE status = 'active' AND created_at < ?").bind(now - ttl * 86400).run();
    for (const w of (expired.results || [])) {
      if (w.inline_message_id) {
        await tgApi(env, "editMessageReplyMarkup", {
          inline_message_id: w.inline_message_id,
          reply_markup: { inline_keyboard: [[{ text: "⏳", callback_data: "expired" }]] }
        });
      }
    }
  } else if (action === "optimize") {
    try { await env.DB.prepare("ANALYZE").run(); } catch {}
  }
  if (env.CACHE) await env.CACHE.delete("stats:detailed");
  await logAdminAction(env, session, "cleanup", action);
  return redirect("/admin/cleanup?saved=1");
}

async function handleTransferPost(request, env, session) {
  const form = await request.formData();
  const action = String(form.get("action") || "");
  const days = parseInt(String(form.get("days") || "30"), 10);
  const cutoff = Math.floor(Date.now() / 1000) - days * 86400;

  if (action === "archive_whispers") {
    const rows = await env.DB.prepare("SELECT * FROM whispers WHERE created_at < ? AND status != 'active' LIMIT 5000").bind(cutoff).all();
    const archive = { version: BOT_VERSION, type: "archive", archived_at: Math.floor(Date.now() / 1000), whispers: rows.results || [] };
    const filename = `begobem-archive-${new Date().toISOString().slice(0, 10)}.json`;
    await logAdminAction(env, session, "archive", `days:${days} count:${(rows.results || []).length}`);
    return new Response(JSON.stringify(archive, null, 2), {
      status: 200,
      headers: { "Content-Type": "application/json; charset=utf-8", "Content-Disposition": `attachment; filename="${filename}"`, ...SECURITY_HEADERS }
    });
  }
  if (action === "delete_archived") {
    await env.DB.prepare("DELETE FROM whispers WHERE created_at < ? AND status != 'active'").bind(cutoff).run();
    await logAdminAction(env, session, "archive_delete", `days:${days}`);
    return redirect("/admin/transfer?saved=1");
  }
  return redirect("/admin/transfer");
}

async function handleWebhook(request, env, ctx) {
  const secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token");
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  if (env.WEBHOOK_SECRET && !safeEqual(secret || "", env.WEBHOOK_SECRET)) return new Response("Unauthorized", { status: 401, headers: SECURITY_HEADERS });
  if (!await rateLimit(env, `wh:${ip}`, RATE_LIMITS.webhook_ip_sec, 1)) return new Response("Too Many Requests", { status: 429, headers: SECURITY_HEADERS });

  let update;
  try { update = await request.json(); }
  catch { return new Response("Bad Request", { status: 400, headers: SECURITY_HEADERS }); }

  let lockAcquired = false;
  if (update.update_id) {
    try {
      const res = await env.DB.prepare("INSERT OR IGNORE INTO processed_updates (update_id, status) VALUES (?, 'processing')").bind(update.update_id).run();
      if (res.meta.changes === 0) {
        const existing = await env.DB.prepare("SELECT status, created_at FROM processed_updates WHERE update_id = ?").bind(update.update_id).first();
        if (existing) {
          if (existing.status === "done") return new Response("OK", { status: 200, headers: SECURITY_HEADERS });
          const age = Math.floor(Date.now() / 1000) - (existing.created_at || 0);
          if (existing.status === "processing" && age < PROCESSING_LOCK_TTL) {
            return new Response("OK", { status: 200, headers: SECURITY_HEADERS });
          }
        }
      }
      lockAcquired = true;
    } catch (e) {
      console.error("lock error:", e.message);
      return new Response("Internal Server Error", { status: 500, headers: SECURITY_HEADERS });
    }
  }

  try {
    await routeUpdate(update, env, ctx);
    if (lockAcquired && update.update_id) {
      try { await env.DB.prepare("UPDATE processed_updates SET status = 'done' WHERE update_id = ?").bind(update.update_id).run(); } catch {}
    }
  } catch (err) {
    console.error("routeUpdate error:", err.message, err.stack);
    if (lockAcquired && update.update_id) {
      try { await env.DB.prepare("DELETE FROM processed_updates WHERE update_id = ? AND status = 'processing'").bind(update.update_id).run(); } catch {}
    }
    return new Response("Internal Server Error", { status: 500, headers: SECURITY_HEADERS });
  }

  return new Response("OK", { status: 200, headers: SECURITY_HEADERS });
}

async function routeUpdate(update, env, ctx) {
  const settings = await getAllSettings(env);
  const maintenance = settings.maintenance_mode === "1";

  const senderId = update.message?.from?.id || update.inline_query?.from?.id || update.callback_query?.from?.id || update.chosen_inline_result?.from?.id;
  let isAdminUpdate = false;
  if (senderId) {
    try { isAdminUpdate = await isAdminUser(env, senderId); }
    catch (e) {}
  }

  if (maintenance && !isAdminUpdate) {
    if (update.message) {
      const lang = await getUserLang(env, update.message.from.id);
      await tgApi(env, "sendMessage", { chat_id: update.message.chat.id, text: t(lang, "maintenance") });
    }
    if (update.inline_query) {
      const lang = await getUserLang(env, update.inline_query.from.id);
      return answerInlineError(env, update.inline_query.id, t(lang, "maintenance"));
    }
    return;
  }

  if (update.inline_query) return handleInlineQuery(update.inline_query, env, settings);
  if (update.chosen_inline_result) return handleChosenInlineResult(update.chosen_inline_result, env, settings);
  if (update.callback_query) return handleCallbackQuery(update.callback_query, env, settings);
  if (update.message) return handleMessage(update.message, env, settings, ctx);
}

async function resolveUsername(env, username) {
  if (!username) return null;
  try {
    const row = await env.DB.prepare("SELECT user_id FROM users WHERE username = ? COLLATE NOCASE").bind(username).first();
    return row?.user_id || null;
  } catch (e) { return null; }
}

async function handleInlineQuery(iq, env, settings) {
  const raw = (iq.query || "").trim();
  const lang = await getUserLang(env, iq.from.id);

  const userRow = await env.DB.prepare("SELECT * FROM users WHERE user_id = ?").bind(iq.from.id).first();
  const isVip = userRow?.is_vip === 1 || userRow?.is_vip === "1";
  const now = Math.floor(Date.now() / 1000);

  if (userRow?.banned_until && userRow.banned_until > now) {
    return answerInlineError(env, iq.id, t(lang, "user_banned", { date: formatDate(userRow.banned_until) }));
  }

  if (raw.startsWith("reply_")) {
    const parts = raw.split(/\s+/);
    const replyToken = parts[0].replace("reply_", "");
    const text = raw.substring(parts[0].length).trim();

    if (!text) {
      return answerInlineError(env, iq.id, "متن پاسخ را وارد کنید");
    }

    const whisper = await env.DB.prepare("SELECT * FROM whispers WHERE id = ?").bind(replyToken).first();
    if (!whisper || whisper.status !== "active") {
      return answerInlineError(env, iq.id, "پیام یافت نشد یا منقضی شده است");
    }

    const targetIds = safeParseIds(whisper.target_ids);
    const isRecipient = targetIds.map(String).includes(String(iq.from.id)) || (iq.from.username && targetIds.map(t => t.toLowerCase()).includes("@" + iq.from.username.toLowerCase()));
    const isSender = String(iq.from.id) === String(whisper.sender_id);

    if (!isRecipient && !isSender) {
      return answerInlineError(env, iq.id, "شما مجاز به پاسخ به این پیام نیستید");
    }

    const recipientId = isSender ? whisper.target_ids : whisper.sender_id;
    const token = generateToken(12);

    const targetStrings = [];
    const resolvedTargets = isSender ? safeParseIds(recipientId) : [String(whisper.sender_id)];
    
    for (const t of resolvedTargets) {
      let dbTarget = null;
      if (String(t).startsWith('@')) {
        dbTarget = await env.DB.prepare("SELECT user_id, username, first_name FROM users WHERE username = ? COLLATE NOCASE").bind(String(t).slice(1)).first();
      } else {
        dbTarget = await env.DB.prepare("SELECT user_id, username, first_name FROM users WHERE user_id = ?").bind(t).first();
      }
      const name = dbTarget?.first_name || "کاربر";
      const username = dbTarget?.username ? ` / @${dbTarget.username}` : (String(t).startsWith('@') ? ` / ${t}` : '');
      const id = dbTarget?.user_id || (String(t).startsWith('@') ? "نامشخص" : t);
      targetStrings.push(`${esc(name)} (${esc(id)}${esc(username)})`);
    }

    const targetsText = targetStrings.map(ts => `🎯 مقصد: ${ts}`).join('\n');
    const displayTargetStr = targetStrings.join(", ");

    await env.DB.prepare(
      `INSERT INTO pending_whispers (token, sender_id, target_ids, target_usernames, text, media_code, created_at)
       VALUES (?, ?, ?, ?, ?, ?, unixepoch())`
    ).bind(token, iq.from.id, JSON.stringify(resolvedTargets), displayTargetStr, text, null).run();

    const senderName = iq.from.first_name || 'ناشناس';
    const senderUsername = iq.from.username ? ` / @${iq.from.username}` : '';
    const senderStr = `${senderName} (${iq.from.id}${senderUsername})`;
    
    const cardText = `🔒 <b>پیام نجوا</b>\n\n👤 فرستنده: ${esc(senderStr)}\n${targetsText}\n\nبرای مشاهده روی دکمه زیر بزنید:`;

    const buttons = [
      [{ text: t(lang, "btn_view"), callback_data: `v:${token}`, style: "primary" }, { text: t(lang, "btn_peepers"), callback_data: `p:${token}`, style: "primary" }],
      [
        { text: t(lang, "btn_reply"), switch_inline_query_current_chat: `reply_${token} `, style: "success" },
        { text: t(lang, "btn_report"), callback_data: `g:${token}`, style: "danger" },
        { text: t(lang, "btn_delete"), callback_data: `d:${token}`, style: "danger" }
      ]
    ];

    return tgApi(env, "answerInlineQuery", {
      inline_query_id: iq.id, cache_time: 10, is_personal: true,
      results: [{
        type: "article", id: token, title: "🔒", description: displayTargetStr,
        input_message_content: { message_text: cardText, parse_mode: "HTML" },
        reply_markup: { inline_keyboard: buttons }
      }]
    });
  }

  if (settings.force_join_channels && !(isVip && settings.vip_bypass_forcejoin === "1")) {
    const channels = settings.force_join_channels.split(",").map(c => c.trim()).filter(Boolean);
    if (channels.length > 0) {
      let joinedAll = true;
      for (const channel of channels) {
        try {
          const res = await tgApi(env, "getChatMember", { chat_id: channel, user_id: iq.from.id });
          const isMember = res.ok && (["creator", "administrator", "member"].includes(res.result?.status) || (res.result?.status === "restricted" && res.result?.is_member));
          if (!isMember) {
            joinedAll = false;
            break;
          }
        } catch (e) {
          joinedAll = false;
          break;
        }
      }
      if (!joinedAll) {
        return tgApi(env, "answerInlineQuery", {
          inline_query_id: iq.id, cache_time: 0, is_personal: true,
          results: [{
            type: "article", id: "force_join",
            title: "⚠️ ابتدا عضو کانال شوید",
            description: "برای ارسال نجوا، لطفاً ابتدا در کانال‌های ما عضو شوید.",
            input_message_content: { message_text: "⚠️ برای ارسال نجوا ابتدا باید عضو کانال شوید." },
            reply_markup: {
              inline_keyboard: [[{ text: "📢 عضویت در کانال", url: channels[0].startsWith('@') ? `https://t.me/${channels[0].replace('@', '')}` : `https://t.me/${channels[0]}`, style: "primary" }]]
            }
          }]
        });
      }
    }
  }

  if (!await rateLimit(env, `inl:${iq.from.id}`, RATE_LIMITS.inline_sec, 1)) {
    return answerInlineError(env, iq.id, t(lang, "rate_limit"));
  }

  const parts = raw.split(/\s+/).filter(Boolean);

  if (parts.length === 0) {
    const recentSenders = await env.DB.prepare(`
      SELECT target_usernames as name FROM whispers WHERE sender_id = ? AND target_usernames IS NOT NULL
      UNION
      SELECT '@' || u.username as name FROM whispers w JOIN users u ON w.sender_id = u.user_id WHERE w.target_ids LIKE ?
      LIMIT 10
    `).bind(iq.from.id, `%${iq.from.id}%`).all();

    const helpResults = [
      {
        type: "article", id: "help1", title: "📝 آموزش ارسال نجوا",
        description: "برای ارسال پیام ناشناس، بنویسید: متن @آیدی",
        input_message_content: { message_text: `📝 @${env.BOT_USERNAME} متن @آیدی` }
      }
    ];

    for (const r of recentSenders.results || []) {
      if (r.name && r.name !== 'null' && r.name.trim() !== '') {
        helpResults.push({
          type: "article", id: "rec_" + generateToken(4), title: `✍️ ارسال به ${r.name}`,
          description: "برای ارسال پیام، متن خود را بعد از انتخاب بنویسید",
          input_message_content: { message_text: `@${env.BOT_USERNAME} متن ${r.name}` }
        });
      }
    }

    return tgApi(env, "answerInlineQuery", {
      inline_query_id: iq.id, cache_time: 0, is_personal: true,
      results: helpResults
    });
  }

  let mediaRef = null;
  let contentParts = parts;
  if (parts[0] && parts[0].match(/^#m_[a-zA-Z0-9]{6}$/)) {
    mediaRef = parts[0];
    contentParts = parts.slice(1);
  }

  const parsed = parseTargetsAndText(contentParts);
  const text = parsed.text;
  const targets = parsed.targets;

  if (targets.length === 0) return answerInlineError(env, iq.id, t(lang, "invalid_target"));
  if (targets.length > MAX_INLINE_TARGETS) return answerInlineError(env, iq.id, `حداکثر ${MAX_INLINE_TARGETS} گیرنده مجاز است.`);

  const maxLen = parseInt(settings.max_whisper_length || "4000", 10);
  if (!text && !mediaRef) return answerInlineError(env, iq.id, t(lang, "empty_text"));
  if (text.length > maxLen) return answerInlineError(env, iq.id, t(lang, "too_long", { max: maxLen }));

  const resolvedTargets = [];
  for (const tRaw of targets) {
    const res = classifyTargetToken(tRaw);
    if (!res.valid) continue;
    
    let tId = null;
    let tUser = null;

    if (res.type === "numeric_id") {
      tId = res.value;
    } else if (res.type === "username") {
      tUser = res.value;
      const resolved = await resolveUsername(env, tUser);
      if (resolved) tId = resolved;
    }

    if (tId) {
      if (String(tId) === String(iq.from.id)) return answerInlineError(env, iq.id, t(lang, "self_whisper"));
      resolvedTargets.push(tId);
    } else if (tUser) {
      if (tUser.toLowerCase() === (iq.from.username || "").toLowerCase()) return answerInlineError(env, iq.id, t(lang, "self_whisper"));
      resolvedTargets.push(`@${tUser}`);
    }
  }

  if (resolvedTargets.length === 0) return answerInlineError(env, iq.id, t(lang, "invalid_target"));

  if (settings.force_start === "1" && !isVip) {
    const started = await env.DB.prepare("SELECT started_at FROM users WHERE user_id = ?").bind(iq.from.id).first();
    if (!started || !started.started_at) return answerInlineError(env, iq.id, t(lang, "need_start", { bot: env.BOT_USERNAME }));
  }

  for (const targetId of resolvedTargets) {
    if (String(targetId).startsWith("@")) continue;
    const blocked = await env.DB.prepare("SELECT 1 FROM blocks WHERE user_id = ? AND blocked_id = ?").bind(targetId, iq.from.id).first();
    if (blocked) return answerInlineError(env, iq.id, t(lang, "blocked_by_recipient"));
  }

  const hourAgo = now - 3600;
  const recent = await env.DB.prepare("SELECT COUNT(*) as c FROM whispers WHERE sender_id = ? AND created_at > ?").bind(iq.from.id, hourAgo).first();
  const limit = isVip ? parseInt(settings.vip_rate_limit || "100", 10) : RATE_LIMITS.whisper_hour;

  if ((recent?.c || 0) >= limit) return answerInlineError(env, iq.id, t(lang, "rate_limit"));

  let mediaData = null;
  if (mediaRef) {
    if (isVip && settings.vip_media_enabled === "0") {
      return answerInlineError(env, iq.id, "ارسال نجوای مدیا در حال حاضر برای VIP غیرفعال است.");
    }
    mediaData = await env.DB.prepare("SELECT * FROM user_media WHERE code = ? AND user_id = ?").bind(mediaRef, iq.from.id).first();
    if (!mediaData) return answerInlineError(env, iq.id, t(lang, "media_not_found"));
    if (settings[`media_${mediaData.media_type}_enabled`] === "0") {
      return answerInlineError(env, iq.id, "ارسال این نوع مدیا در حال حاضر غیرفعال است.");
    }
  }

  const token = generateToken(12);
  
  const senderName = iq.from.first_name || 'ناشناس';
  const senderUsername = iq.from.username ? ` / @${iq.from.username}` : '';
  const senderStr = `${senderName} (${iq.from.id}${senderUsername})`;

  const targetStrings = [];
  for (const t of resolvedTargets) {
      let dbTarget = null;
      if (String(t).startsWith('@')) {
          dbTarget = await env.DB.prepare("SELECT user_id, username, first_name FROM users WHERE username = ? COLLATE NOCASE").bind(String(t).slice(1)).first();
      } else {
          dbTarget = await env.DB.prepare("SELECT user_id, username, first_name FROM users WHERE user_id = ?").bind(t).first();
      }
      const name = dbTarget?.first_name || "کاربر";
      const username = dbTarget?.username ? ` / @${dbTarget.username}` : (String(t).startsWith('@') ? ` / ${t}` : '');
      const id = dbTarget?.user_id || (String(t).startsWith('@') ? "نامشخص" : t);
      targetStrings.push(`${esc(name)} (${esc(id)}${esc(username)})`);
  }
  const targetsText = targetStrings.map(ts => `🎯 مقصد: ${ts}`).join('\n');
  const displayTargetStr = targetStrings.join(", ");

  await env.DB.prepare(
    `INSERT INTO pending_whispers (token, sender_id, target_ids, target_usernames, text, media_code, created_at)
     VALUES (?, ?, ?, ?, ?, ?, unixepoch())`
  ).bind(token, iq.from.id, JSON.stringify(resolvedTargets), displayTargetStr, text || "", mediaRef).run();

  const vipBadge = isVip ? " ⭐️" : "";
  const cardText = `🔒 <b>پیام نجوا</b>${vipBadge}\n\n👤 فرستنده: ${esc(senderStr)}\n${targetsText}\n\nبرای مشاهده روی دکمه زیر بزنید:`;

  const buttons = [
    [{ text: t(lang, "btn_view"), callback_data: `v:${token}`, style: "primary" }, { text: t(lang, "btn_peepers"), callback_data: `p:${token}`, style: "primary" }],
    [
      { text: t(lang, "btn_reply"), switch_inline_query_current_chat: `reply_${token} `, style: "success" },
      { text: t(lang, "btn_report"), callback_data: `g:${token}`, style: "danger" },
      { text: t(lang, "btn_delete"), callback_data: `d:${token}`, style: "danger" }
    ]
  ];

  const showAds = settings.ads_enabled === "1" && settings.ads_text && settings.ads_url && !(isVip && settings.vip_bypass_ads === "1");
  if (showAds) {
    buttons.push([{ text: settings.ads_text.slice(0, 64), url: settings.ads_url, style: "primary" }]);
  }

  const useAdsImage = showAds && settings.ads_image_url && /^https:\/\//.test(settings.ads_image_url);
  let result;

  if (useAdsImage) {
    result = { type: "photo", id: token, photo_url: settings.ads_image_url, thumbnail_url: settings.ads_image_url, caption: cardText, parse_mode: "HTML", reply_markup: { inline_keyboard: buttons } };
  } else {
    result = { type: "article", id: token, title: "🔒", description: displayTargetStr, input_message_content: { message_text: cardText, parse_mode: "HTML" }, reply_markup: { inline_keyboard: buttons } };
  }

  return tgApi(env, "answerInlineQuery", {
    inline_query_id: iq.id, cache_time: 10, is_personal: true,
    results: [result]
  });
}

async function answerInlineError(env, iqId, message) {
  return tgApi(env, "answerInlineQuery", {
    inline_query_id: iqId, cache_time: 0, is_personal: true,
    results: [],
    switch_pm_text: message.slice(0, 64),
    switch_pm_parameter: "help"
  });
}

async function handleChosenInlineResult(chosen, env, settings) {
  const token = chosen.result_id;
  if (!token) return;
  const pending = await env.DB.prepare("SELECT * FROM pending_whispers WHERE token = ?").bind(token).first();
  if (!pending) return;
  
  if (String(pending.sender_id) !== String(chosen.from.id)) {
    return;
  }

  const res = await env.DB.prepare(
    `INSERT OR IGNORE INTO whispers (id, sender_id, target_ids, target_usernames, text, media_code, inline_message_id, created_at, viewed_by, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, unixepoch(), '[]', 'active')`
  ).bind(token, pending.sender_id, pending.target_ids, pending.target_usernames, pending.text, pending.media_code, chosen.inline_message_id || null).run();

  if (res.meta.changes > 0) {
    await env.DB.prepare("DELETE FROM pending_whispers WHERE token = ?").bind(token).run();
  }

  await upsertUser(env, chosen.from);
  await invalidateStatsCache(env);
}

async function handleCallbackQuery(cq, env, settings) {
  const userId = cq.from.id;
  const lang = await getUserLang(env, userId);
  const chatId = cq.message?.chat?.id || cq.from.id;

  const answer = (text, alert) => tgApi(env, "answerCallbackQuery", {
    callback_query_id: cq.id, text, show_alert: !!alert
  });
  const answerUrl = (url) => tgApi(env, "answerCallbackQuery", {
    callback_query_id: cq.id, url
  });

  try {
    const data = cq.data || "";
    const parts = data.split(":");
    const action = parts[0];

    if (action === "none" || action === "expired") return answer();

    if (action === "delmedia") {
      const code = parts[1];
      const inUse = await env.DB.prepare("SELECT 1 FROM whispers WHERE media_code = ? AND status = 'active'").bind(code).first();
      if (inUse) return answer("این مدیا در یک نجوای فعال استفاده می‌شود و قابل حذف نیست.", true);
      await env.DB.prepare("DELETE FROM user_media WHERE code = ? AND user_id = ?").bind(code, userId).run();
      return answer(t(lang, "media_deleted"), true);
    }

    if (action === "adm") {
      if (!await isAdminUser(env, userId)) return answer(t(lang, "not_admin"), true);
      return handleAdminCallback(cq, env, parts.slice(1).join(":"), answer, lang, chatId);
    }

    if (action === "usr") return handleUserCallback(cq, env, parts.slice(1).join(":"), answer, lang, chatId);

    if (action === "pp") {
      return handlePeepersPagination(env, cq, parts[1], parseInt(parts[2], 10) || 1, lang, answer);
    }

    const token = parts[1];
    if (!token) return answer();

    const whisper = await env.DB.prepare("SELECT * FROM whispers WHERE id = ?").bind(token).first();
    if (!whisper) return answer(t(lang, "not_found"), true);

    if (whisper.status === "deleted") return answer(t(lang, "deleted"), true);
    if (whisper.status === "expired") return answer(t(lang, "expired"), true);
    if (whisper.status === "reported") return answer(t(lang, "reported"), true);

    const ttl = parseInt(settings.whisper_ttl_days || "7", 10);
    const now = Math.floor(Date.now() / 1000);
    if (whisper.status === "active" && whisper.created_at < now - ttl * 86400) {
      await env.DB.prepare("UPDATE whispers SET status = 'expired' WHERE id = ?").bind(token).run();
      return answer(t(lang, "expired"), true);
    }

    const targetIds = safeParseIds(whisper.target_ids);
    const isSender = String(userId) === String(whisper.sender_id);
    let isRecipient = targetIds.map(String).includes(String(userId));

    if (!isRecipient && cq.from.username) {
      if (targetIds.map(t => t.toLowerCase()).includes("@" + cq.from.username.toLowerCase())) {
        isRecipient = true;
        targetIds.push(String(userId));
        await env.DB.prepare("UPDATE whispers SET target_ids = ? WHERE id = ?").bind(JSON.stringify(targetIds), token).run();
      }
    }

    if (action === "v") {
      if (isSender || isRecipient) {
        if (isRecipient) {
          const userRow = await env.DB.prepare("SELECT started_at, is_vip FROM users WHERE user_id = ?").bind(userId).first();
          const isVip = userRow?.is_vip === 1 || userRow?.is_vip === "1";
          
          if (!userRow || !userRow.started_at) {
            return tgApi(env, "answerCallbackQuery", {
              callback_query_id: cq.id,
              text: "⚠️ برای مشاهده این نجوا، ابتدا باید ربات را استارت کنید.",
              show_alert: true,
              url: `https://t.me/${env.BOT_USERNAME}?start=view_${token}`
            });
          }

          if (settings.force_join_channels && !(isVip && settings.vip_bypass_forcejoin === "1")) {
            const channels = settings.force_join_channels.split(",").map(c => c.trim()).filter(Boolean);
            let joinedAll = true;
            for (const channel of channels) {
              try {
                const res = await tgApi(env, "getChatMember", { chat_id: channel, user_id: userId });
                const isMember = res.ok && (["creator", "administrator", "member"].includes(res.result?.status) || (res.result?.status === "restricted" && res.result?.is_member));
                if (!isMember) { joinedAll = false; break; }
              } catch(e) { joinedAll = false; break; }
            }
            if (!joinedAll) {
              return tgApi(env, "answerCallbackQuery", {
                callback_query_id: cq.id,
                text: "⚠️ برای مشاهده نجوا، ابتدا باید در کانال‌های ما عضو شوید.",
                show_alert: true,
                url: `https://t.me/${channels[0].replace('@', '')}`
              });
            }
          }

          let viewedBy = safeParseIds(whisper.viewed_by);
          if (!viewedBy.map(String).includes(String(userId))) {
            viewedBy.push(String(userId));
            await env.DB.prepare("UPDATE whispers SET viewed_by = ? WHERE id = ?").bind(JSON.stringify(viewedBy), token).run();
            if (whisper.inline_message_id) {
              const buttons = [
                [{ text: t(lang, "btn_viewed"), callback_data: `v:${token}`, style: "primary" }, { text: t(lang, "btn_peepers"), callback_data: `p:${token}`, style: "primary" }],
                [
                  { text: t(lang, "btn_reply"), switch_inline_query_current_chat: `reply_${token} `, style: "success" },
                  { text: t(lang, "btn_report"), callback_data: `g:${token}`, style: "danger" },
                  { text: t(lang, "btn_delete"), callback_data: `d:${token}`, style: "danger" }
                ]
              ];
              const showAds = settings.ads_enabled === "1" && settings.ads_text && settings.ads_url && !(isVip && settings.vip_bypass_ads === "1");
              if (showAds) {
                buttons.push([{ text: settings.ads_text.slice(0, 64), url: settings.ads_url, style: "primary" }]);
              }
              await tgApi(env, "editMessageReplyMarkup", {
                inline_message_id: whisper.inline_message_id,
                reply_markup: { inline_keyboard: buttons }
              });
            }
          }
        }
        if (whisper.media_code) {
          const media = await env.DB.prepare("SELECT * FROM user_media WHERE code = ?").bind(whisper.media_code).first();
          if (media) {
            const map = { photo: "sendPhoto", video: "sendVideo", document: "sendDocument", audio: "sendAudio", voice: "sendVoice", animation: "sendAnimation", sticker: "sendSticker" };
            const keyMap = { photo: "photo", video: "video", document: "document", audio: "audio", voice: "voice", animation: "animation", sticker: "sticker" };
            const method = map[media.media_type];
            if (method) {
              const payload = { chat_id: userId };
              payload[keyMap[media.media_type]] = media.file_id;
              if (media.media_type !== "sticker") {
                payload.caption = whisper.text ? t(lang, "view_content", { content: esc(whisper.text) }) : t(lang, "view_content_media");
                payload.parse_mode = "HTML";
              }
              payload.reply_markup = { inline_keyboard: [[{ text: t(lang, "btn_reply"), switch_inline_query_current_chat: `reply_${token} `, style: "success" }]] };
              const res = await tgApi(env, method, payload);
              if (res.ok) {
                return answer(t(lang, "media_sent_pm"), true);
              } else {
                return answer(t(lang, "media_pm_failed"), true);
              }
            }
          }
        }
        const text = whisper.text || "";
        if (text.length <= 200) return answer(text, true);
        return answerUrl(`https://t.me/${env.BOT_USERNAME}?start=view_${token}`);
      }
      if (!await rateLimit(env, `pk:${userId}`, RATE_LIMITS.peek_hour, 3600)) return answer(t(lang, "rate_limit"), true);
      await recordPeeper(env, token, cq.from);
      return answer(t(lang, "not_yours"), true);
    }

    if (action === "p") {
      if (!isSender && !isRecipient) {
        await recordPeeper(env, token, cq.from);
        return answer(t(lang, "only_parties"), true);
      }
      const peepers = await env.DB.prepare("SELECT user_id, first_name, username, peeked_at FROM peepers WHERE whisper_id = ? ORDER BY peeked_at DESC").bind(token).all();
      const list = peepers.results || [];
      if (list.length === 0) return answer("🎉 هیچ‌کس تلاش نکرد این پیام را ببینید.", true);

      let text = `🕵 لیست مشاهده‌کنندگان (${list.length}):\n\n`;
      const maxAlert = 5;
      const displayList = list.slice(0, maxAlert);
      displayList.forEach((p, i) => {
        text += `${i+1}. ${p.first_name || "کاربر"} ${p.username ? `(@${p.username})` : ""}\n`;
      });
      if (list.length > maxAlert) {
        text += `\nو ${list.length - maxAlert} نفر دیگر...`;
        const fullText = `🕵 <b>لیست کامل مشاهده‌کنندگان:</b>\n\n` + list.map((r, i) => `${i+1}. ${r.username ? "@" + esc(r.username) : "کاربر " + r.user_id}`).join("\n");
        await tgApi(env, "sendMessage", { chat_id: userId, text: fullText, parse_mode: "HTML" });
      }
      return answer(text, true);
    }

    if (action === "r") {
      if (!isSender && !isRecipient) {
        await recordPeeper(env, token, cq.from);
        return answer(t(lang, "only_parties"), true);
      }
      if (isSender) {
        return answer("شما نمی‌توانید به پیام خودتان پاسخ دهید.", true);
      }
      if (settings.require_start_for_reply === "1") {
        const started = await env.DB.prepare("SELECT started_at FROM users WHERE user_id = ?").bind(userId).first();
        if (!started || !started.started_at) return answer(t(lang, "need_start", { bot: env.BOT_USERNAME }), true);
      }

      await sendReplyForceReply(env, userId, token, whisper, lang);
      return answer("📨 به PV ربات مراجعه کنید و پاسخ خود را بنویسید.", true);
    }

    if (action === "g") {
      if (isSender) return answer(t(lang, "cant_report_own"), true);
      if (!isRecipient) return answer(t(lang, "not_yours"), true);
      const existing = await env.DB.prepare("SELECT 1 FROM reports WHERE whisper_id = ? AND reporter_id = ?").bind(token, userId).first();
      if (existing) return answer(t(lang, "report_dup"), true);
      if (!await rateLimit(env, `rp:${userId}`, RATE_LIMITS.report_day, 86400)) return answer(t(lang, "rate_limit"), true);

      await env.DB.prepare("INSERT INTO reports (id, whisper_id, reporter_id, reason, created_at) VALUES (?, ?, ?, ?, unixepoch())").bind(generateId(), token, userId, "user_report").run();

      await env.DB.prepare("UPDATE users SET reports_count = reports_count + 1 WHERE user_id = ?").bind(whisper.sender_id).run();

      const senderLang = await getUserLang(env, whisper.sender_id);
      await tgApi(env, "sendMessage", {
        chat_id: whisper.sender_id,
        text: t(senderLang, "warning_sent"),
        parse_mode: "HTML"
      });

      const senderRow = await env.DB.prepare("SELECT reports_count, is_vip, banned_until FROM users WHERE user_id = ?").bind(whisper.sender_id).first();
      const maxReports = parseInt(settings.max_reports_before_ban || "5", 10);

      if (senderRow && senderRow.reports_count >= maxReports && senderRow.is_vip !== 1) {
        const banHours = parseInt(settings.ban_duration_hours || "24", 10);
        const bannedUntil = Math.floor(Date.now() / 1000) + (banHours * 3600);
        await env.DB.prepare("UPDATE users SET banned_until = ?, reports_count = 0 WHERE user_id = ?").bind(bannedUntil, whisper.sender_id).run();
        await tgApi(env, "sendMessage", {
          chat_id: whisper.sender_id,
          text: t(senderLang, "user_banned_auto", { hours: banHours }),
          parse_mode: "HTML"
        });
      }

      const countRow = await env.DB.prepare("SELECT COUNT(*) as c FROM reports WHERE whisper_id = ?").bind(token).first();
      if ((countRow?.c || 0) >= REPORT_THRESHOLD) {
        await env.DB.prepare("UPDATE whispers SET status = 'reported' WHERE id = ?").bind(token).run();
        await deactivateCard(env, whisper, t(lang, "btn_reported"));
      }
      return answer(t(lang, "report_ok"), true);
    }

    if (action === "d") {
      if (!isSender) return answer(t(lang, "only_sender_delete"), true);
      await env.DB.prepare("UPDATE whispers SET status = 'deleted' WHERE id = ?").bind(token).run();
      const cardUpdated = await deactivateCard(env, whisper, t(lang, "btn_deleted"));
      if (whisper.inline_message_id && !cardUpdated) {
        return answer(t(lang, "delete_ok") + " (کارت در گروه باقی می‌ماند)", true);
      }
      return answer(t(lang, "delete_ok"), true);
    }

    return answer();
  } catch (err) {
    console.error("handleCallbackQuery error:", err.message, err.stack);
    try { await answer("خطا در پردازش", true); } catch {}
  }
}

async function deactivateCard(env, whisper, text) {
  if (!whisper.inline_message_id) return false;
  const r = await tgApi(env, "editMessageReplyMarkup", {
    inline_message_id: whisper.inline_message_id,
    reply_markup: { inline_keyboard: [[{ text, callback_data: "expired", style: "danger" }]] }
  });
  return r.ok;
}

async function handlePeepersPagination(env, cq, token, page, lang, answer) {
  const safeAnswer = answer || (() => Promise.resolve({ ok: true }));
  const whisper = await env.DB.prepare("SELECT * FROM whispers WHERE id = ?").bind(token).first();
  if (!whisper) return safeAnswer(t(lang, "not_found"), true);

  if (whisper.status === "deleted") return safeAnswer(t(lang, "deleted"), true);
  if (whisper.status === "expired") return safeAnswer(t(lang, "expired"), true);
  if (whisper.status === "reported") return safeAnswer(t(lang, "reported"), true);

  const userId = cq.from.id;
  const targetIds = safeParseIds(whisper.target_ids);
  const isSender = String(userId) === String(whisper.sender_id);
  const isRecipient = targetIds.map(String).includes(String(userId));

  if (!isSender && !isRecipient) return safeAnswer(t(lang, "only_parties"), true);

  const perPage = 10;
  const offset = (page - 1) * perPage;
  const rows = await env.DB.prepare(
    "SELECT user_id, username, first_name, peeked_at FROM peepers WHERE whisper_id = ? ORDER BY peeked_at DESC LIMIT ? OFFSET ?"
  ).bind(token, perPage, offset).all();
  const total = await env.DB.prepare("SELECT COUNT(*) as c FROM peepers WHERE whisper_id = ?").bind(token).first();
  const totalCount = total?.c || 0;
  const list = rows.results || [];
  const chatId = userId;

  await safeAnswer();

  const totalPages = Math.max(1, Math.ceil(totalCount / perPage));
  const header = t(lang, "peepers_header", { total: totalCount, page, total_pages: totalPages });

  let body = "";
  if (list.length === 0) {
    body = t(lang, "peepers_empty");
  } else {
    body = list.map((r, i) => `${offset + i + 1}. ${r.username ? "@" + esc(r.username) : "کاربر " + r.user_id}\n   <i>${formatDate(r.peeked_at)}</i>`).join("\n\n");
  }

  const nav = [];
  if (page > 1) nav.push({ text: t(lang, "peepers_btn_prev"), callback_data: `pp:${token}:${page - 1}`, style: "primary" });
  if (totalPages > 1) nav.push({ text: t(lang, "peepers_page_info", { page, total_pages: totalPages }), callback_data: "none" });
  if (page < totalPages) nav.push({ text: t(lang, "peepers_btn_next"), callback_data: `pp:${token}:${page + 1}`, style: "primary" });

  const reply_markup = nav.length > 0 ? { inline_keyboard: [nav] } : undefined;

  return tgApi(env, "sendMessage", {
    chat_id: chatId, text: `${header}\n\n${body}`, parse_mode: "HTML",
    reply_markup
  });
}

async function recordPeeper(env, whisperId, user) {
  await env.DB.prepare(
    "INSERT OR IGNORE INTO peepers (whisper_id, user_id, username, first_name, peeked_at) VALUES (?, ?, ?, ?, unixepoch())"
  ).bind(whisperId, user.id, user.username || null, user.first_name || null).run();
}

async function handleMessage(msg, env, settings, ctx) {
  const text = msg.text || "";
  const userId = msg.from.id;
  const chatId = msg.chat.id;
  const isPrivate = msg.chat.type === "private";
  const pmChatId = isPrivate ? chatId : userId;

  if (msg.reply_to_message?.text) {
    const m = msg.reply_to_message.text.match(/\[RT:([A-Za-z0-9_-]+)\]/);
    if (m) return handleReplyMessage(env, msg, m[1]);
  }

  try { await upsertUser(env, msg.from); } catch (e) {}
  const lang = await getUserLang(env, userId);

  if (text.startsWith("/start")) {
    try {
      await env.DB.prepare("UPDATE users SET started_at = CASE WHEN started_at = 0 OR started_at IS NULL THEN unixepoch() ELSE started_at END WHERE user_id = ?").bind(userId).run();
    } catch (e) {}
    const payload = text.replace("/start", "").trim();
    if (payload.startsWith("view_")) return handleViewCommand(env, pmChatId, payload.slice(5), msg.from, lang);
    if (payload.startsWith("reply_")) return handleReplyStart(env, pmChatId, payload.slice(6), msg.from, lang);
    if (payload.startsWith("peekers_")) return handlePeekersCommand(env, pmChatId, payload.slice(8), msg.from, lang);
    return sendMainMenu(env, pmChatId, msg.from, settings, lang);
  }

  if (text === "/help" || text === "/راهنما") return tgApi(env, "sendMessage", { chat_id: pmChatId, text: t(lang, "help_text", { bot: env.BOT_USERNAME }), parse_mode: "HTML" });
  if (text === "/upload" || text === "/مدیا") return tgApi(env, "sendMessage", { chat_id: pmChatId, text: t(lang, "upload_prompt"), parse_mode: "HTML" });
  if (text === "/my_media" || text === "/مدیای_من") return handleMyMedia(env, pmChatId, userId, lang);
  if (text === "/settings" || text === "/تنظیمات") return sendUserSettings(env, pmChatId, userId, lang);
  if (text === "/privacy" || text === "/حریم") {
    const ttl = await getSetting(env, "whisper_ttl_days");
    return tgApi(env, "sendMessage", { chat_id: pmChatId, text: t(lang, "privacy_text", { ttl }), parse_mode: "HTML" });
  }
  if (text === "/blocklist" || text === "/بلاک") return sendBlockList(env, pmChatId, userId, lang);
  if (text === "/my_stats" || text === "/آمار") return sendUserStats(env, pmChatId, userId, lang);
  if (text === "/delete_my_data" || text === "/حذف_داده") return confirmDeleteData(env, pmChatId, lang);

  if (text.startsWith("/unblock ")) {
    const target = parseInt(text.replace("/unblock", "").trim(), 10);
    if (!isNaN(target)) {
      await env.DB.prepare("DELETE FROM blocks WHERE user_id = ? AND blocked_id = ?").bind(userId, target).run();
      return tgApi(env, "sendMessage", { chat_id: pmChatId, text: t(lang, "unblock_ok", { id: target }) });
    }
  }

  if (text === "/najva" || text === "/نجوا") {
    return tgApi(env, "sendMessage", { chat_id: pmChatId, text: `🔒 <b>PV whisper</b>\n\n<code>متن @username</code>\n<code>متن 123456789</code>`, parse_mode: "HTML" });
  }

  const isAdmin = await isAdminUser(env, userId);
  if (text.startsWith("/panel") || text.startsWith("/admin")) {
    if (!isAdmin) return tgApi(env, "sendMessage", { chat_id: pmChatId, text: t(lang, "not_admin") });
    return sendAdminPanel(env, pmChatId, lang);
  }
  if (text.startsWith("/stats") && isAdmin) return sendTelegramStats(env, pmChatId, lang);

  if (text.startsWith("/broadcast ") && isAdmin) {
    const msgText = text.replace("/broadcast ", "").trim();
    if (msgText) {
      const broadcastId = generateId();
      const totalRow = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
      const total = totalRow?.c || 0;
      await env.DB.prepare(
        `INSERT INTO broadcasts (id, text, sent_by, sent_at, recipients, status, cursor_offset, total_count)
         VALUES (?, ?, ?, unixepoch(), 0, 'sending', 0, ?)`
      ).bind(broadcastId, msgText, userId, total).run();
      if (env.BROADCAST_QUEUE) ctx.waitUntil(enqueueBroadcast(env, broadcastId, msgText));
      else ctx.waitUntil(processBroadcastBatch(env, broadcastId, msgText, 0, BROADCAST_INITIAL_LIMIT));
      await tgApi(env, "sendMessage", { chat_id: pmChatId, text: `✅ ارسال همگانی شروع شد. (${total} کاربر)` });
    }
    return;
  }

  if (text.startsWith("/ban ") && isAdmin) {
    const target = parseInt(text.replace("/ban", "").trim(), 10);
    if (!isNaN(target)) {
      const banHours = 24;
      const bannedUntil = Math.floor(Date.now() / 1000) + (banHours * 3600);
      await env.DB.prepare("UPDATE users SET banned_until = ?, reports_count = 0 WHERE user_id = ?").bind(bannedUntil, target).run();
      return tgApi(env, "sendMessage", { chat_id: pmChatId, text: t(lang, "admin_ban_success", { id: target, hours: banHours }) });
    }
  }
  if (text.startsWith("/unban ") && isAdmin) {
    const target = parseInt(text.replace("/unban", "").trim(), 10);
    if (!isNaN(target)) {
      await env.DB.prepare("UPDATE users SET banned_until = 0, reports_count = 0 WHERE user_id = ?").bind(target).run();
      return tgApi(env, "sendMessage", { chat_id: pmChatId, text: t(lang, "admin_unban_success", { id: target }) });
    }
  }
  if (text.startsWith("/setvip ") && isAdmin) {
    const target = parseInt(text.replace("/setvip", "").trim(), 10);
    if (!isNaN(target)) {
      await env.DB.prepare("UPDATE users SET is_vip = 1 WHERE user_id = ?").bind(target).run();
      return tgApi(env, "sendMessage", { chat_id: pmChatId, text: t(lang, "admin_vip_success", { id: target }) });
    }
  }
  if (text.startsWith("/unsetvip ") && isAdmin) {
    const target = parseInt(text.replace("/unsetvip", "").trim(), 10);
    if (!isNaN(target)) {
      await env.DB.prepare("UPDATE users SET is_vip = 0 WHERE user_id = ?").bind(target).run();
      return tgApi(env, "sendMessage", { chat_id: pmChatId, text: t(lang, "admin_unvip_success", { id: target }) });
    }
  }
  if (text.startsWith("/warn ") && isAdmin) {
    const target = parseInt(text.replace("/warn", "").trim(), 10);
    if (!isNaN(target)) {
      const targetLang = await getUserLang(env, target);
      await tgApi(env, "sendMessage", {
        chat_id: target,
        text: t(targetLang, "admin_warn_msg"),
        parse_mode: "HTML"
      });
      return tgApi(env, "sendMessage", { chat_id: pmChatId, text: t(lang, "admin_warn_success", { id: target }) });
    }
  }

  if (msg.photo || msg.video || msg.document || msg.audio || msg.voice || msg.animation || msg.sticker) {
    if (!isPrivate) return;
    return handleMediaUpload(env, msg, lang, settings);
  }
}

async function handleMyMedia(env, chatId, userId, lang) {
  const rows = await env.DB.prepare("SELECT * FROM user_media WHERE user_id = ? ORDER BY created_at DESC").bind(userId).all();
  const list = rows.results || [];
  if (list.length === 0) return tgApi(env, "sendMessage", { chat_id: chatId, text: t(lang, "my_media_empty") });
  const buttons = list.map(m => [{ text: `🗑 ${m.code} (${m.media_type})`, callback_data: `delmedia:${m.code}`, style: "danger" }]);
  return tgApi(env, "sendMessage", {
    chat_id: chatId,
    text: t(lang, "my_media_title"),
    parse_mode: "HTML",
    reply_markup: { inline_keyboard: buttons }
  });
}

async function handleMediaUpload(env, msg, lang, settings) {
  const userId = msg.from.id;
  const chatId = msg.chat.id;
  let mediaType = null, fileId = null;
  if (msg.photo) { mediaType = "photo"; fileId = msg.photo[msg.photo.length - 1].file_id; }
  else if (msg.video) { mediaType = "video"; fileId = msg.video.file_id; }
  else if (msg.document) { mediaType = "document"; fileId = msg.document.file_id; }
  else if (msg.audio) { mediaType = "audio"; fileId = msg.audio.file_id; }
  else if (msg.voice) { mediaType = "voice"; fileId = msg.voice.file_id; }
  else if (msg.animation) { mediaType = "animation"; fileId = msg.animation.file_id; }
  else if (msg.sticker) { mediaType = "sticker"; fileId = msg.sticker.file_id; }
  else return;

  if (settings[`media_${mediaType}_enabled`] === "0") {
    return tgApi(env, "sendMessage", { chat_id: chatId, text: "ارسال این نوع مدیا در حال حاضر غیرفعال است." });
  }

  const code = "#m_" + generateToken(MEDIA_CODE_LEN);
  await env.DB.prepare("INSERT INTO user_media (code, user_id, media_type, file_id, created_at) VALUES (?, ?, ?, ?, unixepoch())").bind(code, userId, mediaType, fileId).run();
  return tgApi(env, "sendMessage", { chat_id: chatId, text: t(lang, "media_saved", { code, bot: env.BOT_USERNAME }), parse_mode: "HTML" });
}

async function handleViewCommand(env, chatId, token, user, lang) {
  const whisper = await env.DB.prepare("SELECT * FROM whispers WHERE id = ?").bind(token).first();
  if (!whisper) return tgApi(env, "sendMessage", { chat_id: chatId, text: t(lang, "not_found") });

  if (whisper.status === "deleted") return tgApi(env, "sendMessage", { chat_id: chatId, text: t(lang, "deleted") });
  if (whisper.status === "reported") return tgApi(env, "sendMessage", { chat_id: chatId, text: t(lang, "reported") });

  const now = Math.floor(Date.now() / 1000);
  const ttl = parseInt(await getSetting(env, "whisper_ttl_days") || "7", 10);
  if (whisper.status === "expired" || (whisper.status === "active" && whisper.created_at < now - ttl * 86400)) {
    if (whisper.status === "active") {
      await env.DB.prepare("UPDATE whispers SET status = 'expired' WHERE id = ?").bind(token).run();
    }
    return tgApi(env, "sendMessage", { chat_id: chatId, text: t(lang, "expired") });
  }

  if (whisper.status !== "active") return tgApi(env, "sendMessage", { chat_id: chatId, text: t(lang, "not_found") });

  const targetIds = safeParseIds(whisper.target_ids);
  const isSender = String(user.id) === String(whisper.sender_id);
  let isRecipient = targetIds.map(String).includes(String(user.id));

  if (!isRecipient && user.username) {
    if (targetIds.map(t => t.toLowerCase()).includes("@" + user.username.toLowerCase())) {
      isRecipient = true;
      targetIds.push(String(user.id));
      await env.DB.prepare("UPDATE whispers SET target_ids = ? WHERE id = ?").bind(JSON.stringify(targetIds), token).run();
    }
  }

  if (!isSender && !isRecipient) {
    await recordPeeper(env, token, user);
    return tgApi(env, "sendMessage", { chat_id: chatId, text: t(lang, "not_yours") });
  }

  if (isRecipient) {
    let viewedBy = safeParseIds(whisper.viewed_by);
    if (!viewedBy.map(String).includes(String(user.id))) {
      viewedBy.push(String(user.id));
      await env.DB.prepare("UPDATE whispers SET viewed_by = ? WHERE id = ?").bind(JSON.stringify(viewedBy), token).run();
    }
  }

  if (whisper.media_code) {
    const media = await env.DB.prepare("SELECT * FROM user_media WHERE code = ?").bind(whisper.media_code).first();
    if (media) {
      const map = { photo: "sendPhoto", video: "sendVideo", document: "sendDocument", audio: "sendAudio", voice: "sendVoice", animation: "sendAnimation", sticker: "sendSticker" };
      const keyMap = { photo: "photo", video: "video", document: "document", audio: "audio", voice: "voice", animation: "animation", sticker: "sticker" };
      const method = map[media.media_type];
      if (method) {
        const payload = { chat_id: chatId };
        payload[keyMap[media.media_type]] = media.file_id;
        if (media.media_type !== "sticker") {
          payload.caption = whisper.text ? t(lang, "view_content", { content: esc(whisper.text) }) : t(lang, "view_content_media");
          payload.parse_mode = "HTML";
        }
        payload.reply_markup = { inline_keyboard: [[{ text: t(lang, "btn_reply"), switch_inline_query_current_chat: `reply_${token} `, style: "success" }]] };
        return tgApi(env, method, payload);
      }
    }
  }

  return tgApi(env, "sendMessage", {
    chat_id: chatId,
    text: t(lang, "view_content", { content: esc(whisper.text) }),
    parse_mode: "HTML",
    reply_markup: { inline_keyboard: [[{ text: t(lang, "btn_reply"), switch_inline_query_current_chat: `reply_${token} `, style: "success" }]] }
  });
}

async function handlePeekersCommand(env, chatId, token, user, lang) {
  const whisper = await env.DB.prepare("SELECT * FROM whispers WHERE id = ?").bind(token).first();
  if (!whisper) return tgApi(env, "sendMessage", { chat_id: chatId, text: t(lang, "not_found") });

  const targetIds = safeParseIds(whisper.target_ids);
  const isSender = String(user.id) === String(whisper.sender_id);
  const isRecipient = targetIds.map(String).includes(String(user.id));

  if (!isSender && !isRecipient) return tgApi(env, "sendMessage", { chat_id: chatId, text: t(lang, "only_parties") });

  const fakeCq = { from: user, message: { chat: { id: chatId } }, id: "fake" };
  const noopAnswer = () => Promise.resolve({ ok: true });
  return handlePeepersPagination(env, fakeCq, token, 1, lang, noopAnswer);
}

async function handleReplyStart(env, chatId, token, user, lang) {
  const whisper = await env.DB.prepare("SELECT * FROM whispers WHERE id = ? AND status = 'active'").bind(token).first();
  if (!whisper) return tgApi(env, "sendMessage", { chat_id: chatId, text: t(lang, "not_found") });

  const targetIds = safeParseIds(whisper.target_ids);
  const isSender = String(user.id) === String(whisper.sender_id);
  const isRecipient = targetIds.map(String).includes(String(user.id));

  if (!isSender && !isRecipient) return tgApi(env, "sendMessage", { chat_id: chatId, text: t(lang, "only_parties") });
  if (isSender) return tgApi(env, "sendMessage", { chat_id: chatId, text: "شما نمی‌توانید به پیام خودتان پاسخ دهید." });

  return sendReplyForceReply(env, chatId, token, whisper, lang);
}

async function sendReplyForceReply(env, chatId, token, whisper, lang) {
  const preview = (whisper.text || "").length > 150 ? whisper.text.slice(0, 147) + "..." : (whisper.text || "[media]");
  return tgApi(env, "sendMessage", {
    chat_id: chatId,
    text: `${t(lang, "reply_prompt", { preview: esc(preview) })}\n\n💡 برای پاسخ به چند نفر: <code>@id1 @id2 متن</code>\n[RT:${token}]`,
    parse_mode: "HTML",
    reply_markup: { force_reply: true, input_field_placeholder: t(lang, "reply_write"), selective: true }
  });
}

async function handleReplyMessage(env, msg, token) {
  const settings = await getAllSettings(env);
  const lang = await getUserLang(env, msg.from.id);
  const whisper = await env.DB.prepare("SELECT * FROM whispers WHERE id = ? AND status = 'active'").bind(token).first();
  if (!whisper) return tgApi(env, "sendMessage", { chat_id: msg.chat.id, text: t(lang, "not_found") });

  const senderId = msg.from.id;
  const originalTargets = safeParseIds(whisper.target_ids);
  const isOriginalSender = String(senderId) === String(whisper.sender_id);
  const isRecipient = originalTargets.map(String).includes(String(senderId)) || (msg.from.username && originalTargets.map(t=>t.toLowerCase()).includes("@"+msg.from.username.toLowerCase()));

  if (!isOriginalSender && !isRecipient) {
    return tgApi(env, "sendMessage", { chat_id: msg.chat.id, text: t(lang, "only_parties") });
  }

  if (!await rateLimit(env, `rep:${senderId}`, RATE_LIMITS.reply_hour, 3600)) {
    return tgApi(env, "sendMessage", { chat_id: msg.chat.id, text: t(lang, "rate_limit") });
  }

  let replyText = msg.text || "";
  const parts = replyText.split(/\s+/).filter(Boolean);
  const parsed = parseTargetsAndText(parts);
  const targetTokens = parsed.targets;
  replyText = parsed.text;

  const customTargets = [];
  if (isOriginalSender) {
    for (const tok of targetTokens) {
      const res = classifyTargetToken(tok);
      if (!res.valid) continue;
      if (res.type === "numeric_id") {
        customTargets.push(res.value);
      } else if (res.type === "username") {
        const resolved = await resolveUsername(env, res.value);
        customTargets.push(resolved ? String(resolved) : `@${res.value}`);
      }
    }
  }

  if (customTargets.length > MAX_INLINE_TARGETS) {
    return tgApi(env, "sendMessage", { chat_id: msg.chat.id, text: `حداکثر ${MAX_INLINE_TARGETS} گیرنده مجاز است.` });
  }

  let recipientIds = [];
  if (customTargets.length > 0) {
    recipientIds = customTargets;
  } else {
    if (isOriginalSender) recipientIds = originalTargets;
    else recipientIds = [String(whisper.sender_id)];
  }

  if (!replyText) return tgApi(env, "sendMessage", { chat_id: msg.chat.id, text: "متن پاسخ خالی است." });
  if (replyText.length > MAX_REPLY_LENGTH) return tgApi(env, "sendMessage", { chat_id: msg.chat.id, text: t(lang, "too_long", { max: MAX_REPLY_LENGTH }) });

  let successCount = 0;
  for (const rId of recipientIds) {
    if (String(rId) === String(senderId)) continue;

    let actualChatId = rId;
    if (typeof rId === "string" && rId.startsWith("@")) {
      const resolved = await resolveUsername(env, rId.slice(1));
      if (resolved) actualChatId = resolved;
      else continue;
    }

    const blocked = await env.DB.prepare("SELECT 1 FROM blocks WHERE user_id = ? AND blocked_id = ?").bind(actualChatId, senderId).first();
    if (blocked) continue;

    await env.DB.prepare(
      "INSERT INTO replies (id, whisper_id, from_id, to_id, text, created_at) VALUES (?, ?, ?, ?, ?, unixepoch())"
    ).bind(generateId(), token, senderId, actualChatId, replyText).run();

    const recipientLang = await getUserLang(env, actualChatId);
    const header = settings.announce_replies === "1" ? t(recipientLang, "reply_header") + "\n\n" : t(recipientLang, "reply_plain") + "\n";
    const replyBody = `${header}«${esc(replyText)}»\n\n<code>[RT:${token}]</code>`;

    const r = await tgApi(env, "sendMessage", {
      chat_id: actualChatId,
      text: replyBody, parse_mode: "HTML",
      reply_markup: { inline_keyboard: [[{ text: t(recipientLang, "btn_reply"), switch_inline_query_current_chat: `reply_${token} `, style: "success" }]] }
    });
    if (r.ok) successCount++;
  }

  await tgApi(env, "sendMessage", { chat_id: msg.chat.id, text: `✅ پاسخ شما به ${successCount} نفر ارسال شد.` });
}

async function sendMainMenu(env, chatId, user, settings, lang) {
  const name = user.first_name || "دوست عزیز";
  const isAdmin = await isAdminUser(env, user.id);
  let text = t(lang, "main_menu", { name: esc(name), bot: env.BOT_USERNAME });

  if (!isAdmin) {
    text = text.replace("⚠️ <b>مهم:</b> برای کارکرد ربات در گروه‌ها، باید حالت Inline را در @BotFather فعال کنید (دستور /setinline).\n\n", "");
  }

  const inlineKb = [
    [{ text: "⚙️ تنظیمات", callback_data: "usr:settings", style: "primary" }, { text: "📊 آمار من", callback_data: "usr:stats", style: "primary" }],
    [{ text: "📖 راهنما", callback_data: "usr:help", style: "success" }, { text: "🔒 حریم خصوصی", callback_data: "usr:privacy", style: "success" }]
  ];

  if (isAdmin) {
    inlineKb.push([{ text: "🛠 پنل مدیریت", callback_data: "adm:menu", style: "danger" }]);
  }

  const payload = { chat_id: chatId, text, parse_mode: "HTML", reply_markup: { inline_keyboard: inlineKb } };
  if (settings.reply_keyboard_enabled === "1") {
    payload.reply_markup = {
      keyboard: [
        [{ text: "/help" }, { text: "/settings" }],
        [{ text: "/my_stats" }, { text: "/blocklist" }],
        [{ text: "/upload" }]
      ],
      resize_keyboard: true, is_persistent: true
    };
  }
  return tgApi(env, "sendMessage", payload);
}

async function sendUserSettings(env, chatId, userId, lang) {
  const s = await env.DB.prepare("SELECT * FROM user_settings WHERE user_id = ?").bind(userId).first();
  const notif = s?.notifications ?? 1;
  const userLang = normalizeLang(s?.lang || lang || "fa");
  const text = t(userLang, "settings_title", {
    notif: notif === 1 ? t(userLang, "settings_on") : t(userLang, "settings_off"),
    lang: userLang === "fa" ? t(userLang, "settings_lang_fa") : t(userLang, "settings_lang_en")
  });
  return tgApi(env, "sendMessage", {
    chat_id: chatId, text, parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [
        [{ text: `🔔 ${notif === 1 ? "خاموش" : "روشن"}`, callback_data: "usr:tgl_notif", style: "primary" }],
        [{ text: `🌐 ${userLang === "fa" ? "English" : "فارسی"}`, callback_data: "usr:tgl_lang", style: "primary" }],
        [{ text: t(userLang, "settings_btn_back"), callback_data: "usr:menu", style: "success" }]
      ]
    }
  });
}

async function toggleNotifications(env, chatId, userId) {
  const s = await env.DB.prepare("SELECT * FROM user_settings WHERE user_id = ?").bind(userId).first();
  if (s) await env.DB.prepare("UPDATE user_settings SET notifications = ?, updated_at = unixepoch() WHERE user_id = ?").bind(s.notifications === 1 ? 0 : 1, userId).run();
  else await env.DB.prepare("INSERT INTO user_settings (user_id, notifications) VALUES (?, 0)").bind(userId).run();
  return sendUserSettings(env, chatId, userId);
}

async function toggleUserLang(env, chatId, userId) {
  const s = await env.DB.prepare("SELECT * FROM user_settings WHERE user_id = ?").bind(userId).first();
  const cur = normalizeLang(s?.lang || "fa");
  const next = cur === "fa" ? "en" : "fa";
  if (s) await env.DB.prepare("UPDATE user_settings SET lang = ?, updated_at = unixepoch() WHERE user_id = ?").bind(next, userId).run();
  else await env.DB.prepare("INSERT INTO user_settings (user_id, notifications, lang) VALUES (?, 1, ?)").bind(userId, next).run();
  await invalidateLangCache(env, userId);
  return sendUserSettings(env, chatId, userId, next);
}

async function sendUserStats(env, chatId, userId, lang) {
  const sent = await env.DB.prepare("SELECT COUNT(*) as c FROM whispers WHERE sender_id = ?").bind(userId).first();
  const received = await env.DB.prepare("SELECT COUNT(*) as c FROM whispers WHERE target_ids LIKE ?").bind(`%${userId}%`).first();
  const peekers = await env.DB.prepare("SELECT COUNT(DISTINCT p.user_id) as c FROM peepers p JOIN whispers w ON p.whisper_id = w.id WHERE w.sender_id = ?").bind(userId).first();
  const replies = await env.DB.prepare("SELECT COUNT(*) as c FROM replies WHERE from_id = ?").bind(userId).first();
  const blocked = await env.DB.prepare("SELECT COUNT(*) as c FROM blocks WHERE user_id = ?").bind(userId).first();
  return tgApi(env, "sendMessage", {
    chat_id: chatId,
    text: t(lang, "stats_my", {
      sent: sent?.c || 0, received: received?.c || 0, peekers: peekers?.c || 0,
      replies: replies?.c || 0, blocked: blocked?.c || 0
    }), parse_mode: "HTML"
  });
}

async function sendBlockList(env, chatId, userId, lang) {
  const rows = await env.DB.prepare("SELECT blocked_id, created_at FROM blocks WHERE user_id = ? ORDER BY created_at DESC LIMIT 50").bind(userId).all();
  const list = rows.results || [];
  if (list.length === 0) return tgApi(env, "sendMessage", { chat_id: chatId, text: t(lang, "blocklist_empty") });
  const text = `${t(lang, "blocklist_header", { count: list.length })}\n\n${list.map(b => `• <code>${b.blocked_id}</code> — ${formatDate(b.created_at)}`).join("\n")}\n\n${t(lang, "blocklist_hint")}`;
  return tgApi(env, "sendMessage", { chat_id: chatId, text, parse_mode: "HTML" });
}

async function confirmDeleteData(env, chatId, lang) {
  return tgApi(env, "sendMessage", {
    chat_id: chatId, text: t(lang, "confirm_delete"), parse_mode: "HTML",
    reply_markup: { inline_keyboard: [[
      { text: t(lang, "confirm_yes"), callback_data: "usr:confirm_delete", style: "danger" },
      { text: t(lang, "confirm_no"), callback_data: "usr:menu", style: "success" }
    ]] }
  });
}

async function deleteUserData(env, userId) {
  const whispers = await env.DB.prepare("SELECT id FROM whispers WHERE sender_id = ? OR target_ids LIKE ?").bind(userId, `%"${userId}"%`).all();
  const ids = (whispers.results || []).map(w => w.id);
  if (ids.length > 0) {
    const ph = ids.map(() => "?").join(",");
    await env.DB.prepare(`DELETE FROM peepers WHERE whisper_id IN (${ph})`).bind(...ids).run();
    await env.DB.prepare(`DELETE FROM reports WHERE whisper_id IN (${ph})`).bind(...ids).run();
    await env.DB.prepare(`DELETE FROM replies WHERE whisper_id IN (${ph})`).bind(...ids).run();
  }
  await env.DB.prepare("DELETE FROM whispers WHERE sender_id = ? OR target_ids LIKE ?").bind(userId, `%"${userId}"%`).run();
  await env.DB.prepare("DELETE FROM replies WHERE from_id = ? OR to_id = ?").bind(userId, userId).run();
  await env.DB.prepare("DELETE FROM peepers WHERE user_id = ?").bind(userId).run();
  await env.DB.prepare("DELETE FROM blocks WHERE user_id = ?").bind(userId).run();
  await env.DB.prepare("DELETE FROM reports WHERE reporter_id = ?").bind(userId).run();
  await env.DB.prepare("DELETE FROM user_media WHERE user_id = ?").bind(userId).run();
  await env.DB.prepare("DELETE FROM user_settings WHERE user_id = ?").bind(userId).run();
  await env.DB.prepare("DELETE FROM pending_whispers WHERE sender_id = ?").bind(userId).run();
  await env.DB.prepare("DELETE FROM users WHERE user_id = ?").bind(userId).run();
  await invalidateLangCache(env, userId);
}

async function upsertUser(env, user) {
  await env.DB.prepare(
    `INSERT INTO users (user_id, username, first_name, last_name, started_at, last_seen) VALUES (?, ?, ?, ?, 0, unixepoch())
     ON CONFLICT(user_id) DO UPDATE SET username = excluded.username, first_name = excluded.first_name, last_name = excluded.last_name, last_seen = unixepoch()`
  ).bind(user.id, user.username || null, user.first_name || null, user.last_name || null).run();
}

async function sendAdminPanel(env, chatId, lang) {
  const settings = await getAllSettings(env);
  const stats = await getDetailedStats(env);
  const text = t(lang, "admin_panel_title", {
    version: BOT_VERSION, users: formatNumber(stats.users), whispers: formatNumber(stats.whispers),
    replies: formatNumber(stats.replies), peepers: formatNumber(stats.peepers),
    today: stats.today, active24: stats.active24,
    force_start: settings.force_start === "1" ? "✅" : "❌",
    ads: settings.ads_enabled === "1" ? "✅" : "❌"
  });
  return tgApi(env, "sendMessage", {
    chat_id: chatId, text, parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [
        [{ text: t(lang, "admin_btn_stats"), callback_data: "adm:stats", style: "primary" }, { text: t(lang, "admin_btn_settings"), callback_data: "adm:settings", style: "primary" }],
        [{ text: t(lang, "admin_btn_webhook"), callback_data: "adm:webhook", style: "success" }, { text: t(lang, "admin_btn_broadcast"), callback_data: "adm:broadcast", style: "success" }],
        [{ text: t(lang, "admin_btn_backup"), callback_data: "adm:backup", style: "danger" }, { text: t(lang, "admin_btn_cleanup"), callback_data: "adm:cleanup", style: "danger" }]
      ]
    }
  });
}

async function sendTelegramStats(env, chatId, lang) {
  const stats = await getDetailedStats(env);
  return tgApi(env, "sendMessage", {
    chat_id: chatId,
    text: t(lang, "admin_stats_title", {
      users: formatNumber(stats.users), whispers: formatNumber(stats.whispers),
      replies: formatNumber(stats.replies), peepers: formatNumber(stats.peepers),
      reports: formatNumber(stats.reports), today: stats.today,
      active24: stats.active24, viewed: stats.viewed
    }), parse_mode: "HTML"
  });
}

async function handleAdminCallback(cq, env, action, answer, lang, chatId) {
  if (action === "menu") { await answer(); return sendAdminPanel(env, chatId, lang); }
  if (action === "stats") { await answer(); return sendTelegramStats(env, chatId, lang); }

  if (action === "settings") {
    await answer();
    const s = await getAllSettings(env);
    const tgl = (label, key) => [{ text: `${label}: ${s[key] === "1" ? "✅" : "❌"}`, callback_data: `adm:tg:${key}`, style: "primary" }];
    return tgApi(env, "sendMessage", {
      chat_id: chatId, text: t(lang, "admin_settings_title"), parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [
          tgl("⚡️ Force", "force_start"),
          tgl("📢 Ads", "ads_enabled"),
          tgl("🛠 Maintenance", "maintenance_mode"),
          tgl("🔔 Announce", "announce_replies"),
          [{ text: t(lang, "admin_btn_back"), callback_data: "adm:menu", style: "danger" }]
        ]
      }
    });
  }

  if (action.startsWith("tg:")) {
    await answer();
    const key = action.slice(3);
    const allowed = ["force_start", "ads_enabled", "maintenance_mode", "announce_replies"];
    if (allowed.includes(key)) {
      const cur = await getSetting(env, key);
      await setSetting(env, key, cur === "1" ? "0" : "1");
      await logAdminAction(env, cq.from.id, "toggle_setting", key);
    }
    const s = await getAllSettings(env);
    const tgl = (label, k) => [{ text: `${label}: ${s[k] === "1" ? "✅" : "❌"}`, callback_data: `adm:tg:${k}`, style: "primary" }];
    return tgApi(env, "sendMessage", {
      chat_id: chatId, text: t(lang, "admin_settings_title"), parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [
          tgl("⚡️ Force", "force_start"),
          tgl("📢 Ads", "ads_enabled"),
          tgl("🛠 Maintenance", "maintenance_mode"),
          tgl("🔔 Announce", "announce_replies"),
          [{ text: t(lang, "admin_btn_back"), callback_data: "adm:menu", style: "danger" }]
        ]
      }
    });
  }

  if (action === "webhook") {
    await answer();
    const info = await tgApi(env, "getWebhookInfo", {});
    const wh = info.result || {};
    return tgApi(env, "sendMessage", {
      chat_id: chatId,
      text: t(lang, "admin_webhook_title", {
        url: esc(wh.url || "—"),
        error: wh.last_error_message ? esc(wh.last_error_message) : "—",
        pending: wh.pending_update_count || 0
      }), parse_mode: "HTML",
      reply_markup: { inline_keyboard: [[{ text: t(lang, "admin_btn_back"), callback_data: "adm:menu", style: "danger" }]] }
    });
  }

  if (action === "broadcast") {
    await answer();
    return tgApi(env, "sendMessage", {
      chat_id: chatId,
      text: "📨 <b>ارسال همگانی</b>\n\nبرای ارسال پیام به تمام کاربران، دستور زیر را با متن دلخواه بفرستید:\n\n<code>/broadcast متن پیام شما</code>",
      parse_mode: "HTML",
      reply_markup: { inline_keyboard: [[{ text: t(lang, "admin_btn_back"), callback_data: "adm:menu", style: "danger" }]] }
    });
  }

  if (action === "cleanup") {
    await answer();
    return tgApi(env, "sendMessage", {
      chat_id: chatId,
      text: "🧹 <b>پاکسازی سریع</b>\n\nنجواهای قدیمی، فضول‌ها و لاگ‌های قدیمی پاک خواهند شد.",
      parse_mode: "HTML",
      reply_markup: { inline_keyboard: [
        [{ text: "🗑 بله، پاکسازی کن", callback_data: "adm:do_cleanup", style: "danger" }],
        [{ text: t(lang, "admin_btn_back"), callback_data: "adm:menu", style: "primary" }]
      ] }
    });
  }

  if (action === "do_cleanup") {
    await answer("در حال پاکسازی...");
    await runScheduledTasks(env);
    return tgApi(env, "sendMessage", { chat_id: chatId, text: "✅ پاکسازی با موفقیت انجام شد." });
  }

  if (action === "backup") {
    await answer();
    return tgApi(env, "sendMessage", {
      chat_id: chatId,
      text: `💾 <b>پشتیبان‌گیری</b>\n\nبرای دریافت فایل بکاپ، از پنل وب ربات خودتان استفاده کنید.`,
      parse_mode: "HTML",
      reply_markup: { inline_keyboard: [[{ text: t(lang, "admin_btn_back"), callback_data: "adm:menu", style: "danger" }]] }
    });
  }
}

async function handleUserCallback(cq, env, action, answer, lang, chatId) {
  const userId = cq.from.id;

  if (action === "menu") { await answer(); return sendMainMenu(env, chatId, cq.from, await getAllSettings(env), lang); }
  if (action === "help") { await answer(); return tgApi(env, "sendMessage", { chat_id: chatId, text: t(lang, "help_text", { bot: env.BOT_USERNAME }), parse_mode: "HTML" }); }
  if (action === "privacy") {
    await answer();
    const ttl = await getSetting(env, "whisper_ttl_days");
    return tgApi(env, "sendMessage", { chat_id: chatId, text: t(lang, "privacy_text", { ttl }), parse_mode: "HTML" });
  }
  if (action === "stats") { await answer(); return sendUserStats(env, chatId, userId, lang); }
  if (action === "settings") { await answer(); return sendUserSettings(env, chatId, userId, lang); }
  if (action === "tgl_notif") { await answer(); return toggleNotifications(env, chatId, userId); }
  if (action === "tgl_lang") { await answer(); return toggleUserLang(env, chatId, userId); }
  if (action === "confirm_delete") {
    await answer();
    await deleteUserData(env, userId);
    return tgApi(env, "sendMessage", { chat_id: chatId, text: t(lang, "data_deleted") });
  }
  return answer();
}

async function tgApi(env, method, payload, hasStyle = true) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TG_API_TIMEOUT);
  const botToken = env.BOT_TOKEN || env.TELEGRAM_BOT_TOKEN;
  
  try {
    const res = await fetch(`https://api.telegram.org/bot${botToken}/${method}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    
    let data;
    try {
      data = await res.json();
    } catch {
      return { ok: false, description: "TELEGRAM_INVALID_JSON" };
    }
    
    if (!res.ok || data?.ok !== true) {
      if (hasStyle && (data?.error_code === 400 || res.status === 400)) {
        const desc = data?.description || "";
        if (desc.toLowerCase().includes("style") || desc.toLowerCase().includes("button")) {
          const stripStyle = (obj) => {
            if (!obj) return obj;
            if (Array.isArray(obj)) return obj.map(stripStyle);
            if (typeof obj === "object") {
              const copy = { ...obj };
              delete copy.style;
              for (const k in copy) {
                 if (typeof copy[k] === "object") copy[k] = stripStyle(copy[k]);
              }
              return copy;
            }
            return obj;
          };
          const fallbackPayload = stripStyle(payload);
          return await tgApi(env, method, fallbackPayload, false);
        }
      }
      return data;
    }
    return data;
  } catch (err) {
    if (err.name === 'AbortError') {
       return { ok: false, description: "TELEGRAM_REQUEST_TIMEOUT" };
    }
    return { ok: false, description: err.message };
  } finally {
    clearTimeout(timer);
  }
}

async function runScheduledTasks(env) {
  try {
    const now = Math.floor(Date.now() / 1000);
    const ttl = parseInt(await getSetting(env, "whisper_ttl_days") || "7", 10);
    const logRetention = parseInt(await getSetting(env, "log_retention_days") || "30", 10);

    await env.DB.prepare("DELETE FROM pending_whispers WHERE created_at < ?").bind(now - 3600).run();
    await env.DB.prepare("DELETE FROM processed_updates WHERE created_at < ?").bind(now - 86400).run();
    await env.DB.prepare("DELETE FROM login_attempts WHERE updated_at < ? AND locked_until < ?").bind(Date.now() - 86400000, Date.now()).run();
    await env.DB.prepare(
      "DELETE FROM user_media WHERE created_at < ? AND code NOT IN (SELECT media_code FROM whispers WHERE status = 'active' AND media_code IS NOT NULL)"
    ).bind(now - 30 * 86400).run();
    await env.DB.prepare("DELETE FROM admin_logs WHERE created_at < ?").bind(now - logRetention * 86400).run();
    await env.DB.prepare("DELETE FROM sessions_log WHERE logged_in_at < ?").bind(now - logRetention * 86400).run();
    await env.DB.prepare("UPDATE users SET reports_count = 0 WHERE banned_until > 0 AND banned_until < ?").bind(now).run();

    const expiring = await env.DB.prepare(
      "SELECT id, inline_message_id FROM whispers WHERE status = 'active' AND created_at < ? LIMIT 20"
    ).bind(now - ttl * 86400).all();

    for (const w of (expiring.results || [])) {
      await env.DB.prepare("UPDATE whispers SET status = 'expired' WHERE id = ?").bind(w.id).run();
      if (w.inline_message_id) {
        await tgApi(env, "editMessageReplyMarkup", {
          inline_message_id: w.inline_message_id,
          reply_markup: { inline_keyboard: [[{ text: "⏳", callback_data: "expired" }]] }
        });
      }
    }

    const scheduled = await env.DB.prepare(
      "SELECT * FROM broadcasts WHERE status = 'scheduled' AND sent_at <= ? ORDER BY sent_at ASC LIMIT 1"
    ).bind(now).first();
    if (scheduled) {
      await env.DB.prepare("UPDATE broadcasts SET status = 'sending' WHERE id = ?").bind(scheduled.id).run();
      if (env.BROADCAST_QUEUE) await enqueueBroadcast(env, scheduled.id, scheduled.text).catch(() => {});
      else await processBroadcastBatch(env, scheduled.id, scheduled.text, 0, BROADCAST_INITIAL_LIMIT);
    }

    const pending = await env.DB.prepare("SELECT * FROM broadcasts WHERE status = 'sending' ORDER BY sent_at ASC LIMIT 1").first();
    if (pending && !env.BROADCAST_QUEUE) {
      const remaining = pending.total_count - pending.cursor_offset;
      if (remaining > 0) await processBroadcastBatch(env, pending.id, pending.text, pending.cursor_offset, Math.min(remaining, BROADCAST_BATCH_SIZE));
      else await env.DB.prepare("UPDATE broadcasts SET status = 'done' WHERE id = ?").bind(pending.id).run();
    }

    const stalledBroadcasts = await env.DB.prepare(
      "SELECT id, cursor_offset, total_count FROM broadcasts WHERE status = 'sending' AND cursor_offset >= total_count"
    ).all();
    for (const b of (stalledBroadcasts.results || [])) {
      await env.DB.prepare("UPDATE broadcasts SET status = 'done' WHERE id = ?").bind(b.id).run();
    }

    const staleBroadcasts = await env.DB.prepare(
      "SELECT id FROM broadcasts WHERE status IN ('sending', 'scheduled') AND sent_at < ?"
    ).bind(now - 86400).all();
    for (const b of (staleBroadcasts.results || [])) {
      await env.DB.prepare("UPDATE broadcasts SET status = 'failed' WHERE id = ?").bind(b.id).run();
    }

    if (env.CACHE) await env.CACHE.delete("stats:detailed");
  } catch (e) {}
}

async function renderDashboard(env, session) {
  const stats = await getDetailedStats(env);
  const recent = await env.DB.prepare(
    "SELECT id, sender_id, target_usernames, text, created_at, status, viewed_by FROM whispers ORDER BY created_at DESC LIMIT 8"
  ).all();
  const settings = await getAllSettings(env);
  const webhook = await tgApi(env, "getWebhookInfo", {});
  const wh = webhook.result || {};
  let whisperTrend = { results: [] };
  try {
    whisperTrend = await env.DB.prepare(
      "SELECT date(created_at, 'unixepoch') as day, COUNT(*) as c FROM whispers WHERE created_at > ? GROUP BY day ORDER BY day"
    ).bind(Math.floor(Date.now() / 1000) - 7 * 86400).all();
  } catch (e) {}

  const trendData = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000);
    const key = d.toISOString().slice(0, 10);
    const found = (whisperTrend.results || []).find(r => r.day === key);
    trendData.push({ label: key.slice(5), value: found?.c || 0 });
  }

  const inlineWarning = stats.missing_inline_feedback > 0;

  return htmlResponse(layout("داشبورد", `
    <div class="page-header"><h1>داشبورد</h1><p class="subtitle">نمای کلی — نسخه ${BOT_VERSION}</p></div>
    ${inlineWarning ? `<div class="alert alert-warning">${icon("warning", 18)}<span>هشدار: ${stats.missing_inline_feedback} نجوا بدون <code>inline_message_id</code> در ۲۴ ساعت اخیر. لطفاً در BotFather دستور <code>/setinlinefeedback</code> را فعال کنید تا دکمه «حذف» کارت را از گروه پاک کند.</span></div>` : ""}
    <div class="stats-grid">
      ${statCard("users", "کاربران", stats.users)}
      ${statCard("whisper", "نجواها", stats.whispers, `${stats.active_whispers} فعال`)}
      ${statCard("reply", "پاسخ‌ها", stats.replies)}
      ${statCard("peek", "فضول‌ها", stats.peepers)}
      ${statCard("calendar", "امروز", stats.today)}
      ${statCard("activity", "فعال ۲۴س", stats.active24)}
      ${statCard("report", "گزارش‌ها", stats.reports)}
      ${statCard("chart", "دیده‌شده", stats.viewed)}
    </div>
    <div class="grid-2">
      <div class="card"><h2>${icon("chart")} روند ۷ روز</h2>${barChart(trendData)}</div>
      <div class="card"><h2>${icon("shield")} وضعیت سیستم</h2>
        <div class="kv"><span>Webhook</span><strong>${wh.url ? "✅ متصل" : "❌ تنظیم نشده"}</strong></div>
        <div class="kv"><span>آخرین خطا</span><strong>${wh.last_error_message ? esc(wh.last_error_message).slice(0, 40) : "بدون خطا"}</strong></div>
        <div class="kv"><span>آپدیت معلق</span><strong>${wh.pending_update_count || 0}</strong></div>
        <div class="kv"><span>Database</span><strong>✅ متصل</strong></div>
        <div class="kv"><span>KV Cache</span><strong>${env.CACHE ? "✅ فعال" : "⚠️ غیرفعال"}</strong></div>
        <div class="kv"><span>Queue</span><strong>${env.BROADCAST_QUEUE ? "✅ فعال" : "⚠️ غیرفعال"}</strong></div>
        <div class="kv"><span>IP Bind</span><strong>${env.BIND_SESSION_IP !== "0" ? "✅ فعال" : "❌ غیرفعال"}</strong></div>
        <div class="kv"><span>استارت اجباری</span><strong>${settings.force_start === "1" ? "✅" : "❌"}</strong></div>
        <div class="kv"><span>تبلیغات</span><strong>${settings.ads_enabled === "1" ? "✅" : "❌"}</strong></div>
        <div class="kv"><span>حالت تعمیرات</span><strong>${settings.maintenance_mode === "1" ? "⚠️ فعال" : "✅ غیرفعال"}</strong></div>
        <div class="kv"><span>دستورات ثبت</span><strong>${settings.commands_synced === "1" ? "✅" : "❌"}</strong></div>
        <div class="kv"><span>جوین اجباری</span><strong>${settings.force_join_channels ? "✅ فعال" : "❌ غیرفعال"}</strong></div>
      </div>
    </div>
    <div class="card"><h2>${icon("whisper")} ۸ نجوای اخیر</h2>
      ${(recent.results || []).length === 0 ? `<div class="empty-state">${icon("whisper", 40)}<p>هنوز نجوایی ثبت نشده</p></div>` :
        `<div class="list">${(recent.results || []).map(w => `<div class="list-item"><div style="display:flex;justify-content:space-between;align-items:start;gap:.5rem"><strong>${esc((w.text || "").slice(0, 60) || "[مدیا]")}</strong><span class="badge badge-${w.status}">${w.status}</span></div><small>${formatDate(w.created_at)} → ${esc(w.target_usernames)}${w.viewed_by !== '[]' ? " 👁" : ""}</small></div>`).join("")}</div>`}
    </div>
  `, "dashboard", session.csrf));
}

async function renderStats(env, session) {
  const stats = await getDetailedStats(env);
  const topSenders = await env.DB.prepare("SELECT sender_id, COUNT(*) as c FROM whispers GROUP BY sender_id ORDER BY c DESC LIMIT 10").all();
  const topPeepers = await env.DB.prepare("SELECT user_id, COUNT(*) as c FROM peepers GROUP BY user_id ORDER BY c DESC LIMIT 10").all();
  const statusDist = await env.DB.prepare("SELECT status, COUNT(*) as c FROM whispers GROUP BY status").all();
  const statusData = (statusDist.results || []).map(r => ({ label: r.status, value: r.c }));

  return htmlResponse(layout("آمار", `
    <div class="page-header"><h1>آمار تفصیلی</h1></div>
    <div class="stats-grid">
      ${statCard("users", "کاربران", stats.users)}
      ${statCard("activity", "فعال هفته", stats.active_week)}
      ${statCard("whisper", "فعال", stats.active_whispers)}
      ${statCard("clock", "منقضی", stats.expired_whispers)}
      ${statCard("report", "گزارش‌شده", stats.reported_whispers)}
      ${statCard("chart", "دیده‌شده", stats.viewed)}
    </div>
    <div class="card"><h2>${icon("chart")} توزیع وضعیت</h2>${barChart(statusData)}</div>
    <div class="grid-2">
      <div class="card"><h2>${icon("users")} پرکارترین فرستنده‌ها</h2>${(topSenders.results || []).length === 0 ? `<div class="empty-state"><p>خالی</p></div>` : (topSenders.results || []).map((s, i) => `<div class="kv"><span>${i + 1}. ${esc(s.sender_id)}</span><strong>${s.c} نجوا</strong></div>`).join("")}</div>
      <div class="card"><h2>${icon("peek")} پر فضول‌ترین</h2>${(topPeepers.results || []).length === 0 ? `<div class="empty-state"><p>خالی</p></div>` : (topPeepers.results || []).map((p, i) => `<div class="kv"><span>${i + 1}. ${esc(p.user_id)}</span><strong>${p.c} تلاش</strong></div>`).join("")}</div>
    </div>
  `, "stats", session.csrf));
}

async function renderUsers(env, url, session) {
  const page = Math.max(1, parseInt(url.searchParams.get("page") || "1", 10));
  const perPage = 50;
  const offset = (page - 1) * perPage;
  const search = (url.searchParams.get("q") || "").trim();
  let q = "SELECT * FROM users", cq = "SELECT COUNT(*) as c FROM users", params = [], cparams = [];
  if (search) {
    const like = `%${search}%`;
    q += " WHERE CAST(user_id AS TEXT) LIKE ? OR username LIKE ? OR first_name LIKE ?";
    cq += " WHERE CAST(user_id AS TEXT) LIKE ? OR username LIKE ? OR first_name LIKE ?";
    params.push(like, like, like); cparams.push(like, like, like);
  }
  q += ` ORDER BY last_seen DESC LIMIT ${perPage} OFFSET ${offset}`;
  const users = await env.DB.prepare(q).bind(...params).all();
  const total = await env.DB.prepare(cq).bind(...cparams).first();
  const totalPages = Math.ceil((total?.c || 0) / perPage);
  const now = Math.floor(Date.now() / 1000);

  return htmlResponse(layout("کاربران", `
    <div class="page-header"><h1>کاربران</h1><p class="subtitle">${formatNumber(total?.c || 0)} کاربر</p></div>
    <form method="GET" class="search-form">${icon("search", 18)}<input type="text" name="q" value="${esc(search)}" placeholder="جستجو..."><button class="btn btn-primary">جستجو</button></form>
    <div class="card table-card"><table><thead><tr><th>آیدی</th><th>یوزرنیم</th><th>نام</th><th>وضعیت</th><th>عملیات مدیریتی</th></tr></thead><tbody>
      ${(users.results || []).length === 0 ? `<tr><td colspan="5" class="empty-state">${icon("users", 32)}<p>کاربری یافت نشد</p></td></tr>` :
        (users.results || []).map(u => {
          let statusBadge = "";
          if (u.banned_until && u.banned_until > now) statusBadge += `<span class="badge badge-reported">بن</span> `;
          if (u.is_vip === 1) statusBadge += `<span class="badge badge-active">VIP</span>`;
          if (u.reports_count > 0) statusBadge += ` <span class="badge badge-expired">${u.reports_count} گزارش</span>`;

          const isBanned = u.banned_until && u.banned_until > now;

          return `<tr>
            <td class="mono">${u.user_id}</td>
            <td>${u.username ? "@" + esc(u.username) : "—"}</td>
            <td>${esc(u.first_name || "—")}</td>
            <td>${statusBadge || "عادی"}</td>
            <td>
              <div style="display:flex; gap:0.25rem; flex-wrap:wrap;">
                <form method="POST" action="/admin/users" style="display:flex; gap:0.25rem;">
                  <input type="hidden" name="csrf" value="${session.csrf}">
                  <input type="hidden" name="user_id" value="${u.user_id}">
                  <input type="hidden" name="action" value="send_dm">
                  <input type="text" name="message" placeholder="پیام..." style="width:100px; margin:0; padding:0.25rem;">
                  <button class="btn btn-small btn-primary" title="ارسال پیام">ارسال</button>
                </form>
                ${isBanned
                  ? `<form method="POST"><input type="hidden" name="csrf" value="${session.csrf}"><input type="hidden" name="user_id" value="${u.user_id}"><input type="hidden" name="action" value="unban"><button class="btn btn-small btn-success" title="رفع مسدودی">${icon("unlock", 14)} آنبن</button></form>`
                  : `<form method="POST"><input type="hidden" name="csrf" value="${session.csrf}"><input type="hidden" name="user_id" value="${u.user_id}"><input type="hidden" name="action" value="ban"><button class="btn btn-small btn-danger" title="مسدود کردن">${icon("lock", 14)} بن</button></form>`
                }
              </div>
            </td>
          </tr>`;
        }).join("")}
    </tbody></table></div>
    ${renderPagination(page, totalPages, "/admin/users", search)}
  `, "users", session.csrf));
}

async function renderWhispers(env, url, session) {
  const page = Math.max(1, parseInt(url.searchParams.get("page") || "1", 10));
  const perPage = 50;
  const offset = (page - 1) * perPage;
  const status = url.searchParams.get("status") || "";
  const where = status ? "WHERE status = ?" : "";
  const params = status ? [status] : [];
  const rows = await env.DB.prepare(`SELECT * FROM whispers ${where} ORDER BY created_at DESC LIMIT ${perPage} OFFSET ${offset}`).bind(...params).all();
  const total = await env.DB.prepare(`SELECT COUNT(*) as c FROM whispers ${where}`).bind(...params).first();
  const totalPages = Math.ceil((total?.c || 0) / perPage);
  const filter = ["all", "active", "expired", "deleted", "reported"].map(s => `<a href="/admin/whispers${s === "all" ? "" : "?status=" + s}" class="btn btn-small ${(status === s || (!status && s === "all")) ? "btn-primary" : ""}">${s === "all" ? "همه" : s}</a>`).join("");

  return htmlResponse(layout("نجواها", `
    <div class="page-header"><h1>نجواها</h1><p class="subtitle">${formatNumber(total?.c || 0)} نجوا</p></div>
    <div class="filter-bar">${filter}</div>
    <div class="card table-card"><table><thead><tr><th>ID</th><th>فرستنده</th><th>مقصدها</th><th>متن</th><th>مدیا</th><th>وضعیت</th><th>مشاهده</th><th>تاریخ</th></tr></thead><tbody>
      ${(rows.results || []).length === 0 ? `<tr><td colspan="8" class="empty-state">${icon("whisper", 32)}<p>خالی</p></td></tr>` :
        (rows.results || []).map(w => {
          const viewedCount = safeParseIds(w.viewed_by).length;
          const targetCount = safeParseIds(w.target_ids).length;
          return `<tr><td class="mono">${esc(w.id)}</td><td class="mono">${w.sender_id}</td><td>${esc(w.target_usernames || "—")}</td><td>${esc((w.text || "").slice(0, 40) || "—")}</td><td>${w.media_code ? "📎" : "—"}</td><td><span class="badge badge-${w.status}">${w.status}</span></td><td>${viewedCount}/${targetCount} 👁</td><td>${formatDate(w.created_at)}</td></tr>`;
        }).join("")}
    </tbody></table></div>
    ${renderPagination(page, totalPages, "/admin/whispers", "")}
  `, "whispers", session.csrf));
}

async function renderReplies(env, url, session) {
  const page = Math.max(1, parseInt(url.searchParams.get("page") || "1", 10));
  const perPage = 50;
  const offset = (page - 1) * perPage;
  const rows = await env.DB.prepare(`SELECT * FROM replies ORDER BY created_at DESC LIMIT ${perPage} OFFSET ${offset}`).all();
  const total = await env.DB.prepare("SELECT COUNT(*) as c FROM replies").first();
  const totalPages = Math.ceil((total?.c || 0) / perPage);

  return htmlResponse(layout("پاسخ‌ها", `
    <div class="page-header"><h1>پاسخ‌ها</h1><p class="subtitle">${formatNumber(total?.c || 0)} پاسخ</p></div>
    <div class="card table-card"><table><thead><tr><th>نجوا</th><th>از</th><th>به</th><th>متن</th><th>تاریخ</th></tr></thead><tbody>
      ${(rows.results || []).length === 0 ? `<tr><td colspan="5" class="empty-state">${icon("reply", 32)}<p>خالی</p></td></tr>` :
        (rows.results || []).map(r => `<tr><td class="mono">${esc(r.whisper_id)}</td><td class="mono">${r.from_id}</td><td class="mono">${r.to_id}</td><td>${esc((r.text || "").slice(0, 80))}</td><td>${formatDate(r.created_at)}</td></tr>`).join("")}
    </tbody></table></div>
    ${renderPagination(page, totalPages, "/admin/replies", "")}
  `, "replies", session.csrf));
}

async function renderPeepers(env, url, session) {
  const page = Math.max(1, parseInt(url.searchParams.get("page") || "1", 10));
  const perPage = 100;
  const offset = (page - 1) * perPage;
  const rows = await env.DB.prepare(`SELECT * FROM peepers ORDER BY peeked_at DESC LIMIT ${perPage} OFFSET ${offset}`).all();
  const total = await env.DB.prepare("SELECT COUNT(*) as c FROM peepers").first();
  const totalPages = Math.ceil((total?.c || 0) / perPage);

  return htmlResponse(layout("فضول‌ها", `
    <div class="page-header"><h1>فضول‌ها</h1><p class="subtitle">${formatNumber(total?.c || 0)} رکورد</p></div>
    <div class="card table-card"><table><thead><tr><th>نجوا</th><th>کاربر</th><th>نام</th><th>تاریخ</th></tr></thead><tbody>
      ${(rows.results || []).length === 0 ? `<tr><td colspan="4" class="empty-state">${icon("peek", 32)}<p>خالی</p></td></tr>` :
        (rows.results || []).map(p => `<tr><td class="mono">${esc(p.whisper_id)}</td><td class="mono">${p.user_id}</td><td>${p.username ? "@" + esc(p.username) : esc(p.first_name || "—")}</td><td>${formatDate(p.peeked_at)}</td></tr>`).join("")}
    </tbody></table></div>
    ${renderPagination(page, totalPages, "/admin/peepers", "")}
  `, "peepers", session.csrf));
}

async function renderReports(env, url, session) {
  const page = Math.max(1, parseInt(url.searchParams.get("page") || "1", 10));
  const perPage = 100;
  const offset = (page - 1) * perPage;
  const rows = await env.DB.prepare(`SELECT r.*, w.text as whisper_text, w.status as whisper_status, w.sender_id FROM reports r LEFT JOIN whispers w ON r.whisper_id = w.id ORDER BY r.created_at DESC LIMIT ${perPage} OFFSET ${offset}`).all();
  const total = await env.DB.prepare("SELECT COUNT(*) as c FROM reports").first();
  const totalPages = Math.ceil((total?.c || 0) / perPage);

  return htmlResponse(layout("گزارش‌ها", `
    <div class="page-header"><h1>گزارش‌ها</h1><p class="subtitle">${formatNumber(total?.c || 0)} گزارش</p></div>
    <div class="card table-card"><table><thead><tr><th>نجوا</th><th>محتوا</th><th>فرستنده اصلی</th><th>گزارش‌دهنده</th><th>وضعیت نجوا</th><th>تاریخ</th></tr></thead><tbody>
      ${(rows.results || []).length === 0 ? `<tr><td colspan="6" class="empty-state">${icon("report", 32)}<p>خالی</p></td></tr>` :
        (rows.results || []).map(r => `<tr><td class="mono">${esc(r.whisper_id)}</td><td>${esc((r.whisper_text || "").slice(0, 50))}</td><td class="mono">${r.sender_id}</td><td class="mono">${r.reporter_id}</td><td><span class="badge badge-${r.whisper_status || ''}">${r.whisper_status || "?"}</span></td><td>${formatDate(r.created_at)}</td></tr>`).join("")}
    </tbody></table></div>
    ${renderPagination(page, totalPages, "/admin/reports", "")}
  `, "reports", session.csrf));
}

async function renderBlocks(env, url, session) {
  const page = Math.max(1, parseInt(url.searchParams.get("page") || "1", 10));
  const perPage = 100;
  const offset = (page - 1) * perPage;
  const rows = await env.DB.prepare(`SELECT * FROM blocks ORDER BY created_at DESC LIMIT ${perPage} OFFSET ${offset}`).all();
  const total = await env.DB.prepare("SELECT COUNT(*) as c FROM blocks").first();
  const totalPages = Math.ceil((total?.c || 0) / perPage);

  return htmlResponse(layout("بلاک‌ها", `
    <div class="page-header"><h1>بلاک‌ها</h1><p class="subtitle">${formatNumber(total?.c || 0)} رکورد</p></div>
    <div class="card table-card"><table><thead><tr><th>کاربر</th><th>بلاک‌شده</th><th>تاریخ</th></tr></thead><tbody>
      ${(rows.results || []).length === 0 ? `<tr><td colspan="3" class="empty-state">${icon("block", 32)}<p>خالی</p></td></tr>` :
        (rows.results || []).map(b => `<tr><td class="mono">${b.user_id}</td><td class="mono">${b.blocked_id}</td><td>${formatDate(b.created_at)}</td></tr>`).join("")}
    </tbody></table></div>
    ${renderPagination(page, totalPages, "/admin/blocks", "")}
  `, "blocks", session.csrf));
}

async function renderMedia(env, url, session) {
  const page = Math.max(1, parseInt(url.searchParams.get("page") || "1", 10));
  const perPage = 50;
  const offset = (page - 1) * perPage;
  const rows = await env.DB.prepare(`SELECT * FROM user_media ORDER BY created_at DESC LIMIT ${perPage} OFFSET ${offset}`).all();
  const total = await env.DB.prepare("SELECT COUNT(*) as c FROM user_media").first();
  const totalPages = Math.ceil((total?.c || 0) / perPage);
  const error = url.searchParams.get("error");

  return htmlResponse(layout("مدیاها", `
    <div class="page-header"><h1>مدیای کاربران</h1><p class="subtitle">${formatNumber(total?.c || 0)} رکورد</p></div>
    ${error ? `<div class="alert alert-error">${icon("warning", 18)}<span>${esc(error)}</span></div>` : ""}
    <div class="card table-card"><table><thead><tr><th>کد</th><th>کاربر</th><th>نوع</th><th>تاریخ</th><th></th></tr></thead><tbody>
      ${(rows.results || []).length === 0 ? `<tr><td colspan="5" class="empty-state">${icon("database", 32)}<p>خالی</p></td></tr>` :
        (rows.results || []).map(m => `<tr><td class="mono">${esc(m.code)}</td><td class="mono">${m.user_id}</td><td>${esc(m.media_type)}</td><td>${formatDate(m.created_at)}</td><td><form method="POST" data-confirm="حذف شود؟"><input type="hidden" name="csrf" value="${session.csrf}"><input type="hidden" name="action" value="delete_media"><input type="hidden" name="code" value="${esc(m.code)}"><button class="btn btn-small btn-danger">${icon("trash", 14)} حذف</button></form></td></tr>`).join("")}
    </tbody></table></div>
    ${renderPagination(page, totalPages, "/admin/media", "")}
  `, "media", session.csrf));
}

async function handleMediaPost(request, env, session) {
  const form = await request.formData();
  const action = String(form.get("action") || "");
  if (action === "delete_media") {
    const code = String(form.get("code") || "");
    const inUse = await env.DB.prepare("SELECT 1 FROM whispers WHERE media_code = ? AND status = 'active'").bind(code).first();
    if (inUse) {
      return redirect("/admin/media?error=" + encodeURIComponent("این مدیا در یک نجوای فعال استفاده می‌شود و قابل حذف نیست"));
    }
    await env.DB.prepare("DELETE FROM user_media WHERE code = ?").bind(code).run();
    await logAdminAction(env, session, "delete_media", code);
  }
  return redirect("/admin/media?saved=1");
}

async function renderSettings(env, session) {
  const s = await getAllSettings(env);
  const toggle = (key, label, desc) => {
    const isOn = s[key] === "1";
    return `<div class="setting-row"><div><strong>${label}</strong><p>${desc}</p></div><form method="POST" action="/admin/settings"><input type="hidden" name="csrf" value="${session.csrf}"><input type="hidden" name="action" value="toggle"><input type="hidden" name="key" value="${key}"><button class="btn ${isOn ? "btn-success" : "btn-danger"}" style="min-width:80px;">${isOn ? "✅ فعال" : "❌ غیرفعال"}</button></form></div>`;
  };
  const numeric = (key, label, desc) => `<div class="setting-row"><div><strong>${label}</strong><p>${desc}</p></div><form method="POST" action="/admin/settings" style="display:flex;gap:.5rem;align-items:center"><input type="hidden" name="csrf" value="${session.csrf}"><input type="hidden" name="action" value="numeric"><input type="hidden" name="key" value="${key}"><input type="number" name="value" value="${esc(s[key] || "")}" style="width:100px;margin:0"><button class="btn">ذخیره</button></form></div>`;

  return htmlResponse(layout("تنظیمات", `
    <div class="page-header"><h1>تنظیمات ربات</h1></div>
    <div class="card"><h2>${icon("settings")} عمومی</h2>
      ${toggle("force_start", "استارت اجباری", "کاربر قبل از ارسال نجوا باید /start بزند")}
      ${toggle("ads_enabled", "تبلیغات", "نمایش دکمه و تصویر تبلیغاتی")}
      ${toggle("maintenance_mode", "حالت تعمیرات", "غیرفعال کردن ربات برای کاربران عادی")}
      ${toggle("require_start_for_reply", "استارت برای پاسخ", "گیرنده برای پاسخ باید استارت کرده باشد")}
      ${toggle("announce_replies", "اعلان پاسخ", "نمایش هدر «پاسخ جدید» در تحویل پاسخ")}
      ${toggle("reply_keyboard_enabled", "کیبورد پایدار", "نمایش Reply Keyboard")}
    </div>
    <div class="card"><h2>${icon("admin")} تنظیمات VIP و مدیا</h2>
      ${toggle("vip_media_enabled", "ارسال مدیا برای VIP", "آیا کاربران VIP می‌توانند نجوای مدیا بفرستند؟")}
      ${toggle("vip_bypass_ads", "معافیت از تبلیغات برای VIP", "آیا کاربران VIP تبلیغات را نمی‌بینند؟")}
      ${toggle("vip_bypass_forcejoin", "معافیت از جوین اجباری برای VIP", "آیا کاربران VIP نیازی به عضویت در کانال ندارند؟")}
      ${toggle("media_photo_enabled", "ارسال عکس", "فعال بودن ارسال عکس")}
      ${toggle("media_video_enabled", "ارسال ویدیو", "فعال بودن ارسال ویدیو")}
      ${toggle("media_document_enabled", "ارسال فایل", "فعال بودن ارسال فایل")}
      ${toggle("media_audio_enabled", "ارسال صدا", "فعال بودن ارسال صدا")}
      ${toggle("media_voice_enabled", "ارسال ویس", "فعال بودن ارسال ویس")}
      ${toggle("media_animation_enabled", "ارسال گیف", "فعال بودن ارسال گیف")}
      ${toggle("media_sticker_enabled", "ارسال استیکر", "فعال بودن ارسال استیکر")}
    </div>
    <div class="card"><h2>${icon("clock")} مقادیر عددی</h2>
      ${numeric("whisper_ttl_days", "انقضای نجوا (روز)", "بعد از این مدت نجوا منقضی می‌شود")}
      ${numeric("max_whisper_length", "حداکثر طول پیام", "بیشترین کاراکتر مجاز")}
      ${numeric("log_retention_days", "نگهداری لاگ (روز)", "لاگ‌های قدیمی‌تر پاک می‌شوند")}
      ${numeric("auto_backup_days", "بکاپ خودکار (روز)", "فاصله بین بکاپ‌های خودکار")}
    </div>
    <div class="card"><h2>${icon("warning")} سیستم گزارش و بن</h2>
      ${numeric("max_reports_before_ban", "حداکثر گزارش مجاز", "بعد از این تعداد گزارش، کاربر بن می‌شود")}
      ${numeric("ban_duration_hours", "مدت بن (ساعت)", "کاربر به مدت چند ساعت بن شود")}
      ${numeric("vip_rate_limit", "سقف ارسال VIP (ساعت)", "حداکثر نجوا در ساعت برای کاربران VIP")}
    </div>
    <div class="card"><h2>${icon("lock")} جوین اجباری (Force Join)</h2>
      <p style="color:var(--text-muted);font-size:.9rem;margin-bottom:1rem">آیدی کانال‌هایی که کاربر باید در آن‌ها عضو باشد را با کاما (,) جدا کنید. (مثال: @channel1,@channel2) - ربات باید در آن کانال‌ها ادمین باشد.</p>
      <form method="POST" action="/admin/settings">
        <input type="hidden" name="csrf" value="${session.csrf}">
        <input type="hidden" name="action" value="force_join">
        <input type="text" name="force_join_channels" value="${esc(s.force_join_channels || "")}" placeholder="@my_channel">
        <button class="btn btn-primary">ذخیره</button>
      </form>
    </div>
    <div class="card"><h2>${icon("globe")} زبان پیش‌فرض</h2>
      <form method="POST" action="/admin/settings" class="inline-form">
        <input type="hidden" name="csrf" value="${session.csrf}">
        <input type="hidden" name="action" value="lang">
        <select name="lang" style="flex:1;margin:0">
          <option value="fa" ${s.language === "fa" ? "selected" : ""}>فارسی</option>
          <option value="en" ${s.language === "en" ? "selected" : ""}>English</option>
        </select>
        <button class="btn btn-primary">ذخیره</button>
      </form>
    </div>
  `, "settings", session.csrf));
}

async function renderAds(env, session, url) {
  const s = await getAllSettings(env);
  return htmlResponse(layout("تبلیغات", `
    <div class="page-header"><h1>تبلیغات</h1></div>
    ${url.searchParams.get("saved") ? `<div class="alert alert-success">${icon("check", 18)}<span>ذخیره شد</span></div>` : ""}
    ${url.searchParams.get("error") ? `<div class="alert alert-error">${icon("warning", 18)}<span>${esc(url.searchParams.get("error"))}</span></div>` : ""}
    <div class="card">
      <form method="POST" action="/admin/ads">
        <input type="hidden" name="csrf" value="${session.csrf}">
        <label>متن دکمه تبلیغ</label>
        <input type="text" name="ads_text" value="${esc(s.ads_text || "")}" maxlength="200">
        <label>لینک دکمه</label>
        <input type="url" name="ads_url" value="${esc(s.ads_url || "")}" placeholder="https://t.me/channel">
        <label>URL تصویر تبلیغ</label>
        <input type="url" name="ads_image_url" value="${esc(s.ads_image_url || "")}" placeholder="https://example.com/banner.jpg">
        <label><input type="checkbox" name="test_image" value="1"> تست تصویر</label>
        ${s.ads_image_url ? `<div class="image-preview"><p style="color:var(--text-muted);font-size:.9rem;margin-top:.5rem">پیش‌نمایش:</p><img src="${esc(s.ads_image_url)}" onerror="this.style.display='none'"></div>` : ""}
        <button class="btn btn-primary" style="margin-top:1rem">${icon("check")} ذخیره</button>
      </form>
      <p style="color:var(--text-muted);font-size:.9rem;margin-top:1rem">وضعیت: ${s.ads_enabled === "1" ? "✅ فعال" : "❌ غیرفعال"}</p>
    </div>
  `, "ads", session.csrf));
}

async function renderAdmins(env, url, session) {
  const admins = await env.DB.prepare(`SELECT a.user_id, u.username, u.first_name, a.added_at FROM admins a LEFT JOIN users u ON a.user_id = u.user_id ORDER BY a.added_at DESC`).all();
  const webAdmins = await env.DB.prepare(`SELECT username, created_at FROM web_admins ORDER BY created_at DESC`).all();
  const error = url.searchParams.get("error");

  return htmlResponse(layout("مدیران", `
    <div class="page-header"><h1>مدیران</h1></div>
    ${error ? `<div class="alert alert-error">${icon("warning", 18)}<span>${esc(error)}</span></div>` : ""}
    
    <div class="card"><h2>${icon("admin")} مدیران تلگرام (دسترسی به ربات)</h2>
      <form method="POST" action="/admin/admins" class="inline-form">
        <input type="hidden" name="csrf" value="${session.csrf}">
        <input type="hidden" name="action" value="add_tg">
        <input type="number" name="user_id" placeholder="آیدی عددی" required>
        <button class="btn btn-primary">${icon("plus")} افزودن</button>
      </form>
      <div class="table-card" style="margin-top:1rem">
        <table><thead><tr><th>آیدی</th><th>نام</th><th>یوزرنیم</th><th>تاریخ</th><th></th></tr></thead><tbody>
          ${(admins.results || []).length === 0 ? `<tr><td colspan="5" class="empty-state"><p>هیچ مدیری تعریف نشده</p></td></tr>` :
            (admins.results || []).map(a => `<tr><td class="mono">${a.user_id}</td><td>${esc(a.first_name || "—")}</td><td>${a.username ? "@" + esc(a.username) : "—"}</td><td>${formatDate(a.added_at)}</td><td><form method="POST" data-confirm="حذف شود؟"><input type="hidden" name="csrf" value="${session.csrf}"><input type="hidden" name="action" value="remove_tg"><input type="hidden" name="user_id" value="${a.user_id}"><button class="btn btn-small btn-danger">${icon("trash", 14)} حذف</button></form></td></tr>`).join("")}
        </tbody></table>
      </div>
    </div>

    <div class="card"><h2>${icon("users")} مدیران وب (دسترسی به پنل)</h2>
      <form method="POST" action="/admin/admins" class="inline-form">
        <input type="hidden" name="csrf" value="${session.csrf}">
        <input type="hidden" name="action" value="add_web">
        <input type="text" name="web_username" placeholder="نام کاربری جدید" required>
        <input type="password" name="web_password" placeholder="رمز عبور" required>
        <button class="btn btn-primary">${icon("plus")} افزودن</button>
      </form>
      <div class="table-card" style="margin-top:1rem">
        <table><thead><tr><th>نام کاربری</th><th>تاریخ ایجاد</th><th></th></tr></thead><tbody>
          ${(webAdmins.results || []).length === 0 ? `<tr><td colspan="3" class="empty-state"><p>هیچ مدیر وبی تعریف نشده</p></td></tr>` :
            (webAdmins.results || []).map(w => `<tr><td class="mono">${esc(w.username)}</td><td>${formatDate(w.created_at)}</td><td><form method="POST" data-confirm="حذف شود؟"><input type="hidden" name="csrf" value="${session.csrf}"><input type="hidden" name="action" value="remove_web"><input type="hidden" name="web_username" value="${esc(w.username)}"><button class="btn btn-small btn-danger">${icon("trash", 14)} حذف</button></form></td></tr>`).join("")}
        </tbody></table>
      </div>
    </div>
  `, "admins", session.csrf));
}

async function renderWebhook(env, url, session) {
  const info = await tgApi(env, "getWebhookInfo", {});
  const wh = info.result || {};
  const currentUrl = `${url.origin}/webhook`;
  return htmlResponse(layout("Webhook", `
    <div class="page-header"><h1>مدیریت Webhook</h1></div>
    ${url.searchParams.get("saved") ? `<div class="alert alert-success">${icon("check", 18)}<span>انجام شد</span></div>` : ""}
    ${url.searchParams.get("tested") ? `<div class="alert alert-success">${icon("check", 18)}<span>تست ارسال شد</span></div>` : ""}
    ${url.searchParams.get("error") ? `<div class="alert alert-error">${icon("warning", 18)}<span>${esc(url.searchParams.get("error"))}</span></div>` : ""}
    <div class="card"><h2>${icon("webhook")} وضعیت</h2>
      <div class="kv"><span>URL ثبت‌شده</span><strong class="mono">${wh.url ? esc(wh.url) : "— تنظیم نشده —"}</strong></div>
      <div class="kv"><span>URL پیشنهادی</span><strong class="mono">${esc(currentUrl)}</strong></div>
      <div class="kv"><span>آخرین خطا</span><strong>${wh.last_error_message ? esc(wh.last_error_message) : "بدون خطا"}</strong></div>
      <div class="kv"><span>آپدیت معلق</span><strong>${wh.pending_update_count || 0}</strong></div>
    </div>
    <div class="card"><h2>${icon("settings")} عملیات</h2>
      <div class="button-row">
        <form method="POST"><input type="hidden" name="csrf" value="${session.csrf}"><input type="hidden" name="action" value="set"><button class="btn btn-primary">${icon("check")} ثبت Webhook</button></form>
        <form method="POST" data-confirm="حذف شود؟"><input type="hidden" name="csrf" value="${session.csrf}"><input type="hidden" name="action" value="delete"><button class="btn btn-danger">${icon("trash")} حذف</button></form>
        <form method="POST"><input type="hidden" name="csrf" value="${session.csrf}"><input type="hidden" name="action" value="test_send"><button class="btn">${icon("broadcast")} پیام تست</button></form>
      </div>
    </div>
  `, "webhook", session.csrf));
}

async function renderBroadcast(env, session) {
  const history = await env.DB.prepare("SELECT * FROM broadcasts ORDER BY sent_at DESC LIMIT 20").all();
  const hasQueue = !!env.BROADCAST_QUEUE;
  return htmlResponse(layout("ارسال همگانی", `
    <div class="page-header"><h1>ارسال همگانی</h1></div>
    ${hasQueue ? `<div class="alert alert-success">${icon("check", 18)}<span>Queue فعال — ارسال سریع</span></div>` : `<div class="alert alert-warning">${icon("warning", 18)}<span>Queue تنظیم نشده — ارسال تدریجی از Cron</span></div>`}
    <div class="card"><h2>${icon("broadcast")} ارسال جدید</h2>
      <form method="POST" action="/admin/broadcast">
        <input type="hidden" name="csrf" value="${session.csrf}">
        <label>متن پیام</label>
        <textarea name="text" rows="5" maxlength="4000" required></textarea>
        <label>زمان‌بندی (اختیاری)</label>
        <input type="datetime-local" name="schedule_at">
        <button class="btn btn-primary">${icon("broadcast")} شروع</button>
      </form>
    </div>
    <div class="card"><h2>${icon("clock")} تاریخچه</h2>
      <div class="table-card"><table><thead><tr><th>متن</th><th>پیشرفت</th><th>وضعیت</th><th>تاریخ</th></tr></thead><tbody>
        ${(history.results || []).length === 0 ? `<tr><td colspan="4" class="empty-state"><p>خالی</p></td></tr>` :
          (history.results || []).map(b => `<tr><td>${esc((b.text || "").slice(0, 60))}</td><td class="mono">${b.cursor_offset || 0} / ${b.total_count || 0} (${b.recipients} ✓)</td><td><span class="badge badge-${b.status}">${b.status}</span></td><td>${formatDate(b.sent_at)}</td></tr>`).join("")}
      </tbody></table></div>
    </div>
  `, "broadcast", session.csrf));
}

async function renderLogs(env, url, session) {
  const page = Math.max(1, parseInt(url.searchParams.get("page") || "1", 10));
  const perPage = 100;
  const offset = (page - 1) * perPage;
  const rows = await env.DB.prepare(`SELECT * FROM admin_logs ORDER BY created_at DESC LIMIT ${perPage} OFFSET ${offset}`).all();
  const total = await env.DB.prepare("SELECT COUNT(*) as c FROM admin_logs").first();
  const totalPages = Math.ceil((total?.c || 0) / perPage);

  return htmlResponse(layout("لاگ‌ها", `
    <div class="page-header"><h1>لاگ‌های مدیریتی</h1><p class="subtitle">${formatNumber(total?.c || 0)} رکورد</p></div>

    <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
      <div class="button-row" style="margin:0">
        <a href="/admin/logs/download" class="btn btn-primary">${icon("download")} دانلود JSON</a>
        <form method="POST" data-confirm="تمام لاگ‌ها پاک شوند؟"><input type="hidden" name="csrf" value="${session.csrf}"><input type="hidden" name="action" value="clear"><button class="btn btn-danger">${icon("trash")} پاکسازی لاگ‌ها</button></form>
      </div>
    </div>

    <div class="card table-card"><table><thead><tr><th>منبع</th><th>IP</th><th>عملیات</th><th>جزئیات</th><th>تاریخ</th></tr></thead><tbody>
      ${(rows.results || []).length === 0 ? `<tr><td colspan="5" class="empty-state">${icon("logs", 32)}<p>خالی</p></td></tr>` :
        (rows.results || []).map(l => `<tr><td class="mono">${l.admin_id === 0 ? "web" : l.admin_id}</td><td class="mono">${esc(l.ip || "—")}</td><td>${esc(l.action)}</td><td class="mono">${esc((l.details || "").slice(0, 60))}</td><td>${formatDate(l.created_at)}</td></tr>`).join("")}
    </tbody></table></div>
    ${renderPagination(page, totalPages, "/admin/logs", "")}
  `, "logs", session.csrf));
}

async function renderBackup(env, url, session) {
  const s = await getAllSettings(env);
  const stats = await getDetailedStats(env);
  const restored = url.searchParams.get("restored");
  const error = url.searchParams.get("error");
  const saved = url.searchParams.get("saved");
  let summary = null;
  try { const sum = url.searchParams.get("summary"); if (sum) summary = JSON.parse(sum); } catch {}

  const tables = [
    { name: "users", label: "کاربران", count: stats.users },
    { name: "whispers", label: "نجواها", count: stats.whispers },
    { name: "replies", label: "پاسخ‌ها", count: stats.replies },
    { name: "peepers", label: "فضول‌ها", count: stats.peepers },
    { name: "reports", label: "گزارش‌ها", count: stats.reports },
    { name: "admins", label: "مدیران", count: null },
    { name: "blocks", label: "بلاک‌ها", count: null },
    { name: "settings", label: "تنظیمات", count: null },
    { name: "user_settings", label: "تنظیمات کاربران", count: null },
    { name: "user_media", label: "مدیای کاربران", count: null },
    { name: "broadcasts", label: "ارسال‌ها", count: null },
    { name: "admin_logs", label: "لاگ‌ها", count: null }
  ];

  return htmlResponse(layout("پشتیبان‌گیری", `
    <div class="page-header"><h1>پشتیبان‌گیری و بازیابی</h1></div>
    ${restored ? `<div class="alert alert-success">${icon("check", 18)}<span>ریستور انجام شد</span></div>` : ""}
    ${saved ? `<div class="alert alert-success">${icon("check", 18)}<span>ذخیره شد</span></div>` : ""}
    ${error ? `<div class="alert alert-error">${icon("warning", 18)}<span>${esc(error)}</span></div>` : ""}
    ${summary ? `<div class="card"><h2>نتیجه ریستور</h2>${Object.entries(summary).map(([t, r]) => `<div class="kv"><span>${t}</span><strong>${r.inserted || 0} درج / ${r.failed || 0} خطا${r.error ? ` — ${esc(r.error)}` : ""}</strong></div>`).join("")}</div>` : ""}
    <div class="alert alert-warning">${icon("warning", 18)}<span>توجه: <code>file_id</code> مدیا مخصوص هر ربات است. بکاپ از ربات A در ربات B مدیاها را نشان نمی‌دهد.</span></div>

    <div class="card"><h2>${icon("download")} خروجی</h2>
      <form method="POST" action="/admin/backup">
        <input type="hidden" name="csrf" value="${session.csrf}">
        <input type="hidden" name="action" value="export">
        <div class="checkbox-grid">${tables.map(t => `<label><input type="checkbox" name="tables" value="${t.name}" checked> ${t.label} ${t.count !== null ? `<span class="mono">(${formatNumber(t.count)})</span>` : ""}</label>`).join("")}</div>
        <button class="btn btn-primary">${icon("download")} دانلود JSON</button>
      </form>
    </div>

    <div class="card"><h2>${icon("upload")} بازیابی</h2>
      <form method="POST" action="/admin/backup?csrf=${session.csrf}" enctype="multipart/form-data" data-confirm="از انجام ریستور مطمئنید؟">
        <input type="hidden" name="csrf" value="${session.csrf}">
        <input type="hidden" name="action" value="import">
        <label>فایل JSON</label>
        <input type="file" name="backup_file" accept=".json,application/json" required>
        <label>حالت</label>
        <select name="mode">
          <option value="merge">ادغام</option>
          <option value="replace">جایگزینی (Safety backup در KV)</option>
        </select>
        <button class="btn btn-primary" style="margin-top:1rem">${icon("upload")} ریستور</button>
      </form>
    </div>

    <div class="card"><h2>${icon("refresh")} بکاپ خودکار</h2>
      <div class="setting-row">
        <div><strong>فعال‌سازی</strong><p>روزانه از طریق Cron</p></div>
        <form method="POST" action="/admin/backup">
          <input type="hidden" name="csrf" value="${session.csrf}">
          <input type="hidden" name="action" value="auto_toggle">
          <button class="btn ${s.auto_backup_enabled === "1" ? "btn-danger" : "btn-success"}">${s.auto_backup_enabled === "1" ? "خاموش" : "روشن"}</button>
        </form>
      </div>
    </div>
  `, "backup", session.csrf));
}

async function renderCleanup(env, url, session) {
  const stats = await getDetailedStats(env);
  const saved = url.searchParams.get("saved");
  const inlineForm = (action, label, days, danger = true) => `<form method="POST" action="/admin/cleanup" class="inline-form" ${danger ? 'data-confirm="آیا مطمئنید؟"' : ""}><input type="hidden" name="csrf" value="${session.csrf}"><input type="hidden" name="action" value="${action}"><label>${label}</label><input type="number" name="days" value="${days}" style="width:100px"><span>روز</span><button class="btn ${danger ? "btn-danger" : "btn-primary"}">اجرا</button></form>`;

  return htmlResponse(layout("پاکسازی", `
    <div class="page-header"><h1>پاکسازی و سبک‌سازی</h1></div>
    ${saved ? `<div class="alert alert-success">${icon("check", 18)}<span>انجام شد</span></div>` : ""}
    <div class="card"><h2>${icon("database")} آمار فعلی</h2>
      <div class="kv"><span>کاربران</span><strong>${formatNumber(stats.users)}</strong></div>
      <div class="kv"><span>نجواها</span><strong>${formatNumber(stats.whispers)}</strong></div>
      <div class="kv"><span>پاسخ‌ها</span><strong>${formatNumber(stats.replies)}</strong></div>
      <div class="kv"><span>فضول‌ها</span><strong>${formatNumber(stats.peepers)}</strong></div>
      <div class="kv"><span>گزارش‌ها</span><strong>${formatNumber(stats.reports)}</strong></div>
    </div>
    <div class="card"><h2>${icon("cleanup")} پاکسازی کامل</h2>
      <p style="color:var(--text-muted);font-size:.95rem;margin-bottom:1rem">انقضا، حذف داده‌های قدیمی، پاکسازی مدیاهای بی‌استفاده، بهینه‌سازی</p>
      <form method="POST" action="/admin/cleanup" data-confirm="پاکسازی کامل انجام شود؟"><input type="hidden" name="csrf" value="${session.csrf}"><input type="hidden" name="action" value="full_cleanup"><button class="btn btn-primary">${icon("cleanup")} اجرا</button></form>
    </div>
    <div class="card"><h2>${icon("trash")} حذف موارد خاص</h2>
      ${inlineForm("delete_old_whispers", "نجواهای غیرفعال قدیمی‌تر از", 30)}
      ${inlineForm("delete_old_peepers", "فضول‌های قدیمی‌تر از", 30)}
      ${inlineForm("delete_old_replies", "پاسخ‌های قدیمی‌تر از", 30)}
      ${inlineForm("delete_inactive_users", "کاربران غیرفعال بیش از", 180)}
      ${inlineForm("delete_old_logs", "لاگ‌های قدیمی‌تر از", 30)}
      ${inlineForm("delete_finished_broadcasts", "ارسال‌های تمام‌شده قدیمی‌تر از", 30)}
    </div>
    <div class="card"><h2>${icon("refresh")} عملیات سبک</h2>
      <div class="button-row">
        <form method="POST" action="/admin/cleanup"><input type="hidden" name="csrf" value="${session.csrf}"><button name="action" value="delete_pending" class="btn">پاک pending_whispers</button></form>
        <form method="POST" action="/admin/cleanup"><input type="hidden" name="csrf" value="${session.csrf}"><button name="action" value="delete_processed" class="btn">پاک processed_updates</button></form>
        <form method="POST" action="/admin/cleanup"><input type="hidden" name="csrf" value="${session.csrf}"><button name="action" value="delete_login_attempts" class="btn">پاک login_attempts</button></form>
        <form method="POST" action="/admin/cleanup"><input type="hidden" name="csrf" value="${session.csrf}"><button name="action" value="expire_whispers" class="btn">انقضای نجواها</button></form>
        <form method="POST" action="/admin/cleanup"><input type="hidden" name="csrf" value="${session.csrf}"><button name="action" value="optimize" class="btn btn-primary">ANALYZE</button></form>
      </div>
    </div>
  `, "cleanup", session.csrf));
}

async function renderTransfer(env, url, session) {
  return htmlResponse(layout("انتقال", `
    <div class="page-header"><h1>انتقال و آرشیو</h1></div>
    ${url.searchParams.get("saved") ? `<div class="alert alert-success">${icon("check", 18)}<span>انجام شد</span></div>` : ""}
    <div class="card"><h2>${icon("download")} آرشیو</h2>
      <form method="POST" action="/admin/transfer" class="inline-form"><input type="hidden" name="csrf" value="${session.csrf}"><input type="hidden" name="action" value="archive_whispers"><label>قدیمی‌تر از</label><input type="number" name="days" value="30" style="width:100px"><span>روز</span><button class="btn btn-primary">${icon("download")} دانلود</button></form>
    </div>
    <div class="card"><h2>${icon("trash")} حذف پس از آرشیو</h2>
      <form method="POST" action="/admin/transfer" class="inline-form" data-confirm="آیا مطمئنید؟"><input type="hidden" name="csrf" value="${session.csrf}"><input type="hidden" name="action" value="delete_archived"><label>حذف دائمی قدیمی‌تر از</label><input type="number" name="days" value="30" style="width:100px"><span>روز</span><button class="btn btn-danger">${icon("trash")} حذف</button></form>
    </div>
    <div class="card"><h2>${icon("transfer")} انتقال کامل</h2>
      <p style="color:var(--text-muted);font-size:.95rem">از صفحه <a href="/admin/backup" style="color:var(--primary)">پشتیبان‌گیری</a> برای دانلود کامل و ریستور در نصب مقصد استفاده کنید.</p>
    </div>
  `, "transfer", session.csrf));
}

async function renderSessions(env, session) {
  const sessions = await env.DB.prepare("SELECT ip, user_agent, logged_in_at FROM sessions_log ORDER BY logged_in_at DESC LIMIT 50").all();
  return htmlResponse(layout("نشست‌ها", `
    <div class="page-header"><h1>تاریخچه ورود</h1><p class="subtitle">آخرین ورودهای موفق به پنل وب</p></div>
    <div class="alert alert-info">${icon("shield", 18)}<span>نشست فعلی: ${esc(session.nonce || "—")} | کاربر: ${esc(session.username)} | IP: ${esc(session.ip || "—")}</span></div>
    <div class="card">
      <div class="session-list">
        ${(sessions.results || []).length === 0 ? `<div class="empty-state">${icon("sessions", 32)}<p>تاریخچه‌ای نیست</p></div>` :
          (sessions.results || []).map(s => `<div class="session-item"><span class="ip">${esc(s.ip || "—")}</span><span class="time">${formatDate(s.logged_in_at)}</span></div>`).join("")}
      </div>
    </div>
  `, "sessions", session.csrf));
}

function renderPagination(page, totalPages, basePath, search) {
  if (totalPages <= 1) return "";
  const q = search ? `&q=${encodeURIComponent(search)}` : "";
  const parts = [];
  if (page > 1) parts.push(`<a href="${basePath}?page=${page - 1}${q}" class="btn">قبلی</a>`);
  const start = Math.max(1, page - 2);
  const end = Math.min(totalPages, page + 2);
  if (start > 1) parts.push(`<a href="${basePath}?page=1${q}" class="btn">1</a>`, `<span>...</span>`);
  for (let i = start; i <= end; i++) parts.push(`<a href="${basePath}?page=${i}${q}" class="btn ${i === page ? "btn-primary" : ""}">${i}</a>`);
  if (end < totalPages) parts.push(`<span>...</span>`, `<a href="${basePath}?page=${totalPages}${q}" class="btn">${totalPages}</a>`);
  if (page < totalPages) parts.push(`<a href="${basePath}?page=${page + 1}${q}" class="btn">بعدی</a>`);
  return `<div class="pagination">${parts.join("")}</div>`;
}