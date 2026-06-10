const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const multer = require("multer");
let mammoth = null;
try { mammoth = require("mammoth"); } catch {}

loadEnv();

const EDITION = "free";
const IS_PRO = false;
const FAQ_LIMIT = null;
const FORCE_CREDIT = true;
const STORAGE_MODE = "json";
const SYS_TEXT_ENC = "UG93ZXJlZCBieSBTdGVsbGEgQ2hhdGJvdA==";
const SYS_URL_ENC = "aHR0cHM6Ly9tYXJpYXN0ZWxsYXRlY2guY29t";
const SYS_FALLBACK_TEXT = Buffer.from(["UG93ZXJl", "ZCBieSBT", "dGVsbGEg", "Q2hhdGJvdA=="].join(""), "base64").toString("utf8");
const SYS_FALLBACK_URL = Buffer.from(["aHR0cHM6", "Ly9tYXJp", "YXN0ZWxs", "YXRlY2gu", "Y29t"].join(""), "base64").toString("utf8");
const SYS_ENC_HASH_EXPECTED = "29346efb682cf766065b326caf339e427e644d2e2f04821b64e32fbd0b6e7bc6";
const SYS_VALUE_HASH_EXPECTED = "1cbeb654ecbdaa2afad4aa55a76c6e0b5de21467b0c7488714345b696ec41b8d";

function safeDecodeBase64(value) {
  try { return Buffer.from(String(value || ""), "base64").toString("utf8"); }
  catch { return ""; }
}

const SYS_ENC_HASH = crypto.createHash("sha256").update(`${SYS_TEXT_ENC}|${SYS_URL_ENC}`, "utf8").digest("hex");
const SYS_DECODED_TEXT = safeDecodeBase64(SYS_TEXT_ENC);
const SYS_DECODED_URL = safeDecodeBase64(SYS_URL_ENC);
const SYS_VALUE_HASH = crypto.createHash("sha256").update(`${SYS_DECODED_TEXT}|${SYS_DECODED_URL}`, "utf8").digest("hex");
const SYS_UNCHANGED = SYS_ENC_HASH === SYS_ENC_HASH_EXPECTED && SYS_VALUE_HASH === SYS_VALUE_HASH_EXPECTED;
const SYS_TEXT = SYS_UNCHANGED ? SYS_DECODED_TEXT : SYS_FALLBACK_TEXT;
const SYS_URL = SYS_UNCHANGED ? SYS_DECODED_URL : SYS_FALLBACK_URL;

const app = express();
const PORT = Number(process.env.PORT || 8080);
const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");
const META_FILE = path.join(DATA_DIR, "meta.json");
const SETTINGS_FILE = path.join(DATA_DIR, "settings.json");
const CATEGORIES_FILE = path.join(DATA_DIR, "categories.json");
const FAQS_FILE = path.join(DATA_DIR, "faqs.json");
const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");
const MESSAGES_FILE = path.join(DATA_DIR, "messages.json");
const LEADS_FILE = path.join(DATA_DIR, "leads.json");
const LOCK_FILE = path.join(DATA_DIR, "install.lock");
const APP_SECRET = process.env.APP_SECRET || "change-me";
const DATA_ENCRYPTION_KEY = process.env.DATA_ENCRYPTION_KEY || APP_SECRET;
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "admin123";
const IS_PRODUCTION = String(process.env.NODE_ENV || "").toLowerCase() === "production";
const TRUST_PROXY = /^(1|true|yes)$/i.test(String(process.env.TRUST_PROXY || ""));
const CSP_RELAXED = /^(1|true|yes)$/i.test(String(process.env.CSP_RELAXED || ""));
const INSTALL_MAINTENANCE_MODE = /^(1|true|yes)$/i.test(String(process.env.INSTALL_MAINTENANCE_MODE || ""));
const INSTALL_TOKEN = String(process.env.INSTALL_TOKEN || "").trim();
const REQUIRE_WIDGET_CALLER_HEADERS = !/^(0|false|no)$/i.test(String(process.env.REQUIRE_WIDGET_CALLER_HEADERS || "true"));
const ADMIN_SESSION_COOKIE = "stella_admin_session";
const loginAttempts = new Map();
const publicBuckets = new Map();

enforceStartupSecurity();

if (TRUST_PROXY) app.set("trust proxy", true);
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString("base64");
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": CSP_RELAXED
        ? ["'self'", "'unsafe-inline'"]
        : ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`],
      "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      "font-src": ["'self'", "https://fonts.gstatic.com", "data:"],
      "img-src": ["'self'", "data:", "https:"],
      "connect-src": ["'self'", "http:", "https:"],
      "object-src": ["'none'"],
      "base-uri": ["'self'"],
      "frame-ancestors": ["'self'"]
    }
  },
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("tiny"));
const ALLOWED_ORIGINS = String(process.env.CORS_ORIGINS || "").split(",").map((v) => v.trim()).filter(Boolean);
function isLocalOrigin(origin) {
  if (!origin) return true;
  return /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(origin);
}
function sanitizeWidgetDomainList(v) {
  const rawList = Array.isArray(v) ? v : String(v || "").split(/\r?\n|,/);
  const out = [];
  const seen = new Set();
  for (const item of rawList) {
    let entry = String(item || "").trim().toLowerCase();
    if (!entry) continue;
    if (/^https?:\/\//i.test(entry)) {
      try { entry = new URL(entry).origin.toLowerCase(); }
      catch { continue; }
    } else {
      entry = entry.replace(/^https?:\/\//i, "");
      entry = entry.replace(/\/.*$/, "");
      if (!entry) continue;
    }
    if (seen.has(entry)) continue;
    seen.add(entry);
    out.push(entry);
  }
  return out.slice(0, 100);
}
function getHostFromHeaderUrl(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try { return String(new URL(raw).host || "").toLowerCase(); }
  catch { return ""; }
}
function getOriginFromHeader(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try { return String(new URL(raw).origin || "").toLowerCase(); }
  catch { return ""; }
}
function matchesAllowedWidgetEntry(entry, callerOrigin, callerHost) {
  const e = String(entry || "").trim().toLowerCase();
  if (!e) return false;
  if (/^https?:\/\//i.test(e)) return !!callerOrigin && callerOrigin === e;
  if (e.startsWith("*.")) {
    const base = e.slice(2);
    return !!callerHost && (callerHost === base || callerHost.endsWith(`.${base}`));
  }
  return !!callerHost && callerHost === e;
}
function isWidgetRequestAllowed(req) {
  const db = readDb();
  const allowed = sanitizeWidgetDomainList(db?.settings?.widgetAllowedDomains);
  const policy = String(db?.settings?.widgetDomainPolicy || "open").toLowerCase();
  const callerOrigin = getOriginFromHeader(req.headers.origin) || getOriginFromHeader(req.headers.referer);
  const callerHost = getHostFromHeaderUrl(callerOrigin || req.headers.referer);
  if (REQUIRE_WIDGET_CALLER_HEADERS && !callerHost && !callerOrigin && !isLocalRequest(req)) return false;
  if (!allowed.length) return policy !== "restricted";
  if (!callerHost && !callerOrigin) return false;
  return allowed.some((entry) => matchesAllowedWidgetEntry(entry, callerOrigin, callerHost));
}
function getWidgetCaller(req) {
  const callerOrigin = getOriginFromHeader(req.headers.origin) || getOriginFromHeader(req.headers.referer);
  const callerHost = getHostFromHeaderUrl(callerOrigin || req.headers.referer);
  return { callerOrigin, callerHost };
}
function issueWidgetAuthToken(req) {
  const caller = getWidgetCaller(req);
  return sign({
    role: "widget",
    origin: caller.callerOrigin || "",
    host: caller.callerHost || "",
    exp: Date.now() + (24 * 60 * 60 * 1000)
  });
}
function requireAllowedWidgetDomain(req, res, next) {
  if (isWidgetRequestAllowed(req)) return next();
  if (req.path === "/widget.js") return res.status(403).type("text/plain").send("Widget domain is not allowed.");
  return res.status(403).json({ success: false, message: "This domain is not allowed for widget usage." });
}
function requireWidgetAuth(req, res, next) {
  const token = String(req.headers["x-stella-widget-auth"] || "").trim();
  if (!token) return res.status(403).json({ success: false, message: "Missing widget authorization." });
  const payload = verify(token);
  if (!payload || payload.role !== "widget") {
    return res.status(403).json({ success: false, message: "Invalid widget authorization." });
  }
  const caller = getWidgetCaller(req);
  const tokenOrigin = String(payload.origin || "");
  const tokenHost = String(payload.host || "");
  if (tokenOrigin) {
    if (!caller.callerOrigin || caller.callerOrigin !== tokenOrigin) {
      return res.status(403).json({ success: false, message: "Widget origin mismatch." });
    }
  } else if (tokenHost) {
    if (!caller.callerHost || caller.callerHost !== tokenHost) {
      return res.status(403).json({ success: false, message: "Widget host mismatch." });
    }
  }
  return next();
}
function corsOriginCheck(origin, cb) {
  if (!origin || isLocalOrigin(origin)) return cb(null, true);
  if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
  try {
    const settingsDomains = sanitizeWidgetDomainList(readDb()?.settings?.widgetAllowedDomains);
    if (settingsDomains.length) {
      const originHost = new URL(origin).host.toLowerCase();
      const originValue = new URL(origin).origin.toLowerCase();
      if (settingsDomains.some((entry) => matchesAllowedWidgetEntry(entry, originValue, originHost))) {
        return cb(null, true);
      }
    }
  } catch {}
  return cb(null, false);
}
app.use(cors({ origin: corsOriginCheck, credentials: false }));

function blockAdminWhenSysTampered(req, res, next) {
  if (SYS_UNCHANGED) return next();
  const p = String(req.path || "");
  const isAdminPath = p === "/admin" || p.startsWith("/admin/") || p === "/admin-style.css" || p.startsWith("/api/admin");
  if (!isAdminPath) return next();
  if (p.startsWith("/api/")) {
    return res.status(403).json({ success: false, message: "Integrity check failed. Admin is locked until original system branding is restored." });
  }
  return res.status(403).type("html").send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Integrity Lock</title><link rel="stylesheet" href="/admin-style.css"></head><body style="display:flex;min-height:100vh;align-items:center;justify-content:center;"><div class="card" style="max-width:560px;"><h2>Integrity Lock Enabled</h2><p>System branding integrity check failed. Restore original free-edition branding values to unlock admin access.</p></div></body></html>`);
}

if (!SYS_UNCHANGED) {
  console.error("[integrity] System branding tamper detected. Admin routes are locked.");
}

app.use(blockAdminWhenSysTampered);

function loadEnv() {
  const f = path.join(__dirname, ".env");
  if (!fs.existsSync(f)) return;
  const lines = fs.readFileSync(f, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const i = t.indexOf("=");
    if (i < 1) continue;
    const k = t.slice(0, i).trim();
    const v = t.slice(i + 1).trim();
    if (!process.env[k]) process.env[k] = v;
  }
}

function now() { return new Date().toISOString(); }
function uid() { return (global.crypto && crypto.randomUUID) ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`; }
function hash(v) { return crypto.createHash("sha256").update(String(v)).digest("hex"); }
const PII_ENC_PREFIX = "enc:v1:";
const PII_KEY = crypto.createHash("sha256").update(String(DATA_ENCRYPTION_KEY || ""), "utf8").digest();
function encryptPii(value) {
  const plain = String(value || "");
  if (!plain) return "";
  if (plain.startsWith(PII_ENC_PREFIX)) return plain;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", PII_KEY, iv);
  const enc = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${PII_ENC_PREFIX}${iv.toString("base64url")}.${tag.toString("base64url")}.${enc.toString("base64url")}`;
}
function decryptPii(value) {
  const input = String(value || "");
  if (!input) return "";
  if (!input.startsWith(PII_ENC_PREFIX)) return input;
  const raw = input.slice(PII_ENC_PREFIX.length);
  const parts = raw.split(".");
  if (parts.length !== 3) return "";
  try {
    const iv = Buffer.from(parts[0], "base64url");
    const tag = Buffer.from(parts[1], "base64url");
    const data = Buffer.from(parts[2], "base64url");
    const decipher = crypto.createDecipheriv("aes-256-gcm", PII_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
  } catch {
    return "";
  }
}
function htmlEscape(v) { return String(v || "").replace(/[&<>"']/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#039;" }[c])); }
function formatBotHtml(text) { return `<p>${htmlEscape(String(text || "")).replace(/\n/g,"<br>")}</p>`; }
function timingSafeTextEquals(a, b) {
  const x = Buffer.from(String(a || ""), "utf8");
  const y = Buffer.from(String(b || ""), "utf8");
  if (x.length !== y.length) return false;
  return crypto.timingSafeEqual(x, y);
}
function clientIp(req) {
  const ip = String(req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || "").trim();
  return ip || "unknown";
}
function parseCookies(req) {
  const raw = String(req.headers.cookie || "");
  const out = {};
  if (!raw) return out;
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (!k) continue;
    try { out[k] = decodeURIComponent(v); }
    catch { out[k] = v; }
  }
  return out;
}
function sendHtmlWithNonce(res, filename) {
  const file = path.join(__dirname, "public", filename);
  const html = fs.readFileSync(file, "utf8");
  const nonce = String(res.locals.cspNonce || "");
  res.type("html").send(html.replace(/__CSP_NONCE__/g, nonce));
}
function setAdminSessionCookie(res, token) {
  const maxAge = 12 * 60 * 60;
  const parts = [
    `${ADMIN_SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${maxAge}`
  ];
  if (IS_PRODUCTION) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}
function clearAdminSessionCookie(res) {
  const parts = [
    `${ADMIN_SESSION_COOKIE}=`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=0"
  ];
  if (IS_PRODUCTION) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}
function isLoopbackIp(ip) {
  const v = String(ip || "").toLowerCase();
  return v === "127.0.0.1" || v === "::1" || v === "::ffff:127.0.0.1" || v === "localhost";
}
function isLoopbackHost(host) {
  const h = String(host || "").toLowerCase();
  return h === "localhost" || h === "127.0.0.1" || h === "::1";
}
function isTrustedLocalInstallHost(req) {
  const raw = String(req.headers.host || "").trim().toLowerCase();
  if (!raw) return false;
  const hostOnly = raw.replace(/^\[|\]$/g, "").split(":")[0];
  return isLoopbackHost(hostOnly);
}
function isLocalRequest(req) {
  if (isLoopbackIp(req.ip)) return true;
  if (isLoopbackIp(req.connection?.remoteAddress)) return true;
  if (isLoopbackIp(req.socket?.remoteAddress)) return true;
  return false;
}
function isHttpsRequest(req) {
  if (req.secure) return true;
  const proto = String(req.headers["x-forwarded-proto"] || "").toLowerCase();
  return proto.split(",").map((x) => x.trim()).includes("https");
}
function sweepRateMap(map) {
  const t = Date.now();
  for (const [k, v] of map.entries()) {
    if (!v || t > Number(v.exp || 0)) map.delete(k);
  }
}
function allowByRate(map, key, max, windowMs) {
  if (map.size > 10000) sweepRateMap(map);
  const t = Date.now();
  const row = map.get(key) || { count: 0, exp: t + windowMs };
  if (t > row.exp) {
    row.count = 0;
    row.exp = t + windowMs;
  }
  row.count += 1;
  map.set(key, row);
  return row.count <= max;
}
function enforceStartupSecurity() {
  const issues = [];
  const nodeMajor = Number(String(process.versions?.node || "0").split(".")[0] || 0);
  if (!Number.isFinite(nodeMajor) || nodeMajor < 18) {
    issues.push(`Node.js ${process.versions?.node || "unknown"} detected. Use Node.js 18 or newer.`);
  }
  if (!process.env.APP_SECRET || APP_SECRET === "change-me") {
    issues.push("APP_SECRET is missing/default. Set a strong random secret.");
  }
  if (!process.env.ADMIN_USER || ADMIN_USER === "admin") {
    issues.push("ADMIN_USER is missing/default. Set a custom admin username.");
  }
  if (!process.env.ADMIN_PASS || ADMIN_PASS === "admin123") {
    issues.push("ADMIN_PASS is missing/default. Set a strong admin password.");
  }
  if (!INSTALL_TOKEN) {
    issues.push("INSTALL_TOKEN is missing. Set an installer token.");
  }
  if (!process.env.DATA_ENCRYPTION_KEY || DATA_ENCRYPTION_KEY === "change-this-to-a-strong-random-value") {
    issues.push("DATA_ENCRYPTION_KEY is missing/default. Set a dedicated encryption key.");
  }
  if (issues.length) {
    console.error("Startup blocked. Update .env before running npm start:");
    for (const issue of issues) console.error(`- ${issue}`);
    process.exit(1);
  }
}

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", APP_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}
function verify(token) {
  if (!token || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  const exp = crypto.createHmac("sha256", APP_SECRET).update(body).digest("base64url");
  if (!timingSafeTextEquals(sig, exp)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (p.exp && Date.now() > p.exp) return null;
    return p;
  } catch { return null; }
}
function adminOnly(req, res, next) {
  const bearer = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const cookies = parseCookies(req);
  const cookieToken = String(cookies[ADMIN_SESSION_COOKIE] || "");
  const t = bearer || cookieToken;
  const p = verify(t);
  if (!p || p.role !== "admin") return res.status(401).json({ success: false, message: "Unauthorized" });
  req.admin = p;
  next();
}
function adminPageOnly(req, res, next) {
  const cookies = parseCookies(req);
  const cookieToken = String(cookies[ADMIN_SESSION_COOKIE] || "");
  const p = verify(cookieToken);
  if (!p || p.role !== "admin") return res.redirect("/admin");
  req.admin = p;
  next();
}
function requireAdminCsrf(req, res, next) {
  const method = String(req.method || "GET").toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return next();
  const s = readDb().settings || {};
  if (s.enforceAdminCsrf === false) return next();
  const csrfHeader = String(req.headers["x-csrf-token"] || "");
  const csrfExpected = String(req.admin?.csrf || "");
  if (!csrfHeader || !csrfExpected || !timingSafeTextEquals(csrfHeader, csrfExpected)) {
    return res.status(403).json({ success: false, message: "Invalid CSRF token" });
  }
  next();
}
function requireHttpsIfEnabled(req, res, next) {
  if (isLocalRequest(req)) return next();
  const s = readDb().settings || {};
  if (!s.enforceHttps) return next();
  if (isHttpsRequest(req)) return next();
  return res.status(400).json({ success: false, message: "HTTPS is required by security settings." });
}

app.use(requireHttpsIfEnabled);

function defaults() {
  const categories = ["General", "Sales", "Support"].map((name) => ({ id: uid(), name, createdAt: now() }));
  const byName = Object.fromEntries(categories.map((c) => [c.name.toLowerCase(), c.id]));
  const faqs = [
    ["General","hours","What are your business hours?","Our business hours are Monday to Friday, 9:00 AM to 6:00 PM."],
    ["General","location","Where are you located?","Our office is located in the city center. Contact us for full directions."],
    ["Support","contact","How can I contact support?","You can contact support using our contact form or by email. We usually respond within one business day."],
    ["Sales","delivery","How long does delivery take?","Standard delivery usually takes 3 to 7 business days depending on your location."],
    ["Sales","shipping","Do you offer free shipping?","Yes, free shipping is available for eligible orders above our minimum cart amount."],
    ["Support","refund","What is your refund policy?","Refund requests are accepted within 14 days of purchase, subject to policy terms."],
    ["Sales","payment","What payment methods do you accept?","We accept major credit cards, debit cards, and selected online payment providers."],
    ["Sales","track","How can I track my order?","After shipping, we send a tracking link by email so you can monitor order status."],
    ["Sales","cancel","Can I cancel my order?","Yes, you can cancel before dispatch. Once shipped, cancellation may not be possible."],
    ["Support","account","Do I need an account to place an order?","No, guest checkout is available, but creating an account helps track orders."]
  ].map((r) => ({ id: uid(), categoryId: byName[r[0].toLowerCase()], keyword: r[1], question: r[2], answer: r[3], createdAt: now(), updatedAt: now() }));
  return {
    meta: { edition: EDITION, createdAt: now() },
    settings: {
      chatbotName: "Stella Assistant",
      showLivePreview: true,
      avatarUrl: "/default_avatar.jpg",
      avatarShape: "round",
      showWidget: true,
      welcomeMessage: "Welcome to Stella Assistant. How can I help you today?",
      showWelcomeMessage: true,
      showWelcomeCategories: true,
      showReturnToCategoriesLink: false,
      managedCategories: ["General","Sales","Support"],
      welcomeCategories: ["General","Sales","Support"],
      noMatchMessage: "Sorry, I could not find an exact answer to that.\nPlease try a different keyword or choose one of the suggested questions below.",
      noMatchShowSuggestions: true,

      widgetPosition: "right",
      widgetTheme: "light",
      widgetAnimation: "float",
      widgetSize: 56,
      widgetAllowedDomains: [],
      widgetDomainPolicy: "restricted",
      avatarSize: 36,
      chatboxWidth: 350,
      chatboxHeight: 480,
      chatboxBgColor: "#ffffff",
      brandColor: "#6366f1",
      leadCaptureEnabled: false,
      leadCapturePrompt: "Before we continue, please share your name and email.",
      handoffEnabled: IS_PRO,
      handoffAfterUnmatched: 3,
      handoffMessage: "I can connect you with our support team.",
      handoffUrl: "",
      handoffBusinessHours: "09:00-18:00",
      fuzzyMatchEnabled: true,
      fuzzyMatchThreshold: 60,
      aiEnabled: false,
      aiProvider: "openrouter",
      aiApiKey: "",
      aiModel: "",
      aiMaxTokens: 512,
      aiSystemPrompt: "You are a website support assistant. Reply with concise, accurate answers only about the business context.",
      aiDisclaimerEnabled: false,
      aiDisclaimerMessage: "This is an AI-generated answer and there may be errors in the answer.",
      adminPageSize: 20,
      logRetentionDays: 180,
      autoCleanupEnabled: true,
      enforceHttps: false,
      enforceAdminCsrf: true,
      deleteDataOnUninstall: false
    },
    categories,
    faqs,
    sessions: [],
    messages: [],
    leads: []
  };
}

function readJson(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    return parsed == null ? fallback : parsed;
  } catch { return fallback; }
}
function writeJson(file, value) {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `.${path.basename(file)}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`);
  const data = JSON.stringify(value, null, 2);
  fs.writeFileSync(tmp, data, "utf8");
  fs.renameSync(tmp, file);
}
function saveDbParts(db) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  writeJson(META_FILE, db.meta || {});
  writeJson(SETTINGS_FILE, db.settings || {});
  writeJson(CATEGORIES_FILE, Array.isArray(db.categories) ? db.categories : []);
  writeJson(FAQS_FILE, Array.isArray(db.faqs) ? db.faqs : []);
  writeJson(SESSIONS_FILE, Array.isArray(db.sessions) ? db.sessions : []);
  writeJson(MESSAGES_FILE, Array.isArray(db.messages) ? db.messages : []);
  writeJson(LEADS_FILE, Array.isArray(db.leads) ? db.leads : []);
}
function hasSplitFiles() {
  return fs.existsSync(META_FILE) && fs.existsSync(SETTINGS_FILE) && fs.existsSync(CATEGORIES_FILE) && fs.existsSync(FAQS_FILE) && fs.existsSync(SESSIONS_FILE) && fs.existsSync(MESSAGES_FILE) && fs.existsSync(LEADS_FILE);
}
function coerceDb(raw) {
  const seed = defaults();
  const out = {
    meta: raw && typeof raw.meta === "object" ? raw.meta : seed.meta,
    settings: { ...seed.settings, ...(raw && typeof raw.settings === "object" ? raw.settings : {}) },
    categories: Array.isArray(raw?.categories) ? raw.categories : seed.categories,
    faqs: Array.isArray(raw?.faqs) ? raw.faqs : seed.faqs,
    sessions: Array.isArray(raw?.sessions) ? raw.sessions : [],
    messages: Array.isArray(raw?.messages) ? raw.messages : [],
    leads: Array.isArray(raw?.leads) ? raw.leads : []
  };
  out.settings.welcomeMessage = normalizeWelcomeMessage(out.settings.welcomeMessage);
  out.settings.noMatchMessage = normalizeNoMatchMessage(out.settings.noMatchMessage);
  out.settings.logRetentionDays = Math.max(1, Math.min(3650, Number(out.settings.logRetentionDays || 180)));
  out.settings.autoCleanupEnabled = !!out.settings.autoCleanupEnabled;
  out.settings.enforceHttps = !!out.settings.enforceHttps;
  out.settings.enforceAdminCsrf = out.settings.enforceAdminCsrf !== false;
  delete out.settings.removeCredit;
  delete out.settings.creditText;
  delete out.settings.creditUrl;
  return out;
}
function ensureSplitStorage() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (hasSplitFiles()) return;
  let source = defaults();
  if (fs.existsSync(DB_FILE)) {
    try { source = coerceDb(JSON.parse(fs.readFileSync(DB_FILE, "utf8"))); }
    catch { source = defaults(); }
  }
  saveDbParts(source);
}
function applyRetentionPolicy(db) {
  const s = db.settings || {};
  if (!s.autoCleanupEnabled) return db;
  const days = Math.max(1, Math.min(3650, Number(s.logRetentionDays || 180)));
  const cutoffIso = new Date(Date.now() - (days * 86400000)).toISOString();
  db.messages = (db.messages || []).filter((m) => String(m.createdAt || "") >= cutoffIso);
  db.leads = (db.leads || []).filter((l) => String(l.createdAt || "") >= cutoffIso);
  const alive = new Set();
  for (const m of db.messages) alive.add(m.sessionId);
  for (const l of db.leads) alive.add(l.sessionId);
  db.sessions = (db.sessions || []).filter((sRow) => alive.has(sRow.id) || String(sRow.updatedAt || sRow.startedAt || "") >= cutoffIso);
  return db;
}
function readDb() {
  ensureSplitStorage();
  return coerceDb({
    meta: readJson(META_FILE, {}),
    settings: readJson(SETTINGS_FILE, {}),
    categories: readJson(CATEGORIES_FILE, []),
    faqs: readJson(FAQS_FILE, []),
    sessions: readJson(SESSIONS_FILE, []),
    messages: readJson(MESSAGES_FILE, []),
    leads: readJson(LEADS_FILE, [])
  });
}
let dbWriteQueue = Promise.resolve();
function writeDb(mutator) {
  const run = async () => {
    const db = readDb();
    await mutator(db);
    applyRetentionPolicy(db);
    saveDbParts(db);
    return db;
  };
  const next = dbWriteQueue.then(run, run);
  dbWriteQueue = next.then(() => undefined, () => undefined);
  return next;
}

function getSession(db, sessionKey) {
  let s = db.sessions.find((x) => x.sessionKey === sessionKey);
  if (!s) {
    s = { id: uid(), sessionKey, leadName: "", leadEmail: "", startedAt: now(), updatedAt: now() };
    db.sessions.push(s);
  }
  s.updatedAt = now();
  return s;
}

function suggestionList(db, msg, selectedCategory) {
  const terms = String(msg || "").toLowerCase().split(/\s+/).filter((x) => x.length > 1);
  const cat = db.categories.find((c) => c.name.toLowerCase() === String(selectedCategory||"").toLowerCase());
  let source = db.faqs;
  if (cat) source = source.filter((f) => f.categoryId === cat.id);
  const scored = source.map((f) => {
    const hay = `${f.keyword} ${f.question}`.toLowerCase();
    let score = 0; for (const t of terms) if (hay.includes(t)) score += 1;
    return { f, score };
  }).filter((x) => x.score > 0).sort((a,b) => b.score-a.score);
  const out = []; const seen = new Set();
  for (const row of scored) { if (out.length >= 3) break; if (seen.has(row.f.keyword.toLowerCase())) continue; seen.add(row.f.keyword.toLowerCase()); out.push({ keyword: row.f.keyword, question: row.f.question }); }
  for (const f of source) { if (out.length >= 3) break; if (seen.has(f.keyword.toLowerCase())) continue; seen.add(f.keyword.toLowerCase()); out.push({ keyword: f.keyword, question: f.question }); }
  return out;
}

function dist(a,b){const d=Array.from({length:a.length+1},()=>Array(b.length+1).fill(0));for(let i=0;i<=a.length;i++)d[i][0]=i;for(let j=0;j<=b.length;j++)d[0][j]=j;for(let i=1;i<=a.length;i++)for(let j=1;j<=b.length;j++){const c=a[i-1]===b[j-1]?0:1;d[i][j]=Math.min(d[i-1][j]+1,d[i][j-1]+1,d[i-1][j-1]+c)}return d[a.length][b.length]}
function sim(a,b){if(!a||!b)return 0;const x=dist(a,b);const m=Math.max(a.length,b.length);return ((m-x)/m)*100}
function normalizeQueryText(v) {
  return String(v || "").toLowerCase().replace(/[\s\p{P}\p{S}]+/gu, " ").trim();
}

async function aiReply(s, message, selectedCategory) {
  if (!IS_PRO || !s.aiEnabled || !s.aiApiKey || !s.aiModel) return "";
  const provider = s.aiProvider || "openrouter";
  const userMsg = selectedCategory ? `${message}\nCategory: ${selectedCategory}` : message;
  const prompt = s.aiSystemPrompt || "You are a support assistant.";
  const maxTokens = Math.max(32, Math.min(4096, Number(s.aiMaxTokens || 512)));

  if (["openai","groq","openrouter"].includes(provider)) {
    const url = provider === "openai" ? "https://api.openai.com/v1/chat/completions" : provider === "groq" ? "https://api.groq.com/openai/v1/chat/completions" : "https://openrouter.ai/api/v1/chat/completions";
    const r = await fetch(url,{method:"POST",headers:{"Content-Type":"application/json",Authorization:`Bearer ${s.aiApiKey}`},body:JSON.stringify({model:s.aiModel,temperature:0.2,max_tokens:maxTokens,messages:[{role:"system",content:prompt},{role:"user",content:userMsg}]})});
    const j = await r.json().catch(() => ({}));
    return j?.choices?.[0]?.message?.content || "";
  }
  if (provider === "anthropic") {
    const r = await fetch("https://api.anthropic.com/v1/messages",{method:"POST",headers:{"Content-Type":"application/json","x-api-key":s.aiApiKey,"anthropic-version":"2023-06-01"},body:JSON.stringify({model:s.aiModel,max_tokens:maxTokens,system:prompt,messages:[{role:"user",content:[{type:"text",text:userMsg}]}]})});
    const j = await r.json().catch(() => ({}));
    return j?.content?.[0]?.text || "";
  }
  if (provider === "google") {
    const u = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(s.aiModel)}:generateContent?key=${encodeURIComponent(s.aiApiKey)}`;
    const r = await fetch(u,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({system_instruction:{parts:[{text:prompt}]},contents:[{parts:[{text:userMsg}]}],generationConfig:{maxOutputTokens:maxTokens,temperature:0.2}})});
    const j = await r.json().catch(() => ({}));
    return j?.candidates?.[0]?.content?.parts?.[0]?.text || "";
  }
  return "";
}

function csv(v){const s=String(v??"");const n=/^[=+\-@]/.test(s)?"'"+s:s;return '"'+n.replaceAll('"','""')+'"';}
function cleanText(v, max = 5000) { return String(v || "").trim().slice(0, max); }
function normalizeCategoryName(name) {
  let out = cleanText(name, 120).normalize("NFKC");
  out = out.replace(/[\u200B-\u200D\uFEFF\u2060]/g, "");
  out = out.replace(/\s+/g, " ").trim();
  if ((out.startsWith('"') && out.endsWith('"')) || (out.startsWith("'") && out.endsWith("'"))) {
    out = out.slice(1, -1).trim();
  }
  return out;
}
function categoryKey(name) {
  return normalizeCategoryName(name).toLowerCase();
}
function mergeDuplicateCategoriesInState(state) {
  if (!state || !Array.isArray(state.categories)) return false;
  const keyToPrimary = new Map();
  const duplicateToPrimary = new Map();
  const kept = [];
  for (const c of state.categories) {
    const key = categoryKey(c && c.name);
    if (!key) continue;
    if (!keyToPrimary.has(key)) {
      const normalizedName = normalizeCategoryName(c.name);
      const row = { ...c, name: normalizedName || String(c.name || "").trim() };
      keyToPrimary.set(key, row.id);
      kept.push(row);
    } else {
      duplicateToPrimary.set(c.id, keyToPrimary.get(key));
    }
  }
  if (!duplicateToPrimary.size) return false;
  for (const f of (state.faqs || [])) {
    if (duplicateToPrimary.has(f.categoryId)) {
      f.categoryId = duplicateToPrimary.get(f.categoryId);
    }
  }
  state.categories = kept;
  state.settings = state.settings || {};
  state.settings.managedCategories = normalizeStringArray(state.settings.managedCategories || [], 200, 60).map(normalizeCategoryName);
  state.settings.welcomeCategories = normalizeStringArray(state.settings.welcomeCategories || [], 3, 60).map(normalizeCategoryName);
  return true;
}
const STD_WELCOME = "Welcome to Stella Assistant. How can I help you today?";
const STD_NO_MATCH = "Sorry, I could not find an exact answer to that.\nPlease try a different keyword or choose one of the suggested questions below.";
const STD_LEAD_PROMPT = "Before we continue, please share your name and email.";
function normalizeWelcomeMessage(v) {
  const t = String(v || "").trim();
  if (!t || /^welcome$/i.test(t)) return STD_WELCOME;
  return t;
}
function normalizeNoMatchMessage(v) {
  const t = String(v || "").trim();
  if (!t || /^no$/i.test(t) || /^no\s*match$/i.test(t)) return STD_NO_MATCH;
  return t;
}
function normalizeLeadPrompt(v) {
  const t = String(v || "").trim();
  if (!t || /^prompt$/i.test(t)) return STD_LEAD_PROMPT;
  return t;
}
function normalizeStringArray(arr, maxItems = 100, maxLen = 60) {
  if (!Array.isArray(arr)) return [];
  const out = [];
  const seen = new Set();
  for (const item of arr) {
    const val = cleanText(item, maxLen);
    if (!val) continue;
    const key = val.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(val);
    if (out.length >= maxItems) break;
  }
  return out;
}
function sanitizeAvatarUrl(value) {
  const s = cleanText(value, 250000);
  if (!s) return "";
  if (/^\/[a-z0-9/_\-.]+$/i.test(s)) return s;
  if (/^https?:\/\//i.test(s)) return s;
  if (/^data:image\/(png|jpeg|jpg|gif|webp|svg\+xml);base64,[a-z0-9+/=]+$/i.test(s)) return s;
  return "";
}
function parsePositiveInt(value, fallback, min = 1, max = 1000) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(n)));
}
function paginateArray(items, page, limit) {
  const total = items.length;
  const pages = Math.max(1, Math.ceil(total / limit));
  const safePage = Math.max(1, Math.min(page, pages));
  const start = (safePage - 1) * limit;
  const data = items.slice(start, start + limit);
  return { data, meta: { total, page: safePage, pages, limit } };
}

const FAQ_IMPORT_MAX_BYTES = 2 * 1024 * 1024;
const FAQ_IMPORT_ALLOWED_EXT = new Set([".txt", ".csv", ".csb", ".docx"]);
const faqImportUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: FAQ_IMPORT_MAX_BYTES, files: 1 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(String(file?.originalname || "")).toLowerCase();
    if (!FAQ_IMPORT_ALLOWED_EXT.has(ext)) return cb(new Error("Allowed file types: .txt, .csv, .csb, .docx"));
    cb(null, true);
  }
});

function runFaqImportUpload(req, res) {
  return new Promise((resolve, reject) => {
    faqImportUpload.single("file")(req, res, (err) => err ? reject(err) : resolve());
  });
}

function splitCsvLine(line) {
  const out = [];
  let cell = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') { cell += '"'; i += 1; }
      else inQuotes = !inQuotes;
      continue;
    }
    if (ch === "," && !inQuotes) { out.push(cell); cell = ""; continue; }
    cell += ch;
  }
  out.push(cell);
  return out.map((v) => String(v || "").trim());
}

function parseCsvFaqRows(text) {
  const lines = String(text || "").replace(/^\uFEFF/, "").split(/\r?\n/).filter((l) => String(l || "").trim());
  if (!lines.length) return [];
  const head = splitCsvLine(lines[0]).map((h) => String(h || "").trim().toLowerCase());
  const idx = {
    question: head.indexOf("question"),
    answer: head.indexOf("answer"),
    keyword: head.indexOf("keyword"),
    category: Math.max(head.indexOf("category"), head.indexOf("categoryname"))
  };
  const rows = [];
  const hasHeader = idx.question >= 0 || idx.answer >= 0 || idx.keyword >= 0 || idx.category >= 0;
  for (let i = hasHeader ? 1 : 0; i < lines.length; i++) {
    const cols = splitCsvLine(lines[i]);
    const question = idx.question >= 0 ? cols[idx.question] : cols[0];
    const answer = idx.answer >= 0 ? cols[idx.answer] : cols[1];
    const keyword = idx.keyword >= 0 ? cols[idx.keyword] : (cols[2] || "");
    const category = idx.category >= 0 ? cols[idx.category] : (cols[3] || "");
    rows.push({ question, answer, keyword, category });
  }
  return rows;
}

function parseTxtFaqRows(text) {
  const rows = [];
  const lines = String(text || "").replace(/\r/g, "").split("\n");
  let q = "";
  let a = "";
  const flush = () => {
    const qq = cleanText(q, 500);
    const aa = cleanText(a, 5000);
    if (qq && aa) rows.push({ question: qq, answer: aa, keyword: "", category: "" });
    q = ""; a = "";
  };
  for (const raw of lines) {
    const line = String(raw || "").trim();
    if (!line) { flush(); continue; }
    const qm = line.match(/^q(?:uestion)?\s*[:\-]\s*(.+)$/i);
    if (qm) { if (q && a) flush(); q = qm[1].trim(); continue; }
    const am = line.match(/^a(?:nswer)?\s*[:\-]\s*(.+)$/i);
    if (am) { a = a ? `${a}\n${am[1].trim()}` : am[1].trim(); continue; }
    if (!q && line.includes("|")) {
      const parts = line.split("|");
      if (parts.length >= 2) {
        const qq = cleanText(parts[0], 500);
        const aa = cleanText(parts.slice(1).join("|"), 5000);
        if (qq && aa) rows.push({ question: qq, answer: aa, keyword: "", category: "" });
      }
      continue;
    }
    if (q && !a) q = `${q} ${line}`.trim();
    else if (q && a) a = `${a}\n${line}`.trim();
  }
  flush();
  return rows;
}

function normalizeImportDelimiter(raw) {
  const t = String(raw || "").trim();
  if (!t) return "";
  if (t.toLowerCase() === "tab" || t === "\\t") return "\t";
  if (t.length > 3) return "";
  return t;
}

function parseDelimitedFaqRows(text, delimiter) {
  const d = normalizeImportDelimiter(delimiter);
  if (!d) return [];
  const out = [];
  const lines = String(text || "").replace(/\r/g, "").split("\n");
  for (const raw of lines) {
    const line = String(raw || "").trim();
    if (!line) continue;
    const parts = line.split(d).map((x) => cleanText(x, 5000));
    if (parts.length < 2) continue;
    const question = cleanText(parts[0], 500);
    const answer = cleanText(parts[1], 5000);
    const keyword = cleanText(parts[2], 80);
    const category = cleanText(parts[3], 120);
    if (!question || !answer) continue;
    out.push({ question, answer, keyword, category });
  }
  return out;
}

function parseAutoDelimitedFaqRows(text) {
  const candidates = [",", ":", ";", "|", "\t"];
  let best = [];
  for (const delimiter of candidates) {
    const rows = parseDelimitedFaqRows(text, delimiter);
    if (rows.length > best.length) best = rows;
  }
  return best;
}

function keywordFromQuestion(question) {
  const base = String(question || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return cleanText(base || "faq", 80);
}

function resolveImportCategoryId(db, rowCategory, chosenCategoryId) {
  if (chosenCategoryId && db.categories.find((c) => c.id === chosenCategoryId)) return chosenCategoryId;
  const catName = cleanText(rowCategory, 120).toLowerCase();
  if (!catName) return null;
  const found = db.categories.find((c) => String(c.name || "").toLowerCase() === catName);
  return found ? found.id : null;
}

async function parseFaqImportFile(file, options = {}) {
  const ext = path.extname(String(file?.originalname || "")).toLowerCase();
  if (!file?.buffer?.length) return [];
  const userDelimiter = normalizeImportDelimiter(options.delimiter || "");
  if (ext === ".docx") {
    if (!mammoth) throw new Error("DOCX support is unavailable. Install dependencies and restart.");
    const parsed = await mammoth.extractRawText({ buffer: file.buffer });
    const text = parsed.value || "";
    const delimited = parseDelimitedFaqRows(text, userDelimiter);
    if (delimited.length) return delimited;
    if (!userDelimiter) {
      const autoDelimited = parseAutoDelimitedFaqRows(text);
      if (autoDelimited.length) return autoDelimited;
    }
    return parseTxtFaqRows(text);
  }
  const text = file.buffer.toString("utf8");
  if (ext === ".csv" || ext === ".csb") return parseCsvFaqRows(text);
  const delimited = parseDelimitedFaqRows(text, userDelimiter);
  if (delimited.length) return delimited;
  if (!userDelimiter) {
    const autoDelimited = parseAutoDelimitedFaqRows(text);
    if (autoDelimited.length) return autoDelimited;
  }
  return parseTxtFaqRows(text);
}

app.get("/api/health", (req,res)=>res.json({success:true,edition:EDITION,isPro:IS_PRO,storageMode:STORAGE_MODE}));

app.post("/api/admin/login", (req,res)=>{
  const ip = clientIp(req);
  if (!allowByRate(loginAttempts, `login:${ip}`, 10, 10 * 60 * 1000)) {
    return res.status(429).json({ success: false, message: "Too many login attempts. Try again later." });
  }
  const user = String(req.body.username||"").trim();
  const pass = String(req.body.password||"").trim();
  if (!timingSafeTextEquals(user, ADMIN_USER) || !timingSafeTextEquals(hash(pass), hash(ADMIN_PASS))) {
    return res.status(401).json({success:false,message:"Invalid credentials"});
  }
  loginAttempts.delete(`login:${ip}`);
  const csrf = uid();
  const token = sign({role:"admin",user,csrf,exp:Date.now()+12*60*60*1000});
  setAdminSessionCookie(res, token);
  res.json({success:true,csrfToken:csrf});
});
app.post("/api/admin/logout", adminOnly, requireAdminCsrf, (req,res)=>{
  clearAdminSessionCookie(res);
  res.json({success:true});
});
app.get("/api/admin/csrf", adminOnly, (req,res)=>{
  res.json({success:true,data:{csrfToken:String(req.admin?.csrf || "")}});
});

app.get("/api/config", requireAllowedWidgetDomain, (req,res)=>{
  const ip = clientIp(req);
  if (!allowByRate(publicBuckets, `config:${ip}`, 240, 10 * 60 * 1000)) {
    return res.status(429).json({ success: false, message: "Too many requests. Please try again later." });
  }
  const db=readDb(); const s=db.settings;
  const creditEnabled = true;
  const allCategories = [...new Set([...(s.managedCategories||[]),...(s.welcomeCategories||[]),...db.categories.map(c=>c.name)])];
  const map={};
  for(const name of allCategories){
    const cat=db.categories.find(c=>c.name.toLowerCase()===name.toLowerCase());
    map[name]=db.faqs.filter(f=>cat && f.categoryId===cat.id).map(f=>({id:f.id,keyword:f.keyword,question:f.question}));
  }
  res.json({success:true,data:{
    edition:EDITION,chatbotName:s.chatbotName,avatarUrl:((s.avatarUrl === "/default-avatar.svg" ? "/default_avatar.jpg" : s.avatarUrl) || "/default_avatar.jpg"),avatarShape:s.avatarShape,
    showWidget:!!s.showWidget,welcomeMessage:normalizeWelcomeMessage(s.welcomeMessage),showWelcomeMessage:!!s.showWelcomeMessage,
    showWelcomeCategories:!!s.showWelcomeCategories,showReturnToCategoriesLink:!!s.showReturnToCategoriesLink,
    welcomeCategories:s.welcomeCategories||[],allCategories,faqByCategory:map,
    noMatchMessage:normalizeNoMatchMessage(s.noMatchMessage),noMatchShowSuggestions:!!s.noMatchShowSuggestions,
    creditEnabled,creditText:SYS_TEXT,creditUrl:SYS_URL,
    widgetPosition:s.widgetPosition||"right",widgetTheme:s.widgetTheme||"light",widgetAnimation:s.widgetAnimation||"float",
    widgetSize:s.widgetSize||56,avatarSize:s.avatarSize||36,chatboxWidth:s.chatboxWidth||350,chatboxHeight:s.chatboxHeight||480,chatboxBgColor:s.chatboxBgColor||"#ffffff",widgetDomainPolicy:s.widgetDomainPolicy||"open",
    leadCaptureEnabled:!!s.leadCaptureEnabled,leadCapturePrompt:normalizeLeadPrompt(s.leadCapturePrompt),
    aiDisclaimerEnabled:IS_PRO?!!s.aiDisclaimerEnabled:false,aiDisclaimerMessage:s.aiDisclaimerMessage,
    widgetAuthToken: issueWidgetAuthToken(req)
  }});
});

app.post("/api/chat/lead", requireAllowedWidgetDomain, requireWidgetAuth, async (req,res)=>{
  const ip = clientIp(req);
  if (!allowByRate(publicBuckets, `lead:${ip}`, 30, 10 * 60 * 1000)) {
    return res.status(429).json({ success: false, message: "Too many requests. Please try again later." });
  }
  const name=cleanText(req.body.name, 120);
  const email=cleanText(req.body.email, 254).toLowerCase();
  const sessionKey=cleanText(req.body.sessionKey, 120);
  if(!name||!email||!sessionKey) return res.status(400).json({success:false,message:"name/email/sessionKey required"});
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({success:false,message:"Valid email required"});
  const encName = encryptPii(name);
  const encEmail = encryptPii(email);
  await writeDb(db=>{
    const s=getSession(db,sessionKey); s.leadName=encName; s.leadEmail=encEmail;
    const e=db.leads.find(l=>l.sessionId===s.id);
    if(e){e.name=encName;e.email=encEmail;e.createdAt=now();} else db.leads.push({id:uid(),sessionId:s.id,name:encName,email:encEmail,createdAt:now()});
  });
  res.json({success:true,message:"Thanks. Your details were saved."});
});

app.post("/api/chat/query", requireAllowedWidgetDomain, requireWidgetAuth, async (req,res)=>{
  const ip = clientIp(req);
  if (!allowByRate(publicBuckets, `chat:${ip}`, 120, 10 * 60 * 1000)) {
    return res.status(429).json({ success: false, message: "Too many requests. Please try again later." });
  }
  const message=cleanText(req.body.message, 2000);
  const selectedCategory=cleanText(req.body.selectedCategory, 80);
  const pageUrl=cleanText(req.body.pageUrl, 1000);
  if(!message) return res.status(400).json({success:false,message:"Message is required"});
  const sessionKey=cleanText(req.body.sessionKey, 120) || uid();

  let answerHtml=""; let source="nomatch"; let matchedKeyword=""; let handoff=null; let aiDisclaimer=null; let suggestions=[];
  await writeDb(()=>{});
  let db=readDb();
  const s=db.settings;
  await writeDb(x=>getSession(x,sessionKey));
  db=readDb();
  const sess=db.sessions.find(x=>x.sessionKey===sessionKey);

  const msgNorm = normalizeQueryText(message);
  const selectedCat = db.categories.find((c) => c.name.toLowerCase() === selectedCategory.toLowerCase());
  const faqPool = selectedCat ? db.faqs.filter((f) => f.categoryId === selectedCat.id) : db.faqs;
  const exact=faqPool.find((f)=>{
    const kw = normalizeQueryText(f.keyword);
    const qn = normalizeQueryText(f.question);
    return kw === msgNorm || qn === msgNorm;
  });
  if(exact){
    answerHtml=formatBotHtml(exact.answer); source="faq"; matchedKeyword=exact.keyword;
  } else if (s.fuzzyMatchEnabled !== false) {
    // Free edition also uses fuzzy keyword/question matching to reduce no-match replies.
    let best=null; let score=0;
    for(const f of faqPool){
      const kw = normalizeQueryText(f.keyword);
      const qn = normalizeQueryText(f.question);
      const sc=Math.max(sim(msgNorm, kw),sim(msgNorm, qn));
      if(sc>score){score=sc;best=f;}
    }
    const threshold = Math.max(45, Math.min(95, Number(s.fuzzyMatchThreshold || 60)));
    if(best && score>=threshold){ answerHtml=formatBotHtml(best.answer); source="fuzzy"; matchedKeyword=best.keyword; }
  }

  if(!answerHtml && IS_PRO){
    try{ const ai=await aiReply(s,message,selectedCategory); if(ai){ answerHtml=formatBotHtml(ai); source="ai"; matchedKeyword="__ai__"; if(s.aiDisclaimerEnabled) aiDisclaimer=s.aiDisclaimerMessage; } }catch{}
  }

  if(!answerHtml){
    answerHtml=formatBotHtml(normalizeNoMatchMessage(s.noMatchMessage));
    source="nomatch"; matchedKeyword="";
    if(s.noMatchShowSuggestions) suggestions=suggestionList(db,message,selectedCategory);
    if(IS_PRO && s.handoffEnabled){
      const un=db.messages.filter(m=>m.sessionId===sess.id && m.isMatched===0).length + 1;
      if(un>=Number(s.handoffAfterUnmatched||3)) handoff={message:s.handoffMessage,url:s.handoffUrl,hours:s.handoffBusinessHours};
    }
  }

  await writeDb(x=>{
    const ss=x.sessions.find(t=>t.sessionKey===sessionKey);
    x.messages.push({id:uid(),sessionId:ss.id,userMessage:message,botResponse:answerHtml.replace(/<[^>]+>/g,"").slice(0,5000),matchedKeyword,isMatched:matchedKeyword?1:0,source,pageUrl,userAgent:cleanText(req.headers['user-agent']||"",255),createdAt:now()});
  });

  res.json({success:true,data:{sessionKey,answerHtml,source,matchedKeyword,suggestions:suggestions.slice(0,3),handoff,aiDisclaimer}});
});

app.get("/api/admin/overview", adminOnly, (req,res)=>{
  const db=readDb();
  const topMatched = {};
  const topUnmatched = {};
  const trend = {};
  for (const m of db.messages) {
    const day = String(m.createdAt || "").slice(0, 10);
    if (!day) continue;
    trend[day] = trend[day] || { day, total: 0, matched: 0 };
    trend[day].total += 1;
    if (m.isMatched) trend[day].matched += 1;
    if (m.isMatched && m.matchedKeyword && !String(m.matchedKeyword).startsWith("__")) topMatched[m.matchedKeyword] = (topMatched[m.matchedKeyword] || 0) + 1;
    if (!m.isMatched) topUnmatched[m.userMessage] = (topUnmatched[m.userMessage] || 0) + 1;
  }
  res.json({
    success: true,
    data: {
      edition: EDITION,
      isPro: IS_PRO,
      faqCount: db.faqs.length,
      faqLimit: FAQ_LIMIT,
      sessions: db.sessions.length,
      messages: db.messages.length,
      leads: db.leads.length,
      analytics: {
        topMatched: Object.entries(topMatched).map(([k, v]) => ({ matchedKeyword: cleanText(k, 200), total: v })).sort((a, b) => b.total - a.total).slice(0, 10),
        topUnmatched: Object.entries(topUnmatched).map(([k, v]) => ({ userMessage: cleanText(k, 300), total: v })).sort((a, b) => b.total - a.total).slice(0, 10),
        trend: Object.values(trend).map((r) => ({ day: cleanText(r.day, 20), total: Number(r.total || 0), matched: Number(r.matched || 0) })).sort((a, b) => a.day.localeCompare(b.day)).slice(-7)
      }
    }
  });
});

app.get("/api/admin/settings", adminOnly, (req,res)=>{
  const db=readDb();
  delete db.settings.removeCredit; delete db.settings.creditText; delete db.settings.creditUrl;
  const data={...db.settings};
  data.avatarUrl = (data.avatarUrl === "/default-avatar.svg" ? "/default_avatar.jpg" : data.avatarUrl) || "/default_avatar.jpg";
  data.welcomeMessage = normalizeWelcomeMessage(data.welcomeMessage);
  data.noMatchMessage = normalizeNoMatchMessage(data.noMatchMessage);
  data.leadCapturePrompt = normalizeLeadPrompt(data.leadCapturePrompt);
  data.showLivePreview = data.showLivePreview !== false;
  data.adminPageSize = parsePositiveInt(data.adminPageSize, 20, 5, 200);
  data.enforceHttps = !!data.enforceHttps;
  data.enforceAdminCsrf = data.enforceAdminCsrf !== false;
  data.widgetAllowedDomains = sanitizeWidgetDomainList(data.widgetAllowedDomains);
  data.widgetDomainPolicy = String(data.widgetDomainPolicy || "open").toLowerCase() === "restricted" ? "restricted" : "open";
  res.json({success:true,data});
});
app.get("/api/admin/security/status", adminOnly, (req,res)=>{
  const db = readDb();
  const weakSecret = !process.env.APP_SECRET || APP_SECRET === "change-me";
  const weakAdminUser = !process.env.ADMIN_USER || ADMIN_USER === "admin";
  const weakAdminPass = !process.env.ADMIN_PASS || ADMIN_PASS === "admin123";
  const missingInstallToken = !INSTALL_TOKEN;
  const weakDataKey = !process.env.DATA_ENCRYPTION_KEY || DATA_ENCRYPTION_KEY === "change-this-to-a-strong-random-value";
  const readyForProduction = !(weakSecret || weakAdminUser || weakAdminPass || missingInstallToken || weakDataKey);
  const issues = [];
  if (weakSecret) issues.push("APP_SECRET is default or missing");
  if (weakAdminUser) issues.push("ADMIN_USER is default or missing");
  if (weakAdminPass) issues.push("ADMIN_PASS is default or missing");
  if (missingInstallToken) issues.push("INSTALL_TOKEN is missing");
  if (weakDataKey) issues.push("DATA_ENCRYPTION_KEY is missing/default");
  if (String(db.settings?.widgetDomainPolicy || "open") === "open") issues.push("Widget domain policy is open");
  res.json({
    success: true,
    data: {
      isProduction: IS_PRODUCTION,
      readyForProduction,
      issues,
      widgetDomainPolicy: String(db.settings?.widgetDomainPolicy || "open"),
      cspMode: CSP_RELAXED ? "relaxed" : "strict",
      installMaintenanceMode: INSTALL_MAINTENANCE_MODE,
      message: readyForProduction ? "Security configuration is production-ready." : "Security warning: defaults are active. Do not ship to production yet."
    }
  });
});
app.post("/api/admin/settings", adminOnly, requireAdminCsrf, async (req,res)=>{
  const body = req.body || {};
  const managedCategories = normalizeStringArray(body.managedCategories, 200, 60);
  const welcomeCategoriesRaw = normalizeStringArray(body.welcomeCategories, 3, 60);
  const avatarShape = String(body.avatarShape || "round").toLowerCase() === "square" ? "square" : "round";
  const widgetPosition = String(body.widgetPosition || "right").toLowerCase() === "left" ? "left" : "right";
  const widgetAnimation = ["none", "float", "pulse", "shake"].includes(String(body.widgetAnimation || "").toLowerCase()) ? String(body.widgetAnimation).toLowerCase() : "float";
  const allowed = {
    chatbotName: cleanText(body.chatbotName, 120),
    showLivePreview: !!body.showLivePreview,
    avatarUrl: sanitizeAvatarUrl(body.avatarUrl),
    avatarShape,
    welcomeMessage: normalizeWelcomeMessage(String(body.welcomeMessage || "").slice(0, 5000)),
    noMatchMessage: normalizeNoMatchMessage(String(body.noMatchMessage || "").slice(0, 5000)),
    showWidget: !!body.showWidget,
    widgetPosition,
    widgetAnimation,
    widgetSize: Math.max(36, Math.min(120, Number(body.widgetSize || 56))),
    chatboxBgColor: /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(String(body.chatboxBgColor || "").trim()) ? String(body.chatboxBgColor).trim() : "#ffffff",
    leadCaptureEnabled: !!body.leadCaptureEnabled,
    leadCapturePrompt: normalizeLeadPrompt(String(body.leadCapturePrompt || "").slice(0, 500)),
    fuzzyMatchEnabled: !!body.fuzzyMatchEnabled,
    fuzzyMatchThreshold: Math.max(45, Math.min(95, Number(body.fuzzyMatchThreshold || 60))),
    enforceHttps: !!body.enforceHttps,
    enforceAdminCsrf: !!body.enforceAdminCsrf,
    adminPageSize: parsePositiveInt(body.adminPageSize, 20, 5, 200),
    logRetentionDays: Math.max(1, Math.min(3650, Number(body.logRetentionDays || 180))),
    autoCleanupEnabled: !!body.autoCleanupEnabled,
    showWelcomeCategories: !!body.showWelcomeCategories,
    showReturnToCategoriesLink: !!body.showReturnToCategoriesLink,
    widgetAllowedDomains: sanitizeWidgetDomainList(body.widgetAllowedDomains),
    widgetDomainPolicy: String(body.widgetDomainPolicy || "open").toLowerCase() === "restricted" ? "restricted" : "open",
    managedCategories,
    welcomeCategories: welcomeCategoriesRaw
  };
  await writeDb(db=>{
    db.settings.chatbotName = allowed.chatbotName || db.settings.chatbotName;
    db.settings.showLivePreview = allowed.showLivePreview;
    db.settings.avatarUrl = allowed.avatarUrl || db.settings.avatarUrl;
    db.settings.avatarShape = allowed.avatarShape;
    db.settings.welcomeMessage = allowed.welcomeMessage;
    db.settings.noMatchMessage = allowed.noMatchMessage;
    db.settings.showWidget = allowed.showWidget;
    db.settings.widgetPosition = allowed.widgetPosition;
    db.settings.widgetAnimation = allowed.widgetAnimation;
    db.settings.widgetSize = allowed.widgetSize;
    db.settings.chatboxBgColor = allowed.chatboxBgColor;
    db.settings.leadCaptureEnabled = allowed.leadCaptureEnabled;
    db.settings.leadCapturePrompt = allowed.leadCapturePrompt || db.settings.leadCapturePrompt;
    db.settings.fuzzyMatchEnabled = allowed.fuzzyMatchEnabled;
    db.settings.fuzzyMatchThreshold = allowed.fuzzyMatchThreshold;
    db.settings.enforceHttps = allowed.enforceHttps;
    db.settings.enforceAdminCsrf = allowed.enforceAdminCsrf;
    db.settings.adminPageSize = allowed.adminPageSize;
    db.settings.logRetentionDays = allowed.logRetentionDays;
    db.settings.autoCleanupEnabled = allowed.autoCleanupEnabled;
    db.settings.showWelcomeCategories = allowed.showWelcomeCategories;
    db.settings.showReturnToCategoriesLink = allowed.showReturnToCategoriesLink;
    db.settings.widgetAllowedDomains = allowed.widgetAllowedDomains;
    db.settings.widgetDomainPolicy = Object.prototype.hasOwnProperty.call(body, "widgetDomainPolicy")
      ? allowed.widgetDomainPolicy
      : String(db.settings.widgetDomainPolicy || "open");
    db.settings.managedCategories = allowed.managedCategories.length ? allowed.managedCategories : (db.settings.managedCategories || []);
    db.settings.welcomeCategories = allowed.welcomeCategories;
    delete db.settings.removeCredit;
    delete db.settings.creditText;
    delete db.settings.creditUrl;
    db.settings.aiEnabled = false;
    db.settings.aiApiKey = "";
    db.settings.aiModel = "";
  });
  res.json({success:true,message:"Settings saved"});
});

app.get("/api/admin/categories", adminOnly, async (req,res)=>{
  await writeDb((db) => { mergeDuplicateCategoriesInState(db); });
  res.json({success:true,data:readDb().categories});
});
app.post("/api/admin/categories", adminOnly, requireAdminCsrf, async (req,res)=>{
  const name = normalizeCategoryName(req.body.name);
  if(!name) return res.status(400).json({success:false,message:"Name required"});
  let row=null; await writeDb(db=>{if(db.categories.find(c=>categoryKey(c.name)===categoryKey(name))) return; row={id:uid(),name,createdAt:now()}; db.categories.push(row);});
  if(!row) return res.status(400).json({success:false,message:"Category already exists"});
  res.json({success:true,data:row});
});
app.delete("/api/admin/categories/:id", adminOnly, requireAdminCsrf, async (req,res)=>{
  const id = String(req.params.id || "").trim();
  if (!id) return res.status(400).json({ success:false, message:"Category id is required" });
  const db = readDb();
  const cat = db.categories.find((c) => c.id === id);
  if (!cat) return res.status(404).json({ success:false, message:"Category not found" });
  const key = categoryKey(cat.name);
  const sibling = db.categories.find((c) => c.id !== id && categoryKey(c.name) === key) || null;
  const inUseCount = db.faqs.filter((f) => f.categoryId === id).length;
  if (inUseCount > 0 && !sibling) {
    return res.status(400).json({ success:false, message:`Category is used by ${inUseCount} FAQ(s). Reassign or delete those FAQs first.` });
  }
  await writeDb((state) => {
    if (sibling) {
      for (const f of (state.faqs || [])) {
        if (f.categoryId === id) f.categoryId = sibling.id;
      }
    }
    state.categories = (state.categories || []).filter((c) => c.id !== id);
    const catName = normalizeCategoryName(cat.name);
    state.settings.managedCategories = normalizeStringArray((state.settings && state.settings.managedCategories) || [], 200, 60)
      .filter((name) => categoryKey(name) !== categoryKey(catName));
    state.settings.welcomeCategories = normalizeStringArray((state.settings && state.settings.welcomeCategories) || [], 3, 60)
      .filter((name) => categoryKey(name) !== categoryKey(catName));
  });
  const msg = sibling ? "Category merged into existing category and deleted successfully." : "Category deleted successfully.";
  res.json({ success:true, message: msg });
});

app.post("/api/admin/faqs/import", adminOnly, requireAdminCsrf, async (req,res)=>{
  try {
    await runFaqImportUpload(req, res);
    if (!req.file) return res.status(400).json({ success: false, message: "Please select a file to import." });
    const delimiter = normalizeImportDelimiter(req.body?.delimiter || "");
    const categoryMode = String(req.body?.categoryMode || "create_missing").toLowerCase() === "selected_only" ? "selected_only" : "create_missing";
    const duplicateStrategy = String(req.body?.duplicateStrategy || "suffix").toLowerCase() === "skip" ? "skip" : "suffix";
    const parsedRows = await parseFaqImportFile(req.file, { delimiter });
    if (!parsedRows.length) return res.status(400).json({ success: false, message: "No valid FAQ rows found in file." });
    const chosenCategoryId = cleanText(req.body?.categoryId, 120);
    const db = readDb();
    if (chosenCategoryId && !db.categories.find((c) => c.id === chosenCategoryId)) {
      return res.status(400).json({ success: false, message: "Selected category is invalid." });
    }
    if (categoryMode === "selected_only" && !chosenCategoryId) {
      return res.status(400).json({ success: false, message: "Please select a category for selected-only mode." });
    }
    const categoryByName = new Map(
      db.categories.map((c) => [categoryKey(c.name), c.id])
    );
    const createdCategories = [];
    const existing = new Set(db.faqs.map((f) => String(f.keyword || "").toLowerCase()));
    const staged = [];
    let rejected = 0;
    let duplicates = 0;
    const uniqueFinalKeywords = new Set();
    for (const row of parsedRows) {
      const question = cleanText(row.question, 500);
      const answer = cleanText(row.answer, 5000);
      if (!question || !answer) { rejected += 1; continue; }
      let keywordBase = cleanText(row.keyword, 80) || keywordFromQuestion(question);
      if (!keywordBase) keywordBase = `faq-${staged.length + 1}`;
      let keyword = keywordBase;
      const baseKey = keyword.toLowerCase();
      const baseDuplicate = existing.has(baseKey) || staged.find((x) => x.keyword.toLowerCase() === baseKey);
      if (baseDuplicate) {
        duplicates += 1;
        if (duplicateStrategy === "skip") {
          rejected += 1;
          continue;
        }
        let suffix = 2;
        while (existing.has(keyword.toLowerCase()) || staged.find((x) => x.keyword.toLowerCase() === keyword.toLowerCase())) {
          keyword = cleanText(`${keywordBase}-${suffix}`, 80);
          suffix += 1;
        }
      }
      let categoryId = null;
      if (categoryMode === "selected_only") {
        categoryId = chosenCategoryId;
      } else {
        const rowCategoryName = normalizeCategoryName(row.category);
        if (rowCategoryName) {
          const lookup = categoryKey(rowCategoryName);
          const existingCategoryId = categoryByName.get(lookup);
          if (existingCategoryId) {
            categoryId = existingCategoryId;
          } else {
            const newCategory = { id: uid(), name: rowCategoryName, createdAt: now() };
            db.categories.push(newCategory);
            categoryByName.set(lookup, newCategory.id);
            createdCategories.push(newCategory);
            categoryId = newCategory.id;
          }
        } else {
          categoryId = chosenCategoryId || null;
        }
      }
      staged.push({ id: uid(), categoryId, keyword, question, answer, createdAt: now(), updatedAt: now() });
      uniqueFinalKeywords.add(keyword.toLowerCase());
    }
    if (!staged.length) return res.status(400).json({ success: false, message: "No valid rows to import after validation." });
    await writeDb((state) => {
      if (createdCategories.length) state.categories.push(...createdCategories);
      state.faqs.push(...staged);
    });
    return res.json({
      success: true,
      message: `Imported ${staged.length} FAQ(s).`,
      data: {
        imported: staged.length,
        rejected,
        duplicates,
        uniqueKeywords: uniqueFinalKeywords.size,
        totalParsed: parsedRows.length,
        categoriesAdded: createdCategories.length,
        duplicateStrategy
      }
    });
  } catch (err) {
    const msg = String(err?.message || "Import failed");
    return res.status(400).json({ success: false, message: msg });
  }
});

app.get("/api/admin/faqs", adminOnly, (req,res)=>{
  const db=readDb();
  const defaultLimit = parsePositiveInt(db.settings?.adminPageSize, 20, 5, 200);
  const page = parsePositiveInt(req.query.page, 1, 1, 1000000);
  const limit = parsePositiveInt(req.query.limit, defaultLimit, 5, 200);
  const all = db.faqs.map(f=>({...f,categoryName:(db.categories.find(c=>c.id===f.categoryId)||{}).name||"General"}));
  const paged = paginateArray(all, page, limit);
  res.json({success:true,data:paged.data,meta:{count:all.length,limit:null,page:paged.meta.page,pages:paged.meta.pages,pageSize:paged.meta.limit,total:paged.meta.total}});
});
app.post("/api/admin/faqs", adminOnly, requireAdminCsrf, async (req,res)=>{
  const b=req.body||{}; const keyword=String(b.keyword||"").trim(); const question=String(b.question||"").trim(); const answer=String(b.answer||"").trim(); const categoryId=String(b.categoryId||"").trim()||null;
  if(!keyword||!question||!answer) return res.status(400).json({success:false,message:"keyword/question/answer required"});
  const db=readDb();
  if (categoryId && !db.categories.find(c => c.id === categoryId)) return res.status(400).json({ success:false, message:"Invalid category" });
  if(db.faqs.find(f=>f.keyword.toLowerCase()===keyword.toLowerCase())) return res.status(400).json({success:false,code:"DUPLICATE_KEYWORD",message:"Keyword already exists"});
  let row=null; await writeDb(x=>{row={id:uid(),categoryId,keyword,question,answer,createdAt:now(),updatedAt:now()};x.faqs.push(row);});
  res.json({success:true,data:row});
});
app.put("/api/admin/faqs/:id", adminOnly, requireAdminCsrf, async (req,res)=>{
  const id=String(req.params.id||"").trim();
  const b=req.body||{};
  const keyword=String(b.keyword||"").trim();
  const question=String(b.question||"").trim();
  const answer=String(b.answer||"").trim();
  const categoryId=String(b.categoryId||"").trim()||null;
  if(!id||!keyword||!question||!answer) return res.status(400).json({success:false,message:"id/keyword/question/answer required"});
  const db=readDb();
  if(!db.faqs.find(f=>f.id===id)) return res.status(404).json({success:false,message:"FAQ not found"});
  if (categoryId && !db.categories.find(c => c.id === categoryId)) return res.status(400).json({ success:false, message:"Invalid category" });
  if(db.faqs.find(f=>f.id!==id && f.keyword.toLowerCase()===keyword.toLowerCase())) return res.status(400).json({success:false,code:"DUPLICATE_KEYWORD",message:"Keyword already exists"});
  let updated=null;
  await writeDb(x=>{
    const row=x.faqs.find(f=>f.id===id);
    if(!row) return;
    row.categoryId=categoryId;
    row.keyword=keyword;
    row.question=question;
    row.answer=answer;
    row.updatedAt=now();
    updated=row;
  });
  res.json({success:true,data:updated});
});
app.delete("/api/admin/faqs/:id", adminOnly, requireAdminCsrf, async (req,res)=>{const id=String(req.params.id||""); await writeDb(db=>{db.faqs=db.faqs.filter(f=>f.id!==id);}); res.json({success:true});});

app.get("/api/admin/sessions", adminOnly, (req,res)=>{
  const db=readDb();
  const stats = new Map();
  for (const m of db.messages) {
    const row = stats.get(m.sessionId) || { total: 0, matched: 0 };
    row.total += 1;
    if (m.isMatched) row.matched += 1;
    stats.set(m.sessionId, row);
  }
  const rows=db.sessions.map(s=>{
    const st = stats.get(s.id) || { total: 0, matched: 0 };
    return {
      sessionKey:s.sessionKey,
      startedAt:s.startedAt,
      updatedAt:s.updatedAt,
      leadName:decryptPii(s.leadName)||"",
      leadEmail:decryptPii(s.leadEmail)||"",
      totalMessages:st.total,
      matchedMessages:st.matched
    };
  });
  res.json({success:true,data:rows});
});
app.get("/api/admin/sessions/:sessionKey", adminOnly, (req,res)=>{
  const db=readDb(); const s=db.sessions.find(x=>x.sessionKey===String(req.params.sessionKey||"")); if(!s) return res.status(404).json({success:false,message:"Session not found"});
  res.json({success:true,data:db.messages.filter(m=>m.sessionId===s.id)});
});
app.get("/api/admin/logs", adminOnly, (req,res)=>{
  const db=readDb();
  const defaultLimit = parsePositiveInt(db.settings?.adminPageSize, 20, 5, 200);
  const sessionsPage = parsePositiveInt(req.query.sessionsPage, 1, 1, 1000000);
  const messagesPage = parsePositiveInt(req.query.messagesPage, 1, 1, 1000000);
  const leadsPage = parsePositiveInt(req.query.leadsPage, 1, 1, 1000000);
  const sessionsLimit = parsePositiveInt(req.query.sessionsLimit, defaultLimit, 5, 200);
  const messagesLimit = parsePositiveInt(req.query.messagesLimit, defaultLimit, 5, 200);
  const leadsLimit = parsePositiveInt(req.query.leadsLimit, defaultLimit, 5, 200);
  const filterSession = String(req.query.filterSession || "").trim().toLowerCase();
  const filterName = String(req.query.filterName || "").trim().toLowerCase();
  const filterEmail = String(req.query.filterEmail || "").trim().toLowerCase();
  const selectedSessionKey = String(req.query.sessionKey || "").trim();

  const sessionById = new Map();
  const sessionByKey = new Map();
  for (const s of db.sessions) {
    sessionById.set(s.id, s);
    sessionByKey.set(s.sessionKey, s);
  }
  const msgStats = new Map();
  for (const m of db.messages) {
    const row = msgStats.get(m.sessionId) || { total: 0, matched: 0 };
    row.total += 1;
    if (m.isMatched) row.matched += 1;
    msgStats.set(m.sessionId, row);
  }
  const sessionsAll=db.sessions.map(s=>{
    const st = msgStats.get(s.id) || { total: 0, matched: 0 };
    return {
      id:s.id,
      sessionKey:s.sessionKey,
      startedAt:s.startedAt,
      updatedAt:s.updatedAt,
      leadName:decryptPii(s.leadName)||"",
      leadEmail:decryptPii(s.leadEmail)||"",
      totalMessages:st.total,
      matchedMessages:st.matched
    };
  })
    .filter((s)=>{
      if (filterSession && !String(s.sessionKey||"").toLowerCase().includes(filterSession)) return false;
      if (filterName && !String(s.leadName||"").toLowerCase().includes(filterName)) return false;
      if (filterEmail && !String(s.leadEmail||"").toLowerCase().includes(filterEmail)) return false;
      return true;
    })
    .sort((a,b)=>String(b.updatedAt||"").localeCompare(String(a.updatedAt||"")));

  const selectedSession = selectedSessionKey ? sessionByKey.get(selectedSessionKey) : null;
  const selectedSessionId = selectedSession ? selectedSession.id : "";
  const messagesAll=db.messages
    .filter((m)=>selectedSessionId && String(m.sessionId||"")===selectedSessionId)
    .map(m=>({id:m.id,sessionId:m.sessionId,sessionKey:selectedSessionKey,userMessage:m.userMessage,botResponse:m.botResponse,matchedKeyword:m.matchedKeyword,isMatched:m.isMatched,source:m.source,pageUrl:m.pageUrl,createdAt:m.createdAt}))
    .sort((a,b)=>String(b.createdAt||"").localeCompare(String(a.createdAt||"")));

  const leadsAll=db.leads.map(l=>({id:l.id,sessionId:l.sessionId,sessionKey:(sessionById.get(l.sessionId)||{}).sessionKey||"",name:decryptPii(l.name),email:decryptPii(l.email),createdAt:l.createdAt}))
    .sort((a,b)=>String(b.createdAt||"").localeCompare(String(a.createdAt||"")));

  const sessionsPaged = paginateArray(sessionsAll, sessionsPage, sessionsLimit);
  const messagesPaged = paginateArray(messagesAll, messagesPage, messagesLimit);
  const leadsPaged = paginateArray(leadsAll, leadsPage, leadsLimit);
  res.json({
    success:true,
    data:{
      sessions:sessionsPaged.data,
      messages:messagesPaged.data,
      leads:leadsPaged.data
    },
    meta:{
      defaultPageSize: defaultLimit,
      sessions: sessionsPaged.meta,
      messages: messagesPaged.meta,
      leads: leadsPaged.meta
    }
  });
});
app.get("/api/admin/analytics", adminOnly, (req,res)=>{
  if(!IS_PRO) return res.status(403).json({success:false,message:"Pro feature"});
  const db=readDb(); const topMatched={}, topUnmatched={}, trend={};
  for(const m of db.messages){const day=String(m.createdAt).slice(0,10); trend[day]=trend[day]||{day,total:0,matched:0}; trend[day].total++; if(m.isMatched) trend[day].matched++; if(m.isMatched&&m.matchedKeyword&&!String(m.matchedKeyword).startsWith("__")) topMatched[m.matchedKeyword]=(topMatched[m.matchedKeyword]||0)+1; if(!m.isMatched) topUnmatched[m.userMessage]=(topUnmatched[m.userMessage]||0)+1;}
  res.json({success:true,data:{topMatched:Object.entries(topMatched).map(([k,v])=>({matchedKeyword:k,total:v})).sort((a,b)=>b.total-a.total).slice(0,10),topUnmatched:Object.entries(topUnmatched).map(([k,v])=>({userMessage:k,total:v})).sort((a,b)=>b.total-a.total).slice(0,10),trend:Object.values(trend).sort((a,b)=>a.day.localeCompare(b.day)).slice(-14)}});
});

app.get("/api/admin/export/logs.csv", adminOnly, (req,res)=>{
  if(!IS_PRO) return res.status(403).json({success:false,message:"Pro feature"});
  const db=readDb(); const lines=[["id","sessionKey","userMessage","botResponse","matchedKeyword","isMatched","source","pageUrl","createdAt"].map(csv).join(",")];
  for(const m of db.messages){const sk=(db.sessions.find(s=>s.id===m.sessionId)||{}).sessionKey||""; lines.push([m.id,sk,m.userMessage,m.botResponse,m.matchedKeyword,m.isMatched,m.source,m.pageUrl,m.createdAt].map(csv).join(","));}
  res.setHeader("Content-Type","text/csv; charset=utf-8"); res.setHeader("Content-Disposition",`attachment; filename=stella-chatbot-logs-${Date.now()}.csv`); res.send(lines.join("\r\n"));
});
app.get("/api/admin/export/leads.csv", adminOnly, (req,res)=>{
  if(!IS_PRO) return res.status(403).json({success:false,message:"Pro feature"});
  const db=readDb(); const lines=[["id","sessionKey","name","email","createdAt"].map(csv).join(",")];
  for(const l of db.leads){const sk=(db.sessions.find(s=>s.id===l.sessionId)||{}).sessionKey||""; lines.push([l.id,sk,decryptPii(l.name),decryptPii(l.email),l.createdAt].map(csv).join(","));}
  res.setHeader("Content-Type","text/csv; charset=utf-8"); res.setHeader("Content-Disposition",`attachment; filename=stella-chatbot-leads-${Date.now()}.csv`); res.send(lines.join("\r\n"));
});

app.get("/widget.js", requireAllowedWidgetDomain, (req,res)=>res.sendFile(path.join(__dirname,"public","widget.js")));
app.get("/widget.css", (req,res)=>res.sendFile(path.join(__dirname,"public","widget.css")));
app.get("/default_avatar.jpg", (req,res)=>res.sendFile(path.join(__dirname,"public","default_avatar.jpg")));
app.get("/admin-style.css", (req,res)=>res.sendFile(path.join(__dirname,"public","admin-style.css")));
app.get("/admin", (req,res)=>sendHtmlWithNonce(res, "admin.html"));
app.get("/admin/settings", adminPageOnly, (req,res)=>sendHtmlWithNonce(res, "admin-settings.html"));
app.get("/admin/faqs", adminPageOnly, (req,res)=>sendHtmlWithNonce(res, "admin-faqs.html"));
app.get("/admin/logs", adminPageOnly, (req,res)=>sendHtmlWithNonce(res, "admin-logs.html"));
app.get("/", (req, res) => {
  if (fs.existsSync(LOCK_FILE) && !INSTALL_MAINTENANCE_MODE) return res.redirect("/admin");
  return res.redirect("/install");
});
app.get("/install", (req,res)=>{
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Referrer-Policy", "no-referrer");
  if(fs.existsSync(LOCK_FILE) && !INSTALL_MAINTENANCE_MODE) return res.redirect("/admin");
  if (IS_PRODUCTION) {
    if (!INSTALL_TOKEN) {
      return res.status(503).type("text/plain").send("INSTALL_TOKEN is required in production.");
    }
  } else if (!isLocalRequest(req) || !isTrustedLocalInstallHost(req)) {
    if (!INSTALL_TOKEN) {
      return res.status(403).type("text/plain").send("Installer is restricted. Configure INSTALL_TOKEN in .env.");
    }
    const sent = String(req.headers["x-install-token"] || "").trim();
    if (!timingSafeTextEquals(sent, INSTALL_TOKEN)) {
      return res.status(403).type("text/plain").send("Invalid install token.");
    }
  }
  sendHtmlWithNonce(res, "install.html");
});
app.post("/install", (req,res)=>{
  if (fs.existsSync(LOCK_FILE) && !INSTALL_MAINTENANCE_MODE) return res.status(400).json({ success:false, message:"Already installed" });
  const token = String(req.headers["x-install-token"] || "").trim();
  if (IS_PRODUCTION) {
    if (!INSTALL_TOKEN) {
      return res.status(503).json({ success:false, message:"INSTALL_TOKEN is required in production." });
    }
    if (!timingSafeTextEquals(token, INSTALL_TOKEN)) {
      return res.status(403).json({ success:false, message:"Invalid install token." });
    }
  } else if (!isLocalRequest(req) || !isTrustedLocalInstallHost(req)) {
    if (!INSTALL_TOKEN || !timingSafeTextEquals(token, INSTALL_TOKEN)) {
      return res.status(403).json({ success:false, message:"Installer is restricted. Provide a valid install token." });
    }
  }
  fs.mkdirSync(DATA_DIR,{recursive:true});
  saveDbParts(defaults());
  fs.writeFileSync(LOCK_FILE,`installed_at=${now()}\nedition=${EDITION}\n`);
  res.json({success:true,message:"Installed successfully"});
});


app.listen(PORT, ()=>console.log(`Stella AI Chatbot ${EDITION} running on http://localhost:${PORT}`));
