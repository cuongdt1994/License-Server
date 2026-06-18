'use strict';
const tls       = require('tls');
const http      = require('http');
const https     = require('https');
const crypto    = require('crypto');
const fs        = require('fs');
const path      = require('path');
const express   = require('express');
const session   = require('express-session');
const multer    = require('multer');
const speakeasy = require('speakeasy');
const QRCode    = require('qrcode');
const { resolveDataDirInfo, rememberDataDir } = require('./data_dir');
const { buildRuntimeConfig } = require('./runtime_config');
const { SqliteSessionStore } = require('./session_store');
const {
    ensureCsrfToken,
    verifyCsrfRequest,
    strictLicenseKeyEnabled,
    canAuthWithoutLicenseKey,
    licenseKeyBootstrapEnabled,
    canBootstrapLicenseKey,
    isValidMachineId,
    canViewPortalLicense,
    consumeFlash,
    auditEvent,
    securityHeaders,
    isAgentScriptAuthorized,
    hashPassword,
    verifyPassword,
    normalizeAdminCredentials,
    isStrongPassword,
    recordLockEvent,
    clearLockHistory,
    AUTO_BAN_LOCK_THRESHOLD,
    AUTO_BAN_WINDOW_MS,
    AUTO_BAN_DURATION_MS,
    getProgressiveDelayMs,
    clearFailDelay,
    appendAuditLine,
    verifyAuditChain,
    migrateAuditChainIfNeeded,
} = require('./security');
const agent     = require('./agent_manager');
const commandPolicy = require('./command_policy');
const { createDeployManager } = require('./deploy_manager');
const { createStore } = require('./store');

// ── Cấu hình ──────────────────────────────────────────────────────────────────
const RUNTIME         = buildRuntimeConfig();
const TCP_PORT        = RUNTIME.tcpPort;
const WEB_PORT        = RUNTIME.webPort;
const BIND_HOST       = RUNTIME.bindHost;
const DATA_DIR_INFO   = resolveDataDirInfo({ appDir: __dirname });
const DATA_DIR        = DATA_DIR_INFO.dir;

// ── Init dirs + SQLite store (phải có trước khi resolve session secret) ──────
const SQLITE_FILE     = path.join(DATA_DIR, 'license.sqlite3');
const BACKUP_DIR      = path.join(DATA_DIR, 'backups');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(BACKUP_DIR, { recursive: true });

let _storeInstance = null;
let _storeLogger = () => {};  // sẽ được gán lại sau khi log() định nghĩa
function getStore() {
    if (_storeInstance) return _storeInstance;
    _storeInstance = createStore({
        driver: 'sqlite',
        dataDir: DATA_DIR,
        dbPath: SQLITE_FILE,
        log: (level, msg) => _storeLogger(level, msg),
    });
    return _storeInstance;
}

// Wire up agent + deploy manager to SQLite store
agent.init(() => getStore());
const deployManagerModule = require('./deploy_manager');
deployManagerModule.init(() => getStore());

function resolveSessionSecret() {
    // 1. Env var — ưu tiên cao nhất
    const envVal = String(process.env.LICENSE_SESSION_SECRET || '').trim();
    if (Buffer.byteLength(envVal, 'utf8') >= 48) {
        return { secret: envVal, source: 'env' };
    }
    // 2. SQLite — đọc secret đã lưu từ lần chạy trước
    try {
        const settings = getStore().loadSettings();
        if (settings.session_secret && Buffer.byteLength(String(settings.session_secret), 'utf8') >= 48) {
            return { secret: String(settings.session_secret), source: 'sqlite' };
        }
    } catch {}
    // 3. Tự sinh + lưu SQLite — lần đầu tiên
    const generated = crypto.randomBytes(48).toString('base64url');
    try {
        const store = getStore();
        const settings = store.loadSettings();
        settings.session_secret = generated;
        store.saveSettings(settings);
    } catch {}
    return { secret: generated, source: 'sqlite:auto' };
}

const SESSION_RESOLVE = resolveSessionSecret();
const SESSION_SECRET  = SESSION_RESOLVE.secret;
const RUNTIME_SECRETS = {
    sessionSecret: SESSION_SECRET,
    tcpSecret: process.env.LICENSE_TCP_SECRET || '',
    sources: { session: SESSION_RESOLVE.source, tcp: process.env.LICENSE_TCP_SECRET ? 'env' : 'embedded-client-sync' },
    file: null,
};

// TLS-only license transport.
const TLS_PORT = clampEnvPort(process.env.LICENSE_TLS_PORT, TCP_PORT);
const TLS_KEY_FILE = String(process.env.LICENSE_TLS_KEY_FILE || '').trim();
const TLS_CERT_FILE = String(process.env.LICENSE_TLS_CERT_FILE || '').trim();
const TLS_CA_FILE = String(process.env.LICENSE_TLS_CA_FILE || '').trim();
const TLS_MIN_VERSION = String(process.env.LICENSE_TLS_MIN_VERSION || 'TLSv1.2').trim();
const TLS_HANDSHAKE_TIMEOUT_MS = clampEnvInt(process.env.LICENSE_TLS_HANDSHAKE_TIMEOUT_MS, 5000, 1000, 30000);
const TLS_HANDSHAKE_LOG_WINDOW_MS = clampEnvInt(process.env.LICENSE_TLS_HANDSHAKE_LOG_WINDOW_MS, 60000, 1000, 3600000);
const TLS_MTLS = process.env.LICENSE_TLS_MTLS === '1';

function clampEnvInt(value, fallback, min, max) {
    const n = Number.parseInt(value, 10);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, n));
}
function clampEnvPort(value, fallback) {
    return clampEnvInt(value, fallback, 1, 65535);
}

// TCP secret dùng chung với license_check.cpp. Mặc định server dùng cùng 2 XOR-shares
// với client để tránh lệch key khi runtime_secret được sinh khác môi trường. Nếu cần
// override có kiểm soát, đặt LICENSE_TCP_SECRET + LICENSE_ALLOW_RUNTIME_TCP_SECRET=1
// và build lại client cùng secret đó.
const TCP_KEY_SHARE_A = Buffer.from([
    0x98,0x77,0xE5,0x2C,0x80,0x16,0x53,0xF6,
    0x02,0x7E,0x9D,0x77,0xD1,0x1C,0x7A,0xF4,
    0x6A,0x8D,0xB9,0x16,0x52,0xC7,0x6D,0xFD,
    0x22,0x17,0x85,0x4E,0xBC,0x54,0xE6,0x6D,
]);
const TCP_KEY_SHARE_B = Buffer.from([
    0xD3,0x1F,0x8A,0x42,0xE7,0x55,0x3C,0x91,
    0x6B,0x2D,0xF8,0x14,0xA3,0x79,0x0E,0xC6,
    0x5A,0xBF,0x8D,0x37,0x12,0xE4,0x49,0xD8,
    0x7C,0x31,0xAF,0x66,0x95,0x0B,0xCD,0x50,
]);
function deriveEmbeddedTcpSecret() {
    return Buffer.from(TCP_KEY_SHARE_A.map((b, i) => b ^ TCP_KEY_SHARE_B[i]));
}
function normalizeSecretBuffer(value) {
    if (!value) return null;
    if (Buffer.isBuffer(value)) return Buffer.from(value);
    const text = String(value).trim();
    if (/^hex:[0-9a-fA-F]{64}$/.test(text)) return Buffer.from(text.slice(4), 'hex');
    if (/^[0-9a-fA-F]{64}$/.test(text)) return Buffer.from(text, 'hex');
    if (/^base64:/i.test(text)) return Buffer.from(text.slice(7), 'base64');
    return Buffer.from(text, 'utf8');
}
function resolveTcpSecret(runtimeSecret) {
    const embedded = deriveEmbeddedTcpSecret();
    const envSecret = normalizeSecretBuffer(process.env.LICENSE_TCP_SECRET);
    if (envSecret) {
        if (envSecret.length !== 32) throw new Error('LICENSE_TCP_SECRET must be exactly 32 bytes or 64 hex chars.');
        return { key: envSecret, source: 'env' };
    }
    const raw = normalizeSecretBuffer(runtimeSecret);
    if (raw && raw.length === 32 && raw.equals(embedded)) return { key: raw, source: 'runtime' };
    if (raw && raw.length === 32 && process.env.LICENSE_ALLOW_RUNTIME_TCP_SECRET === '1') {
        return { key: raw, source: 'runtime-override' };
    }
    return {
        key: embedded,
        source: 'embedded-client-sync',
        info: 'TCP secret: using embedded client-synced key. Set LICENSE_TCP_SECRET env if you need a custom secret.',
    };
}
const TCP_SECRET_INFO = resolveTcpSecret(RUNTIME_SECRETS.tcpSecret);
const SECRET_KEY      = TCP_SECRET_INFO.key;
const LOG_FILE        = path.join(DATA_DIR, 'license.log');
const AUDIT_FILE      = path.join(DATA_DIR, 'audit.log');
RUNTIME.secretSources = RUNTIME_SECRETS.sources;
RUNTIME.secretFile = RUNTIME_SECRETS.file;
RUNTIME.tcpSecretSource = TCP_SECRET_INFO.source;
if (!Array.isArray(RUNTIME.warnings)) RUNTIME.warnings = [];
if (TCP_SECRET_INFO.info) {
    log('INFO', TCP_SECRET_INFO.info);
}

const STRICT_LICENSE_KEY = strictLicenseKeyEnabled();
const DEFAULT_PLAYERS = 10;  // Basic tier: 10 players
const MAX_PLAYERS_LIMIT = 100000;
const UNLIMITED_PLAYERS = 9999;

function isHexString(s) { return typeof s === 'string' && /^[0-9a-fA-F]+$/.test(s); }
function isHexLen(s, n) { return typeof s === 'string' && s.length === n && isHexString(s); }
function isValidLicenseKey(k) { return isHexLen(String(k || '').trim(), 32); }
function normalizeLicenseKey(k) { const v = String(k || '').trim(); return isValidLicenseKey(v) ? v.toUpperCase() : ''; }
function isValidAgentToken(k) { return isHexLen(String(k || '').trim(), 48); }
function sameKey(a, b) { return String(a || '').toLowerCase() === String(b || '').toLowerCase(); }
function clampInt(value, fallback, min, max) {
    const n = Number.parseInt(value, 10);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, n));
}
function normalizeMaxPlayers(value, tier = 'basic') {
    if (tier === 'unlimited') return UNLIMITED_PLAYERS;
    return clampInt(value, DEFAULT_PLAYERS, 1, MAX_PLAYERS_LIMIT);
}

// ── Safe max_players resolver ─────────────────────────────────────────────────
// Luôn trả về số nguyên dương, clamp về biên an toàn để client không reject.
function getMaxPlayers(entry) {
    if (!entry) return DEFAULT_PLAYERS;
    return normalizeMaxPlayers(entry.max_players, entry.tier);
}

function normalizeMachineEntry(entry) {
    if (!entry || typeof entry !== 'object') return { max_players: DEFAULT_PLAYERS, tier: 'basic' };
    if (!TIERS[entry.tier]) entry.tier = 'basic';
    entry.max_players = getMaxPlayers(entry);
    if (entry.license_key && !isValidLicenseKey(entry.license_key)) delete entry.license_key;
    if (Array.isArray(entry.previous_keys)) {
        const nowMs = Date.now();
        entry.previous_keys = entry.previous_keys
            .filter(p => p && isValidLicenseKey(p.key) && (!p.expires_at || p.expires_at > nowMs))
            .slice(-5);
    }
    return entry;
}

// Quét và sửa toàn bộ DB: đảm bảo max_players/key luôn hợp lệ
function repairDBMaxPlayers() {
    const db = loadDB();
    let changed = false;
    for (const [mid, entry] of Object.entries(db)) {
        const before = JSON.stringify(entry);
        db[mid] = normalizeMachineEntry(entry);
        if (JSON.stringify(db[mid]) !== before) changed = true;
    }
    if (changed) {
        saveDB(db);
        log('INFO', `DB repaired: normalized max_players/license keys`);
    }
}

const STATS_SAMPLE_MS = 60 * 1000;
const MAX_STATS_PER_MACHINE = 1440;  // ~24h at 60s stats sampling
const MAX_HISTORY     = 1000;
const ZOMBIE_DAYS     = 30;          // Mark zombie nếu offline > N ngày
const deployManager   = createDeployManager({ cwd: __dirname, historyFile: path.join(DATA_DIR, 'deploy_history.json') });

// ── Tier system ───────────────────────────────────────────────────────────────
const TIERS = {
    trial:     { label: 'Trial',     color: '#fbbf24', bg: '#451a03' },
    basic:     { label: 'Basic',     color: '#60a5fa', bg: '#1e3a5f' },
    pro:       { label: 'Pro',       color: '#a78bfa', bg: '#2e1065' },
    unlimited: { label: 'Unlimited', color: '#34d399', bg: '#064e3b' },
};

// ── AES-256-GCM TCP encryption (AEAD) + timestamp anti-replay ────────────────
// Wire format: HEX(iv12):HEX(tag16):HEX(ciphertext)\n
// Plaintext format: "<unix_ms>|<payload>"  → reject nếu lệch > REPLAY_WINDOW_MS
const CIPHER = 'aes-256-gcm';
const REPLAY_WINDOW_MS = 30 * 1000;        // 30s
const MAX_TCP_FRAME_BYTES = 8 * 1024;
const MAX_SEEN_NONCES = 20000;
const TCP_SOCKET_TIMEOUT_MS = 8000;
const TCP_MAX_BUFFER_BYTES = MAX_TCP_FRAME_BYTES * 2 + 128;
const seenNonces = new Map();              // iv_hex → expireAt (chống replay đúng nghĩa)
let lastTcpDecryptError = 'unknown';

function purgeSeenNonces(nowMs = Date.now()) {
    for (const [k, exp] of seenNonces) if (exp <= nowMs) seenNonces.delete(k);
    while (seenNonces.size > MAX_SEEN_NONCES) seenNonces.delete(seenNonces.keys().next().value);
}

function tcpEncrypt(plain) {
    const iv  = crypto.randomBytes(12);
    const c   = crypto.createCipheriv(CIPHER, SECRET_KEY, iv);
    const stamped = `${Date.now()}|${plain}`;
    const enc = Buffer.concat([c.update(Buffer.from(stamped, 'utf8')), c.final()]);
    const tag = c.getAuthTag();
    return iv.toString('hex') + ':' + tag.toString('hex') + ':' + enc.toString('hex') + '\n';
}

function tcpDecrypt(line) {
    lastTcpDecryptError = 'invalid';
    try {
        const t = String(line || '').trim();
        if (!t || t.length > MAX_TCP_FRAME_BYTES * 2) return null;
        const parts = t.split(':');
        if (parts.length !== 3) return null;
        const ivHex  = parts[0], tagHex = parts[1], encHex = parts[2];
        if (!isHexLen(ivHex, 24) || !isHexLen(tagHex, 32)) return null;
        if (!encHex || encHex.length % 2 !== 0 || encHex.length > MAX_TCP_FRAME_BYTES * 2 || !isHexString(encHex)) return null;

        const iv  = Buffer.from(ivHex,  'hex');
        const tag = Buffer.from(tagHex, 'hex');
        const enc = Buffer.from(encHex, 'hex');
        if (iv.length !== 12 || tag.length !== 16 || enc.length < 1 || enc.length > MAX_TCP_FRAME_BYTES) return null;

        const d = crypto.createDecipheriv(CIPHER, SECRET_KEY, iv);
        d.setAuthTag(tag);
        const out = Buffer.concat([d.update(enc), d.final()]).toString('utf8');

        const sep = out.indexOf('|');
        if (sep <= 0 || sep > 20) return null;
        const tsRaw = out.slice(0, sep);
        if (!/^\d+$/.test(tsRaw)) return null;
        const ts = Number.parseInt(tsRaw, 10);
        const nowMs = Date.now();
        if (!Number.isFinite(ts) || Math.abs(nowMs - ts) > REPLAY_WINDOW_MS) { lastTcpDecryptError = 'replay'; return null; }

        purgeSeenNonces(nowMs);
        if (seenNonces.has(ivHex)) { lastTcpDecryptError = 'replay'; return null; }
        seenNonces.set(ivHex, nowMs + REPLAY_WINDOW_MS);

        return out.slice(sep + 1);
    } catch { return null; }
}

// ── Rate limiting (Web login) ─────────────────────────────────────────────────
const loginAttempts = {};
const MAX_ATTEMPTS = 5, LOCK_MS = 15 * 60 * 1000;
function rl_check(ip) {
    const e = loginAttempts[ip];
    if (e && e.lockedUntil > Date.now())
        return { blocked: true, remaining: Math.ceil((e.lockedUntil - Date.now()) / 60000) };
    return { blocked: false };
}
function rl_fail(ip) {
    if (!loginAttempts[ip]) loginAttempts[ip] = { count: 0, lockedUntil: 0 };
    const e = loginAttempts[ip];
    if (e.lockedUntil && e.lockedUntil < Date.now()) e.count = 0;
    if (++e.count >= MAX_ATTEMPTS) { e.lockedUntil = Date.now() + LOCK_MS; e.count = 0; }
}
function rl_clear(ip) { delete loginAttempts[ip]; }

const portalAttempts = {};
const PORTAL_MAX_ATTEMPTS = 20, PORTAL_LOCK_MS = 10 * 60 * 1000;
function portalRlCheck(ip) {
    const e = portalAttempts[ip];
    if (e && e.lockedUntil > Date.now()) return { blocked: true };
    return { blocked: false };
}
function portalRlFail(ip) {
    if (!portalAttempts[ip]) portalAttempts[ip] = { count: 0, lockedUntil: 0 };
    const e = portalAttempts[ip];
    if (e.lockedUntil && e.lockedUntil < Date.now()) { e.count = 0; e.lockedUntil = 0; }
    if (++e.count >= PORTAL_MAX_ATTEMPTS) { e.lockedUntil = Date.now() + PORTAL_LOCK_MS; e.count = 0; }
}
function portalRlClear(ip) { delete portalAttempts[ip]; }

// ── TCP Rate limiting per IP ──────────────────────────────────────────────────
const tcpAttempts = {};
const TCP_MAX = 8, TCP_LOCK_MS = 5 * 60 * 1000;  // Giảm từ 15 → 8 (với realtime HB 5s, traffic ít hơn)
function tcpRlBlocked(ip) {
    const e = tcpAttempts[ip];
    if (!e) return false;
    if (e.lockedUntil > Date.now()) return true;
    if (e.lockedUntil < Date.now()) { delete tcpAttempts[ip]; return false; }
    return false;
}
function tcpRlFail(ip) {
    if (!tcpAttempts[ip]) tcpAttempts[ip] = { count: 0, lockedUntil: 0 };
    const e = tcpAttempts[ip];
    if (e.lockedUntil && e.lockedUntil < Date.now()) { e.count = 0; e.lockedUntil = 0; }
    if (++e.count >= TCP_MAX) e.lockedUntil = Date.now() + TCP_LOCK_MS;
}
function tcpRlSuccess(ip) { delete tcpAttempts[ip]; }

// ── IP Ban ────────────────────────────────────────────────────────────────────
function loadBans() {
    return getStore().loadBans();
}
function saveBans(b) {
    getStore().saveBans(b || {});
}
function normalizeIp(ip) {
    let v = String(ip || '?').trim();
    if (v.includes(',')) v = v.split(',')[0].trim();
    v = v.replace(/^::ffff:/, '');
    if (v === '::1') return '127.0.0.1';
    return v || '?';
}
function isIPv4(ip) {
    const parts = String(ip || '').split('.');
    return parts.length === 4 && parts.every(p => /^\d+$/.test(p) && +p >= 0 && +p <= 255);
}
function ipToInt(ip) {
    if (!isIPv4(ip)) return null;
    return ip.split('.').reduce((a, o) => ((a << 8) + Number.parseInt(o, 10)) >>> 0, 0);
}
function isIpBanned(ip, bans) {
    ip = normalizeIp(ip);
    const ipInt = ipToInt(ip);
    for (const [rangeRaw, info] of Object.entries(bans || {})) {
        if (info && info.disabled) continue;
        const range = String(rangeRaw || '').trim();
        if (!range) continue;
        if (range.includes('/')) {
            const [base, bitsRaw] = range.split('/');
            const bits = Number.parseInt(bitsRaw, 10);
            const baseInt = ipToInt(base);
            if (ipInt === null || baseInt === null || !Number.isInteger(bits) || bits < 0 || bits > 32) continue;
            const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
            if ((baseInt & mask) === (ipInt & mask)) return true;
        } else if (range.endsWith('.*')) {
            if (ip.startsWith(range.slice(0, -1))) return true;
        } else if (ip === range) return true;
    }
    return false;
}

// ── Expiry helpers ────────────────────────────────────────────────────────────
function validDateOrNull(value) {
    const d = value instanceof Date ? value : new Date(value);
    return Number.isFinite(d.getTime()) ? d : null;
}
function getExpiryDate(entry) {
    if (!entry) return null;
    let d = null;
    if (entry.tier === 'trial' && entry.trial_days && entry.added) {
        const base = validDateOrNull(String(entry.added).replace(' ', 'T'));
        if (base) d = new Date(base.getTime() + clampInt(entry.trial_days, 7, 1, 3650) * 86400000);
    }
    if (entry.expires_at) {
        const ed = validDateOrNull(`${entry.expires_at}T23:59:59`);
        if (ed && (!d || ed < d)) d = ed;
    }
    return d;
}
function isExpired(entry) { const d = getExpiryDate(entry); return d ? d < new Date() : false; }
function expiryInfo(entry) {
    const d = getExpiryDate(entry);
    if (!d) return null;
    const daysLeft = Math.ceil((d - new Date()) / 86400000);
    return { date: d.toISOString().slice(0, 10), daysLeft };
}

// ── Prometheus-style metrics ─────────────────────────────────────────────────
const metrics = Object.create(null);
const METRIC_DEFS = {
    license_active_machines: ['gauge', 'Currently online machines.'],
    license_total_machines: ['gauge', 'Total registered machines.'],
    license_revoked_machines: ['gauge', 'Total revoked machines.'],
    license_expired_machines: ['gauge', 'Total expired machines.'],
    license_total_players: ['gauge', 'Total online players.'],
    license_sse_clients: ['gauge', 'Connected SSE dashboard clients.'],
    license_sessions_active: ['gauge', 'Active AUTH2 sessions in memory.'],
    license_sessions_created_total: ['counter', 'Total AUTH2 sessions created.'],
    license_sessions_expired_total: ['counter', 'Total AUTH2 sessions expired or revoked.'],
    license_offline_leases_issued_total: ['counter', 'Total signed offline leases issued.'],
    license_tcp_auth_ok_total: ['counter', 'Legacy AUTH successes.'],
    license_tcp_auth_deny_total: ['counter', 'Legacy AUTH denials.'],
    license_tcp_auth2_ok_total: ['counter', 'AUTH2 successes.'],
    license_tcp_auth2_deny_total: ['counter', 'AUTH2 denials.'],
    license_tcp_hb_ok_total: ['counter', 'Legacy HB successes.'],
    license_tcp_hb_deny_total: ['counter', 'Legacy HB denials.'],
    license_tcp_hb2_ok_total: ['counter', 'HB2 successes.'],
    license_tcp_hb2_deny_total: ['counter', 'HB2 denials.'],
    license_tcp_decrypt_fail_total: ['counter', 'TCP AES-GCM decrypt or frame validation failures.'],
    license_tcp_replay_fail_total: ['counter', 'TCP timestamp/nonce replay failures.'],
    license_tcp_rate_limited_total: ['counter', 'TLS license requests rejected by rate or concurrency limits.'],
    license_tls_connections: ['gauge', 'Current established TLS license connections.'],
    license_tls_handshake_ok_total: ['counter', 'Successful TLS handshakes.'],
    license_tls_handshake_fail_total: ['counter', 'Failed TLS handshakes.'],
    license_graceful_shutdown_total: ['counter', 'Graceful shutdowns initiated.'],
    license_db_save_total: ['counter', 'Store save operations.'],
    license_db_save_fail_total: ['counter', 'Store save failures.'],
    license_process_uptime_seconds: ['gauge', 'Node.js process uptime in seconds.'],
    license_process_rss_bytes: ['gauge', 'Node.js RSS memory usage.'],
    license_process_heap_used_bytes: ['gauge', 'Node.js heap used bytes.'],
};
for (const name of Object.keys(METRIC_DEFS)) metrics[name] = 0;
function incMetric(name, delta = 1) {
    try { metrics[name] = (Number(metrics[name]) || 0) + delta; } catch {}
}
function setMetric(name, value) {
    try { metrics[name] = Number.isFinite(Number(value)) ? Number(value) : 0; } catch {}
}
function collectDynamicMetrics() {
    try {
        const db = loadDB();
        setMetric('license_active_machines', Object.keys(active).length);
        setMetric('license_total_machines', Object.keys(db).length);
        setMetric('license_revoked_machines', Object.values(db).filter(v => v && v.revoked).length);
        setMetric('license_expired_machines', Object.values(db).filter(v => v && !v.revoked && isExpired(v)).length);
        setMetric('license_total_players', Object.values(active).reduce((sum, row) => sum + (Number(row.players) || 0), 0));
    } catch {}
    setMetric('license_sse_clients', sseClientCount());
    setMetric('license_sessions_active', sessions.size);
    setMetric('license_tls_connections', typeof _tlsConnections !== 'undefined' ? _tlsConnections.size : 0);
    try {
        const health = getStore().health ? getStore().health() : {};
        if (Number.isFinite(Number(health.saves_total))) setMetric('license_db_save_total', health.saves_total);
        if (Number.isFinite(Number(health.save_fail_total))) setMetric('license_db_save_fail_total', health.save_fail_total);
    } catch {}
    const mem = process.memoryUsage();
    setMetric('license_process_uptime_seconds', Math.floor(process.uptime()));
    setMetric('license_process_rss_bytes', mem.rss);
    setMetric('license_process_heap_used_bytes', mem.heapUsed);
}
function renderMetrics() {
    collectDynamicMetrics();
    const lines = [];
    for (const [name, [type, help]] of Object.entries(METRIC_DEFS)) {
        lines.push(`# HELP ${name} ${help}`);
        lines.push(`# TYPE ${name} ${type}`);
        lines.push(`${name} ${Number(metrics[name]) || 0}`);
    }
    return lines.join('\n') + '\n';
}

// ── Logging ───────────────────────────────────────────────────────────────────
function loadAdminCredentials() {
    const envUser = (process.env.LICENSE_WEB_USER || '').trim();
    const envPass = (process.env.LICENSE_WEB_PASS || '').trim();
    if (envUser || envPass) {
        if (!envUser || !envPass) {
            throw new Error('LICENSE_WEB_USER and LICENSE_WEB_PASS must both be set when using env credentials.');
        }
        return { user: envUser, pass_hash: hashPassword(envPass), source: 'env' };
    }
    try {
        const raw = getStore().loadAdminCredentials();
        const normalized = normalizeAdminCredentials(raw);
        if (normalized) {
            if (raw.pass || raw.pass_hash !== normalized.pass_hash) getStore().saveAdminCredentials(normalized);
            return normalized;
        }
    } catch (err) {
        log('ERROR', `Cannot load admin credentials from SQLite: ${err.message}`);
        throw err;
    }
    return null;
}

let adminCreds = loadAdminCredentials();
let setupRequired = !adminCreds;
let WEB_USER = adminCreds?.user || null;
function verifyAdminLogin(username, password) {
    if (setupRequired || !adminCreds) return false;
    if (username !== WEB_USER) return false;
    return verifyPassword(password, adminCreds.pass_hash);
}

function log(level, msg) {
    const line = `${new Date().toISOString().replace('T', ' ').slice(0, 19)}  ${level.padEnd(7)}  ${msg}`;
    console.log(line);
    fs.appendFileSync(LOG_FILE, line + '\n');
}
_storeLogger = log;  // wire up store logging after log() is defined

function audit(req, action, details = {}) {
    try {
        appendAuditLine(AUDIT_FILE, { action, user: WEB_USER, ip: clientIp(req), details });
    } catch (e) {
        log('WARNING', `AUDIT FAIL action=${action} err=${e.message}`);
    }
}

// ── Database ──────────────────────────────────────────────────────────────────
function loadDB() {
    return getStore().loadDB();
}
function saveDB(db) {
    getStore().saveDB(db || {});
}
function now() { return new Date().toLocaleString('sv').replace('T', ' '); }

// ── Settings ──────────────────────────────────────────────────────────────────
function loadSettings() {
    return getStore().loadSettings();
}
function saveSettings(s) {
    getStore().saveSettings(s || {});
}

// ── Plans ─────────────────────────────────────────────────────────────────────
function loadPlans() {
    return getStore().loadPlans();
}
function savePlans(p) {
    getStore().savePlans(Array.isArray(p) ? p : []);
}

// ── Stats (time-series) ───────────────────────────────────────────────────────
function loadStats() {
    return getStore().loadStats();
}
const _lastStatPush = new Map();
function pushStat(mid, players) {
    const ts = Date.now();
    const prev = _lastStatPush.get(mid);
    const normalizedPlayers = Math.max(0, Math.min(Number.parseInt(players, 10) || 0, MAX_PLAYERS_LIMIT));
    if (prev && ts - prev.ts < STATS_SAMPLE_MS && prev.players === normalizedPlayers) return;
    if (prev && ts - prev.ts < 10 * 1000) return; // hard cap disk writes when player count churns

    getStore().pushStat(mid, normalizedPlayers, { maxPerMachine: MAX_STATS_PER_MACHINE });
    _lastStatPush.set(mid, { ts, players: normalizedPlayers });
}

// ── History ───────────────────────────────────────────────────────────────────
function loadHistory() {
    return getStore().loadHistory();
}
function pushHistory(entry) {
    getStore().pushHistory({ ...entry, ts: now(), ts_ms: Date.now() }, { maxHistory: MAX_HISTORY });
}

// ── License key generation ────────────────────────────────────────────────────
function generateLicenseKey() {
    return crypto.randomBytes(16).toString('hex').toUpperCase();
}

// ── GeoIP (ip-api.com free, no package needed) ────────────────────────────────
const geoCache = {};
function isPrivateIPv4(ip) {
    if (!isIPv4(ip)) return true;
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31);
}
function getGeoIP(ip) {
    ip = normalizeIp(ip);
    if (!ip || ip === '?' || isPrivateIPv4(ip)) return Promise.resolve(null);
    if (geoCache[ip]) return Promise.resolve(geoCache[ip]);
    return new Promise(resolve => {
        const req = http.get(
            `http://ip-api.com/json/${ip}?fields=status,country,countryCode,city`,
            res => {
                let body = '';
                res.on('data', d => body += d);
                res.on('end', () => {
                    try {
                        const d = JSON.parse(body);
                        if (d.status === 'success') {
                            const info = { country: d.country, code: d.countryCode, city: d.city };
                            geoCache[ip] = info;
                            resolve(info);
                        } else resolve(null);
                    } catch { resolve(null); }
                });
            }
        );
        req.on('error', () => resolve(null));
        req.setTimeout(3000, () => { req.destroy(); resolve(null); });
    });
}

// ── Telegram notifications ────────────────────────────────────────────────────
function sendTelegram(msg) {
    const s = loadSettings();
    if (!s.telegram_token || !s.telegram_chat_id) return;
    const body = JSON.stringify({ chat_id: s.telegram_chat_id, text: msg, parse_mode: 'HTML' });
    const opts = {
        hostname: 'api.telegram.org',
        path: `/bot${s.telegram_token}/sendMessage`,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    };
    const req = https.request(opts, () => {});
    req.on('error', () => {});
    req.write(body); req.end();
}

// ── Webhook dispatch ──────────────────────────────────────────────────────────
function dispatchWebhook(event, data) {
    try { sseBroadcast(event, data || {}); } catch {}
    const s = loadSettings();
    if (!Array.isArray(s.webhooks) || !s.webhooks.length) return;
    const payload = JSON.stringify({ event, data, ts: Date.now() });
    for (const urlStr of s.webhooks) {
        try {
            const u = new URL(urlStr);
            const mod = u.protocol === 'https:' ? https : http;
            const opts = {
                hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
                path: u.pathname + u.search, method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
            };
            const req = mod.request(opts, () => {});
            req.on('error', () => {}); req.write(payload); req.end();
        } catch {}
    }
}

function shellEnabled() {
    return loadSettings().advanced_shell_enabled === true;
}

function defaultShellTimeout() {
    return commandPolicy.clampTimeout(loadSettings().agent_shell_timeout || 120, 120);
}

function enqueueAgentCommand(mid, kind, payload) {
    const timeoutSec = commandPolicy.clampTimeout(payload?.timeoutSec, 300);
    const script = commandPolicy.wrapWithTimeout(payload?.script || '', timeoutSec);
    return agent.enqueueCommand(mid, kind, { ...payload, script, timeoutSec });
}

function autoRegisterEnabled(env = process.env) {
    return !/^(0|false|no|off)$/i.test(String(env.LICENSE_AUTO_REGISTER || '').trim());
}

function csvSafeCell(value) {
    const text = String(value ?? '');
    return /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
}

// ── Maintenance mode (persistent via settings) ────────────────────────────────
function isMaintenanceActive() {
    const s = loadSettings();
    if (!s.maintenance) return false;
    if (s.maintenance_until && Date.now() > s.maintenance_until) {
        s.maintenance = false; delete s.maintenance_until; saveSettings(s);
        log('INFO', 'Maintenance mode ended automatically');
        return false;
    }
    return true;
}

// ── SQLite online backup ─────────────────────────────────────────────────────
let _lastBackupDate = '';
let _backupInFlight = null;
async function doBackup(force = false) {
    const today = new Date().toISOString().slice(0, 10);
    if (!force && _lastBackupDate === today) return null;
    if (_backupInFlight) return _backupInFlight;
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const dest = path.join(BACKUP_DIR, `license_${stamp}.sqlite3`);
    _backupInFlight = getStore().backup(dest)
        .then(() => {
            _lastBackupDate = today;
            const list = fs.readdirSync(BACKUP_DIR)
                .filter(name => name.startsWith('license_') && name.endsWith('.sqlite3'))
                .sort();
            while (list.length > 30) fs.unlinkSync(path.join(BACKUP_DIR, list.shift()));
            log('INFO', `SQLite backup complete → ${dest}`);
            return dest;
        })
        .catch(err => {
            log('ERROR', `SQLite backup failed: ${err.message}`);
            throw err;
        })
        .finally(() => { _backupInFlight = null; });
    return _backupInFlight;
}

// ── Active servers map ────────────────────────────────────────────────────────
const active = {};

// ── Pending config change maps (CFGMAX + KEY real-time push) ──────────────────
// Khi admin thay đổi max_players hoặc license key trên web UI, thay đổi được
// đánh dấu "pending" ở đây. Lần heartbeat tiếp theo (≤5s với client mới),
// server gửi CFGMAX:<n> và/hoặc KEY:<hex> kèm trong HB response, sau đó
// clear pending flag. Điều này cho phép config thay đổi có hiệu lực gần như
// ngay lập tức mà không cần restart game server.
const _pendingMaxPlayers = new Map(); // mid → newValue
const _pendingKey        = new Map(); // mid → newKey

// ── TCP connection tracking ───────────────────────────────────────────────────
const _tcpConnsPerIp = new Map();     // ip → count
const TCP_MAX_CONCURRENT_PER_IP = 64; // NAT/proxy friendly, vẫn chống flood
const _lastHbLog = new Map();
const HB_LOG_INTERVAL_MS = 60 * 1000;
const HB_DB_TOUCH_MS = 60 * 1000;

function shouldLogHeartbeat(mid) {
    const ts = Date.now();
    const prev = _lastHbLog.get(mid) || 0;
    if (ts - prev < HB_LOG_INTERVAL_MS) return false;
    _lastHbLog.set(mid, ts);
    return true;
}

// ── HMAC token ────────────────────────────────────────────────────────────────
function makeToken(mid, maxPl) {
    return crypto.createHmac('sha256', SECRET_KEY).update(`${mid}|${maxPl}`).digest('hex');
}

// ── AUTH2 sessions + signed offline leases ──────────────────────────────────
const SESSION_LIFETIME_MS = clampInt(process.env.LICENSE_SESSION_TTL_MS, 10 * 60 * 1000, 1000, 24 * 60 * 60 * 1000);
const sessions = new Map(); // session_id -> session state; token stored as hash only

function restorePersistedSessions() {
    const nowMs = Date.now();
    let restored = 0;
    for (const state of getStore().loadActiveLicenseSessions(nowMs)) {
        if (!state || !isHexLen(state.session_id, 32) || !state.mid || !state.token_hash) continue;
        sessions.set(state.session_id, state);
        restored++;
    }
    getStore().cleanupExpiredLicenseSessions(nowMs);
    if (restored) log('INFO', `Restored ${restored} active AUTH2 session(s) from SQLite.`);
}

function persistSession(sessionId, state) {
    getStore().saveLicenseSession(sessionId, { ...state, session_id: sessionId });
}

function hashSessionToken(token) {
    return crypto.createHmac('sha256', SECRET_KEY).update(`session-token-v2|${token}`).digest('hex');
}
function timingSafeEqualHex(a, b) {
    if (!isHexString(String(a || '')) || !isHexString(String(b || ''))) return false;
    const aa = Buffer.from(String(a), 'hex');
    const bb = Buffer.from(String(b), 'hex');
    if (aa.length !== bb.length || aa.length === 0) return false;
    try { return crypto.timingSafeEqual(aa, bb); } catch { return false; }
}
function licenseKeyHash(key) {
    return crypto.createHmac('sha256', SECRET_KEY).update(`license-key|${normalizeLicenseKey(key || '')}`).digest('hex');
}
function createSession(mid, ip, entry, maxPlayers) {
    const sessionId = crypto.randomBytes(16).toString('hex');
    const sessionToken = crypto.randomBytes(32).toString('hex');
    const nowMs = Date.now();
    const state = {
        session_id: sessionId,
        mid,
        token_hash: hashSessionToken(sessionToken),
        ip,
        risk_flags: [],
        created_at: nowMs,
        expires_at: nowMs + SESSION_LIFETIME_MS,
        last_seen: nowMs,
        max_players_snapshot: maxPlayers,
        license_key_hash_snapshot: licenseKeyHash(entry?.license_key || ''),
    };
    sessions.set(sessionId, state);
    persistSession(sessionId, state);
    incMetric('license_sessions_created_total');
    sseBroadcast('session.created', { mid, session_id: sessionId, ip, expires_at: state.expires_at });
    return { sessionId, sessionToken, expiresAt: state.expires_at };
}
function validateSession(mid, sessionId, sessionToken, ip) {
    const sid = String(sessionId || '').trim();
    const st = String(sessionToken || '').trim();
    if (!isHexLen(sid, 32) || !isHexLen(st, 64)) return { ok: false, reason: 'DENY_SESSION' };
    let state = sessions.get(sid);
    if (!state) {
        state = getStore().loadLicenseSession(sid);
        if (state) sessions.set(sid, state);
    }
    if (!state) return { ok: false, reason: 'DENY_SESSION' };
    if (state.mid !== mid) return { ok: false, reason: 'DENY_SESSION' };
    if (Date.now() > state.expires_at) {
        sessions.delete(sid);
        getStore().deleteLicenseSession(sid);
        incMetric('license_sessions_expired_total');
        sseBroadcast('session.expired', { mid, session_id: sid, reason: 'ttl' });
        return { ok: false, reason: 'SESSION_EXPIRED' };
    }
    if (!timingSafeEqualHex(hashSessionToken(st), state.token_hash)) return { ok: false, reason: 'DENY_SESSION' };
    let changed = false;
    if (state.ip && ip && state.ip !== ip && !state.risk_flags.includes('ip_changed')) {
        state.risk_flags.push('ip_changed');
        changed = true;
        log('WARNING', `SESSION IP-CHANGE [${mid}] sid=${sid.slice(0, 8)} prev=${state.ip} new=${ip}`);
        sseBroadcast('machine.multi_ip', { mid, prev_ip: state.ip, new_ip: ip, session_id: sid });
    }
    const nowMs = Date.now();
    if (!state.last_seen || nowMs - state.last_seen >= HB_DB_TOUCH_MS) {
        state.last_seen = nowMs;
        changed = true;
    }
    if (changed) persistSession(sid, state);
    return { ok: true, session_id: sid, state };
}
function revokeSessionsForMachine(mid) {
    let n = 0;
    for (const [sid, state] of sessions) {
        if (state.mid === mid) {
            sessions.delete(sid);
            n++;
            sseBroadcast('session.expired', { mid, session_id: sid, reason: 'revoke' });
        }
    }
    const deleted = getStore().deleteLicenseSessionsForMachine(mid);
    n = Math.max(n, Number(deleted) || 0);
    if (n) incMetric('license_sessions_expired_total', n);
    return n;
}
function cleanupExpiredSessions() {
    const nowMs = Date.now();
    let n = 0;
    for (const [sid, state] of sessions) {
        if (state.expires_at <= nowMs) {
            sessions.delete(sid);
            n++;
            sseBroadcast('session.expired', { mid: state.mid, session_id: sid, reason: 'ttl' });
        }
    }
    const deleted = getStore().cleanupExpiredLicenseSessions(nowMs);
    n = Math.max(n, Number(deleted) || 0);
    if (n) incMetric('license_sessions_expired_total', n);
}
setInterval(cleanupExpiredSessions, 60 * 1000).unref();

function base64UrlEncodeBuffer(buf) {
    return Buffer.from(buf).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function base64UrlEncodeJson(obj) {
    return base64UrlEncodeBuffer(Buffer.from(JSON.stringify(obj), 'utf8'));
}
function getOfflineLeaseTtlMs(entry) {
    const tier = entry?.tier || 'basic';
    const defaults = {
        trial: 30 * 60 * 1000,
        basic: 6 * 60 * 60 * 1000,
        pro: 24 * 60 * 60 * 1000,
        unlimited: 48 * 60 * 60 * 1000,
    };
    const s = loadSettings();
    const byMs = s.offline_lease_ttl_ms_by_tier || s.lease_ttl_ms_by_tier || {};
    const byHours = s.offline_lease_ttl_hours_by_tier || s.lease_ttl_hours_by_tier || {};
    if (Number.isFinite(Number(byMs[tier])) && Number(byMs[tier]) > 0) return Number(byMs[tier]);
    if (Number.isFinite(Number(byHours[tier])) && Number(byHours[tier]) > 0) return Number(byHours[tier]) * 60 * 60 * 1000;
    return defaults[tier] || defaults.basic;
}
function signOfflineLease(payloadB64) {
    return base64UrlEncodeBuffer(crypto.createHmac('sha256', SECRET_KEY).update(payloadB64).digest());
}
function issueOfflineLease(mid, entry, maxPlayers) {
    const issuedAt = Date.now();
    const payload = {
        v: 1,
        alg: 'HS256',
        mid,
        license_key_hash: licenseKeyHash(entry?.license_key || ''),
        max_players: maxPlayers,
        tier: entry?.tier || 'basic',
        issued_at: issuedAt,
        expires_at: issuedAt + getOfflineLeaseTtlMs(entry),
        server_time: issuedAt,
        lease_id: crypto.randomBytes(12).toString('hex'),
        features: entry?.features && typeof entry.features === 'object' ? entry.features : {},
    };
    const payloadB64 = base64UrlEncodeJson(payload);
    const lease = `${payloadB64}.${signOfflineLease(payloadB64)}`;
    incMetric('license_offline_leases_issued_total');
    sseBroadcast('lease.issued', { mid, lease_id: payload.lease_id, expires_at: payload.expires_at });
    return lease;
}
function parseTagged(parts) {
    const out = {};
    for (const part of parts || []) {
        const i = String(part).indexOf(':');
        if (i <= 0) continue;
        out[String(part.slice(0, i)).toUpperCase()] = String(part.slice(i + 1));
    }
    return out;
}
function licenseKeyAccepted(entry, sentKey, justRegistered) {
    const currentKey = normalizeLicenseKey(entry?.license_key || '');
    if (!canAuthWithoutLicenseKey(entry, { strict: STRICT_LICENSE_KEY, justRegistered })) {
        return { ok: false, reason: 'missing key in strict mode', needSyncKey: false };
    }
    if (!currentKey || justRegistered) return { ok: true, needSyncKey: !!currentKey && justRegistered };
    const prev = Array.isArray(entry.previous_keys) ? entry.previous_keys : [];
    const validKey = !!sentKey && (sentKey === currentKey || prev.some(p => {
        const prevKey = normalizeLicenseKey(p?.key || '');
        return prevKey && prevKey === sentKey && (!p.expires_at || p.expires_at > Date.now());
    }));
    const shouldBootstrapKey = canBootstrapLicenseKey(entry, {
        sentKey,
        justRegistered,
        enabled: licenseKeyBootstrapEnabled(),
    });
    if (!validKey && !shouldBootstrapKey) return { ok: false, reason: 'wrong key', needSyncKey: false };
    return { ok: true, needSyncKey: shouldBootstrapKey || (!!sentKey && sentKey !== currentKey) };
}
function ipAllowedForEntry(entry, ip) {
    if (!Array.isArray(entry?.allowed_ips) || entry.allowed_ips.length === 0) return true;
    return entry.allowed_ips.some(a => {
        const rule = String(a || '').trim();
        return rule === ip || (rule.endsWith('.*') && ip.startsWith(rule.slice(0, -1)));
    });
}
function markMachineOnline(mid, ip, entry, maxPl, players = null) {
    if (active[mid] && active[mid].ip !== ip) {
        log('WARNING', `AUTH MULTI-IP  [${mid}]  prev=${active[mid].ip}  new=${ip}`);
        sendTelegram(`⚠️ <b>Multi-IP Alert</b>\n<code>${mid}</code>\nPrev: ${active[mid].ip}\nNew: ${ip}\n— Possible license sharing —`);
        dispatchWebhook('machine.multi_ip', { mid, prev_ip: active[mid].ip, new_ip: ip });
    }
    const wasOnline = !!active[mid];
    active[mid] = {
        ...active[mid],
        ip,
        players: players === null ? (active[mid]?.players || 0) : players,
        last_seen: now(),
        uptime_start: active[mid]?.uptime_start || now(),
    };
    if (!wasOnline) {
        pushHistory({ mid, event: 'online', ip });
        sendTelegram(`🟢 <b>Server Online</b>\n<code>${mid}</code>\nIP: ${ip}\nTier: ${entry?.tier || 'basic'} | Max: ${maxPl}`);
        dispatchWebhook('machine.online', { mid, ip, tier: entry?.tier || 'basic', max_players: maxPl });
    }
    getGeoIP(ip).then(geo => {
        if (geo && active[mid]) {
            active[mid].geo = geo;
            sseBroadcast('machine.geo', { mid, ip, geo });
        }
    });
}
function buildHeartbeatExtras(mid, entry, sessionState = null) {
    let extra = '';
    const pendingMax = _pendingMaxPlayers.get(mid);
    const pendingKey = normalizeLicenseKey(_pendingKey.get(mid) || '');
    const currentKey = normalizeLicenseKey(entry?.license_key || '');
    let keyToPush = pendingKey;
    if (!keyToPush && sessionState && currentKey && licenseKeyHash(currentKey) !== sessionState.license_key_hash_snapshot) {
        keyToPush = currentKey;
    }
    if (pendingMax !== undefined && pendingMax > 0 && pendingMax <= MAX_PLAYERS_LIMIT) {
        extra += ` CFGMAX:${pendingMax}`;
        _pendingMaxPlayers.delete(mid);
        log('INFO', `HB CFGMAX   [${mid}]  max_players -> ${pendingMax} (real-time push)`);
        sseBroadcast('cfgmax.synced', { mid, max_players: pendingMax });
    }
    if (keyToPush) {
        extra += ` KEY:${keyToPush}`;
        _pendingKey.delete(mid);
        log('INFO', `HB KEY-SYNC [${mid}]  license_key updated (real-time push)`);
        sseBroadcast('key.synced', { mid });
    }
    return extra;
}
function processHeartbeatState(mid, ip, entry, cnt, maxPl) {
    let dbChanged = false;
    if (cnt > maxPl) {
        if (!entry._alertOver) {
            entry._alertOver = true;
            dbChanged = true;
            sendTelegram(`🚨 <b>Player Over Limit</b>\n<code>${mid}</code>\n${cnt}/${maxPl} players (over by ${cnt - maxPl})\n— Client tự chặn login mới —`);
            dispatchWebhook('players.over', { mid, ip, players: cnt, max_players: maxPl });
        }
        log('WARNING', `HB OVER     ${ip}  [${mid}]  players=${cnt}>${maxPl}  (soft-limit, không revoke)`);
    } else if (cnt < Math.floor(maxPl * 0.9) && entry._alertOver) {
        entry._alertOver = false;
        dbChanged = true;
    }
    if (cnt > (entry.peak_players || 0)) {
        entry.peak_players = cnt;
        dbChanged = true;
    }
    if (maxPl > 0 && cnt >= Math.floor(maxPl * 0.8) && !entry._alert80) {
        entry._alert80 = true;
        dbChanged = true;
        sendTelegram(`⚡ <b>Player Alert 80%</b>\n<code>${mid}</code>\n${cnt}/${maxPl} players`);
        dispatchWebhook('players.high', { mid, ip, players: cnt, max_players: maxPl });
    } else if (maxPl > 0 && cnt < Math.floor(maxPl * 0.7) && entry._alert80) {
        entry._alert80 = false;
        dbChanged = true;
    }
    const nowMs = Date.now();
    if (!entry.last_hb_ts || nowMs - entry.last_hb_ts >= HB_DB_TOUCH_MS) {
        entry.last_hb_ts = nowMs;
        dbChanged = true;
    }
    return dbChanged;
}

// ── SSE dashboard realtime ───────────────────────────────────────────────────
const sseClients = new Set();
function sseBroadcast(event, data = {}) {
    const payload = `event: ${event}\ndata: ${JSON.stringify({ ...data, ts: Date.now() })}\n\n`;
    for (const res of Array.from(sseClients)) {
        try { res.write(payload); } catch { sseClients.delete(res); }
    }
}
function wsBroadcast(event, data = {}) { sseBroadcast(event, data); }
function sseClientCount() { return sseClients.size; }
setInterval(() => sseBroadcast('ping', { ts: Date.now() }), 25 * 1000).unref();
setInterval(() => { collectDynamicMetrics(); sseBroadcast('metrics.updated', { active: metrics.license_active_machines, players: metrics.license_total_players }); }, 15 * 1000).unref();


// ── Offline detector (5 min timeout) ─────────────────────────────────────────
setInterval(() => {
    const cutoff = Date.now() - 5 * 60 * 1000;
    for (const [mid, info] of Object.entries(active)) {
        const ls = new Date(info.last_seen.replace(' ', 'T')).getTime();
        if (ls < cutoff) {
            pushHistory({ mid, event: 'offline', ip: info.ip, reason: 'timeout' });
            log('INFO', `OFFLINE     [${mid}]  ip=${info.ip}  (timeout)`);
            sendTelegram(`🔴 <b>Server Offline</b>\n<code>${mid}</code>\nIP: ${info.ip}\nReason: heartbeat timeout`);
            dispatchWebhook('machine.offline', { mid, ip: info.ip, reason: 'timeout' });
            delete active[mid];
        }
    }
}, 60 * 1000);

// ── Zombie license detector (offline > ZOMBIE_DAYS) ───────────────────────────
setInterval(() => {
    const db = loadDB();
    let changed = false;
    const cutoff = Date.now() - ZOMBIE_DAYS * 86400000;
    for (const [mid, entry] of Object.entries(db)) {
        if (entry.revoked || active[mid] || entry.zombie) continue;
        if (entry.last_hb_ts && entry.last_hb_ts < cutoff) {
            entry.zombie = true; changed = true;
            log('INFO', `ZOMBIE      [${mid}]  (no heartbeat > ${ZOMBIE_DAYS}d)`);
            sendTelegram(`⚠️ <b>Zombie License</b>\n<code>${mid}</code>\nKhông heartbeat > ${ZOMBIE_DAYS} ngày`);
        }
    }
    if (changed) saveDB(db);
}, 6 * 60 * 60 * 1000);

// ── Replay nonce cleanup (60s) ─────────────────────────────────────────────────
// seenNonces map có thể grow unbounded nếu không cleanup định kỳ.
// Mỗi 60s quét và xóa nonces đã hết hạn.
setInterval(() => {
    const now = Date.now();
    for (const [k, exp] of seenNonces) {
        if (exp < now) seenNonces.delete(k);
    }
}, 60 * 1000).unref();

// ── Auto-ban expiry cleanup (hourly) ──────────────────────────────────────────
// Tự động gỡ ban khi hết thời hạn auto-ban (24h).
setInterval(() => {
    const bans = loadBans();
    let changed = false;
    const now = Date.now();
    for (const [range, info] of Object.entries(bans)) {
        if (info.expires_at && info.expires_at < now) {
            delete bans[range];
            changed = true;
            log('INFO', `AUTO-BAN EXPIRED ${range}`);
        }
    }
    if (changed) saveBans(bans);
}, 60 * 60 * 1000).unref();

// ── Agent token expiry check (daily 9:00 AM) ──────────────────────────────────
scheduleDailyTask('agent_token_expiry', 9, 5, () => {
    const expiring = agent.checkExpiringTokens();
    if (expiring.length > 0) {
        const list = expiring.map(e => `• <code>${e.mid}</code> — còn ${e.daysLeft} ngày`).join('\n');
        sendTelegram(`🔑 <b>Agent Token sắp hết hạn</b>\n${list}\n\nCần chạy lại lệnh cài đặt agent để cấp token mới.`);
    }
});

// ── Cron: daily backup 3:00 AM ────────────────────────────────────────────────
function scheduleDailyTask(name, hour, minute, fn, { dayOfWeek = null } = {}) {
    let lastRunKey = '';
    setInterval(() => {
        const d = new Date();
        if (d.getHours() !== hour || d.getMinutes() !== minute) return;
        if (dayOfWeek !== null && d.getDay() !== dayOfWeek) return;
        const key = d.toISOString().slice(0, 10);
        if (lastRunKey === key) return;
        lastRunKey = key;
        try { fn(); } catch (e) { log('ERROR', `${name} failed: ${e.message}`); }
    }, 60 * 1000).unref();
}

scheduleDailyTask('daily_backup', 3, 0, () => { doBackup().catch(() => {}); });

// ── Cron: expiry warning 9:00 AM daily ───────────────────────────────────────
scheduleDailyTask('expiry_warning', 9, 0, () => {
    const db = loadDB();
    for (const [mid, entry] of Object.entries(db)) {
        if (entry.revoked) continue;
        const info = expiryInfo(entry);
        if (!info) continue;
        if ([7, 3, 1].includes(info.daysLeft)) {
            sendTelegram(`⏰ <b>License sắp hết hạn</b>\n<code>${mid}</code>\nCòn ${info.daysLeft} ngày (${info.date})\nGhi chú: ${entry.note || '—'}`);
            log('INFO', `EXPIRY WARN [${mid}] ${info.daysLeft}d left`);
        }
    }
});

// ── Cron: weekly report Monday 8:00 AM ───────────────────────────────────────
scheduleDailyTask('weekly_report', 8, 0, () => {
    const db = loadDB();
    const total = Object.keys(db).length;
    const online = Object.keys(active).length;
    const revoked = Object.values(db).filter(v => v.revoked).length;
    const totalPlayers = Object.values(active).reduce((s, r) => s + (r.players || 0), 0);
    const expiringSoon = Object.entries(db)
        .filter(([, v]) => { if (v.revoked) return false; const i = expiryInfo(v); return i && i.daysLeft >= 0 && i.daysLeft <= 7; })
        .map(([mid, v]) => `• <code>${mid}</code> — còn ${expiryInfo(v).daysLeft} ngày`);
    let msg = `📊 <b>Báo cáo tuần</b>\n\n🟢 Online: ${online}/${total}\n🔴 Revoked: ${revoked}\n👥 Players: ${totalPlayers}`;
    if (expiringSoon.length) msg += `\n\n⏰ <b>Sắp hết hạn (≤7 ngày):</b>\n${expiringSoon.join('\n')}`;
    sendTelegram(msg);
    log('INFO', 'Weekly report sent');
}, { dayOfWeek: 1 });

// ── TCP License Server ────────────────────────────────────────────────────────
function tcpReply(socket, plain) {
    try {
        if (socket.destroyed) return;
        socket.end(tcpEncrypt(String(plain || 'DENY')));
    } catch {
        try { socket.destroy(); } catch {}
    }
}

function handleTcpRequest(socket, ip, raw) {
    if (tcpRlBlocked(ip)) {
        incMetric('license_tcp_rate_limited_total');
        tcpReply(socket, 'DENY');
        return;
    }

    if (isIpBanned(ip, loadBans())) {
        tcpReply(socket, 'DENY');
        log('WARNING', `TCP BANNED  ${ip}`);
        return;
    }

    const plain = tcpDecrypt(raw);
    if (!plain) {
        if (lastTcpDecryptError === 'replay') incMetric('license_tcp_replay_fail_total');
        else incMetric('license_tcp_decrypt_fail_total');
        log('WARNING', `TCP DECRYPT FAIL  ${ip}`);
        tcpRlFail(ip);
        socket.end();
        return;
    }

    if (isMaintenanceActive()) {
        tcpReply(socket, 'MAINTENANCE');
        return;
    }

    const parts = plain.trim().split(/\s+/);
    const cmd = parts[0]?.toUpperCase();

    // ── AUTH2 (session token + signed offline lease) ─────────────────────
    if (cmd === 'AUTH2' && parts[1]) {
        const mid = parts[1];
        const sentKey = normalizeLicenseKey(parts[2] || '');
        const deny = (payload, reason) => {
            tcpReply(socket, payload || 'DENY');
            incMetric('license_tcp_auth2_deny_total');
            log('WARNING', `AUTH2 DENY  ${ip}  [${mid}]  (${reason})`);
            tcpRlFail(ip);
        };

        if (!isValidMachineId(mid)) return deny('DENY', 'invalid machine id');

        const db = loadDB();
        let entry = db[mid];
        let justRegistered = false;

        if (!entry) {
            if (!autoRegisterEnabled()) return deny('DENY', 'not registered');
            const newKey = generateLicenseKey();
            entry = {
                max_players: DEFAULT_PLAYERS,
                tier: 'basic',
                note: 'Auto-registered',
                added: now(),
                revoked: false,
                auto: true,
                peak_players: 0,
                license_key: newKey,
                zombie: false,
            };
            db[mid] = entry;
            saveDB(db);
            justRegistered = true;
            log('INFO', `AUTH2 AUTO  ${ip}  [${mid}]  tier=basic max=${DEFAULT_PLAYERS}  key=${newKey}`);
            sendTelegram(`🆕 <b>Auto-registered</b>\n<code>${mid}</code>\nIP: ${ip}\nTier: Basic · Max: ${DEFAULT_PLAYERS} players · Không giới hạn ngày\nKey: ${newKey}`);
        }

        normalizeMachineEntry(entry);
        if (entry.revoked) {
            revokeSessionsForMachine(mid);
            delete active[mid];
            return deny('REVOKE', 'revoked');
        }
        if (isExpired(entry)) {
            revokeSessionsForMachine(mid);
            delete active[mid];
            dispatchWebhook('license.expired', { mid, ip });
            return deny('EXPIRED', 'expired');
        }

        const keyCheck = licenseKeyAccepted(entry, sentKey, justRegistered);
        if (!keyCheck.ok) return deny('DENY', keyCheck.reason);
        if (!ipAllowedForEntry(entry, ip)) return deny('DENY', 'IP not whitelisted');

        const maxPl = getMaxPlayers(entry);
        const token = makeToken(mid, maxPl);
        const sess = createSession(mid, ip, entry, maxPl);
        const lease = issueOfflineLease(mid, entry, maxPl);
        let agentTok = '';
        try { agentTok = agent.getOrCreateToken(mid) || ''; }
        catch (e) { log('WARNING', `AGENT TOKEN FAIL [${mid}] ${e.message}`); }
        if (!isValidAgentToken(agentTok)) agentTok = '';

        const currentKey = normalizeLicenseKey(entry.license_key || '');
        const needSyncKey = justRegistered || keyCheck.needSyncKey || (currentKey && sentKey && sentKey !== currentKey);
        let okPayload = `OK2 ${maxPl} ${token} SID:${sess.sessionId} ST:${sess.sessionToken} EXP:${sess.expiresAt} LEASE:${lease} SERVER_TIME:${Date.now()} CFGMAX:${maxPl}`;
        if (needSyncKey && currentKey) okPayload += ` KEY:${currentKey}`;
        if (agentTok) okPayload += ` AGENT:${agentTok}`;
        tcpReply(socket, okPayload);

        markMachineOnline(mid, ip, entry, maxPl);
        if (entry.zombie) {
            entry.zombie = false;
            db[mid] = entry;
            saveDB(db);
        }
        tcpRlSuccess(ip);
        incMetric('license_tcp_auth2_ok_total');
        log('INFO', `AUTH2 OK    ${ip}  [${mid}]  tier=${entry.tier} max=${maxPl} sid=${sess.sessionId.slice(0, 8)}`);
        return;
    }

    // ── AUTH ──────────────────────────────────────────────────────────────
    if (cmd === 'AUTH' && parts[1]) {
        const mid = parts[1];
        const sentKey = normalizeLicenseKey(parts[2] || '');
        if (!isValidMachineId(mid)) {
            tcpReply(socket, 'DENY');
            log('WARNING', `AUTH DENY   ${ip}  [${mid}]  (invalid machine id)`);
            tcpRlFail(ip);
            return;
        }

        const db = loadDB();
        let entry = db[mid];
        let justRegistered = false;

        if (!entry) {
            if (!autoRegisterEnabled()) {
                tcpReply(socket, 'DENY');
                log('WARNING', `AUTH DENY   ${ip}  [${mid}]  (not registered)`);
                tcpRlFail(ip);
                return;
            }
            const newKey = generateLicenseKey();
            entry = {
                max_players: DEFAULT_PLAYERS,
                tier: 'basic',
                note: 'Auto-registered',
                added: now(),
                revoked: false,
                auto: true,
                peak_players: 0,
                license_key: newKey,
                zombie: false,
            };
            db[mid] = entry;
            saveDB(db);
            justRegistered = true;
            log('INFO', `AUTH AUTO   ${ip}  [${mid}]  tier=basic max=${DEFAULT_PLAYERS}  key=${newKey}`);
            sendTelegram(`🆕 <b>Auto-registered</b>\n<code>${mid}</code>\nIP: ${ip}\nTier: Basic · Max: ${DEFAULT_PLAYERS} players · Không giới hạn ngày\nKey: ${newKey}`);
        }

        if (entry.revoked) {
            revokeSessionsForMachine(mid);
            tcpReply(socket, 'DENY');
            log('WARNING', `AUTH DENY   ${ip}  [${mid}]  (revoked)`);
            tcpRlFail(ip);
            return;
        }
        if (isExpired(entry)) {
            revokeSessionsForMachine(mid);
            tcpReply(socket, 'DENY');
            log('WARNING', `AUTH DENY   ${ip}  [${mid}]  (expired)`);
            dispatchWebhook('license.expired', { mid, ip });
            tcpRlFail(ip);
            return;
        }

        if (!canAuthWithoutLicenseKey(entry, { strict: STRICT_LICENSE_KEY, justRegistered })) {
            tcpReply(socket, 'DENY');
            log('WARNING', `AUTH DENY   ${ip}  [${mid}]  (missing key in strict mode)`);
            tcpRlFail(ip);
            return;
        }

        let shouldBootstrapKey = false;
        const currentKey = normalizeLicenseKey(entry.license_key || '');
        if (currentKey && !justRegistered) {
            const prev = Array.isArray(entry.previous_keys) ? entry.previous_keys : [];
            const validKey = !!sentKey && (sentKey === currentKey || prev.some(p => {
                const prevKey = normalizeLicenseKey(p?.key || '');
                return prevKey && prevKey === sentKey && (!p.expires_at || p.expires_at > Date.now());
            }));
            shouldBootstrapKey = canBootstrapLicenseKey(entry, {
                sentKey,
                justRegistered,
                enabled: licenseKeyBootstrapEnabled(),
            });
            if (!validKey && !shouldBootstrapKey) {
                tcpReply(socket, 'DENY');
                log('WARNING', `AUTH DENY   ${ip}  [${mid}]  (wrong key)`);
                tcpRlFail(ip);
                return;
            }
            if (shouldBootstrapKey) {
                log('INFO', `AUTH BOOTSTRAP-KEY ${ip}  [${mid}]  -> sync license.key`);
            }
            if (!shouldBootstrapKey && sentKey && sentKey !== currentKey) {
                log('INFO', `AUTH OLD-KEY ${ip}  [${mid}]  -> sync new key`);
            }
        }

        if (Array.isArray(entry.allowed_ips) && entry.allowed_ips.length > 0) {
            const allowed = entry.allowed_ips.some(a => {
                const rule = String(a || '').trim();
                return rule === ip || (rule.endsWith('.*') && ip.startsWith(rule.slice(0, -1)));
            });
            if (!allowed) {
                tcpReply(socket, 'DENY');
                log('WARNING', `AUTH DENY   ${ip}  [${mid}]  (IP not whitelisted)`);
                tcpRlFail(ip);
                return;
            }
        }

        if (active[mid] && active[mid].ip !== ip) {
            log('WARNING', `AUTH MULTI-IP  [${mid}]  prev=${active[mid].ip}  new=${ip}`);
            sendTelegram(`⚠️ <b>Multi-IP Alert</b>\n<code>${mid}</code>\nPrev: ${active[mid].ip}\nNew: ${ip}\n— Possible license sharing —`);
            dispatchWebhook('machine.multi_ip', { mid, prev_ip: active[mid].ip, new_ip: ip });
        }

        const maxPl = getMaxPlayers(entry);
        const token = makeToken(mid, maxPl);
        let agentTok = '';
        try { agentTok = agent.getOrCreateToken(mid) || ''; }
        catch (e) { log('WARNING', `AGENT TOKEN FAIL [${mid}] ${e.message}`); }
        if (!isValidAgentToken(agentTok)) agentTok = '';

        const needSyncKey = justRegistered || shouldBootstrapKey || (currentKey && sentKey && sentKey !== currentKey);
        let okPayload = `OK ${maxPl} ${token}`;
        if (needSyncKey && currentKey) okPayload += ` ${currentKey}`;
        if (agentTok) okPayload += ` ${agentTok}`;
        tcpReply(socket, okPayload);

        const wasOnline = !!active[mid];
        active[mid] = {
            ip,
            players: active[mid]?.players || 0,
            last_seen: now(),
            uptime_start: active[mid]?.uptime_start || now(),
        };
        if (!wasOnline) {
            pushHistory({ mid, event: 'online', ip });
            sendTelegram(`🟢 <b>Server Online</b>\n<code>${mid}</code>\nIP: ${ip}\nTier: ${entry.tier} | Max: ${maxPl}`);
            dispatchWebhook('machine.online', { mid, ip, tier: entry.tier, max_players: maxPl });
        }

        if (entry.zombie) {
            entry.zombie = false;
            db[mid] = entry;
            saveDB(db);
        }
        tcpRlSuccess(ip);
        incMetric('license_tcp_auth_ok_total');
        log('INFO', `AUTH OK     ${ip}  [${mid}]  tier=${entry.tier} max=${maxPl}`);

        getGeoIP(ip).then(geo => {
            if (geo && active[mid]) {
                active[mid].geo = geo;
            }
        });
        return;
    }

    // ── HB2 (session token heartbeat, no license_key on wire) ─────────────
    if (cmd === 'HB2' && parts[1] && parts[2] !== undefined) {
        const mid = parts[1];
        const rawCnt = Number.parseInt(parts[2], 10);
        const cnt = Number.isFinite(rawCnt) ? Math.max(0, Math.min(rawCnt, MAX_PLAYERS_LIMIT)) : 0;
        const tagged = parseTagged(parts.slice(3));
        const deny = (payload, reason) => {
            tcpReply(socket, payload || 'DENY_SESSION');
            incMetric('license_tcp_hb2_deny_total');
            log('WARNING', `HB2 DENY    ${ip}  [${mid}]  (${reason})`);
            tcpRlFail(ip);
        };
        if (!isValidMachineId(mid)) return deny('DENY', 'invalid machine id');

        const db = loadDB();
        const entry = db[mid];
        if (!entry || entry.revoked) {
            revokeSessionsForMachine(mid);
            tcpReply(socket, 'REVOKE');
            incMetric('license_tcp_hb2_deny_total');
            if (active[mid]) {
                pushHistory({ mid, event: 'offline', ip, reason: 'revoked' });
                dispatchWebhook('license.revoked', { mid, ip });
            }
            delete active[mid];
            log('WARNING', `HB2 REVOKE  ${ip}  [${mid}]  (revoked)`);
            return;
        }
        if (isExpired(entry)) {
            revokeSessionsForMachine(mid);
            tcpReply(socket, 'EXPIRED');
            incMetric('license_tcp_hb2_deny_total');
            if (active[mid]) {
                pushHistory({ mid, event: 'offline', ip, reason: 'expired' });
                dispatchWebhook('license.expired', { mid, ip });
            }
            delete active[mid];
            log('WARNING', `HB2 EXPIRED ${ip}  [${mid}]`);
            return;
        }

        const sessionCheck = validateSession(mid, tagged.SID, tagged.ST, ip);
        if (!sessionCheck.ok) return deny(sessionCheck.reason, sessionCheck.reason.toLowerCase());

        normalizeMachineEntry(entry);
        const maxPl = getMaxPlayers(entry);
        let dbChanged = processHeartbeatState(mid, ip, entry, cnt, maxPl);
        if (dbChanged) { db[mid] = entry; saveDB(db); }
        pushStat(mid, cnt);

        if (active[mid] && active[mid].ip && active[mid].ip !== ip) {
            log('WARNING', `HB2 IP-CHANGE [${mid}] prev=${active[mid].ip} new=${ip}`);
        }

        const nowMs = Date.now();
        sessionCheck.state.expires_at = nowMs + SESSION_LIFETIME_MS;
        sessionCheck.state.last_seen = nowMs;
        sessionCheck.state.max_players_snapshot = maxPl;
        const extra = buildHeartbeatExtras(mid, entry, sessionCheck.state);
        const leaseRefreshMs = clampInt(process.env.LICENSE_OFFLINE_LEASE_REFRESH_MS, 30 * 60 * 1000, 60 * 1000, 24 * 60 * 60 * 1000);
        let leaseExtra = '';
        if (!sessionCheck.state.last_lease_issued_at || nowMs - sessionCheck.state.last_lease_issued_at >= leaseRefreshMs) {
            leaseExtra = ` LEASE:${issueOfflineLease(mid, entry, maxPl)}`;
            sessionCheck.state.last_lease_issued_at = nowMs;
        }
        persistSession(sessionCheck.session_id, sessionCheck.state);
        tcpReply(socket, `OK2 ${maxPl} EXP:${sessionCheck.state.expires_at} SERVER_TIME:${nowMs}${extra}${leaseExtra}`);

        active[mid] = {
            ...active[mid],
            ip,
            players: cnt,
            last_seen: now(),
            uptime_start: active[mid]?.uptime_start || now(),
        };
        tcpRlSuccess(ip);
        incMetric('license_tcp_hb2_ok_total');
        sseBroadcast('machine.hb', { mid, ip, players: cnt, max_players: maxPl, exp: sessionCheck.state.expires_at });
        if (extra || shouldLogHeartbeat(mid)) {
            log('INFO', `HB2 OK      ${ip}  [${mid}]  players=${cnt}/${maxPl}${extra ? ' +' + extra : ''}`);
        }
        return;
    }

    // ── HB ────────────────────────────────────────────────────────────────
    if (cmd === 'HB' && parts[1] && parts[2] !== undefined) {
        const mid = parts[1];
        const rawCnt = Number.parseInt(parts[2], 10);
        const cnt = Number.isFinite(rawCnt) ? Math.max(0, Math.min(rawCnt, MAX_PLAYERS_LIMIT)) : 0;
        if (!isValidMachineId(mid)) {
            tcpReply(socket, 'DENY');
            log('WARNING', `HB DENY     ${ip}  [${mid}]  (invalid machine id)`);
            tcpRlFail(ip);
            return;
        }

        const db = loadDB();
        const entry = db[mid];
        if (!entry || entry.revoked) {
            revokeSessionsForMachine(mid);
            tcpReply(socket, 'REVOKE');
            if (active[mid]) {
                pushHistory({ mid, event: 'offline', ip, reason: 'revoked' });
                dispatchWebhook('license.revoked', { mid, ip });
            }
            delete active[mid];
            log('WARNING', `HB REVOKE   ${ip}  [${mid}]  (revoked)`);
            return;
        }
        if (isExpired(entry)) {
            revokeSessionsForMachine(mid);
            tcpReply(socket, 'REVOKE');
            if (active[mid]) {
                pushHistory({ mid, event: 'offline', ip, reason: 'expired' });
                dispatchWebhook('license.expired', { mid, ip });
            }
            delete active[mid];
            log('WARNING', `HB REVOKE   ${ip}  [${mid}]  (expired)`);
            return;
        }

        normalizeMachineEntry(entry);

        const hbKey = normalizeLicenseKey(parts[3] || '');
        const currentKey = normalizeLicenseKey(entry.license_key || '');
        let hbKeyNeedsSync = false;
        if (hbKey && currentKey) {
            const prev = Array.isArray(entry.previous_keys) ? entry.previous_keys : [];
            const validHbKey = hbKey === currentKey || prev.some(p => {
                const prevKey = normalizeLicenseKey(p?.key || '');
                return prevKey && prevKey === hbKey && (!p.expires_at || p.expires_at > Date.now());
            });
            if (!validHbKey) {
                tcpReply(socket, 'REVOKE');
                log('WARNING', `HB REVOKE   ${ip}  [${mid}]  (wrong heartbeat key)`);
                tcpRlFail(ip);
                return;
            }
            hbKeyNeedsSync = hbKey !== currentKey;
        }

        const maxPl = getMaxPlayers(entry);
        let dbChanged = false;
        if (cnt > maxPl) {
            if (!entry._alertOver) {
                entry._alertOver = true;
                dbChanged = true;
                sendTelegram(`🚨 <b>Player Over Limit</b>\n<code>${mid}</code>\n${cnt}/${maxPl} players (over by ${cnt - maxPl})\n— Client tự chặn login mới —`);
                dispatchWebhook('players.over', { mid, ip, players: cnt, max_players: maxPl });
            }
            log('WARNING', `HB OVER     ${ip}  [${mid}]  players=${cnt}>${maxPl}  (soft-limit, không revoke)`);
        } else if (cnt < Math.floor(maxPl * 0.9) && entry._alertOver) {
            entry._alertOver = false;
            dbChanged = true;
        }

        if (cnt > (entry.peak_players || 0)) {
            entry.peak_players = cnt;
            dbChanged = true;
        }

        if (maxPl > 0 && cnt >= Math.floor(maxPl * 0.8) && !entry._alert80) {
            entry._alert80 = true;
            dbChanged = true;
            sendTelegram(`⚡ <b>Player Alert 80%</b>\n<code>${mid}</code>\n${cnt}/${maxPl} players`);
            dispatchWebhook('players.high', { mid, ip, players: cnt, max_players: maxPl });
        } else if (maxPl > 0 && cnt < Math.floor(maxPl * 0.7) && entry._alert80) {
            entry._alert80 = false;
            dbChanged = true;
        }

        const nowMs = Date.now();
        if (!entry.last_hb_ts || nowMs - entry.last_hb_ts >= HB_DB_TOUCH_MS) {
            entry.last_hb_ts = nowMs;
            dbChanged = true;
        }
        if (dbChanged) {
            db[mid] = entry;
            saveDB(db);
        }

        pushStat(mid, cnt);

        if (active[mid] && active[mid].ip && active[mid].ip !== ip) {
            log('WARNING', `HB IP-CHANGE [${mid}] prev=${active[mid].ip} new=${ip}`);
        }

        let hbExtra = '';
        const pendingMax = _pendingMaxPlayers.get(mid);
        const pendingKey = normalizeLicenseKey(_pendingKey.get(mid) || '');
        const keyToPush = pendingKey || (hbKeyNeedsSync ? currentKey : '');

        if (pendingMax !== undefined && pendingMax > 0 && pendingMax <= MAX_PLAYERS_LIMIT) {
            hbExtra += ` CFGMAX:${pendingMax}`;
            _pendingMaxPlayers.delete(mid);
            log('INFO', `HB CFGMAX   [${mid}]  max_players -> ${pendingMax} (real-time push)`);
        }
        if (keyToPush) {
            hbExtra += ` KEY:${keyToPush}`;
            _pendingKey.delete(mid);
            log('INFO', `HB KEY-SYNC [${mid}]  license_key updated (real-time push)`);
        }

        tcpReply(socket, `OK ${maxPl}${hbExtra}`);
        active[mid] = {
            ...active[mid],
            ip,
            players: cnt,
            last_seen: now(),
            uptime_start: active[mid]?.uptime_start || now(),
        };
        tcpRlSuccess(ip);
        incMetric('license_tcp_hb_ok_total');
        sseBroadcast('machine.hb', { mid, ip, players: cnt, max_players: maxPl });
        if (hbExtra || shouldLogHeartbeat(mid)) {
            log('INFO', `HB OK       ${ip}  [${mid}]  players=${cnt}/${maxPl}${hbExtra ? ' +' + hbExtra : ''}`);
        }
        return;
    }

    tcpReply(socket, 'DENY');
    tcpRlFail(ip);
}

let _tlsCertificateInfo = { valid_to: null, fingerprint256: null, subject_alt_name: null };
const _tlsConnections = new Set();
const _tlsHandshakeLog = new Map();

function normalizeTlsFingerprint(value) {
    return String(value || '').replace(/^sha256:/i, '').replace(/[^0-9a-f]/gi, '').toUpperCase();
}

function classifyTlsClientError(err) {
    const code = String(err?.code || '');
    const message = String(err?.message || 'unknown');
    const lower = `${code} ${message}`.toLowerCase();
    if (lower.includes('wrong version number') ||
        lower.includes('unknown protocol') ||
        lower.includes('http request')) {
        return {
            kind: 'PLAINTEXT',
            message: 'client sent raw TCP/HTTP to the TLS-only license port; rebuild/deploy the TLS license_check client',
        };
    }
    if (lower.includes('certificate') || lower.includes('unknown ca') || lower.includes('bad certificate')) {
        return { kind: 'CERTIFICATE', message };
    }
    if (lower.includes('handshake timeout')) return { kind: 'TIMEOUT', message };
    return { kind: code || 'TLS_ERROR', message };
}

function shouldLogTlsHandshake(ip, kind) {
    const nowMs = Date.now();
    const key = `${ip}|${kind}`;
    const previous = _tlsHandshakeLog.get(key) || 0;
    if (nowMs - previous < TLS_HANDSHAKE_LOG_WINDOW_MS) return false;
    _tlsHandshakeLog.set(key, nowMs);
    if (_tlsHandshakeLog.size > 4096) {
        for (const [k, ts] of _tlsHandshakeLog) {
            if (nowMs - ts >= TLS_HANDSHAKE_LOG_WINDOW_MS) _tlsHandshakeLog.delete(k);
            if (_tlsHandshakeLog.size <= 2048) break;
        }
    }
    return true;
}

function readTlsMaterial() {
    if (!TLS_KEY_FILE || !TLS_CERT_FILE) {
        throw new Error('LICENSE_TLS_KEY_FILE and LICENSE_TLS_CERT_FILE are required; raw TCP is disabled.');
    }
    const key = fs.readFileSync(TLS_KEY_FILE);
    const cert = fs.readFileSync(TLS_CERT_FILE);
    const ca = TLS_CA_FILE ? fs.readFileSync(TLS_CA_FILE) : undefined;
    const x509 = new crypto.X509Certificate(cert);
    const validToMs = Date.parse(x509.validTo);
    if (!Number.isFinite(validToMs) || validToMs <= Date.now()) {
        throw new Error(`TLS certificate is expired or invalid: validTo=${x509.validTo}`);
    }
    _tlsCertificateInfo = {
        valid_to: new Date(validToMs).toISOString(),
        fingerprint256: normalizeTlsFingerprint(x509.fingerprint256 || ''),
        subject: x509.subject || null,
        subject_alt_name: x509.subjectAltName || null,
        serial_number: x509.serialNumber || null,
    };
    return {
        key,
        cert,
        ...(ca ? { ca } : {}),
        minVersion: TLS_MIN_VERSION,
        ...(TLS_MTLS ? { requestCert: true, rejectUnauthorized: true } : { requestCert: false }),
        handshakeTimeout: TLS_HANDSHAKE_TIMEOUT_MS,
        honorCipherOrder: true,
    };
}

function configureLicenseSocket(socket) {
    const ip = normalizeIp(socket.remoteAddress || '?');
    socket.setNoDelay(true);
    socket.setKeepAlive(true, 30000);
    socket.setTimeout(TCP_SOCKET_TIMEOUT_MS);
    if (typeof socket.disableRenegotiation === 'function') {
        try { socket.disableRenegotiation(); } catch {}
    }

    _tlsConnections.add(socket);
    let tracked = true;
    const currentConns = (_tcpConnsPerIp.get(ip) || 0) + 1;
    _tcpConnsPerIp.set(ip, currentConns);
    socket.once('close', () => {
        _tlsConnections.delete(socket);
        if (!tracked) return;
        tracked = false;
        const n = (_tcpConnsPerIp.get(ip) || 1) - 1;
        if (n <= 0) _tcpConnsPerIp.delete(ip);
        else _tcpConnsPerIp.set(ip, n);
    });

    if (currentConns > TCP_MAX_CONCURRENT_PER_IP) {
        incMetric('license_tcp_rate_limited_total');
        tcpReply(socket, 'DENY');
        return;
    }

    let buf = '';
    let handled = false;
    socket.on('data', (chunk) => {
        if (handled) return;
        buf += chunk.toString('utf8');
        if (buf.length > TCP_MAX_BUFFER_BYTES) {
            handled = true;
            log('WARNING', `TLS FRAME OVERSIZE ${ip} len=${buf.length}`);
            tcpRlFail(ip);
            socket.destroy();
            return;
        }
        const nl = buf.indexOf('\n');
        if (nl === -1) return;
        const raw = buf.slice(0, nl + 1);
        handled = true;
        try {
            handleTcpRequest(socket, ip, raw);
        } catch (err) {
            log('ERROR', `TLS LICENSE HANDLER ERROR ${ip}: ${err.message}`);
            socket.destroy();
        }
    });

    socket.on('error', () => {});
    socket.on('timeout', () => socket.destroy());
}

const tlsServer = tls.createServer(readTlsMaterial(), (socket) => {
    incMetric('license_tls_handshake_ok_total');
    configureLicenseSocket(socket);
});
tlsServer.maxConnections = clampEnvInt(process.env.LICENSE_TLS_MAX_CONNECTIONS, 4096, 64, 100000);
tlsServer.on('tlsClientError', (err, socket) => {
    incMetric('license_tls_handshake_fail_total');
    const ip = normalizeIp(socket?.remoteAddress || '?');
    const detail = classifyTlsClientError(err);
    if (shouldLogTlsHandshake(ip, detail.kind)) {
        const code = String(err?.code || '').slice(0, 80);
        log('WARNING', `TLS HANDSHAKE ${detail.kind} ${ip}${code ? ` code=${code}` : ''}: ${String(detail.message).slice(0, 220)}`);
    }
    try { socket?.destroy(); } catch {}
});
tlsServer.on('error', (err) => {
    log('ERROR', `TLS listener error: ${err.message}`);
});

process.on('SIGHUP', () => {
    try {
        const options = readTlsMaterial();
        tlsServer.setSecureContext(options);
        log('INFO', `TLS certificate reloaded; valid_to=${_tlsCertificateInfo.valid_to}`);
    } catch (err) {
        log('ERROR', `TLS certificate reload failed; keeping current certificate: ${err.message}`);
    }
});

// ── Express + HTTP server ─────────────────────────────────────────────────────
const app        = express();
const httpServer = http.createServer(app);
app.disable('x-powered-by');
app.use((req, res, next) => {
    for (const [k, v] of Object.entries(securityHeaders())) res.setHeader(k, v);
    next();
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
function clientIp(req) {
    return normalizeIp(req.socket.remoteAddress || '?');
}
const webSessionStore = new SqliteSessionStore({ store: getStore(), ttlMs: 8 * 60 * 60 * 1000 });
const sessionParser = session({
    store: webSessionStore,
    secret: RUNTIME_SECRETS.sessionSecret,
    resave: false, saveUninitialized: false,
    cookie: {
        maxAge: 8 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'lax',
        secure: RUNTIME.cookieSecure,
    },
});
app.use(sessionParser);
app.use((req, res, next) => {
    if (req.session?.loggedIn || req.session?.pendingTwoFactor) {
        res.set('Cache-Control', 'no-store');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
    }
    next();
});
app.use((req, res, next) => {
    if (req.session) res.locals.csrfToken = ensureCsrfToken(req.session);
    next();
});
app.use((req, res, next) => {
    if ((req.path || '').startsWith('/agent/') || (req.path || '') === '/import') return next();
    if (verifyCsrfRequest(req)) return next();
    res.status(403).type('text/plain').send('CSRF token invalid');
});
app.use((req, res, next) => {
    if (req.method === 'POST' && req.session?.loggedIn && !(req.path || '').startsWith('/agent/')) {
        const bodyKeys = req.body && typeof req.body === 'object' ? Object.keys(req.body).filter(k => k !== '_csrf') : [];
        audit(req, 'admin.post', { path: req.path, bodyKeys });
    }
    next();
});

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 } });

function suggestedDataDir() {
    return path.resolve(__dirname, '..', 'runtime', 'license-server-data');
}

function saveInitialSetup({ username, password, confirmPassword, dataDir }) {
    const user = String(username || '').trim();
    const pass = String(password || '');
    const confirm = String(confirmPassword || '');
    const dirInput = String(dataDir || '').trim();
    if (!user) return { ok: false, error: 'Tài khoản admin không được để trống.' };
    if (pass.length < 10) return { ok: false, error: 'Mật khẩu cần ít nhất 10 ký tự.' };
    if (pass !== confirm) return { ok: false, error: 'Xác nhận mật khẩu không khớp.' };
    if (!dirInput) return { ok: false, error: 'Vui lòng chọn thư mục lưu data.' };

    let targetInfo;
    try {
        targetInfo = resolveDataDirInfo({ appDir: __dirname, env: { LICENSE_DATA_DIR: dirInput } });
    } catch (e) {
        return { ok: false, error: e.message };
    }

    if (path.resolve(targetInfo.dir) !== path.resolve(DATA_DIR)) {
        return { ok: false, error: 'SQLite đang mở tại LICENSE_DATA_DIR hiện tại. Hãy đổi LICENSE_DATA_DIR trong PM2 rồi restart trước khi setup.' };
    }

    rememberDataDir(__dirname, targetInfo.dir);
    const nextCreds = { user, pass_hash: hashPassword(pass) };
    getStore().saveAdminCredentials(nextCreds);
    adminCreds = nextCreds;
    WEB_USER = user;
    setupRequired = false;

    return {
        ok: true,
        restartRequired: false,
        dataDir: targetInfo.dir,
    };
}

function auth(req, res, next) {
    if (setupRequired) return res.redirect('/setup');
    if (req.session.pendingTwoFactor) return res.redirect('/verify-2fa');
    if (req.session.loggedIn) return next();
    res.redirect('/login');
}

function metricsAccessGranted(req) {
    const s = loadSettings();
    if (s.metrics_public === true) return true;
    if (req.session && req.session.loggedIn) return true;
    const expected = String(s.metrics_token || process.env.LICENSE_METRICS_TOKEN || RUNTIME_SECRETS.metricsToken || '').trim();
    if (!expected) return false;
    const authz = String(req.headers.authorization || '');
    const bearer = authz.toLowerCase().startsWith('bearer ') ? authz.slice(7).trim() : '';
    const supplied = String(req.query.token || bearer || '').trim();
    if (!supplied) return false;
    const a = Buffer.from(supplied);
    const b = Buffer.from(expected);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

app.get('/events', auth, (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();
    sseClients.add(res);
    res.write(`event: hello\ndata: ${JSON.stringify({ ts: Date.now(), clients: sseClients.size })}\n\n`);
    req.on('close', () => { sseClients.delete(res); });
});

app.get('/metrics', (req, res) => {
    if (!metricsAccessGranted(req)) {
        res.setHeader('WWW-Authenticate', 'Bearer realm="license-metrics"');
        return res.status(401).type('text/plain').send('metrics authentication required\n');
    }
    res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.send(renderMetrics());
});

// ── Login / Logout ────────────────────────────────────────────────────────────
app.get('/setup', (req, res) => {
    if (!setupRequired) return res.redirect('/login');
    res.render('setup', { error: null, suggestedDataDir: suggestedDataDir(), result: null });
});
app.post('/setup', (req, res) => {
    if (!setupRequired) return res.redirect('/login');
    const result = saveInitialSetup({
        username: req.body.username,
        password: req.body.password,
        confirmPassword: req.body.confirm_password,
        dataDir: req.body.data_dir,
    });
    if (!result.ok) {
        return res.render('setup', {
            error: result.error,
            suggestedDataDir: req.body.data_dir || suggestedDataDir(),
            result: null,
        });
    }
    auditEvent(AUDIT_FILE, {
        action: 'setup.created',
        user: req.body.username,
        ip: clientIp(req),
        details: { dataDir: result.dataDir, restartRequired: result.restartRequired },
    });
    res.render('setup', { error: null, suggestedDataDir: result.dataDir, result });
});

app.get('/login', (req, res) => {
    if (setupRequired) return res.redirect('/setup');
    res.render('login', { error: null });
});
app.post('/login', (req, res) => {
    if (setupRequired) return res.redirect('/setup');
    const ip = clientIp(req);
    const rl = rl_check(ip);
    if (rl.blocked) return res.render('login', { error: `Quá nhiều lần thử. Chờ ${rl.remaining} phút.` });
    if (verifyAdminLogin(req.body.username, req.body.password)) {
        rl_clear(ip);
        clearFailDelay(ip);
        clearLockHistory(ip);
        const s = loadSettings();
        if (s.totp_enabled && s.totp_secret) {
            return req.session.regenerate((err) => {
                if (err) return res.render('login', { error: 'Không thể tạo session mới.' });
                req.session.pendingTwoFactor = true;
                res.redirect('/verify-2fa');
            });
        }
        return req.session.regenerate((err) => {
            if (err) return res.render('login', { error: 'Không thể tạo session mới.' });
            req.session.loggedIn = true;
            log('INFO', `LOGIN OK  ip=${ip}`);
            res.redirect('/');
        });
    }
    // ── Fail2ban + progressive delay ───────────────────────────────────────
    rl_fail(ip);
    const e = loginAttempts[ip];
    const left = e ? Math.max(0, MAX_ATTEMPTS - (e.count || 0)) : MAX_ATTEMPTS;
    log('WARNING', `LOGIN FAIL  ip=${ip}  (${left} left)`);

    // Kiểm tra nếu IP này vừa bị lock → fail2ban auto-ban
    if (left === 0) {
        const shouldAutoBan = recordLockEvent(ip);
        if (shouldAutoBan) {
            const bans = loadBans();
            bans[ip] = {
                note: `Auto-ban: ${AUTO_BAN_LOCK_THRESHOLD} lockouts in ${Math.round(AUTO_BAN_WINDOW_MS / 3600000)}h`,
                added: now(),
                disabled: false,
                expires_at: Date.now() + AUTO_BAN_DURATION_MS,
            };
            saveBans(bans);
            log('SECURITY', `AUTO-BAN ${ip} — ${AUTO_BAN_LOCK_THRESHOLD}+ lockouts in ${Math.round(AUTO_BAN_WINDOW_MS / 3600000)}h`);
            sendTelegram(`🚫 <b>Auto-Ban</b>\nIP: ${ip}\nLý do: ${AUTO_BAN_LOCK_THRESHOLD}+ lần lock trong ${Math.round(AUTO_BAN_WINDOW_MS / 3600000)}h\nHết hạn: 24h`);
            return res.render('login', { error: 'IP đã bị khóa tự động trong 24h do quá nhiều lần thử sai.' });
        }
    }

    // Progressive delay: làm chậm response để chống brute-force timing
    const delayMs = getProgressiveDelayMs(ip);
    setTimeout(() => {
        res.render('login', { error: `Sai tài khoản hoặc mật khẩu. Còn ${left} lần thử.` });
    }, delayMs);
});
app.get('/logout', auth, (req, res) => res.render('logout', { flash: null }));
app.post('/logout', auth, (req, res) => { req.session.destroy(); res.redirect('/login'); });

// ── 2FA ───────────────────────────────────────────────────────────────────────
app.get('/verify-2fa', (req, res) => {
    if (!req.session.pendingTwoFactor) return res.redirect('/login');
    res.render('verify-2fa', { error: null });
});
app.post('/verify-2fa', (req, res) => {
    if (!req.session.pendingTwoFactor) return res.redirect('/login');
    const s     = loadSettings();
    const token = (req.body.token || '').replace(/\s/g, '');
    const valid = speakeasy.totp.verify({ secret: s.totp_secret, encoding: 'base32', token, window: 1 });
    if (valid) {
        return req.session.regenerate((err) => {
            if (err) return res.render('verify-2fa', { error: 'Không thể tạo session mới.' });
            req.session.loggedIn = true;
            log('INFO', 'LOGIN 2FA OK');
            res.redirect('/');
        });
    }
    log('WARNING', 'LOGIN 2FA FAIL');
    res.render('verify-2fa', { error: 'Mã OTP không đúng.' });
});

// ── Dashboard ─────────────────────────────────────────────────────────────────
app.get('/', auth, (req, res) => {
    const db = loadDB();
    const rows = Object.entries(active).map(([mid, info]) => {
        const e   = db[mid] || {};
        const maxPl = getMaxPlayers(e);
        const hasPending = _pendingMaxPlayers.has(mid) || _pendingKey.has(mid);
        return {
            mid, ...info, max_players: maxPl, tier: e.tier || 'basic',
            pct: maxPl ? Math.round((info.players || 0) / maxPl * 100) : 0,
            pending_cfg: hasPending,
            pending_max: _pendingMaxPlayers.has(mid),
            pending_key: _pendingKey.has(mid),
        };
    }).sort((a, b) => b.players - a.players);
    const storeHealth = getStore().health();
    res.render('dashboard', {
        active_count:  rows.length,
        total:         Object.keys(db).length,
        revoked:       Object.values(db).filter(v => v.revoked).length,
        expired:       Object.values(db).filter(v => !v.revoked && isExpired(v)).length,
        total_players: rows.reduce((s, r) => s + (r.players || 0), 0),
        maintenance:   isMaintenanceActive(),
        rows, flash: consumeFlash(req.session), TIERS,
        last_updated:  new Date().toLocaleTimeString('vi-VN'),
        transport: {
            mode: 'TLS-only',
            port: TLS_PORT,
            listening: tlsServer.listening,
            connections: _tlsConnections.size,
            certificate_valid_to: _tlsCertificateInfo.valid_to,
            min_version: TLS_MIN_VERSION,
        },
        database: storeHealth,
        auth2_sessions: sessions.size,
    });
});

// ── Machines ──────────────────────────────────────────────────────────────────
app.get('/machines', auth, (req, res) => {
    const db = loadDB();
    const rows = Object.entries(db)
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([mid, info]) => {
            return {
                mid, ...info,
                max_players: getMaxPlayers(info),
                isOnline: !!active[mid],
                expiry:   expiryInfo(info),
                expired:  isExpired(info),
                currentPlayers: active[mid]?.players || 0,
                pending_cfg: _pendingMaxPlayers.has(mid) || _pendingKey.has(mid),
                pending_max: _pendingMaxPlayers.has(mid),
                pending_key: _pendingKey.has(mid),
            };
        });
    res.render('machines', { rows, TIERS, plans: loadPlans(), flash: consumeFlash(req.session) });
});

app.post('/add', auth, (req, res) => {
    const mid        = (req.body.mid || '').trim();
    const tier       = ['trial', 'basic', 'pro', 'unlimited'].includes(req.body.tier) ? req.body.tier : 'basic';
    const maxPl      = tier === 'unlimited' ? UNLIMITED_PLAYERS : normalizeMaxPlayers(req.body.max_players, tier);
    const trial_days = clampInt(req.body.trial_days, 7, 1, 3650);
    const expires_at = req.body.expires_at || null;
    const note       = (req.body.note || '').trim();
    const gen_key    = req.body.gen_key === '1';
    const ips_raw    = (req.body.allowed_ips || '').trim();
    const allowed_ips = ips_raw ? ips_raw.split(/[\n,]/).map(s => s.trim()).filter(Boolean) : [];

    if (!mid) { req.session.flash = { type: 'danger', msg: 'Machine ID trống.' }; return res.redirect('/machines'); }
    if (!isValidMachineId(mid)) {
        req.session.flash = { type: 'danger', msg: 'Machine ID không hợp lệ. MAC phải có dạng 00:0c:29:2f:71:4e|hostname.' };
        return res.redirect('/machines');
    }
    const db = loadDB();
    const license_key = gen_key ? generateLicenseKey() : null;
    db[mid] = {
        max_players: maxPl, tier,
        trial_days: tier === 'trial' ? trial_days : undefined,
        expires_at: expires_at || undefined,
        note, added: now(), revoked: false, peak_players: 0,
        license_key: license_key || undefined,
        allowed_ips: allowed_ips.length ? allowed_ips : undefined,
        zombie: false,
    };
    // Luôn chuẩn hóa max_players trước khi lưu (phòng trường hợp string "0", v.v.)
    db[mid].max_players = getMaxPlayers(db[mid]);
    saveDB(db);
    const keyMsg = license_key ? ` | Key: ${license_key}` : '';
    req.session.flash = { type: 'success', msg: `Đã cấp: ${mid} (${TIERS[tier].label}, max ${maxPl})${keyMsg}` };
    log('INFO', `WEB ADD [${mid}] tier=${tier} max=${maxPl} key=${license_key || 'none'}`);
    res.redirect('/machines');
});

app.post('/update-limit', auth, (req, res) => {
    const mid   = (req.body.mid || '').trim();
    const maxPl = Number.parseInt(req.body.max_players, 10);
    const tier  = req.body.tier;
    const exp   = req.body.expires_at;
    const db    = loadDB();
    if (!db[mid]) { req.session.flash = { type: 'danger', msg: 'Không tìm thấy.' }; return res.redirect('/machines'); }
    const oldMax = getMaxPlayers(db[mid]);
    if (Number.isFinite(maxPl) && maxPl > 0) {
        db[mid].max_players = Math.min(maxPl, MAX_PLAYERS_LIMIT);
    } else if (db[mid]) {
        // Chỉ dùng getMaxPlayers làm fallback nếu user không tự set max_players
        db[mid].max_players = getMaxPlayers(db[mid]);
    }
    if (tier && TIERS[tier]) db[mid].tier = tier;
    db[mid].max_players = normalizeMaxPlayers(db[mid].max_players, db[mid].tier);
    if (exp !== undefined) db[mid].expires_at = exp || undefined;
    saveDB(db);

    // ── CFGMAX real-time push ─────────────────────────────────────────────
    // Nếu max_players thay đổi và máy đang online, đánh dấu pending để
    // lần HB tiếp theo (≤5s) server gửi CFGMAX:<new_max>.
    const newMax = getMaxPlayers(db[mid]);
    if (newMax !== oldMax && active[mid]) {
        _pendingMaxPlayers.set(mid, newMax);
        log('INFO', `CFGMAX PENDING [${mid}] ${oldMax} → ${newMax} (will push on next HB)`);
    }

    req.session.flash = { type: 'success', msg: `Đã cập nhật ${mid}` + (active[mid] && newMax !== oldMax ? ' — thay đổi sẽ có hiệu lực trong ≤5s.' : '') };
    res.redirect('/machines');
});

// Gia hạn license
app.post('/renew', auth, (req, res) => {
    const mid  = (req.body.mid || '').trim();
    const days = clampInt(req.body.days, 30, 1, 3650);
    const db   = loadDB();
    if (!db[mid]) { req.session.flash = { type: 'danger', msg: 'Không tìm thấy.' }; return res.redirect('/machines'); }
    const entry = db[mid];
    // Tính ngày mới từ expires_at hiện tại hoặc hôm nay
    const base = entry.expires_at && new Date(entry.expires_at + 'T23:59:59') > new Date()
        ? new Date(entry.expires_at + 'T23:59:59')
        : new Date();
    base.setDate(base.getDate() + days);
    entry.expires_at = base.toISOString().slice(0, 10);
    entry.revoked    = false;
    db[mid] = entry; saveDB(db);
    req.session.flash = { type: 'success', msg: `Đã gia hạn ${mid} +${days} ngày → ${entry.expires_at}` };
    log('INFO', `WEB RENEW [${mid}] +${days}d → ${entry.expires_at}`);
    res.redirect('/machines');
});

// Tạo / đổi license key — giữ key cũ trong previous_keys[] với grace period 24h
// để các gs đang chạy còn dùng key cũ vẫn AUTH/HB được trong khi tự đồng bộ key mới.
const KEY_GRACE_MS = 24 * 60 * 60 * 1000;
app.post('/gen-key', auth, (req, res) => {
    const mid = (req.body.mid || '').trim();
    const db  = loadDB();
    if (!db[mid]) { req.session.flash = { type: 'danger', msg: 'Không tìm thấy.' }; return res.redirect('/machines'); }
    const entry = db[mid];
    const oldKey = entry.license_key;
    const newKey = generateLicenseKey();
    if (oldKey && oldKey !== newKey) {
        if (!Array.isArray(entry.previous_keys)) entry.previous_keys = [];
        // Loại key cũ trùng + key đã hết grace
        const cutoff = Date.now();
        entry.previous_keys = entry.previous_keys
            .filter(p => p && p.key && p.key !== oldKey && p.key !== newKey
                         && (!p.expires_at || p.expires_at > cutoff));
        entry.previous_keys.push({ key: oldKey, expires_at: cutoff + KEY_GRACE_MS });
        // Giới hạn lịch sử
        if (entry.previous_keys.length > 5) entry.previous_keys = entry.previous_keys.slice(-5);
    }
    entry.license_key = newKey;
    db[mid] = entry; saveDB(db);

    // ── KEY real-time sync ────────────────────────────────────────────────
    // Nếu máy đang online, đánh dấu pending để lần HB tiếp theo (≤5s)
    // server gửi KEY:<new_key> xuống client, client tự ghi license.key.
    if (active[mid]) {
        _pendingKey.set(mid, newKey);
        log('INFO', `KEY-SYNC PENDING [${mid}] → new key will be pushed on next HB`);
    }

    req.session.flash = { type: 'success',
        msg: `Key mới [${mid}]: ${newKey} — key cũ còn hiệu lực 24h để client đồng bộ.` + (active[mid] ? ' Key sẽ được đẩy xuống máy trong ≤5s.' : '') };
    log('INFO', `WEB GEN-KEY [${mid}] (old key kept ${KEY_GRACE_MS/3600000}h grace)`);
    res.redirect('/machines');
});

// Xóa license key (backwards compat)
app.post('/remove-key', auth, (req, res) => {
    const mid = (req.body.mid || '').trim();
    const db  = loadDB();
    if (db[mid]) { delete db[mid].license_key; saveDB(db); }
    req.session.flash = { type: 'success', msg: `Đã xóa key của ${mid}` };
    res.redirect('/machines');
});

app.post('/revoke', auth, (req, res) => {
    const mid = (req.body.mid || '').trim(), db = loadDB();
    if (db[mid]) { db[mid].revoked = true; saveDB(db); }
    revokeSessionsForMachine(mid);
    if (active[mid]) { delete active[mid]; }
    dispatchWebhook('license.revoked', { mid });
    req.session.flash = { type: 'success', msg: `Đã revoke: ${mid}` };
    log('INFO', `WEB REVOKE [${mid}]`); res.redirect('/machines');
});
app.post('/restore', auth, (req, res) => {
    const mid = (req.body.mid || '').trim(), db = loadDB();
    if (db[mid]) { db[mid].revoked = false; db[mid].zombie = false; saveDB(db); }
    req.session.flash = { type: 'success', msg: `Đã khôi phục: ${mid}` };
    log('INFO', `WEB RESTORE [${mid}]`); res.redirect('/machines');
});

// Xóa hẳn machine khỏi hệ thống — gỡ whitelist + agent + active + stats
// Dùng khi khách trả máy / đổi máy hẳn / muốn cấp lại từ đầu.
app.post('/delete-machine', auth, (req, res) => {
    const mid = (req.body.mid || '').trim();
    if (!mid) { req.session.flash = { type: 'danger', msg: 'Machine ID trống.' }; return res.redirect('/machines'); }
    const db = loadDB();
    if (!db[mid]) { req.session.flash = { type: 'danger', msg: `Không tìm thấy ${mid}.` }; return res.redirect('/machines'); }

    revokeSessionsForMachine(mid);
    delete db[mid];
    saveDB(db);

    // Gỡ agent (token + state + queues)
    try { agent.uninstall(mid); } catch {}

    // Gỡ khỏi active map
    if (active[mid]) {
        delete active[mid];
    }

    // Xóa time-series stats
    try {
        const stats = loadStats();
        if (stats[mid]) {
            delete stats[mid];
            getStore().saveStats(stats);
        }
    } catch {}

    pushHistory({ mid, event: 'deleted', ip: '—', reason: 'admin delete' });
    dispatchWebhook('machine.deleted', { mid });
    log('INFO', `WEB DELETE  [${mid}]  (full removal)`);
    sendTelegram(`🗑 <b>Machine deleted</b>\n<code>${mid}</code>`);
    req.session.flash = { type: 'success', msg: `Đã xóa hoàn toàn ${mid} (whitelist + agent + stats).` };
    res.redirect('/machines');
});

// Transfer license
app.post('/transfer', auth, (req, res) => {
    const oldMid = (req.body.old_mid || '').trim();
    const newMid = (req.body.new_mid || '').trim();
    if (!oldMid || !newMid || oldMid === newMid) {
        req.session.flash = { type: 'danger', msg: 'Machine ID không hợp lệ.' }; return res.redirect('/machines');
    }
    const db = loadDB();
    if (!db[oldMid]) { req.session.flash = { type: 'danger', msg: `${oldMid} không tồn tại.` }; return res.redirect('/machines'); }
    if (db[newMid])  { req.session.flash = { type: 'danger', msg: `${newMid} đã tồn tại.` }; return res.redirect('/machines'); }
    db[newMid] = { ...db[oldMid], note: `${db[oldMid].note || ''} [Transfer từ ${oldMid}]`.trim() };
    delete db[oldMid]; saveDB(db);
    if (active[oldMid]) { active[newMid] = { ...active[oldMid] }; delete active[oldMid]; }
    const stats = loadStats();
    if (stats[oldMid]) { stats[newMid] = stats[oldMid]; delete stats[oldMid]; getStore().saveStats(stats); }
    pushHistory({ mid: newMid, event: 'transfer', ip: active[newMid]?.ip || '—', reason: `from ${oldMid}` });
    req.session.flash = { type: 'success', msg: `Đã transfer ${oldMid} → ${newMid}` };
    log('INFO', `WEB TRANSFER [${oldMid}] → [${newMid}]`); res.redirect('/machines');
});

// ── Bulk actions ──────────────────────────────────────────────────────────────
function parseMidsFromBody(body) {
    const raw = body.mids;
    if (typeof raw === 'string') {
        try { return JSON.parse(raw); } catch { return raw.split(',').map(s => s.trim()).filter(Boolean); }
    }
    if (Array.isArray(raw)) return raw.map(s => String(s).trim()).filter(Boolean);
    return [];
}

app.post('/bulk-revoke', auth, (req, res) => {
    const mids = parseMidsFromBody(req.body);
    if (!mids.length) { req.session.flash = { type: 'danger', msg: 'Chưa chọn máy nào.' }; return res.redirect('/machines'); }
    const db = loadDB();
    let done = 0;
    for (const mid of mids) {
        if (db[mid] && !db[mid].revoked) { db[mid].revoked = true; revokeSessionsForMachine(mid); if (active[mid]) delete active[mid]; done++; }
    }
    saveDB(db);
    req.session.flash = { type: 'success', msg: `Đã revoke ${done}/${mids.length} máy.` };
    log('INFO', `WEB BULK-REVOKE ${done}/${mids.length}`);
    res.redirect('/machines');
});

app.post('/bulk-renew', auth, (req, res) => {
    const mids = parseMidsFromBody(req.body);
    const days = clampInt(req.body.days, 30, 1, 3650);
    if (!mids.length) { req.session.flash = { type: 'danger', msg: 'Chưa chọn máy nào.' }; return res.redirect('/machines'); }
    const db = loadDB();
    let done = 0;
    for (const mid of mids) {
        const entry = db[mid];
        if (!entry) continue;
        const base = entry.expires_at && new Date(entry.expires_at + 'T23:59:59') > new Date()
            ? new Date(entry.expires_at + 'T23:59:59')
            : new Date();
        base.setDate(base.getDate() + days);
        entry.expires_at = base.toISOString().slice(0, 10);
        entry.revoked = false;
        done++;
    }
    saveDB(db);
    req.session.flash = { type: 'success', msg: `Đã gia hạn ${done}/${mids.length} máy +${days} ngày.` };
    log('INFO', `WEB BULK-RENEW ${done}/${mids.length} +${days}d`);
    res.redirect('/machines');
});

app.post('/bulk-delete', auth, (req, res) => {
    const mids = parseMidsFromBody(req.body);
    if (!mids.length) { req.session.flash = { type: 'danger', msg: 'Chưa chọn máy nào.' }; return res.redirect('/machines'); }
    const db = loadDB();
    let done = 0;
    for (const mid of mids) {
        if (!db[mid]) continue;
        revokeSessionsForMachine(mid);
        delete db[mid];
        try { agent.uninstall(mid); } catch {}
        if (active[mid]) { delete active[mid]; }
        try {
            const stats = loadStats();
            if (stats[mid]) { delete stats[mid]; getStore().saveStats(stats); }
        } catch {}
        pushHistory({ mid, event: 'deleted', ip: '—', reason: 'bulk delete' });
        done++;
    }
    saveDB(db);
    req.session.flash = { type: 'success', msg: `Đã xóa ${done}/${mids.length} máy.` };
    log('INFO', `WEB BULK-DELETE ${done}/${mids.length}`);
    res.redirect('/machines');
});

app.post('/bulk-tier', auth, (req, res) => {
    const mids = parseMidsFromBody(req.body);
    const tier = ['trial', 'basic', 'pro', 'unlimited'].includes(req.body.tier) ? req.body.tier : null;
    if (!mids.length || !tier) {
        req.session.flash = { type: 'danger', msg: 'Chưa chọn máy hoặc tier không hợp lệ.' };
        return res.redirect('/machines');
    }
    const db = loadDB();
    let done = 0;
    for (const mid of mids) {
        if (db[mid]) { db[mid].tier = tier; db[mid].max_players = getMaxPlayers(db[mid]); done++; }
    }
    saveDB(db);
    req.session.flash = { type: 'success', msg: `Đã đổi ${done}/${mids.length} máy sang ${TIERS[tier].label}.` };
    log('INFO', `WEB BULK-TIER ${done}/${mids.length} → ${tier}`);
    res.redirect('/machines');
});

// ── Maintenance mode ──────────────────────────────────────────────────────────
app.post('/maintenance', auth, (req, res) => {
    const s = loadSettings();
    const action  = req.body.action;
    const minutes = clampInt(req.body.minutes, 0, 0, 1440);
    if (action === 'on') {
        s.maintenance       = true;
        s.maintenance_until = minutes > 0 ? Date.now() + minutes * 60000 : null;
        saveSettings(s);
        log('INFO', `MAINTENANCE ON  ${minutes ? minutes + 'min' : '∞'}`);
        req.session.flash = { type: 'success', msg: `Maintenance BẬT${minutes ? ` (${minutes} phút)` : ' (vô thời hạn)'}` };
    } else {
        s.maintenance = false; delete s.maintenance_until; saveSettings(s);
        log('INFO', 'MAINTENANCE OFF');
        req.session.flash = { type: 'success', msg: 'Maintenance TẮT' };
    }
    res.redirect('/');
});

// ── Plans ─────────────────────────────────────────────────────────────────────
app.get('/plans', auth, (req, res) => {
    res.render('plans', { plans: loadPlans(), TIERS, flash: consumeFlash(req.session) });
});
app.post('/plans/add', auth, (req, res) => {
    const plans = loadPlans();
    const p = {
        id: crypto.randomBytes(4).toString('hex'),
        name:        (req.body.name || '').trim(),
        tier:        ['trial', 'basic', 'pro', 'unlimited'].includes(req.body.tier) ? req.body.tier : 'basic',
        max_players: normalizeMaxPlayers(req.body.max_players, req.body.tier),
        trial_days:  clampInt(req.body.trial_days, 0, 0, 3650),
        expires_days:clampInt(req.body.expires_days, 0, 0, 3650),
        note:        (req.body.note || '').trim(),
    };
    if (!p.name) { req.session.flash = { type: 'danger', msg: 'Tên plan trống.' }; return res.redirect('/plans'); }
    plans.push(p); savePlans(plans);
    req.session.flash = { type: 'success', msg: `Đã tạo plan: ${p.name}` };
    res.redirect('/plans');
});
app.post('/plans/delete', auth, (req, res) => {
    savePlans(loadPlans().filter(p => p.id !== req.body.id));
    req.session.flash = { type: 'success', msg: 'Đã xóa plan.' };
    res.redirect('/plans');
});

// ── Settings ──────────────────────────────────────────────────────────────────
function operationsSnapshot() {
    const backups = fs.existsSync(BACKUP_DIR)
        ? fs.readdirSync(BACKUP_DIR).filter(f => f.startsWith('license_') && f.endsWith('.sqlite3')).sort()
        : [];
    const latestBackup = backups.length ? backups[backups.length - 1] : null;
    const memory = process.memoryUsage();
    return {
        runtime: RUNTIME,
        processInfo: {
            pid: process.pid,
            uptime: Math.floor(process.uptime()),
            node: process.version,
            platform: `${process.platform} ${process.arch}`,
            rssMb: Math.round(memory.rss / 1024 / 1024),
            heapUsedMb: Math.round(memory.heapUsed / 1024 / 1024),
        },
        backupInfo: {
            count: backups.length,
            latest: latestBackup,
            dir: BACKUP_DIR,
        },
        dataDir: DATA_DIR,
        dataDirSource: DATA_DIR_INFO.source,
        webUrl: `http://${BIND_HOST}:${WEB_PORT}`,
        tlsAddress: `${BIND_HOST}:${TLS_PORT}`,
        deployStatus: deployManager.status(),
        storeHealth: (() => { try { return getStore().health(); } catch (e) { return { error: e.message }; } })(),
    };
}

app.get('/operations', auth, (req, res) => {
    res.render('operations', { ...operationsSnapshot(), flash: consumeFlash(req.session) });
});

app.post('/operations/update', auth, async (req, res) => {
    try {
        const result = await deployManager.runGitUpdate();
        audit(req, 'deploy.update', { ok: result.ok });
        req.session.flash = result.ok
            ? { type: 'success', msg: 'Đã cập nhật code từ Git.' + (result.changed ? ' Đang restart PM2...' : ' Không có thay đổi.') }
            : { type: 'danger', msg: 'Cập nhật thất bại. Xem chi tiết trong Operations.' };
        // Gửi response trước KHI PM2 restart — tránh ERR_EMPTY_RESPONSE
        res.redirect('/operations');
        // Restart PM2 detached sau khi response đã gửi
        if (result.ok && result.changed) {
            setTimeout(() => {
                const { spawn } = require('child_process');
                const pm2Bin = deployManager.getPm2Bin();
                spawn(pm2Bin, ['restart', 'all', '--update-env'], { detached: true, stdio: 'ignore' }).unref();
            }, 1500);
        }
    } catch (err) {
        if (!res.headersSent) {
            req.session.flash = { type: 'danger', msg: err.message || 'Không thể chạy cập nhật.' };
            res.redirect('/operations');
        }
    }
});

app.post('/operations/check-update', auth, async (req, res) => {
    try {
        const result = await deployManager.checkForUpdates();
        audit(req, 'deploy.check_update', { ok: result.ok, updateAvailable: result.updateAvailable });
        req.session.flash = result.ok
            ? { type: 'success', msg: result.updateAvailable ? 'Có bản cập nhật mới trên Git.' : 'Git đang ở bản mới nhất.' }
            : { type: 'danger', msg: 'Không kiểm tra được update. Xem chi tiết trong Operations.' };
    } catch (err) {
        req.session.flash = { type: 'danger', msg: err.message || 'Không thể kiểm tra update.' };
    }
    res.redirect('/operations');
});

app.post('/operations/restart', auth, async (req, res) => {
    try {
        const result = await deployManager.restartPm2Only();
        audit(req, 'deploy.restart', { ok: result.ok });
        req.session.flash = result.ok
            ? { type: 'success', msg: 'Đã restart PM2.' }
            : { type: 'danger', msg: 'Restart PM2 thất bại. Xem chi tiết trong Operations.' };
        // Gửi response trước khi PM2 kill process này
        res.redirect('/operations');
        if (result.ok) {
            setTimeout(() => {
                const { spawn } = require('child_process');
                const pm2Bin = deployManager.getPm2Bin();
                spawn(pm2Bin, ['restart', 'all', '--update-env'], { detached: true, stdio: 'ignore' }).unref();
            }, 1500);
        }
    } catch (err) {
        if (!res.headersSent) {
            req.session.flash = { type: 'danger', msg: err.message || 'Không thể restart PM2.' };
            res.redirect('/operations');
        }
    }
});

app.post('/operations/rollback', auth, async (req, res) => {
    try {
        const result = await deployManager.rollbackLast();
        audit(req, 'deploy.rollback', { ok: result.ok, rollbackTo: result.rollbackTo });
        req.session.flash = result.ok
            ? { type: 'success', msg: `Đã rollback về commit ${result.rollbackTo}. Đang restart PM2...` }
            : { type: 'danger', msg: 'Rollback thất bại. Xem chi tiết trong Operations.' };
        res.redirect('/operations');
        if (result.ok) {
            setTimeout(() => {
                const { spawn } = require('child_process');
                const pm2Bin = deployManager.getPm2Bin();
                spawn(pm2Bin, ['restart', 'all', '--update-env'], { detached: true, stdio: 'ignore' }).unref();
            }, 1500);
        }
    } catch (err) {
        if (!res.headersSent) {
            req.session.flash = { type: 'danger', msg: err.message || 'Không thể rollback.' };
            res.redirect('/operations');
        }
    }
});

app.get('/settings', auth, (req, res) => {
    res.render('settings', {
        settings: loadSettings(),
        dataDir: DATA_DIR,
        dataDirSource: DATA_DIR_INFO.source,
        dataDirLocalFile: path.join(__dirname, 'data_dir.local'),
        runtime: RUNTIME,
        runtimeWarnings: RUNTIME.warnings,
        flash: consumeFlash(req.session),
    });
});
app.post('/settings/telegram', auth, (req, res) => {
    const s = loadSettings();
    s.telegram_token   = (req.body.telegram_token || '').trim();
    s.telegram_chat_id = (req.body.telegram_chat_id || '').trim();
    saveSettings(s);
    req.session.flash = { type: 'success', msg: 'Đã lưu cài đặt Telegram.' };
    res.redirect('/settings');
});
app.post('/settings/test-telegram', auth, (req, res) => {
    sendTelegram('✅ <b>Test message</b>\nLicense Manager đang hoạt động bình thường.');
    req.session.flash = { type: 'success', msg: 'Đã gửi test message.' };
    res.redirect('/settings');
});
app.post('/settings/webhook', auth, (req, res) => {
    const s = loadSettings();
    const raw = (req.body.webhooks || '').trim();
    s.webhooks = raw ? raw.split('\n').map(u => u.trim()).filter(u => u.startsWith('http')) : [];
    saveSettings(s);
    req.session.flash = { type: 'success', msg: `Đã lưu ${s.webhooks.length} webhook URL.` };
    res.redirect('/settings');
});

app.post('/settings/agent', auth, (req, res) => {
    const s = loadSettings();
    s.advanced_shell_enabled = req.body.advanced_shell_enabled === '1';
    s.agent_shell_timeout = commandPolicy.clampTimeout(req.body.agent_shell_timeout || 120, 120);
    saveSettings(s);
    req.session.flash = { type: 'success', msg: 'Đã lưu cài đặt agent command.' };
    res.redirect('/settings');
});


// 2FA setup
app.get('/settings/setup-2fa', auth, async (req, res) => {
    const secret = speakeasy.generateSecret({ name: 'License Manager', length: 20 });
    req.session.totp_pending = secret.base32;
    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);
    req.session.totp_qr = qrDataUrl;
    res.render('setup-2fa', { qrDataUrl, secret: secret.base32, flash: null });
});
app.post('/settings/setup-2fa', auth, (req, res) => {
    const token  = (req.body.token || '').replace(/\s/g, '');
    const secret = req.session.totp_pending;
    if (!secret) return res.redirect('/settings');
    const valid = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });
    if (!valid) {
        return res.render('setup-2fa', { qrDataUrl: req.session.totp_qr, secret, flash: { type: 'danger', msg: 'Mã OTP không đúng. Thử lại.' } });
    }
    const s = loadSettings();
    s.totp_secret = secret; s.totp_enabled = true; saveSettings(s);
    delete req.session.totp_pending; delete req.session.totp_qr;
    req.session.flash = { type: 'success', msg: '2FA đã bật thành công!' };
    log('INFO', '2FA ENABLED'); res.redirect('/settings');
});
app.post('/settings/disable-2fa', auth, (req, res) => {
    const s = loadSettings();
    s.totp_enabled = false; s.totp_secret = null; saveSettings(s);
    req.session.flash = { type: 'success', msg: '2FA đã tắt.' };
    log('INFO', '2FA DISABLED'); res.redirect('/settings');
});

// ── Change admin password ────────────────────────────────────────────────────
app.post('/settings/change-password', auth, (req, res) => {
    const currentPassword = String(req.body.current_password || '');
    const newPassword     = String(req.body.new_password || '');
    const confirmPassword = String(req.body.confirm_password || '');

    // Verify current password
    if (!verifyPassword(currentPassword, adminCreds.pass_hash)) {
        return res.render('settings', {
            settings: loadSettings(),
            dataDir: DATA_DIR, dataDirSource: DATA_DIR_INFO.source,
            dataDirLocalFile: path.join(__dirname, 'data_dir.local'),
            runtime: RUNTIME, runtimeWarnings: RUNTIME.warnings,
            flash: { type: 'danger', msg: 'Mật khẩu hiện tại không đúng.' },
        });
    }

    // Validate new password strength
    const strength = isStrongPassword(newPassword);
    if (!strength.ok) {
        return res.render('settings', {
            settings: loadSettings(),
            dataDir: DATA_DIR, dataDirSource: DATA_DIR_INFO.source,
            dataDirLocalFile: path.join(__dirname, 'data_dir.local'),
            runtime: RUNTIME, runtimeWarnings: RUNTIME.warnings,
            flash: { type: 'danger', msg: strength.error },
        });
    }

    if (newPassword !== confirmPassword) {
        return res.render('settings', {
            settings: loadSettings(),
            dataDir: DATA_DIR, dataDirSource: DATA_DIR_INFO.source,
            dataDirLocalFile: path.join(__dirname, 'data_dir.local'),
            runtime: RUNTIME, runtimeWarnings: RUNTIME.warnings,
            flash: { type: 'danger', msg: 'Xác nhận mật khẩu mới không khớp.' },
        });
    }

    // Save new password
    adminCreds = { user: WEB_USER, pass_hash: hashPassword(newPassword) };
    getStore().saveAdminCredentials(adminCreds);

    audit(req, 'settings.change_password', {});
    log('SECURITY', `ADMIN PASSWORD CHANGED  ip=${clientIp(req)}`);
    sendTelegram(`🔐 <b>Admin password changed</b>\nIP: ${clientIp(req)}`);

    // Regenerate session to prevent session fixation
    req.session.regenerate((err) => {
        req.session.loggedIn = true;
        req.session.flash = { type: 'success', msg: 'Đã đổi mật khẩu thành công. Vui lòng đăng nhập lại.' };
        res.redirect('/login');
    });
});

// ── Bulk import CSV ───────────────────────────────────────────────────────────
app.get('/import', auth, (req, res) => res.render('import', { result: null, flash: null }));
app.post('/import', auth, upload.single('csvfile'), (req, res) => {
    if (!verifyCsrfRequest(req)) return res.status(403).type('text/plain').send('CSRF token invalid');
    if (!req.file) return res.render('import', { result: { error: 'Chưa chọn file.' }, flash: null });
    const lines = req.file.buffer.toString('utf8')
        .split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#') && !l.startsWith('machine_id'));
    const db = loadDB();
    let added = 0, skipped = 0, errors = [];
    for (const line of lines) {
        const [mid, tier = 'basic', max_players = '10', note = '', expires_at = ''] = line.split(',').map(c => c.trim().replace(/^"|"$/g, ''));
        if (!mid) { skipped++; continue; }
        if (db[mid]) { skipped++; errors.push(`${mid}: đã tồn tại`); continue; }
        const validTier = TIERS[tier] ? tier : 'basic';
        db[mid] = {
            max_players: normalizeMaxPlayers(max_players, validTier),
            tier: validTier, note: note || 'Imported',
            added: now(), revoked: false, peak_players: 0,
            expires_at: expires_at || undefined, zombie: false,
        };
        added++;
    }
    saveDB(db);
    log('INFO', `WEB IMPORT  added=${added} skipped=${skipped}`);
    res.render('import', { result: { added, skipped, errors }, flash: null });
});

// ── IP Bans ───────────────────────────────────────────────────────────────────
app.get('/bans', auth, (req, res) => {
    res.render('bans', { rows: Object.entries(loadBans()), flash: consumeFlash(req.session) });
});
app.post('/ban-add', auth, (req, res) => {
    const range = (req.body.range || '').trim(), note = (req.body.note || '').trim();
    if (!range) { req.session.flash = { type: 'danger', msg: 'IP/Range trống.' }; return res.redirect('/bans'); }
    const b = loadBans(); b[range] = { note, added: now(), disabled: false }; saveBans(b);
    req.session.flash = { type: 'success', msg: `Đã ban: ${range}` };
    log('INFO', `WEB BAN-ADD [${range}]`); res.redirect('/bans');
});
app.post('/ban-delete', auth, (req, res) => {
    const b = loadBans(); delete b[(req.body.range || '').trim()]; saveBans(b);
    req.session.flash = { type: 'success', msg: 'Đã xóa ban.' }; res.redirect('/bans');
});
app.post('/ban-toggle', auth, (req, res) => {
    const range = (req.body.range || '').trim(), b = loadBans();
    if (b[range]) b[range].disabled = !b[range].disabled; saveBans(b); res.redirect('/bans');
});

// ── History ───────────────────────────────────────────────────────────────────
app.get('/history', auth, (req, res) => {
    const mid = req.query.mid || null;
    let h = loadHistory().reverse();
    if (mid) h = h.filter(e => e.mid === mid);
    res.render('history', { events: h.slice(0, 200), filter_mid: mid, flash: null });
});

// ── Logs ──────────────────────────────────────────────────────────────────────
app.get('/logs', auth, (req, res) => {
    let lines = [];
    if (fs.existsSync(LOG_FILE)) lines = fs.readFileSync(LOG_FILE, 'utf8').split('\n').filter(Boolean).slice(-80);
    res.render('logs', { lines });
});

// ── Portal (self-service khách hàng) ─────────────────────────────────────────
app.get('/portal', (req, res) => res.render('portal', { result: null, error: null }));
app.post('/portal', (req, res) => {
    const ip = clientIp(req);
    const genericPortalError = 'Thông tin tra cứu không hợp lệ.';
    if (portalRlCheck(ip).blocked) {
        return res.render('portal', { result: null, error: 'Thử quá nhiều lần. Vui lòng quay lại sau.' });
    }
    const mid = (req.body.mid || '').trim();
    const key = (req.body.key || '').trim();
    const db  = loadDB();
    const entry = db[mid];
    if (!entry) {
        portalRlFail(ip);
        return res.render('portal', { result: null, error: genericPortalError });
    }
    if (!entry.license_key) {
        portalRlFail(ip);
        return res.render('portal', { result: null, error: genericPortalError });
    }
    if (!canViewPortalLicense(entry, key)) {
        portalRlFail(ip);
        return res.render('portal', { result: null, error: genericPortalError });
    }
    portalRlClear(ip);
    const info = {
        mid, tier: entry.tier || 'basic', max_players: getMaxPlayers(entry),
        revoked: entry.revoked, expired: isExpired(entry),
        expiry: expiryInfo(entry), note: entry.note, added: entry.added,
        isOnline: !!active[mid], players: active[mid]?.players || 0,
        peak_players: entry.peak_players || 0, geo: active[mid]?.geo || null,
        TIERS,
    };
    res.render('portal', { result: info, error: null });
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
    const dbHealth = getStore().health();
    const database = {
        driver: dbHealth.driver,
        ok: dbHealth.ok,
        journal_mode: dbHealth.journal_mode,
        quick_check: dbHealth.quick_check,
        db_size_bytes: dbHealth.db_size_bytes,
        wal_size_bytes: dbHealth.wal_size_bytes,
        last_backup_at: dbHealth.last_backup_at,
    };
    const healthy = startupState.ready && tlsServer.listening && database.ok;
    res.status(healthy ? 200 : 503).json({
        status: healthy ? 'ok' : 'degraded',
        uptime: Math.floor(process.uptime()),
        runtime: {
            node_env: RUNTIME.nodeEnv,
            web_port: WEB_PORT,
            pm2: RUNTIME.pm2,
        },
        transport: {
            tls_only: true,
            tls_enabled: true,
            tls_port: TLS_PORT,
            tls_listening: tlsServer.listening,
            tls_connections: _tlsConnections.size,
            tls_min_version: TLS_MIN_VERSION,
            certificate_valid_to: _tlsCertificateInfo.valid_to,
        },
        database,
        auth2_sessions_active: sessions.size,
        maintenance: isMaintenanceActive(),
        ts: Date.now(),
    });
});

// ── Export CSV ────────────────────────────────────────────────────────────────
app.get('/export/csv', auth, (req, res) => {
    const db   = loadDB();
    const head = 'machine_id,tier,max_players,peak_players,note,added,expires_at,revoked,expired,license_key\n';
    const rows = Object.entries(db).map(([mid, e]) =>
        [mid, e.tier || 'basic', getMaxPlayers(e), e.peak_players || 0,
         e.note || '', e.added || '', e.expires_at || '',
         e.revoked ? 'yes' : 'no', isExpired(e) ? 'yes' : 'no', e.license_key || '']
        .map(v => `"${csvSafeCell(v).replace(/"/g, '""')}"`)
        .join(',')
    ).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="licenses_${new Date().toISOString().slice(0, 10)}.csv"`);
    res.send(head + rows);
});

// ── API ───────────────────────────────────────────────────────────────────────
app.get('/api/logs', auth, (req, res) => {
    let lines = [];
    if (fs.existsSync(LOG_FILE)) lines = fs.readFileSync(LOG_FILE, 'utf8').split('\n').filter(Boolean).slice(-80);
    res.json({ lines });
});
app.get('/api/active', auth, (req, res) => res.json(active));
app.get('/api/stats', auth, (req, res) => {
    const raw = loadStats();
    const mid = req.query.mid;
    if (mid) return res.json(raw[mid] || []);
    const buckets = {};
    for (const pts of Object.values(raw)) {
        for (const [ts, cnt] of pts) {
            const b = Math.floor(ts / 300000) * 300000;
            if (!buckets[b]) buckets[b] = { sum: 0, count: 0 };
            buckets[b].sum += cnt; buckets[b].count++;
        }
    }
    const sorted = Object.entries(buckets).sort((a, b) => +a[0] - +b[0]).slice(-144)
        .map(([ts, v]) => [+ts, Math.round(v.sum / v.count)]);
    res.json({ total: sorted, per_machine: raw });
});

// ── SSH / Server control ──────────────────────────────────────────────────────
// Replaced with reverse-agent (xem agent_manager.js): không cần mở port SSH,
// agent ở máy game tự kết nối ra license server để nhận lệnh.

app.get('/machine/:mid', auth, (req, res) => {
    const mid = req.params.mid;
    const db  = loadDB();
    const entry = db[mid];
    if (!entry) { req.session.flash = { type: 'danger', msg: 'Machine không tồn tại.' }; return res.redirect('/machines'); }
    const agentInfo = agent.infoFor(mid);
    const settings = loadSettings();
    res.render('machine_detail', {
        mid, entry, TIERS,
        max_players: getMaxPlayers(entry),
        isOnline: !!active[mid], live: active[mid] || null,
        agentInfo,
        safeActions: commandPolicy.getSafeActions(),
        shellEnabled: settings.advanced_shell_enabled === true,
        shellTimeout: commandPolicy.clampTimeout(settings.agent_shell_timeout || 120, 120),
        publicBase: req.protocol + '://' + req.get('host'),
        expiry: expiryInfo(entry), expired: isExpired(entry),
        flash: consumeFlash(req.session),
    });
});

// Tạo / lấy install token + script cài đặt
app.post('/machine/:mid/agent-install', auth, (req, res) => {
    const mid = req.params.mid;
    const db  = loadDB();
    if (!db[mid]) { req.session.flash = { type: 'danger', msg: 'Machine chưa được cấp license.' }; return res.redirect('/machines'); }
    const tok = agent.getOrCreateToken(mid);
    if (req.body.server_dir) agent.setServerDir(mid, req.body.server_dir);
    const base = (loadSettings().public_url || (req.protocol + '://' + req.get('host'))).replace(/\/+$/, '');
    const oneLiner = `curl -fsSL "${base}/agent/install.sh?mid=${encodeURIComponent(mid)}&token=${tok}" | sudo bash`;
    req.session.flash = {
        type: 'success',
        msg: `Lệnh cài đặt agent (chạy trên máy game, một dòng):\n\n${oneLiner}`,
    };
    log('INFO', `AGENT INSTALL [${mid}] token issued`);
    res.redirect(`/machine/${encodeURIComponent(mid)}`);
});

app.post('/machine/:mid/agent-rotate', auth, (req, res) => {
    const mid = req.params.mid;
    agent.regenerateToken(mid);
    req.session.flash = { type: 'success', msg: `Đã cấp token mới — cần chạy lại lệnh cài đặt trên máy đích.` };
    log('INFO', `AGENT ROTATE [${mid}]`);
    res.redirect(`/machine/${encodeURIComponent(mid)}`);
});

app.post('/machine/:mid/agent-uninstall', auth, (req, res) => {
    const mid = req.params.mid;
    agent.uninstall(mid);
    req.session.flash = { type: 'success', msg: `Đã gỡ agent của ${mid} khỏi license server. Trên máy đích chạy: curl ... /agent/uninstall.sh | sudo bash` };
    log('INFO', `AGENT UNINSTALL [${mid}]`);
    res.redirect(`/machine/${encodeURIComponent(mid)}`);
});

app.post('/machine/:mid/agent-server-dir', auth, (req, res) => {
    const mid = req.params.mid;
    agent.setServerDir(mid, req.body.server_dir || 'pwserver');
    req.session.flash = { type: 'success', msg: `Đã cập nhật ServerDir cho ${mid}.` };
    res.redirect(`/machine/${encodeURIComponent(mid)}`);
});

// ── Agent runtime endpoints (no auth — token-protected) ─────────────────────
function checkAgentAuth(req) {
    const auth_h = req.headers['authorization'] || '';
    const m = auth_h.match(/^Bearer\s+(.+)$/i);
    if (!m) return null;
    const mid = (req.headers['x-mid'] || '').toString();
    if (!mid || !agent.verifyToken(mid, m[1].trim())) return null;
    return mid;
}

// Installer one-liner: returns the install bash script
app.get('/agent/install.sh', (req, res) => {
    const mid   = (req.query.mid   || '').toString();
    const token = (req.query.token || '').toString();
    if (!mid || !token || !agent.verifyToken(mid, token)) {
        return res.status(403).type('text/plain').send('# invalid mid/token\nexit 1\n');
    }
    const base = (loadSettings().public_url || (req.protocol + '://' + req.get('host'))).replace(/\/+$/, '');
    res.type('text/plain').send(
        require('./agent_manager').buildInstallScript({ serverUrl: base, mid, token })
    );
});

// Uninstaller helper
app.get('/agent/uninstall.sh', (req, res) => {
    if (!isAgentScriptAuthorized(req.query, agent.verifyToken)) {
        return res.status(403).type('text/plain').send('# invalid mid/token\nexit 1\n');
    }
    res.type('text/plain').send(agent.buildUninstallScript());
});

// Static runtime fetched by installer
app.get('/agent/runtime.sh', (req, res) => {
    if (!isAgentScriptAuthorized(req.query, agent.verifyToken)) {
        return res.status(403).type('text/plain').send('# invalid mid/token\nexit 1\n');
    }
    res.type('text/plain').send(agent.AGENT_RUNTIME);
});

// Long-poll: returns a single command (200 + X-Cmd-Id + script body) or 204
app.get('/agent/poll', async (req, res) => {
    const mid = checkAgentAuth(req);
    if (!mid) return res.status(401).end();
    const ip  = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?').split(',')[0].trim();
    const ver = (req.headers['x-agent-ver'] || '').toString();
    agent.recordHeartbeat(mid, ip, ver);
    const cmd = await agent.pollOne(mid, ip);
    if (!cmd) return res.status(204).end();
    res.set('X-Cmd-Id', cmd.id);
    res.set('X-Cmd-Kind', cmd.kind || 'shell');
    res.set('X-Cmd-Timeout-Seconds', String(commandPolicy.clampTimeout(cmd.payload?.timeoutSec, 300)));
    res.type('text/plain').send(cmd.payload?.script || '');
});

// Monitor blob from agent
app.post('/agent/monitor',
    express.text({ type: '*/*', limit: '256kb' }),
    (req, res) => {
        const mid = checkAgentAuth(req);
        if (!mid) return res.status(401).end();
        const ip  = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?').split(',')[0].trim();
        agent.recordHeartbeat(mid, ip, req.headers['x-agent-ver']);
        try {
            const parsed = agent.parseMonitorRaw(req.body || '');
            agent.setMonitor(mid, parsed);
            res.json({ ok: true });
        } catch {
            res.status(400).json({ ok: false });
        }
    }
);

// Result of executed command (multipart form: id, code, stdout, stderr)
app.post('/agent/result',
    upload.fields([{ name: 'stdout', maxCount: 1 }, { name: 'stderr', maxCount: 1 }]),
    (req, res) => {
        const mid = checkAgentAuth(req);
        if (!mid) return res.status(401).end();
        const id   = (req.body.id   || '').toString();
        const code = parseInt(req.body.code, 10);
        const stdout = req.files?.stdout?.[0]?.buffer?.toString('utf8') || '';
        const stderr = req.files?.stderr?.[0]?.buffer?.toString('utf8') || '';
        if (!id) return res.status(400).end();
        agent.recordResult(mid, id, isNaN(code) ? null : code, stdout, stderr);
        res.json({ ok: true });
    }
);

// ── Web → Agent: monitor snapshot ────────────────────────────────────────────
app.get('/api/machine/:mid/monitor', auth, (req, res) => {
    const mid = req.params.mid;
    if (!agent.infoFor(mid)) return res.status(404).json({ error: 'no_agent' });
    const snap = agent.getMonitor(mid);
    if (!snap) return res.status(204).end();
    res.json(snap);
});

// ── Web → Agent: control (start/stop/restart) ───────────────────────────────
async function runControl(req, res, action) {
    const mid = req.params.mid;
    const info = agent.infoFor(mid);
    if (!info) {
        req.session.flash = { type: 'danger', msg: `Chưa cài agent cho ${mid}` };
        return res.redirect(`/machine/${encodeURIComponent(mid)}`);
    }
    if (!info.online) {
        req.session.flash = { type: 'danger', msg: `Agent của ${mid} đang offline (last seen: ${info.last_seen ? new Date(info.last_seen).toLocaleString() : 'chưa từng kết nối'}).` };
        return res.redirect(`/machine/${encodeURIComponent(mid)}`);
    }
    const dir = agent.getServerDir(mid);
    const script = action === 'start'   ? agent.buildStartScript(dir)
                 : action === 'stop'    ? agent.buildStopScript(dir)
                 : agent.buildStopScript(dir) + '\nsleep 5\n' + agent.buildStartScript(dir);
    const controlTimeout = action === 'stop' ? 90 : action === 'restart' ? 240 : 180;
    const cmdId = enqueueAgentCommand(mid, action, { script, timeoutSec: controlTimeout });
    log('INFO', `SERVER ${action.toUpperCase()}  [${mid}]  cmd=${cmdId}`);

    // Wait for result up to 60s, otherwise show "đang chạy nền"
    const deadline = Date.now() + 60000;
    let r = null;
    while (Date.now() < deadline) {
        r = agent.takeResult(mid, cmdId);
        if (r) break;
        await new Promise(rs => setTimeout(rs, 800));
    }
    if (r) {
        pushHistory({ mid, event: `srv_${action}`, ip: info.agent_ip || '?', reason: `exit=${r.code}` });
        sendTelegram(`🔧 <b>Server ${action}</b>\n<code>${mid}</code>\nExit: ${r.code}`);
        req.session.flash = { type: r.code === 0 ? 'success' : 'danger',
                              msg: `${action} → exit=${r.code}\n` + (r.stdout || r.stderr || '').slice(-400) };
    } else {
        req.session.flash = { type: 'success',
                              msg: `${action} đã được gửi tới agent. Lệnh đang chạy nền — kiểm tra lại sau.` };
    }
    res.redirect(`/machine/${encodeURIComponent(mid)}`);
}
app.post('/machine/:mid/start',   auth, (req, res) => runControl(req, res, 'start'));
app.post('/machine/:mid/stop',    auth, (req, res) => runControl(req, res, 'stop'));
app.post('/machine/:mid/restart', auth, (req, res) => runControl(req, res, 'restart'));

app.post('/api/machine/:mid/safe-action', auth, async (req, res) => {
    const mid = req.params.mid;
    const info = agent.infoFor(mid);
    if (!info)         return res.status(404).json({ error: 'no_agent' });
    if (!info.online)  return res.status(503).json({ error: 'agent_offline' });

    const action = commandPolicy.buildSafeActionScript(req.body?.action, {
        serverDir: agent.getServerDir(mid),
        lines: req.body?.lines,
    });
    if (!action) return res.status(400).json({ error: 'unknown_action' });

    const id = enqueueAgentCommand(mid, 'safe_action', {
        script: action.script,
        timeoutSec: action.timeoutSec,
        action: action.id,
        label: action.label,
    });
    audit(req, 'agent.safe_action', { mid, action: action.id, timeoutSec: action.timeoutSec });
    log('INFO', `SAFE ACTION [${mid}] action=${action.id} cmd=${id} timeout=${action.timeoutSec}s`);
    res.json({ id, label: action.label });
});

// ── Web → Agent: ad-hoc command (web "terminal" mỗi dòng = một lệnh) ────────
app.post('/api/machine/:mid/exec', auth, async (req, res) => {
    const mid = req.params.mid;
    const info = agent.infoFor(mid);
    if (!info)         return res.status(404).json({ error: 'no_agent' });
    if (!info.online)  return res.status(503).json({ error: 'agent_offline' });
    if (!shellEnabled()) return res.status(403).json({ error: 'advanced_shell_disabled' });
    const script = (req.body && req.body.script) ? String(req.body.script) : '';
    const checked = commandPolicy.validateShellScript(script, { timeoutSec: req.body?.timeoutSec || defaultShellTimeout() });
    if (!checked.ok) return res.status(400).json({ error: checked.error });
    const sha256 = crypto.createHash('sha256').update(checked.script).digest('hex');
    const id = enqueueAgentCommand(mid, 'shell', { script: checked.script, timeoutSec: checked.timeoutSec, sha256 });
    audit(req, 'agent.shell', {
        mid,
        timeoutSec: checked.timeoutSec,
        bytes: Buffer.byteLength(checked.script, 'utf8'),
        sha256,
    });
    log('WARNING', `ADV SHELL [${mid}] cmd=${id} timeout=${checked.timeoutSec}s sha256=${sha256.slice(0, 12)}`);
    res.json({ id, timeoutSec: checked.timeoutSec });
});
app.get('/api/machine/:mid/exec/:id', auth, (req, res) => {
    const r = agent.takeResult(req.params.mid, req.params.id);
    if (!r) return res.status(204).end();
    res.json(r);
});

// ── Start ─────────────────────────────────────────────────────────────────────
const startupState = { http: false, tls: false, ready: false };
let shuttingDown = false;

function failStartup(component, err) {
    if (startupState.ready || shuttingDown) return;
    log('ERROR', `${component} startup failed: ${err.message}`);
    process.exitCode = 1;
    setImmediate(() => process.exit(1));
}

function maybeSignalReady() {
    if (startupState.ready || !startupState.http || !startupState.tls) return;
    const dbHealth = getStore().health();
    if (!dbHealth.ok) return failStartup('SQLite', new Error(`quick_check=${dbHealth.quick_check}, journal=${dbHealth.journal_mode}`));
    startupState.ready = true;
    log('INFO', `READY TLS=${BIND_HOST}:${TLS_PORT} SQLite=${dbHealth.db_path}`);
    if (typeof process.send === 'function') process.send('ready');
    doBackup().catch(() => {});
}

function initializeRuntime() {
    for (const warning of RUNTIME.warnings) log('WARNING', warning);
    restorePersistedSessions();
    repairDBMaxPlayers();

    const auditMigrate = migrateAuditChainIfNeeded(AUDIT_FILE);
    if (auditMigrate.migrated) {
        log('INFO', `Audit log migrated: ${auditMigrate.entries} entries — added HMAC chain hashes`);
    }
    const auditVerify = verifyAuditChain(AUDIT_FILE);
    if (!auditVerify.ok) {
        log('SECURITY', `AUDIT CHAIN TAMPERED! ${auditVerify.error} (${auditVerify.entries} entries)`);
        sendTelegram(`🚨 <b>SECURITY ALERT: Audit Log Tampered!</b>\n${auditVerify.error}\n${auditVerify.entries} entries`);
    } else {
        log('INFO', `Audit chain verified: ${auditVerify.entries} entries OK`);
    }
}

initializeRuntime();

httpServer.once('error', err => failStartup('HTTP', err));
tlsServer.once('error', err => failStartup('TLS', err));

httpServer.listen(WEB_PORT, BIND_HOST, () => {
    startupState.http = true;
    log('INFO', `Web UI: http://${BIND_HOST}:${WEB_PORT}`);
    maybeSignalReady();
});

tlsServer.listen(TLS_PORT, BIND_HOST, () => {
    startupState.tls = true;
    log('INFO', `TLS license listener: ${BIND_HOST}:${TLS_PORT} min=${TLS_MIN_VERSION} AES-256-GCM payload valid_to=${_tlsCertificateInfo.valid_to} sha256=${_tlsCertificateInfo.fingerprint256 || 'n/a'}`);
    if (!_tlsCertificateInfo.subject_alt_name) {
        log('WARNING', 'TLS certificate has no Subject Alternative Name (SAN). The patched client supports a pinned/self-signed CN fallback, but a SAN certificate is recommended.');
    }
    maybeSignalReady();
});

async function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    incMetric('license_graceful_shutdown_total');
    log('INFO', `${signal} received, shutting down gracefully...`);
    const forceExit = setTimeout(() => process.exit(1), 12000);
    forceExit.unref();

    const closeServer = server => new Promise(resolve => {
        if (!server.listening) return resolve();
        server.close(() => resolve());
    });

    const tlsClosed = closeServer(tlsServer);
    const httpClosed = closeServer(httpServer);
    for (const socket of _tlsConnections) socket.destroy();
    _tlsConnections.clear();
    if (typeof httpServer.closeAllConnections === 'function') httpServer.closeAllConnections();
    await Promise.all([tlsClosed, httpClosed]);
    try { webSessionStore.close(); } catch {}
    try { if (_backupInFlight) await _backupInFlight; } catch {}
    try { getStore().close(); } catch (err) { log('ERROR', `SQLite close failed: ${err.message}`); }
    clearTimeout(forceExit);
    log('INFO', 'Shutdown complete');
    process.exit(0);
}

process.on('SIGINT', () => { shutdown('SIGINT').catch(() => process.exit(1)); });
process.on('SIGTERM', () => { shutdown('SIGTERM').catch(() => process.exit(1)); });
