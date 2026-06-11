'use strict';
const net       = require('net');
const http      = require('http');
const https     = require('https');
const crypto    = require('crypto');
const fs        = require('fs');
const path      = require('path');
const express   = require('express');
const session   = require('express-session');
const WebSocket = require('ws');
const multer    = require('multer');
const speakeasy = require('speakeasy');
const QRCode    = require('qrcode');
const cron      = require('node-cron');
const { resolveDataDirInfo } = require('./data_dir');
const {
    ensureCsrfToken,
    verifyCsrfRequest,
    strictLicenseKeyEnabled,
    canAuthWithoutLicenseKey,
    consumeFlash,
    auditEvent,
    securityHeaders,
    isAgentScriptAuthorized,
} = require('./security');
const agent     = require('./agent_manager');
const risk      = require('./risk_manager');
const commandPolicy = require('./command_policy');

// ── Cấu hình ──────────────────────────────────────────────────────────────────
const SECRET_KEY      = Buffer.from('KhongCogiSecret2024!@#$%^&*()_+=');
const TCP_PORT        = 27015;
const WEB_PORT        = 5000;
const DATA_DIR_INFO   = resolveDataDirInfo({ appDir: __dirname });
const DATA_DIR        = DATA_DIR_INFO.dir;
const DB_FILE         = path.join(DATA_DIR, 'whitelist.json');
const BAN_FILE        = path.join(DATA_DIR, 'bans.json');
const LOG_FILE        = path.join(DATA_DIR, 'license.log');
const AUDIT_FILE      = path.join(DATA_DIR, 'audit.log');
const STATS_FILE      = path.join(DATA_DIR, 'stats.json');
const HISTORY_FILE    = path.join(DATA_DIR, 'history.json');
const PLANS_FILE      = path.join(DATA_DIR, 'plans.json');
const SETTINGS_FILE   = path.join(DATA_DIR, 'settings.json');
const ADMIN_FILE      = path.join(DATA_DIR, 'admin.json');
const RISK_FILE       = path.join(DATA_DIR, 'risk_events.json');
const BACKUP_DIR      = path.join(DATA_DIR, 'backups');

const AUTO_REGISTER   = true;
const STRICT_LICENSE_KEY = strictLicenseKeyEnabled();
const DEFAULT_PLAYERS = 5;
const MAX_STATS_PER_MACHINE = 720;   // ~16h at 80s heartbeat
const MAX_HISTORY     = 1000;
const ZOMBIE_DAYS     = 30;          // Mark zombie nếu offline > N ngày

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
const seenNonces = new Map();              // iv_hex → expireAt (chống replay đúng nghĩa)

function tcpEncrypt(plain) {
    const iv  = crypto.randomBytes(12);
    const c   = crypto.createCipheriv(CIPHER, SECRET_KEY, iv);
    const stamped = `${Date.now()}|${plain}`;
    const enc = Buffer.concat([c.update(Buffer.from(stamped, 'utf8')), c.final()]);
    const tag = c.getAuthTag();
    return iv.toString('hex') + ':' + tag.toString('hex') + ':' + enc.toString('hex') + '\n';
}

function tcpDecrypt(line) {
    try {
        const t = line.trim();
        const parts = t.split(':');
        if (parts.length !== 3) return null;
        const ivHex  = parts[0], tagHex = parts[1], encHex = parts[2];
        if (ivHex.length !== 24 || tagHex.length !== 32 || !encHex.length) return null;

        const iv  = Buffer.from(ivHex,  'hex');
        const tag = Buffer.from(tagHex, 'hex');
        const enc = Buffer.from(encHex, 'hex');
        if (iv.length !== 12 || tag.length !== 16) return null;

        const d = crypto.createDecipheriv(CIPHER, SECRET_KEY, iv);
        d.setAuthTag(tag);
        const out = Buffer.concat([d.update(enc), d.final()]).toString('utf8');

        // Tách timestamp
        const sep = out.indexOf('|');
        if (sep < 0) return null;
        const ts = parseInt(out.slice(0, sep), 10);
        if (!ts || Math.abs(Date.now() - ts) > REPLAY_WINDOW_MS) return null;

        // Chống replay nonce: từ chối nếu IV đã từng dùng
        const now = Date.now();
        for (const [k, exp] of seenNonces) if (exp < now) seenNonces.delete(k);
        if (seenNonces.has(ivHex)) return null;
        seenNonces.set(ivHex, now + REPLAY_WINDOW_MS);

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

// ── TCP Rate limiting per IP ──────────────────────────────────────────────────
const tcpAttempts = {};
const TCP_MAX = 15, TCP_LOCK_MS = 5 * 60 * 1000;
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
    if (!fs.existsSync(BAN_FILE)) return {};
    try { return JSON.parse(fs.readFileSync(BAN_FILE, 'utf8')); } catch { return {}; }
}
function saveJsonPrivate(file, data, pretty = true) {
    const payload = pretty ? JSON.stringify(data, null, 2) : JSON.stringify(data);
    fs.writeFileSync(file, payload, { mode: 0o600 });
}
function saveBans(b) { saveJsonPrivate(BAN_FILE, b); }
function ipToInt(ip) { return ip.split('.').reduce((a, o) => ((a << 8) + parseInt(o, 10)) >>> 0, 0); }
function isIpBanned(ip, bans) {
    for (const [range, info] of Object.entries(bans)) {
        if (info.disabled) continue;
        if (range.includes('/')) {
            const [base, bits] = range.split('/');
            const mask = bits === '0' ? 0 : (~0 << (32 - +bits)) >>> 0;
            if ((ipToInt(base) & mask) === (ipToInt(ip) & mask)) return true;
        } else if (range.endsWith('.*')) {
            if (ip.startsWith(range.slice(0, -1))) return true;
        } else if (ip === range) return true;
    }
    return false;
}

// ── Expiry helpers ────────────────────────────────────────────────────────────
function getExpiryDate(entry) {
    let d = null;
    if (entry.tier === 'trial' && entry.trial_days && entry.added) {
        const base = new Date(entry.added.replace(' ', 'T'));
        d = new Date(base.getTime() + entry.trial_days * 86400000);
    }
    if (entry.expires_at) {
        const ed = new Date(entry.expires_at + 'T23:59:59');
        if (!d || ed < d) d = ed;
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

// ── Init dirs ─────────────────────────────────────────────────────────────────
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(BACKUP_DIR, { recursive: true });

// ── Logging ───────────────────────────────────────────────────────────────────
function loadAdminCredentials() {
    const envUser = (process.env.LICENSE_WEB_USER || '').trim();
    const envPass = (process.env.LICENSE_WEB_PASS || '').trim();
    if (envUser || envPass) {
        if (!envUser || !envPass) {
            throw new Error('LICENSE_WEB_USER and LICENSE_WEB_PASS must both be set when using env credentials.');
        }
        return { user: envUser, pass: envPass };
    }
    if (fs.existsSync(ADMIN_FILE)) {
        try {
            const raw = JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf8'));
            if (raw?.user && raw?.pass) return { user: String(raw.user), pass: String(raw.pass) };
        } catch {}
    }
    const generated = { user: 'admin', pass: crypto.randomBytes(18).toString('base64url') };
    fs.writeFileSync(ADMIN_FILE, JSON.stringify(generated, null, 2), { mode: 0o600 });
    console.warn(`[WARN] Generated initial admin credentials in ${ADMIN_FILE}. User: ${generated.user} Password: ${generated.pass}`);
    return generated;
}

const adminCreds = loadAdminCredentials();
const WEB_USER = adminCreds.user;
const WEB_PASS = adminCreds.pass;

function log(level, msg) {
    const line = `${new Date().toISOString().replace('T', ' ').slice(0, 19)}  ${level.padEnd(7)}  ${msg}`;
    console.log(line);
    fs.appendFileSync(LOG_FILE, line + '\n');
}

function audit(req, action, details = {}) {
    try {
        auditEvent(AUDIT_FILE, { action, user: WEB_USER, ip: clientIp(req), details });
    } catch (e) {
        log('WARNING', `AUDIT FAIL action=${action} err=${e.message}`);
    }
}

// ── Database ──────────────────────────────────────────────────────────────────
function loadDB() {
    if (!fs.existsSync(DB_FILE)) return {};
    try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { return {}; }
}
function saveDB(db) { saveJsonPrivate(DB_FILE, db); }
function now() { return new Date().toLocaleString('sv').replace('T', ' '); }

// ── Settings ──────────────────────────────────────────────────────────────────
function loadSettings() {
    if (!fs.existsSync(SETTINGS_FILE)) return {};
    try { return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')); } catch { return {}; }
}
function saveSettings(s) { saveJsonPrivate(SETTINGS_FILE, s); }

// ── Plans ─────────────────────────────────────────────────────────────────────
function loadPlans() {
    if (!fs.existsSync(PLANS_FILE)) return [];
    try { return JSON.parse(fs.readFileSync(PLANS_FILE, 'utf8')); } catch { return []; }
}
function savePlans(p) { saveJsonPrivate(PLANS_FILE, p); }

// ── Stats (time-series) ───────────────────────────────────────────────────────
function loadStats() {
    if (!fs.existsSync(STATS_FILE)) return {};
    try { return JSON.parse(fs.readFileSync(STATS_FILE, 'utf8')); } catch { return {}; }
}
function pushStat(mid, players) {
    const s = loadStats();
    if (!s[mid]) s[mid] = [];
    s[mid].push([Date.now(), players]);
    if (s[mid].length > MAX_STATS_PER_MACHINE) s[mid] = s[mid].slice(-MAX_STATS_PER_MACHINE);
    saveJsonPrivate(STATS_FILE, s, false);
}

// ── History ───────────────────────────────────────────────────────────────────
function loadHistory() {
    if (!fs.existsSync(HISTORY_FILE)) return [];
    try { return JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8')); } catch { return []; }
}
function pushHistory(entry) {
    const h = loadHistory();
    h.push({ ...entry, ts: now(), ts_ms: Date.now() });
    if (h.length > MAX_HISTORY) h.splice(0, h.length - MAX_HISTORY);
    saveJsonPrivate(HISTORY_FILE, h, false);
}

// ── License key generation ────────────────────────────────────────────────────
function generateLicenseKey() {
    return crypto.randomBytes(16).toString('hex').toUpperCase();
}

// ── GeoIP (ip-api.com free, no package needed) ────────────────────────────────
const geoCache = {};
function getGeoIP(ip) {
    if (!ip || ip === '?' || ip === '127.0.0.1' || ip.startsWith('10.') || ip.startsWith('192.168.'))
        return Promise.resolve(null);
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

function recordRisk(mid, type, details = {}) {
    const result = risk.recordEvent(RISK_FILE, mid, type, details);
    if (!result.event) return result.summary;

    log('WARNING', `RISK ${result.summary.level.toUpperCase().padEnd(10)} [${mid}] type=${type} score=${result.summary.score}`);
    if (result.crossed) {
        sendTelegram(`<b>License Risk</b>\n<code>${mid}</code>\nLevel: ${result.summary.level}\nScore: ${result.summary.score}\nType: ${type}`);
        dispatchWebhook('license.risk', { mid, type, details, summary: result.summary });
    }
    return result.summary;
}

function shellEnabled() {
    return loadSettings().advanced_shell_enabled !== false;
}

function defaultShellTimeout() {
    return commandPolicy.clampTimeout(loadSettings().agent_shell_timeout || 120, 120);
}

function enqueueAgentCommand(mid, kind, payload) {
    const timeoutSec = commandPolicy.clampTimeout(payload?.timeoutSec, 300);
    const script = commandPolicy.wrapWithTimeout(payload?.script || '', timeoutSec);
    return agent.enqueueCommand(mid, kind, { ...payload, script, timeoutSec });
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

// ── Backup ────────────────────────────────────────────────────────────────────
let _lastBackupDate = '';
function doBackup() {
    const today = new Date().toISOString().slice(0, 10);
    if (_lastBackupDate === today) return;
    _lastBackupDate = today;
    if (!fs.existsSync(DB_FILE)) return;
    const dest = path.join(BACKUP_DIR, `whitelist_${today}.json`);
    fs.copyFileSync(DB_FILE, dest);
    // Keep last 30 backups
    const list = fs.readdirSync(BACKUP_DIR)
        .filter(f => f.startsWith('whitelist_') && f.endsWith('.json'))
        .sort();
    while (list.length > 30) fs.unlinkSync(path.join(BACKUP_DIR, list.shift()));
    log('INFO', `Backup → ${dest}`);
}

// ── Active servers map ────────────────────────────────────────────────────────
const active = {};

// ── HMAC token ────────────────────────────────────────────────────────────────
function makeToken(mid, maxPl) {
    return crypto.createHmac('sha256', SECRET_KEY).update(`${mid}|${maxPl}`).digest('hex');
}

// ── WebSocket broadcast ───────────────────────────────────────────────────────
let wss = null;
function wsBroadcast(event, data) {
    if (!wss) return;
    const msg = JSON.stringify({ event, data, ts: Date.now() });
    wss.clients.forEach(ws => {
        if (ws.readyState === WebSocket.OPEN) try { ws.send(msg); } catch {}
    });
}

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
            wsBroadcast('machine.offline', { mid });
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

// ── Cron: daily backup 3:00 AM ────────────────────────────────────────────────
cron.schedule('0 3 * * *', doBackup);

// ── Cron: expiry warning 9:00 AM daily ───────────────────────────────────────
cron.schedule('0 9 * * *', () => {
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
cron.schedule('0 8 * * 1', () => {
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
});

// ── TCP License Server ────────────────────────────────────────────────────────
const tcpServer = net.createServer((socket) => {
    const ip = (socket.remoteAddress || '').replace('::ffff:', '') || '?';
    socket.setTimeout(15000);
    let buf = '';

    socket.on('data', (chunk) => {
        buf += chunk.toString();
        const nl = buf.indexOf('\n');
        if (nl === -1 && buf.length < 1024) return;
        const raw = buf.slice(0, nl === -1 ? buf.length : nl + 1);
        buf = '';

        // TCP rate limit
        if (tcpRlBlocked(ip)) {
            socket.write(tcpEncrypt('DENY')); socket.end(); return;
        }

        const plain = tcpDecrypt(raw);
        if (!plain) {
            log('WARNING', `TCP DECRYPT FAIL  ${ip}`);
            tcpRlFail(ip); socket.end(); return;
        }

        if (isIpBanned(ip, loadBans())) {
            socket.write(tcpEncrypt('DENY'));
            log('WARNING', `TCP BANNED  ${ip}`); socket.end(); return;
        }

        // Maintenance mode
        if (isMaintenanceActive()) {
            socket.write(tcpEncrypt('MAINTENANCE')); socket.end(); return;
        }

        const parts = plain.trim().split(' ');
        const cmd   = parts[0]?.toUpperCase();

        // ── AUTH ──────────────────────────────────────────────────────────────
        if (cmd === 'AUTH' && parts[1]) {
            const mid     = parts[1];
            const sentKey = parts[2] || null;
            const db      = loadDB();
            let entry     = db[mid];
            let justRegistered = false;

            if (!entry) {
                if (!AUTO_REGISTER) {
                    socket.write(tcpEncrypt('DENY'));
                    log('WARNING', `AUTH DENY   ${ip}  [${mid}]  (not registered)`);
                    tcpRlFail(ip); socket.end(); return;
                }
                const newKey = generateLicenseKey();
                entry = {
                    max_players: DEFAULT_PLAYERS, tier: 'trial', trial_days: 7,
                    note: 'Auto-registered', added: now(), revoked: false, auto: true,
                    peak_players: 0, license_key: newKey, zombie: false,
                };
                db[mid] = entry; saveDB(db);
                justRegistered = true;
                log('INFO', `AUTH AUTO   ${ip}  [${mid}]  key=${newKey}`);
                sendTelegram(`🆕 <b>Auto-registered</b>\n<code>${mid}</code>\nIP: ${ip}\nKey: <code>${newKey}</code>`);
            }

            if (entry.revoked) {
                socket.write(tcpEncrypt('DENY'));
                log('WARNING', `AUTH DENY   ${ip}  [${mid}]  (revoked)`);
                tcpRlFail(ip); socket.end(); return;
            }
            if (isExpired(entry)) {
                socket.write(tcpEncrypt('DENY'));
                log('WARNING', `AUTH DENY   ${ip}  [${mid}]  (expired)`);
                dispatchWebhook('license.expired', { mid, ip }); tcpRlFail(ip); socket.end(); return;
            }

            if (!canAuthWithoutLicenseKey(entry, { strict: STRICT_LICENSE_KEY, justRegistered })) {
                socket.write(tcpEncrypt('DENY'));
                log('WARNING', `AUTH DENY   ${ip}  [${mid}]  (missing key in strict mode)`);
                recordRisk(mid, 'missing_key', { ip });
                tcpRlFail(ip); socket.end(); return;
            }

            // License key verification — bỏ qua nếu vừa auto-register (client chưa biết key)
            // Chấp nhận previous_keys trong grace window để client có thời gian đồng bộ key mới
            if (entry.license_key && !justRegistered) {
                const prev = Array.isArray(entry.previous_keys) ? entry.previous_keys : [];
                const validKey = sentKey && (sentKey === entry.license_key
                    || prev.some(p => p && p.key === sentKey
                                       && (!p.expires_at || p.expires_at > Date.now())));
                if (!validKey) {
                    socket.write(tcpEncrypt('DENY'));
                    log('WARNING', `AUTH DENY   ${ip}  [${mid}]  (wrong key)`);
                    recordRisk(mid, 'wrong_key', { ip });
                    tcpRlFail(ip); socket.end(); return;
                }
                // Key cũ vẫn hợp lệ → gửi key mới xuống client lần này (qua AUTH OK payload bên dưới)
                if (sentKey !== entry.license_key) {
                    log('INFO', `AUTH OLD-KEY ${ip}  [${mid}]  → sẽ đồng bộ key mới`);
                }
            }

            // IP whitelist per machine
            if (Array.isArray(entry.allowed_ips) && entry.allowed_ips.length > 0) {
                const allowed = entry.allowed_ips.some(a =>
                    a === ip || (a.endsWith('.*') && ip.startsWith(a.slice(0, -1)))
                );
                if (!allowed) {
                    socket.write(tcpEncrypt('DENY'));
                    log('WARNING', `AUTH DENY   ${ip}  [${mid}]  (IP not whitelisted)`);
                    recordRisk(mid, 'ip_not_whitelisted', { ip, allowed_ips: entry.allowed_ips });
                    tcpRlFail(ip); socket.end(); return;
                }
            }

            // Multi-IP detection
            if (active[mid] && active[mid].ip !== ip) {
                log('WARNING', `AUTH MULTI-IP  [${mid}]  prev=${active[mid].ip}  new=${ip}`);
                recordRisk(mid, 'multi_ip', { prev_ip: active[mid].ip, new_ip: ip });
                sendTelegram(`⚠️ <b>Multi-IP Alert</b>\n<code>${mid}</code>\nPrev: ${active[mid].ip}\nNew: ${ip}\n— Possible license sharing —`);
                dispatchWebhook('machine.multi_ip', { mid, prev_ip: active[mid].ip, new_ip: ip });
            }

            const maxPl   = entry.tier === 'unlimited' ? 9999 : (entry.max_players || DEFAULT_PLAYERS);
            const token   = makeToken(mid, maxPl);
            // Cấp/lấy agent token để client tự cài agent điều khiển từ xa
            const agentTok = agent.getOrCreateToken(mid);
            // Format response:
            //   OK <max> <hmac>                          → auth thường, không agent
            //   OK <max> <hmac> <agent_token>            → auth thường + agent
            //   OK <max> <hmac> <new_key>                → auto-register / sync key mới
            //   OK <max> <hmac> <new_key> <agent_token>  → auto-register / sync key + agent
            // Client phân giải bằng heuristic: license_key = 32 hex, agent token = 48 hex.
            const needSyncKey = justRegistered
                || (entry.license_key && sentKey && sentKey !== entry.license_key);
            let okPayload = `OK ${maxPl} ${token}`;
            if (needSyncKey && entry.license_key) okPayload += ` ${entry.license_key}`;
            if (agentTok) okPayload += ` ${agentTok}`;
            socket.write(tcpEncrypt(okPayload));

            const wasOnline = !!active[mid];
            active[mid] = {
                ip, players: active[mid]?.players || 0,
                last_seen: now(), uptime_start: active[mid]?.uptime_start || now(),
            };
            if (!wasOnline) {
                pushHistory({ mid, event: 'online', ip });
                sendTelegram(`🟢 <b>Server Online</b>\n<code>${mid}</code>\nIP: ${ip}\nTier: ${entry.tier} | Max: ${maxPl}`);
                dispatchWebhook('machine.online', { mid, ip, tier: entry.tier, max_players: maxPl });
                wsBroadcast('machine.online', { mid, ip, tier: entry.tier, max_players: maxPl, players: 0 });
            }

            // Clear zombie flag
            if (entry.zombie) { entry.zombie = false; db[mid] = entry; saveDB(db); }
            tcpRlSuccess(ip);
            log('INFO', `AUTH OK     ${ip}  [${mid}]  tier=${entry.tier} max=${maxPl}`);

            // GeoIP async (non-blocking)
            getGeoIP(ip).then(geo => {
                if (geo && active[mid]) {
                    active[mid].geo = geo;
                    wsBroadcast('machine.geo', { mid, geo });
                }
            });

        // ── HB ────────────────────────────────────────────────────────────────
        } else if (cmd === 'HB' && parts[1] && parts[2] !== undefined) {
            const mid = parts[1];
            const cnt = parseInt(parts[2]) || 0;
            const db  = loadDB();
            const entry = db[mid];

            if (!entry || entry.revoked) {
                socket.write(tcpEncrypt('REVOKE'));
                if (active[mid]) { pushHistory({ mid, event: 'offline', ip, reason: 'revoked' }); dispatchWebhook('license.revoked', { mid, ip }); }
                delete active[mid]; wsBroadcast('machine.offline', { mid });
                log('WARNING', `HB REVOKE   ${ip}  [${mid}]  (revoked)`); socket.end(); return;
            }
            if (isExpired(entry)) {
                socket.write(tcpEncrypt('REVOKE'));
                if (active[mid]) { pushHistory({ mid, event: 'offline', ip, reason: 'expired' }); dispatchWebhook('license.expired', { mid, ip }); }
                delete active[mid]; wsBroadcast('machine.offline', { mid });
                log('WARNING', `HB REVOKE   ${ip}  [${mid}]  (expired)`); socket.end(); return;
            }

            const maxPl = entry.tier === 'unlimited' ? 9999 : (entry.max_players || DEFAULT_PLAYERS);
            // KHÔNG revoke khi vượt quota — vì client gs sẽ _exit(1) làm sập
            // toàn bộ game server, mọi người bị kick về login. Chỉ alert.
            // Hard-limit thực sự đã được áp dụng phía gs (userlogin.cpp) tự
            // chặn login mới khi online > max_pl.
            if (cnt > maxPl) {
                if (!entry._alertOver) {
                    entry._alertOver = true;
                    sendTelegram(`🚨 <b>Player Over Limit</b>\n<code>${mid}</code>\n${cnt}/${maxPl} players (over by ${cnt - maxPl})\n— Client tự chặn login mới —`);
                    dispatchWebhook('players.over', { mid, ip, players: cnt, max_players: maxPl });
                }
                log('WARNING', `HB OVER     ${ip}  [${mid}]  players=${cnt}>${maxPl}  (soft-limit, không revoke)`);
            } else if (cnt < Math.floor(maxPl * 0.9)) {
                entry._alertOver = false;
            }

            // Peak players update
            if (cnt > (entry.peak_players || 0)) { entry.peak_players = cnt; }

            // 80% player alert
            if (maxPl > 0 && cnt >= Math.floor(maxPl * 0.8) && !entry._alert80) {
                entry._alert80 = true;
                sendTelegram(`⚡ <b>Player Alert 80%</b>\n<code>${mid}</code>\n${cnt}/${maxPl} players`);
                dispatchWebhook('players.high', { mid, ip, players: cnt, max_players: maxPl });
            } else if (maxPl > 0 && cnt < Math.floor(maxPl * 0.7)) {
                entry._alert80 = false;
            }

            entry.last_hb_ts = Date.now();
            db[mid] = entry; saveDB(db);
            pushStat(mid, cnt);

            if (active[mid] && active[mid].ip && active[mid].ip !== ip) {
                recordRisk(mid, 'heartbeat_ip_change', { prev_ip: active[mid].ip, new_ip: ip });
            }

            // Trả về "OK <max>" và kèm "KEY:<key>" nếu có để client tự đồng bộ license.key
            // Client sẽ ghi đè ./license.key khi phát hiện key khác key đang dùng.
            let hbPayload = `OK ${maxPl}`;
            if (entry.license_key) hbPayload += ` KEY:${entry.license_key}`;
            socket.write(tcpEncrypt(hbPayload));
            active[mid] = { ...active[mid], ip, players: cnt, last_seen: now(), uptime_start: active[mid]?.uptime_start || now() };
            wsBroadcast('machine.hb', { mid, players: cnt, max_players: maxPl });
            log('INFO', `HB OK       ${ip}  [${mid}]  players=${cnt}/${maxPl}`);
        }
        socket.end();
    });

    socket.on('error', () => {});
    socket.on('timeout', () => socket.destroy());
});
tcpServer.listen(TCP_PORT, '0.0.0.0', () => log('INFO', `TCP :${TCP_PORT}  AES-256-CTR`));

// ── Express + HTTP server ─────────────────────────────────────────────────────
const app        = express();
const httpServer = http.createServer(app);
app.disable('x-powered-by');
app.use((req, res, next) => {
    for (const [k, v] of Object.entries(securityHeaders())) res.setHeader(k, v);
    next();
});

// WebSocket server (dashboard live updates)
wss = new WebSocket.Server({ noServer: true });
wss.on('connection', (ws) => {
    ws.on('error', () => {});
    // Send current snapshot on connect
    const db = loadDB();
    const snapshot = Object.entries(active).map(([mid, info]) => {
        const e = db[mid] || {};
        return { mid, ...info, tier: e.tier || 'basic', max_players: e.tier === 'unlimited' ? 9999 : (e.max_players || 0) };
    });
    try { ws.send(JSON.stringify({ event: 'init', data: snapshot, ts: Date.now() })); } catch {}
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
function clientIp(req) {
    return (req.socket.remoteAddress || '?').replace(/^::ffff:/, '');
}
const sessionParser = session({
    secret: process.env.LICENSE_SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false, saveUninitialized: false,
    cookie: {
        maxAge: 8 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
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

function auth(req, res, next) {
    if (req.session.pendingTwoFactor) return res.redirect('/verify-2fa');
    if (req.session.loggedIn) return next();
    res.redirect('/login');
}

// ── Login / Logout ────────────────────────────────────────────────────────────
app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', (req, res) => {
    const ip = clientIp(req);
    const rl = rl_check(ip);
    if (rl.blocked) return res.render('login', { error: `Quá nhiều lần thử. Chờ ${rl.remaining} phút.` });
    if (req.body.username === WEB_USER && req.body.password === WEB_PASS) {
        rl_clear(ip);
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
    rl_fail(ip);
    const e = loginAttempts[ip];
    const left = e ? Math.max(0, MAX_ATTEMPTS - (e.count || 0)) : MAX_ATTEMPTS;
    log('WARNING', `LOGIN FAIL  ip=${ip}  (${left} left)`);
    res.render('login', { error: `Sai tài khoản hoặc mật khẩu. Còn ${left} lần thử.` });
});
app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/login'); });

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
        const maxPl = e.tier === 'unlimited' ? 9999 : (e.max_players || 0);
        return { mid, ...info, max_players: maxPl, tier: e.tier || 'basic', pct: maxPl ? Math.round((info.players || 0) / maxPl * 100) : 0 };
    }).sort((a, b) => b.players - a.players);
    res.render('dashboard', {
        active_count:  rows.length,
        total:         Object.keys(db).length,
        revoked:       Object.values(db).filter(v => v.revoked).length,
        expired:       Object.values(db).filter(v => !v.revoked && isExpired(v)).length,
        total_players: rows.reduce((s, r) => s + (r.players || 0), 0),
        maintenance:   isMaintenanceActive(),
        rows, flash: consumeFlash(req.session), TIERS,
    });
});

// ── Machines ──────────────────────────────────────────────────────────────────
app.get('/machines', auth, (req, res) => {
    const db = loadDB();
    const rows = Object.entries(db)
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([mid, info]) => ({
            mid, ...info,
            isOnline: !!active[mid],
            expiry:   expiryInfo(info),
            expired:  isExpired(info),
            currentPlayers: active[mid]?.players || 0,
            risk:     risk.summarize(RISK_FILE, mid),
        }));
    res.render('machines', { rows, TIERS, plans: loadPlans(), flash: consumeFlash(req.session) });
});

app.post('/add', auth, (req, res) => {
    const mid        = (req.body.mid || '').trim();
    const tier       = ['trial', 'basic', 'pro', 'unlimited'].includes(req.body.tier) ? req.body.tier : 'basic';
    const maxPl      = tier === 'unlimited' ? 9999 : (parseInt(req.body.max_players) || DEFAULT_PLAYERS);
    const trial_days = parseInt(req.body.trial_days) || 7;
    const expires_at = req.body.expires_at || null;
    const note       = (req.body.note || '').trim();
    const gen_key    = req.body.gen_key === '1';
    const ips_raw    = (req.body.allowed_ips || '').trim();
    const allowed_ips = ips_raw ? ips_raw.split(/[\n,]/).map(s => s.trim()).filter(Boolean) : [];

    if (!mid) { req.session.flash = { type: 'danger', msg: 'Machine ID trống.' }; return res.redirect('/machines'); }
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
    saveDB(db);
    const keyMsg = license_key ? ` | Key: <code>${license_key}</code>` : '';
    req.session.flash = { type: 'success', msg: `Đã cấp: ${mid} (${TIERS[tier].label}, max ${maxPl})${keyMsg}` };
    log('INFO', `WEB ADD [${mid}] tier=${tier} max=${maxPl} key=${license_key || 'none'}`);
    res.redirect('/machines');
});

app.post('/update-limit', auth, (req, res) => {
    const mid   = (req.body.mid || '').trim();
    const maxPl = parseInt(req.body.max_players);
    const tier  = req.body.tier;
    const exp   = req.body.expires_at;
    const db    = loadDB();
    if (!db[mid]) { req.session.flash = { type: 'danger', msg: 'Không tìm thấy.' }; return res.redirect('/machines'); }
    if (!isNaN(maxPl) && maxPl > 0) db[mid].max_players = maxPl;
    if (tier && TIERS[tier]) db[mid].tier = tier;
    if (exp !== undefined) db[mid].expires_at = exp || undefined;
    saveDB(db);
    req.session.flash = { type: 'success', msg: `Đã cập nhật ${mid}` };
    res.redirect('/machines');
});

// Gia hạn license
app.post('/renew', auth, (req, res) => {
    const mid  = (req.body.mid || '').trim();
    const days = parseInt(req.body.days) || 30;
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
    req.session.flash = { type: 'success',
        msg: `Key mới [${mid}]: ${newKey} — key cũ còn hiệu lực 24h để client đồng bộ.` };
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

    delete db[mid];
    saveDB(db);

    // Gỡ agent (token + state + queues)
    try { agent.uninstall(mid); } catch {}

    // Gỡ khỏi active map
    if (active[mid]) {
        wsBroadcast('machine.offline', { mid });
        delete active[mid];
    }

    // Xóa time-series stats
    try {
        const stats = loadStats();
        if (stats[mid]) {
            delete stats[mid];
            saveJsonPrivate(STATS_FILE, stats, false);
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
    if (stats[oldMid]) { stats[newMid] = stats[oldMid]; delete stats[oldMid]; saveJsonPrivate(STATS_FILE, stats, false); }
    pushHistory({ mid: newMid, event: 'transfer', ip: active[newMid]?.ip || '—', reason: `from ${oldMid}` });
    req.session.flash = { type: 'success', msg: `Đã transfer ${oldMid} → ${newMid}` };
    log('INFO', `WEB TRANSFER [${oldMid}] → [${newMid}]`); res.redirect('/machines');
});

// ── Maintenance mode ──────────────────────────────────────────────────────────
app.post('/maintenance', auth, (req, res) => {
    const s = loadSettings();
    const action  = req.body.action;
    const minutes = parseInt(req.body.minutes) || 0;
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
        max_players: parseInt(req.body.max_players) || 20,
        trial_days:  parseInt(req.body.trial_days) || 0,
        expires_days:parseInt(req.body.expires_days) || 0,
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
app.get('/settings', auth, (req, res) => {
    res.render('settings', {
        settings: loadSettings(),
        dataDir: DATA_DIR,
        dataDirSource: DATA_DIR_INFO.source,
        dataDirLocalFile: path.join(__dirname, 'data_dir.local'),
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
    req.session.flash = { type: 'success', msg: 'Da luu cai dat agent command.' };
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
        const [mid, tier = 'basic', max_players = '20', note = '', expires_at = ''] = line.split(',').map(c => c.trim().replace(/^"|"$/g, ''));
        if (!mid) { skipped++; continue; }
        if (db[mid]) { skipped++; errors.push(`${mid}: đã tồn tại`); continue; }
        const validTier = TIERS[tier] ? tier : 'basic';
        db[mid] = {
            max_players: parseInt(max_players) || DEFAULT_PLAYERS,
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

// ── Plans CRUD ────────────────────────────────────────────────────────────────

// ── Portal (self-service khách hàng) ─────────────────────────────────────────
app.get('/portal', (req, res) => res.render('portal', { result: null, error: null }));
app.post('/portal', (req, res) => {
    const mid = (req.body.mid || '').trim();
    const key = (req.body.key || '').trim();
    const db  = loadDB();
    const entry = db[mid];
    if (!entry) return res.render('portal', { result: null, error: 'Machine ID không tồn tại.' });
    if (STRICT_LICENSE_KEY && !entry.license_key) {
        return res.render('portal', { result: null, error: 'Machine này chưa có license key hợp lệ.' });
    }
    if (entry.license_key && key !== entry.license_key)
        return res.render('portal', { result: null, error: 'License key không đúng.' });
    const info = {
        mid, tier: entry.tier || 'basic', max_players: entry.max_players,
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
    res.json({
        status: 'ok', uptime: Math.floor(process.uptime()),
        machines_total: Object.keys(loadDB()).length,
        machines_online: Object.keys(active).length,
        maintenance: isMaintenanceActive(), ts: Date.now(),
    });
});

// ── Export CSV ────────────────────────────────────────────────────────────────
app.get('/export/csv', auth, (req, res) => {
    const db   = loadDB();
    const head = 'machine_id,tier,max_players,peak_players,note,added,expires_at,revoked,expired,license_key\n';
    const rows = Object.entries(db).map(([mid, e]) =>
        [mid, e.tier || 'basic', e.max_players || 0, e.peak_players || 0,
         e.note || '', e.added || '', e.expires_at || '',
         e.revoked ? 'yes' : 'no', isExpired(e) ? 'yes' : 'no', e.license_key || '']
        .map(v => `"${String(v).replace(/"/g, '""')}"`)
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
        isOnline: !!active[mid], live: active[mid] || null,
        agentInfo,
        riskSummary: risk.summarize(RISK_FILE, mid),
        riskEvents: risk.listEvents(RISK_FILE, mid).slice(-15).reverse(),
        safeActions: commandPolicy.getSafeActions(),
        shellEnabled: settings.advanced_shell_enabled !== false,
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

// ── HTTP upgrade: chỉ còn dashboard /ws ─────────────────────────────────────
httpServer.on('upgrade', (req, sock, head) => {
    if ((req.url || '') === '/ws') {
        wss.handleUpgrade(req, sock, head, (ws) => wss.emit('connection', ws, req));
    } else {
        sock.destroy();
    }
});

// ── Start ─────────────────────────────────────────────────────────────────────
httpServer.listen(WEB_PORT, '0.0.0.0', () => {
    log('INFO', `Web UI: http://0.0.0.0:${WEB_PORT}`);
    doBackup(); // Backup on startup
});
