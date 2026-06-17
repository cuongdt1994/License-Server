'use strict';
const net       = require('net');
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
const { ensureRuntimeSecrets } = require('./runtime_secrets');
const { FileSessionStore } = require('./session_store');
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
    updateChecksum,
    verifyAllChecksums,
} = require('./security');
const agent     = require('./agent_manager');
const commandPolicy = require('./command_policy');
const { createDeployManager } = require('./deploy_manager');
const RUNTIME         = buildRuntimeConfig();
const TCP_PORT        = 27500;
const WEB_PORT        = RUNTIME.webPort;
const BIND_HOST       = RUNTIME.bindHost;
const DATA_DIR_INFO   = resolveDataDirInfo({ appDir: __dirname });
const DATA_DIR        = DATA_DIR_INFO.dir;
const RUNTIME_SECRETS = ensureRuntimeSecrets({ dataDir: DATA_DIR });
const SECRET_KEY      = Buffer.from(RUNTIME_SECRETS.tcpSecret);
const DB_FILE         = path.join(DATA_DIR, 'whitelist.json');
const BAN_FILE        = path.join(DATA_DIR, 'bans.json');
const LOG_FILE        = path.join(DATA_DIR, 'license.log');
const AUDIT_FILE      = path.join(DATA_DIR, 'audit.log');
const STATS_FILE      = path.join(DATA_DIR, 'stats.json');
const HISTORY_FILE    = path.join(DATA_DIR, 'history.json');
const PLANS_FILE      = path.join(DATA_DIR, 'plans.json');
const SETTINGS_FILE   = path.join(DATA_DIR, 'settings.json');
const ADMIN_FILE      = path.join(DATA_DIR, 'admin.json');
const BACKUP_DIR      = path.join(DATA_DIR, 'backups');
const SESSION_DIR     = path.join(DATA_DIR, 'sessions');
RUNTIME.secretSources = RUNTIME_SECRETS.sources;
RUNTIME.secretFile = RUNTIME_SECRETS.file;
const STRICT_LICENSE_KEY = strictLicenseKeyEnabled();
const DEFAULT_PLAYERS = 10;  
function getMaxPlayers(entry) {
    if (!entry) return DEFAULT_PLAYERS;
    if (entry.tier === 'unlimited') return 9999;
    const mp = parseInt(entry.max_players, 10);
    if (!Number.isFinite(mp) || mp <= 0) return DEFAULT_PLAYERS;
    return mp;
}
function repairDBMaxPlayers() {
    const db = loadDB();
    let changed = false;
    for (const [mid, entry] of Object.entries(db)) {
        if (entry.tier === 'unlimited') {
            if (entry.max_players !== 9999) { entry.max_players = 9999; changed = true; }
            continue;
        }
        const mp = parseInt(entry.max_players, 10);
        if (!Number.isFinite(mp) || mp <= 0) {
            entry.max_players = DEFAULT_PLAYERS;
            changed = true;
        } else if (typeof entry.max_players !== 'number') {
            entry.max_players = mp;
            changed = true;
        }
    }
    if (changed) {
        saveDB(db);
        log('INFO', `DB repaired: fixed max_players → ${DEFAULT_PLAYERS} for entries with invalid/zero values`);
    }
}
const MAX_STATS_PER_MACHINE = 720;   
const MAX_HISTORY     = 1000;
const ZOMBIE_DAYS     = 30;          
const deployManager   = createDeployManager({ cwd: __dirname, historyFile: path.join(DATA_DIR, 'deploy_history.json') });
const TIERS = {
    trial:     { label: 'Trial',     color: '#fbbf24', bg: '#451a03' },
    basic:     { label: 'Basic',     color: '#60a5fa', bg: '#1e3a5f' },
    pro:       { label: 'Pro',       color: '#a78bfa', bg: '#2e1065' },
    unlimited: { label: 'Unlimited', color: '#34d399', bg: '#064e3b' },
};
const CIPHER = 'aes-256-gcm';
const REPLAY_WINDOW_MS = 30 * 1000;        
const seenNonces = new Map();              
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
        const sep = out.indexOf('|');
        if (sep < 0) return null;
        const ts = parseInt(out.slice(0, sep), 10);
        if (!ts || Math.abs(Date.now() - ts) > REPLAY_WINDOW_MS) return null;
        const now = Date.now();
        for (const [k, exp] of seenNonces) if (exp < now) seenNonces.delete(k);
        if (seenNonces.has(ivHex)) return null;
        seenNonces.set(ivHex, now + REPLAY_WINDOW_MS);
        return out.slice(sep + 1);
    } catch { return null; }
}
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
const tcpAttempts = {};
const TCP_MAX = 8, TCP_LOCK_MS = 5 * 60 * 1000;  
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
function loadBans() {
    if (!fs.existsSync(BAN_FILE)) return {};
    try { return JSON.parse(fs.readFileSync(BAN_FILE, 'utf8')); } catch { return {}; }
}
function saveJsonPrivate(file, data, pretty = true) {
    const payload = pretty ? JSON.stringify(data, null, 2) : JSON.stringify(data);
    fs.writeFileSync(file, payload, { mode: 0o600 });
}
function saveBans(b) {
    saveJsonPrivate(BAN_FILE, b);
    updateChecksum(CHECKSUM_FILE, BAN_FILE);
}
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
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(BACKUP_DIR, { recursive: true });
function loadAdminCredentials() {
    const envUser = (process.env.LICENSE_WEB_USER || '').trim();
    const envPass = (process.env.LICENSE_WEB_PASS || '').trim();
    if (envUser || envPass) {
        if (!envUser || !envPass) {
            throw new Error('LICENSE_WEB_USER and LICENSE_WEB_PASS must both be set when using env credentials.');
        }
        return { user: envUser, pass_hash: hashPassword(envPass), source: 'env' };
    }
    if (fs.existsSync(ADMIN_FILE)) {
        try {
            const raw = JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf8'));
            const normalized = normalizeAdminCredentials(raw);
            if (normalized) {
                if (raw.pass || raw.pass_hash !== normalized.pass_hash) {
                    fs.writeFileSync(ADMIN_FILE, JSON.stringify(normalized, null, 2), { mode: 0o600 });
                }
                return normalized;
            }
        } catch {}
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
function audit(req, action, details = {}) {
    try {
        appendAuditLine(AUDIT_FILE, { action, user: WEB_USER, ip: clientIp(req), details });
    } catch (e) {
        log('WARNING', `AUDIT FAIL action=${action} err=${e.message}`);
    }
}
function loadDB() {
    if (!fs.existsSync(DB_FILE)) return {};
    try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { return {}; }
}
function saveDB(db) {
    saveJsonPrivate(DB_FILE, db);
    updateChecksum(CHECKSUM_FILE, DB_FILE);
}
function now() { return new Date().toLocaleString('sv').replace('T', ' '); }
function loadSettings() {
    if (!fs.existsSync(SETTINGS_FILE)) return {};
    try { return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')); } catch { return {}; }
}
function saveSettings(s) {
    saveJsonPrivate(SETTINGS_FILE, s);
    updateChecksum(CHECKSUM_FILE, SETTINGS_FILE);
}
function loadPlans() {
    if (!fs.existsSync(PLANS_FILE)) return [];
    try { return JSON.parse(fs.readFileSync(PLANS_FILE, 'utf8')); } catch { return []; }
}
function savePlans(p) {
    saveJsonPrivate(PLANS_FILE, p);
    updateChecksum(CHECKSUM_FILE, PLANS_FILE);
}
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
function generateLicenseKey() {
    return crypto.randomBytes(16).toString('hex').toUpperCase();
}
function safeEqualString(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const ab = Buffer.from(a, 'utf8');
    const bb = Buffer.from(b, 'utf8');
    return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}
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
let _lastBackupDate = '';
function doBackup() {
    const today = new Date().toISOString().slice(0, 10);
    if (_lastBackupDate === today) return;
    _lastBackupDate = today;
    if (!fs.existsSync(DB_FILE)) return;
    const dest = path.join(BACKUP_DIR, `whitelist_${today}.json`);
    fs.copyFileSync(DB_FILE, dest);
    const list = fs.readdirSync(BACKUP_DIR)
        .filter(f => f.startsWith('whitelist_') && f.endsWith('.json'))
        .sort();
    while (list.length > 30) fs.unlinkSync(path.join(BACKUP_DIR, list.shift()));
    log('INFO', `Backup → ${dest}`);
}
const CHECKSUM_FILE   = path.join(DATA_DIR, '.checksums.json');
const active = {};
const _pendingMaxPlayers = new Map(); 
const _pendingKey        = new Map(); 
const _tcpConnsPerIp = new Map();     
const TCP_MAX_CONCURRENT_PER_IP = 10; 
function makeToken(mid, maxPl) {
    return crypto.createHmac('sha256', SECRET_KEY).update(`${mid}|${maxPl}`).digest('hex');
}
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
setInterval(() => {
    const now = Date.now();
    for (const [k, exp] of seenNonces) {
        if (exp < now) seenNonces.delete(k);
    }
}, REPLAY_WINDOW_MS).unref();
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
scheduleDailyTask('agent_token_expiry', 9, 5, () => {
    const expiring = agent.checkExpiringTokens();
    if (expiring.length > 0) {
        const list = expiring.map(e => `• <code>${e.mid}</code> — còn ${e.daysLeft} ngày`).join('\n');
        sendTelegram(`🔑 <b>Agent Token sắp hết hạn</b>\n${list}\n\nCần chạy lại lệnh cài đặt agent để cấp token mới.`);
    }
});
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
scheduleDailyTask('daily_backup', 3, 0, doBackup);
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
// -- TCP License Server (Persistent, State-per-Socket) ------------------------
const TCP_FRAME_MAX = 65536;
const TCP_IDLE_TIMEOUT_MS = 120000;
const TCP_DB_FLUSH_MS = 60 * 1000;
const TCP_STATS_FLUSH_MS = 15 * 1000;

// State per socket: Map<net.Socket, { mid, ip, authenticated, buf, lastHb }>
const tcpSockets = new Map();
const activeTcpByMid = new Map();
const _lastDbHbFlush = new Map();
const _lastStatFlush = new Map();

function tcpWrite(socket, plain, cb) {
    if (!socket || socket.destroyed || !socket.writable) return false;
    const payload = tcpEncrypt(plain);
    socket.write(payload, err => {
        if (err) {
            try { socket.destroy(err); } catch {}
            if (cb) cb(err);
            return;
        }
        if (cb) cb(null);
    });
    return true;
}

function tcpEnd(socket, plain) {
    if (!socket || socket.destroyed) return;
    try { socket.end(tcpEncrypt(plain)); }
    catch { try { socket.destroy(); } catch {} }
}

function tcpFailAndClose(socket, state, response, reason, { countFailure = true } = {}) {
    if (countFailure && state?.ip) tcpRlFail(state.ip);
    if (reason) log('WARNING', reason);
    tcpEnd(socket, response || 'DENY');
}

function shouldFlushStat(mid, players, ts) {
    const prev = _lastStatFlush.get(mid);
    if (!prev || ts - prev.ts >= TCP_STATS_FLUSH_MS) {
        _lastStatFlush.set(mid, { ts, players });
        return true;
    }
    return false;
}

function closePreviousSocketForMid(mid, socket, ip) {
    const old = activeTcpByMid.get(mid);
    if (old && old !== socket && !old.destroyed) {
        const oldState = tcpSockets.get(old);
        log('INFO', `TCP AUTH REPLACE [${mid}] old_ip=${oldState?.ip || '?'} new_ip=${ip}`);
        old.destroy();
    }
    activeTcpByMid.set(mid, socket);
}

const tcpServer = net.createServer((socket) => {
    const ip = (socket.remoteAddress || '').replace('::ffff:', '') || '?';
    const state = { mid: null, ip, authenticated: false, buf: '', lastHb: Date.now() };

    const cur = (_tcpConnsPerIp.get(ip) || 0) + 1;
    _tcpConnsPerIp.set(ip, cur);

    socket.on('close', () => {
        tcpSockets.delete(socket);
        if (state.mid && activeTcpByMid.get(state.mid) === socket) activeTcpByMid.delete(state.mid);
        const n = (_tcpConnsPerIp.get(ip) || 1) - 1;
        if (n <= 0) _tcpConnsPerIp.delete(ip);
        else _tcpConnsPerIp.set(ip, n);
    });

    socket.on('error', err => {
        if (err && err.code !== 'ECONNRESET') log('WARNING', `TCP SOCKET ERROR ${ip}: ${err.message}`);
    });
    socket.setTimeout(TCP_IDLE_TIMEOUT_MS, () => socket.destroy());

    if (cur > TCP_MAX_CONCURRENT_PER_IP) {
        log('WARNING', `TCP TOO-MANY-CONNS ${ip} count=${cur}/${TCP_MAX_CONCURRENT_PER_IP}`);
        tcpEnd(socket, 'DENY');
        return;
    }

    tcpSockets.set(socket, state);

    socket.on('data', (chunk) => {
        if (socket.destroyed) return;
        state.buf += chunk.toString('utf8');

        if (state.buf.length > TCP_FRAME_MAX) {
            tcpFailAndClose(socket, state, 'DENY', `TCP BUFFER OVERFLOW ${ip} [${state.mid || '?'}] len=${state.buf.length}`);
            return;
        }

        let nl;
        while ((nl = state.buf.indexOf('\n')) !== -1) {
            const frame = state.buf.slice(0, nl + 1);
            state.buf = state.buf.slice(nl + 1);
            processTcpFrame(socket, state, frame);
            if (socket.destroyed) return;
        }
    });
});

function processTcpFrame(socket, state, frame) {
    const plain = tcpDecrypt(frame);
    if (!plain) {
        tcpFailAndClose(socket, state, 'DENY', `TCP DECRYPT FAIL ${state.ip} [${state.mid || '?'}]`);
        return;
    }

    const parts = plain.trim().split(/\s+/);
    const cmd   = (parts[0] || '').toUpperCase();

    if (isIpBanned(state.ip, loadBans())) {
        tcpFailAndClose(socket, state, 'DENY', `TCP BANNED  ${state.ip}`, { countFailure: false });
        return;
    }

    if (isMaintenanceActive()) {
        tcpEnd(socket, 'MAINTENANCE');
        return;
    }

    if (tcpRlBlocked(state.ip)) {
        tcpEnd(socket, 'DENY');
        return;
    }

    if (cmd === 'AUTH' && !state.authenticated && parts[1]) {
        const mid     = parts[1];
        const sentKey = parts[2] || null;

        if (!isValidMachineId(mid)) {
            tcpFailAndClose(socket, state, 'DENY', `TCP AUTH DENY  ${state.ip}  [${mid}]  (invalid id)`);
            return;
        }

        const db = loadDB();
        let entry = db[mid];
        let justRegistered = false;

        if (!entry) {
            if (!autoRegisterEnabled()) {
                tcpFailAndClose(socket, state, 'DENY', `TCP AUTH DENY  ${state.ip}  [${mid}]  (not registered)`);
                return;
            }
            const newKey = generateLicenseKey();
            entry = {
                max_players: 10, tier: 'basic',
                note: 'Auto-registered', added: now(), revoked: false, auto: true,
                peak_players: 0, license_key: newKey, zombie: false,
            };
            db[mid] = entry;
            saveDB(db);
            justRegistered = true;
            log('INFO', `TCP AUTH AUTO  ${state.ip}  [${mid}]  tier=basic max=10  key=${newKey}`);
            sendTelegram(`🆕 <b>Auto-registered</b>\n<code>${mid}</code>\nIP: ${state.ip}\nTier: Basic · Max: 10 players · Khong gioi han ngay\nKey: ${newKey}`);
        }

        if (entry.revoked) {
            tcpFailAndClose(socket, state, 'DENY', `TCP AUTH DENY  ${state.ip}  [${mid}]  (revoked)`);
            return;
        }
        if (isExpired(entry)) {
            dispatchWebhook('license.expired', { mid, ip: state.ip });
            tcpFailAndClose(socket, state, 'DENY', `TCP AUTH DENY  ${state.ip}  [${mid}]  (expired)`);
            return;
        }

        if (!canAuthWithoutLicenseKey(entry, { strict: STRICT_LICENSE_KEY, justRegistered })) {
            tcpFailAndClose(socket, state, 'DENY', `TCP AUTH DENY  ${state.ip}  [${mid}]  (missing key in strict mode)`);
            return;
        }

        let shouldBootstrapKey = false;
        if (entry.license_key && !justRegistered) {
            const prev = Array.isArray(entry.previous_keys) ? entry.previous_keys : [];
            const validKey = sentKey && (
                safeEqualString(sentKey, entry.license_key) ||
                prev.some(p => p && p.key && safeEqualString(sentKey, p.key) && (!p.expires_at || p.expires_at > Date.now()))
            );
            shouldBootstrapKey = canBootstrapLicenseKey(entry, {
                sentKey, justRegistered,
                enabled: licenseKeyBootstrapEnabled(),
            });
            if (!validKey && !shouldBootstrapKey) {
                tcpFailAndClose(socket, state, 'DENY', `TCP AUTH DENY  ${state.ip}  [${mid}]  (wrong key)`);
                return;
            }
            if (shouldBootstrapKey) log('INFO', `TCP AUTH BOOTSTRAP-KEY ${state.ip}  [${mid}]  -> sync license.key`);
            if (!shouldBootstrapKey && sentKey !== entry.license_key) log('INFO', `TCP AUTH OLD-KEY ${state.ip}  [${mid}]  -> sync new key`);
        }

        if (Array.isArray(entry.allowed_ips) && entry.allowed_ips.length > 0) {
            const allowed = entry.allowed_ips.some(a =>
                a === state.ip || (a.endsWith('.*') && state.ip.startsWith(a.slice(0, -1)))
            );
            if (!allowed) {
                tcpFailAndClose(socket, state, 'DENY', `TCP AUTH DENY  ${state.ip}  [${mid}]  (IP not whitelisted)`);
                return;
            }
        }

        if (active[mid] && active[mid].ip !== state.ip) {
            log('WARNING', `TCP AUTH MULTI-IP [${mid}]  prev=${active[mid].ip}  new=${state.ip}`);
            sendTelegram(`⚠️ <b>Multi-IP Alert</b>\n<code>${mid}</code>\nPrev: ${active[mid].ip}\nNew: ${state.ip}\n— Possible license sharing —`);
            dispatchWebhook('machine.multi_ip', { mid, prev_ip: active[mid].ip, new_ip: state.ip });
        }

        const maxPl = getMaxPlayers(entry);
        const token = makeToken(mid, maxPl);
        const agentTok = agent.getOrCreateToken(mid);
        const needSyncKey = justRegistered || shouldBootstrapKey || (entry.license_key && sentKey && sentKey !== entry.license_key);

        let resp = `OK MAX:${maxPl} TOKEN:${token}`;
        if (needSyncKey && entry.license_key) resp += ` KEY:${entry.license_key}`;
        if (agentTok) resp += ` AGENT:${agentTok}`;

        closePreviousSocketForMid(mid, socket, state.ip);
        state.mid = mid;
        state.authenticated = true;
        state.lastHb = Date.now();

        if (!tcpWrite(socket, resp, err => {
            if (err) log('WARNING', `TCP AUTH WRITE FAIL ${state.ip} [${mid}]: ${err.message}`);
        })) {
            socket.destroy();
            return;
        }

        const wasOnline = !!active[mid];
        active[mid] = {
            ip: state.ip,
            players: active[mid]?.players || 0,
            last_seen: now(),
            uptime_start: active[mid]?.uptime_start || now(),
        };

        if (!wasOnline) {
            pushHistory({ mid, event: 'online', ip: state.ip });
            sendTelegram(`🟢 <b>Server Online</b>\n<code>${mid}</code>\nIP: ${state.ip}\nTier: ${entry.tier} | Max: ${maxPl}`);
            dispatchWebhook('machine.online', { mid, ip: state.ip, tier: entry.tier, max_players: maxPl });
        }

        if (entry.zombie) { entry.zombie = false; db[mid] = entry; saveDB(db); }
        tcpRlSuccess(state.ip);
        log('INFO', `TCP AUTH OK   ${state.ip}  [${mid}]  tier=${entry.tier} max=${maxPl}`);

        getGeoIP(state.ip).then(geo => {
            if (geo && active[mid]) active[mid].geo = geo;
        });

        if (agentTok) agent.ensureInstalled(mid, agentTok);
        return;
    }

    if (cmd === 'HB' && state.authenticated && parts[1] && parts[2] !== undefined) {
        const mid = parts[1];
        const cnt = parseInt(parts[2], 10);

        if (mid !== state.mid) {
            tcpFailAndClose(socket, state, 'DENY', `TCP HB MID-MISMATCH ${state.ip} claimed=${mid} actual=${state.mid}`);
            return;
        }

        if (activeTcpByMid.get(mid) !== socket) {
            log('INFO', `TCP HB STALE-SOCKET ${state.ip} [${mid}] closing old connection`);
            socket.destroy();
            return;
        }

        if (!Number.isFinite(cnt) || cnt < 0 || cnt > 100000) {
            tcpFailAndClose(socket, state, 'DENY', `TCP HB INVALID-COUNT ${state.ip} [${mid}] cnt=${parts[2]}`);
            return;
        }

        const db = loadDB();
        const entry = db[mid];
        if (!entry || entry.revoked) {
            tcpEnd(socket, 'REVOKE');
            if (active[mid]) {
                pushHistory({ mid, event: 'offline', ip: state.ip, reason: 'revoked' });
                dispatchWebhook('license.revoked', { mid, ip: state.ip });
            }
            delete active[mid];
            activeTcpByMid.delete(mid);
            log('WARNING', `TCP HB REVOKE ${state.ip}  [${mid}]  (revoked)`);
            return;
        }
        if (isExpired(entry)) {
            tcpEnd(socket, 'REVOKE');
            if (active[mid]) {
                pushHistory({ mid, event: 'offline', ip: state.ip, reason: 'expired' });
                dispatchWebhook('license.expired', { mid, ip: state.ip });
            }
            delete active[mid];
            activeTcpByMid.delete(mid);
            log('WARNING', `TCP HB REVOKE ${state.ip}  [${mid}]  (expired)`);
            return;
        }

        const maxPl = getMaxPlayers(entry);
        const ts = Date.now();
        let dbDirty = false;

        if (cnt > maxPl) {
            if (!entry._alertOver) {
                entry._alertOver = true;
                dbDirty = true;
                sendTelegram(`🚨 <b>Player Over Limit</b>\n<code>${mid}</code>\n${cnt}/${maxPl} players (over by ${cnt - maxPl})\n— Client tu chan login moi —`);
                dispatchWebhook('players.over', { mid, ip: state.ip, players: cnt, max_players: maxPl });
            }
            log('WARNING', `TCP HB OVER   ${state.ip}  [${mid}]  players=${cnt}>${maxPl}  (soft-limit)`);
        } else if (cnt < Math.floor(maxPl * 0.9) && entry._alertOver) {
            entry._alertOver = false;
            dbDirty = true;
        }

        if (cnt > (entry.peak_players || 0)) {
            entry.peak_players = cnt;
            dbDirty = true;
        }

        if (maxPl > 0 && cnt >= Math.floor(maxPl * 0.8) && !entry._alert80) {
            entry._alert80 = true;
            dbDirty = true;
            sendTelegram(`⚡ <b>Player Alert 80%</b>\n<code>${mid}</code>\n${cnt}/${maxPl} players`);
            dispatchWebhook('players.high', { mid, ip: state.ip, players: cnt, max_players: maxPl });
        } else if (maxPl > 0 && cnt < Math.floor(maxPl * 0.7) && entry._alert80) {
            entry._alert80 = false;
            dbDirty = true;
        }

        if (active[mid] && active[mid].ip && active[mid].ip !== state.ip) {
            log('WARNING', `TCP HB IP-CHANGE [${mid}] prev=${active[mid].ip} new=${state.ip}`);
        }

        let resp = `OK MAX:${maxPl}`;
        const pendingMax = _pendingMaxPlayers.get(mid);
        const pendingKey = _pendingKey.get(mid);

        if (pendingMax !== undefined && pendingMax > 0 && pendingMax <= 100000) resp += ` CFGMAX:${pendingMax}`;
        if (pendingKey !== undefined && pendingKey.length === 32) resp += ` KEY:${pendingKey}`;

        if (!tcpWrite(socket, resp, err => {
            if (err) {
                log('WARNING', `TCP HB WRITE FAIL ${state.ip} [${mid}]: ${err.message}`);
                return;
            }
            if (pendingMax !== undefined && _pendingMaxPlayers.get(mid) === pendingMax) {
                _pendingMaxPlayers.delete(mid);
                log('INFO', `TCP HB CFGMAX [${mid}] ${maxPl} -> ${pendingMax} (pushed)`);
            }
            if (pendingKey !== undefined && _pendingKey.get(mid) === pendingKey) {
                _pendingKey.delete(mid);
                log('INFO', `TCP HB KEY-SYNC [${mid}] (pushed)`);
            }
        })) {
            socket.destroy();
            return;
        }

        state.lastHb = ts;
        active[mid] = {
            ...active[mid],
            ip: state.ip,
            players: cnt,
            last_seen: now(),
            uptime_start: active[mid]?.uptime_start || now(),
        };

        entry.last_hb_ts = ts;
        const lastDbFlush = _lastDbHbFlush.get(mid) || 0;
        if (dbDirty || ts - lastDbFlush >= TCP_DB_FLUSH_MS) {
            db[mid] = entry;
            saveDB(db);
            _lastDbHbFlush.set(mid, ts);
        }
        if (shouldFlushStat(mid, cnt, ts)) pushStat(mid, cnt);

        log('INFO', `TCP HB OK     ${state.ip}  [${mid}]  players=${cnt}/${maxPl}${pendingMax ? ' +CFGMAX' : ''}${pendingKey ? ' +KEY' : ''}`);
        return;
    }

    tcpFailAndClose(socket, state, 'DENY', `TCP UNKNOWN  ${state.ip}  cmd=${cmd}  auth=${state.authenticated}  mid=${state.mid || '?'}`);
}

tcpServer.listen(TCP_PORT, BIND_HOST, () => log('INFO', `TCP ${BIND_HOST}:${TCP_PORT}  AES-256-GCM (persistent, state-per-socket)`));

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
    return (req.socket.remoteAddress || '?').replace(/^::ffff:/, '');
}
const sessionParser = session({
    store: new FileSessionStore({ dir: SESSION_DIR, ttlMs: 8 * 60 * 60 * 1000 }),
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
    rememberDataDir(__dirname, targetInfo.dir);
    const nextCreds = { user, pass_hash: hashPassword(pass) };
    fs.writeFileSync(path.join(targetInfo.dir, 'admin.json'), JSON.stringify(nextCreds, null, 2), { mode: 0o600 });
    if (path.resolve(targetInfo.dir) === path.resolve(DATA_DIR)) {
        adminCreds = nextCreds;
        WEB_USER = user;
        setupRequired = false;
    }
    return {
        ok: true,
        restartRequired: path.resolve(targetInfo.dir) !== path.resolve(DATA_DIR),
        dataDir: targetInfo.dir,
    };
}
function auth(req, res, next) {
    if (setupRequired) return res.redirect('/setup');
    if (req.session.pendingTwoFactor) return res.redirect('/verify-2fa');
    if (req.session.loggedIn) return next();
    res.redirect('/login');
}
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
    rl_fail(ip);
    const e = loginAttempts[ip];
    const left = e ? Math.max(0, MAX_ATTEMPTS - (e.count || 0)) : MAX_ATTEMPTS;
    log('WARNING', `LOGIN FAIL  ip=${ip}  (${left} left)`);
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
    const delayMs = getProgressiveDelayMs(ip);
    setTimeout(() => {
        res.render('login', { error: `Sai tài khoản hoặc mật khẩu. Còn ${left} lần thử.` });
    }, delayMs);
});
app.get('/logout', auth, (req, res) => res.render('logout', { flash: null }));
app.post('/logout', auth, (req, res) => { req.session.destroy(); res.redirect('/login'); });
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
    res.render('dashboard', {
        active_count:  rows.length,
        total:         Object.keys(db).length,
        revoked:       Object.values(db).filter(v => v.revoked).length,
        expired:       Object.values(db).filter(v => !v.revoked && isExpired(v)).length,
        total_players: rows.reduce((s, r) => s + (r.players || 0), 0),
        maintenance:   isMaintenanceActive(),
        rows, flash: consumeFlash(req.session), TIERS,
        last_updated:  new Date().toLocaleTimeString('vi-VN'),
    });
});
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
    const maxPl      = tier === 'unlimited' ? 9999 : (parseInt(req.body.max_players) || DEFAULT_PLAYERS);
    const trial_days = parseInt(req.body.trial_days) || 7;
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
    db[mid].max_players = getMaxPlayers(db[mid]);
    saveDB(db);
    const keyMsg = license_key ? ` | Key: ${license_key}` : '';
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
    const oldMax = getMaxPlayers(db[mid]);
    if (!isNaN(maxPl) && maxPl > 0) {
        db[mid].max_players = maxPl;
    } else if (db[mid]) {
        db[mid].max_players = getMaxPlayers(db[mid]);
    }
    if (tier && TIERS[tier]) db[mid].tier = tier;
    if (exp !== undefined) db[mid].expires_at = exp || undefined;
    saveDB(db);
    const newMax = getMaxPlayers(db[mid]);
    if (newMax !== oldMax && active[mid]) {
        _pendingMaxPlayers.set(mid, newMax);
        log('INFO', `CFGMAX PENDING [${mid}] ${oldMax} → ${newMax} (will push on next HB)`);
    }
    req.session.flash = { type: 'success', msg: `Đã cập nhật ${mid}` + (active[mid] && newMax !== oldMax ? ' — thay đổi sẽ có hiệu lực ngay lập tức.' : '') };
    res.redirect('/machines');
});
app.post('/renew', auth, (req, res) => {
    const mid  = (req.body.mid || '').trim();
    const days = parseInt(req.body.days) || 30;
    const db   = loadDB();
    if (!db[mid]) { req.session.flash = { type: 'danger', msg: 'Không tìm thấy.' }; return res.redirect('/machines'); }
    const entry = db[mid];
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
        const cutoff = Date.now();
        entry.previous_keys = entry.previous_keys
            .filter(p => p && p.key && p.key !== oldKey && p.key !== newKey
                         && (!p.expires_at || p.expires_at > cutoff));
        entry.previous_keys.push({ key: oldKey, expires_at: cutoff + KEY_GRACE_MS });
        if (entry.previous_keys.length > 5) entry.previous_keys = entry.previous_keys.slice(-5);
    }
    entry.license_key = newKey;
    db[mid] = entry; saveDB(db);
    if (active[mid]) {
        _pendingKey.set(mid, newKey);
        log('INFO', `KEY-SYNC PENDING [${mid}] → new key will be pushed on next HB`);
    }
    req.session.flash = { type: 'success',
        msg: `Key mới [${mid}]: ${newKey} — key cũ còn hiệu lực 24h để client đồng bộ.` + (active[mid] ? ' Key sẽ được đẩy xuống máy ngay lập tức.' : '') };
    log('INFO', `WEB GEN-KEY [${mid}] (old key kept ${KEY_GRACE_MS/3600000}h grace)`);
    res.redirect('/machines');
});
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
app.post('/delete-machine', auth, (req, res) => {
    const mid = (req.body.mid || '').trim();
    if (!mid) { req.session.flash = { type: 'danger', msg: 'Machine ID trống.' }; return res.redirect('/machines'); }
    const db = loadDB();
    if (!db[mid]) { req.session.flash = { type: 'danger', msg: `Không tìm thấy ${mid}.` }; return res.redirect('/machines'); }
    delete db[mid];
    saveDB(db);
    try { agent.uninstall(mid); } catch {}
    if (active[mid]) {
        delete active[mid];
    }
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
        if (db[mid] && !db[mid].revoked) { db[mid].revoked = true; done++; }
    }
    saveDB(db);
    req.session.flash = { type: 'success', msg: `Đã revoke ${done}/${mids.length} máy.` };
    log('INFO', `WEB BULK-REVOKE ${done}/${mids.length}`);
    res.redirect('/machines');
});
app.post('/bulk-renew', auth, (req, res) => {
    const mids = parseMidsFromBody(req.body);
    const days = parseInt(req.body.days) || 30;
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
        delete db[mid];
        try { agent.uninstall(mid); } catch {}
        try {
            const stats = loadStats();
            if (stats[mid]) { delete stats[mid]; saveJsonPrivate(STATS_FILE, stats, false); }
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
app.get('/plans', auth, (req, res) => {
    res.render('plans', { plans: loadPlans(), TIERS, flash: consumeFlash(req.session) });
});
app.post('/plans/add', auth, (req, res) => {
    const plans = loadPlans();
    const p = {
        id: crypto.randomBytes(4).toString('hex'),
        name:        (req.body.name || '').trim(),
        tier:        ['trial', 'basic', 'pro', 'unlimited'].includes(req.body.tier) ? req.body.tier : 'basic',
        max_players: parseInt(req.body.max_players) || DEFAULT_PLAYERS,
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
function operationsSnapshot() {
    const backups = fs.existsSync(BACKUP_DIR)
        ? fs.readdirSync(BACKUP_DIR).filter(f => f.startsWith('whitelist_') && f.endsWith('.json')).sort()
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
        tcpAddress: `${BIND_HOST}:${TCP_PORT}`,
        deployStatus: deployManager.status(),
    };
}
app.get('/operations', auth, (req, res) => {
    res.render('operations', { ...operationsSnapshot(), flash: consumeFlash(req.session) });
});
app.post('/operations/update', auth, async (req, res) => {
    try {
        const result = await deployManager.runUpdate();
        audit(req, 'deploy.update', { ok: result.ok });
        req.session.flash = result.ok
            ? { type: 'success', msg: 'Đã cập nhật từ Git và restart PM2.' }
            : { type: 'danger', msg: 'Cập nhật thất bại. Xem chi tiết trong Operations.' };
    } catch (err) {
        req.session.flash = { type: 'danger', msg: err.message || 'Không thể chạy cập nhật.' };
    }
    res.redirect('/operations');
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
    } catch (err) {
        req.session.flash = { type: 'danger', msg: err.message || 'Không thể restart PM2.' };
    }
    res.redirect('/operations');
});
app.post('/operations/rollback', auth, async (req, res) => {
    try {
        const result = await deployManager.rollbackLast();
        audit(req, 'deploy.rollback', { ok: result.ok, rollbackTo: result.rollbackTo });
        req.session.flash = result.ok
            ? { type: 'success', msg: `Đã rollback về commit ${result.rollbackTo} và restart PM2.` }
            : { type: 'danger', msg: 'Rollback thất bại. Xem chi tiết trong Operations.' };
    } catch (err) {
        req.session.flash = { type: 'danger', msg: err.message || 'Không thể rollback.' };
    }
    res.redirect('/operations');
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
app.post('/settings/change-password', auth, (req, res) => {
    const currentPassword = String(req.body.current_password || '');
    const newPassword     = String(req.body.new_password || '');
    const confirmPassword = String(req.body.confirm_password || '');
    if (!verifyPassword(currentPassword, adminCreds.pass_hash)) {
        return res.render('settings', {
            settings: loadSettings(),
            dataDir: DATA_DIR, dataDirSource: DATA_DIR_INFO.source,
            dataDirLocalFile: path.join(__dirname, 'data_dir.local'),
            runtime: RUNTIME, runtimeWarnings: RUNTIME.warnings,
            flash: { type: 'danger', msg: 'Mật khẩu hiện tại không đúng.' },
        });
    }
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
    adminCreds = { user: WEB_USER, pass_hash: hashPassword(newPassword) };
    fs.writeFileSync(ADMIN_FILE, JSON.stringify(adminCreds, null, 2), { mode: 0o600 });
    updateChecksum(CHECKSUM_FILE, ADMIN_FILE);
    audit(req, 'settings.change_password', {});
    log('SECURITY', `ADMIN PASSWORD CHANGED  ip=${clientIp(req)}`);
    sendTelegram(`🔐 <b>Admin password changed</b>\nIP: ${clientIp(req)}`);
    req.session.regenerate((err) => {
        req.session.loggedIn = true;
        req.session.flash = { type: 'success', msg: 'Đã đổi mật khẩu thành công. Vui lòng đăng nhập lại.' };
        res.redirect('/login');
    });
});
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
app.get('/history', auth, (req, res) => {
    const mid = req.query.mid || null;
    let h = loadHistory().reverse();
    if (mid) h = h.filter(e => e.mid === mid);
    res.render('history', { events: h.slice(0, 200), filter_mid: mid, flash: null });
});
app.get('/logs', auth, (req, res) => {
    let lines = [];
    if (fs.existsSync(LOG_FILE)) lines = fs.readFileSync(LOG_FILE, 'utf8').split('\n').filter(Boolean).slice(-80);
    res.render('logs', { lines });
});
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
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        uptime: Math.floor(process.uptime()),
        runtime: {
            node_env: RUNTIME.nodeEnv,
            web_port: WEB_PORT,
            tcp_port: TCP_PORT,
            pm2: RUNTIME.pm2,
        },
        maintenance: isMaintenanceActive(), ts: Date.now(),
    });
});
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
app.post('/machine/:mid/agent-install', auth, (req, res) => {
    const mid = req.params.mid;
    const db  = loadDB();
    if (!db[mid]) { req.session.flash = { type: 'danger', msg: 'Machine chưa được cấp license.' }; return res.redirect('/machines'); }
    const tok = agent.getOrCreateToken(mid);
    if (req.body.server_dir) agent.setServerDir(mid, req.body.server_dir);
    const base = (loadSettings().public_url || (req.protocol + '://' + req.get('host'))).replace(/\/+$/, '')
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
function checkAgentAuth(req) {
    const auth_h = req.headers['authorization'] || '';
    const m = auth_h.match(/^Bearer\s+(.+)$/i);
    if (!m) return null;
    const mid = (req.headers['x-mid'] || '').toString();
    if (!mid || !agent.verifyToken(mid, m[1].trim())) return null;
    return mid;
}
app.get('/agent/install.sh', (req, res) => {
    const mid   = (req.query.mid   || '').toString();
    const token = (req.query.token || '').toString();
    if (!mid || !token || !agent.verifyToken(mid, token)) {
        return res.status(403).type('text/plain').send('# invalid mid/token\nexit 1\n');
    }
    const base = (loadSettings().public_url || (req.protocol + '://' + req.get('host'))).replace(/\/+$/, '')
    res.type('text/plain').send(
        require('./agent_manager').buildInstallScript({ serverUrl: base, mid, token })
    );
});
app.get('/agent/uninstall.sh', (req, res) => {
    if (!isAgentScriptAuthorized(req.query, agent.verifyToken)) {
        return res.status(403).type('text/plain').send('# invalid mid/token\nexit 1\n');
    }
    res.type('text/plain').send(agent.buildUninstallScript());
});
app.get('/agent/runtime.sh', (req, res) => {
    if (!isAgentScriptAuthorized(req.query, agent.verifyToken)) {
        return res.status(403).type('text/plain').send('# invalid mid/token\nexit 1\n');
    }
    res.type('text/plain').send(agent.AGENT_RUNTIME);
});
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
app.get('/api/machine/:mid/monitor', auth, (req, res) => {
    const mid = req.params.mid;
    if (!agent.infoFor(mid)) return res.status(404).json({ error: 'no_agent' });
    const snap = agent.getMonitor(mid);
    if (!snap) return res.status(204).end();
    res.json(snap);
});
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
httpServer.listen(WEB_PORT, BIND_HOST, () => {
    log('INFO', `Web UI: http://${BIND_HOST}:${WEB_PORT}`);
    for (const warning of RUNTIME.warnings) log('WARNING', warning);
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
    const integrityResults = verifyAllChecksums(CHECKSUM_FILE);
    const tampered = integrityResults.filter(r => !r.ok);
    if (tampered.length > 0) {
        const list = tampered.map(r => `• ${path.basename(r.file)}: ${r.error}${r.expected ? ' (expected ' + r.expected + '..., got ' + r.actual + '...)' : ''}`).join('\n');
        log('SECURITY', `CONFIG INTEGRITY TAMPERED!\n${list}`);
        sendTelegram(`🚨 <b>SECURITY ALERT: Config Files Tampered!</b>\n${list}`);
    } else if (integrityResults.length > 0) {
        log('INFO', `Config integrity verified: ${integrityResults.length} files OK`);
    }
    if (!fs.existsSync(CHECKSUM_FILE)) {
        updateChecksum(CHECKSUM_FILE, DB_FILE);
        updateChecksum(CHECKSUM_FILE, BAN_FILE);
        updateChecksum(CHECKSUM_FILE, SETTINGS_FILE);
        updateChecksum(CHECKSUM_FILE, PLANS_FILE);
        updateChecksum(CHECKSUM_FILE, ADMIN_FILE);
        log('INFO', 'Config checksums initialized');
    }
    doBackup(); 
    repairDBMaxPlayers(); 
});
function shutdown(signal) {
    log('INFO', `${signal} received, shutting down gracefully...`);
    const forceExit = setTimeout(() => process.exit(1), 10000);
    forceExit.unref();
    for (const socket of tcpSockets.keys()) {
        try { socket.destroy(); } catch {}
    }
    tcpServer.close(() => {
        httpServer.close(() => {
            log('INFO', 'Shutdown complete');
            process.exit(0);
        });
    });
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));