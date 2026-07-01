'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const PASSWORD_ITERATIONS = 210000;
const PASSWORD_KEYLEN = 32;
const PASSWORD_DIGEST = 'sha256';

function ensureCsrfToken(session) {
    if (!session.csrfToken) session.csrfToken = crypto.randomBytes(32).toString('base64url');
    return session.csrfToken;
}

function safeEqual(a, b) {
    const aa = Buffer.from(String(a || ''));
    const bb = Buffer.from(String(b || ''));
    return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function hashPassword(password, { iterations = PASSWORD_ITERATIONS } = {}) {
    const salt = crypto.randomBytes(16).toString('base64url');
    const hash = crypto.pbkdf2Sync(String(password || ''), salt, iterations, PASSWORD_KEYLEN, PASSWORD_DIGEST).toString('base64url');
    return `pbkdf2_sha256$${iterations}$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
    const parts = String(stored || '').split('$');
    if (parts.length !== 4 || parts[0] !== 'pbkdf2_sha256') return false;
    const iterations = parseInt(parts[1], 10);
    if (!Number.isInteger(iterations) || iterations < 100000) return false;
    const expected = Buffer.from(parts[3], 'base64url');
    const actual = crypto.pbkdf2Sync(String(password || ''), parts[2], iterations, expected.length, PASSWORD_DIGEST);
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function normalizeAdminCredentials(raw) {
    const user = String(raw?.user || 'admin');
    if (raw?.pass_hash) return { user, pass_hash: String(raw.pass_hash) };
    if (raw?.pass) return { user, pass_hash: hashPassword(String(raw.pass)) };
    return null;
}

function verifyCsrfRequest(req) {
    if (SAFE_METHODS.has(String(req.method || '').toUpperCase())) return true;
    const expected = req.session?.csrfToken;
    const provided = req.body?._csrf || req.headers?.['x-csrf-token'];
    return !!expected && !!provided && safeEqual(expected, provided);
}

function strictLicenseKeyEnabled(env = process.env) {
    return /^(1|true|yes|on)$/i.test(String(env.STRICT_LICENSE_KEY || '').trim());
}

function licenseKeyBootstrapEnabled(env = process.env) {
    return !/^(0|false|no|off)$/i.test(String(env.LICENSE_KEY_BOOTSTRAP || '').trim());
}

function canAuthWithoutLicenseKey(entry, { strict, justRegistered }) {
    if (justRegistered) return true;
    if (!strict) return true;
    return !!entry?.license_key;
}

function canBootstrapLicenseKey(entry, { sentKey, justRegistered, enabled }) {
    if (!enabled || justRegistered) return false;
    if (!entry?.license_key) return false;
    return !String(sentKey || '').trim();
}

function isValidMachineId(mid) {
    // HWID is a SHA-256 hash: 64 lowercase hex characters.
    // Built by license_check.cpp GetMachineID() from DMI product_uuid,
    // board_serial, /etc/machine-id, CPU model, and hostname.
    const text = String(mid || '').trim();
    return /^[0-9a-f]{64}$/.test(text);
}

function canViewPortalLicense(entry, providedKey) {
    const stored = String(entry?.license_key || '').trim().toUpperCase();
    const provided = String(providedKey || '').trim().toUpperCase();
    return !!stored && !!provided && safeEqual(stored, provided);
}

function consumeFlash(session) {
    if (!session || !session.flash) return null;
    const flash = session.flash;
    delete session.flash;
    return flash;
}

function auditEvent(file, event) {
    const row = {
        ts: new Date().toISOString(),
        action: String(event.action || 'unknown'),
        user: event.user || null,
        ip: event.ip || null,
        details: event.details || {},
    };
    fs.appendFileSync(path.normalize(file), JSON.stringify(row) + '\n', { mode: 0o600 });
}

function securityHeaders() {
    return {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'same-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        'Content-Security-Policy': "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'",
    };
}

function isAgentScriptAuthorized(query, verifyToken) {
    const mid = String(query?.mid || '');
    const token = String(query?.token || '');
    return !!mid && !!token && verifyToken(mid, token);
}

// ── Strong password policy ─────────────────────────────────────────────────
// Yêu cầu: tối thiểu 10 ký tự, có ít nhất 1 chữ hoa, 1 chữ thường, 1 chữ số.
// Từ chối các mật khẩu phổ biến (top 20).
const COMMON_PASSWORDS = new Set([
    'password', '1234567890', 'qwerty12345', 'adminadmin',
    'administrator', 'letmein123', 'welcome1234', 'changeme123',
    'abc12345678', 'password123', '123456789a', 'qwertyuiop',
]);

function isStrongPassword(password) {
    const pwd = String(password || '');
    if (pwd.length < 10) return { ok: false, error: 'Mật khẩu cần ít nhất 10 ký tự.' };
    if (!/[A-Z]/.test(pwd)) return { ok: false, error: 'Mật khẩu cần ít nhất 1 chữ hoa (A-Z).' };
    if (!/[a-z]/.test(pwd)) return { ok: false, error: 'Mật khẩu cần ít nhất 1 chữ thường (a-z).' };
    if (!/[0-9]/.test(pwd)) return { ok: false, error: 'Mật khẩu cần ít nhất 1 chữ số (0-9).' };
    if (COMMON_PASSWORDS.has(pwd.toLowerCase())) return { ok: false, error: 'Mật khẩu quá phổ biến, dễ bị đoán. Vui lòng chọn mật khẩu khác.' };
    return { ok: true };
}

// ── Fail2ban-style auto-ban ────────────────────────────────────────────────
// Nếu 1 IP bị lock ≥ AUTO_BAN_LOCK_THRESHOLD lần trong AUTO_BAN_WINDOW_MS
// thì tự động thêm vào bans.json trong AUTO_BAN_DURATION_MS.
const AUTO_BAN_LOCK_THRESHOLD = 3;
const AUTO_BAN_WINDOW_MS = 60 * 60 * 1000;       // 1 giờ
const AUTO_BAN_DURATION_MS = 24 * 60 * 60 * 1000; // 24 giờ
const _lockHistory = {}; // ip → [timestamp, ...]

function recordLockEvent(ip) {
    if (!_lockHistory[ip]) _lockHistory[ip] = [];
    const now = Date.now();
    _lockHistory[ip].push(now);
    // Chỉ giữ các lần lock trong window
    const cutoff = now - AUTO_BAN_WINDOW_MS;
    _lockHistory[ip] = _lockHistory[ip].filter(t => t > cutoff);
    return _lockHistory[ip].length >= AUTO_BAN_LOCK_THRESHOLD;
}

function clearLockHistory(ip) {
    delete _lockHistory[ip];
}

// ── Progressive delay for failed logins ────────────────────────────────────
// Mỗi lần fail thêm delay tăng dần (max 5s) để chống brute-force timing.
const _failDelays = {}; // ip → { count, lastFail }

function getProgressiveDelayMs(ip) {
    if (!_failDelays[ip]) _failDelays[ip] = { count: 0, lastFail: 0 };
    const entry = _failDelays[ip];
    // Reset counter nếu lần fail cuối > 30 phút
    if (Date.now() - entry.lastFail > 30 * 60 * 1000) entry.count = 0;
    entry.count++;
    entry.lastFail = Date.now();
    // 0.5s → 1s → 2s → 3s → 5s (max)
    const delays = [500, 1000, 2000, 3000, 5000];
    return delays[Math.min(entry.count - 1, delays.length - 1)];
}

function clearFailDelay(ip) {
    delete _failDelays[ip];
}

// ── HMAC chain for audit log integrity ─────────────────────────────────────
function computeAuditChainHash(prevHash, line) {
    return crypto.createHmac('sha256', String(prevHash || 'GENESIS'))
        .update(line, 'utf8')
        .digest('hex');
}

function appendAuditLine(file, rowObj) {
    const fs = require('fs');
    const prevHash = readAuditChainState(file);
    const line = JSON.stringify(rowObj);
    const newHash = computeAuditChainHash(prevHash, line);
    // Format: <line>\t<chain_hash>\n
    fs.appendFileSync(path.normalize(file), line + '\t' + newHash + '\n', { mode: 0o600 });
    saveAuditChainState(file, newHash);
}

function readAuditChainState(file) {
    const fs = require('fs');
    const stateFile = path.normalize(file + '.chain');
    if (!fs.existsSync(stateFile)) return 'GENESIS';
    try {
        return fs.readFileSync(stateFile, 'utf8').trim() || 'GENESIS';
    } catch { return 'GENESIS'; }
}

function saveAuditChainState(file, hash) {
    const fs = require('fs');
    fs.writeFileSync(path.normalize(file + '.chain'), hash, { mode: 0o600 });
}

function verifyAuditChain(file) {
    const fs = require('fs');
    const safeFile = path.normalize(file);
    if (!fs.existsSync(safeFile)) return { ok: true, entries: 0, migrated: false };
    const content = fs.readFileSync(safeFile, 'utf8');
    const lines = content.split('\n').filter(l => l.trim());
    if (lines.length === 0) return { ok: true, entries: 0, migrated: false };

    let prevHash = 'GENESIS';
    for (let i = 0; i < lines.length; i++) {
        const parts = lines[i].split('\t');
        if (parts.length < 2) return { ok: false, error: `Line ${i + 1}: missing chain hash`, entries: lines.length, migrated: false };
        const lineContent = parts.slice(0, -1).join('\t');
        const storedHash = parts[parts.length - 1];
        const expectedHash = computeAuditChainHash(prevHash, lineContent);
        if (!safeEqual(expectedHash, storedHash)) {
            return { ok: false, error: `Line ${i + 1}: chain hash mismatch (expected ${expectedHash.slice(0, 12)}..., got ${storedHash.slice(0, 12)}...)`, entries: lines.length, migrated: false };
        }
        prevHash = expectedHash;
    }
    return { ok: true, entries: lines.length, migrated: false };
}

// ── Auto-migrate old audit log (no chain hashes) ────────────────────────────
// Audit log cũ không có \t<chain_hash>. Hàm này phát hiện và re-write
// toàn bộ file với chain hash cho từng dòng.
function migrateAuditChainIfNeeded(file) {
    const fs = require('fs');
    const safeFile = path.normalize(file);
    if (!fs.existsSync(safeFile)) return { ok: true, entries: 0, migrated: false };

    const content = fs.readFileSync(safeFile, 'utf8');
    const lines = content.split('\n').filter(l => l.trim());
    if (lines.length === 0) return { ok: true, entries: 0, migrated: false };

    // Check if first line has chain hash (contains \t at end)
    const firstParts = lines[0].split('\t');
    if (firstParts.length >= 2 && firstParts[firstParts.length - 1].length === 64) {
        // Already has chain hash — nothing to migrate
        return { ok: true, entries: lines.length, migrated: false };
    }

    // Old format detected — rebuild with chain hashes
    let prevHash = 'GENESIS';
    const newLines = [];
    for (const line of lines) {
        const newHash = computeAuditChainHash(prevHash, line);
        newLines.push(line + '\t' + newHash);
        prevHash = newHash;
    }

    // Write migrated file
    fs.writeFileSync(safeFile, newLines.join('\n') + '\n', { mode: 0o600 });
    saveAuditChainState(safeFile, prevHash);

    return { ok: true, entries: lines.length, migrated: true };
}

// ── Config file integrity checksums ────────────────────────────────────────
function computeChecksum(filePath) {
    const fs = require('fs');
    const safePath = path.normalize(filePath);
    if (!fs.existsSync(safePath)) return null;
    const data = fs.readFileSync(safePath);
    return crypto.createHash('sha256').update(data).digest('hex');
}

function loadChecksums(checksumFile) {
    const fs = require('fs');
    const safeFile = path.normalize(checksumFile);
    if (!fs.existsSync(safeFile)) return {};
    try { return JSON.parse(fs.readFileSync(safeFile, 'utf8')); } catch { return {}; }
}

function saveChecksums(checksumFile, checksums) {
    const fs = require('fs');
    fs.writeFileSync(path.normalize(checksumFile), JSON.stringify(checksums, null, 2), { mode: 0o600 });
}

function updateChecksum(checksumFile, filePath) {
    const checksums = loadChecksums(checksumFile);
    const hash = computeChecksum(filePath);
    if (hash) checksums[filePath] = hash;
    else delete checksums[filePath];
    saveChecksums(checksumFile, checksums);
}

function verifyAllChecksums(checksumFile) {
    const checksums = loadChecksums(checksumFile);
    const results = [];
    for (const [filePath, expectedHash] of Object.entries(checksums)) {
        const actualHash = computeChecksum(filePath);
        if (!actualHash) {
            results.push({ file: filePath, ok: false, error: 'file_missing' });
        } else if (actualHash !== expectedHash) {
            results.push({ file: filePath, ok: false, error: 'hash_mismatch', expected: expectedHash.slice(0, 16), actual: actualHash.slice(0, 16) });
        } else {
            results.push({ file: filePath, ok: true });
        }
    }
    return results;
}

module.exports = {
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
};
