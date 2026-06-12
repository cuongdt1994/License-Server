'use strict';

const crypto = require('crypto');
const fs = require('fs');

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
    const text = String(mid || '').trim();
    const sep = text.indexOf('|');
    if (sep <= 0 || sep === text.length - 1) return false;
    const mac = text.slice(0, sep);
    const host = text.slice(sep + 1).trim();
    if (!host || host.length > 128) return false;
    return /^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(mac);
}

function canViewPortalLicense(entry, providedKey) {
    const stored = String(entry?.license_key || '').trim();
    const provided = String(providedKey || '').trim();
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
    fs.appendFileSync(file, JSON.stringify(row) + '\n', { mode: 0o600 });
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
};
