'use strict';

const crypto = require('crypto');
const fs = require('fs');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function ensureCsrfToken(session) {
    if (!session.csrfToken) session.csrfToken = crypto.randomBytes(32).toString('base64url');
    return session.csrfToken;
}

function safeEqual(a, b) {
    const aa = Buffer.from(String(a || ''));
    const bb = Buffer.from(String(b || ''));
    return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
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

function canAuthWithoutLicenseKey(entry, { strict, justRegistered }) {
    if (justRegistered) return true;
    if (!strict) return true;
    return !!entry?.license_key;
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
    consumeFlash,
    auditEvent,
    securityHeaders,
    isAgentScriptAuthorized,
};
