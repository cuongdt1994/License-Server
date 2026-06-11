'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
    ensureCsrfToken,
    verifyCsrfRequest,
    strictLicenseKeyEnabled,
    canAuthWithoutLicenseKey,
    auditEvent,
    securityHeaders,
    isAgentScriptAuthorized,
    consumeFlash,
} = require('../security');

{
    const session = {};
    const token = ensureCsrfToken(session);
    assert.strictEqual(typeof token, 'string');
    assert.ok(token.length >= 32);
    assert.strictEqual(ensureCsrfToken(session), token);
    assert.strictEqual(verifyCsrfRequest({ method: 'POST', session, body: { _csrf: token }, headers: {} }), true);
    assert.strictEqual(verifyCsrfRequest({ method: 'POST', session, body: { _csrf: 'bad' }, headers: {} }), false);
    assert.strictEqual(verifyCsrfRequest({ method: 'GET', session, body: {}, headers: {} }), true);
}

{
    assert.strictEqual(strictLicenseKeyEnabled({ STRICT_LICENSE_KEY: 'true' }), true);
    assert.strictEqual(strictLicenseKeyEnabled({ STRICT_LICENSE_KEY: '1' }), true);
    assert.strictEqual(strictLicenseKeyEnabled({ STRICT_LICENSE_KEY: 'yes' }), true);
    assert.strictEqual(strictLicenseKeyEnabled({ STRICT_LICENSE_KEY: 'false' }), false);
    assert.strictEqual(canAuthWithoutLicenseKey({ license_key: 'abc' }, { strict: true, justRegistered: false }), true);
    assert.strictEqual(canAuthWithoutLicenseKey({}, { strict: true, justRegistered: false }), false);
    assert.strictEqual(canAuthWithoutLicenseKey({}, { strict: true, justRegistered: true }), true);
    assert.strictEqual(canAuthWithoutLicenseKey({}, { strict: false, justRegistered: false }), true);
}

{
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'license-audit-')), 'audit.log');
    auditEvent(file, { action: 'machine.delete', ip: '127.0.0.1', user: 'admin', details: { mid: 'm1' } });
    const row = JSON.parse(fs.readFileSync(file, 'utf8').trim());
    assert.strictEqual(row.action, 'machine.delete');
    assert.strictEqual(row.details.mid, 'm1');
    assert.ok(row.ts);
}

{
    const headers = securityHeaders();
    assert.strictEqual(headers['X-Frame-Options'], 'DENY');
    assert.strictEqual(headers['X-Content-Type-Options'], 'nosniff');
    assert.ok(headers['Content-Security-Policy'].includes("frame-ancestors 'none'"));
}

{
    const verify = (mid, token) => mid === 'm1' && token === 'tok';
    assert.strictEqual(isAgentScriptAuthorized({ mid: 'm1', token: 'tok' }, verify), true);
    assert.strictEqual(isAgentScriptAuthorized({ mid: 'm1', token: 'bad' }, verify), false);
    assert.strictEqual(isAgentScriptAuthorized({ mid: '', token: 'tok' }, verify), false);
}

{
    const session = { flash: { type: 'success', msg: 'saved' } };
    assert.deepStrictEqual(consumeFlash(session), { type: 'success', msg: 'saved' });
    assert.strictEqual(session.flash, undefined);
    assert.strictEqual(consumeFlash(session), null);
}

console.log('security tests passed');
