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
    licenseKeyBootstrapEnabled,
    canBootstrapLicenseKey,
    canViewPortalLicense,
    auditEvent,
    securityHeaders,
    isAgentScriptAuthorized,
    consumeFlash,
    hashPassword,
    verifyPassword,
    normalizeAdminCredentials,
} = require('../security');

const serverSource = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const settingsView = fs.readFileSync(path.join(__dirname, '..', 'views', 'settings.ejs'), 'utf8');

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
    assert.strictEqual(licenseKeyBootstrapEnabled({}), true);
    assert.strictEqual(licenseKeyBootstrapEnabled({ LICENSE_KEY_BOOTSTRAP: '0' }), false);
    assert.strictEqual(licenseKeyBootstrapEnabled({ LICENSE_KEY_BOOTSTRAP: 'false' }), false);
    assert.strictEqual(licenseKeyBootstrapEnabled({ LICENSE_KEY_BOOTSTRAP: 'off' }), false);
    assert.strictEqual(licenseKeyBootstrapEnabled({ LICENSE_KEY_BOOTSTRAP: '1' }), true);
    assert.strictEqual(canBootstrapLicenseKey({ license_key: 'ABC123' }, { sentKey: null, justRegistered: false, enabled: true }), true);
    assert.strictEqual(canBootstrapLicenseKey({ license_key: 'ABC123' }, { sentKey: '', justRegistered: false, enabled: true }), true);
    assert.strictEqual(canBootstrapLicenseKey({ license_key: 'ABC123' }, { sentKey: 'WRONG', justRegistered: false, enabled: true }), false);
    assert.strictEqual(canBootstrapLicenseKey({ license_key: 'ABC123' }, { sentKey: null, justRegistered: true, enabled: true }), false);
    assert.strictEqual(canBootstrapLicenseKey({ license_key: '' }, { sentKey: null, justRegistered: false, enabled: true }), false);
    assert.strictEqual(canBootstrapLicenseKey({ license_key: 'ABC123' }, { sentKey: null, justRegistered: false, enabled: false }), false);
}

{
    assert.strictEqual(canViewPortalLicense({ license_key: 'ABC123' }, 'ABC123'), true);
    assert.strictEqual(canViewPortalLicense({ license_key: 'ABC123' }, 'wrong'), false);
    assert.strictEqual(canViewPortalLicense({}, ''), false);
    assert.strictEqual(canViewPortalLicense(null, 'ABC123'), false);
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

{
    const stored = hashPassword('correct horse battery staple');
    assert.match(stored, /^pbkdf2_sha256\$\d+\$/);
    assert.strictEqual(verifyPassword('correct horse battery staple', stored), true);
    assert.strictEqual(verifyPassword('wrong', stored), false);
    assert.notStrictEqual(hashPassword('correct horse battery staple'), stored, 'hashes include a random salt');
}

{
    const normalized = normalizeAdminCredentials({ user: 'admin', pass: 'legacy-plain' });
    assert.strictEqual(normalized.user, 'admin');
    assert.ok(normalized.pass_hash);
    assert.strictEqual(normalized.pass, undefined);
    assert.strictEqual(verifyPassword('legacy-plain', normalized.pass_hash), true);
}

{
    assert.match(serverSource, /function autoRegisterEnabled/);
    assert.match(serverSource, /LICENSE_AUTO_REGISTER/);
    assert.doesNotMatch(serverSource, /return \/\^\(1\|true\|yes\|on\)\$\/i\.test\(String\(env\.LICENSE_AUTO_REGISTER/);
}

{
    assert.match(serverSource, /advanced_shell_enabled === true/);
    assert.doesNotMatch(serverSource, /advanced_shell_enabled !== false/);
    assert.match(settingsView, /settings\.advanced_shell_enabled === true \? 'selected' : ''/);
    assert.doesNotMatch(serverSource, /data_dir:\s*DATA_DIR/);
    assert.doesNotMatch(serverSource, /warnings:\s*RUNTIME\.warnings/);
    assert.match(serverSource, /autoRegisterEnabled\(\)/);
    assert.match(serverSource, /const needSyncKey = justRegistered\s*\|\| shouldBootstrapKey/);
    assert.match(serverSource, /portalRlCheck/);
    assert.match(serverSource, /Thông tin tra cứu không hợp lệ/);
    assert.doesNotMatch(serverSource, /const AUTO_REGISTER\s*=\s*true/);
    assert.doesNotMatch(serverSource, /KEY:\$\{entry\.license_key\}/);
    assert.match(serverSource, /csvSafeCell/);
    assert.match(serverSource, /sessionParser\(req, \{\}, \(\) =>/);
    assert.match(serverSource, /req\.session\?\.loggedIn/);
    const logoutGetLine = serverSource.split('\n').find(line => line.includes("app.get('/logout'")) || '';
    assert.doesNotMatch(logoutGetLine, /req\.session\.destroy/);
    assert.match(serverSource, /app\.post\('\/logout'/);
}

console.log('security tests passed');
