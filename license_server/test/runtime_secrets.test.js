'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ensureRuntimeSecrets } = require('../runtime_secrets');

function tmp() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'license-runtime-secrets-'));
}

{
    const dataDir = tmp();
    const first = ensureRuntimeSecrets({ dataDir, env: {} });
    const second = ensureRuntimeSecrets({ dataDir, env: {} });
    const file = path.join(dataDir, 'runtime_secrets.json');
    const saved = JSON.parse(fs.readFileSync(file, 'utf8'));

    assert.equal(first.sessionSecret.length >= 32, true);
    assert.equal(Buffer.byteLength(first.tcpSecret, 'utf8'), 32);
    assert.equal(first.sessionSecret, second.sessionSecret);
    assert.equal(first.tcpSecret, second.tcpSecret);
    assert.equal(saved.session_secret, first.sessionSecret);
    assert.equal(saved.tcp_secret, first.tcpSecret);
    assert.equal(first.sources.session, 'runtime_secrets.json');
    assert.equal(first.sources.tcp, 'runtime_secrets.json');
}

{
    const dataDir = tmp();
    const env = {
        LICENSE_SESSION_SECRET: 'session-secret-from-env-at-least-32',
        LICENSE_TCP_SECRET: '12345678901234567890123456789012',
    };
    const secrets = ensureRuntimeSecrets({ dataDir, env });
    assert.equal(secrets.sessionSecret, env.LICENSE_SESSION_SECRET);
    assert.equal(secrets.tcpSecret, env.LICENSE_TCP_SECRET);
    assert.equal(secrets.sources.session, 'env:LICENSE_SESSION_SECRET');
    assert.equal(secrets.sources.tcp, 'env:LICENSE_TCP_SECRET');
}

{
    assert.throws(
        () => ensureRuntimeSecrets({ dataDir: tmp(), env: { LICENSE_TCP_SECRET: 'short' } }),
        /LICENSE_TCP_SECRET must be exactly 32 UTF-8 bytes/
    );
}

console.log('runtime secrets tests passed');
