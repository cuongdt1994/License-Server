'use strict';

// ═══════════════════════════════════════════════════════════════════════════════
// DEPRECATED — This module is no longer used by server.js.
//
// Server.js now reads secrets directly from environment variables:
//   - LICENSE_SESSION_SECRET (required, ≥48 bytes)
//   - LICENSE_TCP_SECRET     (optional, else embedded client-sync key is used)
//
// TLS credentials are also read from env vars:
//   - LICENSE_TLS_KEY_FILE, LICENSE_TLS_CERT_FILE, LICENSE_TLS_CA_FILE
//
// This file is kept for reference and backward compatibility only.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DEFAULT_TCP_SECRET = 'KhongCogiSecret2024!@#$%^&*()_+=';

function readJson(file) {
    const safeFile = path.normalize(file);
    if (!fs.existsSync(safeFile)) return {};
    try { return JSON.parse(fs.readFileSync(safeFile, 'utf8')); } catch { return {}; }
}

function writeJsonPrivate(file, data) {
    fs.writeFileSync(path.normalize(file), JSON.stringify(data, null, 2), { mode: 0o600 });
}

function validateTcpSecret(secret) {
    if (Buffer.byteLength(secret, 'utf8') !== 32) {
        throw new Error('LICENSE_TCP_SECRET must be exactly 32 UTF-8 bytes.');
    }
}

function ensureRuntimeSecrets({ dataDir, env = process.env } = {}) {
    const file = path.join(dataDir, 'runtime_secrets.json');
    const saved = readJson(file);
    let changed = false;

    const envSession = String(env.LICENSE_SESSION_SECRET || '').trim();
    const envTcp = String(env.LICENSE_TCP_SECRET || '').trim();
    if (envTcp) validateTcpSecret(envTcp);

    if (!saved.session_secret) {
        saved.session_secret = crypto.randomBytes(32).toString('base64url');
        changed = true;
    }
    if (!saved.tcp_secret) {
        saved.tcp_secret = DEFAULT_TCP_SECRET;
        changed = true;
    }
    validateTcpSecret(saved.tcp_secret);
    if (changed) writeJsonPrivate(file, saved);

    return {
        sessionSecret: envSession || saved.session_secret,
        tcpSecret: envTcp || saved.tcp_secret,
        file,
        sources: {
            session: envSession ? 'env:LICENSE_SESSION_SECRET' : 'runtime_secrets.json',
            tcp: envTcp ? 'env:LICENSE_TCP_SECRET' : 'runtime_secrets.json',
        },
    };
}

module.exports = { ensureRuntimeSecrets, validateTcpSecret };
