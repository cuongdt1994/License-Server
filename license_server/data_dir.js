'use strict';

const fs   = require('fs');
const path = require('path');
const { isInside, safeResolve } = require('./safe_fs');

function ensurePrivateDir(dir) {
    const normalized = path.normalize(dir);
    fs.mkdirSync(normalized, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(normalized, 0o700); } catch {}
}

function readLocalDataDir(appDir) {
    const file = safeResolve(appDir, 'data_dir.local');
    if (!fs.existsSync(file)) return '';
    return fs.readFileSync(file, 'utf8').split(/\r?\n/)[0].trim();
}

function rememberDataDir(appDir, dir) {
    try {
        const file = safeResolve(appDir, 'data_dir.local');
        fs.writeFileSync(file, `${dir}\n`, { mode: 0o600 });
    } catch {}
}

function resolveDataDirInfo({ appDir = __dirname, env = process.env } = {}) {
    const envConfigured = (env.LICENSE_DATA_DIR || env.License_DATA_DIR || '').trim();
    const localConfigured = envConfigured ? '' : readLocalDataDir(appDir);
    const configured = envConfigured || localConfigured;
    const source = envConfigured
        ? (env.LICENSE_DATA_DIR ? 'env:LICENSE_DATA_DIR' : 'env:License_DATA_DIR')
        : (localConfigured ? 'data_dir.local' : 'default');

    if (!configured) {
        const fallback = safeResolve(appDir, 'data');
        ensurePrivateDir(fallback);
        return { dir: fallback, source };
    }

    if (!path.isAbsolute(configured)) {
        throw new Error('LICENSE_DATA_DIR must be an absolute path.');
    }

    // Block path traversal via .. segments
    if (configured.replace(/\\/g, '/').split('/').some(s => s === '..' || s === '...')) {
        throw new Error('LICENSE_DATA_DIR must not contain path traversal (..).');
    }

    const resolved = path.resolve(configured);
    const resolvedAppDir = path.resolve(appDir);
    if (isInside(resolved, resolvedAppDir)) {
        throw new Error('LICENSE_DATA_DIR must point outside license_server so rebuilds do not delete state.');
    }

    ensurePrivateDir(resolved);
    if (envConfigured) rememberDataDir(appDir, resolved);
    return { dir: resolved, source };
}

function resolveDataDir(opts = {}) {
    return resolveDataDirInfo(opts).dir;
}

module.exports = { resolveDataDir, resolveDataDirInfo, rememberDataDir, isInside, safeResolve };
