'use strict';

function parsePort(env, name, fallback) {
    const raw = (env[name] || '').toString().trim();
    if (!raw) return fallback;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
        throw new Error(`${name} must be a number between 1 and 65535.`);
    }
    return n;
}

function buildRuntimeConfig({ env = process.env } = {}) {
    const warnings = [];
    const sessionSecret = (env.LICENSE_SESSION_SECRET || '').trim();
    const tcpSecret = (env.LICENSE_TCP_SECRET || '').trim();
    const dataDir = (env.LICENSE_DATA_DIR || env.License_DATA_DIR || '').trim();

    if (!sessionSecret) {
        warnings.push('LICENSE_SESSION_SECRET is not set; sessions will rotate on restart.');
    } else if (sessionSecret.length < 32) {
        warnings.push('LICENSE_SESSION_SECRET should be at least 32 characters.');
    }
    if (!dataDir) {
        warnings.push('LICENSE_DATA_DIR is not set; runtime data may live inside the app directory.');
    }
    if (tcpSecret && Buffer.byteLength(tcpSecret, 'utf8') !== 32) {
        throw new Error('LICENSE_TCP_SECRET must be exactly 32 UTF-8 bytes.');
    }
    if (!tcpSecret) {
        warnings.push('LICENSE_TCP_SECRET is not set; built-in TCP secret is only for compatibility.');
    }

    const cookieSecureRaw = (env.LICENSE_COOKIE_SECURE || '').trim().toLowerCase();
    const cookieSecure = ['1', 'true', 'yes', 'on'].includes(cookieSecureRaw);

    return {
        webPort: parsePort(env, 'WEB_PORT', 5000),
        tcpPort: parsePort(env, 'TCP_PORT', 27015),
        bindHost: (env.LICENSE_BIND_HOST || '0.0.0.0').trim() || '0.0.0.0',
        nodeEnv: env.NODE_ENV || 'development',
        cookieSecure,
        tcpSecret: tcpSecret || 'KhongCogiSecret2024!@#$%^&*()_+=',
        tcpSecretSource: tcpSecret ? 'env:LICENSE_TCP_SECRET' : 'built-in compatibility default',
        dataDir,
        warnings,
        pm2: {
            enabled: !!(env.pm_id || env.PM2_HOME),
            id: env.pm_id || null,
            name: env.name || env.pm2_name || null,
            home: env.PM2_HOME || null,
            instance: env.NODE_APP_INSTANCE || null,
        },
    };
}

module.exports = { buildRuntimeConfig };
