'use strict';
const fs = require('fs');
const path = require('path');
const appDir = __dirname;
const runtimeRoot =
    process.env.LICENSE_RUNTIME_ROOT ||
    path.join(appDir, '..', 'runtime');
const dataDir =
    process.env.LICENSE_DATA_DIR ||
    path.join(runtimeRoot, 'license-server-data');
const logDir =
    process.env.LICENSE_LOG_DIR ||
    path.join(runtimeRoot, 'logs');
fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(logDir, { recursive: true });
module.exports = {
    apps: [
        {
            name: 'license-server',
            cwd: appDir,
            script: './server.js',
            exec_mode: 'fork',
            instances: 1,
            autorestart: true,
            watch: false,
            max_memory_restart: '512M',
            restart_delay: 3000,
            exp_backoff_restart_delay: 100,
            kill_timeout: 12000,
            listen_timeout: 10000,
            merge_logs: true,
            time: true,
            out_file: path.join(logDir, 'license-server.out.log'),
            error_file: path.join(logDir, 'license-server.err.log'),
            env: {
                NODE_ENV: 'production',
                WEB_PORT: process.env.WEB_PORT || '5000',
                TCP_PORT: process.env.TCP_PORT || '27015',
                LICENSE_TLS_PORT:
                    process.env.LICENSE_TLS_PORT ||
                    process.env.TCP_PORT ||
                    '27015',
                LICENSE_BIND_HOST:
                    process.env.LICENSE_BIND_HOST ||
                    '0.0.0.0',
                LICENSE_DATA_DIR: dataDir,
                LICENSE_WEB_USER:
                    process.env.LICENSE_WEB_USER ||
                    'cuongdt',
                LICENSE_WEB_PASS:
                    process.env.LICENSE_WEB_PASS ||
                    'chemgiovn@123pP',
                LICENSE_SESSION_SECRET:
                    process.env.LICENSE_SESSION_SECRET ||
                    'Xhy_kdn_rvuU18tmOGrkJLGQ0WjrXncCIFpRO0ZbXx3v9GkJQYu9Gp9Qi2ntwql2',
                LICENSE_COOKIE_SECURE:
                    process.env.LICENSE_COOKIE_SECURE ||
                    '0',
                LICENSE_TCP_SECRET:
                    process.env.LICENSE_TCP_SECRET ||
                    '',
                STRICT_LICENSE_KEY:
                    process.env.STRICT_LICENSE_KEY ||
                    '0',
                LICENSE_TLS_KEY_FILE:
                    process.env.LICENSE_TLS_KEY_FILE ||
                    '/var/www/License-Server/certs/license-server.key',
                LICENSE_TLS_CERT_FILE:
                    process.env.LICENSE_TLS_CERT_FILE ||
                    '/var/www/License-Server/certs/license-server.crt',
                LICENSE_TLS_CA_FILE:
                    process.env.LICENSE_TLS_CA_FILE ||
                    '',
                LICENSE_TLS_MIN_VERSION:
                    process.env.LICENSE_TLS_MIN_VERSION ||
                    'TLSv1.2',
                LICENSE_TLS_HANDSHAKE_TIMEOUT_MS:
                    process.env.LICENSE_TLS_HANDSHAKE_TIMEOUT_MS ||
                    '5000',
                LICENSE_TLS_MTLS:
                    process.env.LICENSE_TLS_MTLS ||
                    '0',
            },
        },
    ],
};