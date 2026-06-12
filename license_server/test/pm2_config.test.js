'use strict';

const assert = require('assert');
const pkg = require('../package.json');
const ecosystem = require('../ecosystem.config');

assert.ok(Array.isArray(ecosystem.apps), 'ecosystem exports apps array');
assert.equal(ecosystem.apps.length, 1);

const app = ecosystem.apps[0];
assert.equal(app.name, 'license-server');
assert.equal(app.script, './server.js');
assert.equal(app.cwd, __dirname.replace(/\\test$/, '').replace(/\/test$/, ''));
assert.equal(app.exec_mode, 'fork');
assert.equal(app.instances, 1);
assert.equal(app.max_memory_restart, '512M');
assert.equal(app.env.NODE_ENV, 'production');
assert.equal(app.env.WEB_PORT, '5000');
assert.equal(app.env.TCP_PORT, '27015');
assert.equal(app.env.LICENSE_BIND_HOST, '0.0.0.0');
assert.equal(app.env.LICENSE_COOKIE_SECURE, '0');
assert.ok(app.env.LICENSE_DATA_DIR.includes('license-server-data'));
assert.ok(app.error_file.includes('logs'));
assert.ok(app.out_file.includes('logs'));
assert.ok(app.merge_logs);
assert.ok(app.kill_timeout >= 10000);

for (const script of ['pm2:start', 'pm2:restart', 'pm2:stop', 'pm2:logs', 'pm2:save']) {
    assert.ok(pkg.scripts[script], `${script} script exists`);
}

console.log('pm2 config tests passed');
