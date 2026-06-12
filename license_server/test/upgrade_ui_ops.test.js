'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const server = fs.readFileSync(path.join(root, 'server.js'), 'utf8');
const machines = fs.readFileSync(path.join(root, 'views', 'machines.ejs'), 'utf8');
const operationsPath = path.join(root, 'views', 'operations.ejs');

assert.ok(!pkg.dependencies['node-cron'], 'node-cron should be removed after replacing simple schedules');
assert.doesNotMatch(server, /require\('node-cron'\)/);
assert.match(server, /scheduleDailyTask/);
assert.match(server, /app\.get\('\/operations'/);
assert.match(server, /app\.post\('\/operations\/update'/);
assert.match(server, /deployManager\.runUpdate/);

assert.ok(fs.existsSync(operationsPath), 'operations view exists');
const operations = fs.readFileSync(operationsPath, 'utf8');
assert.match(operations, /Trung tâm vận hành/);
assert.match(operations, /runtime\.pm2/);
assert.match(operations, /processInfo\.uptime/);
assert.match(operations, /backupInfo\.count/);
assert.match(operations, /\/health/);
assert.match(operations, /Cập nhật từ Git/);
assert.match(operations, /deployStatus/);
assert.match(operations, /\/operations\/update/);

assert.match(machines, /id="machineSearch"/);
assert.match(machines, /data-machine-row/);
assert.match(machines, /data-filter-status/);
assert.match(machines, /applyMachineFilters/);
assert.match(machines, /machineVisibleCount/);

console.log('upgrade ui ops tests passed');
