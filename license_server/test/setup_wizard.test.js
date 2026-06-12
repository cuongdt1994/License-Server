'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const setup = fs.readFileSync(path.join(__dirname, '..', 'views', 'setup.ejs'), 'utf8');

assert.match(server, /let setupRequired/);
assert.match(server, /app\.get\('\/setup'/);
assert.match(server, /app\.post\('\/setup'/);
assert.match(server, /saveInitialSetup/);
assert.doesNotMatch(server, /Generated initial admin credentials/);

assert.match(setup, /Thiết lập lần đầu/);
assert.match(setup, /name="data_dir"/);
assert.match(setup, /name="username"/);
assert.match(setup, /name="password"/);
assert.match(setup, /name="confirm_password"/);

console.log('setup wizard tests passed');
