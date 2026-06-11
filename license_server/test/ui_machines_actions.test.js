'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const machines = fs.readFileSync(path.join(__dirname, '..', 'views', 'machines.ejs'), 'utf8');

assert.doesNotMatch(machines, /onclick="openRenew/);
assert.doesNotMatch(machines, /onclick="openKey/);
assert.doesNotMatch(machines, /onclick="openTransfer/);

assert.match(machines, /data-machine-action="renew"/);
assert.match(machines, /data-machine-action="key"/);
assert.match(machines, /data-machine-action="transfer"/);
assert.match(machines, /addEventListener\('click'/);
assert.match(machines, /closest\('\[data-machine-action\]'\)/);

console.log('ui machine actions tests passed');
