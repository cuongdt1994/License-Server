'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

function readView(view) {
    return fs.readFileSync(path.join(__dirname, '..', 'views', view), 'utf8');
}

const machines = readView('machines.ejs');
const partialPath = path.join(__dirname, '..', 'views', 'partials', 'flash-toast.ejs');

assert.ok(fs.existsSync(partialPath), 'flash toast partial should exist');

const partial = fs.readFileSync(partialPath, 'utf8');
const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

assert.match(machines, /include\('partials\/flash-toast'/);
assert.doesNotMatch(machines, /class="flash flash-/);

assert.match(partial, /class="flash-toast-stack"/);
assert.match(partial, /role="alert"/);
assert.match(partial, /data-autohide-ms="4000"/);
assert.match(partial, /aria-label="Đóng thông báo"/);
assert.match(partial, /setTimeout\([^]*4000/);
assert.match(partial, /beforeunload/);
assert.match(partial, /clearFlashToasts/);
assert.match(partial, /addEventListener\('submit'/);
assert.match(server, /consumeFlash\(req\.session\)/);
assert.match(server, /Cache-Control['"], ['"]no-store/);

console.log('ui flash tests passed');
