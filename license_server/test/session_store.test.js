'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { FileSessionStore } = require('../session_store');

function tmp() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'license-session-store-'));
}

function call(fn) {
    return new Promise((resolve, reject) => {
        fn((err, value) => err ? reject(err) : resolve(value));
    });
}

(async () => {
    const dir = tmp();
    const store = new FileSessionStore({ dir, ttlMs: 60 * 60 * 1000 });

    await call(cb => store.set('sid-1', { user: 'admin', cookie: { maxAge: 1000 } }, cb));
    const loaded = await call(cb => store.get('sid-1', cb));
    assert.equal(loaded.user, 'admin');
    assert.ok(fs.existsSync(path.join(dir, 'sid-1.json')));

    await call(cb => store.touch('sid-1', { user: 'admin', touched: true, cookie: { maxAge: 2000 } }, cb));
    const touched = await call(cb => store.get('sid-1', cb));
    assert.equal(touched.touched, true);

    await call(cb => store.destroy('sid-1', cb));
    const missing = await call(cb => store.get('sid-1', cb));
    assert.equal(missing, null);

    const oldStore = new FileSessionStore({ dir, ttlMs: 1 });
    await call(cb => oldStore.set('sid-old', { user: 'old' }, cb));
    await new Promise(resolve => setTimeout(resolve, 5));
    oldStore.cleanupExpired();
    assert.equal(fs.existsSync(path.join(dir, 'sid-old.json')), false);

    console.log('session store tests passed');
})().catch(err => {
    console.error(err);
    process.exit(1);
});
