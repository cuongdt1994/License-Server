'use strict';

const fs = require('fs');
const path = require('path');
const session = require('express-session');

function safeId(sid) {
    return String(sid || '').replace(/[^a-zA-Z0-9_-]/g, '_');
}

class FileSessionStore extends session.Store {
    constructor({ dir, ttlMs = 8 * 60 * 60 * 1000, cleanupIntervalMs = 15 * 60 * 1000 } = {}) {
        super();
        if (!dir) throw new Error('FileSessionStore requires dir.');
        this.dir = dir;
        this.ttlMs = ttlMs;
        fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
        try { fs.chmodSync(this.dir, 0o700); } catch {}
        this.cleanupTimer = setInterval(() => this.cleanupExpired(), cleanupIntervalMs);
        this.cleanupTimer.unref?.();
    }

    fileFor(sid) {
        return path.join(this.dir, `${safeId(sid)}.json`);
    }

    get(sid, cb) {
        const file = this.fileFor(sid);
        fs.readFile(file, 'utf8', (err, raw) => {
            if (err) return cb(err.code === 'ENOENT' ? null : err, null);
            try {
                const row = JSON.parse(raw);
                if (row.expiresAt && row.expiresAt < Date.now()) {
                    fs.unlink(file, () => {});
                    return cb(null, null);
                }
                cb(null, row.session || null);
            } catch (e) {
                cb(e, null);
            }
        });
    }

    set(sid, sess, cb = () => {}) {
        const expiresAt = this.expiresAt(sess);
        const row = { expiresAt, session: sess };
        fs.writeFile(this.fileFor(sid), JSON.stringify(row), { mode: 0o600 }, cb);
    }

    touch(sid, sess, cb = () => {}) {
        this.set(sid, sess, cb);
    }

    destroy(sid, cb = () => {}) {
        fs.unlink(this.fileFor(sid), err => cb(err && err.code !== 'ENOENT' ? err : null));
    }

    expiresAt(sess) {
        const cookie = sess && sess.cookie;
        if (cookie && cookie.expires) {
            const t = new Date(cookie.expires).getTime();
            if (Number.isFinite(t)) return t;
        }
        if (cookie && Number.isFinite(cookie.maxAge)) return Date.now() + cookie.maxAge;
        return Date.now() + this.ttlMs;
    }

    cleanupExpired() {
        const now = Date.now();
        for (const name of fs.readdirSync(this.dir)) {
            if (!name.endsWith('.json')) continue;
            const file = path.join(this.dir, name);
            try {
                const row = JSON.parse(fs.readFileSync(file, 'utf8'));
                if (row.expiresAt && row.expiresAt < now) fs.unlinkSync(file);
            } catch {
                try { fs.unlinkSync(file); } catch {}
            }
        }
    }
}

module.exports = { FileSessionStore };
