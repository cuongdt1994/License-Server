'use strict';

const session = require('express-session');

class SqliteSessionStore extends session.Store {
    constructor({ store, ttlMs = 8 * 60 * 60 * 1000, cleanupIntervalMs = 15 * 60 * 1000 } = {}) {
        super();
        if (!store || store.driver !== 'sqlite') throw new Error('SqliteSessionStore requires an initialized SqliteStore.');
        this.store = store;
        this.ttlMs = ttlMs;
        this.cleanupTimer = setInterval(() => {
            try { this.store.cleanupExpiredWebSessions(Date.now()); } catch {}
        }, cleanupIntervalMs);
        this.cleanupTimer.unref?.();
    }

    get(sid, cb) {
        try { cb(null, this.store.getWebSession(String(sid)) || null); }
        catch (err) { cb(err); }
    }

    set(sid, sess, cb = () => {}) {
        try {
            this.store.setWebSession(String(sid), sess, this.expiresAt(sess));
            cb(null);
        } catch (err) { cb(err); }
    }

    touch(sid, sess, cb = () => {}) {
        this.set(sid, sess, cb);
    }

    destroy(sid, cb = () => {}) {
        try { this.store.deleteWebSession(String(sid)); cb(null); }
        catch (err) { cb(err); }
    }

    clear(cb = () => {}) {
        try { this.store.clearWebSessions(); cb(null); }
        catch (err) { cb(err); }
    }

    expiresAt(sess) {
        const cookie = sess && sess.cookie;
        if (cookie && cookie.expires) {
            const value = new Date(cookie.expires).getTime();
            if (Number.isFinite(value)) return value;
        }
        if (cookie && Number.isFinite(cookie.maxAge)) return Date.now() + cookie.maxAge;
        return Date.now() + this.ttlMs;
    }

    close() {
        if (this.cleanupTimer) clearInterval(this.cleanupTimer);
        this.cleanupTimer = null;
    }
}

module.exports = { SqliteSessionStore };
