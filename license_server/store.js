'use strict';

const { JsonStore } = require('./store_json');

function createStore(options = {}) {
    const requested = String(options.driver || process.env.LICENSE_DB_DRIVER || 'json').trim().toLowerCase();
    const fallbackToJson = options.fallbackToJson !== false && process.env.LICENSE_DB_SQLITE_STRICT !== '1';
    const log = typeof options.log === 'function'
        ? options.log
        : (level, msg) => console.log(`${level || 'INFO'} ${msg}`);

    if (requested === 'sqlite') {
        try {
            const { SqliteStore } = require('./store_sqlite');
            const store = new SqliteStore(options);
            store.init();
            log('INFO', `LICENSE_DB_DRIVER=sqlite active (${store.dbPath})`);
            return store;
        } catch (err) {
            const msg = `LICENSE_DB_DRIVER=sqlite unavailable: ${err.message}`;
            if (!fallbackToJson) throw new Error(`${msg}; set LICENSE_DB_SQLITE_STRICT=0 or install better-sqlite3.`);
            log('ERROR', `${msg}; falling back to JSON mode.`);
        }
    }

    const store = new JsonStore(options);
    store.init();
    log('INFO', 'LICENSE_DB_DRIVER=json active');
    return store;
}

module.exports = { createStore };
