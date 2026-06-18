'use strict';

const { SqliteStore } = require('./store_sqlite');

function createStore(options = {}) {
    const requested = String(options.driver || process.env.LICENSE_DB_DRIVER || 'sqlite').trim().toLowerCase();
    if (requested !== 'sqlite') {
        throw new Error(`Only SQLite is supported; LICENSE_DB_DRIVER=${requested} is invalid.`);
    }
    const store = new SqliteStore(options);
    store.init();
    const health = store.health();
    if (!health.ok) throw new Error(`SQLite startup check failed: journal=${health.journal_mode}, quick_check=${health.quick_check}`);
    const log = typeof options.log === 'function' ? options.log : () => {};
    log('INFO', `SQLite active (${store.dbPath}) journal=${health.journal_mode}`);
    return store;
}

module.exports = { createStore };
