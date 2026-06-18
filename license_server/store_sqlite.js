'use strict';

const fs = require('fs');
const path = require('path');

let BetterSqlite3;
try {
    BetterSqlite3 = require('better-sqlite3');
} catch (err) {
    throw new Error('better-sqlite3 package is not installed');
}

function readJsonIfExists(file, fallback) {
    if (!fs.existsSync(file)) return fallback;
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

function toJson(value) { return JSON.stringify(value === undefined ? null : value); }
function fromJson(value, fallback) { try { return JSON.parse(value); } catch { return fallback; } }

class SqliteStore {
    constructor(options = {}) {
        this.driver = 'sqlite';
        this.dataDir = options.dataDir || process.cwd();
        this.dbPath = options.dbPath || path.join(this.dataDir, 'license.sqlite3');
        this.log = typeof options.log === 'function' ? options.log : () => {};
        this.saveTotal = 0;
        this.saveFailTotal = 0;
        this.db = null;
    }

    init() {
        fs.mkdirSync(this.dataDir, { recursive: true });
        this.db = new BetterSqlite3(this.dbPath);
        this.db.pragma('journal_mode = WAL');
        this.db.pragma('synchronous = NORMAL');
        this.db.exec(`
CREATE TABLE IF NOT EXISTS machines(
  mid TEXT PRIMARY KEY,
  data_json TEXT NOT NULL,
  updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS plans(
  id TEXT PRIMARY KEY,
  data_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bans(
  range TEXT PRIMARY KEY,
  data_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS stats(
  mid TEXT NOT NULL,
  ts INTEGER NOT NULL,
  players INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS history(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_ms INTEGER NOT NULL,
  mid TEXT,
  event TEXT,
  ip TEXT,
  data_json TEXT
);
CREATE TABLE IF NOT EXISTS sessions(
  session_id TEXT PRIMARY KEY,
  mid TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  ip TEXT,
  created_at INTEGER,
  expires_at INTEGER,
  last_seen INTEGER,
  data_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_stats_mid_ts ON stats(mid, ts);
CREATE INDEX IF NOT EXISTS idx_history_ts_ms ON history(ts_ms);
CREATE INDEX IF NOT EXISTS idx_sessions_mid ON sessions(mid);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
`);
        this._migrateJsonOnce();
    }

    _tableEmpty(table) {
        return this.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n === 0;
    }

    _migrateJsonOnce() {
        const marker = path.join(this.dataDir, '.sqlite_import_done');
        if (fs.existsSync(marker)) return;
        let importedMachines = 0;
        const dbJson = readJsonIfExists(path.join(this.dataDir, 'whitelist.json'), {});
        if (dbJson && typeof dbJson === 'object' && this._tableEmpty('machines')) {
            const stmt = this.db.prepare('INSERT OR REPLACE INTO machines(mid, data_json, updated_at) VALUES(?, ?, ?)');
            const tx = this.db.transaction((rows) => {
                for (const [mid, entry] of Object.entries(rows)) {
                    stmt.run(mid, toJson(entry), Date.now());
                    importedMachines++;
                }
            });
            tx(dbJson);
        }
        const settings = readJsonIfExists(path.join(this.dataDir, 'settings.json'), {});
        if (settings && typeof settings === 'object' && this._tableEmpty('settings')) this.saveSettings(settings);
        const plans = readJsonIfExists(path.join(this.dataDir, 'plans.json'), []);
        if (Array.isArray(plans) && plans.length && this._tableEmpty('plans')) this.savePlans(plans);
        const bans = readJsonIfExists(path.join(this.dataDir, 'bans.json'), {});
        if (bans && typeof bans === 'object' && this._tableEmpty('bans')) this.saveBans(bans);
        const stats = readJsonIfExists(path.join(this.dataDir, 'stats.json'), {});
        if (stats && typeof stats === 'object' && this._tableEmpty('stats')) {
            const stmt = this.db.prepare('INSERT INTO stats(mid, ts, players) VALUES(?, ?, ?)');
            const tx = this.db.transaction((all) => {
                for (const [mid, rows] of Object.entries(all)) {
                    if (!Array.isArray(rows)) continue;
                    for (const row of rows) if (Array.isArray(row) && row.length >= 2) stmt.run(mid, Number(row[0]) || Date.now(), Number(row[1]) || 0);
                }
            });
            tx(stats);
        }
        const history = readJsonIfExists(path.join(this.dataDir, 'history.json'), []);
        if (Array.isArray(history) && history.length && this._tableEmpty('history')) {
            const stmt = this.db.prepare('INSERT INTO history(ts_ms, mid, event, ip, data_json) VALUES(?, ?, ?, ?, ?)');
            const tx = this.db.transaction((rows) => {
                for (const item of rows) stmt.run(Number(item.ts_ms) || Date.now(), item.mid || null, item.event || null, item.ip || null, toJson(item));
            });
            tx(history);
        }
        fs.writeFileSync(marker, `${Date.now()}\n`, { mode: 0o600 });
        this.log('INFO', `SQLITE MIGRATION imported machines=${importedMachines}`);
    }

    loadDB() {
        const rows = this.db.prepare('SELECT mid, data_json FROM machines').all();
        const out = {};
        for (const row of rows) out[row.mid] = fromJson(row.data_json, {});
        return out;
    }
    saveDB(db) {
        try {
            const del = this.db.prepare('DELETE FROM machines');
            const ins = this.db.prepare('INSERT INTO machines(mid, data_json, updated_at) VALUES(?, ?, ?)');
            const tx = this.db.transaction((data) => {
                del.run();
                const ts = Date.now();
                for (const [mid, entry] of Object.entries(data || {})) ins.run(mid, toJson(entry), ts);
            });
            tx(db || {});
            this.saveTotal++;
        } catch (err) { this.saveFailTotal++; throw err; }
    }
    loadSettings() {
        const rows = this.db.prepare('SELECT key, value_json FROM settings').all();
        const out = {};
        for (const row of rows) out[row.key] = fromJson(row.value_json, null);
        return out;
    }
    saveSettings(settings) {
        try {
            const del = this.db.prepare('DELETE FROM settings');
            const ins = this.db.prepare('INSERT INTO settings(key, value_json) VALUES(?, ?)');
            const tx = this.db.transaction((data) => { del.run(); for (const [k, v] of Object.entries(data || {})) ins.run(k, toJson(v)); });
            tx(settings || {}); this.saveTotal++;
        } catch (err) { this.saveFailTotal++; throw err; }
    }
    loadPlans() {
        return this.db.prepare('SELECT data_json FROM plans ORDER BY id').all().map(r => fromJson(r.data_json, {}));
    }
    savePlans(plans) {
        try {
            const del = this.db.prepare('DELETE FROM plans');
            const ins = this.db.prepare('INSERT INTO plans(id, data_json) VALUES(?, ?)');
            const tx = this.db.transaction((rows) => { del.run(); (Array.isArray(rows) ? rows : []).forEach((p, i) => ins.run(String(p.id || `plan_${i}`), toJson(p))); });
            tx(plans); this.saveTotal++;
        } catch (err) { this.saveFailTotal++; throw err; }
    }
    loadBans() {
        const rows = this.db.prepare('SELECT range, data_json FROM bans').all();
        const out = {};
        for (const row of rows) out[row.range] = fromJson(row.data_json, {});
        return out;
    }
    saveBans(bans) {
        try {
            const del = this.db.prepare('DELETE FROM bans');
            const ins = this.db.prepare('INSERT INTO bans(range, data_json) VALUES(?, ?)');
            const tx = this.db.transaction((data) => { del.run(); for (const [range, info] of Object.entries(data || {})) ins.run(range, toJson(info)); });
            tx(bans || {}); this.saveTotal++;
        } catch (err) { this.saveFailTotal++; throw err; }
    }
    loadStats() {
        const rows = this.db.prepare('SELECT mid, ts, players FROM stats ORDER BY ts').all();
        const out = {};
        for (const row of rows) {
            if (!Array.isArray(out[row.mid])) out[row.mid] = [];
            out[row.mid].push([row.ts, row.players]);
        }
        return out;
    }
    saveStats(stats) {
        try {
            const del = this.db.prepare('DELETE FROM stats');
            const ins = this.db.prepare('INSERT INTO stats(mid, ts, players) VALUES(?, ?, ?)');
            const tx = this.db.transaction((all) => {
                del.run();
                for (const [mid, rows] of Object.entries(all || {})) {
                    if (!Array.isArray(rows)) continue;
                    for (const row of rows) if (Array.isArray(row) && row.length >= 2) ins.run(mid, Number(row[0]) || Date.now(), Number(row[1]) || 0);
                }
            });
            tx(stats || {}); this.saveTotal++;
        } catch (err) { this.saveFailTotal++; throw err; }
    }
    pushStat(mid, players) {
        this.db.prepare('INSERT INTO stats(mid, ts, players) VALUES(?, ?, ?)').run(mid, Date.now(), Math.max(0, Number.parseInt(players, 10) || 0));
    }
    loadHistory() {
        return this.db.prepare('SELECT data_json FROM history ORDER BY ts_ms DESC LIMIT 1000').all().reverse().map(r => fromJson(r.data_json, {}));
    }
    saveHistory(history) {
        try {
            const del = this.db.prepare('DELETE FROM history');
            const ins = this.db.prepare('INSERT INTO history(ts_ms, mid, event, ip, data_json) VALUES(?, ?, ?, ?, ?)');
            const tx = this.db.transaction((rows) => { del.run(); (Array.isArray(rows) ? rows : []).forEach(item => ins.run(Number(item.ts_ms) || Date.now(), item.mid || null, item.event || null, item.ip || null, toJson(item))); });
            tx(history); this.saveTotal++;
        } catch (err) { this.saveFailTotal++; throw err; }
    }
    pushHistory(entry) {
        const item = entry || {};
        this.db.prepare('INSERT INTO history(ts_ms, mid, event, ip, data_json) VALUES(?, ?, ?, ?, ?)')
            .run(Number(item.ts_ms) || Date.now(), item.mid || null, item.event || null, item.ip || null, toJson(item));
    }
    health() {
        return {
            driver: 'sqlite',
            db_path: this.dbPath,
            saves_total: this.saveTotal,
            save_fail_total: this.saveFailTotal,
        };
    }
}

module.exports = { SqliteStore };
