'use strict';

const fs = require('fs');
const path = require('path');
const BetterSqlite3 = require('better-sqlite3');

function toJson(value) {
    return JSON.stringify(value === undefined ? null : value);
}

function fromJson(value, fallback) {
    try { return JSON.parse(value); } catch { return fallback; }
}

function readLegacyJson(file, fallback) {
    if (!fs.existsSync(file)) return fallback;
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

function safeStatSize(file) {
    try { return fs.statSync(file).size; } catch { return 0; }
}

const HISTORY_LIMIT_DEPLOY = 20;

class SqliteStore {
    constructor(options = {}) {
        this.driver = 'sqlite';
        this.dataDir = options.dataDir || process.cwd();
        this.dbPath = options.dbPath || path.join(this.dataDir, 'license.sqlite3');
        this.log = typeof options.log === 'function' ? options.log : () => {};
        this.saveTotal = 0;
        this.saveFailTotal = 0;
        this.lastBackupAt = 0;
        this.lastBackupFile = '';
        this.db = null;
        this.stmt = Object.create(null);
    }

    init() {
        fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
        try { fs.chmodSync(this.dataDir, 0o700); } catch {}

        this.db = new BetterSqlite3(this.dbPath, {
            timeout: Number.parseInt(process.env.LICENSE_SQLITE_BUSY_TIMEOUT_MS || '5000', 10),
        });
        try { fs.chmodSync(this.dbPath, 0o600); } catch {}

        this.db.pragma('journal_mode = WAL');
        this.db.pragma(`synchronous = ${String(process.env.LICENSE_SQLITE_SYNCHRONOUS || 'NORMAL').toUpperCase()}`);
        this.db.pragma('foreign_keys = ON');
        this.db.pragma('busy_timeout = 5000');
        this.db.pragma('temp_store = MEMORY');
        this.db.pragma('wal_autocheckpoint = 1000');

        this.db.exec(`
CREATE TABLE IF NOT EXISTS schema_migrations(
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL,
  description TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS machines(
  mid TEXT PRIMARY KEY,
  data_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS plans(
  id TEXT PRIMARY KEY,
  sort_order INTEGER NOT NULL,
  data_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bans(
  range TEXT PRIMARY KEY,
  data_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS stats(
  mid TEXT NOT NULL,
  ts INTEGER NOT NULL,
  players INTEGER NOT NULL,
  PRIMARY KEY(mid, ts)
);
CREATE TABLE IF NOT EXISTS history(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_ms INTEGER NOT NULL,
  mid TEXT,
  event TEXT,
  ip TEXT,
  data_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS license_sessions(
  session_id TEXT PRIMARY KEY,
  mid TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  ip TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  data_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS web_sessions(
  sid TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL,
  data_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_credentials(
  id INTEGER PRIMARY KEY CHECK(id = 1),
  data_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_tokens(
  mid TEXT PRIMARY KEY,
  token TEXT NOT NULL,
  created TEXT NOT NULL,
  rotated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_state(
  mid TEXT PRIMARY KEY,
  last_seen INTEGER,
  agent_ip TEXT,
  agent_ver TEXT,
  server_dir TEXT NOT NULL DEFAULT 'pwserver',
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS deploy_history(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_stats_ts ON stats(ts);
CREATE INDEX IF NOT EXISTS idx_history_ts_ms ON history(ts_ms);
CREATE INDEX IF NOT EXISTS idx_license_sessions_mid ON license_sessions(mid);
CREATE INDEX IF NOT EXISTS idx_license_sessions_expires ON license_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_web_sessions_expires ON web_sessions(expires_at);
`);

        this._upgradeLegacySqliteSchema();
        this._prepare();
        this._migrateLegacyJson();
        const quick = this.quickCheck();
        if (!quick.ok) throw new Error(`SQLite quick_check failed: ${quick.result}`);
        return this;
    }

    _upgradeLegacySqliteSchema() {
        const planColumns = this.db.pragma('table_info(plans)').map(row => row.name);
        if (planColumns.length && !planColumns.includes('sort_order')) {
            this.db.exec('ALTER TABLE plans ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0');
        }

        const legacySessions = this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'").get();
        if (legacySessions) {
            const targetCount = this.db.prepare('SELECT COUNT(*) AS n FROM license_sessions').get().n;
            if (targetCount === 0) {
                const rows = this.db.prepare('SELECT session_id,mid,token_hash,ip,created_at,expires_at,last_seen,data_json FROM sessions WHERE expires_at>?').all(Date.now());
                const insert = this.db.prepare(`INSERT OR REPLACE INTO license_sessions(session_id,mid,token_hash,ip,created_at,expires_at,last_seen,data_json)
                    VALUES(?,?,?,?,?,?,?,?)`);
                this.db.transaction(() => {
                    for (const row of rows) {
                        let data = fromJson(row.data_json, {});
                        data = { ...data, session_id: row.session_id, mid: row.mid, token_hash: row.token_hash, ip: row.ip,
                            created_at: row.created_at, expires_at: row.expires_at, last_seen: row.last_seen };
                        insert.run(row.session_id, row.mid, row.token_hash, row.ip, row.created_at || Date.now(), row.expires_at, row.last_seen || Date.now(), toJson(data));
                    }
                })();
            }
        }
    }

    _prepare() {
        const p = (sql) => this.db.prepare(sql);
        this.stmt.machineAll = p('SELECT mid, data_json FROM machines');
        this.stmt.machineUpsert = p('INSERT INTO machines(mid,data_json,updated_at) VALUES(?,?,?) ON CONFLICT(mid) DO UPDATE SET data_json=excluded.data_json, updated_at=excluded.updated_at');
        this.stmt.machineKeys = p('SELECT mid FROM machines');
        this.stmt.machineDelete = p('DELETE FROM machines WHERE mid=?');

        this.stmt.settingsAll = p('SELECT key,value_json FROM settings');
        this.stmt.settingUpsert = p('INSERT INTO settings(key,value_json) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json');
        this.stmt.settingKeys = p('SELECT key FROM settings');
        this.stmt.settingDelete = p('DELETE FROM settings WHERE key=?');

        this.stmt.plansAll = p('SELECT data_json FROM plans ORDER BY sort_order,id');
        this.stmt.planUpsert = p('INSERT INTO plans(id,sort_order,data_json) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET sort_order=excluded.sort_order,data_json=excluded.data_json');
        this.stmt.planKeys = p('SELECT id FROM plans');
        this.stmt.planDelete = p('DELETE FROM plans WHERE id=?');

        this.stmt.bansAll = p('SELECT range,data_json FROM bans');
        this.stmt.banUpsert = p('INSERT INTO bans(range,data_json) VALUES(?,?) ON CONFLICT(range) DO UPDATE SET data_json=excluded.data_json');
        this.stmt.banKeys = p('SELECT range FROM bans');
        this.stmt.banDelete = p('DELETE FROM bans WHERE range=?');

        this.stmt.statInsert = p('INSERT OR REPLACE INTO stats(mid,ts,players) VALUES(?,?,?)');
        this.stmt.statsAll = p('SELECT mid,ts,players FROM stats ORDER BY ts');
        this.stmt.statsDeleteAll = p('DELETE FROM stats');
        this.stmt.statsPruneAge = p('DELETE FROM stats WHERE ts < ?');
        this.stmt.statsPrunePerMid = p(`DELETE FROM stats WHERE rowid IN (
            SELECT rowid FROM stats WHERE mid=? ORDER BY ts DESC LIMIT -1 OFFSET ?
        )`);

        this.stmt.historyInsert = p('INSERT INTO history(ts_ms,mid,event,ip,data_json) VALUES(?,?,?,?,?)');
        this.stmt.historyAll = p('SELECT data_json FROM history ORDER BY ts_ms DESC LIMIT ?');
        this.stmt.historyDeleteAll = p('DELETE FROM history');
        this.stmt.historyPruneAge = p('DELETE FROM history WHERE ts_ms < ?');
        this.stmt.historyPruneCount = p('DELETE FROM history WHERE id NOT IN (SELECT id FROM history ORDER BY ts_ms DESC LIMIT ?)');

        this.stmt.licenseSessionUpsert = p(`INSERT INTO license_sessions(session_id,mid,token_hash,ip,created_at,expires_at,last_seen,data_json)
            VALUES(@session_id,@mid,@token_hash,@ip,@created_at,@expires_at,@last_seen,@data_json)
            ON CONFLICT(session_id) DO UPDATE SET mid=excluded.mid,token_hash=excluded.token_hash,ip=excluded.ip,created_at=excluded.created_at,expires_at=excluded.expires_at,last_seen=excluded.last_seen,data_json=excluded.data_json`);
        this.stmt.licenseSessionGet = p('SELECT data_json FROM license_sessions WHERE session_id=?');
        this.stmt.licenseSessionActive = p('SELECT data_json FROM license_sessions WHERE expires_at>?');
        this.stmt.licenseSessionDelete = p('DELETE FROM license_sessions WHERE session_id=?');
        this.stmt.licenseSessionDeleteMid = p('DELETE FROM license_sessions WHERE mid=?');
        this.stmt.licenseSessionDeleteExpired = p('DELETE FROM license_sessions WHERE expires_at<=?');

        this.stmt.webSessionGet = p('SELECT data_json,expires_at FROM web_sessions WHERE sid=?');
        this.stmt.webSessionUpsert = p(`INSERT INTO web_sessions(sid,expires_at,data_json,updated_at) VALUES(?,?,?,?)
            ON CONFLICT(sid) DO UPDATE SET expires_at=excluded.expires_at,data_json=excluded.data_json,updated_at=excluded.updated_at`);
        this.stmt.webSessionDelete = p('DELETE FROM web_sessions WHERE sid=?');
        this.stmt.webSessionDeleteExpired = p('DELETE FROM web_sessions WHERE expires_at<=?');
        this.stmt.webSessionClear = p('DELETE FROM web_sessions');

        this.stmt.adminGet = p('SELECT data_json FROM admin_credentials WHERE id=1');
        this.stmt.adminSet = p(`INSERT INTO admin_credentials(id,data_json,updated_at) VALUES(1,?,?)
            ON CONFLICT(id) DO UPDATE SET data_json=excluded.data_json,updated_at=excluded.updated_at`);

        this.stmt.agentTokenGet = p('SELECT token,created,rotated_at FROM agent_tokens WHERE mid=?');
        this.stmt.agentTokenUpsert = p(`INSERT INTO agent_tokens(mid,token,created,rotated_at) VALUES(?,?,?,?)
            ON CONFLICT(mid) DO UPDATE SET token=excluded.token,rotated_at=excluded.rotated_at`);
        this.stmt.agentTokenDelete = p('DELETE FROM agent_tokens WHERE mid=?');
        this.stmt.agentTokenAll = p('SELECT mid,token,created,rotated_at FROM agent_tokens');

        this.stmt.agentStateUpsert = p(`INSERT INTO agent_state(mid,last_seen,agent_ip,agent_ver,server_dir,updated_at) VALUES(?,?,?,?,?,?)
            ON CONFLICT(mid) DO UPDATE SET last_seen=excluded.last_seen,agent_ip=excluded.agent_ip,agent_ver=excluded.agent_ver,server_dir=excluded.server_dir,updated_at=excluded.updated_at`);
        this.stmt.agentStateGet = p('SELECT last_seen,agent_ip,agent_ver,server_dir FROM agent_state WHERE mid=?');
        this.stmt.agentStateAll = p('SELECT mid,last_seen,agent_ip,agent_ver,server_dir FROM agent_state');
        this.stmt.agentStateDelete = p('DELETE FROM agent_state WHERE mid=?');

        this.stmt.deployHistoryInsert = p('INSERT INTO deploy_history(ts,data_json) VALUES(?,?)');
        this.stmt.deployHistoryAll = p('SELECT data_json FROM deploy_history ORDER BY id DESC LIMIT ?');
        this.stmt.deployHistoryPrune = p('DELETE FROM deploy_history WHERE id NOT IN (SELECT id FROM deploy_history ORDER BY id DESC LIMIT ?)');
    }

    _write(fn) {
        try {
            const result = this.db.transaction(fn)();
            this.saveTotal++;
            return result;
        } catch (err) {
            this.saveFailTotal++;
            throw err;
        }
    }

    _migrateLegacyJson() {
        const version = 1;
        if (this.db.prepare('SELECT 1 FROM schema_migrations WHERE version=?').get(version)) return;

        const files = {
            machines: path.join(this.dataDir, 'whitelist.json'),
            settings: path.join(this.dataDir, 'settings.json'),
            plans: path.join(this.dataDir, 'plans.json'),
            bans: path.join(this.dataDir, 'bans.json'),
            stats: path.join(this.dataDir, 'stats.json'),
            history: path.join(this.dataDir, 'history.json'),
            admin: path.join(this.dataDir, 'admin.json'),
        };
        this._write(() => {
            if (this.db.prepare('SELECT COUNT(*) n FROM machines').get().n === 0) {
                const rows = readLegacyJson(files.machines, {});
                const ts = Date.now();
                for (const [mid, value] of Object.entries(rows || {})) this.stmt.machineUpsert.run(mid, toJson(value), ts);
            }
            if (this.db.prepare('SELECT COUNT(*) n FROM settings').get().n === 0) {
                const rows = readLegacyJson(files.settings, {});
                for (const [key, value] of Object.entries(rows || {})) this.stmt.settingUpsert.run(key, toJson(value));
            }
            if (this.db.prepare('SELECT COUNT(*) n FROM plans').get().n === 0) {
                const rows = readLegacyJson(files.plans, []);
                (Array.isArray(rows) ? rows : []).forEach((value, i) => this.stmt.planUpsert.run(String(value.id || `plan_${i}`), i, toJson(value)));
            }
            if (this.db.prepare('SELECT COUNT(*) n FROM bans').get().n === 0) {
                const rows = readLegacyJson(files.bans, {});
                for (const [range, value] of Object.entries(rows || {})) this.stmt.banUpsert.run(range, toJson(value));
            }
            if (this.db.prepare('SELECT COUNT(*) n FROM stats').get().n === 0) {
                const rows = readLegacyJson(files.stats, {});
                for (const [mid, points] of Object.entries(rows || {})) {
                    if (!Array.isArray(points)) continue;
                    for (const point of points) {
                        if (Array.isArray(point) && point.length >= 2) this.stmt.statInsert.run(mid, Number(point[0]) || Date.now(), Math.max(0, Number(point[1]) || 0));
                    }
                }
            }
            if (this.db.prepare('SELECT COUNT(*) n FROM history').get().n === 0) {
                const rows = readLegacyJson(files.history, []);
                for (const value of (Array.isArray(rows) ? rows : [])) {
                    this.stmt.historyInsert.run(Number(value.ts_ms) || Date.now(), value.mid || null, value.event || null, value.ip || null, toJson(value));
                }
            }
            if (!this.stmt.adminGet.get()) {
                const admin = readLegacyJson(files.admin, null);
                if (admin && typeof admin === 'object') this.stmt.adminSet.run(toJson(admin), Date.now());
            }
            // Agent tokens
            if (this.db.prepare('SELECT COUNT(*) n FROM agent_tokens').get().n === 0) {
                const tokens = readLegacyJson(path.join(this.dataDir, 'agent_tokens.json'), {});
                for (const [mid, val] of Object.entries(tokens || {})) {
                    if (val && val.token) this.stmt.agentTokenUpsert.run(mid, val.token, val.created || new Date().toISOString(), val.rotated_at || val.created || new Date().toISOString());
                }
            }
            // Agent state
            if (this.db.prepare('SELECT COUNT(*) n FROM agent_state').get().n === 0) {
                const state = readLegacyJson(path.join(this.dataDir, 'agent_state.json'), {});
                const ts = Date.now();
                for (const [mid, val] of Object.entries(state || {})) {
                    this.stmt.agentStateUpsert.run(mid, val.last_seen || null, val.agent_ip || null, val.agent_ver || null, val.server_dir || 'pwserver', ts);
                }
            }
            // Deploy history
            if (this.db.prepare('SELECT COUNT(*) n FROM deploy_history').get().n === 0) {
                const deploys = readLegacyJson(path.join(this.dataDir, 'deploy_history.json'), []);
                for (const entry of (Array.isArray(deploys) ? deploys : [])) {
                    this.stmt.deployHistoryInsert.run(entry.startedAt || new Date().toISOString(), toJson(entry));
                }
            }
            this.db.prepare('INSERT INTO schema_migrations(version,applied_at,description) VALUES(?,?,?)')
                .run(version, Date.now(), 'Import legacy JSON data into SQLite');
        });

        const allLegacyFiles = Object.values(files).concat([
            path.join(this.dataDir, 'agent_tokens.json'),
            path.join(this.dataDir, 'agent_state.json'),
            path.join(this.dataDir, 'deploy_history.json'),
        ]);
        const existing = allLegacyFiles.filter(f => fs.existsSync(f));
        for (const file of existing) {
            const dest = `${file}.migrated-backup`;
            try {
                if (!fs.existsSync(dest)) fs.renameSync(file, dest);
                else fs.unlinkSync(file);
            } catch (err) {
                this.log('WARNING', `Cannot retire legacy JSON ${path.basename(file)}: ${err.message}`);
            }
        }
        if (existing.length) this.log('INFO', `SQLite migration completed; retired ${existing.length} legacy JSON file(s).`);
    }

    loadDB() {
        const out = {};
        for (const row of this.stmt.machineAll.all()) out[row.mid] = fromJson(row.data_json, {});
        return out;
    }

    saveDB(data) {
        const input = data || {};
        return this._write(() => {
            const keep = new Set(Object.keys(input));
            const ts = Date.now();
            for (const [mid, value] of Object.entries(input)) this.stmt.machineUpsert.run(mid, toJson(value), ts);
            for (const row of this.stmt.machineKeys.all()) if (!keep.has(row.mid)) this.stmt.machineDelete.run(row.mid);
        });
    }

    loadSettings() {
        const out = {};
        for (const row of this.stmt.settingsAll.all()) out[row.key] = fromJson(row.value_json, null);
        return out;
    }

    saveSettings(data) {
        const input = data || {};
        return this._write(() => {
            const keep = new Set(Object.keys(input));
            for (const [key, value] of Object.entries(input)) this.stmt.settingUpsert.run(key, toJson(value));
            for (const row of this.stmt.settingKeys.all()) if (!keep.has(row.key)) this.stmt.settingDelete.run(row.key);
        });
    }

    loadPlans() {
        return this.stmt.plansAll.all().map(row => fromJson(row.data_json, {}));
    }

    savePlans(data) {
        const input = Array.isArray(data) ? data : [];
        return this._write(() => {
            const keep = new Set();
            input.forEach((value, i) => {
                const id = String(value.id || `plan_${i}`);
                keep.add(id);
                this.stmt.planUpsert.run(id, i, toJson(value));
            });
            for (const row of this.stmt.planKeys.all()) if (!keep.has(row.id)) this.stmt.planDelete.run(row.id);
        });
    }

    loadBans() {
        const out = {};
        for (const row of this.stmt.bansAll.all()) out[row.range] = fromJson(row.data_json, {});
        return out;
    }

    saveBans(data) {
        const input = data || {};
        return this._write(() => {
            const keep = new Set(Object.keys(input));
            for (const [range, value] of Object.entries(input)) this.stmt.banUpsert.run(range, toJson(value));
            for (const row of this.stmt.banKeys.all()) if (!keep.has(row.range)) this.stmt.banDelete.run(row.range);
        });
    }

    loadStats() {
        const out = {};
        for (const row of this.stmt.statsAll.all()) {
            if (!Array.isArray(out[row.mid])) out[row.mid] = [];
            out[row.mid].push([row.ts, row.players]);
        }
        return out;
    }

    saveStats(data) {
        const input = data || {};
        return this._write(() => {
            this.stmt.statsDeleteAll.run();
            for (const [mid, rows] of Object.entries(input)) {
                if (!Array.isArray(rows)) continue;
                for (const row of rows) if (Array.isArray(row) && row.length >= 2) this.stmt.statInsert.run(mid, Number(row[0]) || Date.now(), Math.max(0, Number(row[1]) || 0));
            }
        });
    }

    pushStat(mid, players, options = {}) {
        const maxPerMachine = Math.max(1, Number(options.maxPerMachine) || 1440);
        const retentionMs = Math.max(60_000, Number(options.retentionMs) || 7 * 24 * 60 * 60 * 1000);
        return this._write(() => {
            this.stmt.statInsert.run(mid, Date.now(), Math.max(0, Number.parseInt(players, 10) || 0));
            this.stmt.statsPruneAge.run(Date.now() - retentionMs);
            this.stmt.statsPrunePerMid.run(mid, maxPerMachine);
        });
    }

    loadHistory(limit = 1000) {
        return this.stmt.historyAll.all(Math.max(1, Number(limit) || 1000)).reverse().map(row => fromJson(row.data_json, {}));
    }

    saveHistory(data) {
        const input = Array.isArray(data) ? data : [];
        return this._write(() => {
            this.stmt.historyDeleteAll.run();
            for (const value of input) this.stmt.historyInsert.run(Number(value.ts_ms) || Date.now(), value.mid || null, value.event || null, value.ip || null, toJson(value));
        });
    }

    pushHistory(value, options = {}) {
        const item = value || {};
        const maxRows = Math.max(100, Number(options.maxRows) || 10_000);
        const retentionMs = Math.max(60_000, Number(options.retentionMs) || 90 * 24 * 60 * 60 * 1000);
        return this._write(() => {
            this.stmt.historyInsert.run(Number(item.ts_ms) || Date.now(), item.mid || null, item.event || null, item.ip || null, toJson(item));
            this.stmt.historyPruneAge.run(Date.now() - retentionMs);
            this.stmt.historyPruneCount.run(maxRows);
        });
    }

    saveLicenseSession(sessionId, state) {
        const row = { ...state, session_id: sessionId, data_json: toJson(state) };
        return this._write(() => this.stmt.licenseSessionUpsert.run(row));
    }

    loadLicenseSession(sessionId) {
        const row = this.stmt.licenseSessionGet.get(sessionId);
        return row ? fromJson(row.data_json, null) : null;
    }

    loadActiveLicenseSessions(nowMs = Date.now()) {
        return this.stmt.licenseSessionActive.all(nowMs).map(row => fromJson(row.data_json, null)).filter(Boolean);
    }

    deleteLicenseSession(sessionId) {
        return this._write(() => this.stmt.licenseSessionDelete.run(sessionId).changes);
    }

    deleteLicenseSessionsForMachine(mid) {
        return this._write(() => this.stmt.licenseSessionDeleteMid.run(mid).changes);
    }

    cleanupExpiredLicenseSessions(nowMs = Date.now()) {
        return this._write(() => this.stmt.licenseSessionDeleteExpired.run(nowMs).changes);
    }

    getWebSession(sid) {
        const row = this.stmt.webSessionGet.get(sid);
        if (!row) return null;
        if (row.expires_at <= Date.now()) {
            this.deleteWebSession(sid);
            return null;
        }
        return fromJson(row.data_json, null);
    }

    setWebSession(sid, sessionData, expiresAt) {
        return this._write(() => this.stmt.webSessionUpsert.run(sid, expiresAt, toJson(sessionData), Date.now()));
    }

    deleteWebSession(sid) {
        return this._write(() => this.stmt.webSessionDelete.run(sid).changes);
    }

    clearWebSessions() {
        return this._write(() => this.stmt.webSessionClear.run().changes);
    }

    cleanupExpiredWebSessions(nowMs = Date.now()) {
        return this._write(() => this.stmt.webSessionDeleteExpired.run(nowMs).changes);
    }

    loadAdminCredentials() {
        const row = this.stmt.adminGet.get();
        return row ? fromJson(row.data_json, null) : null;
    }

    saveAdminCredentials(value) {
        return this._write(() => this.stmt.adminSet.run(toJson(value), Date.now()));
    }

    // ── Agent tokens ─────────────────────────────────────────────────────
    loadAgentTokens() {
        const out = {};
        for (const row of this.stmt.agentTokenAll.all()) out[row.mid] = { token: row.token, created: row.created, rotated_at: row.rotated_at };
        return out;
    }
    saveAgentTokens(data) {
        return this._write(() => {
            const keep = new Set(Object.keys(data || {}));
            for (const [mid, val] of Object.entries(data || {})) this.stmt.agentTokenUpsert.run(mid, val.token, val.created, val.rotated_at);
            for (const row of this.stmt.agentTokenAll.all()) if (!keep.has(row.mid)) this.stmt.agentTokenDelete.run(row.mid);
        });
    }
    deleteAgentToken(mid) {
        return this._write(() => this.stmt.agentTokenDelete.run(mid));
    }

    // ── Agent state ──────────────────────────────────────────────────────
    loadAgentState() {
        const out = {};
        for (const row of this.stmt.agentStateAll.all()) out[row.mid] = { last_seen: row.last_seen, agent_ip: row.agent_ip, agent_ver: row.agent_ver, server_dir: row.server_dir };
        return out;
    }
    saveAgentState(data) {
        return this._write(() => {
            const keep = new Set(Object.keys(data || {}));
            const ts = Date.now();
            for (const [mid, val] of Object.entries(data || {})) {
                this.stmt.agentStateUpsert.run(mid, val.last_seen || null, val.agent_ip || null, val.agent_ver || null, val.server_dir || 'pwserver', ts);
            }
            for (const row of this.stmt.agentStateAll.all()) if (!keep.has(row.mid)) this.stmt.agentStateDelete.run(row.mid);
        });
    }
    deleteAgentState(mid) {
        return this._write(() => this.stmt.agentStateDelete.run(mid));
    }

    // ── Deploy history ──────────────────────────────────────────────────
    loadDeployHistory(limit = 20) {
        return this.stmt.deployHistoryAll.all(Math.max(1, Number(limit) || 20)).reverse().map(row => fromJson(row.data_json, {}));
    }
    pushDeployHistory(entry) {
        return this._write(() => {
            this.stmt.deployHistoryInsert.run(new Date().toISOString(), toJson(entry));
            this.stmt.deployHistoryPrune.run(HISTORY_LIMIT_DEPLOY);
        });
    }

    quickCheck() {
        try {
            const rows = this.db.pragma('quick_check');
            const result = rows.map(row => Object.values(row)[0]).join('; ');
            return { ok: result === 'ok', result };
        } catch (err) {
            return { ok: false, result: err.message };
        }
    }

    checkpoint(mode = 'PASSIVE') {
        return this.db.pragma(`wal_checkpoint(${String(mode).toUpperCase()})`);
    }

    async backup(destination) {
        fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
        await this.db.backup(destination);
        const verifyDb = new BetterSqlite3(destination, { readonly: true, fileMustExist: true });
        try {
            const rows = verifyDb.pragma('quick_check');
            const result = rows.map(row => Object.values(row)[0]).join('; ');
            if (result !== 'ok') throw new Error(`backup quick_check=${result}`);
        } finally {
            verifyDb.close();
        }
        try { fs.chmodSync(destination, 0o600); } catch {}
        this.lastBackupAt = Date.now();
        this.lastBackupFile = destination;
        return destination;
    }

    health() {
        const quick = this.quickCheck();
        let journalMode = 'unknown';
        try { journalMode = String(this.db.pragma('journal_mode', { simple: true })); } catch {}
        return {
            driver: 'sqlite',
            db_path: this.dbPath,
            db_size_bytes: safeStatSize(this.dbPath),
            wal_size_bytes: safeStatSize(`${this.dbPath}-wal`),
            shm_size_bytes: safeStatSize(`${this.dbPath}-shm`),
            journal_mode: journalMode,
            quick_check: quick.result,
            ok: quick.ok && journalMode.toLowerCase() === 'wal',
            saves_total: this.saveTotal,
            save_fail_total: this.saveFailTotal,
            last_backup_at: this.lastBackupAt || null,
            last_backup_file: this.lastBackupFile || null,
        };
    }

    close() {
        if (!this.db) return;
        try { this.checkpoint('TRUNCATE'); } catch {}
        this.db.close();
        this.db = null;
    }
}

module.exports = { SqliteStore };
