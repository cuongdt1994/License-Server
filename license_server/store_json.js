'use strict';

const fs = require('fs');
const path = require('path');

function safeJsonParse(text, fallback) {
    try { return JSON.parse(text); } catch { return fallback; }
}

function cloneJson(value, fallback) {
    try { return JSON.parse(JSON.stringify(value)); } catch { return fallback; }
}

function atomicWritePrivate(file, payload) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.tmp.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}`;
    const fd = fs.openSync(tmp, 'w', 0o600);
    try {
        fs.writeFileSync(fd, payload);
        fs.fsyncSync(fd);
    } finally {
        fs.closeSync(fd);
    }
    fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, file);
}

class JsonStore {
    constructor(options = {}) {
        this.driver = 'json';
        this.dataDir = options.dataDir || process.cwd();
        this.files = {
            db: path.join(this.dataDir, 'whitelist.json'),
            settings: path.join(this.dataDir, 'settings.json'),
            plans: path.join(this.dataDir, 'plans.json'),
            bans: path.join(this.dataDir, 'bans.json'),
            stats: path.join(this.dataDir, 'stats.json'),
            history: path.join(this.dataDir, 'history.json'),
        };
        this.cache = new Map();
        this.saveTotal = 0;
        this.saveFailTotal = 0;
    }

    init() { fs.mkdirSync(this.dataDir, { recursive: true }); }

    _defaultFor(name) {
        if (name === 'plans' || name === 'history') return [];
        return {};
    }

    _load(name) {
        const file = this.files[name];
        const fallback = this._defaultFor(name);
        if (!fs.existsSync(file)) return cloneJson(fallback, fallback);
        let stat;
        try { stat = fs.statSync(file); } catch { return cloneJson(fallback, fallback); }
        const cached = this.cache.get(name);
        if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
            return cloneJson(cached.value, cloneJson(fallback, fallback));
        }
        const value = safeJsonParse(fs.readFileSync(file, 'utf8'), fallback);
        this.cache.set(name, { mtimeMs: stat.mtimeMs, size: stat.size, value: cloneJson(value, fallback) });
        return cloneJson(value, fallback);
    }

    _save(name, value, pretty = true) {
        const file = this.files[name];
        const payload = (pretty ? JSON.stringify(value, null, 2) : JSON.stringify(value)) + (pretty ? '\n' : '');
        try {
            atomicWritePrivate(file, payload);
            const stat = fs.statSync(file);
            this.cache.set(name, { mtimeMs: stat.mtimeMs, size: stat.size, value: cloneJson(value, this._defaultFor(name)) });
            this.saveTotal++;
        } catch (err) {
            this.saveFailTotal++;
            throw err;
        }
    }

    loadDB() { return this._load('db'); }
    saveDB(db) { this._save('db', db || {}, true); }
    loadSettings() { return this._load('settings'); }
    saveSettings(settings) { this._save('settings', settings || {}, true); }
    loadPlans() { return this._load('plans'); }
    savePlans(plans) { this._save('plans', Array.isArray(plans) ? plans : [], true); }
    loadBans() { return this._load('bans'); }
    saveBans(bans) { this._save('bans', bans || {}, true); }
    loadStats() { return this._load('stats'); }
    saveStats(stats) { this._save('stats', stats || {}, false); }
    pushStat(mid, players, options = {}) {
        const maxPerMachine = options.maxPerMachine || 1440;
        const stats = this.loadStats();
        if (!Array.isArray(stats[mid])) stats[mid] = [];
        stats[mid].push([Date.now(), Math.max(0, Number.parseInt(players, 10) || 0)]);
        if (stats[mid].length > maxPerMachine) stats[mid] = stats[mid].slice(-maxPerMachine);
        this.saveStats(stats);
    }
    loadHistory() { return this._load('history'); }
    saveHistory(history) { this._save('history', Array.isArray(history) ? history : [], false); }
    pushHistory(entry, options = {}) {
        const maxHistory = options.maxHistory || 1000;
        const history = this.loadHistory();
        history.push(entry || {});
        if (history.length > maxHistory) history.splice(0, history.length - maxHistory);
        this.saveHistory(history);
    }
    health() {
        return {
            driver: 'json',
            data_dir: this.dataDir,
            saves_total: this.saveTotal,
            save_fail_total: this.saveFailTotal,
        };
    }
}

module.exports = { JsonStore, atomicWritePrivate };
