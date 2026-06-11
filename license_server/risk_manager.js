'use strict';

const fs = require('fs');

const MAX_EVENTS_PER_MACHINE = 100;
const RISK_WINDOW_MS = 48 * 60 * 60 * 1000;

const WEIGHTS = {
    wrong_key: 25,
    missing_key: 20,
    ip_not_whitelisted: 35,
    multi_ip: 20,
    heartbeat_ip_change: 15,
    agent_ip_mismatch: 10,
};

const LEVEL_RANK = {
    none: 0,
    low: 1,
    medium: 2,
    high: 3,
    quarantine: 4,
};

function _now(opts = {}) {
    return Number.isFinite(opts.now) ? opts.now : Date.now();
}

function _load(file) {
    if (!file || !fs.existsSync(file)) return { machines: {} };
    try {
        const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
        if (!raw || typeof raw !== 'object') return { machines: {} };
        if (!raw.machines || typeof raw.machines !== 'object') raw.machines = {};
        return raw;
    } catch {
        return { machines: {} };
    }
}

function _save(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2), { mode: 0o600 });
}

function _entry(data, mid) {
    const id = String(mid || '').trim();
    if (!id) return null;
    if (!data.machines[id]) data.machines[id] = { events: [] };
    if (!Array.isArray(data.machines[id].events)) data.machines[id].events = [];
    return data.machines[id];
}

function levelForScore(score) {
    if (score >= 80) return 'quarantine';
    if (score >= 70) return 'high';
    if (score >= 40) return 'medium';
    if (score > 0) return 'low';
    return 'none';
}

function summarize(file, mid, opts = {}) {
    const data = _load(file);
    const id = String(mid || '').trim();
    const e = id ? data.machines[id] : null;
    const events = Array.isArray(e?.events) ? e.events : [];
    const now = _now(opts);
    const recent = events.filter(ev => Number(ev.ts_ms) && now - Number(ev.ts_ms) <= RISK_WINDOW_MS);
    const rawScore = recent.reduce((sum, ev) => sum + (Number(ev.weight) || 0), 0);
    const score = Math.max(0, Math.min(100, rawScore));
    const level = levelForScore(score);
    const last = events.length ? events[events.length - 1] : null;

    return {
        mid: id,
        score,
        level,
        event_count: events.length,
        recent_count: recent.length,
        last_event: last ? {
            type: last.type,
            ts: last.ts,
            ts_ms: last.ts_ms,
            details: last.details || {},
        } : null,
    };
}

function recordEvent(file, mid, type, details = {}, opts = {}) {
    const id = String(mid || '').trim();
    if (!id) return { event: null, summary: summarize(file, id, opts), crossed: false };

    const before = summarize(file, id, opts);
    const data = _load(file);
    const e = _entry(data, id);
    const now = _now(opts);
    const eventType = String(type || 'unknown');
    const event = {
        type: eventType,
        weight: Number(WEIGHTS[eventType]) || 5,
        details: details && typeof details === 'object' ? details : {},
        ts: new Date(now).toISOString(),
        ts_ms: now,
    };

    e.events.push(event);
    if (e.events.length > MAX_EVENTS_PER_MACHINE) {
        e.events.splice(0, e.events.length - MAX_EVENTS_PER_MACHINE);
    }
    _save(file, data);

    const after = summarize(file, id, opts);
    return {
        event,
        summary: after,
        crossed: LEVEL_RANK[after.level] > LEVEL_RANK[before.level] && LEVEL_RANK[after.level] >= LEVEL_RANK.medium,
    };
}

function listEvents(file, mid) {
    const data = _load(file);
    if (mid) {
        const e = data.machines[String(mid).trim()];
        return Array.isArray(e?.events) ? e.events.slice() : [];
    }
    const out = [];
    for (const [id, e] of Object.entries(data.machines || {})) {
        for (const ev of Array.isArray(e.events) ? e.events : []) out.push({ mid: id, ...ev });
    }
    return out.sort((a, b) => (a.ts_ms || 0) - (b.ts_ms || 0));
}

function clearRisk(file, mid) {
    const data = _load(file);
    const id = String(mid || '').trim();
    if (!id || !data.machines[id]) return false;
    data.machines[id].events = [];
    _save(file, data);
    return true;
}

module.exports = {
    WEIGHTS,
    RISK_WINDOW_MS,
    levelForScore,
    recordEvent,
    summarize,
    listEvents,
    clearRisk,
};
