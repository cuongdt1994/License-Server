'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const risk = require('../risk_manager');

function tmpFile() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'license-risk-'));
    return path.join(dir, 'risk_events.json');
}

{
    const file = tmpFile();
    const now = Date.parse('2026-06-10T00:00:00Z');

    let r = risk.recordEvent(file, 'machine-a', 'wrong_key', { ip: '1.1.1.1' }, { now });
    assert.strictEqual(r.summary.level, 'low');
    assert.strictEqual(r.summary.score, 25);

    r = risk.recordEvent(file, 'machine-a', 'multi_ip', { prev_ip: '1.1.1.1', new_ip: '2.2.2.2' }, { now: now + 1000 });
    assert.strictEqual(r.summary.level, 'medium');
    assert.strictEqual(r.summary.score, 45);
    assert.strictEqual(r.crossed, true);

    r = risk.recordEvent(file, 'machine-a', 'ip_not_whitelisted', { ip: '3.3.3.3' }, { now: now + 2000 });
    assert.strictEqual(r.summary.level, 'quarantine');
    assert.strictEqual(r.summary.score, 80);
    assert.strictEqual(r.crossed, true);
}

{
    const file = tmpFile();
    const now = Date.parse('2026-06-10T00:00:00Z');

    risk.recordEvent(file, 'machine-b', 'wrong_key', { ip: '1.1.1.1' }, { now: now - 49 * 60 * 60 * 1000 });
    const summary = risk.summarize(file, 'machine-b', { now });

    assert.strictEqual(summary.score, 0);
    assert.strictEqual(summary.level, 'none');
    assert.strictEqual(summary.event_count, 1);
}

{
    const file = tmpFile();
    const now = Date.parse('2026-06-10T00:00:00Z');

    for (let i = 0; i < 125; i++) {
        risk.recordEvent(file, 'machine-c', 'wrong_key', { index: i }, { now: now + i });
    }

    const events = risk.listEvents(file, 'machine-c');
    assert.strictEqual(events.length, 100);
    assert.strictEqual(events[0].details.index, 25);

    risk.clearRisk(file, 'machine-c');
    assert.strictEqual(risk.listEvents(file, 'machine-c').length, 0);
    assert.strictEqual(risk.summarize(file, 'machine-c', { now }).level, 'none');
}

console.log('risk manager tests passed');
