'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const policy = require('../command_policy');

{
    assert.strictEqual(policy.sanitizeServerDir('pwserver'), 'pwserver');
    assert.strictEqual(policy.sanitizeServerDir('/pwserver/'), 'pwserver');
    assert.strictEqual(policy.sanitizeServerDir('pw-server_1/live.156'), 'pw-server_1/live.156');
    assert.strictEqual(policy.sanitizeServerDir('pwserver; rm -rf /'), 'pwserver');
    assert.strictEqual(policy.sanitizeServerDir('../pwserver'), 'pwserver');
    assert.strictEqual(policy.sanitizeServerDir(''), 'pwserver');
}

{
    const actions = policy.getSafeActions();
    assert.ok(actions.some(a => a.id === 'check_status'));
    assert.ok(actions.some(a => a.id === 'tail_gs01'));

    const action = policy.buildSafeActionScript('tail_gs01', { serverDir: 'pwserver; bad', lines: 2000 });
    assert.strictEqual(action.id, 'tail_gs01');
    assert.strictEqual(action.timeoutSec, 20);
    assert.match(action.script, /tail -n 500/);
    assert.match(action.script, /\/pwserver\/logs\/gs01\.log/);
    assert.doesNotMatch(action.script, /bad/);
}

{
    let checked = policy.validateShellScript('  ls -la /pwserver\n', { timeoutSec: 9999 });
    assert.strictEqual(checked.ok, true);
    assert.strictEqual(checked.timeoutSec, 300);
    assert.strictEqual(checked.script, 'ls -la /pwserver');

    checked = policy.validateShellScript('', {});
    assert.strictEqual(checked.ok, false);
    assert.strictEqual(checked.error, 'empty');

    checked = policy.validateShellScript('x'.repeat(9000), {});
    assert.strictEqual(checked.ok, false);
    assert.strictEqual(checked.error, 'too_large');

    checked = policy.validateShellScript('echo hi\0echo bye', {});
    assert.strictEqual(checked.ok, false);
    assert.strictEqual(checked.error, 'invalid_bytes');
}

{
    assert.strictEqual(policy.clampTimeout(1), 5);
    assert.strictEqual(policy.clampTimeout(42), 42);
    assert.strictEqual(policy.clampTimeout(999), 300);
    assert.strictEqual(policy.clampTimeout('bad'), 60);
}

{
    const wrapped = policy.wrapWithTimeout('echo hello', 999);
    assert.match(wrapped, /timeout "300s" bash/);
    assert.match(wrapped, /LM_AGENT_SCRIPT/);
    assert.match(wrapped, /echo hello/);
}

{
    process.env.LICENSE_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'license-agent-policy-'));
    const agent = require('../agent_manager');

    agent.setServerDir('machine-safe', "pwserver'; touch /tmp/bad");
    assert.strictEqual(agent.getServerDir('machine-safe'), 'pwserver');

    const script = agent.buildStartScript("pwserver'; touch /tmp/bad");
    assert.match(script, /ServerDir='pwserver'/);
    assert.doesNotMatch(script, /touch \/tmp\/bad/);
}

console.log('command policy tests passed');
