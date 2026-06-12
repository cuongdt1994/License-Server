'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createDeployManager } = require('../deploy_manager');

function tmpFile() {
    return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'license-deploy-history-')), 'history.json');
}

(async () => {
    const commands = [];
    const outputs = {
        'git rev-parse --short HEAD': ['abc111', 'def222'],
        'git pull --ff-only': ['Updating abc111..def222\nFast-forward'],
        'git log -1 --pretty=format:%h %ci %s': ['def222 2026-06-12 01:00:00 +0700 Add feature'],
        'npm.cmd run pm2:restart': ['pm2 restarted'],
    };
    const manager = createDeployManager({
        cwd: 'C:\\app',
        runCommand: async (cmd, args) => {
            const key = [cmd].concat(args).join(' ');
            commands.push([cmd, args]);
            const values = outputs[key] || [`${cmd} ok`];
            return { code: 0, stdout: values.shift(), stderr: '' };
        },
        historyFile: tmpFile(),
    });

    const result = await manager.runUpdate();
    assert.equal(result.ok, true);
    assert.deepEqual(commands.map(([cmd]) => cmd), ['git', 'git', 'git', 'git', 'npm.cmd']);
    assert.deepEqual(commands[0][1], ['rev-parse', '--short', 'HEAD']);
    assert.deepEqual(commands[1][1], ['pull', '--ff-only']);
    assert.deepEqual(commands[2][1], ['rev-parse', '--short', 'HEAD']);
    assert.deepEqual(commands[3][1], ['log', '-1', '--pretty=format:%h %ci %s']);
    assert.deepEqual(commands[4][1], ['run', 'pm2:restart']);
    assert.equal(result.beforeCommit, 'abc111');
    assert.equal(result.afterCommit, 'def222');
    assert.equal(result.changed, true);
    assert.match(result.gitSummary, /Add feature/);
    assert.equal(manager.status().last.ok, true);
    assert.equal(manager.status().history.length, 1);

    const checkCommands = [];
    const check = createDeployManager({
        cwd: 'C:\\app',
        historyFile: tmpFile(),
        runCommand: async (cmd, args) => {
            checkCommands.push([cmd, args]);
            const key = [cmd].concat(args).join(' ');
            if (key === 'git rev-parse --short HEAD') return { code: 0, stdout: 'local1', stderr: '' };
            if (key === 'git fetch --prune') return { code: 0, stdout: 'fetch ok', stderr: '' };
            if (key === 'git rev-parse --short @{u}') return { code: 0, stdout: 'remote2', stderr: '' };
            if (key === 'git log --oneline --decorate -5 HEAD..@{u}') return { code: 0, stdout: 'remote2 new commit', stderr: '' };
            return { code: 0, stdout: '', stderr: '' };
        },
    });
    const checkResult = await check.checkForUpdates();
    assert.equal(checkResult.updateAvailable, true);
    assert.equal(checkResult.localCommit, 'local1');
    assert.equal(checkResult.remoteCommit, 'remote2');
    assert.deepEqual(checkCommands.map(([cmd]) => cmd), ['git', 'git', 'git', 'git']);

    const rollbackCommands = [];
    const rollback = createDeployManager({
        cwd: 'C:\\app',
        historyFile: tmpFile(),
        runCommand: async (cmd, args) => {
            rollbackCommands.push([cmd, args]);
            return { code: 0, stdout: 'ok', stderr: '' };
        },
    });
    rollback.rememberResult({ ok: true, beforeCommit: 'abc111', afterCommit: 'def222', steps: [], startedAt: 'a', finishedAt: 'b' });
    const rollbackResult = await rollback.rollbackLast();
    assert.equal(rollbackResult.ok, true);
    assert.deepEqual(rollbackCommands[0], ['git', ['reset', '--hard', 'abc111']]);
    assert.deepEqual(rollbackCommands[1], ['npm.cmd', ['run', 'pm2:restart']]);

    const historyFile = tmpFile();
    const limited = createDeployManager({ cwd: 'C:\\app', historyFile, runCommand: async () => ({ code: 0, stdout: 'ok', stderr: '' }) });
    for (let i = 0; i < 25; i++) {
        limited.rememberResult({ ok: true, beforeCommit: `a${i}`, afterCommit: `b${i}`, steps: [], startedAt: `${i}`, finishedAt: `${i}` });
    }
    assert.equal(limited.status().history.length, 20);

    let release;
    const locked = createDeployManager({
        cwd: 'C:\\app',
        runCommand: () => new Promise(resolve => { release = () => resolve({ code: 0, stdout: 'done', stderr: '' }); }),
        historyFile: tmpFile(),
    });
    const first = locked.runUpdate();
    await new Promise(resolve => setTimeout(resolve, 5));
    await assert.rejects(() => locked.runUpdate(), /Deployment is already running/);
    release();
    await first;

    console.log('deploy manager tests passed');
})().catch(err => {
    console.error(err);
    process.exit(1);
});
