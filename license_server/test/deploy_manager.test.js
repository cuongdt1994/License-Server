'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createDeployManager, HISTORY_LIMIT } = require('../deploy_manager');

function tmpFile() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'license-deploy-history-'));
    return path.join(dir, 'history.json');
}

(async () => {
    // ── runUpdate: full flow (pull → install → restart) ──────────────────
    {
        const commands = [];
        const outputs = {
            'git rev-parse --short HEAD': ['abc111', 'def222'],
            'git pull --ff-only': ['Updating abc111..def222\nFast-forward'],
            'git log -1 --pretty=format:%h %ci %s': ['def222 2026-06-12 01:00:00 +0700 Add feature'],
            'npm install --production': ['added 0 packages'],
            'pm2 restart all --update-env': ['pm2 restarted'],
        };
        const manager = createDeployManager({
            cwd: '/app',
            runCommand: async (cmd, args) => {
                commands.push([cmd, args]);
                const key = [cmd].concat(args).join(' ');
                const values = outputs[key] || [`${cmd} ok`];
                return { code: 0, stdout: values.shift(), stderr: '' };
            },
            historyFile: tmpFile(),
        });

        const result = await manager.runUpdate();
        assert.equal(result.ok, true);
        assert.equal(commands.length, 6);
        assert.equal(commands[0][0], 'git');   // rev-parse before
        assert.equal(commands[1][0], 'git');   // pull
        assert.equal(commands[2][0], 'git');   // rev-parse after
        assert.equal(commands[3][0], 'git');   // log
        assert.equal(commands[4][0], 'npm');   // install
        assert.equal(commands[5][0], 'pm2');   // restart
        assert.equal(result.beforeCommit, 'abc111');
        assert.equal(result.afterCommit, 'def222');
        assert.equal(result.changed, true);
        assert.match(result.gitSummary, /Add feature/);
        assert.equal(manager.status().last.ok, true);
        assert.equal(manager.status().history.length, 1);
    }

    // ── runUpdate: no changes → skip npm install ───────────────────────
    {
        const commands = [];
        const manager = createDeployManager({
            cwd: '/app',
            runCommand: async (cmd, args) => {
                commands.push([cmd, args]);
                const key = [cmd].concat(args).join(' ');
                if (key === 'git rev-parse --short HEAD') return { code: 0, stdout: 'same1', stderr: '' };
                if (key === 'git pull --ff-only') return { code: 0, stdout: 'Already up to date.', stderr: '' };
                return { code: 0, stdout: 'ok', stderr: '' };
            },
            historyFile: tmpFile(),
        });
        const result = await manager.runUpdate();
        // changed=false → no npm install
        const cmds = commands.map(c => [c[0]].concat(c[1]).join(' '));
        assert.equal(cmds.includes('npm install --production'), false);
        assert.equal(result.changed, false);
    }

    // ── checkForUpdates ──────────────────────────────────────────────────
    {
        const checkCommands = [];
        const check = createDeployManager({
            cwd: '/app',
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
        const result = await check.checkForUpdates();
        assert.equal(result.updateAvailable, true);
        assert.equal(result.localCommit, 'local1');
        assert.equal(result.remoteCommit, 'remote2');
    }

    // ── rollback ─────────────────────────────────────────────────────────
    {
        const commands = [];
        const mgr = createDeployManager({
            cwd: '/app',
            runCommand: async (cmd, args) => {
                commands.push([cmd, args]);
                return { code: 0, stdout: 'ok', stderr: '' };
            },
            historyFile: tmpFile(),
        });
        mgr.rememberResult({ type: 'update', ok: true, beforeCommit: 'abc111', afterCommit: 'def222', steps: [], startedAt: 'a', finishedAt: 'b' });
        const result = await mgr.rollbackLast();
        assert.equal(result.ok, true);
        const cmds = commands.map(c => [c[0]].concat(c[1]).join(' '));
        assert.equal(cmds[0], 'git reset --hard abc111');
        assert.equal(cmds[1], 'npm install --production');
        assert.equal(cmds[2], 'pm2 restart all --update-env');
    }

    // ── PM2 restart fails → result.ok=false ─────────────────────────────
    {
        const mgr = createDeployManager({
            cwd: '/app',
            historyFile: tmpFile(),
            runCommand: async (cmd, args) => {
                const key = [cmd].concat(args).join(' ');
                if (key.endsWith('restart all --update-env')) return { code: 1, stdout: '', stderr: 'pm2 not found' };
                if (key === 'git rev-parse --short HEAD') return { code: 0, stdout: 'abc111', stderr: '' };
                if (key === 'git pull --ff-only') return { code: 0, stdout: 'Updated.', stderr: '' };
                return { code: 0, stdout: 'abc111', stderr: '' };
            },
        });
        const result = await mgr.runUpdate();
        // git steps ok, no changes → skip npm install, pm2 restart fails
        assert.equal(result.ok, false);
    }

    // ── restartPm2Only ───────────────────────────────────────────────────
    {
        const commands = [];
        const mgr = createDeployManager({
            cwd: '/app',
            runCommand: async (cmd, args) => {
                commands.push([cmd, args]);
                return { code: 0, stdout: 'restarted', stderr: '' };
            },
            historyFile: tmpFile(),
        });
        const result = await mgr.restartPm2Only();
        assert.equal(result.ok, true);
        assert.equal(commands[0][1].join(' '), 'restart all --update-env');
        assert.equal(mgr.status().history[0].type, 'restart');
    }

    // ── history limit ────────────────────────────────────────────────────
    {
        const hf = tmpFile();
        const mgr = createDeployManager({ cwd: '/app', historyFile: hf, runCommand: async () => ({ code: 0, stdout: 'ok', stderr: '' }) });
        for (let i = 0; i < 25; i++) {
            mgr.rememberResult({ type: 'update', ok: true, steps: [], startedAt: `${i}`, finishedAt: `${i}` });
        }
        assert.equal(mgr.status().history.length, HISTORY_LIMIT);
    }

    // ── concurrent lock ──────────────────────────────────────────────────
    {
        let release;
        const mgr = createDeployManager({
            cwd: '/app',
            runCommand: () => new Promise(resolve => { release = () => resolve({ code: 0, stdout: 'done', stderr: '' }); }),
            historyFile: tmpFile(),
        });
        const first = mgr.runUpdate();
        await new Promise(resolve => setTimeout(resolve, 5));
        await assert.rejects(() => mgr.runUpdate(), /đang có/i);
        release();
        await first;
    }

    console.log('deploy manager tests passed');
})().catch(err => {
    console.error(err);
    process.exit(1);
});
