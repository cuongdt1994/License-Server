'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const HISTORY_LIMIT = 20;

function defaultRunCommand(cwd, timeoutMs) {
    return (cmd, args) => new Promise(resolve => {
        const child = spawn(cmd, args, {
            cwd,
            shell: false,
            windowsHide: true,
        });
        let stdout = '';
        let stderr = '';
        const timer = setTimeout(() => {
            child.kill('SIGTERM');
            stderr += `\nCommand timed out after ${timeoutMs}ms`;
        }, timeoutMs);

        child.stdout.on('data', chunk => { stdout += chunk.toString(); });
        child.stderr.on('data', chunk => { stderr += chunk.toString(); });
        child.on('error', err => {
            clearTimeout(timer);
            resolve({ code: 1, stdout, stderr: `${stderr}${err.message}` });
        });
        child.on('close', code => {
            clearTimeout(timer);
            resolve({ code: code || 0, stdout, stderr });
        });
    });
}

function commandLabel(cmd, args) {
    return [cmd].concat(args).join(' ');
}

function readHistory(file) {
    if (!file || !fs.existsSync(file)) return [];
    try {
        const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

function writeHistory(file, history) {
    if (!file) return;
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(history.slice(0, HISTORY_LIMIT), null, 2));
}

function cleanOutput(value) {
    return String(value || '').trim();
}

function resolveDefaultPm2Command(env = process.env, platform = process.platform) {
    if (env.PM2_CMD) return env.PM2_CMD;
    if (platform === 'win32') {
        const appDataPm2 = env.APPDATA ? path.join(env.APPDATA, 'npm', 'pm2.cmd') : '';
        if (appDataPm2 && fs.existsSync(appDataPm2)) return appDataPm2;
        return 'pm2.cmd';
    }
    for (const candidate of ['/usr/bin/pm2', '/usr/local/bin/pm2', '/snap/bin/pm2']) {
        if (fs.existsSync(candidate)) return candidate;
    }
    return 'pm2';
}

function addPm2MissingHint(step) {
    const output = `${step.stderr}\n${step.stdout}`;
    if (!/not recognized|ENOENT|no such file|không.*tìm/i.test(output)) return step;
    const hint = 'Không tìm thấy PM2. Hãy cài PM2 hoặc set PM2_CMD tới đường dẫn pm2.cmd/pm2 trước khi dùng cập nhật tự động.';
    return {
        ...step,
        stderr: cleanOutput(`${step.stderr}\n${hint}`),
    };
}

function createDeployManager(options = {}) {
    const cwd = options.cwd || process.cwd();
    const timeoutMs = options.timeoutMs || 120000;
    const npmBin = options.npmBin || process.env.npm_execpath || (process.platform === 'win32' ? 'C:\\Program Files\\nodejs\\npm.cmd' : '/usr/bin/npm');
    const pm2Bin = options.pm2Bin || resolveDefaultPm2Command(options.env || process.env, process.platform);
    const historyFile = options.historyFile || path.join(cwd, 'data', 'deploy_history.json');
    const runCommand = options.runCommand || defaultRunCommand(cwd, timeoutMs);
    let running = false;
    let last = null;
    let lastCheck = null;
    let history = readHistory(historyFile);

    async function runStep(name, cmd, args) {
        const startedAt = new Date().toISOString();
        const output = await runCommand(cmd, args);
        return {
            name,
            command: commandLabel(cmd, args),
            code: typeof output.code === 'number' ? output.code : 1,
            stdout: output.stdout || '',
            stderr: output.stderr || '',
            startedAt,
            finishedAt: new Date().toISOString(),
        };
    }

    function rememberResult(result) {
        const normalized = {
            type: result.type || (result.beforeCommit && result.afterCommit ? 'update' : 'operation'),
            ...result,
        };
        history = [normalized].concat(history).slice(0, HISTORY_LIMIT);
        writeHistory(historyFile, history);
    }

    async function runGitInfoStep(name, args) {
        const step = await runStep(name, 'git', args);
        return step;
    }

    async function runUpdate() {
        if (running) throw new Error('Deployment is already running');
        running = true;
        const result = {
            type: 'update',
            ok: true,
            startedAt: new Date().toISOString(),
            finishedAt: null,
            steps: [],
            beforeCommit: null,
            afterCommit: null,
            changed: false,
            gitSummary: '',
        };
        last = result;

        try {
            const before = await runGitInfoStep('Commit trước update', ['rev-parse', '--short', 'HEAD']);
            result.steps.push(before);
            result.beforeCommit = cleanOutput(before.stdout);
            if (before.code !== 0) result.ok = false;

            if (result.ok) {
                const pull = await runGitInfoStep('Lấy code mới từ Git', ['pull', '--ff-only']);
                result.steps.push(pull);
                if (pull.code !== 0) result.ok = false;
            }

            if (result.ok) {
                const after = await runGitInfoStep('Commit sau update', ['rev-parse', '--short', 'HEAD']);
                result.steps.push(after);
                result.afterCommit = cleanOutput(after.stdout);
                result.changed = Boolean(result.beforeCommit && result.afterCommit && result.beforeCommit !== result.afterCommit);
                if (after.code !== 0) result.ok = false;
            }

            if (result.ok) {
                const summary = await runGitInfoStep('Commit mới nhất', ['log', '-1', '--pretty=format:%h %ci %s']);
                result.steps.push(summary);
                result.gitSummary = cleanOutput(summary.stdout);
                if (summary.code !== 0) result.ok = false;
            }

            if (result.ok) {
                const step = addPm2MissingHint(await runStep('Restart PM2', pm2Bin, ['restart', 'all', '--update-env']));
                result.steps.push(step);
                if (step.code !== 0) result.ok = false;
            }
            return result;
        } finally {
            result.finishedAt = new Date().toISOString();
            rememberResult(result);
            running = false;
        }
    }

    async function restartPm2Only() {
        if (running) throw new Error('Deployment is already running');
        running = true;
        const result = {
            type: 'restart',
            ok: true,
            startedAt: new Date().toISOString(),
            finishedAt: null,
            steps: [],
        };
        last = result;
        try {
            const restart = addPm2MissingHint(await runStep('Restart PM2', pm2Bin, ['restart', 'all', '--update-env']));
            result.steps.push(restart);
            if (restart.code !== 0) result.ok = false;
            return result;
        } finally {
            result.finishedAt = new Date().toISOString();
            rememberResult(result);
            running = false;
        }
    }

    async function checkForUpdates() {
        if (running) throw new Error('Deployment is already running');
        running = true;
        const result = {
            type: 'check',
            ok: true,
            startedAt: new Date().toISOString(),
            finishedAt: null,
            steps: [],
            localCommit: null,
            remoteCommit: null,
            updateAvailable: false,
            remoteLog: '',
        };
        lastCheck = result;
        last = result;
        try {
            const local = await runGitInfoStep('Commit local', ['rev-parse', '--short', 'HEAD']);
            result.steps.push(local);
            result.localCommit = cleanOutput(local.stdout);
            if (local.code !== 0) result.ok = false;

            if (result.ok) {
                const fetch = await runGitInfoStep('Fetch remote', ['fetch', '--prune']);
                result.steps.push(fetch);
                if (fetch.code !== 0) result.ok = false;
            }

            if (result.ok) {
                const remote = await runGitInfoStep('Commit remote', ['rev-parse', '--short', '@{u}']);
                result.steps.push(remote);
                result.remoteCommit = cleanOutput(remote.stdout);
                result.updateAvailable = Boolean(result.localCommit && result.remoteCommit && result.localCommit !== result.remoteCommit);
                if (remote.code !== 0) result.ok = false;
            }

            if (result.ok) {
                const log = await runGitInfoStep('Commit chờ cập nhật', ['log', '--oneline', '--decorate', '-5', 'HEAD..@{u}']);
                result.steps.push(log);
                result.remoteLog = cleanOutput(log.stdout);
                if (log.code !== 0) result.ok = false;
            }

            return result;
        } finally {
            result.finishedAt = new Date().toISOString();
            running = false;
        }
    }

    async function rollbackLast() {
        if (running) throw new Error('Deployment is already running');
        const target = history.find(item => item && item.type === 'update' && item.ok && item.beforeCommit && item.afterCommit && item.beforeCommit !== item.afterCommit);
        if (!target) throw new Error('No rollback target found');
        running = true;
        const result = {
            type: 'rollback',
            ok: true,
            startedAt: new Date().toISOString(),
            finishedAt: null,
            steps: [],
            rollbackTo: target.beforeCommit,
            rollbackFrom: target.afterCommit,
        };
        last = result;
        try {
            const reset = await runGitInfoStep('Rollback Git', ['reset', '--hard', target.beforeCommit]);
            result.steps.push(reset);
            if (reset.code !== 0) result.ok = false;

            if (result.ok) {
                const restart = addPm2MissingHint(await runStep('Restart PM2', pm2Bin, ['restart', 'all', '--update-env']));
                result.steps.push(restart);
                if (restart.code !== 0) result.ok = false;
            }
            return result;
        } finally {
            result.finishedAt = new Date().toISOString();
            rememberResult(result);
            running = false;
        }
    }

    function status() {
        return { running, last, lastCheck, history };
    }

    return { checkForUpdates, rememberResult, restartPm2Only, rollbackLast, runUpdate, status };
}

module.exports = { createDeployManager, resolveDefaultPm2Command, HISTORY_LIMIT };
