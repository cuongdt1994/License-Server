'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const HISTORY_LIMIT = 20;

function resolveBin(name, extraPaths = []) {
    // Check explicit env override first
    const envKey = name.toUpperCase() + '_CMD';
    if (process.env[envKey] && fs.existsSync(process.env[envKey])) return process.env[envKey];

    // Platform-specific default paths
    const candidates = process.platform === 'win32'
        ? [path.join(process.env.APPDATA || '', 'npm', `${name}.cmd`), `${name}.cmd`]
        : ['/usr/bin/' + name, '/usr/local/bin/' + name, '/snap/bin/' + name, ...extraPaths];

    for (const candidate of candidates) {
        if (fs.existsSync(candidate)) return candidate;
    }
    // Fallback: rely on PATH
    return name;
}

function defaultRunCommand(cwd, timeoutMs) {
    return (cmd, args) => new Promise(resolve => {
        const child = spawn(cmd, args, {
            cwd,
            shell: false,
            windowsHide: true,
            timeout: timeoutMs,
        });
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', chunk => { stdout += chunk.toString(); });
        child.stderr.on('data', chunk => { stderr += chunk.toString(); });
        child.on('error', err => {
            resolve({ code: 1, stdout, stderr: `${stderr}${err.message}` });
        });
        child.on('close', code => {
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

function addHint(step, hint) {
    return { ...step, stderr: cleanOutput(`${step.stderr}\n${hint}`) };
}

function createDeployManager(options = {}) {
    const cwd         = options.cwd || process.cwd();
    const timeoutMs   = options.timeoutMs || 120000;
    const npmBin      = resolveBin('npm');
    const gitBin      = resolveBin('git');
    const pm2Bin      = resolveBin('pm2');
    const historyFile = options.historyFile || path.join(cwd, 'data', 'deploy_history.json');
    const runCommand  = options.runCommand || defaultRunCommand(cwd, timeoutMs);
    let running       = false;
    let last          = null;
    let lastCheck     = null;
    let history       = readHistory(historyFile);

    async function runStep(name, cmd, args) {
        const startedAt = new Date().toISOString();
        const output = await runCommand(cmd, args);
        let step = {
            name,
            command: commandLabel(cmd, args),
            code: typeof output.code === 'number' ? output.code : 1,
            stdout: output.stdout || '',
            stderr: output.stderr || '',
            startedAt,
            finishedAt: new Date().toISOString(),
        };
        // Add hints for common failures
        const combined = `${step.stderr}\n${step.stdout}`;
        if (step.code !== 0) {
            if (/not recognized|ENOENT|no such file|không.*tìm|command not found/i.test(combined)) {
                step = addHint(step, `Không tìm thấy ${cmd}. Hãy cài đặt hoặc set ${cmd.toUpperCase()}_CMD.`);
            }
        }
        return step;
    }

    function rememberResult(result) {
        history = [result].concat(history).slice(0, HISTORY_LIMIT);
        writeHistory(historyFile, history);
    }

    // ── Pre-flight: kiểm tra git/pm2/npm có sẵn không ────────────────────────
    async function preflight() {
        const checks = [];
        for (const [name, bin] of [['git', gitBin], ['npm', npmBin], ['pm2', pm2Bin]]) {
            const step = await runStep(`Kiểm tra ${name}`, bin, ['--version']);
            checks.push({ name, ok: step.code === 0, path: bin });
        }
        const failed = checks.filter(c => !c.ok);
        if (failed.length) {
            const list = failed.map(c => `${c.name} (${c.path})`).join(', ');
            throw new Error(`Thiếu công cụ: ${list}. Cài đặt trước khi dùng update.`);
        }
        return checks;
    }

    async function runUpdate() {
        if (running) throw new Error('Đang có tiến trình deploy khác đang chạy.');
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
            // 0. Pre-flight
            try { await preflight(); } catch (e) { result.ok = false; result.steps.push({ name: 'Pre-flight', code: 1, stderr: e.message }); last = result; return result; }

            // 1. Commit hiện tại
            const before = await runStep('Commit trước update', gitBin, ['rev-parse', '--short', 'HEAD']);
            result.steps.push(before);
            result.beforeCommit = cleanOutput(before.stdout);
            if (before.code !== 0) result.ok = false;

            // 2. Git pull
            if (result.ok) {
                const pull = await runStep('Git pull', gitBin, ['pull', '--ff-only']);
                result.steps.push(pull);
                if (pull.code !== 0) result.ok = false;
            }

            // 3. Commit sau pull
            if (result.ok) {
                const after = await runStep('Commit sau update', gitBin, ['rev-parse', '--short', 'HEAD']);
                result.steps.push(after);
                result.afterCommit = cleanOutput(after.stdout);
                result.changed = !!(result.beforeCommit && result.afterCommit && result.beforeCommit !== result.afterCommit);
                if (after.code !== 0) result.ok = false;
            }

            // 4. Git log
            if (result.ok) {
                const summary = await runStep('Commit mới nhất', gitBin, ['log', '-1', '--pretty=format:%h %ci %s']);
                result.steps.push(summary);
                result.gitSummary = cleanOutput(summary.stdout);
            }

            // 5. npm install — luôn chạy để đảm bảo dependencies đúng
            if (result.ok && result.changed) {
                const install = await runStep('npm install', npmBin, ['install', '--production']);
                result.steps.push(install);
                if (install.code !== 0) result.ok = false;
            }

            // 6. PM2 restart
            if (result.ok) {
                const restart = await runStep('PM2 restart', pm2Bin, ['restart', 'all', '--update-env']);
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

    async function restartPm2Only() {
        if (running) throw new Error('Đang có tiến trình deploy khác đang chạy.');
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
            const restart = await runStep('PM2 restart', pm2Bin, ['restart', 'all', '--update-env']);
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
        if (running) throw new Error('Đang có tiến trình deploy khác đang chạy.');
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
            const local = await runStep('Commit local', gitBin, ['rev-parse', '--short', 'HEAD']);
            result.steps.push(local);
            result.localCommit = cleanOutput(local.stdout);
            if (local.code !== 0) result.ok = false;

            if (result.ok) {
                const fetch = await runStep('Fetch remote', gitBin, ['fetch', '--prune']);
                result.steps.push(fetch);
                if (fetch.code !== 0) result.ok = false;
            }

            if (result.ok) {
                const remote = await runStep('Commit remote', gitBin, ['rev-parse', '--short', '@{u}']);
                result.steps.push(remote);
                result.remoteCommit = cleanOutput(remote.stdout);
                result.updateAvailable = !!(result.localCommit && result.remoteCommit && result.localCommit !== result.remoteCommit);
                if (remote.code !== 0) result.ok = false;
            }

            if (result.ok) {
                const log = await runStep('Commit chờ cập nhật', gitBin, ['log', '--oneline', '--decorate', '-5', 'HEAD..@{u}']);
                result.steps.push(log);
                result.remoteLog = cleanOutput(log.stdout);
            }

            return result;
        } finally {
            result.finishedAt = new Date().toISOString();
            running = false;
        }
    }

    async function rollbackLast() {
        if (running) throw new Error('Đang có tiến trình deploy khác đang chạy.');
        const target = history.find(item => item && item.type === 'update' && item.ok && item.beforeCommit && item.afterCommit && item.beforeCommit !== item.afterCommit);
        if (!target) throw new Error('Không tìm thấy bản cập nhật trước để rollback.');
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
            const reset = await runStep('Git reset', gitBin, ['reset', '--hard', target.beforeCommit]);
            result.steps.push(reset);
            if (reset.code !== 0) result.ok = false;

            if (result.ok) {
                const install = await runStep('npm install', npmBin, ['install', '--production']);
                result.steps.push(install);
                if (install.code !== 0) result.ok = false;
            }

            if (result.ok) {
                const restart = await runStep('PM2 restart', pm2Bin, ['restart', 'all', '--update-env']);
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

    return { checkForUpdates, restartPm2Only, rollbackLast, runUpdate, status };
}

module.exports = { createDeployManager, HISTORY_LIMIT };
