'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const HISTORY_LIMIT = 20;

// ── Store reference (set via init() after SQLite is ready) ────────────────
let _getStore = null;
function init(getStoreFn) {
    _getStore = getStoreFn;
}
function _loadHistory() {
    if (!_getStore) return [];
    try { return _getStore().loadDeployHistory(HISTORY_LIMIT); } catch { return []; }
}
function _pushHistory(entry) {
    if (!_getStore) return;
    try { _getStore().pushDeployHistory(entry); } catch {}
}

function resolveBin(name, extraPaths = []) {
    const envKey = name.toUpperCase() + '_CMD';
    const envPath = process.env[envKey] ? path.normalize(process.env[envKey]) : '';
    if (envPath && fs.existsSync(envPath)) return envPath;
    const candidates = process.platform === 'win32'
        ? [path.join(process.env.APPDATA || '', 'npm', `${name}.cmd`), `${name}.cmd`]
        : ['/usr/bin/' + name, '/usr/local/bin/' + name, '/snap/bin/' + name, ...extraPaths];
    for (const candidate of candidates) {
        const normalized = path.normalize(candidate);
        if (fs.existsSync(normalized)) return normalized;
    }
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
    const runCommand  = options.runCommand || defaultRunCommand(cwd, timeoutMs);
    let running       = false;
    let last          = null;
    let lastCheck     = null;

    // Migrate legacy JSON history to SQLite on first load
    if (options.historyFile) {
        const historyFile = path.normalize(options.historyFile);
        if (fs.existsSync(historyFile)) {
            try {
                const legacy = JSON.parse(fs.readFileSync(historyFile, 'utf8'));
                if (Array.isArray(legacy)) {
                    for (const entry of legacy) _pushHistory(entry);
                    fs.unlinkSync(historyFile);
                }
            } catch {}
        }
    }

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
        _pushHistory(result);
    }

    // ── Git pull + npm install (KHÔNG restart PM2) ─────────────────────
    // Tách PM2 restart ra ngoài để response kịp gửi về browser trước khi
    // PM2 kill process (tránh ERR_EMPTY_RESPONSE).
    async function runGitUpdate() {
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
            const before = await runStep('Commit trước update', gitBin, ['rev-parse', '--short', 'HEAD']);
            result.steps.push(before);
            result.beforeCommit = cleanOutput(before.stdout);
            if (before.code !== 0) result.ok = false;

            if (result.ok) {
                const pull = await runStep('Git pull', gitBin, ['pull', '--ff-only']);
                result.steps.push(pull);
                if (pull.code !== 0) result.ok = false;
            }

            if (result.ok) {
                const after = await runStep('Commit sau update', gitBin, ['rev-parse', '--short', 'HEAD']);
                result.steps.push(after);
                result.afterCommit = cleanOutput(after.stdout);
                result.changed = !!(result.beforeCommit && result.afterCommit && result.beforeCommit !== result.afterCommit);
                if (after.code !== 0) result.ok = false;
            }

            if (result.ok) {
                const summary = await runStep('Commit mới nhất', gitBin, ['log', '-1', '--pretty=format:%h %ci %s']);
                result.steps.push(summary);
                result.gitSummary = cleanOutput(summary.stdout);
            }

            if (result.ok && result.changed) {
                const install = await runStep('npm install', npmBin, ['install', '--production']);
                result.steps.push(install);
                if (install.code !== 0) result.ok = false;
            }

            return result;
        } finally {
            result.finishedAt = new Date().toISOString();
            rememberResult(result);
            running = false;
        }
    }

    // Giữ lại để backward compat — server.js KHÔNG gọi trực tiếp nữa
    async function runUpdate() {
        const result = await runGitUpdate();
        if (result.ok && result.changed) {
            const restart = await runStep('PM2 restart', pm2Bin, ['restart', 'all', '--update-env']);
            result.steps.push(restart);
            if (restart.code !== 0) result.ok = false;
        }
        return result;
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
        const allHistory = _loadHistory();
        const target = allHistory.find(item => item && item.type === 'update' && item.ok && item.beforeCommit && item.afterCommit && item.beforeCommit !== item.afterCommit);
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
        return { running, last, lastCheck, history: _loadHistory() };
    }

    return { checkForUpdates, getPm2Bin: () => pm2Bin, rememberResult, restartPm2Only, rollbackLast, runGitUpdate, runUpdate, status };
}

module.exports = { init, createDeployManager, HISTORY_LIMIT };
