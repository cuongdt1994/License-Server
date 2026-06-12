'use strict';

const { spawn } = require('child_process');

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

function createDeployManager(options = {}) {
    const cwd = options.cwd || process.cwd();
    const timeoutMs = options.timeoutMs || 120000;
    const npmBin = options.npmBin || (process.platform === 'win32' ? 'npm.cmd' : 'npm');
    const runCommand = options.runCommand || defaultRunCommand(cwd, timeoutMs);
    let running = false;
    let last = null;

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

    async function runUpdate() {
        if (running) throw new Error('Deployment is already running');
        running = true;
        const result = {
            ok: true,
            startedAt: new Date().toISOString(),
            finishedAt: null,
            steps: [],
        };
        last = result;

        try {
            const steps = [
                ['Lấy code mới từ Git', 'git', ['pull', '--ff-only']],
                ['Restart PM2', npmBin, ['run', 'pm2:restart']],
            ];
            for (const [name, cmd, args] of steps) {
                const step = await runStep(name, cmd, args);
                result.steps.push(step);
                if (step.code !== 0) {
                    result.ok = false;
                    break;
                }
            }
            return result;
        } finally {
            result.finishedAt = new Date().toISOString();
            running = false;
        }
    }

    function status() {
        return { running, last };
    }

    return { runUpdate, status };
}

module.exports = { createDeployManager };
