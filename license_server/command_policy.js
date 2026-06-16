'use strict';

const crypto = require('crypto');

const DEFAULT_SERVER_DIR = 'pwserver';
const DEFAULT_TIMEOUT_SEC = 60;
const MAX_TIMEOUT_SEC = 300;
const MIN_TIMEOUT_SEC = 5;
const MAX_SCRIPT_BYTES = 8192;
const MAX_TAIL_LINES = 500;

function sanitizeServerDir(dir) {
    let value = String(dir || '').trim().replace(/\\/g, '/');
    value = value.replace(/^\/+|\/+$/g, '');
    value = value.split(/[^A-Za-z0-9._/-]+/)[0] || '';
    const parts = value.split('/')
        .map(p => p.trim())
        .filter(p => p && p !== '.' && p !== '..' && /^[A-Za-z0-9._-]+$/.test(p));
    return parts.join('/') || DEFAULT_SERVER_DIR;
}

function clampTimeout(value, fallback = DEFAULT_TIMEOUT_SEC) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.max(MIN_TIMEOUT_SEC, Math.min(MAX_TIMEOUT_SEC, parsed));
}

function _lines(value) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed)) return 120;
    return Math.max(20, Math.min(MAX_TAIL_LINES, parsed));
}

function _q(value) {
    return String(value).replace(/'/g, "'\\''");
}

const SAFE_ACTIONS = [
    {
        id: 'check_status',
        label: 'Check status',
        timeoutSec: 25,
        build: ({ serverDir }) => `#!/bin/bash
set -u
ServerDir='${_q(serverDir)}'
echo "__UPTIME__"
uptime
echo "__DISK__"
df -h /
echo "__MEM__"
free -m
echo "__PROCESSES__"
ps -eo pid,pcpu,pmem,comm,args 2>/dev/null | grep -E ' (gs|glinkd|gdeliveryd|gfactiond|gacd|gamedbd|uniquenamed|gauthd|logservice)( |$)' | grep -v grep | head -80 || true
echo "__SERVER_DIR__"
ls -ld "/$ServerDir" 2>/dev/null || true
`,
    },
    {
        id: 'tail_gs01',
        label: 'Tail gs01 log',
        timeoutSec: 20,
        build: ({ serverDir, lines }) => `#!/bin/bash
set -u
LOG="/home/logs/gs01.log"
echo "==> $LOG"
if [ -r "$LOG" ]; then tail -n ${_lines(lines)} "$LOG"; else echo "[ERR] log not readable: $LOG"; exit 2; fi
`,
    },
    {
        id: 'tail_agent',
        label: 'Tail agent log',
        timeoutSec: 20,
        build: ({ lines }) => `#!/bin/bash
set -u
LOG="/var/log/lm-agent.log"
echo "==> $LOG"
if [ -r "$LOG" ]; then tail -n ${_lines(lines)} "$LOG"; else echo "[ERR] log not readable: $LOG"; exit 2; fi
`,
    },
    {
        id: 'disk_usage',
        label: 'Disk usage',
        timeoutSec: 30,
        build: ({ serverDir }) => `#!/bin/bash
set -u
ServerDir='${_q(serverDir)}'
df -h /
du -sh "/$ServerDir" "/home/logs" 2>/dev/null || true
`,
    },
    {
        id: 'list_processes',
        label: 'List game processes',
        timeoutSec: 20,
        build: () => `#!/bin/bash
set -u
ps -eo pid,ppid,pcpu,pmem,etime,comm,args 2>/dev/null | grep -E ' (gs|glinkd|gdeliveryd|gfactiond|gacd|gamedbd|uniquenamed|gauthd|logservice)( |$)' | grep -v grep || true
`,
    },
];

function getSafeActions() {
    return SAFE_ACTIONS.map(({ id, label, timeoutSec }) => ({ id, label, timeoutSec }));
}

function buildSafeActionScript(id, opts = {}) {
    const action = SAFE_ACTIONS.find(a => a.id === id);
    if (!action) return null;
    const serverDir = sanitizeServerDir(opts.serverDir);
    return {
        id: action.id,
        label: action.label,
        timeoutSec: clampTimeout(action.timeoutSec, DEFAULT_TIMEOUT_SEC),
        script: action.build({ ...opts, serverDir }),
    };
}

// ── Dangerous shell patterns ──────────────────────────────────────────────────
// Blacklist các pattern có khả năng phá hủy hệ thống.
// Mỗi pattern là RegExp — nếu khớp → reject command.
const DANGEROUS_PATTERNS = [
    // Fork bomb
    /:\(\)\s*\{/,
    // Xóa hệ thống filesystem
    /rm\s+.*(-rf?\s+|--recursive\s+)*\/(\s|$)/,
    /rm\s+.*(-rf?\s+|--recursive\s+)*\/etc(\s|$)/,
    /rm\s+.*(-rf?\s+|--recursive\s+)*\/boot(\s|$)/,
    /rm\s+.*(-rf?\s+|--recursive\s+)*\/sys(\s|$)/,
    /rm\s+.*(-rf?\s+|--recursive\s+)*\/proc(\s|$)/,
    /rm\s+.*\-\-no\-preserve\-root/,
    // Ghi đè disk/partition
    /\bdd\s+if=/,
    /\bmkfs\b/,
    /\bmkswap\b/,
    /\bfdisk\b/,
    /\bparted\b/,
    // Redirect output ghi đè file hệ thống
    />\s*\/etc\//,
    />\s*\/boot\//,
    />\s*\/sys\//,
    // Xóa toàn bộ user data
    /rm\s+.*(-rf?\s+|--recursive\s+)*\/home(\s|$)/,
    /rm\s+.*(-rf?\s+|--recursive\s+)*\/root(\s|$)/,
    // Fork bomb variants
    /\bperl\s+-e\b/,
    /\bpython.*-c\b.*fork/,
    // Kernel module manipulation
    /\bmodprobe\s+-r\b/,
    /\brmmod\b/,
    // IPTables flush
    /iptables\s+-F\b/,
    /iptables\s+--flush\b/,
    // Shutdown/reboot
    /\bshutdown\b/,
    /\breboot\b/,
    /\bpoweroff\b/,
    /\bhalt\b/,
    // Chmod hệ thống
    /chmod\s+.*777\s+\//,
    /chmod\s+.*-R\s+777/,
    // Wget/curl pipe to shell without known URL
    /curl.*\|.*(?:ba)?sh/,
    /wget.*\|.*(?:ba)?sh/,
    // Overwrite critical configs
    />\s*\/etc\/systemd\//,
    />\s*\/etc\/ssh\//,
];

function _checkDangerousPatterns(script) {
    for (const pattern of DANGEROUS_PATTERNS) {
        if (pattern.test(script)) {
            return { blocked: true, pattern: pattern.toString().slice(1, -1) };
        }
    }
    return { blocked: false };
}

function validateShellScript(script, opts = {}) {
    if (typeof script !== 'string') return { ok: false, error: 'empty' };
    if (script.includes('\0')) return { ok: false, error: 'invalid_bytes' };
    const normalized = script.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
    if (!normalized) return { ok: false, error: 'empty' };
    if (Buffer.byteLength(normalized, 'utf8') > MAX_SCRIPT_BYTES) {
        return { ok: false, error: 'too_large' };
    }
    // Check dangerous patterns
    const danger = _checkDangerousPatterns(normalized);
    if (danger.blocked) {
        return { ok: false, error: `dangerous_pattern: ${danger.pattern}` };
    }
    return {
        ok: true,
        script: normalized,
        timeoutSec: clampTimeout(opts.timeoutSec, MAX_TIMEOUT_SEC),
    };
}

function wrapWithTimeout(script, timeoutSec) {
    const body = String(script || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const timeout = clampTimeout(timeoutSec, MAX_TIMEOUT_SEC);
    const marker = 'LM_AGENT_SCRIPT_' + crypto.createHash('sha256').update(body).digest('hex').slice(0, 16);
    return `#!/bin/bash
set +e
SCRIPT_FILE=$(mktemp)
cat > "$SCRIPT_FILE" <<'${marker}'
${body}
${marker}
if command -v timeout >/dev/null 2>&1; then
    timeout "${timeout}s" bash "$SCRIPT_FILE"
else
    bash "$SCRIPT_FILE"
fi
CODE=$?
rm -f "$SCRIPT_FILE"
exit "$CODE"
`;
}

module.exports = {
    DEFAULT_SERVER_DIR,
    DEFAULT_TIMEOUT_SEC,
    MAX_TIMEOUT_SEC,
    MIN_TIMEOUT_SEC,
    MAX_SCRIPT_BYTES,
    sanitizeServerDir,
    clampTimeout,
    getSafeActions,
    buildSafeActionScript,
    validateShellScript,
    wrapWithTimeout,
};
