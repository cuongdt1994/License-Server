'use strict';
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { resolveDataDir } = require('./data_dir');
const { sanitizeServerDir } = require('./command_policy');

const DATA_DIR     = resolveDataDir({ appDir: __dirname });
const TOKENS_FILE  = path.join(DATA_DIR, 'agent_tokens.json');
const STATE_FILE   = path.join(DATA_DIR, 'agent_state.json');

const POLL_TIMEOUT_MS = 25000;
const CMD_TTL_MS      = 5 * 60 * 1000;
const RESULT_TTL_MS   = 10 * 60 * 1000;
const MONITOR_TTL_MS  = 5 * 60 * 1000;

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });

function loadTokens() {
    if (!fs.existsSync(TOKENS_FILE)) return {};
    try { return JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf8')); } catch { return {}; }
}
function saveTokens(t) { fs.writeFileSync(TOKENS_FILE, JSON.stringify(t, null, 2), { mode: 0o600 }); }

function loadState() {
    if (!fs.existsSync(STATE_FILE)) return {};
    try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch { return {}; }
}
function saveState(s) { fs.writeFileSync(STATE_FILE, JSON.stringify(s, null, 2), { mode: 0o600 }); }

const queues   = new Map();
const results  = new Map();
const waiters  = new Map();
const monitors = new Map();

function _ensureQ(mid) {
    if (!queues.has(mid)) queues.set(mid, []);
    return queues.get(mid);
}

function getOrCreateToken(mid) {
    const all = loadTokens();
    if (all[mid]?.token) return all[mid].token;
    const tok = crypto.randomBytes(24).toString('hex');
    all[mid] = { token: tok, created: new Date().toISOString() };
    saveTokens(all);
    return tok;
}
function regenerateToken(mid) {
    const all = loadTokens();
    delete all[mid];
    saveTokens(all);
    return getOrCreateToken(mid);
}
function verifyToken(mid, token) {
    const e = loadTokens()[mid];
    if (!e || !token) return false;
    const a = Buffer.from(e.token);
    const b = Buffer.from(token);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function listInstalled() {
    const tokens = loadTokens();
    const state  = loadState();
    const out = {};
    for (const mid of Object.keys(tokens)) {
        const st = state[mid] || {};
        const everSeen = !!st.last_seen;
        out[mid] = {
            installed:    everSeen,
            token_issued: true,
            last_seen:    st.last_seen || null,
            agent_ip:     st.agent_ip || null,
            agent_ver:    st.agent_ver || null,
            server_dir:   st.server_dir || 'pwserver',
            online:       !!(st.last_seen && (Date.now() - st.last_seen) < 90000),
        };
    }
    return out;
}
function infoFor(mid) {
    return listInstalled()[mid] || null;
}
function uninstall(mid) {
    const t = loadTokens(); delete t[mid]; saveTokens(t);
    const s = loadState();  delete s[mid]; saveState(s);
    queues.delete(mid); results.delete(mid); monitors.delete(mid);
    const ws = waiters.get(mid);
    if (ws) { for (const w of ws) try { clearTimeout(w.timer); w.resolve([]); } catch {} ; waiters.delete(mid); }
}

function setServerDir(mid, dir) {
    const s = loadState();
    s[mid] = { ...(s[mid] || {}), server_dir: sanitizeServerDir(dir) };
    saveState(s);
}
function getServerDir(mid) {
    const s = loadState();
    return sanitizeServerDir(s[mid]?.server_dir || 'pwserver');
}

function recordHeartbeat(mid, ip, agentVer) {
    const s = loadState();
    s[mid] = {
        ...(s[mid] || {}),
        last_seen: Date.now(),
        agent_ip:  ip || s[mid]?.agent_ip || null,
        agent_ver: agentVer || s[mid]?.agent_ver || null,
    };
    saveState(s);
}

function setMonitor(mid, snapshot) {
    monitors.set(mid, { ts: Date.now(), data: snapshot });
}
function getMonitor(mid) {
    const m = monitors.get(mid);
    if (!m) return null;
    if (Date.now() - m.ts > MONITOR_TTL_MS) { monitors.delete(mid); return null; }
    return { ...m.data, fetched_at: m.ts };
}

function _gcQueue(q) {
    const now = Date.now();
    for (let i = q.length - 1; i >= 0; i--) if (now - q[i].ts > CMD_TTL_MS) q.splice(i, 1);
}
function _gcResults(mid) {
    const r = results.get(mid); if (!r) return;
    const now = Date.now();
    for (const [id, v] of r) if (now - v.ts > RESULT_TTL_MS) r.delete(id);
}

function enqueueCommand(mid, kind, payload = {}) {
    const id = crypto.randomBytes(8).toString('hex');
    const cmd = { id, kind, payload, ts: Date.now() };
    _ensureQ(mid).push(cmd);
    const ws = waiters.get(mid);
    if (ws && ws.length) {
        const w = ws.shift();
        if (!ws.length) waiters.delete(mid);
        try { clearTimeout(w.timer); w.resolve(_takeOne(mid)); } catch {}
    }
    return id;
}

function _drainQueue(mid) {
    const q = _ensureQ(mid);
    _gcQueue(q);
    if (!q.length) return [];
    return q.splice(0, q.length);
}

function _takeOne(mid) {
    const q = _ensureQ(mid);
    _gcQueue(q);
    if (!q.length) return null;
    return q.shift();
}

function pollOne(mid, ip) {
    recordHeartbeat(mid, ip);
    const cmd = _takeOne(mid);
    if (cmd) return Promise.resolve(cmd);
    return new Promise(resolve => {
        if (!waiters.has(mid)) waiters.set(mid, []);
        const arr = waiters.get(mid);
        const w = { resolve, timer: null };
        w.timer = setTimeout(() => {
            const ws = waiters.get(mid);
            if (ws) {
                const i = ws.indexOf(w);
                if (i >= 0) ws.splice(i, 1);
                if (!ws.length) waiters.delete(mid);
            }
            resolve(null);
        }, POLL_TIMEOUT_MS);
        arr.push(w);
    });
}

function pollCommands(mid, ip) {
    recordHeartbeat(mid, ip);
    const q = _ensureQ(mid);
    _gcQueue(q);
    if (q.length) return Promise.resolve(_drainQueue(mid));
    return new Promise(resolve => {
        if (!waiters.has(mid)) waiters.set(mid, []);
        const arr = waiters.get(mid);
        const w = { resolve, timer: null };
        w.timer = setTimeout(() => {
            const ws = waiters.get(mid);
            if (ws) {
                const i = ws.indexOf(w);
                if (i >= 0) ws.splice(i, 1);
                if (!ws.length) waiters.delete(mid);
            }
            resolve([]);
        }, POLL_TIMEOUT_MS);
        arr.push(w);
    });
}

function recordResult(mid, id, code, stdout, stderr) {
    if (!results.has(mid)) results.set(mid, new Map());
    results.get(mid).set(id, {
        ts: Date.now(),
        code: code === undefined ? null : code,
        stdout: (stdout || '').slice(-8000),
        stderr: (stderr || '').slice(-2000),
    });
    _gcResults(mid);
}
function takeResult(mid, id) {
    _gcResults(mid);
    const r = results.get(mid); if (!r) return null;
    return r.get(id) || null;
}

function buildStartScript(serverDir) {
    serverDir = sanitizeServerDir(serverDir);
    return `#!/bin/bash
ServerDir='${serverDir}'
LOGS="/home/logs"
mkdir -p "$LOGS"

run_svc() {
    local sub="$1" logf="$2"; shift 2
    local dir="/$ServerDir/$sub"
    local bin="$1"
    if [ ! -d "$dir" ]; then echo "[--] $dir not found, skip"; return; fi
    if [ ! -x "$dir/$bin" ]; then echo "[--] $dir/$bin not executable, skip"; return; fi
    cd "$dir" && nohup ./"$@" >"$LOGS/$logf" 2>&1 &
    echo "[OK] start $sub"
    sleep 1
}

run_svc logservice     logservice.log     logservice     logservice.conf
run_svc uniquenamed    uniquenamed.log    uniquenamed    gamesys.conf
run_svc gauthd         authd.log          gauthd         gamesys.conf
run_svc gamedbd        gamedbd.log        gamedbd        gamesys.conf
run_svc gacd           gacd.log           gacd           gamesys.conf
run_svc gfactiond      gfactiond.log      gfactiond      gamesys.conf
run_svc gdeliveryd     gdeliveryd.log     gdeliveryd     gamesys.conf
run_svc glinkd         glinkd.log         glinkd         gamesys.conf 1

GAMED="/$ServerDir/gamed"
if [ ! -d "$GAMED" ]; then echo "[ERR] $GAMED not found"; exit 1; fi
cd "$GAMED"
nohup ./gs gs01 gsalias.conf gmserver.conf gs.conf >"$LOGS/gs01.log" 2>&1 &
echo "[OK] start gs01"; sleep 5
nohup ./gs is61 gsalias.conf gmserver.conf gs.conf >"$LOGS/is61.log" 2>&1 &
echo "[OK] start is61"; sleep 3
nohup ./gs is38 gsalias.conf gmserver.conf gs.conf >"$LOGS/is38.log" 2>&1 &
echo "[OK] start is38"; sleep 2

echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
echo "[OK] === Start finished ==="
`;
}

function buildStopScript(serverDir) {
    serverDir = sanitizeServerDir(serverDir);
    return `#!/bin/bash
ServerDir='${serverDir}'

if [ -x "/$ServerDir/gamedbd/gamedbd" ]; then
    cd "/$ServerDir/gamedbd" && ./gamedbd gamesys.conf exportclsconfig 2>/dev/null
    echo "[OK] exportclsconfig done"; sleep 1
fi

for p in gs glinkd gdeliveryd gfactiond gacd gamedbd uniquenamed logservice gauthd; do
    if pkill -9 -x "$p" 2>/dev/null; then echo "[OK] killed $p"; else echo "[--] $p not running"; fi
done

sync
echo "[OK] === Stop finished ==="
`;
}

function parseMonitorRaw(raw) {
    const sec = {}; let cur = null;
    for (const line of String(raw || '').split('\n')) {
        const m = line.match(/^__([A-Z]+)__$/);
        if (m) { cur = m[1]; sec[cur] = []; continue; }
        if (cur) sec[cur].push(line);
    }
    const out = { cpu: 0, mem: { used: 0, total: 0, pct: 0 }, disk: {}, uptime: '', load: '', gs_procs: [] };
    if (sec.CPU?.[0]) {
        const m = sec.CPU[0].match(/(\d+(?:\.\d+)?)\s*id/);
        if (m) out.cpu = Math.max(0, Math.min(100, +(100 - parseFloat(m[1])).toFixed(1)));
    }
    if (sec.MEM?.[0]) {
        const p = sec.MEM[0].split(/\s+/);
        out.mem.total = +p[1] || 0;
        out.mem.used  = +p[2] || 0;
        if (out.mem.total) out.mem.pct = Math.round(out.mem.used / out.mem.total * 100);
    }
    if (sec.DISK?.[0]) {
        const p = sec.DISK[0].split(/\s+/);
        out.disk = { size: p[1], used: p[2], avail: p[3], pct: parseInt(p[4]) || 0 };
    }
    if (sec.UP?.[0])   out.uptime = sec.UP[0].trim();
    if (sec.LOAD?.[0]) out.load   = sec.LOAD[0].trim().split(' ').slice(0, 3).join(' ');
    if (sec.GS)        out.gs_procs = sec.GS.filter(l => l.trim()).map(l => l.trim());
    return out;
}

const AGENT_RUNTIME = fs.readFileSync(path.join(__dirname, 'agent_runtime.sh'), 'utf8');

function buildInstallScript({ serverUrl, mid, token }) {
    const safeServer = String(serverUrl).replace(/'/g, "");
    const safeMid    = String(mid).replace(/'/g, "");
    const safeToken  = String(token).replace(/'/g, "");
    return `#!/bin/bash
# License Manager Agent — installer
set -e
if [ "$EUID" -ne 0 ]; then echo "Cần chạy bằng root."; exit 1; fi

SERVER='${safeServer}'
MID='${safeMid}'
TOKEN='${safeToken}'
DIR=/etc/lm-agent

mkdir -p "$DIR"
chmod 700 "$DIR"

cat > "$DIR/config" <<CFG
SERVER='$SERVER'
MID='$MID'
TOKEN='$TOKEN'
AGENT_VER='1.1'
CFG
chmod 600 "$DIR/config"

# Tải runtime mới nhất từ server (luôn cập nhật khi reinstall)
curl -fsSL "$SERVER/agent/runtime.sh?mid=$MID&token=$TOKEN" -o "$DIR/agent.sh"
chmod 700 "$DIR/agent.sh"

if command -v systemctl >/dev/null 2>&1; then
    cat > /etc/systemd/system/lm-agent.service <<UNIT
[Unit]
Description=License Manager Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$DIR/agent.sh
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable lm-agent.service >/dev/null 2>&1 || true
    systemctl restart lm-agent.service
    echo "[OK] lm-agent đã cài đặt + chạy qua systemd"
else
    pkill -f "$DIR/agent.sh" 2>/dev/null || true
    nohup "$DIR/agent.sh" >/dev/null 2>&1 &
    ( crontab -l 2>/dev/null | grep -v 'lm-agent/agent.sh' ; echo "@reboot $DIR/agent.sh >/dev/null 2>&1 &" ) | crontab -
    echo "[OK] lm-agent đã cài đặt + chạy (nohup + cron @reboot)"
fi

echo "[OK] Hoàn tất. Kiểm tra log: tail -f /var/log/lm-agent.log"
`;
}

function buildUninstallScript() {
    return `#!/bin/bash
set -e
if [ "$EUID" -ne 0 ]; then echo "Cần chạy bằng root."; exit 1; fi
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop    lm-agent.service 2>/dev/null || true
    systemctl disable lm-agent.service 2>/dev/null || true
    rm -f /etc/systemd/system/lm-agent.service
    systemctl daemon-reload
fi
pkill -f /etc/lm-agent/agent.sh 2>/dev/null || true
( crontab -l 2>/dev/null | grep -v 'lm-agent/agent.sh' ) | crontab - 2>/dev/null || true
rm -rf /etc/lm-agent
echo "[OK] lm-agent đã được gỡ bỏ"
`;
}

module.exports = {
    AGENT_RUNTIME,
    getOrCreateToken, regenerateToken, verifyToken,
    listInstalled, infoFor, uninstall, setServerDir, getServerDir,
    recordHeartbeat, setMonitor, getMonitor, parseMonitorRaw,
    enqueueCommand, pollCommands, pollOne, recordResult, takeResult,
    buildStartScript, buildStopScript,
    buildInstallScript, buildUninstallScript,
};
