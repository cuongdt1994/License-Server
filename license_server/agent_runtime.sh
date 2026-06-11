#!/bin/bash
# License Manager Agent Runtime
CONF=/etc/lm-agent/config
[ -r "$CONF" ] || { echo "[FATAL] no config $CONF"; exit 1; }
. "$CONF"
AGENT_VER="${AGENT_VER:-1.1}"
LOG=/var/log/lm-agent.log
exec >>"$LOG" 2>&1

UA="lm-agent/$AGENT_VER"
H_AUTH="Authorization: Bearer $TOKEN"
H_MID="X-MID: $MID"
H_VER="X-Agent-Ver: $AGENT_VER"

post_monitor() {
    local CPU MEM DISK UP LOAD GS BLOB
    CPU=$(top -bn1 | grep -E '^%?Cpu' | head -1)
    MEM=$(free -m | grep -E '^Mem')
    DISK=$(df -h / | tail -1)
    UP=$(uptime)
    LOAD=$(cat /proc/loadavg)
    GS=$(ps -eo pid,pcpu,pmem,comm,args 2>/dev/null \
        | grep -E ' (gs|glinkd|gdeliveryd|gfactiond|gacd|gamedbd|uniquenamed|gauthd|logservice)( |$)' \
        | grep -v grep | head -40)

    BLOB=$(printf '__CPU__\n%s\n__MEM__\n%s\n__DISK__\n%s\n__UP__\n%s\n__LOAD__\n%s\n__GS__\n%s\n' \
        "$CPU" "$MEM" "$DISK" "$UP" "$LOAD" "$GS")

    curl -fsS -A "$UA" -H "$H_AUTH" -H "$H_MID" -H "$H_VER" \
         -H 'Content-Type: text/plain' --data-binary "$BLOB" \
         --max-time 10 "$SERVER/agent/monitor" >/dev/null 2>&1 || true
}

submit_result() {
    local CID="$1" CODE="$2" OUT_FILE="$3" ERR_FILE="$4"
    curl -fsS -A "$UA" -H "$H_AUTH" -H "$H_MID" -H "$H_VER" \
         --max-time 20 \
         -F "id=$CID" -F "code=$CODE" \
         -F "stdout=@$OUT_FILE;type=text/plain" \
         -F "stderr=@$ERR_FILE;type=text/plain" \
         "$SERVER/agent/result" >/dev/null 2>&1 || true
}

run_one() {
    local CID="$1" SCRIPT_FILE="$2" TIMEOUT_SEC="${3:-300}"
    local OUT_FILE ERR_FILE CODE
    OUT_FILE=$(mktemp); ERR_FILE=$(mktemp)

    case "$TIMEOUT_SEC" in ''|*[!0-9]*) TIMEOUT_SEC=300;; esac
    [ "$TIMEOUT_SEC" -lt 5 ] && TIMEOUT_SEC=5
    [ "$TIMEOUT_SEC" -gt 300 ] && TIMEOUT_SEC=300

    if command -v timeout >/dev/null 2>&1; then
        timeout "${TIMEOUT_SEC}s" bash "$SCRIPT_FILE" >"$OUT_FILE" 2>"$ERR_FILE"
    else
        bash "$SCRIPT_FILE" >"$OUT_FILE" 2>"$ERR_FILE"
    fi
    CODE=$?
    submit_result "$CID" "$CODE" "$OUT_FILE" "$ERR_FILE"
    rm -f "$SCRIPT_FILE" "$OUT_FILE" "$ERR_FILE"
}

# Long-poll loop. Server returns 200 + header X-Cmd-Id + body = script,
# or 204 when no work after long-poll window.
LAST_MON=0
while true; do
    NOW=$(date +%s)
    if [ $((NOW - LAST_MON)) -ge 30 ]; then post_monitor; LAST_MON=$NOW; fi

    CMD_DIR=$(mktemp -d)
    HTTP_CODE=$(curl -sS -D "$CMD_DIR/headers" -o "$CMD_DIR/body" -w '%{http_code}' \
        -A "$UA" -H "$H_AUTH" -H "$H_MID" -H "$H_VER" \
        --max-time 35 "$SERVER/agent/poll" 2>/dev/null || echo "000")

    if [ "$HTTP_CODE" = "200" ] && [ -s "$CMD_DIR/body" ]; then
        CID=$(awk 'BEGIN{IGNORECASE=1} /^X-Cmd-Id:/ {sub(/^[^:]*: */,""); sub(/\r$/,""); print; exit}' "$CMD_DIR/headers")
        CTIME=$(awk 'BEGIN{IGNORECASE=1} /^X-Cmd-Timeout-Seconds:/ {sub(/^[^:]*: */,""); sub(/\r$/,""); print; exit}' "$CMD_DIR/headers")
        if [ -n "$CID" ]; then
            mv "$CMD_DIR/body" "$CMD_DIR/script.sh"
            ( run_one "$CID" "$CMD_DIR/script.sh" "$CTIME"; rm -rf "$CMD_DIR" ) &
            continue
        fi
    fi
    rm -rf "$CMD_DIR" 2>/dev/null || true

    [ "$HTTP_CODE" != "204" ] && sleep 5
done
