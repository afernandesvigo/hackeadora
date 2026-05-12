#!/usr/bin/env bash
# watch_generali_batch.sh — heartbeat por Telegram del batch Generali
#
# Uso:  bash tools/watch_generali_batch.sh <batch_dir> [interval_sec]
# Env:  INTERVAL  (default 1800s = 30 min)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BATCH_DIR="${1:?falta batch dir, p.ej. output/batch_generali_20260510_193138}"
INTERVAL="${2:-${INTERVAL:-1800}}"

# Carga TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID
# shellcheck disable=SC1091
source "$SCRIPT_DIR/config.env"

if [[ -z "${TELEGRAM_BOT_TOKEN:-}" || -z "${TELEGRAM_CHAT_ID:-}" ]]; then
  echo "TELEGRAM_BOT_TOKEN o TELEGRAM_CHAT_ID no configurados — abortando" >&2
  exit 1
fi

DB="$SCRIPT_DIR/data/recon.db"
BATCH_LOG="$BATCH_DIR/batch.log"

send_tg() {
  curl -s -X POST \
    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d chat_id="${TELEGRAM_CHAT_ID}" \
    -d parse_mode="Markdown" \
    -d disable_web_page_preview="true" \
    --data-urlencode "text=$1" \
    -o /dev/null 2>/dev/null || true
}

stats_findings_by_sev() {
  sqlite3 "$DB" \
    "SELECT severity || ':' || COUNT(*)
     FROM findings f JOIN domains d ON f.domain_id=d.id
     WHERE d.domain IN ('generali.fr','lamedicale.fr','apigee.net')
     GROUP BY severity
     ORDER BY CASE severity
       WHEN 'critical' THEN 1 WHEN 'high' THEN 2
       WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END;" 2>/dev/null \
    | tr '\n' ' '
}

count_running() {
  ps -ef | grep -E "recon.sh.*generali|recon.sh.*lamedicale|recon.sh.*apigee" \
    | grep -v grep | wc -l
}

# Ping inicial
send_tg "🔭 *Generali batch — monitor activo*
📂 \`$(basename "$BATCH_DIR")\`
⏱ Heartbeat cada $((INTERVAL/60))m
📅 $(date '+%Y-%m-%d %H:%M:%S')"

PREV_OK=0
PREV_FAIL=0
PREV_FINDINGS_HC=0

while true; do
  # ── Detección de fin ───────────────────────
  if grep -q "DONE" "$BATCH_LOG" 2>/dev/null; then
    OK=$(grep -c "COMPLETADO" "$BATCH_LOG" 2>/dev/null); OK=${OK:-0}
    FAIL=$(grep -c "FALLÓ" "$BATCH_LOG" 2>/dev/null); FAIL=${FAIL:-0}
    SEV=$(stats_findings_by_sev)
    send_tg "🏁 *Generali batch — DONE*
✅ OK: ${OK}   ❌ FAIL: ${FAIL}
📊 Findings: ${SEV:-0}
📂 \`$(basename "$BATCH_DIR")\`
📅 $(date '+%Y-%m-%d %H:%M:%S')"
    exit 0
  fi

  # ── Detección de muerte silenciosa (no DONE pero sin recon.sh vivo) ──
  RUNNING=$(count_running)
  if [[ "$RUNNING" == "0" ]]; then
    # esperar 60s y revalidar (puede ser ventana entre targets)
    sleep 60
    RUNNING=$(count_running)
    if [[ "$RUNNING" == "0" ]] && ! grep -q "DONE" "$BATCH_LOG" 2>/dev/null; then
      OK=$(grep -c "COMPLETADO" "$BATCH_LOG" 2>/dev/null); OK=${OK:-0}
      FAIL=$(grep -c "FALLÓ" "$BATCH_LOG" 2>/dev/null); FAIL=${FAIL:-0}
      send_tg "💀 *Generali batch — MUERTO sin DONE*
Sin procesos vivos pero el batch.log no tiene marca de fin.
✅ OK: ${OK}   ❌ FAIL: ${FAIL}
📂 \`$(basename "$BATCH_DIR")\`
📅 $(date '+%Y-%m-%d %H:%M:%S')"
      exit 1
    fi
  fi

  # ── Heartbeat ──────────────────────────────
  STARTED=$(grep -cE "^\[\+\]" "$BATCH_LOG" 2>/dev/null); STARTED=${STARTED:-0}
  OK=$(grep -c "COMPLETADO" "$BATCH_LOG" 2>/dev/null); OK=${OK:-0}
  FAIL=$(grep -c "FALLÓ" "$BATCH_LOG" 2>/dev/null); FAIL=${FAIL:-0}
  HC=$(sqlite3 "$DB" \
    "SELECT COUNT(*) FROM findings f JOIN domains d ON f.domain_id=d.id
     WHERE d.domain IN ('generali.fr','lamedicale.fr','apigee.net')
       AND severity IN ('high','critical');" 2>/dev/null); HC=${HC:-0}
  LOAD=$(uptime | awk -F'load average:' '{print $2}' | xargs)
  SEV=$(stats_findings_by_sev)

  DELTA_OK=$((OK - PREV_OK))
  DELTA_FAIL=$((FAIL - PREV_FAIL))
  DELTA_HC=$((HC - PREV_FINDINGS_HC))

  send_tg "📈 *Generali — heartbeat*
🚀 Iniciados: ${STARTED}/27
✅ OK: ${OK} (+${DELTA_OK})   ❌ FAIL: ${FAIL} (+${DELTA_FAIL})
🔄 recon.sh vivos: ${RUNNING}
🔥 high/critical: ${HC} (+${DELTA_HC})
📊 Sev: ${SEV:-0}
🖥 Load: ${LOAD}
📅 $(date '+%Y-%m-%d %H:%M:%S')"

  PREV_OK=$OK
  PREV_FAIL=$FAIL
  PREV_FINDINGS_HC=$HC

  sleep "$INTERVAL"
done
