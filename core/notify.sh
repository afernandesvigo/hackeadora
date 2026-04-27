#!/usr/bin/env bash
# ============================================================
#  core/notify.sh — Notificaciones Telegram
#  Se incluye con: source core/notify.sh
# ============================================================

# Requiere: TELEGRAM_BOT_TOKEN y TELEGRAM_CHAT_ID en config.env

# Emoji por tipo
_EMOJI_TAKEOVER="⚠️"
_EMOJI_VULN="🔴"
_EMOJI_NEW_SUB="🌐"
_EMOJI_NEW_URL="🔗"
_EMOJI_INFO="ℹ️"
_EMOJI_SCAN_START="🚀"
_EMOJI_SCAN_END="✅"

# ── Función base ─────────────────────────────────────────────
_telegram_send() {
  local TEXT="$1"

  if [[ -z "${TELEGRAM_BOT_TOKEN:-}" ]] || [[ -z "${TELEGRAM_CHAT_ID:-}" ]]; then
    log_warn "Telegram no configurado (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID vacíos)"
    return 0
  fi

  curl -s -X POST \
    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d chat_id="${TELEGRAM_CHAT_ID}" \
    -d parse_mode="Markdown" \
    -d disable_web_page_preview="true" \
    --data-urlencode "text=${TEXT}" \
    -o /dev/null \
    --fail \
  || log_warn "Error enviando mensaje a Telegram"
}

# ── Notificaciones tipadas ────────────────────────────────────

notify_scan_start() {
  local DOMAIN="$1"
  _telegram_send "${_EMOJI_SCAN_START} *Scan iniciado*
\`${DOMAIN}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')"
}

notify_scan_end() {
  local DOMAIN="$1"
  local SUBS_COUNT="$2"
  local URLS_COUNT="$3"
  _telegram_send "${_EMOJI_SCAN_END} *Scan completado*
\`${DOMAIN}\`
🌐 Subdominios: ${SUBS_COUNT}
🔗 URLs: ${URLS_COUNT}
📅 $(date '+%Y-%m-%d %H:%M:%S')"
}

notify_takeover() {
  local SUBDOMAIN="$1"
  local SERVICE="$2"
  local DETAIL="${3:-}"
  _telegram_send "${_EMOJI_TAKEOVER} *Posible Subdomain Takeover*
🎯 Subdominio: \`${SUBDOMAIN}\`
🛠️ Servicio: \`${SERVICE}\`
📋 Detalle: ${DETAIL}
📅 $(date '+%Y-%m-%d %H:%M:%S')"
}

notify_nuclei_finding() {
  local DOMAIN="$1"
  local TEMPLATE="$2"
  local SEVERITY="$3"
  local TARGET="$4"
  local DETAIL="${5:-}"

  local EMOJI
  case "${SEVERITY,,}" in
    critical) EMOJI="🔴🔴" ;;
    high)     EMOJI="🔴" ;;
    medium)   EMOJI="🟠" ;;
    low)      EMOJI="🟡" ;;
    *)        EMOJI="⚪" ;;
  esac

  _telegram_send "${EMOJI} *Nuclei Finding — ${SEVERITY^^}*
🌐 Dominio: \`${DOMAIN}\`
📌 Template: \`${TEMPLATE}\`
🎯 Target: \`${TARGET}\`
📋 ${DETAIL}
📅 $(date '+%Y-%m-%d %H:%M:%S')"
}

notify_new_subdomain() {
  local DOMAIN="$1"
  local SUBDOMAIN="$2"
  _telegram_send "${_EMOJI_NEW_SUB} *Nuevo subdominio*
\`${SUBDOMAIN}\` → \`${DOMAIN}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')"
}

notify_new_url() {
  local DOMAIN="$1"
  local URL="$2"
  _telegram_send "${_EMOJI_NEW_URL} *Nueva URL encontrada*
🌐 ${DOMAIN}
🔗 \`${URL}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')"
}

notify_error() {
  local MSG="$1"
  _telegram_send "❌ *Error en ReconFlow*
${MSG}
📅 $(date '+%Y-%m-%d %H:%M:%S')"
}

# ── Test de conexión ──────────────────────────────────────────
notify_test() {
  _telegram_send "🧪 *ReconFlow — Test de conexión OK*
📅 $(date '+%Y-%m-%d %H:%M:%S')"
  echo "Mensaje de prueba enviado a Telegram"
}
