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

# ── Función base — split automático si supera 4096 chars ─────
_telegram_send() {
  local TEXT="$1"

  if [[ -z "${TELEGRAM_BOT_TOKEN:-}" ]] || [[ -z "${TELEGRAM_CHAT_ID:-}" ]]; then
    log_warn "Telegram no configurado (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID vacíos)"
    return 0
  fi

  local MAX=4000  # margen bajo el límite de 4096 de Telegram
  local LEN=${#TEXT}

  # Función interna: envía un chunk, intenta Markdown; si falla, reintenta sin formato
  _tg_send_chunk() {
    local CHUNK="$1"
    local RESP
    RESP=$(curl -s -X POST \
      "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
      -d chat_id="${TELEGRAM_CHAT_ID}" \
      -d parse_mode="Markdown" \
      -d disable_web_page_preview="true" \
      --data-urlencode "text=${CHUNK}" 2>/dev/null)
    # Si la API devuelve ok:false (Markdown inválido), reintenta sin parse_mode
    if echo "$RESP" | grep -q '"ok":false'; then
      curl -s -X POST \
        "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="${TELEGRAM_CHAT_ID}" \
        -d disable_web_page_preview="true" \
        --data-urlencode "text=${CHUNK}" \
        -o /dev/null 2>/dev/null || true
    fi
  }

  if [[ "$LEN" -le "$MAX" ]]; then
    _tg_send_chunk "$TEXT"
  else
    # Mensaje largo — partir en chunks
    local OFFSET=0
    local PART=1
    local TOTAL=$(( (LEN + MAX - 1) / MAX ))
    while [[ "$OFFSET" -lt "$LEN" ]]; do
      local CHUNK="${TEXT:$OFFSET:$MAX}"
      local HEADER=""
      [[ "$TOTAL" -gt 1 ]] && HEADER="(${PART}/${TOTAL})"$'\n'
      _tg_send_chunk "${HEADER}${CHUNK}"
      OFFSET=$(( OFFSET + MAX ))
      (( PART++ ))
    done
  fi
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
