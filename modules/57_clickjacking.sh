#!/usr/bin/env bash
# modules/57_clickjacking.sh — Tier 3.11 Clickjacking / framing audit
MODULE_NAME="clickjacking"
MODULE_DESC="Clickjacking — X-Frame-Options + CSP frame-ancestors"

_cj_finding() {
  db_add_finding "$1" "clickjacking" "$5" "$3" "$4" "$6" "${7:-low}" 2>/dev/null
  log_warn "  ⚡ [$5/${7:-low}] Clickjack $4: $3"
  # Sin Telegram para low-sev (mucho ruido potencial)
}

_cj_check() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"
  _h_get_noredirect "$URL" --connect-timeout 6
  local STATUS="$HTTP_LAST_STATUS"
  [[ "$STATUS" != "200" ]] && return 1

  local HEADERS="$HTTP_LAST_HEADERS"
  local XFO; XFO=$(echo "$HEADERS" | grep -i '^x-frame-options:' | head -1 | tr -d '\r')
  local CSP; CSP=$(echo "$HEADERS" | grep -i '^content-security-policy:' | head -1 | tr -d '\r')
  local FRAME_ANCESTORS=""
  [[ -n "$CSP" ]] && FRAME_ANCESTORS=$(echo "$CSP" | grep -oiE 'frame-ancestors[^;]*' | head -1)

  # Clickjackeable si: no XFO Y no frame-ancestors (o frame-ancestors '*')
  local PROTECTED=false
  if echo "$XFO" | grep -qiE 'DENY|SAMEORIGIN'; then
    PROTECTED=true
  fi
  if echo "$FRAME_ANCESTORS" | grep -qiE "(?:'self'|'none'|https?://[a-z0-9.-]+)" && \
     ! echo "$FRAME_ANCESTORS" | grep -q "'\*'\|frame-ancestors\s\+\*"; then
    PROTECTED=true
  fi

  if ! $PROTECTED; then
    # Solo flagear si la página es sensitive (login/admin/account/profile)
    if echo "$URL" | grep -qiE '/(login|signin|admin|account|profile|settings|dashboard|payment|checkout|transfer|2fa|otp|password)'; then
      _cj_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "clickjackable_sensitive_page" "medium" \
        "Sin X-Frame-Options ni CSP frame-ancestors → página sensitive frameable. Atacante puede iframe + UI redress para acciones autenticadas. XFO: '${XFO}', CSP frame-ancestors: '${FRAME_ANCESTORS}'" \
        "high"
      return 0
    fi
    # No-sensitive: low severity
    _cj_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "clickjackable" "low" \
      "Sin protección anti-framing. XFO/CSP frame-ancestors ausentes." \
      "medium"
  fi
  return 1
}

module_run() {
  local DOMAIN="$1" DOMAIN_ID="$2" OUT_DIR="$3"
  log_phase "Módulo 57 — $MODULE_DESC: $DOMAIN"
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null

  local CANDIDATES
  CANDIDATES=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls
    WHERE domain_id=${DOMAIN_ID}
      AND (url LIKE '%/login%' OR url LIKE '%/signin%' OR url LIKE '%/admin%'
           OR url LIKE '%/account%' OR url LIKE '%/profile%' OR url LIKE '%/settings%'
           OR url LIKE '%/dashboard%' OR url LIKE '%/payment%' OR url LIKE '%/checkout%'
           OR url LIKE '%/transfer%' OR url LIKE '%/2fa%' OR url LIKE '%/password%')
    LIMIT 30;" 2>/dev/null | sort -u)
  [[ -z "$CANDIDATES" ]] && { log_info "  Sin sensitive pages candidatas"; return 0; }
  local TOTAL=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    _cj_check "${URL%%\?*}" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$CANDIDATES"
  log_ok "$MODULE_DESC: $TOTAL clickjackable pages"
}
