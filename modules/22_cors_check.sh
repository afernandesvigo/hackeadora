#!/usr/bin/env bash
# ============================================================
#  modules/22_cors_check.sh
#  Fase 22: CORS Misconfiguration checker dedicado
#
#  Técnicas:
#    - Origin reflection (cualquier origen aceptado)
#    - Null origin
#    - Subdomain wildcard (evil.target.com)
#    - Pre-domain bypass (eviltarget.com)
#    - HTTPS→HTTP downgrade
#    - Credenciales + wildcard (critical)
#
#  Referencias:
#    - PortSwigger Web Security Academy
#    - EdOverflow bugbounty-cheatsheet/cors
#    - HackerOne top CORS reports
# ============================================================

MODULE_NAME="cors_check"
MODULE_DESC="CORS Misconfiguration checker"

# ── Generar origins de test para un dominio ───────────────────
_cors_origins() {
  local DOMAIN="$1"   # app.empresa.com
  local ROOT="$2"     # empresa.com

  cat << ORIGINS
https://evil.com
null
https://evil.${DOMAIN}
https://${DOMAIN}.evil.com
https://not${DOMAIN}
https://evil.com%0d%0a
https://${ROOT}.evil.com
http://${DOMAIN}
https://sub.${ROOT}
ORIGINS
}

# ── Test CORS sobre una URL ───────────────────────────────────
_test_cors_url() {
  local URL="$1"
  local DOMAIN_ID="$2"
  local DOMAIN="$3"
  local ROOT_DOMAIN="$4"
  local PROXY_FLAG="$5"

  local SUBDOMAIN
  SUBDOMAIN=$(echo "$URL" | sed 's|https\?://||;s|/.*||')

  while IFS= read -r ORIGIN; do
    [[ -z "$ORIGIN" ]] && continue

    local RESPONSE ACAO ACAC ACAM
    RESPONSE=$(curl -sI --max-time 8 \
      -H "Origin: ${ORIGIN}" \
      -H "Access-Control-Request-Method: GET" \
      ${PROXY_FLAG} \
      "$URL" 2>/dev/null)

    ACAO=$(echo "$RESPONSE" | grep -i "Access-Control-Allow-Origin:" | tr -d '\r')
    ACAC=$(echo "$RESPONSE" | grep -i "Access-Control-Allow-Credentials:" | tr -d '\r')
    ACAM=$(echo "$RESPONSE" | grep -i "Access-Control-Allow-Methods:" | tr -d '\r')

    [[ -z "$ACAO" ]] && continue

    # Determinar si es vulnerable
    local VULN=false
    local SEVERITY="low"
    local DETAIL=""

    # Caso 1: refleja el origen exacto
    if echo "$ACAO" | grep -qF "$ORIGIN"; then
      VULN=true
      DETAIL="Refleja origen: $ORIGIN"
      SEVERITY="medium"

      # Caso crítico: refleja origen + Allow-Credentials: true
      if echo "$ACAC" | grep -qi "true"; then
        SEVERITY="high"
        DETAIL="Refleja origen + credentials:true → posible robo de sesión"
      fi
    fi

    # Caso 2: wildcard con credentials (siempre crítico si se puede combinar)
    if echo "$ACAO" | grep -qF "*" && echo "$ACAC" | grep -qi "true"; then
      VULN=true
      SEVERITY="high"
      DETAIL="Wildcard + credentials:true (spec violation)"
    fi

    # Caso 3: null origin aceptado
    if [[ "$ORIGIN" == "null" ]] && echo "$ACAO" | grep -qi "null"; then
      VULN=true
      SEVERITY="medium"
      DETAIL="Null origin aceptado → explotable desde iframe sandbox"
      echo "$ACAC" | grep -qi "true" && SEVERITY="high"
    fi

    if $VULN; then
      log_warn "  ⚡ CORS [$SEVERITY]: $URL"
      log_warn "    Origin: $ORIGIN"
      log_warn "    ACAO: $ACAO"
      [[ -n "$ACAC" ]] && log_warn "    ACAC: $ACAC"

      local FINDING_KEY="${URL}|${ORIGIN}"
      local BEFORE
      BEFORE=$(sqlite3 "$DB_PATH" \
        "SELECT COUNT(*) FROM findings
         WHERE domain_id=${DOMAIN_ID} AND target='${URL//\'/\'\'}' AND type='cors'
         AND detail LIKE '%${ORIGIN//%/}%';" 2>/dev/null || echo "1")

      if [[ "${BEFORE:-1}" == "0" ]]; then
        db_add_finding "$DOMAIN_ID" "cors" "$SEVERITY" \
          "$URL" "cors_misconfig" "$DETAIL | Origin: $ORIGIN | $ACAO"

        _telegram_send "🌐 *CORS Misconfiguration*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📋 Severidad: \`${SEVERITY^^}\`
🎯 Origin: \`${ORIGIN}\`
📊 ${ACAO}
${ACAC:+🔑 ${ACAC}}
💡 ${DETAIL}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
      fi

      # Solo reportar el primer origen vulnerable por URL — no spamear
      return 0
    fi

  done < <(_cors_origins "$SUBDOMAIN" "$DOMAIN")
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 22 — $MODULE_DESC: $DOMAIN"

  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  source "$(dirname "$0")/../core/http_analyzer.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  # Targets: endpoints de API + subdominios alive + URLs con parámetros
  local TARGETS="$OUT_DIR/.cors_targets.txt"
  > "$TARGETS"

  # APIs (los más jugosos para CORS)
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (url LIKE '%/api/%' OR url LIKE '%/v1/%' OR url LIKE '%/v2/%'
            OR url LIKE '%/graphql%' OR url LIKE '%/rest/%')
     ORDER BY first_seen DESC LIMIT 50;" 2>/dev/null >> "$TARGETS"

  # Subdominios alive raíz
  if [[ -s "$OUT_DIR/subs_alive.txt" ]]; then
    sed 's|^|https://|' "$OUT_DIR/subs_alive.txt" >> "$TARGETS"
  fi

  # Login forms y OAuth (críticos si CORS misconfigured)
  sqlite3 "$DB_PATH" \
    "SELECT url FROM login_forms WHERE domain_id=${DOMAIN_ID}
     AND login_type IN ('oauth','api_auth');" 2>/dev/null >> "$TARGETS"

  sort -u "$TARGETS" -o "$TARGETS"
  local TOTAL
  TOTAL=$(wc -l < "$TARGETS" | tr -d ' ')

  if [[ "$TOTAL" -eq 0 ]]; then
    log_info "Sin targets para CORS check"
    rm -f "$TARGETS"
    return
  fi

  log_info "CORS check sobre $TOTAL endpoints..."

  local CHECKED=0 FOUND=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    http_should_skip "$URL" 2>/dev/null && continue
    ((CHECKED++))
    (( CHECKED % 20 == 0 )) && log_info "[$CHECKED/$TOTAL] chequeados..."

    _test_cors_url "$URL" "$DOMAIN_ID" "$DOMAIN" "$DOMAIN" "$CURL_PROXY" && ((FOUND++))

  done < "$TARGETS"

  rm -f "$TARGETS"
  log_ok "$MODULE_DESC completado: $FOUND CORS issues en $CHECKED endpoints"
}
