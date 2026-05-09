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
  local PROXY_FLAG="$5"  # ignorado: _h_* auto-inyecta proxy desde globales

  local SUBDOMAIN
  SUBDOMAIN=$(echo "$URL" | sed 's|https\?://||;s|/.*||')

  while IFS= read -r ORIGIN; do
    [[ -z "$ORIGIN" ]] && continue

    local RESPONSE ACAO ACAC ACAM
    _h_head "$URL" \
      -H "Origin: ${ORIGIN}" \
      -H "Access-Control-Request-Method: GET"
    RESPONSE="$HTTP_LAST_HEADERS"

    ACAO=$(echo "$RESPONSE" | grep -i "Access-Control-Allow-Origin:" | tr -d '\r')
    ACAC=$(echo "$RESPONSE" | grep -i "Access-Control-Allow-Credentials:" | tr -d '\r')
    ACAM=$(echo "$RESPONSE" | grep -i "Access-Control-Allow-Methods:" | tr -d '\r')

    [[ -z "$ACAO" ]] && continue

    # CF Access refleja el Origin en su propio 302 — no es la app.
    is_cf_access_response "$RESPONSE" && continue

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
      # ── Confirmación de body: ¿se puede leer token/datos sensibles? ──
      # Cuando CORS+credentials está activo, hacer GET real (no solo HEAD)
      # y ver si la respuesta contiene tokens robables cross-origin.
      local BODY_CONFIRM=""
      if echo "$ACAC" | grep -qi "true" && [[ "$SEVERITY" == "high" ]]; then
        local BODY_RESP
        _h_get "$URL" -H "Origin: ${ORIGIN}"
        BODY_RESP="${HTTP_LAST_BODY:0:2000}"

        # Detectar tokens en el body (CSRF, session, JWT)
        local TOKEN_FOUND=""
        echo "$BODY_RESP" | grep -qP '"csrf_token"\s*:' && \
          TOKEN_FOUND="csrf_token readable (Drupal/CMS)"
        echo "$BODY_RESP" | grep -qP '"X-CSRF-Token"\s*:' && \
          TOKEN_FOUND="X-CSRF-Token readable"
        echo "$BODY_RESP" | grep -qP '"token"\s*:\s*"[A-Za-z0-9_\-\.]{20,}"' && \
          TOKEN_FOUND="API token readable"
        echo "$BODY_RESP" | grep -qP '"access_token"\s*:' && \
          TOKEN_FOUND="access_token readable"
        echo "$BODY_RESP" | grep -qP 'eyJ[A-Za-z0-9_-]{20,}' && \
          TOKEN_FOUND="JWT readable"

        if [[ -n "$TOKEN_FOUND" ]]; then
          SEVERITY="critical"
          BODY_CONFIRM=" | BODY CONFIRM: ${TOKEN_FOUND}"
          log_warn "    ⚠️  Token robable cross-origin: $TOKEN_FOUND"
        fi
      fi

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
          "$URL" "cors_misconfig" "$DETAIL${BODY_CONFIRM} | Origin: $ORIGIN | $ACAO"

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

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
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

  # Endpoints específicos con tokens en body (Drupal, WordPress, CMS)
  # Estos son los más valiosos: CORS+credentials permite leer CSRF tokens
  if [[ -s "$OUT_DIR/subs_alive.txt" ]]; then
    while IFS= read -r SUB; do
      [[ -z "$SUB" ]] && continue
      for TOKEN_PATH in \
        "/session/token" \
        "/user/register?_format=json" \
        "/user/login?_format=json" \
        "/rest/session/token" \
        "/wp-json/wp/v2/users/me" \
        "/api/session" \
        "/api/v1/me" \
        "/api/user/me"; do
        echo "https://${SUB}${TOKEN_PATH}"
      done
    done < "$OUT_DIR/subs_alive.txt" >> "$TARGETS"
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

  log_info "CORS check sobre $TOTAL endpoints (paralelo, max 10 workers)..."

  local MAX_WORKERS=10
  local PIDS=()

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    http_should_skip "$URL" 2>/dev/null && continue
    (
      _test_cors_url "$URL" "$DOMAIN_ID" "$DOMAIN" "$DOMAIN" "$CURL_PROXY"
    ) &
    PIDS+=($!)
    if [[ ${#PIDS[@]} -ge $MAX_WORKERS ]]; then
      wait "${PIDS[0]}" 2>/dev/null || true
      PIDS=("${PIDS[@]:1}")
    fi
  done < "$TARGETS"
  wait "${PIDS[@]}" 2>/dev/null || true

  rm -f "$TARGETS"

  local FOUND
  FOUND=$(_db_query "SELECT COUNT(DISTINCT target) FROM findings
    WHERE domain_id=${DOMAIN_ID} AND type='cors';" 2>/dev/null || echo 0)
  log_ok "$MODULE_DESC completado: $FOUND CORS issues en $TOTAL endpoints"
}
