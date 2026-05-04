#!/usr/bin/env bash
# ============================================================
#  modules/35_oidc_oauth_scan.sh
#  Fase 35: OIDC / OAuth2 Security Scanner
#
#  Técnicas (aprendidas en auditorías reales de BBP):
#
#  1. Open Redirect via Hostname Substring Bypass
#     → Server valida sourceURL/returnUrl con contains(".DOMAIN.")
#       en vez de endsWith(".DOMAIN"). Payload:
#       https://portal.DOMAIN.hackeadora-orp.invalid/
#       — el dominio atacante contiene ".DOMAIN." como substring
#     → Afecta: endpoints logout/signin con parámetros de redirect
#
#  2. Host Header Injection → OAuth2 sourceURL hijack
#     → El IdP construye sourceURL desde el header Host para el
#       flow de autenticación. Inyectando Host: portal.DOMAIN.evil
#       el sourceURL post-auth apunta al dominio del atacante.
#     → Afecta: Ilex Sign&Go, cualquier IdP que confíe en Host
#
#  3. OIDC State Parameter Not Enforced
#     → El endpoint /authorize acepta peticiones sin ?state=
#       RFC 6749 §10.12 requiere state para prevenir CSRF
#
#  4. Implicit Grant Still Enabled (deprecated — RFC 9700)
#     → response_types_supported incluye "token" o "id_token"
#       sin code. Tokens expuestos en URL fragment → logs/history
#
#  5. Sensitive Internal Scopes in Discovery
#     → scopes_supported expone identificadores internos:
#       RACF, listeRACF, hierarchie, isManager, loginAD, cnPrincipal,
#       roleLEA, portefeuille, employeeType, loginDisabled...
#
#  6. PKCE Not Required on Authorization Code Flow
#     → code_challenge_methods_supported ausente o vacío +
#       authorize acepta response_type=code sin code_challenge
#
#  Referencias:
#    OAuth 2.0 Security BCP: RFC 9700
#    OIDC Core 1.0: openid.net/specs/openid-connect-core-1_0.html
#    PortSwigger OAuth vulnerabilities
# ============================================================

MODULE_NAME="oidc_oauth_scan"
MODULE_DESC="OIDC/OAuth2 — substring bypass, host header injection, scope disclosure"

# ── Parámetros de redirect a probar ──────────────────────────
REDIRECT_PARAMS=(
  "sourceURL" "returnUrl" "ReturnUrl" "return_url" "returnTo"
  "next" "goto" "redirect" "redirect_uri" "url" "target"
  "continue" "redir" "destination" "back" "ref" "from"
  "successUrl" "failureUrl" "logoutUrl" "post_logout_redirect_uri"
)

# ── Scopes sensibles de sistemas internos ────────────────────
SENSITIVE_SCOPES=(
  "RACF" "listeRACF" "hierarchie" "isManager" "gef2"
  "loginAD" "cnPrincipal" "loginDisabled" "intermediaire"
  "employeeType" "partenaire" "roleLEA" "folio" "portefeuille"
  "listeGroupe" "telephoneNumber" "department" "managerDN"
  "sAMAccountName" "distinguishedName" "objectGUID"
)

# ── Helper: registrar finding ─────────────────────────────────
_oidc_finding() {
  local DOMAIN_ID="$1" DOMAIN="$2" URL="$3"
  local TYPE="$4" SEV="$5" DETAIL="$6" TEMPLATE="$7"

  local EXISTING
  EXISTING=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID} AND target='${URL//\'/\'\'}' AND type='oidc_oauth'
     AND template_id='${TEMPLATE}';" 2>/dev/null || echo 1)
  [[ "$EXISTING" != "0" ]] && return

  db_add_finding "$DOMAIN_ID" "oidc_oauth" "$SEV" \
    "$URL" "$TEMPLATE" "$DETAIL"

  local EMOJI="🔴"
  [[ "$SEV" == "medium" ]] && EMOJI="🟠"
  [[ "$SEV" == "low"    ]] && EMOJI="🟡"
  [[ "$SEV" == "info"   ]] && EMOJI="ℹ️"

  log_warn "  ⚡ OIDC/OAuth2 [$SEV] $TYPE: $URL"

  _telegram_send "${EMOJI} *OIDC/OAuth2 — ${TYPE}*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📋 Severidad: \`${SEV^^}\`
💡 ${DETAIL:0:300}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
}

# ══════════════════════════════════════════════════════════════
#  1 + 4 + 5 + 6: OIDC Discovery — análisis completo
# ══════════════════════════════════════════════════════════════
_scan_oidc_discovery() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3" PROXY="$4"

  local DISCOVERY_PATHS=(
    "/.well-known/openid-configuration"
    "/oauth/.well-known/openid-configuration"
    "/oauth2/.well-known/openid-configuration"
    "/auth/.well-known/openid-configuration"
    "/connect/.well-known/openid-configuration"
    "/IdPOAuth2/.well-known/openid-configuration"
    "/.well-known/oauth-authorization-server"
  )

  for DPATH in "${DISCOVERY_PATHS[@]}"; do
    local URL="${BASE}${DPATH}"
    local STATUS BODY
    STATUS=$(curl -sk --max-time 10 ${PROXY} \
      -o /tmp/.oidc_disc_$$ -w "%{http_code}" "$URL" 2>/dev/null)
    BODY=$(cat /tmp/.oidc_disc_$$ 2>/dev/null)
    rm -f /tmp/.oidc_disc_$$

    # Ilex Sign&Go: acepta perfil case-insensitive — probar variantes
    if [[ "$STATUS" == "400" || "$STATUS" == "404" ]]; then
      # Buscar profiles conocidos en DB (URLs crawleadas)
      local PROFILES
      PROFILES=$(sqlite3 "$DB_PATH" \
        "SELECT DISTINCT url FROM urls
         WHERE domain_id=${DOMAIN_ID}
           AND url LIKE '%${BASE}%'
           AND (url LIKE '%authorize%' OR url LIKE '%IdPOAuth2%')
         LIMIT 5;" 2>/dev/null | \
        grep -oP '(?<=authorize/)[^?&/]+' | sort -u | head -3)
      while IFS= read -r PROFILE; do
        [[ -z "$PROFILE" ]] && continue
        local PURL="${BASE}/IdPOAuth2/.well-known/openid-configuration/${PROFILE}"
        local PS PB
        PS=$(curl -sk --max-time 10 ${PROXY} \
          -o /tmp/.oidc_dp_$$ -w "%{http_code}" "$PURL" 2>/dev/null)
        PB=$(cat /tmp/.oidc_dp_$$ 2>/dev/null)
        rm -f /tmp/.oidc_dp_$$
        if [[ "$PS" == "200" ]] && echo "$PB" | grep -q "authorization_endpoint"; then
          BODY="$PB"; STATUS="200"; URL="$PURL"
          break
        fi
      done <<< "$PROFILES"
    fi

    [[ "$STATUS" != "200" ]] && continue
    echo "$BODY" | python3 -c "import json,sys; json.loads(sys.stdin.read())" 2>/dev/null || continue

    log_info "  [OIDC discovery] $URL"

    # ── Extraer campos clave ──────────────────────────────────
    local AUTHORIZE_URL RESPONSE_TYPES GRANT_TYPES SCOPES PKCE_METHODS
    AUTHORIZE_URL=$(echo "$BODY" | python3 -c \
      "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('authorization_endpoint',''))" 2>/dev/null)
    RESPONSE_TYPES=$(echo "$BODY" | python3 -c \
      "import json,sys; d=json.loads(sys.stdin.read()); print(' '.join(d.get('response_types_supported',[])))" 2>/dev/null)
    GRANT_TYPES=$(echo "$BODY" | python3 -c \
      "import json,sys; d=json.loads(sys.stdin.read()); print(' '.join(d.get('grant_types_supported',[])))" 2>/dev/null)
    SCOPES=$(echo "$BODY" | python3 -c \
      "import json,sys; d=json.loads(sys.stdin.read()); print(' '.join(d.get('scopes_supported',[])))" 2>/dev/null)
    PKCE_METHODS=$(echo "$BODY" | python3 -c \
      "import json,sys; d=json.loads(sys.stdin.read()); print(' '.join(d.get('code_challenge_methods_supported',[])))" 2>/dev/null)

    # ── Finding 4: Implicit grant ─────────────────────────────
    if echo "$RESPONSE_TYPES $GRANT_TYPES" | grep -qwi "token\|implicit"; then
      local IMPLICIT_TYPES
      IMPLICIT_TYPES=$(echo "$RESPONSE_TYPES" | tr ' ' '\n' | \
        grep -wi "token\|id_token\|implicit" | tr '\n' ' ')
      _oidc_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
        "Implicit grant enabled (deprecated RFC 9700)" "medium" \
        "response_types soportados: [${IMPLICIT_TYPES}] — tokens en URL fragment → logs/history" \
        "oidc_implicit_grant"
    fi

    # ── Finding 5: Sensitive scopes ───────────────────────────
    local FOUND_SENSITIVE=()
    for SCOPE in "${SENSITIVE_SCOPES[@]}"; do
      echo "$SCOPES" | grep -qw "$SCOPE" && FOUND_SENSITIVE+=("$SCOPE")
    done
    if [[ ${#FOUND_SENSITIVE[@]} -gt 0 ]]; then
      _oidc_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
        "Sensitive internal scopes in OIDC discovery" "medium" \
        "Scopes internos expuestos: [${FOUND_SENSITIVE[*]}] — revela esquema LDAP/AD/mainframe" \
        "oidc_sensitive_scopes"
    fi

    # ── Finding 6: PKCE not enforced ─────────────────────────
    if [[ -z "$PKCE_METHODS" ]] && [[ -n "$AUTHORIZE_URL" ]]; then
      # Verificar que el authorize acepta code sin PKCE
      local CLIENT_ID
      CLIENT_ID=$(sqlite3 "$DB_PATH" \
        "SELECT DISTINCT detail FROM findings
         WHERE domain_id=${DOMAIN_ID}
           AND detail LIKE '%client_id%'
         LIMIT 1;" 2>/dev/null | grep -oP '(?<=client_id=)[^&]+' | head -1)
      [[ -z "$CLIENT_ID" ]] && CLIENT_ID="test_client"

      local PKCE_STATUS
      PKCE_STATUS=$(curl -sk --max-time 8 ${PROXY} -o /dev/null \
        -w "%{http_code}" \
        "${AUTHORIZE_URL}?client_id=${CLIENT_ID}&response_type=code&redirect_uri=https%3A%2F%2Fexample.com&scope=openid" \
        2>/dev/null)

      if [[ "$PKCE_STATUS" == "302" || "$PKCE_STATUS" == "200" ]]; then
        _oidc_finding "$DOMAIN_ID" "$DOMAIN" "$AUTHORIZE_URL" \
          "PKCE not enforced on authorization code flow" "low" \
          "code_challenge_methods_supported ausente + authorize acepta code sin PKCE → authorization code interception" \
          "oidc_pkce_not_enforced"
      fi
    fi

    # ── Finding 3: State parameter not enforced ───────────────
    if [[ -n "$AUTHORIZE_URL" ]]; then
      _test_state_enforcement "$AUTHORIZE_URL" "$DOMAIN_ID" "$DOMAIN" "$PROXY"
    fi

    # ── Store authorize URL for host header test ──────────────
    if [[ -n "$AUTHORIZE_URL" ]]; then
      echo "$AUTHORIZE_URL" >> /tmp/.oidc_authorize_urls_${DOMAIN_ID}
    fi

    # Un discovery por subdomain es suficiente
    return 0
  done
}

# ══════════════════════════════════════════════════════════════
#  3: State parameter not enforced
# ══════════════════════════════════════════════════════════════
_test_state_enforcement() {
  local AUTHORIZE_URL="$1" DOMAIN_ID="$2" DOMAIN="$3" PROXY="$4"

  # Obtener un client_id válido de la DB o usar uno conocido
  local CLIENT_ID
  CLIENT_ID=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND url LIKE '%response_type%'
     LIMIT 1;" 2>/dev/null | grep -oP '(?<=client_id=)[^&]+' | head -1)
  [[ -z "$CLIENT_ID" ]] && return

  local REDIR_URI
  REDIR_URI=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND url LIKE '%code=%'
     LIMIT 1;" 2>/dev/null | sed 's|?.*||' | head -1)
  [[ -z "$REDIR_URI" ]] && REDIR_URI="https://example.com/callback"

  # Sin state
  local STATUS LOCATION
  STATUS=$(curl -sk --max-time 8 ${PROXY} -o /dev/null \
    -D /tmp/.oidc_state_hdr_$$ \
    -w "%{http_code}" \
    "${AUTHORIZE_URL}?client_id=${CLIENT_ID}&response_type=code&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$REDIR_URI'))" 2>/dev/null || echo "$REDIR_URI")&scope=openid" \
    2>/dev/null)
  LOCATION=$(grep -i "^location:" /tmp/.oidc_state_hdr_$$ | tr -d '\r' | head -1)
  rm -f /tmp/.oidc_state_hdr_$$

  # Si redirige al login sin error → state no requerido
  if [[ "$STATUS" == "302" ]] && echo "$LOCATION" | grep -qi "login\|auth\|chooseschema\|signin"; then
    _oidc_finding "$DOMAIN_ID" "$DOMAIN" "$AUTHORIZE_URL" \
      "OAuth2 state parameter not enforced" "medium" \
      "Authorize acepta requests sin ?state= — RFC 6749 §10.12 CSRF vector" \
      "oidc_state_not_enforced"
  fi
}

# ══════════════════════════════════════════════════════════════
#  1: Open Redirect via Hostname Substring Bypass
#
#  El servidor valida que la URL de redirect contenga ".DOMAIN."
#  como substring — pero no verifica que termine en ".DOMAIN".
#  Payload: https://portal.DOMAIN.hackeadora-orp.invalid/
#  → ".DOMAIN." aparece en el medio del hostname del atacante
# ══════════════════════════════════════════════════════════════
_test_substring_redirect_bypass() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3" PROXY="$4"

  # Dominio de prueba: contiene .DOMAIN. como substring pero no es DOMAIN
  # .invalid está reservado por IANA — nunca resolverá
  local BYPASS_URL="https://portal.${DOMAIN}.hackeadora-orp.invalid/"

  # Endpoints de logout/redirect comunes
  local LOGOUT_PATHS=(
    "/logout" "/signout" "/sign-out" "/auth/logout" "/user/logout"
    "/user/auth/logout" "/auth/logout.jsp" "/user/auth/signout"
    "/sso/logout" "/oauth/logout" "/connect/endsession"
    "/auth/endsession" "/session/end"
  )

  # También de DB
  local DB_LOGOUT_URLS
  DB_LOGOUT_URLS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (url LIKE '%logout%' OR url LIKE '%signout%' OR url LIKE '%sign-out%')
     LIMIT 10;" 2>/dev/null)

  local TESTED_URLS=()

  # Test sobre rutas canónicas
  for LPATH in "${LOGOUT_PATHS[@]}"; do
    TESTED_URLS+=("${BASE}${LPATH}")
  done

  # Añadir URLs de DB
  while IFS= read -r DURL; do
    [[ -n "$DURL" ]] && TESTED_URLS+=("$DURL")
  done <<< "$DB_LOGOUT_URLS"

  for ENDPOINT in "${TESTED_URLS[@]}"; do
    [[ -z "$ENDPOINT" ]] && continue

    # Para cada parámetro de redirect común
    for PARAM in "${REDIRECT_PARAMS[@]}"; do
      local TEST_URL="${ENDPOINT}?${PARAM}=$(python3 -c \
        "import urllib.parse; print(urllib.parse.quote('${BYPASS_URL}'))" 2>/dev/null || \
        echo "https%3A%2F%2Fportal.${DOMAIN}.hackeadora-orp.invalid%2F")"

      local STATUS LOCATION
      STATUS=$(curl -sk --max-time 8 ${PROXY} \
        -o /dev/null \
        -D /tmp/.oidc_orp_hdr_$$ \
        -w "%{http_code}" \
        "$TEST_URL" 2>/dev/null)
      LOCATION=$(grep -i "^location:" /tmp/.oidc_orp_hdr_$$ | tr -d '\r' | head -1)
      rm -f /tmp/.oidc_orp_hdr_$$

      # Confirmar: redirige a nuestra URL de bypass
      if [[ "$STATUS" == "301" || "$STATUS" == "302" || "$STATUS" == "303" ]]; then
        if echo "$LOCATION" | grep -qi "hackeadora-orp\.invalid"; then
          _oidc_finding "$DOMAIN_ID" "$DOMAIN" "$ENDPOINT" \
            "Open Redirect — Hostname Substring Bypass" "high" \
            "Param '${PARAM}' acepta redirect a ${BYPASS_URL} — validación con contains('.${DOMAIN}.') bypasseable. Attach: ${LOCATION}" \
            "open_redirect_substring_bypass"
          break 2
        fi
      fi
    done
  done
}

# ══════════════════════════════════════════════════════════════
#  2: Host Header Injection → OAuth2 sourceURL hijack
#
#  El IdP construye el sourceURL del flow OAuth2 usando el header
#  Host en vez de una URL fija. Inyectando un host como
#  portal.DOMAIN.hackeadora-hhi.invalid el sourceURL post-auth
#  apunta al atacante.
# ══════════════════════════════════════════════════════════════
_test_host_header_authorize() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3" PROXY="$4"

  # Host inyectado: contiene el dominio original como substring
  local EVIL_HOST="portal.${DOMAIN}.hackeadora-hhi.invalid"

  # Obtener URLs de authorize desde DB + probe canónico
  local AUTHORIZE_URLS=()
  while IFS= read -r AU; do
    [[ -n "$AU" ]] && AUTHORIZE_URLS+=("$AU")
  done < /tmp/.oidc_authorize_urls_${DOMAIN_ID} 2>/dev/null

  # Rutas canónicas de authorize
  local AUTHORIZE_PATHS=(
    "/IdPOAuth2/authorize" "/oauth2/authorize" "/oauth/authorize"
    "/connect/authorize" "/auth/authorize" "/authorize"
    "/as/authorization.oauth2" "/v2/authorize"
  )
  for APATH in "${AUTHORIZE_PATHS[@]}"; do
    AUTHORIZE_URLS+=("${BASE}${APATH}")
  done

  # También de DB
  while IFS= read -r CURL; do
    [[ -n "$CURL" ]] && AUTHORIZE_URLS+=("$CURL")
  done < <(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (url LIKE '%/authorize%' OR url LIKE '%response_type=code%')
     LIMIT 5;" 2>/dev/null | sed 's|?.*||')

  for AUTH_URL in "${AUTHORIZE_URLS[@]}"; do
    [[ -z "$AUTH_URL" ]] && continue

    # Necesitamos un client_id; intentar desde DB primero
    local CLIENT_ID
    CLIENT_ID=$(sqlite3 "$DB_PATH" \
      "SELECT DISTINCT url FROM urls
       WHERE domain_id=${DOMAIN_ID} AND url LIKE '%client_id=%'
       LIMIT 1;" 2>/dev/null | grep -oP '(?<=client_id=)[^&]+' | head -1)
    [[ -z "$CLIENT_ID" ]] && CLIENT_ID="test"

    local TEST_URL="${AUTH_URL}?client_id=${CLIENT_ID}&response_type=code&redirect_uri=https%3A%2F%2Fexample.com&scope=openid&state=test123"

    local STATUS LOCATION BODY
    STATUS=$(curl -sk --max-time 8 ${PROXY} \
      -H "Host: ${EVIL_HOST}" \
      -o /tmp/.oidc_hhi_body_$$ \
      -D /tmp/.oidc_hhi_hdr_$$ \
      -w "%{http_code}" \
      "$TEST_URL" 2>/dev/null)
    LOCATION=$(grep -i "^location:" /tmp/.oidc_hhi_hdr_$$ | tr -d '\r' | head -1)
    BODY=$(cat /tmp/.oidc_hhi_body_$$ 2>/dev/null)
    rm -f /tmp/.oidc_hhi_body_$$ /tmp/.oidc_hhi_hdr_$$

    # Confirmar: el host inyectado aparece en Location o en el cuerpo
    if echo "${LOCATION}${BODY}" | grep -qi "hackeadora-hhi\.invalid"; then
      _oidc_finding "$DOMAIN_ID" "$DOMAIN" "$AUTH_URL" \
        "Host Header Injection — OAuth2 sourceURL hijack" "high" \
        "Host: ${EVIL_HOST} refleja en redirect post-auth → el atacante recibe sng_authz_req_id/session. Location: ${LOCATION}" \
        "oidc_host_header_injection"
      break
    fi
  done
}

# ══════════════════════════════════════════════════════════════
#  Scan de authorize endpoints sin discovery — desde DB
# ══════════════════════════════════════════════════════════════
_scan_authorize_endpoints_db() {
  local DOMAIN_ID="$1" DOMAIN="$2" PROXY="$3"

  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (url LIKE '%response_type=code%' OR url LIKE '%response_type=token%')
     LIMIT 10;" 2>/dev/null | while IFS= read -r AUTH_URL; do
    [[ -z "$AUTH_URL" ]] && continue
    local BASE
    BASE=$(echo "$AUTH_URL" | grep -oP 'https?://[^/]+')
    echo "$AUTH_URL" | sed 's|?.*||' >> /tmp/.oidc_authorize_urls_${DOMAIN_ID}
    _test_state_enforcement "$AUTH_URL" "$DOMAIN_ID" "$DOMAIN" "$PROXY"
  done
}

# ══════════════════════════════════════════════════════════════
#  Función principal
# ══════════════════════════════════════════════════════════════
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 35 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  > /tmp/.oidc_authorize_urls_${DOMAIN_ID}

  local FINDINGS_BEFORE
  FINDINGS_BEFORE=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID} AND type='oidc_oauth';" \
    2>/dev/null || echo 0)

  # Obtener subdominios alive
  local ALL_SUBS
  if [[ -s "$OUT_DIR/subs_alive.txt" ]]; then
    ALL_SUBS=$(cat "$OUT_DIR/subs_alive.txt")
  else
    ALL_SUBS=$(sqlite3 "$DB_PATH" \
      "SELECT subdomain FROM subdomains
       WHERE domain_id=${DOMAIN_ID} AND status='alive';" 2>/dev/null)
  fi

  local CHECKED=0

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    ((CHECKED++))
    local BASE="https://${SUB}"
    log_info "[$CHECKED] OIDC scan: $BASE"

    # 1+4+5+6: OIDC Discovery
    _scan_oidc_discovery "$BASE" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY"

    # 1: Open redirect substring bypass
    _test_substring_redirect_bypass "$BASE" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY"

    # 2: Host header injection (usa authorize URLs acumulados de discovery)
    _test_host_header_authorize "$BASE" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY"

  done <<< "$ALL_SUBS"

  # Scan adicional desde URLs en DB (para authorize sin discovery)
  _scan_authorize_endpoints_db "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY"

  rm -f /tmp/.oidc_authorize_urls_${DOMAIN_ID}

  local FINDINGS_AFTER NEW_FINDINGS
  FINDINGS_AFTER=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID} AND type='oidc_oauth';" \
    2>/dev/null || echo 0)
  NEW_FINDINGS=$(( FINDINGS_AFTER - FINDINGS_BEFORE ))

  [[ "$NEW_FINDINGS" -gt 0 ]] && \
    _telegram_send "🔐 *OIDC/OAuth2 scan completado*
🌐 \`${DOMAIN}\`
🔍 Subdominios: \`${CHECKED}\`
⚡ Findings: \`${NEW_FINDINGS}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

  log_ok "$MODULE_DESC: $NEW_FINDINGS findings en $CHECKED subdominios"
}
