#!/usr/bin/env bash
# ============================================================
#  core/finding_validators.sh
#  Helpers compartidos para validar findings antes de reportar.
#
#  Anti-patterns que estos validators atacan (project_module_fp_catalog.md):
#    A. "HTTP 200 = expuesto"  → _validate_*_exposed valida shape del body
#    B. "Status diff = bypass" → comparar contenido, no solo status
#    C. "Sin error = vuln"      → exigir reflexión específica del payload
#
#  Uso (en cada módulo afectado):
#    source "${SCRIPT_DIR}/core/finding_validators.sh"
#    _h_get "$URL"
#    if _validate_aem_exposed; then
#      db_add_finding ...
#    fi
#
#  Convención: las funciones NO escriben a stdout. Devuelven 0 (true)
#  si el finding pasa la validación, 1 (false) si NO pasa.
# ============================================================

# Inicializar globales (declare -gA porque se sourcea dentro de funciones)
declare -gA _CATCHALL_HOST_CACHE 2>/dev/null || true

# ────────────────────────────────────────────────────────────
#  AEM (Adobe Experience Manager) — body shape
# ────────────────────────────────────────────────────────────
# Bug #1: cms_scan acepta SPA catch-all como AEM.
# Marcadores reales de AEM (Sling/Granite/CQ).
_validate_aem_exposed() {
  local BODY="${1:-$HTTP_LAST_BODY}"
  local HEADERS="${2:-$HTTP_LAST_HEADERS}"

  if [[ -n "$HEADERS" ]]; then
    echo "$HEADERS" | grep -qiE "^Server: (Communique|Day-Servlet|Apache Sling)" && return 0
    echo "$HEADERS" | grep -qiE "^X-(Vhost|Adobe)" && return 0
  fi

  [[ -z "$BODY" ]] && return 1

  # Marcadores fuertes de AEM en body
  echo "$BODY" | grep -qE \
    'Apache Sling|cq:Page|cq:template|jcr:primaryType|jcr:uuid|sling:resourceType|granite\.author|granite/ui|Adobe Experience Manager|/etc/clientlibs/|/libs/granite/|crxde-lite' \
    && return 0

  return 1
}

# ────────────────────────────────────────────────────────────
#  Spring Boot Actuator — JSON shape
# ────────────────────────────────────────────────────────────
# Bug #4: SPA devuelve 200 para /actuator/* sin que sea un actuator real.
_validate_actuator_response() {
  local BODY="${1:-$HTTP_LAST_BODY}"
  local HEADERS="${2:-$HTTP_LAST_HEADERS}"

  # Content-Type debe ser JSON o spring-boot.actuator
  if [[ -n "$HEADERS" ]]; then
    echo "$HEADERS" | grep -qiE "^content-type:.*(application/vnd\.spring-boot\.actuator|application/json)" \
      || return 1
  fi

  [[ -z "$BODY" ]] && return 1

  # Debe arrancar con { (JSON object) — descarta HTML SPA shells
  local FIRST_CHAR="${BODY:0:1}"
  [[ "$FIRST_CHAR" != "{" ]] && return 1

  # Y contener al menos una clave actuator conocida
  echo "$BODY" | grep -qE \
    '"_links"|"contexts"|"profiles"|"propertySources"|"beans"|"mappings"|"build"|"git\.commit"|"systemProperties"|"diskSpace"|"refreshable"|"healthCheck"' \
    && return 0

  return 1
}

# ────────────────────────────────────────────────────────────
#  web.xml exposure — XML shape
# ────────────────────────────────────────────────────────────
# Bug #13: path_confusion flagea por status diff sin verificar body.
_validate_web_xml() {
  local BODY="${1:-$HTTP_LAST_BODY}"
  [[ -z "$BODY" ]] && return 1

  # Debe arrancar con <?xml o tener <web-app/<servlet
  echo "$BODY" | head -c 200 | grep -qE '<\?xml|<web-app|xmlns="http://(java\.sun\.com|xmlns\.jcp\.org|jakarta\.ee)' \
    || return 1
  echo "$BODY" | grep -qE '<(web-app|servlet|servlet-mapping|filter|context-param)\b' \
    && return 0

  return 1
}

# ────────────────────────────────────────────────────────────
#  MANIFEST.MF exposure
# ────────────────────────────────────────────────────────────
_validate_manifest() {
  local BODY="${1:-$HTTP_LAST_BODY}"
  [[ -z "$BODY" ]] && return 1

  # Manifest debe arrancar con Manifest-Version: o tener Bundle-*/Implementation-*
  echo "$BODY" | head -c 100 | grep -qE '^(Manifest-Version|Bundle-|Implementation-Title|Specification-Version):' \
    && return 0

  return 1
}

# ────────────────────────────────────────────────────────────
#  Canary reflection — para reset password, IDOR, smart_scan
# ────────────────────────────────────────────────────────────
# Bug #2: técnicas A/B de reset_password no verifican que el canary
# inyectado se refleje en el body. Sin canary_check, cualquier 200 pinta como vuln.
_validate_canary_in_body() {
  local CANARY="$1"
  local BODY="${2:-$HTTP_LAST_BODY}"
  [[ -z "$CANARY" || -z "$BODY" ]] && return 1
  echo "$BODY" | grep -qF "$CANARY"
}

# ────────────────────────────────────────────────────────────
#  IDOR diff — body diff "real", no SPA noise
# ────────────────────────────────────────────────────────────
# Bug #3: smart_idor flagea cualquier diferencia de bytes. SPA shells
# producen variaciones de 1-2 bytes (timestamps en script tags).
# Reglas:
#   - Si baseline es SPA shell → no es IDOR válido (siempre cambia algo)
#   - DIFF debe superar threshold dinámico:
#       baseline >4000B → mínimo 200B diff
#       baseline <=4000B → mínimo 5% del tamaño base
_validate_idor_diff() {
  local ORIG_LEN="$1"
  local TEST_LEN="$2"
  local ORIG_BODY="${3:-}"

  [[ -z "$ORIG_LEN" || -z "$TEST_LEN" ]] && return 1
  [[ "$ORIG_LEN" -eq 0 ]] && return 1

  # Si baseline parece SPA shell, descartar
  if [[ -n "$ORIG_BODY" ]] && type is_spa_csr_body &>/dev/null; then
    is_spa_csr_body "$ORIG_BODY" && return 1
  fi

  local DIFF=$(( TEST_LEN - ORIG_LEN ))
  local ABS_DIFF="${DIFF#-}"
  local THRESHOLD
  if [[ "$ORIG_LEN" -gt 4000 ]]; then
    THRESHOLD=200
  else
    THRESHOLD=$(( ORIG_LEN / 20 ))
    [[ "$THRESHOLD" -lt 32 ]] && THRESHOLD=32
  fi

  [[ "$ABS_DIFF" -ge "$THRESHOLD" ]] && return 0
  return 1
}

# ────────────────────────────────────────────────────────────
#  is_catchall_host — sondea path random, cachea por host
# ────────────────────────────────────────────────────────────
# Mejora E del refactor plan. Cache file: ${OUT_DIR}/.catchall_cache.txt
# Una sola sondeo por host por scan, reusado por mods 25/30/20/26.
#
# Devuelve 0 (true) si el host devuelve 200 con body sustancial
# para un path inexistente (catch-all SPA o redirector).
is_catchall_host() {
  local HOST="$1"   # https://example.com (puede tener :port)
  [[ -z "$HOST" ]] && return 1

  # Strip trailing slash para cache key consistente
  local KEY="${HOST%/}"

  # In-memory cache (por subshell)
  if [[ -n "${_CATCHALL_HOST_CACHE[$KEY]:-}" ]]; then
    [[ "${_CATCHALL_HOST_CACHE[$KEY]}" == "yes" ]] && return 0
    return 1
  fi

  # On-disk cache (cross-module dentro del scan)
  local CACHE_FILE="${OUT_DIR:-/tmp}/.catchall_cache.txt"
  if [[ -f "$CACHE_FILE" ]]; then
    local CACHED
    CACHED=$(awk -F'\t' -v k="$KEY" '$1==k {print $2; exit}' "$CACHE_FILE" 2>/dev/null)
    if [[ -n "$CACHED" ]]; then
      _CATCHALL_HOST_CACHE[$KEY]="$CACHED"
      [[ "$CACHED" == "yes" ]] && return 0
      return 1
    fi
  fi

  # Probe: path random largo + segmento /admin random
  local RAND
  RAND=$(openssl rand -hex 6 2>/dev/null || echo "${RANDOM}${RANDOM}")
  local PROBE_URL="${KEY}/HACKEADORA_NX_${RAND}_$(date +%s)"

  if ! type _h_get &>/dev/null; then
    # No hay http_analyzer disponible → no podemos probar, asumir no-catchall
    _CATCHALL_HOST_CACHE[$KEY]="no"
    return 1
  fi

  _h_get "$PROBE_URL" --connect-timeout 5
  local PROBE_STATUS="$HTTP_LAST_STATUS"
  local PROBE_BODY="$HTTP_LAST_BODY"
  local PROBE_LEN=${#PROBE_BODY}

  local RESULT="no"
  # 200 con body >500B → casi siempre catch-all
  if [[ "$PROBE_STATUS" == "200" ]] && [[ "$PROBE_LEN" -gt 500 ]]; then
    RESULT="yes"
  # 302 con Location no-relativa al path probado → catch-all redirect
  elif [[ "$PROBE_STATUS" =~ ^30[127]$ ]]; then
    local LOC
    LOC=$(echo "$HTTP_LAST_HEADERS" | grep -i '^location:' | head -1 | tr -d '\r')
    # Si Location apunta al mismo path probado → no catch-all (404 redirect normal)
    # Si apunta a otra URL completa → posible catch-all
    if [[ -n "$LOC" ]] && ! echo "$LOC" | grep -qF "$PROBE_URL"; then
      RESULT="yes"
    fi
  fi

  # Cache
  _CATCHALL_HOST_CACHE[$KEY]="$RESULT"
  echo -e "${KEY}\t${RESULT}" >> "$CACHE_FILE" 2>/dev/null || true

  [[ "$RESULT" == "yes" ]] && return 0
  return 1
}

# ────────────────────────────────────────────────────────────
#  is_idempotent_endpoint — descartar GET/HEAD/SAML/OAuth de race tests
# ────────────────────────────────────────────────────────────
# Bug #11: race_condition flagea endpoints idempotentes. Solo POST/PUT/PATCH/DELETE
# pueden tener race real. Métodos seguros (RFC 7231) y paths SAML/OAuth/health
# son idempotentes por diseño.
is_idempotent_endpoint() {
  local METHOD="$1" URL="$2"

  # Métodos seguros
  case "$METHOD" in
    GET|HEAD|OPTIONS|TRACE) return 0 ;;
  esac

  # Path-based idempotency
  local PATH_PORTION
  PATH_PORTION=$(echo "$URL" | sed -E 's#^https?://[^/]+##; s#\?.*##; s#\#.*##')

  case "$PATH_PORTION" in
    */saml/*|*/saml2/*) return 0 ;;
    */oauth/authorize*|*/oauth2/authorize*|*/oidc/authorize*|*/connect/authorize*) return 0 ;;
    */openid-connect/auth*) return 0 ;;
    */health*|*/status|*/ping|*/ready|*/live|*/livez|*/readyz) return 0 ;;
    */.well-known/*) return 0 ;;
    */metrics|*/info) return 0 ;;
    *) return 1 ;;
  esac
}

# ────────────────────────────────────────────────────────────
#  is_oauth_authorize_path — distingue OAuth flow de admin endpoint
# ────────────────────────────────────────────────────────────
# Bug #8: business_logic flagea /as/authorize como admin sin auth.
is_oauth_authorize_path() {
  local URL="$1"
  echo "$URL" | grep -qiE \
    '/(as|oauth2?|oidc|connect|auth|saml|saml2|openid-connect)/(authorize|authorization|token|userinfo|jwks|introspect|revoke|endsession)' \
    && return 0
  # Query con response_type/client_id es OAuth seguro
  echo "$URL" | grep -qiE 'response_type=|client_id=|grant_type=' && return 0
  return 1
}

# ────────────────────────────────────────────────────────────
#  is_known_framework_error — distinguir error real de framework noise
# ────────────────────────────────────────────────────────────
# Bug #10: SQLi error detection matchea Salesforce Aura framework strings.
# Si la app es Lightning/Aura, los strings "exception", "ORA", "error" no son DB errors.
is_salesforce_lightning_body() {
  local BODY="${1:-$HTTP_LAST_BODY}"
  [[ -z "$BODY" ]] && return 1
  echo "$BODY" | grep -qE 'Aura\.Component|salesforce\.com|lightning/|aura:|/auraFW/|/sfdcjs/|sforce\.one|app\.aura\.framework' \
    && return 0
  return 1
}
