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

  if ! type _h_get &>/dev/null; then
    # No hay http_analyzer disponible → no podemos probar, asumir no-catchall
    _CATCHALL_HOST_CACHE[$KEY]="no"
    return 1
  fi

  # Estrategia 2-probe (fix 2026-05-09):
  # Probar DOS paths random distintos y comparar bodies. Solo es catch-all si
  # ambos devuelven 200 + body >500B + lengths similares (diff <5% o <100B).
  # Casos que distingue:
  #   - SPA Vue/React (aassethealth): 200 13KB idéntico × 2 → catch-all
  #   - AEM auth gate (prod-author): 401 0B × 2 → NO catch-all (escanear)
  #   - Auth gate variable: 200 13KB vs 401 16B → NO catch-all (escanear)
  local RAND1 RAND2
  RAND1=$(openssl rand -hex 6 2>/dev/null || echo "${RANDOM}${RANDOM}")
  RAND2=$(openssl rand -hex 6 2>/dev/null || echo "${RANDOM}${RANDOM}")
  local PROBE1_URL="${KEY}/HACKEADORA_NX_${RAND1}_$(date +%s)"
  local PROBE2_URL="${KEY}/api/v1/HACKEADORA_${RAND2}/$(date +%s)"

  _h_get "$PROBE1_URL" --connect-timeout 5
  local STATUS1="$HTTP_LAST_STATUS"
  local LEN1=${#HTTP_LAST_BODY}
  local HEADERS1="$HTTP_LAST_HEADERS"

  local RESULT="no"

  # Si probe1 NO es 200 con body sustancial → ya sabemos que no es catch-all simple
  # Edge case: redirect 302/301 con Location consistente → catch-all redirect
  if [[ "$STATUS1" =~ ^30[127]$ ]]; then
    local LOC
    LOC=$(echo "$HEADERS1" | grep -i '^location:' | head -1 | tr -d '\r')
    if [[ -n "$LOC" ]] && ! echo "$LOC" | grep -qF "$PROBE1_URL"; then
      RESULT="yes"
    fi
  elif [[ "$STATUS1" == "200" ]] && [[ "$LEN1" -gt 500 ]]; then
    # Probe 2 (path completamente distinto)
    _h_get "$PROBE2_URL" --connect-timeout 5
    local STATUS2="$HTTP_LAST_STATUS"
    local LEN2=${#HTTP_LAST_BODY}

    if [[ "$STATUS2" == "200" ]] && [[ "$LEN2" -gt 500 ]]; then
      # Ambos 200 con body sustancial. Verificar que lengths sean similares.
      local DIFF=$(( LEN1 - LEN2 ))
      [[ "$DIFF" -lt 0 ]] && DIFF=$(( -DIFF ))
      local THRESHOLD=$(( LEN1 / 20 ))
      [[ "$THRESHOLD" -lt 100 ]] && THRESHOLD=100
      if [[ "$DIFF" -lt "$THRESHOLD" ]]; then
        # Edge case (refactor 2026-05-09): si el body de catch-all contiene
        # markers de framework empresarial (AEM, Sharepoint, Drupal admin,
        # Magento, Hippo, "POST data" de AEM author), NO marcar como catch-all
        # — es un auth gate real que merece scaneo (validators filtrarán FPs).
        if echo "$HTTP_LAST_BODY" | grep -qiE \
          'AEM Sign In|Apache Sling|granite\.author|cq:Page|cq:template|<title>POST data|sharepoint|drupal\.behaviors|Magento_|magentoStorefrontEvents|bloomreach|<title>Hippo|hippo:|/libs/granite|/etc/clientlibs'; then
          RESULT="no"
        else
          RESULT="yes"
        fi
      fi
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

# ────────────────────────────────────────────────────────────
#  has_pii_shape — body contiene patrones de PII (auth bypass / IDOR confirm)
# ────────────────────────────────────────────────────────────
# Tier 2.3 — usado por mod 41 (auth replay) para confirmar que un response
# realmente expone datos de usuario antes de flagear como auth bypass.
#
# Devuelve 0 (true) si body tiene markers PII fuertes (email, phone, SSN, etc.).
has_pii_shape() {
  local BODY="${1:-$HTTP_LAST_BODY}"
  [[ -z "$BODY" ]] && return 1

  # Email real (no @example.com / @placeholder)
  if echo "$BODY" | grep -qE '"[a-zA-Z0-9_]+":\s*"[a-zA-Z0-9._+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"'; then
    if ! echo "$BODY" | grep -qiE '@(example|test|placeholder|invalid|domain)\.'; then
      return 0
    fi
  fi
  # Phone con formato válido E.164 o nacional (no 555-555-555)
  if echo "$BODY" | grep -qE '"(phone|mobile|tel|telephone|telefono|telefon)":\s*"\+?[0-9]{6,15}"'; then
    return 0
  fi
  # SSN/DNI/CIF
  if echo "$BODY" | grep -qE '"(ssn|nationalId|dni|cif|nie|tax_id|taxId)":\s*"[0-9A-Z]{6,15}"'; then
    return 0
  fi
  # Birth date
  if echo "$BODY" | grep -qE '"(birthDate|birthdate|dob|dateOfBirth|fechaNacimiento)":\s*"[0-9]{4}-[0-9]{2}-[0-9]{2}'; then
    return 0
  fi
  # Address con calle real
  if echo "$BODY" | grep -qE '"(street|address|addressLine|direccion|ulica)":\s*"[^"]{8,}"'; then
    if ! echo "$BODY" | grep -qiE '"(street|address)":\s*"(test|none|n/a|null|placeholder)"'; then
      return 0
    fi
  fi
  # Credit card / IBAN
  if echo "$BODY" | grep -qE '"(ccNumber|cardNumber|iban|account_number)":\s*"[A-Z0-9]{8,}"'; then
    return 0
  fi
  # JWT en body
  if echo "$BODY" | grep -qE '"(token|accessToken|refreshToken|sessionToken)":\s*"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.'; then
    return 0
  fi

  return 1
}

# ────────────────────────────────────────────────────────────
#  is_synthetic_endpoint — descartar URLs sintéticas extraídas del JS
# ────────────────────────────────────────────────────────────
# Bug #16 (refactor 2026-05-09): el JS analyzer extrae "endpoints" de archivos
# fuente Vue/Svelte/JSX. Esos no son endpoints reales — son rutas de componentes
# con keywords del framework como ?scoped, ?type, ?vue, ?props que NO son query
# params. dalfox/ghauri sobre estos URLs producen 0 findings históricos.
#
# Devuelve 0 (true) si la URL/param pinta como sintético — el caller debe skip.
#
# Uso:
#   is_synthetic_endpoint "$URL" "$PARAM" && continue
is_synthetic_endpoint() {
  local URL="$1" PARAM="${2:-}"
  [[ -z "$URL" ]] && return 1

  # Path con extensión de archivo fuente de framework → NO es endpoint real
  echo "$URL" | grep -qiE '\.(vue|svelte|tsx|jsx|module\.(ts|js)|d\.ts)([?#]|$)' && return 0

  # Param name = keyword del compilador framework (Vue/React/Svelte)
  if [[ -n "$PARAM" ]]; then
    case "$PARAM" in
      scoped|inheritAttrs|setup|props|emits|slots|render|template|methods|\
computed|watched|watch|mounted|created|beforeMount|destroyed|unmounted|\
provide|inject|directives|filters|mixins|extends|inheritOptions|key|ref|\
is|component|transition|teleport|suspense|portal|app|layout|page|nuxt|\
__namespace|__webpack|__esModule|__vite|hmr|hot|module|exports)
        return 0 ;;
    esac
  fi

  return 1
}

# ────────────────────────────────────────────────────────────
#  is_nuclei_finding_actionable — filtrar fingerprinting templates
# ────────────────────────────────────────────────────────────
# Refactor 2026-05-09: las integraciones nuclei en mods 25/26 acepta CUALQUIER
# template con su tag, incluyendo `apache-detect`, `tech-detect`, etc., que
# son fingerprinting (severity=info), NO vulnerabilidades. Genera ruido.
#
# Devuelve 0 si el finding nuclei merece reportarse:
#   - severity != info (excluye plantillas de info-disclosure noise)
#   - template-id NO contiene 'detect'/'fingerprint'/'tech' a no ser que sea cve-*
#
# Uso:
#   is_nuclei_finding_actionable "$TEMPLATE_ID" "$SEVERITY" || continue
is_nuclei_finding_actionable() {
  local TPL="$1" SEV="$2"
  [[ -z "$TPL" || "$TPL" == "?" ]] && return 1
  [[ "$SEV" == "info" ]] && return 1
  # CVE templates siempre actionable (ya pasan severity check)
  echo "$TPL" | grep -qE '^cve-[0-9]{4}' && return 0
  # Excluir fingerprinting / detection
  echo "$TPL" | grep -qiE '(^|-)(detect|fingerprint|tech|version)(-|$)' && return 1
  # Por defecto, aceptable si severity >= medium
  return 0
}
