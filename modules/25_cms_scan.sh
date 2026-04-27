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

  db_add_finding "$DOMAIN_ID" "cms_scan" "$SEVERITY" \
    "$TARGET" "$TEMPLATE" "$DETAIL"

  local EMOJI="🔴"
  [[ "$SEVERITY" == "medium" ]] && EMOJI="🟠"
  [[ "$SEVERITY" == "low"    ]] && EMOJI="🟡"

  _telegram_send "${EMOJI} *CMS Scan — ${TYPE}*
🌐 \`${DOMAIN}\`
🎯 \`${TARGET}\`
📋 ${DETAIL:0:300}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

  log_warn "  ⚡ [$SEVERITY] $TYPE: $TARGET — $DETAIL"
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

# ── WordPress ─────────────────────────────────────────────────
_scan_wordpress() {
  local DOMAIN_ID="$1" DOMAIN="$2" OUT_DIR="$3"

  local SUBS
  SUBS=$(_get_subs_with_tech "$DOMAIN_ID" "%WordPress%")
  [[ -z "$SUBS" ]] && return

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
      docker run --rm wpscanteam/wpscan \
        --url "$URL" \
        --format json \
        --no-banner \
        --plugins-detection passive \
        $TOKEN_FLAG \
        2>/dev/null > "$WP_OUT" || true
    else
      wpscan \
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

    perl "$HOME/tools/joomscan/joomscan.pl" \
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

    droopescan scan drupal -u "$URL" 2>/dev/null > "$DS_OUT" || true

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

  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    local IS_AEM=false

    # Detectar AEM por paths característicos
    for PATH in "/libs/granite/core/content/login.html" "/crx/de/index.jsp"; do
      local STATUS
      STATUS=$(curl -sL --max-time 8 ${CURL_PROXY} \
        -o /dev/null -w "%{http_code}" "${BASE}${PATH}" 2>/dev/null)
      if [[ "$STATUS" == "200" || "$STATUS" == "302" ]]; then
        IS_AEM=true
        log_warn "  ⚡ AEM detectado: $BASE"
        break
      fi
    done

    $IS_AEM || continue

    # Comprobar paths críticos
    for AEM_PATH in "${AEM_PATHS[@]}"; do
      local STATUS RESP
      STATUS=$(curl -sL --max-time 8 ${CURL_PROXY} \
        -o /tmp/.aem_resp_$$ -w "%{http_code}" "${BASE}${AEM_PATH}" 2>/dev/null)

      if [[ "$STATUS" == "200" ]]; then
        local SEVERITY="medium"
        [[ "$AEM_PATH" == *"crx/de"* || "$AEM_PATH" == *"console"* ]] && SEVERITY="critical"
        [[ "$AEM_PATH" == *"passwd"* ]] && SEVERITY="critical"

        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${AEM_PATH}" \
          "AEM Exposed Endpoint" "$SEVERITY" \
          "Endpoint AEM accesible: ${AEM_PATH}" "aem_check"
      fi
    done
    rm -f /tmp/.aem_resp_$$

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
      nuclei -u "$BASE" -tags "aem,adobe" -silent -json 2>/dev/null | \
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

  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    log_info "  Liferay scan → $BASE"

    # JSONWS API — enumerar métodos disponibles
    local JSONWS_STATUS
    JSONWS_STATUS=$(curl -sL --max-time 8 ${CURL_PROXY} \
      -o /dev/null -w "%{http_code}" "${BASE}/api/jsonws" 2>/dev/null)

    if [[ "$JSONWS_STATUS" == "200" ]]; then
      _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/api/jsonws" \
        "Liferay JSONWS API Exposed" "high" \
        "API JSONWS accesible — posible enumeración de métodos y SSRF" "liferay"
    fi

    # CVE-2020-7961 — Deserialización RCE (uno de los más famosos en H1)
    if command -v nuclei &>/dev/null; then
      nuclei -u "$BASE" -tags "liferay,cve-2020-7961" -silent -json 2>/dev/null | \
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

  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
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

    # Comprobar endpoints SAP críticos
    for SAP_PATH in "${SAP_PATHS[@]}"; do
      local STATUS
      STATUS=$(curl -sL --max-time 8 ${CURL_PROXY} \
        -o /dev/null -w "%{http_code}" "${BASE}${SAP_PATH}" 2>/dev/null)

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
        -silent -json 2>/dev/null | \
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
        -silent -json 2>/dev/null | \
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
        -silent -json 2>/dev/null | \
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

  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
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

    for ACT_PATH in "${ACTUATOR_PATHS[@]}"; do
      local STATUS
      STATUS=$(curl -sL --max-time 8 ${CURL_PROXY} \
        -o /dev/null -w "%{http_code}" "${BASE}${ACT_PATH}" 2>/dev/null)
      if [[ "$STATUS" == "200" ]]; then
        local SEVERITY="medium"
        [[ "$ACT_PATH" == *"heapdump"* || "$ACT_PATH" == *"env"* ]] && SEVERITY="high"
        _cms_finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${ACT_PATH}" \
          "Spring Boot Actuator Exposed" "$SEVERITY" \
          "Actuator endpoint accesible: ${ACT_PATH}" "spring_actuator"
      fi
    done

    # Spring4Shell — CVE-2022-22965
    if command -v nuclei &>/dev/null; then
      nuclei -u "$BASE" \
        -tags "spring,cve-2022-22965,spring4shell" \
        -silent -json 2>/dev/null | \
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
  JAVA_SUBS_DB=$(sqlite3 "$DB_PATH"     "SELECT DISTINCT subdomain FROM technologies
     WHERE domain_id=${DOMAIN_ID}
       AND (tech_name LIKE '%Java%' OR tech_name LIKE '%Tomcat%'
            OR tech_name LIKE '%Spring%' OR tech_name LIKE '%Log4j%'
            OR tech_name LIKE '%Struts%' OR tech_name LIKE '%JBoss%'
            OR tech_name LIKE '%WebLogic%' OR tech_name LIKE '%Jetty%'
            OR tech_name LIKE '%GlassFish%' OR tech_name LIKE '%WildFly%'
            OR tech_name LIKE '%Elasticsearch%');" 2>/dev/null)

  # 2. URLs con extensiones Java (.do, .action, .jsp, .jsf)
  local JAVA_SUBS_URLS
  JAVA_SUBS_URLS=$(sqlite3 "$DB_PATH"     "SELECT DISTINCT subdomain FROM subdomains s
     WHERE s.domain_id=${DOMAIN_ID} AND s.status='alive'
       AND EXISTS (
         SELECT 1 FROM urls u
         WHERE u.domain_id=s.domain_id
           AND u.url LIKE '%' || s.subdomain || '%'
           AND (u.url LIKE '%.do' OR u.url LIKE '%.action'
                OR u.url LIKE '%.jsp' OR u.url LIKE '%.jsf'
                OR u.url LIKE '%struts%' OR u.url LIKE '%spring%')
       );" 2>/dev/null)

  # Combinar y deduplicar — sin live detection para no molestar
  # Si el módulo 10 no detectó Java, no lanzamos Log4Shell
  local ALL_JAVA_SUBS
  ALL_JAVA_SUBS=$(printf '%s
%s'     "$JAVA_SUBS_DB" "$JAVA_SUBS_URLS" |     grep -v '^$' | sort -u)

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
    nuclei       -l "$JAVA_TARGETS"       -tags "log4j,cve-2021-44228,cve-2021-45046,cve-2021-45105"       -silent -json 2>/dev/null |       while IFS= read -r LINE; do
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
    timeout 300 python3 "$HOME/tools/log4j-scan/log4j-scan.py"       -l "$JAVA_TARGETS"       --run-all-tests       2>/dev/null | grep -i "vulnerable\|CVE" |       while IFS= read -r LINE; do
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
        -silent -json 2>/dev/null | \
        while IFS= read -r LINE; do
          local TEMPLATE SEV
          TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
          SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','?'))" 2>/dev/null)
          _cms_finding "$DOMAIN_ID" "$DOMAIN" "$BASE" \
            "Magento" "$SEV" "Template: $TEMPLATE" "nuclei:$TEMPLATE"
        done
    fi
  done <<< "$SUBS"
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
        -silent -json 2>/dev/null | \
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

  source "$(dirname "$0")/../core/rotator.sh" 2>/dev/null || true

  # Crear archivo de targets
  local TARGETS="$OUT_DIR/.react2shell_targets.txt"
  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    echo "https://${SUB}"
    echo "http://${SUB}"
  done <<< "$SUBS" | sort -u > "$TARGETS"

  local R2S_OUT="$OUT_DIR/.react2shell_results.json"

  local R2S_CMD="nuclei -l ${TARGETS} -t ${TEMPLATE_FILE} -silent -json 2>/dev/null > ${R2S_OUT}"

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

# ── Función principal ─────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 25 — $MODULE_DESC: $DOMAIN"

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
