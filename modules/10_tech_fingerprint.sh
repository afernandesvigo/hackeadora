#!/usr/bin/env bash
# ============================================================
#  modules/10_tech_fingerprint.sh
#  Fase 10: Fingerprinting de tecnologías y versiones
#
#  Estrategia en capas:
#    1. webanalyze  (Wappalyzer rules en Go, más rápido)
#    2. httpx -tech-detect (fallback si no hay webanalyze)
#    3. whatweb     (fallback adicional con versiones)
#
#  Se ejecuta sobre CADA URL/directorio descubierto, no solo
#  sobre subdominios raíz — así capturamos tech distinta
#  en paths como /wp-admin, /api/v2, /phpmyadmin, etc.
# ============================================================

MODULE_NAME="tech_fingerprint"
MODULE_DESC="Fingerprinting de tecnologías y versiones"

# ── Instalar webanalyze si no está ────────────────────────────
_ensure_webanalyze() {
  if command -v webanalyze &>/dev/null; then return 0; fi
  log_info "Instalando webanalyze (Wappalyzer para CLI)..."
  go install github.com/rverton/webanalyze/cmd/webanalyze@latest 2>/dev/null \
    && log_ok "webanalyze instalado" \
    || { log_warn "webanalyze: fallo en instalación"; return 1; }
}

# Descarga/actualiza las reglas de Wappalyzer
_update_wappalyzer_rules() {
  local RULES_DIR="$HOME/.webanalyze"
  mkdir -p "$RULES_DIR"
  local RULES="$RULES_DIR/technologies.json"

  # Actualizar si tiene más de 7 días o no existe
  if [[ ! -f "$RULES" ]] || find "$RULES" -mtime +7 | grep -q .; then
    log_info "Actualizando reglas Wappalyzer..."
    curl -sL "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/a.json" \
      -o "$RULES_DIR/tech_a.json" 2>/dev/null || true
    # webanalyze descarga automáticamente si no encuentra el archivo
    webanalyze -update 2>/dev/null || true
  fi
}

# ── Parser de salida webanalyze ───────────────────────────────
# Formato real (verificado con webanalyze v0.3.9): Host,Category,App,Version
# Category puede llevar comas dentro de comillas: "Web servers,Reverse proxies"
# Usamos python para parseo CSV correcto en lugar de IFS=',' que rompe con comillas.
_parse_webanalyze() {
  local LINE="$1"
  local DOMAIN_ID="$2"

  # Skip header
  [[ "$LINE" == Host,* ]] && return

  # Parseo CSV via python (maneja comillas correctamente)
  local PARSED
  PARSED=$(python3 -c "
import csv, sys
r = next(csv.reader([sys.argv[1]]))
if len(r) >= 4:
    print(r[0] + '|' + r[2] + '|' + r[3] + '|' + r[1])
" "$LINE" 2>/dev/null) || return

  IFS='|' read -r URL TECH VERSION CATEGORY <<< "$PARSED"
  [[ -z "$URL" || -z "$TECH" ]] && return

  local SUBDOMAIN
  SUBDOMAIN=$(echo "$URL" | sed 's|https\?://||;s|/.*||')

  db_upsert_tech "$DOMAIN_ID" "$URL" "$SUBDOMAIN" \
    "$TECH" "$VERSION" "$CATEGORY" "100" "wappalyzer"
}

# ── Parser de salida httpx -json ──────────────────────────────
_parse_httpx_tech() {
  local JSON_LINE="$1"
  local DOMAIN_ID="$2"

  local URL
  URL=$(echo "$JSON_LINE" | jq -r '.url // ""')
  [[ -z "$URL" ]] && return

  local SUBDOMAIN
  SUBDOMAIN=$(echo "$URL" | sed 's|https\?://||;s|/.*||')

  # httpx devuelve "tech": ["Cloudflare","OutSystems",...] (lista de strings)
  # y "cpe": [{"vendor":"..","product":"..","cpe":"..."}] para versiones CPE
  # Construir mapa de versiones desde CPE
  local CPE_JSON
  CPE_JSON=$(echo "$JSON_LINE" | jq -r '.cpe // []' 2>/dev/null)

  echo "$JSON_LINE" | jq -r '.tech[]? // empty' 2>/dev/null | while IFS= read -r TNAME; do
    [[ -z "$TNAME" ]] && continue
    # Buscar versión en CPE si hay match por product o vendor
    local TVER=""
    TVER=$(echo "$CPE_JSON" | jq -r \
      --arg t "$(echo "$TNAME" | tr '[:upper:]' '[:lower:]')" \
      '.[]? | select((.product | ascii_downcase | contains($t)) or (.vendor | ascii_downcase | contains($t))) | .cpe' \
      2>/dev/null | head -1)
    db_upsert_tech "$DOMAIN_ID" "$URL" "$SUBDOMAIN" \
      "$TNAME" "${TVER}" "" "80" "httpx"
  done

  # También parsear el webserver header como tech
  local WEBSERVER
  WEBSERVER=$(echo "$JSON_LINE" | jq -r '.webserver // ""' 2>/dev/null)
  [[ -n "$WEBSERVER" && "$WEBSERVER" != "null" ]] && \
    db_upsert_tech "$DOMAIN_ID" "$URL" "$SUBDOMAIN" \
      "$WEBSERVER" "" "web-server" "90" "httpx-webserver"
}

# ── Parser de salida whatweb -json ────────────────────────────
_parse_whatweb() {
  local JSON_LINE="$1"
  local DOMAIN_ID="$2"

  local TARGET
  TARGET=$(echo "$JSON_LINE" | jq -r '.target // ""' 2>/dev/null)
  [[ -z "$TARGET" ]] && return

  local SUBDOMAIN
  SUBDOMAIN=$(echo "$TARGET" | sed 's|https\?://||;s|/.*||')

  echo "$JSON_LINE" | jq -r '.plugins | to_entries[] | "\(.key)|\(.value.version[0] // "")"' \
    2>/dev/null | while IFS='|' read -r TNAME TVER; do
    [[ -z "$TNAME" ]] && continue
    db_upsert_tech "$DOMAIN_ID" "$TARGET" "$SUBDOMAIN" \
      "$TNAME" "$TVER" "" "70" "whatweb"
  done
}

# ── Función principal ─────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 10 — $MODULE_DESC: $DOMAIN"

  local ALIVE="$OUT_DIR/subs_alive.txt"
  local URLS_RAW="$OUT_DIR/urls_raw.txt"

  if [[ ! -s "$ALIVE" ]]; then
    log_warn "Sin subdominios alive, saltando"
    return
  fi

  # Construir lista de targets: subdominios + URLs únicas por subdominio
  # (no lanzamos sobre TODAS las urls, solo una muestra representativa por path depth)
  local TARGETS="$OUT_DIR/.tech_targets.txt"
  > "$TARGETS"

  # 1. Subdominios raíz (https://sub.domain.com)
  sed 's|^|https://|' "$ALIVE" >> "$TARGETS"

  # 2. URLs con paths únicos (máximo 3 niveles, deduplicadas por "directorio base")
  if [[ -s "$URLS_RAW" ]]; then
    # Extraer paths únicos hasta el 2º nivel: /a/b/... → /a/b
    grep -oP 'https?://[^/]+(/[^/?#]+){1,2}' "$URLS_RAW" 2>/dev/null \
      | sort -u \
      | head -500 \
      >> "$TARGETS" || true
  fi

  sort -u "$TARGETS" -o "$TARGETS"
  local TARGET_COUNT
  TARGET_COUNT=$(wc -l < "$TARGETS" | tr -d ' ')
  log_info "Analizando tecnologías en $TARGET_COUNT targets..."

  local TECH_OUT="$OUT_DIR/tech_results.csv"
  > "$TECH_OUT"
  local TOTAL_FOUND=0

  # ── Capa 1: webanalyze (Wappalyzer) ──────────────────────
  if _ensure_webanalyze 2>/dev/null; then
    _update_wappalyzer_rules
    log_info "Ejecutando webanalyze (Wappalyzer)..."
    local WA_OUT="$OUT_DIR/.webanalyze_raw.csv"

    webanalyze \
      -hosts "$TARGETS" \
      -output csv \
      -worker 20 \
      -crawl 0 \
      -silent \
      2>/dev/null \
    > "$WA_OUT" || true

    if [[ -s "$WA_OUT" ]]; then
      local WA_COUNT=0
      while IFS= read -r LINE; do
        [[ -z "$LINE" || "$LINE" == url* ]] && continue  # saltar header
        _parse_webanalyze "$LINE" "$DOMAIN_ID"
        echo "$LINE" >> "$TECH_OUT"
        ((WA_COUNT++))
      done < "$WA_OUT"
      log_ok "webanalyze: $WA_COUNT entradas de tecnología"
      ((TOTAL_FOUND += WA_COUNT))
      rm -f "$WA_OUT"
    fi
  else
    log_warn "webanalyze no disponible"
  fi

  # ── Capa 2: httpx -tech-detect (complementa con versiones HTTP) ──
  if command -v "${HTTPX_BIN:-httpx}" &>/dev/null; then
    log_info "httpx tech-detect como capa adicional..."
    local HX_OUT="$OUT_DIR/.httpx_tech.json"

    "${HTTPX_BIN:-httpx}" \
      -l "$TARGETS" \
      -tech-detect \
      -json \
      -silent \
      -threads 30 \
      ${SCAN_UA:+-H "User-Agent: ${SCAN_UA}"} \
      -o "$HX_OUT" \
      2>/dev/null || true

    if [[ -s "$HX_OUT" ]]; then
      local HX_COUNT=0
      while IFS= read -r LINE; do
        _parse_httpx_tech "$LINE" "$DOMAIN_ID"
        ((HX_COUNT++))
      done < "$HX_OUT"
      log_ok "httpx tech-detect: $HX_COUNT URLs procesadas"
      rm -f "$HX_OUT"
    fi
  fi

  # ── Capa 3: whatweb (para versiones específicas) ──────────
  if command -v whatweb &>/dev/null; then
    log_info "whatweb para detección de versiones..."
    local WW_OUT="$OUT_DIR/.whatweb_tech.json"

    # Solo sobre subdominios raíz (whatweb es más lento)
    while IFS= read -r SUB; do
      [[ -z "$SUB" ]] && continue
      whatweb \
        --aggression 1 \
        --quiet \
        --log-json=/dev/stdout \
        "https://${SUB}" \
        2>/dev/null
    done < "$ALIVE" > "$WW_OUT" || true

    if [[ -s "$WW_OUT" ]]; then
      while IFS= read -r LINE; do
        [[ -z "$LINE" ]] && continue
        _parse_whatweb "$LINE" "$DOMAIN_ID"
      done < "$WW_OUT"
      log_ok "whatweb: versiones extraídas"
      rm -f "$WW_OUT"
    fi
  fi

  # ── Capa 4: Custom pattern matching (SaaS/enterprise no cubiertos por Wappalyzer) ──
  log_info "Custom fingerprints (body/header/CNAME/title)..."
  local CUSTOM_COUNT=0

  _save_tech() {
    local SUB_="$1" TECH_="$2" VER_="$3" CAT_="$4" SRC_="$5"
    sqlite3 "$DB_PATH" \
      "INSERT OR REPLACE INTO technologies
         (domain_id, url, subdomain, tech_name, tech_version, category, confidence, source)
       VALUES(${DOMAIN_ID}, 'https://${SUB_}', '${SUB_}',
         '${TECH_//\'/\'\'}', '${VER_//\'/\'\'}',
         '${CAT_//\'/\'\'}', 95, '${SRC_}');" 2>/dev/null || true
    log_info "  ✦ $SRC_: $SUB_ → $TECH_${VER_:+ $VER_}"
    ((CUSTOM_COUNT++))
  }

  # ── CNAME-based SaaS detection (más fiable que body: no requiere ver el app) ──
  # Mapa: patrón en CNAME → "Tech Name|Category"
  declare -gA CNAME_VENDORS=(
    ["cloud.looker.com"]="Looker|BI Platform"
    ["force.com"]="Salesforce|CRM"
    ["salesforce.com"]="Salesforce|CRM"
    ["service-now.com"]="ServiceNow|ITSM"
    ["myworkday.com"]="Workday|HRM"
    ["zendesk.com"]="Zendesk|Support"
    ["freshdesk.com"]="Freshdesk|Support"
    ["hubspot.com"]="HubSpot|CRM"
    ["intercom.io"]="Intercom|Support"
    ["atlassian.net"]="Atlassian|Project Mgmt"
    ["notion.so"]="Notion|Productivity"
    ["airtable.com"]="Airtable|Database"
    ["retool.com"]="Retool|Low-Code"
    ["grafana.net"]="Grafana Cloud|Monitoring"
    ["datadoghq.com"]="Datadog|Monitoring"
    ["newrelic.com"]="New Relic|Monitoring"
    ["splunkcloud.com"]="Splunk|Analytics"
    ["tableau.com"]="Tableau|BI Platform"
    ["powerbi.com"]="Power BI|BI Platform"
    ["metabaseapp.com"]="Metabase|BI Platform"
    ["supabase.co"]="Supabase|Backend"
    ["firebase.google.com"]="Firebase|Backend"
    ["heroku.com"]="Heroku|PaaS"
    ["netlify.app"]="Netlify|PaaS"
    ["vercel.app"]="Vercel|PaaS"
    ["wpengine.com"]="WP Engine|CMS"
    ["kinsta.cloud"]="Kinsta|CMS"
    ["shopify.com"]="Shopify|E-Commerce"
    ["myshopify.com"]="Shopify|E-Commerce"
    ["bigcommerce.com"]="BigCommerce|E-Commerce"
    ["fastly.net"]="Fastly CDN|CDN"
    ["cloudfront.net"]="AWS CloudFront|CDN"
    ["akamaized.net"]="Akamai|CDN"
    ["cdn77.org"]="CDN77|CDN"
  )

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue

    # ── CNAME lookup ──────────────────────────────────────────
    local CNAMES
    CNAMES=$(dig +short CNAME "${SUB}" 2>/dev/null | tr '\n' ' ')
    for CNAME_PATTERN in "${!CNAME_VENDORS[@]}"; do
      if echo "$CNAMES" | grep -qi "$CNAME_PATTERN" 2>/dev/null; then
        IFS='|' read -r VTECH VCAT <<< "${CNAME_VENDORS[$CNAME_PATTERN]}"
        _save_tech "$SUB" "$VTECH" "" "$VCAT" "cname_detection"
        break
      fi
    done

    # ── Fetch body + headers (una sola petición) ─────────────
    local RESP BODY HEADERS HTTP_TITLE
    RESP=$(curl -sL --max-time 12 --compressed -D - "https://${SUB}" 2>/dev/null | head -c 80000)
    HEADERS=$(echo "$RESP" | sed -n '1,/^\r\{0,1\}$/p')
    BODY=$(echo "$RESP" | sed '1,/^\r\{0,1\}$/d')

    # ── Título de página como señal de tech ──────────────────
    HTTP_TITLE=$(echo "$BODY" | grep -oiP '(?<=<title[^>]*>)[^<]+' | head -1 | tr -d '\r\n' | xargs 2>/dev/null || true)

    # ── Body patterns: TECH|CATEGORY|DETECTION_REGEX|VERSION_REGEX_OR_EMPTY ──
    # VERSION_REGEX: si se proporciona, se extrae con grep -oP y es el valor de versión.
    # Si está vacío, solo se detecta presencia (sin versión).
    local -a BODY_PATTERNS=(
      "Looker|BI Platform|lookerVersion:\s*'[^']+'|(?<=lookerVersion: ')[^']+(?=')"
      "Looker|BI Platform|window\.GADATA\s*=|"
      "Grafana|Monitoring|\"appUrl\":\"[^\"]+grafana|\"version\":\"([0-9.]+)\",\"commit\""
      "Metabase|BI Platform|<meta name=\"metabase-version\"|(?<=content=\")[0-9][^\"]+(?=\")"
      "Kibana|Analytics|\"version\":\{\"number\":\"[^\"]+\"|(?<=\"number\":\")[0-9][^\"]+(?=\")"
      "Retool|Low-Code Platform|window\.RETOOL_CONFIG\s*=|"
      "Superset|BI Platform|window\.SUPERSET_BOOTSTRAP_DATA|"
      "Redash|BI Platform|<div id=\"redash-app\"|"
      "Jupyter|Notebook|<title>Jupyter|"
      "Airflow|Workflow|<title>Airflow|"
      "Jenkins|CI/CD|<title>Dashboard \[Jenkins\]|"
      "GitLab|DevOps|<meta content=\"GitLab\"|"
      "Confluence|Wiki|<meta name=\"application-name\" content=\"Confluence\"|"
      "Jira|Project Mgmt|<meta name=\"application-name\" content=\"JIRA\"|"
      "Sentry|Monitoring|window\.__initialData.*sentry|"
      "Datadog|Monitoring|DD_RUM\.init\(\{|"
      "New Relic|Monitoring|NREUM\.loader_config|"
      "Segment|Analytics|analytics\.load\s*\(|"
      "Mixpanel|Analytics|mixpanel\.init\s*\(|"
      "LaunchDarkly|Feature Flags|window\.LDClient\b|"
      "Stripe|Payments|js\.stripe\.com/v[0-9]|"
      "Twilio|Communications|twilio\.com/js|"
      "Auth0|Identity|auth0\.com/auth|"
      "Okta|Identity|okta\.com/app|"
      "Shopify|E-Commerce|Shopify\.theme|"
      "WordPress|CMS|<meta name=\"generator\" content=\"WordPress|(?<=WordPress )[\d.]+(?=\")"
      "Drupal|CMS|Drupal\.settings\b|"
      "Next.js|Framework|__NEXT_DATA__\b|"
      "Nuxt.js|Framework|window\.__NUXT__|"
      "React|Framework|__reactFiber|"
      "Angular|Framework|ng-version=|(?<=ng-version=\")[0-9][^\"]+(?=\")"
      "Vue.js|Framework|__vue_app__|"
      "Svelte|Framework|__svelte\b|"
    )

    for BPAT in "${BODY_PATTERNS[@]}"; do
      IFS='|' read -r BTECH BCAT DETECT_RE VER_RE <<< "$BPAT"
      if echo "$BODY" | grep -qP "$DETECT_RE" 2>/dev/null; then
        local BVER=""
        if [[ -n "$VER_RE" ]]; then
          BVER=$(echo "$BODY" | grep -oP "$VER_RE" | head -1 | tr -d '\r\n' || true)
        fi
        _save_tech "$SUB" "$BTECH" "$BVER" "$BCAT" "custom_fingerprint"
      fi
    done

    # ── Header patterns ───────────────────────────────────────
    local -a HEADER_PATTERNS=(
      "Looker|BI Platform|csp/looker/"
      "WordPress|CMS|X-Powered-By: W3 Total Cache"
      "Drupal|CMS|X-Generator: Drupal"
      "PHP|Language|X-Powered-By: PHP/([0-9.]+)"
      "ASP.NET|Framework|X-Powered-By: ASP.NET"
      "Express.js|Framework|X-Powered-By: Express"
      "Ruby on Rails|Framework|X-Powered-By: Phusion Passenger"
    )

    for HPAT in "${HEADER_PATTERNS[@]}"; do
      IFS='|' read -r HTECH HCAT HREGEX <<< "$HPAT"
      if echo "$HEADERS" | grep -qiP "$HREGEX" 2>/dev/null; then
        local HVER
        HVER=$(echo "$HEADERS" | grep -oiP "$HREGEX" | grep -oP '[0-9][0-9.]+' | head -1 || true)
        _save_tech "$SUB" "$HTECH" "$HVER" "$HCAT" "header_fingerprint"
      fi
    done

    # ── Title-based detection (último recurso) ────────────────
    if [[ -n "$HTTP_TITLE" ]]; then
      case "${HTTP_TITLE,,}" in
        *looker*)   _save_tech "$SUB" "Looker" "" "BI Platform" "title_detection" ;;
        *grafana*)  _save_tech "$SUB" "Grafana" "" "Monitoring" "title_detection" ;;
        *kibana*)   _save_tech "$SUB" "Kibana" "" "Analytics" "title_detection" ;;
        *jenkins*)  _save_tech "$SUB" "Jenkins" "" "CI/CD" "title_detection" ;;
        *gitlab*)   _save_tech "$SUB" "GitLab" "" "DevOps" "title_detection" ;;
        *jira*)     _save_tech "$SUB" "Jira" "" "Project Mgmt" "title_detection" ;;
        *confluence*) _save_tech "$SUB" "Confluence" "" "Wiki" "title_detection" ;;
        *datadog*)  _save_tech "$SUB" "Datadog" "" "Monitoring" "title_detection" ;;
        *airflow*)  _save_tech "$SUB" "Airflow" "" "Workflow" "title_detection" ;;
        *jupyter*)  _save_tech "$SUB" "Jupyter" "" "Notebook" "title_detection" ;;
        *superset*) _save_tech "$SUB" "Superset" "" "BI Platform" "title_detection" ;;
      esac
    fi

  done < "$ALIVE"

  [[ "$CUSTOM_COUNT" -gt 0 ]] && log_ok "Custom fingerprints: $CUSTOM_COUNT detecciones"

  # ── Capa 5: Generic version leakage — detecta versiones en body/headers/endpoints ──
  # Lógica: si el nombre tech ya existe en DB (sin versión) → actualiza.
  #         si es desconocido → inserta como nueva entrada para que AI lo analice.
  log_info "Version leakage scan (body patterns + version endpoints)..."
  local VLEAK_COUNT=0

  _upsert_version() {
    local SUB_="$1" TECH_="$2" VER_="$3" CAT_="${4:-Unknown}" SRC_="${5:-version_leakage}"
    [[ -z "$VER_" || -z "$TECH_" ]] && return

    # ¿Ya tenemos esta tech sin versión? → actualizar
    local EXISTING
    EXISTING=$(sqlite3 "$DB_PATH" \
      "SELECT id FROM technologies
       WHERE domain_id=${DOMAIN_ID} AND subdomain='${SUB_//\'/\'\'}'
         AND tech_name='${TECH_//\'/\'\'}' AND (tech_version='' OR tech_version IS NULL)
       LIMIT 1;" 2>/dev/null || echo "")

    if [[ -n "$EXISTING" ]]; then
      sqlite3 "$DB_PATH" \
        "UPDATE technologies SET tech_version='${VER_//\'/\'\'}', source='${SRC_}'
         WHERE id=${EXISTING};" 2>/dev/null || true
      log_info "  ↳ Version actualizada: $TECH_ → $VER_ ($SUB_)"
    else
      # Tech nueva — insertar (puede ser software desconocido)
      sqlite3 "$DB_PATH" \
        "INSERT OR IGNORE INTO technologies
           (domain_id, url, subdomain, tech_name, tech_version, category, confidence, source)
         VALUES(${DOMAIN_ID}, 'https://${SUB_}', '${SUB_}',
           '${TECH_//\'/\'\'}', '${VER_//\'/\'\'}',
           '${CAT_//\'/\'\'}', 70, '${SRC_}');" 2>/dev/null || true
      log_info "  ↳ Tech nueva: $TECH_ $VER_ ($SUB_)"
    fi
    ((VLEAK_COUNT++))
  }

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue

    # Fetch login/root page (una petición, headers + body)
    local VRESP VBODY VHEADERS
    VRESP=$(curl -sL --max-time 12 --compressed -D - "https://${SUB}" 2>/dev/null | head -c 100000)
    VHEADERS=$(echo "$VRESP" | sed -n '1,/^\r\{0,1\}$/p')
    VBODY=$(echo "$VRESP" | sed '1,/^\r\{0,1\}$/d')

    # ── 1. Header: X-Powered-By: Tech/version ────────────────
    local XPB
    XPB=$(echo "$VHEADERS" | grep -oi 'X-Powered-By:[^\r\n]*' | head -1 || true)
    if [[ -n "$XPB" ]]; then
      # Forma "Tech/1.2.3"
      local XPB_TECH XPB_VER
      XPB_TECH=$(echo "$XPB" | grep -oP '(?<=X-Powered-By:\s)[^/\r\n]+' | xargs || true)
      XPB_VER=$(echo "$XPB"  | grep -oP '(?<=/)[0-9][^\s\r\n]+' | head -1 || true)
      [[ -n "$XPB_TECH" ]] && _upsert_version "$SUB" "$XPB_TECH" "$XPB_VER" "Language/Framework" "header_xpoweredby"
    fi

    # ── 2. Meta generator: <meta name="generator" content="Tech x.y.z"> ──
    local GEN
    GEN=$(echo "$VBODY" | grep -oiP '<meta[^>]+name="generator"[^>]+>' | head -3 || true)
    [[ -z "$GEN" ]] && GEN=$(echo "$VBODY" | grep -oiP "<meta[^>]+name='generator'[^>]+>" | head -3 || true)
    while IFS= read -r GTAG; do
      [[ -z "$GTAG" ]] && continue
      local GCONTENT
      GCONTENT=$(echo "$GTAG" | grep -oiP 'content="[^"]+"' | tr -d '"' | sed 's/^content=//i' | head -1 || true)
      [[ -z "$GCONTENT" ]] && GCONTENT=$(echo "$GTAG" | grep -oiP "content='[^']+'" | tr -d "'" | sed "s/^content=//i" | head -1 || true)
      if [[ -n "$GCONTENT" ]]; then
        local GTECH GVER
        GTECH=$(echo "$GCONTENT" | grep -oP '^[^\d]+' | xargs || true)
        GVER=$(echo "$GCONTENT"  | grep -oP '[0-9][0-9.]+' | head -1 || true)
        [[ -n "$GTECH" ]] && _upsert_version "$SUB" "$GTECH" "$GVER" "CMS" "meta_generator"
      fi
    done <<< "$GEN"

    # ── 3. Meta *-version tags: <meta name="app-version" content="1.2.3"> ──
    while IFS= read -r MVTAG; do
      [[ -z "$MVTAG" ]] && continue
      local MV_NAME MV_VER
      # Extraer name= y content= sin lookaheads (evita bug bash en $() con paréntesis en single-quoted)
      MV_NAME=$(echo "$MVTAG" | grep -oiP 'name="[^"]+"' | tr -d '"' | sed 's/^name=//i; s/-version$//i' | xargs || true)
      MV_VER=$(echo "$MVTAG"  | grep -oiP 'content="[0-9][^"]{1,30}"' | tr -d '"' | sed 's/^content=//i' | head -1 || true)
      [[ -n "$MV_NAME" && -n "$MV_VER" ]] && _upsert_version "$SUB" "$MV_NAME" "$MV_VER" "Unknown" "meta_version_tag"
    done < <(echo "$VBODY" | grep -oiP '<meta[^>]+name="[^"]*version[^"]*"[^>]+>' | head -5)

    # ── 4. HTML comments: <!-- v2.3.1 --> or <!-- version: 2.3.1 --> ──
    local COMMENT_VER
    COMMENT_VER=$(echo "$VBODY" | grep -oP '<!--[^->]*[0-9]+\.[0-9]+[^->]{0,10}' \
      | grep -oP '[0-9]+\.[0-9]+[^ >-]{0,10}' | head -1 || true)
    if [[ -n "$COMMENT_VER" ]]; then
      local HTITLE
      HTITLE=$(echo "$VBODY" | grep -oiP '<title[^>]*>[^<]+' | sed 's/<title[^>]*>//i' | head -1 | xargs || true)
      [[ -n "$HTITLE" ]] && _upsert_version "$SUB" "$HTITLE" "$COMMENT_VER" "Unknown" "html_comment"
    fi

    # ── 5. Generic JS window.X = {version: 'N.N.N'} patterns ──
    while IFS= read -r JSLINE; do
      [[ -z "$JSLINE" ]] && continue
      local JS_VARNAME JS_VER
      JS_VARNAME=$(echo "$JSLINE" | grep -oP 'window\.[A-Z][A-Z0-9_]+' | sed 's/window\.//' | head -1 || true)
      JS_VER=$(echo "$JSLINE" | grep -oP '"version"\s*:\s*"[0-9][^"]{1,20}"' | tr -d '"' | sed 's/version\s*:\s*//' | head -1 || true)
      [[ -z "$JS_VER" ]] && JS_VER=$(echo "$JSLINE" | grep -oP "[']version[']\s*:\s*'[0-9][^']{1,20}'" | tr -d "'" | sed "s/version\s*:\s*//" | head -1 || true)
      [[ -z "$JS_VER" ]] && JS_VER=$(echo "$JSLINE" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
      [[ -n "$JS_VARNAME" && -n "$JS_VER" ]] && _upsert_version "$SUB" "$JS_VARNAME" "$JS_VER" "Unknown" "js_global_var"
    done < <(echo "$VBODY" | grep -oP 'window\.[A-Z][A-Z0-9_]+\s*=\s*\{[^}]{0,300}version[^}]{0,100}\}' | head -10)

    # ── 6. Probe version-exposing endpoints ──────────────────
    local -a VER_ENDPOINTS=(
      "/api/version" "/version" "/version.json" "/api/v1/version" "/api/v2/version"
      "/actuator/info" "/actuator/health" "/health" "/healthz" "/status"
      "/_version" "/_info" "/info" "/api/info" "/api/health"
      "/api/status" "/app/version" "/build-info" "/buildInfo"
    )

    for VPATH in "${VER_ENDPOINTS[@]}"; do
      local VRESP_EP
      VRESP_EP=$(curl -s --max-time 6 -H "Accept: application/json" \
        "https://${SUB}${VPATH}" 2>/dev/null | head -c 4000)
      [[ -z "$VRESP_EP" ]] && continue

      # Solo procesar si parece JSON con version
      echo "$VRESP_EP" | grep -qiP '"version"' || continue

      # Extraer version
      local EP_VER
      EP_VER=$(echo "$VRESP_EP" | grep -oP '"version"\s*:\s*"[0-9][^"]{1,30}"' | tr -d '"' | sed 's/version\s*:\s*//' | head -1 || true)
      [[ -z "$EP_VER" ]] && EP_VER=$(echo "$VRESP_EP" | grep -oP "[']version[']\s*:\s*'[0-9][^']{1,30}'" | tr -d "'" | sed "s/version\s*:\s*//" | head -1 || true)
      [[ -z "$EP_VER" ]] && continue

      # Extraer nombre de la app del JSON si existe
      local EP_NAME
      EP_NAME=$(echo "$VRESP_EP" | grep -oP '"(name|app|application|service)"\s*:\s*"[^"]{1,40}"' | sed 's/.*:\s*"//; s/"$//' | head -1 || true)
      [[ -z "$EP_NAME" ]] && EP_NAME="$SUB"

      log_info "  ↳ Version endpoint $VPATH: $EP_NAME $EP_VER"
      _upsert_version "$SUB" "$EP_NAME" "$EP_VER" "Unknown" "version_endpoint:$VPATH"
      break  # Un endpoint con versión es suficiente por subdominio
    done

  done < "$ALIVE"

  [[ "$VLEAK_COUNT" -gt 0 ]] && log_ok "Version leakage: $VLEAK_COUNT versiones extraídas"

  # ── Capa 6: JS bundle filename version extraction ────────
  # Lee URLs de js_files / urls (cero fetches) y matchea filenames como:
  #   jquery-3.5.1.min.js, bootstrap.4.6.0.css, react-17.0.2.js, lodash@4.17.21.js
  # Cubre las libs más reportadas en BBP (versiones outdated → CVEs).
  log_info "JS bundle version scan (sin fetches, lee URLs en DB)..."
  local JS_VER_COUNT=0

  # Map: regex-en-URL → tech_name|category
  # Usamos PCRE: captura la versión en el grupo 1
  declare -A _JS_LIB_PATTERNS=(
    ['jquery[._-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='jQuery|JS Library'
    ['bootstrap[@._/-]v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Bootstrap|UI Framework'
    ['lodash[@._-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Lodash|JS Library'
    ['underscore[._-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Underscore|JS Library'
    ['react[@._/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)\.']='React|Framework'
    ['react-dom[@._/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)\.']='React DOM|Framework'
    ['vue[@._/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)\.']='Vue.js|Framework'
    ['angular[._/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='AngularJS|Framework'
    ['@angular/core[@/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Angular|Framework'
    ['moment[._-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Moment.js|JS Library'
    ['axios[._/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Axios|HTTP Library'
    ['d3[._/-]v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='D3.js|Visualization'
    ['fontawesome[._/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Font Awesome|Icons'
    ['polyfill[._-].*([0-9]+\.[0-9]+\.[0-9]+)']='polyfill|Polyfill'
    ['select2[._/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Select2|UI Library'
    ['datatables[._/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='DataTables|UI Library'
    ['mathjax[._/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='MathJax|Math'
    ['handlebars[._/-]v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Handlebars|Templating'
    ['knockout[._-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Knockout|MVVM'
    ['ember[._/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Ember.js|Framework'
    ['backbone[._-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Backbone.js|Framework'
    ['ckeditor[._/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='CKEditor|Editor'
    ['tinymce[._/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='TinyMCE|Editor'
    ['highlightjs[._-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Highlight.js|Syntax Highlighter'
    ['highlight\.js[._/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Highlight.js|Syntax Highlighter'
    ['prism[._/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Prism|Syntax Highlighter'
    ['swiper[._/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Swiper|UI Library'
    ['slick[._-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Slick|UI Library'
    ['popper\.js[@._/-]v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Popper.js|UI Library'
    ['video\.?js[@._/-]v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)']='Video.js|Media'
  )

  # Leer todas las URLs .js / .css de este dominio (de js_files + urls)
  # Filtrado SQL para no procesar todo el universo de URLs
  local JS_URLS
  JS_URLS=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT subdomain, url FROM js_files WHERE domain_id=${DOMAIN_ID}
    UNION
    SELECT DISTINCT
      CASE WHEN instr(url, '://') > 0
           THEN substr(url, instr(url,'://')+3, instr(substr(url, instr(url,'://')+3),'/')-1)
           ELSE '' END as subdomain,
      url
    FROM urls
    WHERE domain_id=${DOMAIN_ID}
      AND (url LIKE '%.js' OR url LIKE '%.js?%' OR url LIKE '%.css' OR url LIKE '%.css?%');
  " 2>/dev/null)

  while IFS='|' read -r SUB URL; do
    [[ -z "$URL" ]] && continue
    [[ -z "$SUB" ]] && SUB=$(echo "$URL" | sed 's|https\?://||;s|/.*||')

    for PAT in "${!_JS_LIB_PATTERNS[@]}"; do
      local MATCH
      MATCH=$(echo "$URL" | grep -oiP "$PAT" | head -1) || continue
      [[ -z "$MATCH" ]] && continue

      # Extraer versión: el primer grupo numérico tras el separador
      local VER
      VER=$(echo "$MATCH" | grep -oP '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
      [[ -z "$VER" ]] && continue

      IFS='|' read -r LIB_NAME LIB_CAT <<< "${_JS_LIB_PATTERNS[$PAT]}"
      db_upsert_tech "$DOMAIN_ID" "$URL" "$SUB" \
        "$LIB_NAME" "$VER" "$LIB_CAT" "85" "js_filename" 2>/dev/null || true
      ((JS_VER_COUNT++))
    done
  done <<< "$JS_URLS"

  [[ "$JS_VER_COUNT" -gt 0 ]] && \
    log_ok "JS bundle versions: $JS_VER_COUNT detecciones (sin fetches)"

  # ── Capa C: Custom registry (refactor 2026-05-09) ───────────
  # Usa core/tech_registry.json + data/tech_registry_custom.json para detectar
  # CMS/middleware/ecommerce/SSO/etc con guarda catch-all + body_re obligatorio.
  # Resultado se persiste en `technologies` con source='registry'.
  log_info "Capa C — custom tech registry (CMS/middleware/SSO/devops)..."
  local REGISTRY_DETECTIONS=0
  local SUGGESTIONS_FILE="$OUT_DIR/tech_suggestions.txt"
  > "$SUGGESTIONS_FILE"

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    # Tier 2.7: format actualizado a 6 campos (KIND TECH CAT CVE_FAM VERSION REASON)
    while IFS=$'\t' read -r KIND TECH CATEGORY CVE_FAMILY VERSION REASON; do
      [[ -z "$KIND" ]] && continue
      if [[ "$KIND" == "MATCH" ]]; then
        # VERSION puede estar vacío si el host no expone version banner
        db_upsert_tech "$DOMAIN_ID" "$BASE" "$SUB" \
          "$TECH" "$VERSION" "$CATEGORY" "90" "registry" 2>/dev/null || true
        ((REGISTRY_DETECTIONS++))
      elif [[ "$KIND" == "SUGGEST" ]]; then
        # SUGGEST tiene format antiguo (KIND + 1 valor) — TECH contiene el marker
        echo "$SUB|$TECH" >> "$SUGGESTIONS_FILE"
      fi
    done < <(timeout 30 python3 -W ignore "$SCRIPT_DIR/core/tech_detector.py" --suggest --probe-host "$BASE" 2>/dev/null)
  done < "$ALIVE"

  [[ "$REGISTRY_DETECTIONS" -gt 0 ]] && \
    log_ok "Custom registry: $REGISTRY_DETECTIONS detecciones (CMS/middleware/SSO/etc)"

  if [[ -s "$SUGGESTIONS_FILE" ]]; then
    local SUGG_COUNT
    SUGG_COUNT=$(wc -l < "$SUGGESTIONS_FILE" | tr -d ' ')
    log_info "tech_suggestions.txt: $SUGG_COUNT markers desconocidos para review manual"
    log_info "  Para añadir: ./tools/tech_add.sh \"Tech Name\" CATEGORY HEADER_RE BODY_RE [URL_PROBES] [STATUS]"
  fi

  # ── Resumen en log ────────────────────────────────────────
  TOTAL_FOUND=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(DISTINCT tech_name||url) FROM technologies WHERE domain_id=${DOMAIN_ID};" 2>/dev/null || echo "?")

  local TOP_TECHS
  TOP_TECHS=$(sqlite3 "$DB_PATH" \
    "SELECT tech_name || COALESCE(' ' || tech_version, '') || ' (' || COUNT(*) || ')'
     FROM technologies WHERE domain_id=${DOMAIN_ID}
     GROUP BY tech_name, tech_version ORDER BY COUNT(*) DESC LIMIT 5;" \
    2>/dev/null | paste -sd ', ' || echo "")

  log_ok "$MODULE_DESC completado: $TOTAL_FOUND detecciones"
  [[ -n "$TOP_TECHS" ]] && log_info "Top techs: $TOP_TECHS"

  rm -f "$TARGETS"
}
