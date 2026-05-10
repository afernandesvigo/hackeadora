#!/usr/bin/env bash
# modules/58_dom_xss_static.sh — Tier 4.2 DOM XSS static analysis
# Analiza JS files buscando flujos source→sink (location.hash → innerHTML, etc.)
# Sin headless browser — pattern matching estricto.

MODULE_NAME="dom_xss_static"
MODULE_DESC="DOM XSS static — source→sink flow analysis en JS files"

_dx_finding() {
  db_add_finding "$1" "dom_xss" "$5" "$3" "$4" "$6" "${7:-medium}" 2>/dev/null
  log_warn "  ⚡ [$5/${7:-medium}] DOMXSS $4: $3"
  if [[ "${7:-medium}" != "low" ]] && [[ "$5" == "high" ]]; then
    _telegram_send "🟠 *DOM XSS — $4*
🌐 \`$2\` 🔗 \`$3\`
📋 ${6:0:280}" 2>/dev/null || true
  fi
}

_dx_check_js() {
  local JS_URL="$1" DOMAIN_ID="$2" DOMAIN="$3"
  _h_get_noredirect "$JS_URL" --connect-timeout 8
  local BODY="$HTTP_LAST_BODY"
  [[ -z "$BODY" || ${#BODY} -lt 100 ]] && return 1

  # Sources peligrosos
  local SOURCES='location\.hash|location\.search|location\.href|window\.name|document\.referrer|document\.URL|document\.documentURI|history\.pushState|message\.data'
  # Sinks peligrosos
  local SINKS='innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|document\.writeln\s*\(|eval\s*\(|setTimeout\s*\(|setInterval\s*\(|new\s+Function\s*\(|jQuery.*\.html\s*\(|\$\([^)]+\)\.html\s*\(|insertAdjacentHTML\s*\(|location\s*=|location\.href\s*='

  local FINDINGS_HERE=()
  # Buscar bloques cortos donde aparecen source y sink cerca (~200 chars)
  python3 -c "
import re, sys
js = sys.stdin.read()
sources = re.compile(r'($SOURCES)')
sinks = re.compile(r'($SINKS)')
for m in sources.finditer(js):
    pos = m.start()
    ctx = js[max(0,pos-50):pos+250]
    sm = sinks.search(ctx)
    if sm:
        snippet = ctx[max(0,sm.start()-30):sm.end()+50].replace('\n',' ')[:180]
        print(f'{m.group(1)}|{sm.group(1)}|{snippet}')
" <<< "$BODY" 2>/dev/null | head -3 | while IFS='|' read -r SRC SINK SNIPPET; do
    [[ -z "$SRC" || -z "$SINK" ]] && continue
    _dx_finding "$DOMAIN_ID" "$DOMAIN" "$JS_URL" "source_${SRC%%[\\.\\(]*}_to_sink_${SINK%%[\\.\\(\\s]*}" "high" \
      "DOM XSS flow: ${SRC} → ${SINK} en ${JS_URL}. Snippet: ${SNIPPET:0:180}" \
      "medium"
    return 0
  done
}

module_run() {
  local DOMAIN="$1" DOMAIN_ID="$2" OUT_DIR="$3"
  log_phase "Módulo 58 — $MODULE_DESC: $DOMAIN"
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null

  local JS_URLS
  JS_URLS=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls WHERE domain_id=${DOMAIN_ID}
    AND (url LIKE '%.js' OR url LIKE '%.js?%')
    AND url NOT LIKE '%/jquery%' AND url NOT LIKE '%/bootstrap%'
    AND url NOT LIKE '%/lodash%' AND url NOT LIKE '%/react.production%'
    LIMIT 30;" 2>/dev/null | sort -u)
  [[ -z "$JS_URLS" ]] && { log_info "  Sin JS files candidatos"; return 0; }
  local TOTAL=0
  while IFS= read -r JS; do
    [[ -z "$JS" ]] && continue
    _dx_check_js "$JS" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$JS_URLS"
  log_ok "$MODULE_DESC: $TOTAL DOM XSS flows"
}
