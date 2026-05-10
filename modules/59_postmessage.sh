#!/usr/bin/env bash
# modules/59_postmessage.sh — Tier 4.2 PostMessage origin laxness
# Detecta listeners postMessage sin origin check → cross-origin DOM access.

MODULE_NAME="postmessage"
MODULE_DESC="PostMessage — origin check ausente en window.addEventListener('message')"

_pm_finding() {
  db_add_finding "$1" "postmessage" "$5" "$3" "$4" "$6" "${7:-medium}" 2>/dev/null
  log_warn "  ⚡ [$5/${7:-medium}] PostMsg $4: $3"
}

_pm_check_js() {
  local JS_URL="$1" DOMAIN_ID="$2" DOMAIN="$3"
  _h_get_noredirect "$JS_URL" --connect-timeout 8
  local BODY="$HTTP_LAST_BODY"
  [[ ${#BODY} -lt 200 ]] && return 1

  # Buscar addEventListener('message', ...) dentro de ventana ~600 chars
  local LISTENERS
  LISTENERS=$(python3 -c "
import re, sys
js = sys.stdin.read()
# Match: addEventListener('message', handler) y captura 600 chars siguientes
pattern = re.compile(r'addEventListener\s*\(\s*[\"\\']message[\"\\']\s*,\s*([^)]{0,800})')
results = []
for m in pattern.finditer(js):
    handler_body = m.group(1) + js[m.end():m.end()+600]
    # Si NO contiene origin check → vulnerable
    has_origin_check = bool(re.search(r'(\.origin|\.source\s*===|origin\s*===|origin\s*==|origin\.match|origin\.indexOf|origin\.startsWith|trustedOrigins|allowedOrigins)', handler_body[:600]))
    if not has_origin_check:
        snippet = handler_body[:250].replace('\n',' ')
        results.append(snippet)
for r in results[:3]:
    print(r)
" <<< "$BODY" 2>/dev/null)
  [[ -z "$LISTENERS" ]] && return 1

  local SNIPPET; SNIPPET=$(echo "$LISTENERS" | head -1)
  _pm_finding "$DOMAIN_ID" "$DOMAIN" "$JS_URL" "postmessage_no_origin_check" "high" \
    "JS contiene window.addEventListener('message',...) sin origin check — atacante puede iframe + postMessage para invocar handler sensible. Snippet: ${SNIPPET:0:200}" \
    "medium"
  return 0
}

module_run() {
  local DOMAIN="$1" DOMAIN_ID="$2" OUT_DIR="$3"
  log_phase "Módulo 59 — $MODULE_DESC: $DOMAIN"
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null

  local JS_URLS
  JS_URLS=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls WHERE domain_id=${DOMAIN_ID}
    AND (url LIKE '%.js' OR url LIKE '%.js?%')
    LIMIT 40;" 2>/dev/null | sort -u)
  [[ -z "$JS_URLS" ]] && { log_info "  Sin JS files"; return 0; }
  local TOTAL=0
  while IFS= read -r JS; do
    [[ -z "$JS" ]] && continue
    _pm_check_js "$JS" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$JS_URLS"
  log_ok "$MODULE_DESC: $TOTAL postmessage handlers vulnerables"
}
