#!/usr/bin/env bash
# modules/56_cookie_attacks.sh — Tier 3.10 Cookie security audit
MODULE_NAME="cookie_attacks"
MODULE_DESC="Cookie audit — Secure/HttpOnly/SameSite/__Host- prefix"

_co_finding() {
  db_add_finding "$1" "cookie_attacks" "$5" "$3" "$4" "$6" "${7:-medium}" 2>/dev/null
  log_warn "  ⚡ [$5/${7:-medium}] Cookie $4: $3"
  if [[ "${7:-medium}" != "low" ]] && [[ "$5" == "high" ]]; then
    _telegram_send "🟠 *Cookie — $4*
🌐 \`$2\` 🔗 \`$3\`
📋 ${6:0:250}
📊 \`${5^^}\`/\`${7:-medium}\`" 2>/dev/null || true
  fi
}

_co_check() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"
  _h_get_noredirect "$URL" --connect-timeout 6
  local HEADERS="$HTTP_LAST_HEADERS"

  # Para cada Set-Cookie línea
  local COOKIE_LINES; COOKIE_LINES=$(echo "$HEADERS" | grep -i '^set-cookie:')
  [[ -z "$COOKIE_LINES" ]] && return 1

  local FINDINGS_HERE=0
  while IFS= read -r LINE; do
    [[ -z "$LINE" ]] && continue
    local COOKIE_NAME; COOKIE_NAME=$(echo "$LINE" | sed -E 's/^[Ss]et-[Cc]ookie:\s*([^=]+)=.*/\1/' | tr -d ' \r')
    [[ -z "$COOKIE_NAME" ]] && continue
    local COOKIE_LOWER; COOKIE_LOWER=$(echo "$LINE" | tr 'A-Z' 'a-z')

    # Cookie de sesión sin HttpOnly (vulnerable a XSS robo)
    if echo "$COOKIE_LOWER" | grep -qE 'session|sessid|sid|jsessionid|phpsessid|aspsessionid|connect\.sid'; then
      if ! echo "$COOKIE_LOWER" | grep -q 'httponly'; then
        _co_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "session_no_httponly" "high" \
          "Cookie de sesión '${COOKIE_NAME}' sin HttpOnly — XSS puede robar la cookie. Set-Cookie: ${LINE:0:200}" \
          "high"
        ((FINDINGS_HERE++))
      fi
      if ! echo "$COOKIE_LOWER" | grep -q 'secure'; then
        _co_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "session_no_secure" "high" \
          "Cookie de sesión '${COOKIE_NAME}' sin Secure flag — sniff posible en HTTP downgrade. ${LINE:0:200}" \
          "high"
        ((FINDINGS_HERE++))
      fi
    fi

    # SameSite=None sin Secure (browsers rechazan, pero algunos viejos no)
    if echo "$COOKIE_LOWER" | grep -qE 'samesite=none' && ! echo "$COOKIE_LOWER" | grep -q 'secure'; then
      _co_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "samesite_none_no_secure" "medium" \
        "Cookie '${COOKIE_NAME}' SameSite=None sin Secure — modern browsers reject pero clients viejos aceptan. ${LINE:0:200}" \
        "medium"
      ((FINDINGS_HERE++))
    fi

    # __Host- prefix sin Path=/; Secure
    if [[ "$COOKIE_NAME" == __Host-* ]]; then
      if ! echo "$COOKIE_LOWER" | grep -q 'path=/' || \
         ! echo "$COOKIE_LOWER" | grep -q 'secure' || \
         echo "$COOKIE_LOWER" | grep -q 'domain='; then
        _co_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "host_prefix_invalid" "medium" \
          "Cookie con prefijo __Host- pero falta Path=/, Secure o tiene Domain= — browser puede rechazar. ${LINE:0:200}" \
          "medium"
        ((FINDINGS_HERE++))
      fi
    fi

    # __Secure- prefix sin Secure
    if [[ "$COOKIE_NAME" == __Secure-* ]] && ! echo "$COOKIE_LOWER" | grep -q 'secure'; then
      _co_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "secure_prefix_no_secure" "medium" \
        "Cookie con prefijo __Secure- pero sin Secure flag — browser rechaza." \
        "medium"
      ((FINDINGS_HERE++))
    fi
  done <<< "$COOKIE_LINES"

  [[ $FINDINGS_HERE -gt 0 ]] && return 0 || return 1
}

module_run() {
  local DOMAIN="$1" DOMAIN_ID="$2" OUT_DIR="$3"
  log_phase "Módulo 56 — $MODULE_DESC: $DOMAIN"
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null

  # Hosts alive (root path) — Set-Cookie típicamente solo en login/auth response
  local TARGETS
  TARGETS=$(sqlite3 "$DB_PATH" "
    SELECT subdomain FROM subdomains
    WHERE domain_id=${DOMAIN_ID} AND status='alive'
    LIMIT 30;" 2>/dev/null)
  # Plus URLs con login/session
  local LOGIN_URLS
  LOGIN_URLS=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls
    WHERE domain_id=${DOMAIN_ID}
      AND (url LIKE '%/login%' OR url LIKE '%/auth%' OR url LIKE '%/session%')
    LIMIT 10;" 2>/dev/null | sort -u)

  local TOTAL=0
  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    _co_check "https://${SUB}/" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$TARGETS"
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    _co_check "${URL%%\?*}" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$LOGIN_URLS"
  log_ok "$MODULE_DESC: $TOTAL hosts con cookie issues"
}
