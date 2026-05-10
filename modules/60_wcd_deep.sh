#!/usr/bin/env bash
# modules/60_wcd_deep.sh — Tier 4.2 Web Cache Deception deep
# Variantes adicionales sobre mod 28: extension confusion + path normalization
# + cache key manipulation.

MODULE_NAME="wcd_deep"
MODULE_DESC="Web Cache Deception deep — extension confusion + path tricks"

_wcd_finding() {
  db_add_finding "$1" "wcd_deep" "$5" "$3" "$4" "$6" "${7:-medium}" 2>/dev/null
  log_warn "  ⚡ [$5/${7:-medium}] WCD $4: $3"
  if [[ "$5" == "high" ]]; then
    _telegram_send "🟠 *WCD Deep — $4*
🌐 \`$2\` 🔗 \`$3\`
📋 ${6:0:280}" 2>/dev/null || true
  fi
}

_wcd_probe() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"
  # Páginas autenticadas devuelven datos privados; con WCD tras /static/ semantic
  # el CDN cachea como pública
  local PROBES=(
    "/non-existent-static-${RANDOM}.css"
    "/static/x.${RANDOM}.css"
    "/api/me;.css"
    "/api/me%2F${RANDOM}.css"
    "/account/profile/.css"
    "/account/profile.css/test"
  )

  local ROOT_BASE; ROOT_BASE=$(echo "$URL" | grep -oP 'https?://[^/]+')
  for PROBE in "${PROBES[@]}"; do
    local TEST_URL="${ROOT_BASE}${PROBE}"
    _h_get_noredirect "$TEST_URL" --connect-timeout 8
    local STATUS="$HTTP_LAST_STATUS"
    local CACHE; CACHE=$(echo "$HTTP_LAST_HEADERS" | grep -iE '^(x-cache|cache-control|cf-cache-status|age|x-served-by):' | head -3 | tr '\n' ' ')

    # Si responde 200 con Cache-Control public/max-age >0 + datos auth-específicos en body → WCD posible
    if [[ "$STATUS" == "200" ]] && \
       echo "$CACHE" | grep -qiE 'cache-control:.*(public|max-age=[1-9])|x-cache.*HIT|cf-cache-status.*HIT|age:[[:space:]]*[1-9]'; then
      local BODY="${HTTP_LAST_BODY:0:1500}"
      if echo "$BODY" | grep -qiE '"email":|"username":|csrf|session_token|"role":|user_id|account_id'; then
        _wcd_finding "$DOMAIN_ID" "$DOMAIN" "$TEST_URL" "wcd_auth_data_cached" "high" \
          "Web Cache Deception: ${PROBE} cachea respuesta con datos auth (email/role/session). Cache headers: ${CACHE:0:150}" \
          "medium"
        return 0
      fi
    fi
  done
  return 1
}

module_run() {
  local DOMAIN="$1" DOMAIN_ID="$2" OUT_DIR="$3"
  log_phase "Módulo 60 — $MODULE_DESC: $DOMAIN"
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null

  local CANDIDATES
  CANDIDATES=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT subdomain FROM subdomains
    WHERE domain_id=${DOMAIN_ID} AND status='alive'
    LIMIT 20;" 2>/dev/null)
  [[ -z "$CANDIDATES" ]] && { log_info "  Sin alive subs"; return 0; }
  local TOTAL=0
  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    _wcd_probe "https://${SUB}/" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$CANDIDATES"
  log_ok "$MODULE_DESC: $TOTAL WCD detected"
}
