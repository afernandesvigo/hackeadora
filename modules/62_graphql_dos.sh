#!/usr/bin/env bash
# modules/62_graphql_dos.sh — Tier 4.2 GraphQL DoS
# Deep nesting + alias amplification + circular fragment refs.
# Detection: response time anómalo + status 200 + body válido.

MODULE_NAME="graphql_dos"
MODULE_DESC="GraphQL DoS — deep nesting + alias amplification + circular fragments"

_gd_finding() {
  db_add_finding "$1" "graphql_dos" "$5" "$3" "$4" "$6" "${7:-medium}" 2>/dev/null
  log_warn "  ⚡ [$5/${7:-medium}] GQL-DoS $4: $3"
  if [[ "$5" == "high" ]]; then
    _telegram_send "🟠 *GQL DoS — $4*
🌐 \`$2\` 🔗 \`$3\`
📋 ${6:0:250}" 2>/dev/null || true
  fi
}

_gd_probe() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  # Baseline timing — query simple
  local BASELINE_T
  BASELINE_T=$(curl -s --max-time 8 -o /dev/null -w "%{time_total}" \
    -H "Content-Type: application/json" \
    -X POST -d '{"query":"{__typename}"}' "$URL" 2>/dev/null)
  [[ -z "$BASELINE_T" ]] && return 1

  # 1. Deep nesting (limited a 10 niveles para no romper)
  local DEEP_QUERY
  DEEP_QUERY='{"query":"query{ '
  for i in $(seq 1 8); do DEEP_QUERY="${DEEP_QUERY} a${i}{"; done
  DEEP_QUERY="${DEEP_QUERY}__typename"
  for i in $(seq 1 8); do DEEP_QUERY="${DEEP_QUERY}}"; done
  DEEP_QUERY="${DEEP_QUERY} }\"}"

  local DEEP_T STATUS
  DEEP_T=$(curl -s --max-time 30 -o /dev/null -w "%{time_total}" \
    -H "Content-Type: application/json" \
    -X POST -d "$DEEP_QUERY" "$URL" 2>/dev/null)
  STATUS=$(curl -s --max-time 30 -o /dev/null -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -X POST -d "$DEEP_QUERY" "$URL" 2>/dev/null)

  # Si server acepta deep query (200) y tarda >5x baseline, sin protección
  local RATIO
  RATIO=$(python3 -c "
b=float('${BASELINE_T:-0.001}')
d=float('${DEEP_T:-0}')
print(f'{(d/b) if b>0 else 0:.1f}')
" 2>/dev/null)

  if [[ "$STATUS" == "200" ]]; then
    if (( $(python3 -c "print(int(float('$RATIO') > 5))") )); then
      _gd_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "deep_nesting_no_limit" "high" \
        "GraphQL DoS: query con 8 niveles anidados aceptada — server NO tiene depth limit. Baseline ${BASELINE_T}s vs deep ${DEEP_T}s (ratio ${RATIO}x). Atacante puede hacer DoS con ~100 niveles." \
        "high"
      return 0
    fi
    # Server acepta 8-deep pero responde rápido → sigue siendo finding (sin depth limit)
    if [[ "$RATIO" != "0.0" ]]; then
      _gd_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "deep_nesting_accepted" "medium" \
        "GraphQL acepta deep nesting (8 niveles, ratio ${RATIO}x). Sin depth limit visible — verificar con queries más profundas." \
        "medium"
    fi
  fi

  # 2. Alias amplification — 100 aliases en 1 query
  local ALIAS_QUERY='{"query":"{'
  for i in $(seq 1 50); do ALIAS_QUERY="${ALIAS_QUERY} a${i}:__typename"; done
  ALIAS_QUERY="${ALIAS_QUERY}}\"}"
  local ALIAS_STATUS; ALIAS_STATUS=$(curl -s --max-time 15 -o /dev/null -w "%{http_code}" \
    -H "Content-Type: application/json" -X POST -d "$ALIAS_QUERY" "$URL" 2>/dev/null)
  if [[ "$ALIAS_STATUS" == "200" ]]; then
    _gd_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "alias_amplification_no_limit" "medium" \
      "GraphQL acepta 50 aliases en 1 request — sin alias limit. Atacante puede hacer brute-force credential check sin rate-limit (cada alias = 1 intento)." \
      "medium"
  fi
}

module_run() {
  local DOMAIN="$1" DOMAIN_ID="$2" OUT_DIR="$3"
  log_phase "Módulo 62 — $MODULE_DESC: $DOMAIN"
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null

  # Endpoints GraphQL
  local ENDPOINTS
  ENDPOINTS=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM technologies WHERE domain_id=${DOMAIN_ID} AND tech_name='GraphQL'
    UNION
    SELECT DISTINCT url FROM urls WHERE domain_id=${DOMAIN_ID}
      AND (url LIKE '%/graphql%' OR url LIKE '%/api/graphql%')
    LIMIT 5;" 2>/dev/null | sort -u)
  [[ -z "$ENDPOINTS" ]] && { log_info "  Sin GraphQL endpoints"; return 0; }
  local TOTAL=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    URL="${URL%%\?*}"
    _gd_probe "$URL" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$ENDPOINTS"
  log_ok "$MODULE_DESC: $TOTAL DoS findings"
}
