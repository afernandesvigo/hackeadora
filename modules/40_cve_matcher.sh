#!/usr/bin/env bash
# ============================================================
#  modules/40_cve_matcher.sh
#  Tier 2.1 — Tech→CVE matcher (reemplaza nuclei deadweight Bug #14).
#
#  Lee technologies(tech_name, tech_version) detectadas por mod 09/10 y las
#  cruza contra data/cve_catalog.json + data/cve_catalog_custom.json. Inserta
#  findings con confidence basado en si el CVE tiene rango específico (medium)
#  o aplica a "*" (low). Notifica Telegram para critical/high con confidence
#  >= medium.
#
#  Diseño:
#  - 0 fetches HTTP propios (todo desde DB) → ejecución <5s típica
#  - Iterativo: usuario añade CVEs nuevos con `tools/cve_add.sh` y se reflejan
#    en próximo scan
#  - Confidence sale de cve_matcher.py (medium si version_in_range, low si "*")
# ============================================================

MODULE_NAME="cve_matcher"
MODULE_DESC="Tech→CVE matcher (catalog-based, sin nuclei)"

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 40 — $MODULE_DESC: $DOMAIN"

  if [[ ! -f "$SCRIPT_DIR/core/cve_matcher.py" ]]; then
    log_warn "core/cve_matcher.py no existe — saltando"
    return 0
  fi

  if [[ ! -f "$SCRIPT_DIR/core/cve_catalog.json" ]]; then
    log_warn "core/cve_catalog.json no existe — saltando"
    return 0
  fi

  local TECH_COUNT
  TECH_COUNT=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(DISTINCT tech_name||'|'||COALESCE(tech_version,''))
     FROM technologies WHERE domain_id=${DOMAIN_ID} AND tech_version IS NOT NULL AND tech_version != '';" \
    2>/dev/null || echo "0")

  if [[ "${TECH_COUNT:-0}" -eq 0 ]]; then
    log_info "  Sin tecnologías con versión detectada — saltando matcher"
    log_info "  (mod 09/10 deben emitir tech_version. Capa C registry y JS bundles ayudan.)"
    return 0
  fi

  log_info "  Cruzando ${TECH_COUNT} (tech, version) únicos contra catálogo CVE..."

  local MATCHES_JSON
  MATCHES_JSON=$(python3 "$SCRIPT_DIR/core/cve_matcher.py" \
    --domain "$DOMAIN" --db "$DB_PATH" --json 2>/dev/null)

  if [[ -z "$MATCHES_JSON" || "$MATCHES_JSON" == "[]" ]]; then
    log_ok "$MODULE_DESC: 0 matches en catálogo (versiones detectadas no afectadas por CVEs conocidas)"
    return 0
  fi

  # Persistir cada match como finding (parsing JSON con jq).
  local TOTAL=0
  local TMP_MATCHES; TMP_MATCHES=$(mktemp /tmp/cve_matches.XXXXXX)
  echo "$MATCHES_JSON" > "$TMP_MATCHES"

  TOTAL=$(jq 'length' "$TMP_MATCHES" 2>/dev/null || echo 0)
  if [[ "${TOTAL:-0}" -eq 0 ]]; then
    rm -f "$TMP_MATCHES"
    log_ok "$MODULE_DESC: 0 matches contra catálogo CVE"
    return 0
  fi

  # Iterar matches con jq (TSV-safe usando @sh)
  jq -r '.[] | [.cve, .severity, .confidence, .tech_name, .tech_version, .subdomain, .url, .title, .description, .poc, .ref] | @tsv' "$TMP_MATCHES" | \
  while IFS=$'\t' read -r CVE SEV CONF TECH VER SUB TARGET TITLE DESC POC REF; do
    [[ -z "$CVE" ]] && continue

    local FINDING_TARGET="${TARGET:-https://${SUB}}"
    local DETAIL="${TITLE} | tech=${TECH} v${VER} | ${DESC:0:300} | PoC: ${POC:0:200} | ref: ${REF}"

    db_add_finding "$DOMAIN_ID" "cve_match" "$SEV" \
      "$FINDING_TARGET" "$CVE" "$DETAIL" "$CONF" 2>/dev/null

    log_warn "  ⚡ [$SEV/$CONF] $CVE en $SUB — $TECH v$VER"

    # Telegram solo para confidence>=medium AND severity>=high
    if [[ "$CONF" != "low" ]] && [[ "$SEV" == "critical" || "$SEV" == "high" ]]; then
      local EMOJI="🟠"
      [[ "$SEV" == "critical" ]] && EMOJI="🔴"
      _telegram_send "${EMOJI} *CVE Match — ${CVE}*
🌐 \`${DOMAIN}\`
🎯 \`${SUB}\` (${TECH} v${VER})
📋 ${TITLE}
📊 Severity: \`${SEV^^}\` | Confidence: \`${CONF}\`
💉 PoC: \`${POC:0:200}\`
🔗 ${REF}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
    fi
  done

  rm -f "$TMP_MATCHES"

  log_ok "$MODULE_DESC: ${TOTAL} matches contra catálogo CVE"

  if [[ "$TOTAL" -gt 0 ]]; then
    _telegram_send "🎯 *CVE Matcher — resumen*
🌐 \`${DOMAIN}\`
🆕 ${TOTAL} matches en catálogo curado
💡 Catalog: \`core/cve_catalog.json\` (${TECH_COUNT} techs cruzadas)
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi
}
