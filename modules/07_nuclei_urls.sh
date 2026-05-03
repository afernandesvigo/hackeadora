#!/usr/bin/env bash
# ============================================================
#  modules/07_nuclei_urls.sh
#  Fase 7: Nuclei sobre URLs nuevas descubiertas
# ============================================================
# API pública del módulo:
#   module_run <domain> <domain_id> <output_dir>
# ============================================================

MODULE_NAME="nuclei_urls"
MODULE_DESC="Nuclei sobre nuevas URLs"

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 07 — $MODULE_DESC: $DOMAIN"

  if ! command -v "${NUCLEI_BIN:-nuclei}" &>/dev/null; then
    log_warn "nuclei no encontrado, saltando"
    return
  fi

  # In single-target mode, scope nuclei to the specific subdomain
  local ALIVE="$OUT_DIR/subs_alive.txt"
  local SINGLE_SUB=""
  if [[ -s "$ALIVE" && "$(wc -l < "$ALIVE" | tr -d ' ')" == "1" ]]; then
    SINGLE_SUB=$(head -1 "$ALIVE" | tr -d '[:space:]')
  fi

  # Obtener URLs pendientes de nuclei desde la DB
  local PENDING_FILE="$OUT_DIR/.nuclei_pending_urls.txt"
  db_get_urls_nuclei_pending "$DOMAIN_ID" "${SINGLE_SUB}" > "$PENDING_FILE"

  if [[ ! -s "$PENDING_FILE" ]]; then
    log_info "No hay URLs nuevas para escanear con nuclei"
    rm -f "$PENDING_FILE"
    return
  fi

  local COUNT
  COUNT=$(wc -l < "$PENDING_FILE" | tr -d ' ')
  log_info "Lanzando nuclei sobre $COUNT URLs..."

  # Rotador de IPs
  source "${SCRIPT_DIR}/core/rotator.sh" 2>/dev/null || true

  local NUCLEI_OUT="$OUT_DIR/nuclei_urls_$(date '+%Y%m%d_%H%M%S').jsonl"
  local SEVERITY="${NUCLEI_SEVERITY:-medium,high,critical}"
  local THREADS="${NUCLEI_THREADS:-25}"
  local NUCLEI_TIMEOUT="${NUCLEI_MODULE_TIMEOUT:-900}"
  # Cap configurable: 1000 por defecto (prioridad ya aplicada en db_get_urls_nuclei_pending)
  local URL_CAP="${NUCLEI_URL_CAP:-1000}"

  head -"$URL_CAP" "$PENDING_FILE" > "${PENDING_FILE}.cap"
  mv "${PENDING_FILE}.cap" "$PENDING_FILE"
  COUNT=$(wc -l < "$PENDING_FILE" | tr -d ' ')
  log_info "Lanzando nuclei sobre $COUNT URLs (cap $URL_CAP, priorizadas por relevancia)..."

  # Tags base + tecnología detectada
  local TECH_TAGS=""
  if [[ -f "$OUT_DIR/tech_results.json" ]]; then
    local TECHS
    TECHS=$(python3 -c "
import json, sys
try:
    data = json.load(open('$OUT_DIR/tech_results.json'))
    techs = []
    for item in (data if isinstance(data,list) else [data]):
        techs += [t.lower() for t in item.get('technologies',[])]
    print(','.join(set(techs)))
except: pass
" 2>/dev/null | tr '[:upper:]' '[:lower:]')
    [[ "$TECHS" == *"wordpress"* ]] && TECH_TAGS="wordpress,"
    [[ "$TECHS" == *"drupal"* ]]    && TECH_TAGS="${TECH_TAGS}drupal,"
    [[ "$TECHS" == *"jira"* ]]      && TECH_TAGS="${TECH_TAGS}jira,"
    [[ "$TECHS" == *"confluence"* ]] && TECH_TAGS="${TECH_TAGS}confluence,"
    [[ "$TECHS" == *"jenkins"* ]]   && TECH_TAGS="${TECH_TAGS}jenkins,"
    [[ "$TECHS" == *"spring"* ]]    && TECH_TAGS="${TECH_TAGS}spring,"
    [[ "$TECHS" == *"outsystems"* ]] && TECH_TAGS="${TECH_TAGS}outsystems,"
    [[ "$TECHS" == *"iis"* ]]       && TECH_TAGS="${TECH_TAGS}iis,"
  fi
  local ALL_TAGS="${TECH_TAGS}xss,sqli,ssrf,rce,lfi,idor,open-redirect,exposures,misconfiguration,cves"
  [[ -n "$TECH_TAGS" ]] && log_info "Tech detectada → añadiendo tags: ${TECH_TAGS%,}"

  timeout "$NUCLEI_TIMEOUT" \
  "${NUCLEI_BIN:-nuclei}" \
    -l "$PENDING_FILE" \
    -severity "$SEVERITY" \
    -jsonl \
    -o "$NUCLEI_OUT" \
    -c "$THREADS" \
    -rl 50 \
    -timeout 10 \
    -max-host-error 5 \
    -silent \
    -no-interactsh \
    ${SCAN_UA:+-H "User-Agent: ${SCAN_UA}"} \
    -tags "$ALL_TAGS" \
    ${NUCLEI_EXTRA_TEMPLATES:+-t "$NUCLEI_EXTRA_TEMPLATES"} \
    2>/dev/null \
  || log_warn "nuclei URLs: completado o timeout tras ${NUCLEI_TIMEOUT}s"

  # Procesar resultados (JSONL: una línea por finding)
  if [[ -s "$NUCLEI_OUT" ]]; then
    local FINDINGS=0
    while IFS= read -r LINE; do
      [[ -z "$LINE" ]] && continue
      local TEMPLATE SEVERITY_F HOST DETAIL
      TEMPLATE=$(echo "$LINE"   | jq -r '.["template-id"] // "unknown"' 2>/dev/null)
      SEVERITY_F=$(echo "$LINE" | jq -r '.info.severity // "unknown"' 2>/dev/null)
      HOST=$(echo "$LINE"       | jq -r '.["matched-at"] // .host // ""' 2>/dev/null)
      DETAIL=$(echo "$LINE"     | jq -r '.info.name // ""' 2>/dev/null)

      [[ -z "$TEMPLATE" || "$TEMPLATE" == "unknown" ]] && continue
      log_warn "🔴 Nuclei URL [$SEVERITY_F]: $TEMPLATE @ $HOST"
      notify_nuclei_finding "$DOMAIN" "$TEMPLATE" "$SEVERITY_F" "$HOST" "$DETAIL"
      db_add_finding "$DOMAIN_ID" "nuclei_url" "$SEVERITY_F" "$HOST" "$TEMPLATE" "$DETAIL"
      ((FINDINGS++))
    done < "$NUCLEI_OUT"
    log_ok "$FINDINGS findings de nuclei sobre URLs"
  fi

  # Marcar URLs como nuclei_done
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    db_mark_url_nuclei_done "$DOMAIN_ID" "$URL"
  done < "$PENDING_FILE"

  rm -f "$PENDING_FILE"
  log_ok "$MODULE_DESC completado"
}
