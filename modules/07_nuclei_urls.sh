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

  # Obtener URLs pendientes de nuclei desde la DB
  local PENDING_FILE="$OUT_DIR/.nuclei_pending_urls.txt"
  db_get_urls_nuclei_pending "$DOMAIN_ID" > "$PENDING_FILE"

  if [[ ! -s "$PENDING_FILE" ]]; then
    log_info "No hay URLs nuevas para escanear con nuclei"
    rm -f "$PENDING_FILE"
    return
  fi

  local COUNT
  COUNT=$(wc -l < "$PENDING_FILE" | tr -d ' ')
  log_info "Lanzando nuclei sobre $COUNT URLs..."

  # Rotador de IPs
  source "$(dirname "$0")/../core/rotator.sh" 2>/dev/null || true

  local NUCLEI_OUT="$OUT_DIR/nuclei_urls_$(date '+%Y%m%d_%H%M%S').json"
  local SEVERITY="${NUCLEI_SEVERITY:-medium,high,critical}"
  local THREADS="${NUCLEI_THREADS:-25}"

  "${NUCLEI_BIN:-nuclei}" \
    -l "$PENDING_FILE" \
    -severity "$SEVERITY" \
    -json-export "$NUCLEI_OUT" \
    -c "$THREADS" \
    -silent \
    -no-interactsh \
    -tags "xss,sqli,ssrf,rce,lfi,idor,open-redirect,exposures,misconfiguration,cves" \
    ${NUCLEI_EXTRA_TEMPLATES:+-t "$NUCLEI_EXTRA_TEMPLATES"} \
    2>/dev/null \
  || log_warn "nuclei: error en ejecución"

  # Procesar resultados
  if [[ -s "$NUCLEI_OUT" ]] && command -v jq &>/dev/null; then
    local FINDINGS=0
    while IFS= read -r LINE; do
      local TEMPLATE SEVERITY_F HOST DETAIL
      TEMPLATE=$(echo "$LINE"   | jq -r '.template-id // "unknown"')
      SEVERITY_F=$(echo "$LINE" | jq -r '.info.severity // "unknown"')
      HOST=$(echo "$LINE"       | jq -r '.matched-at // .host // ""')
      DETAIL=$(echo "$LINE"     | jq -r '.info.name // ""')

      log_warn "🔴 Nuclei URL [$SEVERITY_F]: $TEMPLATE @ $HOST"
      notify_nuclei_finding "$DOMAIN" "$TEMPLATE" "$SEVERITY_F" "$HOST" "$DETAIL"
      db_add_finding "$DOMAIN_ID" "nuclei_url" "$SEVERITY_F" "$HOST" "$TEMPLATE" "$DETAIL"
      ((FINDINGS++))
    done < <(jq -c '.' "$NUCLEI_OUT" 2>/dev/null)
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
