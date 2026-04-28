#!/usr/bin/env bash
# ============================================================
#  modules/04_nuclei_scan.sh
#  Fase 4: Nuclei sobre subdominios nuevos (alive)
# ============================================================
# API pública del módulo:
#   module_run <domain> <domain_id> <output_dir>
# ============================================================

MODULE_NAME="nuclei_scan"
MODULE_DESC="Nuclei scan sobre subdominios nuevos"

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 04 — $MODULE_DESC: $DOMAIN"

  if ! command -v "${NUCLEI_BIN:-nuclei}" &>/dev/null; then
    log_warn "nuclei no encontrado, saltando"
    return
  fi

  # Obtener subdominios alive pendientes de nuclei
  local PENDING_FILE="$OUT_DIR/.nuclei_pending_subs.txt"
  db_get_subdomain_nuclei_pending "$DOMAIN_ID" > "$PENDING_FILE"

  if [[ ! -s "$PENDING_FILE" ]]; then
    log_info "No hay subdominios nuevos para escanear con nuclei"
    rm -f "$PENDING_FILE"
    return
  fi

  local COUNT
  COUNT=$(wc -l < "$PENDING_FILE" | tr -d ' ')
  log_info "Lanzando nuclei sobre $COUNT subdominios..."

  # ── Rotador de IPs (opcional) ──────────────────────────────
  source "$(dirname "$0")/../core/rotator.sh" 2>/dev/null || true
  if rotator_enabled && rotator_should_rotate; then
    log_info "Rotando IP para nuclei scan..."
  fi

  local NUCLEI_OUT="$OUT_DIR/nuclei_subs_$(date '+%Y%m%d_%H%M%S').json"
  local SEVERITY="${NUCLEI_SEVERITY:-medium,high,critical}"
  local THREADS="${NUCLEI_THREADS:-25}"

  # Preparar lista con https:// prefix
  sed 's|^|https://|' "$PENDING_FILE" > "$OUT_DIR/.nuclei_targets.txt"

  "${NUCLEI_BIN:-nuclei}" \
    -l "$OUT_DIR/.nuclei_targets.txt" \
    -severity "$SEVERITY" \
    -json-export "$NUCLEI_OUT" \
    -c "$THREADS" \
    -silent \
    -no-interactsh \
    ${NUCLEI_EXTRA_TEMPLATES:+-t "$NUCLEI_EXTRA_TEMPLATES"} \
    2>/dev/null \
  || log_warn "nuclei: error en ejecución"

  # Procesar resultados JSON
  if [[ -s "$NUCLEI_OUT" ]] && command -v jq &>/dev/null; then
    log_info "Procesando findings de nuclei..."
    while IFS= read -r LINE; do
      local TEMPLATE SEVERITY_F HOST INFO DETAIL
      TEMPLATE=$(echo "$LINE"  | jq -r '.template-id // "unknown"')
      SEVERITY_F=$(echo "$LINE" | jq -r '.info.severity // "unknown"')
      HOST=$(echo "$LINE"      | jq -r '.host // .matched-at // ""')
      INFO=$(echo "$LINE"      | jq -r '.info.name // ""')
      DETAIL=$(echo "$LINE"    | jq -r '.matched-at // .curl-command // ""' | head -c 300)

      log_warn "🔴 Nuclei finding [$SEVERITY_F]: $TEMPLATE @ $HOST"
      notify_nuclei_finding "$DOMAIN" "$TEMPLATE" "$SEVERITY_F" "$HOST" "$DETAIL"
      db_add_finding "$DOMAIN_ID" "nuclei" "$SEVERITY_F" "$HOST" "$TEMPLATE" "$DETAIL"
    done < <(jq -c '.' "$NUCLEI_OUT" 2>/dev/null)
  fi

  # Marcar subdominios como nuclei_done
  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    db_mark_subdomain_nuclei_done "$DOMAIN_ID" "$SUB"
  done < "$PENDING_FILE"

  rm -f "$PENDING_FILE" "$OUT_DIR/.nuclei_targets.txt"
  log_ok "$MODULE_DESC completado"
}
