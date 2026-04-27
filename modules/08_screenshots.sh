#!/usr/bin/env bash
# ============================================================
#  modules/08_screenshots.sh
#  Fase 8: Screenshots de subdominios alive (gowitness)
# ============================================================

MODULE_NAME="screenshots"
MODULE_DESC="Screenshots de subdominios (gowitness)"

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  local ALIVE="$OUT_DIR/subs_alive.txt"
  local SHOTS_DIR="$OUT_DIR/screenshots"

  log_phase "Módulo 08 — $MODULE_DESC: $DOMAIN"

  if ! command -v gowitness &>/dev/null; then
    log_warn "gowitness no encontrado (instala: go install github.com/sensepost/gowitness@latest)"
    return
  fi

  if [[ ! -s "$ALIVE" ]]; then
    log_warn "No hay subdominios alive, saltando screenshots"
    return
  fi

  mkdir -p "$SHOTS_DIR"

  # Generar lista con https://
  local TARGETS="$OUT_DIR/.gowitness_targets.txt"
  sed 's|^|https://|' "$ALIVE" > "$TARGETS"
  # También http://
  sed 's|^|http://|' "$ALIVE" >> "$TARGETS"

  local COUNT
  COUNT=$(wc -l < "$ALIVE" | tr -d ' ')
  log_info "Capturando screenshots de $COUNT subdominios..."

  gowitness file \
    -f "$TARGETS" \
    --screenshot-path "$SHOTS_DIR" \
    --threads 4 \
    --timeout 10 \
    --disable-db \
    2>/dev/null \
  || log_warn "gowitness: algunos errores (normal para hosts sin HTTP)"

  # Guardar metadata en DB: añadir ruta de screenshot al subdominio
  local SHOT_COUNT
  SHOT_COUNT=$(find "$SHOTS_DIR" -name "*.png" 2>/dev/null | wc -l | tr -d ' ')

  # Actualizar campo tech en subdominio con ruta del screenshot
  if command -v sqlite3 &>/dev/null && [[ "$SHOT_COUNT" -gt 0 ]]; then
    sqlite3 "$DB_PATH" \
      "UPDATE subdomains SET tech=json_set(COALESCE(tech,'{}'),'$.screenshot_dir','${SHOTS_DIR}')
       WHERE domain_id=${DOMAIN_ID} AND status='alive';" 2>/dev/null || true
  fi

  rm -f "$TARGETS"
  log_ok "$MODULE_DESC completado: $SHOT_COUNT screenshots capturados en $SHOTS_DIR"
}
