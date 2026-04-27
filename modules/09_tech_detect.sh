#!/usr/bin/env bash
# ============================================================
#  modules/09_tech_detect.sh
#  Fase 9: Detección de tecnologías (whatweb)
# ============================================================

MODULE_NAME="tech_detect"
MODULE_DESC="Detección de tecnologías (whatweb)"

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  local ALIVE="$OUT_DIR/subs_alive.txt"
  local OUT_JSON="$OUT_DIR/tech_results.json"
  > "$OUT_JSON"

  log_phase "Módulo 09 — $MODULE_DESC: $DOMAIN"

  if ! command -v whatweb &>/dev/null; then
    log_warn "whatweb no encontrado (instala: apt install whatweb)"
    # Intentar con httpx tech-detect como fallback (ya se hace en módulo 02)
    log_info "Usando tech detection de httpx (módulo 02) como fallback"
    return
  fi

  if [[ ! -s "$ALIVE" ]]; then
    log_warn "No hay subdominios alive, saltando"
    return
  fi

  local COUNT
  COUNT=$(wc -l < "$ALIVE" | tr -d ' ')
  log_info "Analizando tecnologías en $COUNT subdominios..."

  local TMP_OUT="$OUT_DIR/.whatweb_raw.txt"

  # Aggression 1 = pasivo (no intrusivo)
  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    whatweb \
      --aggression 1 \
      --quiet \
      --log-json=/dev/stdout \
      "https://${SUB}" \
      2>/dev/null \
    >> "$TMP_OUT" || true
  done < "$ALIVE"

  # Parsear y guardar en DB
  if [[ -s "$TMP_OUT" ]] && command -v jq &>/dev/null; then
    while IFS= read -r LINE; do
      local TARGET PLUGINS TECH_JSON
      TARGET=$(echo "$LINE" | jq -r '.target // ""' | sed 's|https\?://||;s|/.*||')
      [[ -z "$TARGET" ]] && continue

      # Extraer plugins detectados como array de strings
      PLUGINS=$(echo "$LINE" | jq -r '[.plugins | keys[]] | join(", ")' 2>/dev/null || echo "")
      TECH_JSON=$(echo "$LINE" | jq -c '.plugins | keys' 2>/dev/null || echo "[]")

      if [[ -n "$PLUGINS" ]]; then
        log_info "$TARGET → $PLUGINS"
        # Guardar en DB
        sqlite3 "$DB_PATH" \
          "UPDATE subdomains SET tech='${TECH_JSON//\'/\'\'}' 
           WHERE domain_id=${DOMAIN_ID} AND subdomain='${TARGET}';" 2>/dev/null || true
      fi

      echo "$LINE" >> "$OUT_JSON"
    done < "$TMP_OUT"
  fi

  rm -f "$TMP_OUT"
  local RESULT_COUNT
  RESULT_COUNT=$(wc -l < "$OUT_JSON" | tr -d ' ')
  log_ok "$MODULE_DESC completado: $RESULT_COUNT subdominios analizados"
}
