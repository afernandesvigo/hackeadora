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

  local TMP_OUT="$OUT_DIR/.whatweb_raw.json"
  > "$TMP_OUT"

  # Aggression 1 = pasivo (no intrusivo). Prueba HTTPS; fallback a HTTP.
  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local URL="https://${SUB}"
    local WW_OUT
    WW_OUT=$(whatweb --aggression 1 --quiet --log-json=/dev/stdout "$URL" 2>/dev/null)
    # Si HTTPS devuelve array vacío, intentar HTTP
    if [[ "$WW_OUT" == "["* ]] && echo "$WW_OUT" | jq -e '. == []' &>/dev/null; then
      WW_OUT=$(whatweb --aggression 1 --quiet --log-json=/dev/stdout "http://${SUB}" 2>/dev/null) || true
    fi
    # Aplanar el array (una línea por objeto) y añadir al fichero temporal
    echo "$WW_OUT" | jq -c '.[]' 2>/dev/null >> "$TMP_OUT" || true
  done < "$ALIVE"

  # Parsear y guardar en DB (ya una línea = un JSON object)
  if [[ -s "$TMP_OUT" ]] && command -v jq &>/dev/null; then
    while IFS= read -r LINE; do
      local TARGET PLUGINS TECH_JSON
      TARGET=$(echo "$LINE" | jq -r '.target // ""' 2>/dev/null | sed 's|https\?://||;s|/.*||') || continue
      [[ -z "$TARGET" ]] && continue

      PLUGINS=$(echo "$LINE" | jq -r '[.plugins | keys[]] | join(", ")' 2>/dev/null || echo "")
      TECH_JSON=$(echo "$LINE" | jq -c '.plugins | keys' 2>/dev/null || echo "[]")

      if [[ -n "$PLUGINS" ]]; then
        log_info "$TARGET → $PLUGINS"
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
