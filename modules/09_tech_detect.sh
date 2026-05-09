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
  local TMP_TARGETS="$OUT_DIR/.whatweb_targets.txt"
  > "$TMP_OUT"

  # Incluir https:// y http:// para cada host — whatweb filtra duplicados de contenido
  sed 's|^|https://|' "$ALIVE" > "$TMP_TARGETS"
  sed 's|^|http://|'  "$ALIVE" >> "$TMP_TARGETS"

  # --max-threads: procesa todos los hosts en paralelo en una sola invocación
  whatweb --aggression 1 --quiet \
    --max-threads 20 \
    --follow-redirect NEVER \
    --log-json="$TMP_OUT" \
    -i "$TMP_TARGETS" \
    2>/dev/null || true

  rm -f "$TMP_TARGETS"

  # Convertir el JSON array del fichero a líneas individuales para el parser
  local TMP_LINES="$OUT_DIR/.whatweb_lines.json"
  jq -c '.[]' "$TMP_OUT" 2>/dev/null > "$TMP_LINES" || cp "$TMP_OUT" "$TMP_LINES"

  # Parsear y guardar en DB (ya una línea = un JSON object)
  # 1) tabla `subdomains.tech` con la lista de plugins (compat existente)
  # 2) tabla `technologies` con name + version (extraída de .plugins[].version[0])
  local TECH_VER_COUNT=0
  if [[ -s "$TMP_LINES" ]] && command -v jq &>/dev/null; then
    while IFS= read -r LINE; do
      local TARGET TARGET_URL PLUGINS TECH_JSON
      TARGET_URL=$(echo "$LINE" | jq -r '.target // ""' 2>/dev/null) || continue
      [[ -z "$TARGET_URL" ]] && continue
      TARGET=$(echo "$TARGET_URL" | sed 's|https\?://||;s|/.*||')

      PLUGINS=$(echo "$LINE" | jq -r '[.plugins | keys[]] | join(", ")' 2>/dev/null || echo "")
      TECH_JSON=$(echo "$LINE" | jq -c '.plugins | keys' 2>/dev/null || echo "[]")

      if [[ -n "$PLUGINS" ]]; then
        log_info "$TARGET → $PLUGINS"
        sqlite3 "$DB_PATH" \
          "UPDATE subdomains SET tech='${TECH_JSON//\'/\'\'}'
           WHERE domain_id=${DOMAIN_ID} AND subdomain='${TARGET}';" 2>/dev/null || true

        # Poblar tabla `technologies`. Iteramos cada plugin para extraer su versión.
        # Formato whatweb: {"PluginName": {"version": ["1.2.3"], "string": [...]}}
        while IFS=$'\t' read -r TNAME TVER; do
          [[ -z "$TNAME" ]] && continue
          db_upsert_tech "$DOMAIN_ID" "$TARGET_URL" "$TARGET" \
            "$TNAME" "$TVER" "" "70" "whatweb"
          [[ -n "$TVER" ]] && ((TECH_VER_COUNT++))
        done < <(echo "$LINE" | jq -r '.plugins | to_entries[] | "\(.key)\t\(.value.version[0] // "")"' 2>/dev/null)
      fi

      echo "$LINE" >> "$OUT_JSON"
    done < "$TMP_LINES"
  fi
  [[ "$TECH_VER_COUNT" -gt 0 ]] && \
    log_ok "  ✦ whatweb extrajo $TECH_VER_COUNT versiones a tabla technologies"

  rm -f "$TMP_OUT" "$TMP_LINES"
  local RESULT_COUNT
  RESULT_COUNT=$(wc -l < "$OUT_JSON" | tr -d ' ')
  log_ok "$MODULE_DESC completado: $RESULT_COUNT subdominios analizados"
}
