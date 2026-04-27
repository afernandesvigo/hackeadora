#!/usr/bin/env bash
# ============================================================
#  modules/03_takeover.sh
#  Fase 3: Detección de Subdomain Takeover
#  Herramientas: subzy, subjack
# ============================================================
# API pública del módulo:
#   module_run <domain> <domain_id> <output_dir>
#   Lee:    <output_dir>/subs_dead.txt  (candidatos más probables)
#            <output_dir>/subs_raw.txt  (todos)
#   Escribe: <output_dir>/takeover_results.txt
# ============================================================

MODULE_NAME="takeover"
MODULE_DESC="Detección de Subdomain Takeover"

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  local RAW="$OUT_DIR/subs_raw.txt"
  local DEAD="$OUT_DIR/subs_dead.txt"
  local OUT="$OUT_DIR/takeover_results.txt"
  > "$OUT"

  log_phase "Módulo 03 — $MODULE_DESC: $DOMAIN"

  # Usar preferentemente los dead (más candidatos a takeover)
  # pero pasar también todos para cobertura completa
  local TARGET_LIST="$RAW"
  if [[ -s "$DEAD" ]]; then
    log_info "Usando subdominios dead como candidatos prioritarios"
    TARGET_LIST="$DEAD"
  fi

  if [[ ! -s "$TARGET_LIST" ]]; then
    log_warn "No hay subdominios para analizar, saltando"
    return
  fi

  # ── subzy ─────────────────────────────────────────────────
  if command -v "${SUBZY_BIN:-subzy}" &>/dev/null; then
    log_info "Ejecutando subzy..."
    local SUBZY_OUT="$OUT_DIR/.subzy_raw.txt"

    "${SUBZY_BIN:-subzy}" run \
      --targets "$TARGET_LIST" \
      --concurrency 50 \
      --hide_fails \
      --vuln \
      > "$SUBZY_OUT" 2>/dev/null \
    || log_warn "subzy: error en ejecución"

    if [[ -s "$SUBZY_OUT" ]]; then
      log_info "Procesando resultados de subzy..."
      while IFS= read -r LINE; do
        [[ -z "$LINE" ]] && continue
        # subzy imprime: [VULN] <subdominio> - <servicio>
        local SUB SERVICE
        SUB=$(echo "$LINE" | grep -oP '(?<=\[VULN\] )[^\s]+' | head -1)
        SERVICE=$(echo "$LINE" | grep -oP '(?<= - ).+$' | head -1)

        if [[ -n "$SUB" ]]; then
          log_warn "⚠ TAKEOVER: $SUB ($SERVICE)"
          echo "[subzy] $SUB — $SERVICE" >> "$OUT"
          notify_takeover "$SUB" "$SERVICE" "$LINE"
          db_add_finding "$DOMAIN_ID" "takeover" "high" "$SUB" "subzy" "$LINE"
        fi
      done < "$SUBZY_OUT"
      rm -f "$SUBZY_OUT"
    fi
  else
    log_warn "subzy no encontrado, saltando"
  fi

  # ── subjack ───────────────────────────────────────────────
  if command -v subjack &>/dev/null; then
    log_info "Ejecutando subjack..."
    local SUBJACK_OUT="$OUT_DIR/.subjack_raw.txt"
    local FINGERPRINTS=""
    # Usar fingerprints incluidas en el binario
    [[ -f "$HOME/go/pkg/mod/github.com/haccer/subjack"*"/fingerprints.json" ]] && \
      FINGERPRINTS=$(ls "$HOME/go/pkg/mod/github.com/haccer/subjack"*"/fingerprints.json" 2>/dev/null | head -1)

    subjack \
      -w "$TARGET_LIST" \
      -t 100 \
      -timeout 30 \
      -o "$SUBJACK_OUT" \
      ${FINGERPRINTS:+-c "$FINGERPRINTS"} \
      -ssl \
      2>/dev/null \
    || log_warn "subjack: error en ejecución"

    if [[ -s "$SUBJACK_OUT" ]]; then
      while IFS= read -r LINE; do
        [[ -z "$LINE" ]] && continue
        local SUB
        SUB=$(echo "$LINE" | awk '{print $1}')
        log_warn "⚠ TAKEOVER (subjack): $LINE"
        echo "[subjack] $LINE" >> "$OUT"
        notify_takeover "$SUB" "unknown" "$LINE"
        db_add_finding "$DOMAIN_ID" "takeover" "high" "$SUB" "subjack" "$LINE"
      done < "$SUBJACK_OUT"
      rm -f "$SUBJACK_OUT"
    fi
  else
    log_warn "subjack no encontrado, saltando"
  fi

  local COUNT
  COUNT=$(wc -l < "$OUT" | tr -d ' ')
  log_ok "$MODULE_DESC completado: $COUNT posibles takeovers encontrados"
}
