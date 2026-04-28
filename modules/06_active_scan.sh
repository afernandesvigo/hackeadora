#!/usr/bin/env bash
# ============================================================
#  modules/06_active_scan.sh
#  Fase 6: Descubrimiento de directorios con ffuf
#  Todo el tráfico pasa por proxy (Caido/Burp)
# ============================================================

MODULE_NAME="active_scan"
MODULE_DESC="Descubrimiento de directorios via proxy (ffuf)"

_WORDLISTS=(
  "/usr/share/seclists/Discovery/Web-Content/common.txt"
  "/usr/share/wordlists/dirb/common.txt"
  "/opt/SecLists/Discovery/Web-Content/common.txt"
  "$HOME/wordlists/common.txt"
)

_find_wordlist() {
  for WL in "${_WORDLISTS[@]}"; do
    [[ -f "$WL" ]] && { echo "$WL"; return; }
  done
  local DEFAULT="/tmp/recon_common.txt"
  if [[ ! -f "$DEFAULT" ]]; then
    log_info "Descargando wordlist básica..."
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
      -o "$DEFAULT" 2>/dev/null || log_warn "No se pudo descargar wordlist"
  fi
  echo "$DEFAULT"
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  local ALIVE="$OUT_DIR/subs_alive.txt"
  local OUT="$OUT_DIR/active_scan_results.json"
  > "$OUT"

  log_phase "Módulo 06 — $MODULE_DESC: $DOMAIN"

  if ! command -v "${FFUF_BIN:-ffuf}" &>/dev/null; then
    log_warn "ffuf no encontrado, saltando"
    return
  fi

  local WORDLIST
  WORDLIST=$(_find_wordlist)
  if [[ -z "$WORDLIST" ]] || [[ ! -f "$WORDLIST" ]]; then
    log_warn "Sin wordlist disponible, saltando"
    return
  fi

  # ── Proxy ────────────────────────────────────────────────
  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  proxy_check
  local FFUF_PROXY_FLAG=""
  $PROXY_ACTIVE && FFUF_PROXY_FLAG="-replay-proxy ${PROXY_URL}" && \
    log_info "ffuf enrutado por ${PROXY_TOOL}: ${PROXY_URL}"

  local RATE="${FFUF_RATE:-50}"
  local FINDINGS=0

  if [[ ! -s "$ALIVE" ]]; then
    log_warn "Sin subdominios alive, saltando"
    return
  fi

  # ── Rotador de IPs (opcional) ──────────────────────────────
  source "$(dirname "$0")/../core/rotator.sh" 2>/dev/null || true
  if rotator_enabled; then
    log_info "Rotador activo — ffuf usará IPs rotadas cada ${ROTATOR_INTERVAL} peticiones"
  fi

  log_info "Fuzzing de directorios sobre subdominios alive..."

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local TARGET="https://${SUB}/FUZZ"
    local FFUF_OUT="$OUT_DIR/.ffuf_${SUB//[^a-zA-Z0-9]/_}.json"

    "${FFUF_BIN:-ffuf}" \
      -u "$TARGET" \
      -w "$WORDLIST" \
      -mc 200,201,204,301,302,307,401,403,500 \
      -o "$FFUF_OUT" \
      -of json \
      -rate "$RATE" \
      -t 40 \
      -timeout 10 \
      -s \
      ${FFUF_PROXY_FLAG} \
      2>/dev/null || true

    if [[ -s "$FFUF_OUT" ]] && command -v jq &>/dev/null; then
      local RESULTS
      RESULTS=$(jq -r '.results | length' "$FFUF_OUT" 2>/dev/null || echo 0)

      if [[ "$RESULTS" -gt 0 ]]; then
        log_warn "ffuf: $RESULTS directorios en $SUB"
        jq -c '.results[]' "$FFUF_OUT" 2>/dev/null >> "$OUT"

        # Añadir URLs encontradas a la DB
        jq -r '.results[].url' "$FFUF_OUT" 2>/dev/null | while IFS= read -r URL; do
          local IS_NEW
          IS_NEW=$(db_is_new_url "$DOMAIN_ID" "$URL")
          db_add_url "$DOMAIN_ID" "$URL" "ffuf" ""
          # Si es nueva, notificar
          if [[ "$IS_NEW" == "1" ]]; then
            log_info "  → nuevo directorio: $URL"
          fi
        done
        ((FINDINGS += RESULTS))
      fi
      rm -f "$FFUF_OUT"
    fi
  done < "$ALIVE"

  if [[ "$FINDINGS" -gt 0 ]]; then
    _telegram_send "🔍 *Directory Scan — ffuf*
🌐 \`${DOMAIN}\`
📂 $FINDINGS directorios descubiertos
🔀 Tráfico registrado en ${PROXY_TOOL:-proxy}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
    db_add_finding "$DOMAIN_ID" "active_scan" "info" "$DOMAIN" "ffuf" "$FINDINGS directorios encontrados"
  fi

  log_ok "$MODULE_DESC completado: $FINDINGS directorios encontrados"
}
