#!/usr/bin/env bash
# ============================================================
#  modules/06_active_scan.sh
#  Fase 6: Descubrimiento de directorios con ffuf
#
#  Estrategia:
#    1. Fuzzear raíz del dominio (/FUZZ)
#    2. Si la raíz redirige a un path de app (/ca/inici, /app/...),
#       fuzzear también ese base path (/ca/FUZZ, /app/FUZZ)
#    3. Filtrar WAF/CDN con detección de respuesta uniforme
#    4. Guardar 403/401 en DB para que módulo 23 intente bypass
# ============================================================

MODULE_NAME="active_scan"
MODULE_DESC="Descubrimiento de directorios (ffuf)"

_WORDLISTS=(
  "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
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

# Fuzzear un target con ffuf, guardar resultados en DB
# Retorna solo el número de hallazgos via stdout; logs van a stderr
_ffuf_target() {
  local TARGET_URL="$1"   # URL con /FUZZ al final
  local SUB="$2"
  local DOMAIN_ID="$3"
  local WORDLIST="$4"
  local RATE="$5"
  local WAF_FILTER="$6"   # -fs XXXX o vacío
  local FFUF_PROXY_FLAG="$7"
  local OUT_DIR="$8"
  local LABEL="$9"

  # Redirigir stdout a stderr para que los logs no contaminen el valor de retorno
  exec 3>&1 1>&2

  local FFUF_OUT="$OUT_DIR/.ffuf_${LABEL//[^a-zA-Z0-9]/_}.json"
  local FOUND=0

  "${FFUF_BIN:-ffuf}" \
    -u "$TARGET_URL" \
    -w "$WORDLIST" \
    -mc 200,201,204,301,302,307,401,403,405,500 \
    ${WAF_FILTER} \
    -o "$FFUF_OUT" \
    -of json \
    -rate "$RATE" \
    -t 40 \
    -timeout 10 \
    -s \
    ${FFUF_PROXY_FLAG} \
    2>/dev/null || true

  if [[ -s "$FFUF_OUT" ]] && command -v jq &>/dev/null; then
    FOUND=$(jq -r '.results | length' "$FFUF_OUT" 2>/dev/null || echo 0)

    if [[ "$FOUND" -gt 0 ]]; then
      log_warn "  ffuf [$LABEL]: $FOUND paths encontrados"

      # URLs 200/201/204/301/302/307 → DB como URLs normales
      jq -r '.results[] | select(.status == 200 or .status == 201 or .status == 204 or .status == 301 or .status == 302 or .status == 307) | "\(.url) \(.status)"' \
        "$FFUF_OUT" 2>/dev/null | while IFS=' ' read -r URL STATUS; do
        db_add_url "$DOMAIN_ID" "$URL" "ffuf" "$STATUS"
        log_info "    → [$STATUS] $URL"
      done

      # 401/403 → DB también (para módulo 23 bypass) si no hay WAF activo
      if [[ -z "$WAF_FILTER" ]]; then
        jq -r '.results[] | select(.status == 401 or .status == 403) | "\(.url) \(.status)"' \
          "$FFUF_OUT" 2>/dev/null | while IFS=' ' read -r URL STATUS; do
          db_add_url "$DOMAIN_ID" "$URL" "ffuf" "$STATUS"
          log_info "    → [$STATUS] $URL (candidato bypass)"
        done
      fi
    fi
    rm -f "$FFUF_OUT"
  fi

  # Escribir el número de hallazgos al stdout original (fd3)
  echo "$FOUND" >&3
  exec 1>&3 3>&-
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

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

  local ALIVE="$OUT_DIR/subs_alive.txt"
  if [[ ! -s "$ALIVE" ]]; then
    log_warn "Sin subdominios alive, saltando"
    return
  fi

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local FFUF_PROXY_FLAG=""
  $PROXY_ACTIVE && FFUF_PROXY_FLAG="-replay-proxy ${PROXY_URL}"

  local RATE="${FFUF_RATE:-50}"
  local TOTAL_FINDINGS=0

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    log_info "Fuzzing directorios en $SUB..."

    # ── Detección WAF: respuesta uniforme en paths aleatorios ──
    local WAF_SIZE1 WAF_SIZE2
    WAF_SIZE1=$(curl -s -A "${SCAN_UA:-Mozilla/5.0}" --max-time 6 \
      -o /dev/null -w "%{size_download}" \
      "https://${SUB}/this-path-never-exists-$(date +%s%N)" 2>/dev/null)
    WAF_SIZE2=$(curl -s -A "${SCAN_UA:-Mozilla/5.0}" --max-time 6 \
      -o /dev/null -w "%{size_download}" \
      "https://${SUB}/another-random-$(openssl rand -hex 4)" 2>/dev/null)
    local WAF_FILTER=""
    if [[ -n "$WAF_SIZE1" && "$WAF_SIZE1" == "$WAF_SIZE2" && "$WAF_SIZE1" -gt 500 ]]; then
      WAF_FILTER="-fs ${WAF_SIZE1}"
      log_info "  WAF/CDN detectado (respuesta uniforme: ${WAF_SIZE1}B) — activando filtro"
    fi

    # ── Fuzz 1: raíz del dominio ───────────────────────────────
    local FOUND
    FOUND=$(_ffuf_target "https://${SUB}/FUZZ" "$SUB" "$DOMAIN_ID" \
      "$WORDLIST" "$RATE" "$WAF_FILTER" "$FFUF_PROXY_FLAG" "$OUT_DIR" "${SUB}_root")
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + FOUND))

    # ── Fuzz 2: path base de la app (si raíz redirige) ────────
    local ROOT_LOCATION
    ROOT_LOCATION=$(curl -s -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 \
      -o /dev/null -w "%{redirect_url}" \
      "https://${SUB}/" 2>/dev/null)

    if [[ -n "$ROOT_LOCATION" ]]; then
      # Extraer base path: https://host/ca/inici → /ca/
      local APP_BASE
      APP_BASE=$(echo "$ROOT_LOCATION" | sed -E 's|https?://[^/]+||' | grep -oP '^/[^/]+/' | head -1)

      if [[ -n "$APP_BASE" && "$APP_BASE" != "/" ]]; then
        log_info "  Raíz redirige a $ROOT_LOCATION — fuzzeando también base path: $APP_BASE"
        local LABEL_APP="${SUB}_$(echo "$APP_BASE" | tr -d '/')"
        FOUND=$(_ffuf_target "https://${SUB}${APP_BASE}FUZZ" "$SUB" "$DOMAIN_ID" \
          "$WORDLIST" "$RATE" "$WAF_FILTER" "$FFUF_PROXY_FLAG" "$OUT_DIR" "$LABEL_APP")
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + FOUND))
      fi
    fi

  done < "$ALIVE"

  if [[ "$TOTAL_FINDINGS" -gt 0 ]]; then
    _telegram_send "🗂️ *Directory Fuzzing (ffuf)*
🌐 \`${DOMAIN}\`
📂 $TOTAL_FINDINGS paths descubiertos
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi

  log_ok "$MODULE_DESC completado: $TOTAL_FINDINGS paths encontrados"
}
