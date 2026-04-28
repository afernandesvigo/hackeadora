#!/usr/bin/env bash
# ============================================================
#  modules/24_http_smuggling.sh
#  Fase 24: HTTP Request Smuggling detection
#
#  Técnicas:
#    - CL.TE (Content-Length + Transfer-Encoding)
#    - TE.CL (Transfer-Encoding + Content-Length)
#    - TE.TE (doble Transfer-Encoding ofuscado)
#    - HTTP/2 Downgrade smuggling
#
#  Herramientas:
#    - smuggler.py (defparam/smuggler)
#    - nuclei templates de smuggling
#    - Detección manual via timing
#
#  Referencias:
#    - PortSwigger HTTP Request Smuggling
#    - HackerOne top smuggling reports
# ============================================================

MODULE_NAME="http_smuggling"
MODULE_DESC="HTTP Request Smuggling detector"

# ── Instalar smuggler si no está ──────────────────────────────
_ensure_smuggler() {
  local SMUGGLER_PATH="$HOME/tools/smuggler/smuggler.py"

  if [[ -f "$SMUGGLER_PATH" ]]; then
    echo "$SMUGGLER_PATH"
    return 0
  fi

  log_info "Instalando smuggler..."
  mkdir -p "$HOME/tools"
  git clone -q https://github.com/defparam/smuggler.git \
    "$HOME/tools/smuggler" 2>/dev/null

  if [[ -f "$SMUGGLER_PATH" ]]; then
    pip3 install --break-system-packages requests 2>/dev/null || true
    echo "$SMUGGLER_PATH"
    return 0
  fi

  return 1
}

# ── Test de timing manual CL.TE ──────────────────────────────
_test_clte_timing() {
  local HOST="$1"
  local PORT="${2:-443}"
  local USE_TLS="${3:-true}"
  local PROXY_FLAG="$4"

  # CL.TE: Content-Length dice 6, pero hay body más largo con chunk encoding
  # Si el servidor es vulnerable, la segunda petición tará X segundos (timing)
  local PAYLOAD='POST / HTTP/1.1\r\nHost: '"$HOST"'\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG'

  local START END DIFF
  START=$(date +%s%N)
  curl -s --max-time 15 \
    --http1.1 \
    -X POST \
    -H "Content-Length: 6" \
    -H "Transfer-Encoding: chunked" \
    -d $'0\r\n\r\nG' \
    ${PROXY_FLAG} \
    "https://${HOST}/" \
    -o /dev/null 2>/dev/null
  END=$(date +%s%N)

  DIFF=$(( (END - START) / 1000000 ))  # ms
  echo "$DIFF"
}

# ── Test con smuggler ─────────────────────────────────────────
_run_smuggler() {
  local URL="$1"
  local DOMAIN_ID="$2"
  local DOMAIN="$3"
  local OUT_DIR="$4"

  local SMUGGLER
  SMUGGLER=$(_ensure_smuggler) || {
    log_warn "smuggler no disponible"
    return 1
  }

  local HOST
  HOST=$(echo "$URL" | sed 's|https\?://||;s|/.*||;s|:.*||')
  local PORT=443
  echo "$URL" | grep -q "^http://" && PORT=80

  log_info "  🔍 smuggler sobre $HOST:$PORT..."
  local SMUGGLER_OUT="$OUT_DIR/.smuggler_${HOST//[^a-zA-Z0-9]/_}.txt"

  # Rotador de IPs para smuggling (muy ruidoso)
  source "$(dirname "$0")/../core/rotator.sh" 2>/dev/null || true

  local SMUGGLER_CMD="python3 ${SMUGGLER} -u ${URL} --quiet 2>/dev/null"

  if rotator_enabled; then
    rotator_exec "$SMUGGLER_CMD" "$SMUGGLER_OUT" || \
      eval "$SMUGGLER_CMD" > "$SMUGGLER_OUT" 2>/dev/null
  else
    timeout 60 python3 "$SMUGGLER" -u "$URL" --quiet \
      > "$SMUGGLER_OUT" 2>/dev/null || true
  fi

  if [[ -s "$SMUGGLER_OUT" ]]; then
    # smuggler reporta "Issue Found" si detecta algo
    if grep -qi "Issue\|vulnerable\|CLTE\|TECL\|TETE" "$SMUGGLER_OUT"; then
      local DETAIL
      DETAIL=$(grep -i "Issue\|vulnerable\|CL\|TE" "$SMUGGLER_OUT" | head -3 | tr '\n' ' ')
      log_warn "  ⚡ HTTP Smuggling detectado: $URL"

      db_add_finding "$DOMAIN_ID" "http_smuggling" "high" \
        "$URL" "smuggler" "$DETAIL"

      _telegram_send "🚨 *HTTP Request Smuggling*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📋 ${DETAIL}
⚠️ Alta severidad — revisar urgente
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

      rm -f "$SMUGGLER_OUT"
      return 0
    fi
  fi

  rm -f "$SMUGGLER_OUT"
  return 1
}

# ── Test con nuclei templates de smuggling ────────────────────
_test_nuclei_smuggling() {
  local URL="$1"
  local DOMAIN_ID="$2"
  local DOMAIN="$3"

  if ! command -v nuclei &>/dev/null; then return; fi

  local NUCLEI_OUT
  NUCLEI_OUT=$(nuclei -u "$URL" \
    -tags "smuggling,http-smuggling,request-smuggling" \
    -silent -json 2>/dev/null | head -5)

  if [[ -n "$NUCLEI_OUT" ]]; then
    echo "$NUCLEI_OUT" | while IFS= read -r LINE; do
      local TEMPLATE SEV
      TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
      SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','?'))" 2>/dev/null)
      log_warn "  ⚡ Nuclei smuggling [$SEV]: $TEMPLATE @ $URL"
      notify_nuclei_finding "$DOMAIN" "$TEMPLATE" "$SEV" "$URL" "HTTP Smuggling"
      db_add_finding "$DOMAIN_ID" "http_smuggling" "$SEV" "$URL" "$TEMPLATE" "Nuclei: $TEMPLATE"
    done
  fi
}

# ── Detección por timing ──────────────────────────────────────
_test_timing_detection() {
  local URL="$1"
  local DOMAIN_ID="$2"
  local DOMAIN="$3"
  local PROXY_FLAG="$4"

  local HOST
  HOST=$(echo "$URL" | sed 's|https\?://||;s|/.*||')

  # Test de timing: petición normal vs con Transfer-Encoding chunked malformado
  local NORMAL_TIME TE_TIME

  NORMAL_TIME=$(curl -s --max-time 10 \
    -o /dev/null -w "%{time_total}" \
    ${PROXY_FLAG} "$URL" 2>/dev/null | tr -d '.')

  TE_TIME=$(curl -s --max-time 15 \
    --http1.1 \
    -H "Transfer-Encoding: chunked" \
    -H "Content-Length: 4" \
    -d $'1\r\nZ\r\n' \
    -o /dev/null -w "%{time_total}" \
    ${PROXY_FLAG} "$URL" 2>/dev/null | tr -d '.')

  # Si el tiempo con TE es significativamente mayor, puede ser síntoma
  if [[ -n "$TE_TIME" && -n "$NORMAL_TIME" ]]; then
    local DIFF=$(( ${TE_TIME:-0} - ${NORMAL_TIME:-0} ))
    if [[ "$DIFF" -gt 5000 ]]; then  # >5 segundos de diferencia
      log_warn "  ⚡ Timing anomaly en $URL (normal:${NORMAL_TIME}ms, TE:${TE_TIME}ms)"
      db_add_finding "$DOMAIN_ID" "http_smuggling" "medium" \
        "$URL" "timing_detection" \
        "Timing anomaly: normal=${NORMAL_TIME}ms TE=${TE_TIME}ms diff=${DIFF}ms"
    fi
  fi
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 24 — $MODULE_DESC: $DOMAIN"

  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  # HTTP Smuggling solo tiene sentido contra hosts con proxy/CDN/LB delante.
  # Si no hay evidencia de proxy intermedio, saltamos.
  # Indicadores: Via header, X-Cache, CF-Cache-Status, X-Forwarded-For reflejado,
  #              tecnologías como Nginx/Apache como reverse proxy, Cloudflare, Akamai.

  local TARGETS="$OUT_DIR/.smuggling_targets.txt"
  > "$TARGETS"

  # Solo subdominios con evidencia de proxy/CDN en tech fingerprinting
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT s.subdomain FROM subdomains s
     WHERE s.domain_id=${DOMAIN_ID} AND s.status='alive'
       AND (
         EXISTS (
           SELECT 1 FROM technologies t
           WHERE t.domain_id=s.domain_id AND t.subdomain=s.subdomain
             AND (t.tech_name LIKE '%Nginx%' OR t.tech_name LIKE '%Apache%'
                  OR t.tech_name LIKE '%Cloudflare%' OR t.tech_name LIKE '%Akamai%'
                  OR t.tech_name LIKE '%Fastly%' OR t.tech_name LIKE '%Varnish%'
                  OR t.tech_name LIKE '%CDN%' OR t.tech_name LIKE '%HAProxy%'
                  OR t.tech_name LIKE '%F5%' OR t.tech_name LIKE '%AWS%')
         )
         OR s.subdomain LIKE 'api.%'
         OR s.subdomain LIKE 'gateway.%'
         OR s.subdomain LIKE 'proxy.%'
         OR s.subdomain LIKE 'lb.%'
       );" 2>/dev/null | sed 's|^|https://|' >> "$TARGETS"

  # Si no hay ninguno con tech conocida, hacer detección rápida
  # por headers en los primeros 10 subdominios — una sola petición por sub
  if [[ ! -s "$TARGETS" ]]; then
    log_info "Sin tech de proxy detectada — verificando headers en muestra..."
    local CHECKED_QUICK=0
    while IFS= read -r SUB && [[ $CHECKED_QUICK -lt 10 ]]; do
      ((CHECKED_QUICK++))
      local HEADERS
      HEADERS=$(curl -sI --max-time 6 ${CURL_PROXY} "https://${SUB}" 2>/dev/null)
      echo "$HEADERS" | grep -qiE "^Via:|^X-Cache:|^CF-Cache-Status:|^X-Served-By:|^X-Varnish:" \
        && echo "https://${SUB}" >> "$TARGETS"
    done < <(sqlite3 "$DB_PATH" \
      "SELECT subdomain FROM subdomains
       WHERE domain_id=${DOMAIN_ID} AND status='alive'
       LIMIT 10;" 2>/dev/null)
  fi

  # También endpoints con proxy/gateway en la ruta (ya crawleados)
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (url LIKE '%/api/%' OR url LIKE '%/proxy%' OR url LIKE '%/gateway%')
     LIMIT 20;" 2>/dev/null >> "$TARGETS"

  sort -u "$TARGETS" -o "$TARGETS"
  local TOTAL
  TOTAL=$(wc -l < "$TARGETS" | tr -d ' ')

  if [[ "$TOTAL" -eq 0 ]]; then
    log_info "Sin targets para smuggling detection"
    rm -f "$TARGETS"
    return
  fi

  log_info "HTTP Smuggling detection sobre $TOTAL targets..."
  local FOUND=0

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue

    # Nuclei primero (más rápido y sin efectos secundarios)
    _test_nuclei_smuggling "$URL" "$DOMAIN_ID" "$DOMAIN"

    # Smuggler si está disponible
    _run_smuggler "$URL" "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR" && ((FOUND++))

    # Timing detection como capa adicional
    _test_timing_detection "$URL" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY"

  done < "$TARGETS"

  rm -f "$TARGETS"
  log_ok "$MODULE_DESC completado: $FOUND posibles issues detectados en $TOTAL targets"
}
