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
# Aplica payloads universales a cada param encontrado — agnóstico de stack.
# Detecta: SQLi error-based, LFI, SSTI, XSS reflection, open redirect.
_param_fuzz() {
  local PARAMS_FILE="$1"   # archivo con URLs?param=FUZZ
  local DOMAIN_ID="$2"
  local DOMAIN="$3"

  [[ ! -s "$PARAMS_FILE" ]] && return

  local MAX_URLS=60
  local FINDINGS=0

  # Payloads por categoría de parámetro
  # Cada entrada: "CATEGORY:PAYLOAD" — CATEGORY determina qué parámetros la reciben
  declare -A CAT_PAYLOADS
  CAT_PAYLOADS[sqli]="'"
  CAT_PAYLOADS[ssti]='{{7*7}}'
  CAT_PAYLOADS[xss]='<hackeadora>'
  CAT_PAYLOADS[lfi]='../../../etc/passwd'
  CAT_PAYLOADS[redirect]='//oastify.com'

  local URL_COUNT=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    [[ "$URL" =~ \.(js|css|png|jpg|gif|svg|woff|ico|map)(\?|$) ]] && continue
    (( URL_COUNT++ > MAX_URLS )) && break

    local BASE="${URL%%\?*}"
    local QUERY="${URL#*\?}"

    # Detectar si el endpoint requiere POST: probar GET primero, si da 4xx reintentar POST
    local BASELINE_STATUS METHOD="GET"
    BASELINE_STATUS=$(curl -s --max-time 8 -A "${SCAN_UA:-Mozilla/5.0}" \
      -o /dev/null -w "%{http_code}" "$BASE" 2>/dev/null)
    if [[ "$BASELINE_STATUS" =~ ^(000|4[0-9][0-9])$ ]]; then
      # Intentar POST con los params como form body
      BASELINE_STATUS=$(curl -s --max-time 8 -A "${SCAN_UA:-Mozilla/5.0}" -X POST \
        --data-urlencode "" -o /dev/null -w "%{http_code}" "$BASE" 2>/dev/null)
      [[ "$BASELINE_STATUS" =~ ^(000|4[0-9][0-9])$ ]] && continue
      METHOD="POST"
    fi

    # Para cada parámetro en la URL
    while IFS='=' read -r PNAME _PVAL; do
      [[ -z "$PNAME" || "$PNAME" == "FUZZ" ]] && continue
      local PNAME_CLEAN="${PNAME// /}"

      # Determinar qué categorías aplican a este param
      local CATS=("sqli" "ssti" "xss")
      if echo "$PNAME_CLEAN" | grep -qiE "^(file|path|include|page|load|template|src|dest|url|redirect|next|return|href|link|uri|location)$"; then
        CATS+=("lfi" "redirect")
      fi

      for CAT in "${CATS[@]}"; do
        local PAYLOAD="${CAT_PAYLOADS[$CAT]}"
        local ENC_PAYLOAD
        ENC_PAYLOAD=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" \
          "$PAYLOAD" 2>/dev/null || printf '%s' "$PAYLOAD")

        # Construir request: GET con querystring o POST con form body
        local RESP_BODY RESP_STATUS
        if [[ "$METHOD" == "POST" ]]; then
          # Reconstruir todos los params como POST body, sustituir el param objetivo
          local POST_BODY
          POST_BODY=$(echo "$QUERY" | tr '&' '\n' | sed -E \
            "s|^(${PNAME_CLEAN}=).*|\1${ENC_PAYLOAD}|" | tr '\n' '&' | sed 's/&$//')
          RESP_BODY=$(curl -s --max-time 10 -A "${SCAN_UA:-Mozilla/5.0}" -X POST \
            -d "$POST_BODY" -w "\n###STATUS###%{http_code}" "$BASE" 2>/dev/null)
        else
          local TEST_URL
          TEST_URL=$(echo "$URL" | sed -E "s|([?&]${PNAME_CLEAN}=)[^&]*|\1${ENC_PAYLOAD}|")
          RESP_BODY=$(curl -s --max-time 10 -A "${SCAN_UA:-Mozilla/5.0}" \
            -w "\n###STATUS###%{http_code}" "$TEST_URL" 2>/dev/null)
        fi
        RESP_STATUS=$(echo "$RESP_BODY" | grep -oP '(?<=###STATUS###)\d+' | tail -1)
        RESP_BODY=$(echo "$RESP_BODY" | grep -v "###STATUS###")

        case "$CAT" in
          sqli)
            if echo "$RESP_BODY" | grep -qiE \
              "sql syntax|mysql_fetch|ora-[0-9]{4,}|postgresql.*error|sqlite.*error|\
odbc.*driver|unclosed quotation|syntax error.*near|you have an error in your sql|\
warning.*mysql|division by zero|supplied argument is not a valid"; then
              log_warn "  ⚡ SQLi error-based: $TEST_URL (param: $PNAME_CLEAN)"
              db_add_finding "$DOMAIN_ID" "sqli_error" "high" "$TEST_URL" \
                "param_sqli" "SQLi error en param '$PNAME_CLEAN'"
              notify_nuclei_finding "$DOMAIN" "sqli-error" "high" "$TEST_URL" \
                "param='$PNAME_CLEAN' payload=quote"
              ((FINDINGS++))
            fi
            ;;
          ssti)
            if echo "$RESP_BODY" | grep -qE '\b49\b'; then
              log_warn "  ⚡ SSTI ({{7*7}}=49): $TEST_URL (param: $PNAME_CLEAN)"
              db_add_finding "$DOMAIN_ID" "ssti" "critical" "$TEST_URL" \
                "param_ssti" "SSTI confirmado: {{7*7}}=49 en param '$PNAME_CLEAN'"
              notify_nuclei_finding "$DOMAIN" "ssti" "critical" "$TEST_URL" \
                "param='$PNAME_CLEAN'"
              ((FINDINGS++))
            fi
            ;;
          xss)
            if echo "$RESP_BODY" | grep -qF '<hackeadora>'; then
              log_warn "  ⚡ XSS reflection: $TEST_URL (param: $PNAME_CLEAN)"
              # dalfox para confirmar y encontrar payload completo explotable
              if command -v dalfox &>/dev/null; then
                local DALFOX_OUT
                DALFOX_OUT=$(dalfox url "$TEST_URL" \
                  --silence --no-spinner --timeout 15 \
                  --user-agent "${SCAN_UA:-Mozilla/5.0}" \
                  2>/dev/null | grep -i "POC\|XSS" | head -3)
                [[ -n "$DALFOX_OUT" ]] && \
                  log_warn "  dalfox: $DALFOX_OUT"
              fi
              db_add_finding "$DOMAIN_ID" "xss_reflect" "medium" "$TEST_URL" \
                "param_xss" "XSS reflection en param '$PNAME_CLEAN'"
              notify_nuclei_finding "$DOMAIN" "xss-reflect" "medium" "$TEST_URL" \
                "param='$PNAME_CLEAN'"
              ((FINDINGS++))
            fi
            ;;
          lfi)
            if echo "$RESP_BODY" | grep -qE 'root:.*:0:0:|/bin/(bash|sh)|www-data:'; then
              log_warn "  ⚡ LFI confirmado: $TEST_URL (param: $PNAME_CLEAN)"
              db_add_finding "$DOMAIN_ID" "lfi" "critical" "$TEST_URL" \
                "param_lfi" "LFI en param '$PNAME_CLEAN'"
              notify_nuclei_finding "$DOMAIN" "lfi" "critical" "$TEST_URL" \
                "param='$PNAME_CLEAN'"
              ((FINDINGS++))
            fi
            ;;
          redirect)
            if [[ "$RESP_STATUS" =~ ^3 ]]; then
              local LOC
              LOC=$(curl -sI --max-time 8 -A "${SCAN_UA:-Mozilla/5.0}" \
                "$TEST_URL" 2>/dev/null | grep -i '^location:' | head -1)
              if echo "$LOC" | grep -qi "oastify\.com\|evil\.com"; then
                log_warn "  ⚡ Open redirect: $TEST_URL (param: $PNAME_CLEAN)"
                db_add_finding "$DOMAIN_ID" "open_redirect" "medium" "$TEST_URL" \
                  "param_redirect" "Open redirect en param '$PNAME_CLEAN' → $LOC"
                notify_nuclei_finding "$DOMAIN" "open-redirect" "medium" "$TEST_URL" \
                  "param='$PNAME_CLEAN'"
                ((FINDINGS++))
              fi
            fi
            ;;
        esac
      done
    done < <(echo "$QUERY" | tr '&' '\n')
  done < "$PARAMS_FILE"

  [[ "$FINDINGS" -gt 0 ]] && \
    log_ok "  param_fuzz: $FINDINGS findings en $URL_COUNT URLs"
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
