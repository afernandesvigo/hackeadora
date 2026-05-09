#!/usr/bin/env bash
# ============================================================
#  core/http_analyzer.sh — Análisis inteligente de respuestas HTTP
#  Se incluye con: source core/http_analyzer.sh
#
#  Lógica:
#    404 → marcar URL como muerta, no reintentar
#    429 → respetar Retry-After, pausar y continuar
#    500 → analizar body: stack trace, SQL error, paths...
#         si contiene info útil → guardar como finding
#         si es genérico → ignorar, no reintentar
# ============================================================

# ── Tabla de URLs ignoradas ───────────────────────────────────
# Se inicializa al hacer source
declare -gA HTTP_DEAD_URLS     # url → 1 (404 confirmado)
declare -gA HTTP_ERROR_URLS    # url → código de error
HTTP_RATE_LIMIT_UNTIL=0       # timestamp hasta el que hay que esperar

# ── Patrones en body de 500 que indican info útil ─────────────
# Stack traces
_HTTP_STACKTRACE_PATTERNS=(
  "at com\."
  "at org\."
  "at java\."
  "at net\."
  "Traceback (most recent"
  "File \".*\", line"
  "Stack trace:"
  "Exception in thread"
  "NullPointerException"
  "StackOverflowError"
  "in /var/www"
  "in /home/"
  "in /usr/"
  "\.php on line"
  "\.rb:\d+"
  "\.py\", line"
  "ParseError"
  "SyntaxError"
  "undefined method"
  "undefined variable"
  "Call Stack"
  "Caused by:"
)

# SQL errors → posible SQLi
_HTTP_SQL_PATTERNS=(
  "SQL syntax"
  "mysql_fetch"
  "ORA-[0-9]"
  "PostgreSQL.*ERROR"
  "sqlite3\."
  "SQLSTATE"
  "Unclosed quotation mark"
  "quoted string not properly terminated"
  "syntax error.*SQL"
  "Warning.*mysql"
  "Warning.*pg_"
  "Microsoft OLE DB"
  "ODBC.*Driver"
  "SQLServer JDBC"
  "org\.hibernate"
  "com\.mysql\.jdbc"
)

# Template errors → posible SSTI
_HTTP_TEMPLATE_PATTERNS=(
  "TemplateSyntaxError"
  "jinja2\."
  "Twig_Error"
  "smarty error"
  "Template compilation"
  "freemarker"
  "velocity"
  "Expression Language Error"
  "javax\.el\."
)

# Paths internos → info disclosure
_HTTP_PATH_PATTERNS=(
  "/var/www/"
  "/home/[a-z]"
  "/usr/local/"
  "/opt/"
  "C:\\\\Users\\\\"
  "C:\\\\inetpub\\\\"
  "C:\\\\Windows\\\\"
  "/etc/passwd"
  "/proc/"
)

# Rate limit indicators
_HTTP_RATELIMIT_PATTERNS=(
  "rate limit"
  "too many requests"
  "throttled"
  "slow down"
  "try again"
  "quota exceeded"
  "request limit"
)

# ── Analizar una respuesta HTTP ───────────────────────────────
# Uso: http_analyze_response <url> <status_code> <body_file> <domain_id> <domain>
# Devuelve: "dead" | "ratelimit" | "finding:<tipo>" | "ignore" | "ok"
http_analyze_response() {
  local URL="$1"
  local STATUS="$2"
  local BODY_FILE="$3"
  local DOMAIN_ID="${4:-0}"
  local DOMAIN="${5:-}"

  local BODY=""
  [[ -f "$BODY_FILE" ]] && BODY=$(head -c 10000 "$BODY_FILE" 2>/dev/null || true)

  # ── 404 → muerta, no reintentar ──────────────────────────
  if [[ "$STATUS" == "404" ]]; then
    HTTP_DEAD_URLS["$URL"]=1
    # Guardar en DB para no volver a intentar
    if [[ "$DOMAIN_ID" -gt 0 ]] && command -v sqlite3 &>/dev/null; then
      sqlite3 "$DB_PATH" \
        "UPDATE urls SET status_code=404
         WHERE domain_id=${DOMAIN_ID} AND url='${URL//\'/\'\'}';" \
        2>/dev/null || true
    fi
    echo "dead"
    return
  fi

  # ── 429 → rate limit, respetar ───────────────────────────
  if [[ "$STATUS" == "429" ]]; then
    local RETRY_AFTER=60  # default 60s si no hay header

    # Intentar leer el header Retry-After del body o headers
    if [[ -f "${BODY_FILE}.headers" ]]; then
      local RA
      RA=$(grep -i "Retry-After:" "${BODY_FILE}.headers" | grep -oP '\d+' | head -1)
      [[ -n "$RA" ]] && RETRY_AFTER="$RA"
    fi

    # También detectar por body
    if echo "$BODY" | grep -qiP "${_HTTP_RATELIMIT_PATTERNS[*]}"; then
      log_warn "Rate limit detectado en $URL — pausando ${RETRY_AFTER}s"
      HTTP_RATE_LIMIT_UNTIL=$(( $(date +%s) + RETRY_AFTER ))

      _telegram_send "⏸️ *Rate limit detectado*
🌐 \`${DOMAIN}\`
🔗 \`${URL:0:80}\`
⏱ Pausando \`${RETRY_AFTER}s\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

      sleep "$RETRY_AFTER"
      echo "ratelimit:${RETRY_AFTER}"
      return
    fi
  fi

  # ── 5xx → analizar body ───────────────────────────────────
  if [[ "$STATUS" =~ ^5 ]]; then

    # Comprobar si es un error genérico sin info (ignorar)
    local BODY_LEN=${#BODY}
    if [[ "$BODY_LEN" -lt 50 ]]; then
      HTTP_ERROR_URLS["$URL"]="$STATUS:generic"
      echo "ignore"
      return
    fi

    # ── SQL error ─────────────────────────────────────────
    for PAT in "${_HTTP_SQL_PATTERNS[@]}"; do
      if echo "$BODY" | grep -qiP "$PAT"; then
        local SNIPPET
        SNIPPET=$(echo "$BODY" | grep -iP "$PAT" | head -1 | cut -c1-200)
        log_warn "  ⚡ SQL error en $URL: $SNIPPET"
        if [[ "$DOMAIN_ID" -gt 0 ]]; then
          db_add_finding "$DOMAIN_ID" "http_error_analysis" "high" \
            "$URL" "sql_error_in_500" "SQL error en respuesta 500: $SNIPPET"
        fi
        echo "finding:sql_error"
        return
      fi
    done

    # ── Template/SSTI error ───────────────────────────────
    for PAT in "${_HTTP_TEMPLATE_PATTERNS[@]}"; do
      if echo "$BODY" | grep -qiP "$PAT"; then
        local SNIPPET
        SNIPPET=$(echo "$BODY" | grep -iP "$PAT" | head -1 | cut -c1-200)
        log_warn "  ⚡ Template error en $URL: $SNIPPET"
        if [[ "$DOMAIN_ID" -gt 0 ]]; then
          db_add_finding "$DOMAIN_ID" "http_error_analysis" "high" \
            "$URL" "template_error_in_500" "Template error — posible SSTI: $SNIPPET"
        fi
        echo "finding:template_error"
        return
      fi
    done

    # ── Stack trace ───────────────────────────────────────
    for PAT in "${_HTTP_STACKTRACE_PATTERNS[@]}"; do
      if echo "$BODY" | grep -qP "$PAT" 2>/dev/null; then
        local SNIPPET
        SNIPPET=$(echo "$BODY" | grep -P "$PAT" | head -2 | tr '\n' ' ' | cut -c1-300)
        log_warn "  ⚡ Stack trace en $URL"
        if [[ "$DOMAIN_ID" -gt 0 ]]; then
          db_add_finding "$DOMAIN_ID" "http_error_analysis" "medium" \
            "$URL" "stacktrace_in_500" "Stack trace en respuesta 500: $SNIPPET"
        fi
        echo "finding:stacktrace"
        return
      fi
    done

    # ── Path interno ──────────────────────────────────────
    for PAT in "${_HTTP_PATH_PATTERNS[@]}"; do
      if echo "$BODY" | grep -qP "$PAT" 2>/dev/null; then
        local SNIPPET
        SNIPPET=$(echo "$BODY" | grep -oP "$PAT[^\s\"'<>]+" | head -1 | cut -c1-200)
        log_warn "  ⚡ Path interno expuesto en $URL: $SNIPPET"
        if [[ "$DOMAIN_ID" -gt 0 ]]; then
          db_add_finding "$DOMAIN_ID" "http_error_analysis" "medium" \
            "$URL" "path_disclosure_in_500" "Path interno en 500: $SNIPPET"
        fi
        echo "finding:path_disclosure"
        return
      fi
    done

    # 500 sin info útil → ignorar
    HTTP_ERROR_URLS["$URL"]="$STATUS:no_info"
    echo "ignore"
    return
  fi

  # ── Resto de códigos → ok ─────────────────────────────────
  echo "ok"
}

# ── Wrapper para curl con análisis automático ─────────────────
# Uso: http_fetch <url> <domain_id> <domain> [curl_extra_args...]
# Devuelve el body en stdout, el status en HTTP_LAST_STATUS
HTTP_LAST_STATUS=""
HTTP_LAST_RESULT=""

http_fetch() {
  local URL="$1"
  local DOMAIN_ID="${2:-0}"
  local DOMAIN="${3:-}"
  shift 3

  # No volver a tocar URLs muertas
  if [[ -n "${HTTP_DEAD_URLS[$URL]:-}" ]]; then
    HTTP_LAST_STATUS="404"
    HTTP_LAST_RESULT="dead"
    return 1
  fi

  # Respetar rate limit global
  local NOW
  NOW=$(date +%s)
  if [[ "$NOW" -lt "$HTTP_RATE_LIMIT_UNTIL" ]]; then
    local WAIT=$(( HTTP_RATE_LIMIT_UNTIL - NOW ))
    log_info "Esperando rate limit: ${WAIT}s..."
    sleep "$WAIT"
  fi

  local BODY_FILE
  BODY_FILE=$(mktemp /tmp/hackeadora_http_XXXX)
  local HEADERS_FILE="${BODY_FILE}.headers"

  HTTP_LAST_STATUS=$(curl -sL \
    --max-time 15 \
    --max-filesize 1000000 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36" \
    -D "$HEADERS_FILE" \
    -o "$BODY_FILE" \
    -w "%{http_code}" \
    "$@" \
    "$URL" 2>/dev/null)

  HTTP_LAST_RESULT=$(http_analyze_response \
    "$URL" "$HTTP_LAST_STATUS" "$BODY_FILE" "$DOMAIN_ID" "$DOMAIN")

  local BODY_CONTENT=""
  [[ -f "$BODY_FILE" ]] && BODY_CONTENT=$(cat "$BODY_FILE")

  rm -f "$BODY_FILE" "$HEADERS_FILE"

  echo "$BODY_CONTENT"

  # Devolver código según resultado
  case "$HTTP_LAST_RESULT" in
    dead|ignore) return 1 ;;
    ratelimit:*) return 2 ;;
    finding:*)   return 0 ;;  # Encontró algo interesante
    ok)          return 0 ;;
  esac
}

# ── Verificar si una URL debe saltarse ────────────────────────
http_should_skip() {
  local URL="$1"
  [[ -n "${HTTP_DEAD_URLS[$URL]:-}" ]] && return 0
  [[ -n "${HTTP_ERROR_URLS[$URL]:-}" ]] && return 0
  return 1
}

# ── Detección de Cloudflare Access ───────────────────────────
# Devuelve 0 (true) si la respuesta HTTP viene de CF Access, no de la app.
# Uso: is_cf_access_response "$HEADERS" && return  # saltar, FP garantizado
#
# CF Access siempre añade www-authenticate: Cloudflare-Access y redirige
# a *.cloudflareaccess.com. Cualquier CORS/bypass/redirect detectado en
# estas respuestas es comportamiento del proxy, no de la aplicación.
is_cf_access_response() {
  local HEADERS="$1"
  echo "$HEADERS" | grep -qi "www-authenticate:.*Cloudflare-Access" && return 0
  echo "$HEADERS" | grep -qi "location:.*cloudflareaccess\.com" && return 0
  return 1
}

# ── Detección de SPA CSR (React/Vue/Retool) ───────────────────
# Devuelve 0 (true) si el body es un shell HTML de SPA con CSR puro.
# Un SPA CSR siempre devuelve el mismo HTML vacío para todas las rutas —
# no hay datos de usuario en la respuesta. Reportar WCD/bypass sobre
# estos hosts es siempre un falso positivo.
#
# Marcadores detectados:
#   - React: <div id="root"></div> + webpackJsonp
#   - Retool: window.RETOOL_FRONTEND_FAKE_BACKEND_MODE
#   - Vue CLI: <div id="app"></div>
#   - Vite: /__vite_hmr o /vite/
#   - Next.js SSG: __NEXT_DATA__ con props vacías (no SSR)
is_spa_csr_body() {
  local BODY="$1"
  # React (CRA, Vite, custom webpack)
  echo "$BODY" | grep -q 'id="root"' && \
    echo "$BODY" | grep -qE 'webpackJsonp|__webpack_require__|vite' && return 0
  # Retool
  echo "$BODY" | grep -q 'RETOOL_FRONTEND_FAKE_BACKEND_MODE' && return 0
  # Vue CLI
  echo "$BODY" | grep -q 'id="app"' && \
    echo "$BODY" | grep -qE 'chunk-vendors|app\.[a-f0-9]+\.js' && return 0
  # Cuerpo idéntico al shell: sin contenido después del </script> + <div id=
  local BODY_LEN=${#BODY}
  [[ "$BODY_LEN" -lt 4096 ]] && \
    echo "$BODY" | grep -q '<div id=' && \
    ! echo "$BODY" | grep -qE 'email|@[a-z]+\.[a-z]+|Bearer |"token":|"session"' && return 0
  return 1
}

# ── Comparar body con baseline de raíz ───────────────────────
# Devuelve 0 si el body es idéntico (mismo len + primeros 200 bytes)
# al contenido de la raíz del host — indica SPA catch-all.
is_same_as_root() {
  local HOST="$1"      # https://app.ejemplo.com
  local BODY="$2"
  local PROXY_FLAG="${3:-}"

  local ROOT_BODY
  ROOT_BODY=$(curl -sk -A "Mozilla/5.0" --max-time 8 ${PROXY_FLAG} \
    "${HOST}/" 2>/dev/null | head -c 4096)

  [[ -z "$ROOT_BODY" ]] && return 1

  local BODY_PREFIX ROOT_PREFIX
  BODY_PREFIX="${BODY:0:200}"
  ROOT_PREFIX="${ROOT_BODY:0:200}"

  [[ "$BODY_PREFIX" == "$ROOT_PREFIX" ]] && return 0
  return 1
}

# ============================================================
#  Helpers ergonómicos (Tier 1.1) — drop-in para módulos
#  ──────────────────────────────────────────────────────────
#  Toda llamada respeta:
#    - HTTP_DEAD_URLS  → 404 ya confirmado, skip inmediato
#    - HTTP_RATE_LIMIT_UNTIL → pausa global hasta ese timestamp
#    - SCAN_UA         → User-Agent del scan (configurable)
#    - PROXY_ACTIVE / PROXY_URL → proxy auto-inyectado si activo
#
#  Contrato: las funciones NO escriben en stdout. Tras llamarlas,
#  el caller lee:
#    - HTTP_LAST_STATUS   → código HTTP (e.g. "200", "404", "000" si error)
#    - HTTP_LAST_HEADERS  → headers raw (incluyendo CRLF)
#    - HTTP_LAST_BODY     → body completo
#  Esto evita el problema de command-substitution con globales:
#  hacer `BODY=$(_h_get URL)` ejecuta el helper en una subshell y pierde
#  HTTP_LAST_STATUS — usar globales lo evita.
#
#  Return code:
#    - 0 si la request se completó (cualquier código HTTP, incluso 4xx/5xx
#      o "dead" cacheado) — pensado para no romper `set -e` en módulos.
#      Caller debe inspeccionar HTTP_LAST_STATUS para decidir.
#    - 1 SOLO si hubo error de red completo (status="000") o curl no pudo
#      ejecutarse.
# ============================================================

HTTP_LAST_HEADERS=""
HTTP_LAST_BODY=""

# ── _h_request METHOD URL DATA [extra_curl_args...] (interno) ─
_h_request() {
  local METHOD="$1"; local URL="$2"; local DATA="$3"; shift 3

  HTTP_LAST_STATUS=""
  HTTP_LAST_HEADERS=""
  HTTP_LAST_BODY=""

  # Skip dead URLs (404 confirmado anteriormente) — devolver como resultado, no error
  if [[ -n "${HTTP_DEAD_URLS[$URL]:-}" ]]; then
    HTTP_LAST_STATUS="404"
    HTTP_LAST_RESULT="dead"
    return 0
  fi

  # Honrar rate-limit global
  local NOW
  NOW=$(date +%s)
  if [[ "$NOW" -lt "${HTTP_RATE_LIMIT_UNTIL:-0}" ]]; then
    local WAIT=$(( HTTP_RATE_LIMIT_UNTIL - NOW ))
    type log_info &>/dev/null && log_info "Esperando rate-limit global: ${WAIT}s..."
    sleep "$WAIT"
  fi

  local UA="${SCAN_UA:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36}"
  local TIMEOUT="${HTTP_TIMEOUT:-12}"

  # Proxy automático desde globales (proxy_check los setea)
  local PROXY_ARGS=()
  if [[ "${PROXY_ACTIVE:-false}" == "true" ]] && [[ -n "${PROXY_URL:-}" ]]; then
    PROXY_ARGS=(--proxy "$PROXY_URL")
  fi

  local BODY_FILE HDR_FILE
  BODY_FILE=$(mktemp /tmp/h_body_XXXXXX)
  HDR_FILE=$(mktemp /tmp/h_hdr_XXXXXX)

  # Curl args base
  # HTTP_NO_REDIRECT=1 deshabilita -L (módulos que sondean exposiciones
  # explícitas como AEM JCR write, actuator, hippo login deben usarlo
  # para no falsificar 200 cuando el host responde 30x).
  local CURL_ARGS=(-sk
                   --max-time "$TIMEOUT"
                   --max-filesize 2000000
                   -A "$UA"
                   -D "$HDR_FILE"
                   -o "$BODY_FILE"
                   -w "%{http_code}")
  if [[ "${HTTP_NO_REDIRECT:-0}" != "1" ]]; then
    CURL_ARGS+=(-L)
  fi

  case "$METHOD" in
    HEAD) CURL_ARGS+=(-I) ;;
    GET)  ;;  # default
    *)    CURL_ARGS+=(-X "$METHOD") ;;
  esac

  if [[ -n "$DATA" ]]; then
    CURL_ARGS+=(--data "$DATA")
  fi

  HTTP_LAST_STATUS=$(curl "${CURL_ARGS[@]}" "${PROXY_ARGS[@]}" "$@" "$URL" 2>/dev/null)
  [[ -z "$HTTP_LAST_STATUS" ]] && HTTP_LAST_STATUS="000"

  HTTP_LAST_HEADERS=""
  [[ -f "$HDR_FILE" ]] && HTTP_LAST_HEADERS=$(<"$HDR_FILE")

  HTTP_LAST_BODY=""
  if [[ -f "$BODY_FILE" ]] && [[ "$METHOD" != "HEAD" ]]; then
    HTTP_LAST_BODY=$(<"$BODY_FILE")
  fi

  # 429 → respetar Retry-After y actualizar rate-limit global
  if [[ "$HTTP_LAST_STATUS" == "429" ]]; then
    local RA
    RA=$(echo "$HTTP_LAST_HEADERS" | grep -i '^Retry-After:' | grep -oP '\d+' | head -1)
    [[ -z "$RA" ]] && RA=60
    type log_warn &>/dev/null && log_warn "  ⏸ 429 en $URL — pausando global ${RA}s"
    HTTP_RATE_LIMIT_UNTIL=$(( $(date +%s) + RA ))
  fi

  # 404 → marcar como muerta
  if [[ "$HTTP_LAST_STATUS" == "404" ]]; then
    HTTP_DEAD_URLS["$URL"]=1
  fi

  rm -f "$BODY_FILE" "$HDR_FILE"

  # rc=0 si tenemos cualquier código HTTP válido. rc=1 solo en error de red.
  [[ "$HTTP_LAST_STATUS" == "000" ]] && return 1
  return 0
}

# ── _h_get URL [extra_curl_args...] ──────────────────────────
# Tras la llamada: HTTP_LAST_STATUS, HTTP_LAST_HEADERS, HTTP_LAST_BODY.
# NO usar como `$(_h_get URL)` — los globales se perderían.
_h_get() {
  local URL="$1"; shift
  _h_request "GET" "$URL" "" "$@"
}

# ── _h_post URL DATA [extra_curl_args...] ────────────────────
_h_post() {
  local URL="$1"; local DATA="$2"; shift 2
  _h_request "POST" "$URL" "$DATA" "$@"
}

# ── _h_head URL [extra_curl_args...] — HEAD-only ─────────────
_h_head() {
  local URL="$1"; shift
  _h_request "HEAD" "$URL" "" "$@"
}

# ── _h_status URL [extra_curl_args...] — solo el código ──────
# Echo del status (e.g. "200", "403"). HTTP_LAST_STATUS también seteada.
# Es el ÚNICO helper que escribe a stdout — diseñado para
# `S=$(_h_status URL)`. NO setea HTTP_LAST_STATUS en el caller (subshell).
_h_status() {
  local URL="$1"; shift
  _h_request "GET" "$URL" "" "$@"
  echo "$HTTP_LAST_STATUS"
}

# ── _h_method METHOD URL [extra_curl_args...] — método custom ─
# Para PUT/PATCH/DELETE/OPTIONS/etc.
_h_method() {
  local METHOD="$1" URL="$2"; shift 2
  _h_request "$METHOD" "$URL" "" "$@"
}

# ── Variantes _noredirect — sin -L ──────────────────────────────
# Para módulos que sondean exposiciones explícitas (AEM JCR write,
# actuator, hippo/drupal login). Sin -L, un 30x se queda como 30x.
# Ver Bug #9 en project_module_fp_catalog.md.
_h_get_noredirect() {
  local URL="$1"; shift
  local HTTP_NO_REDIRECT=1
  _h_request "GET" "$URL" "" "$@"
}
_h_head_noredirect() {
  local URL="$1"; shift
  local HTTP_NO_REDIRECT=1
  _h_request "HEAD" "$URL" "" "$@"
}
_h_post_noredirect() {
  local URL="$1"; local DATA="$2"; shift 2
  local HTTP_NO_REDIRECT=1
  _h_request "POST" "$URL" "$DATA" "$@"
}
_h_method_noredirect() {
  local METHOD="$1" URL="$2"; shift 2
  local HTTP_NO_REDIRECT=1
  _h_request "$METHOD" "$URL" "" "$@"
}
_h_status_noredirect() {
  local URL="$1"; shift
  local HTTP_NO_REDIRECT=1
  _h_request "GET" "$URL" "" "$@"
  echo "$HTTP_LAST_STATUS"
}

# ── is_likely_fp_response [ROOT_HOST] [BODY] [HEADERS] ───────
# Combina los 3 detectores existentes:
#   - is_cf_access_response (via headers)
#   - is_spa_csr_body       (via body)
#   - is_same_as_root       (via root host comparison)
# Si BODY/HEADERS no se pasan, usa HTTP_LAST_BODY/HTTP_LAST_HEADERS del
# último _h_* — es el caso típico tras llamar a _h_get.
# Devuelve 0 (true) si parece un FP — el caller debe descartar/bajar severity.
is_likely_fp_response() {
  local ROOT="${1:-}"
  local BODY="${2:-$HTTP_LAST_BODY}"
  local HEADERS="${3:-$HTTP_LAST_HEADERS}"

  if [[ -n "$HEADERS" ]]; then
    is_cf_access_response "$HEADERS" && return 0
  fi
  if [[ -n "$BODY" ]]; then
    is_spa_csr_body "$BODY" && return 0
    [[ -n "$ROOT" ]] && is_same_as_root "$ROOT" "$BODY" && return 0
  fi
  return 1
}

# ── Stats del analizador ──────────────────────────────────────
http_analyzer_stats() {
  echo "HTTP Analyzer:"
  echo "  URLs muertas (404): ${#HTTP_DEAD_URLS[@]}"
  echo "  URLs con error:     ${#HTTP_ERROR_URLS[@]}"
  local NOW; NOW=$(date +%s)
  if [[ "$HTTP_RATE_LIMIT_UNTIL" -gt "$NOW" ]]; then
    echo "  Rate limit activo: $(( HTTP_RATE_LIMIT_UNTIL - NOW ))s restantes"
  fi
}
