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
declare -A HTTP_DEAD_URLS     # url → 1 (404 confirmado)
declare -A HTTP_ERROR_URLS    # url → código de error
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
