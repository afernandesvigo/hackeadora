#!/usr/bin/env bash
# ============================================================
#  modules/12_login_finder.sh
#  Fase 12: Detección de formularios de login
#
#  Estrategia en dos fuentes:
#   1. URLs ya descubiertas por el crawler que parecen login
#      (sin re-crawlear nada — alta precisión, coste cero)
#   2. Probing guiado por tech fingerprint: solo paths relevantes
#      para la tecnología detectada en cada subdominio.
#      Los hosts API se saltan completamente.
#
#  Ambas fuentes se verifican en paralelo (20 workers).
# ============================================================

MODULE_NAME="login_finder"
MODULE_DESC="Detección de formularios de login"

_init_login_table() {
  sqlite3 "$DB_PATH" <<'SQL'
CREATE TABLE IF NOT EXISTS login_forms (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id    INTEGER NOT NULL REFERENCES domains(id),
  url          TEXT NOT NULL,
  subdomain    TEXT NOT NULL,
  form_action  TEXT,
  form_method  TEXT DEFAULT 'POST',
  input_fields TEXT,
  login_type   TEXT,
  http_status  INTEGER,
  page_title   TEXT,
  tech_hints   TEXT,
  found_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(domain_id, url)
);
CREATE INDEX IF NOT EXISTS idx_login_domain ON login_forms(domain_id);
SQL
}

# ── ¿Es un host de API? (no tiene login forms HTML) ──────────
_is_api_host() {
  local SUB="$1"
  echo "$SUB" | grep -qiP '(^|[-.])(api|apis|service|services|backend|gateway|gw|rpc|graphql)([-.:]|$)'
}

# ── Paths a probar según tech detectada ───────────────────────
# Solo HTTPS — curl -L sigue redirects de http a https automáticamente.
_paths_for_subdomain() {
  local SUB="$1"
  local DOMAIN_ID="$2"

  # Paths universales (pocos, alta tasa de acierto)
  local -a PATHS=(
    "/login" "/signin" "/admin"
    "/auth/login" "/user/login"
    "/.well-known/openid-configuration"
    "/oauth/authorize" "/sso"
  )

  # Tech desde la tabla technologies (módulo 10)
  local TECHS
  TECHS=$(_db_query \
    "SELECT GROUP_CONCAT(tech_stack,' ') FROM technologies
     WHERE domain_id=${DOMAIN_ID} AND subdomain='${SUB//\'/\'\'}';" 2>/dev/null)

  # WordPress: detectado por tech O por wp-login en urls ya crawleadas
  local WP_URLS
  WP_URLS=$(_db_query \
    "SELECT COUNT(*) FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND url LIKE '%${SUB//\'/\'\'}%'
       AND url LIKE '%wp-login%';" 2>/dev/null || echo 0)

  if echo "$TECHS" | grep -qi "wordpress" || [[ "${WP_URLS:-0}" -gt 0 ]]; then
    PATHS+=("/wp-login.php" "/wp-admin/")
  fi

  echo "$TECHS" | grep -qi "drupal"           && PATHS+=("/user/login")
  echo "$TECHS" | grep -qi "joomla"           && PATHS+=("/administrator/")
  echo "$TECHS" | grep -qi "django"           && PATHS+=("/accounts/login/" "/admin/login/")
  echo "$TECHS" | grep -qi "rails\|ruby"      && PATHS+=("/users/sign_in")
  echo "$TECHS" | grep -qi "asp\|\.net"       && PATHS+=("/Account/Login" "/login.aspx")
  echo "$TECHS" | grep -qi "zendesk"          && PATHS+=("/access/login" "/hc/signin")
  echo "$TECHS" | grep -qi "shopify"          && PATHS+=("/account/login" "/admin/auth/login")
  echo "$TECHS" | grep -qi "confluence\|jira" && PATHS+=("/login.action" "/secure/Dashboard.jspa")
  echo "$TECHS" | grep -qi "jenkins"          && PATHS+=("/j_spring_security_check" "/login")
  echo "$TECHS" | grep -qi "gitlab"           && PATHS+=("/users/sign_in")

  printf '%s\n' "${PATHS[@]}" | sort -u
}

# ── Parsear HTML buscando formularios de login ────────────────
_parse_login_form() {
  local HTML="$1"

  echo "$HTML" | grep -qi "type=[\"']password[\"']" || return 1

  local FIELDS ACTION METHOD TITLE TECH

  FIELDS=$(echo "$HTML" \
    | grep -oiP '<input[^>]+>' \
    | grep -iv 'hidden\|submit\|button\|csrf\|token' \
    | grep -oiP "name=[\"'][^\"']+[\"']" \
    | sed "s/name=[\"']//;s/[\"']//" \
    | tr '\n' ',' | sed 's/,$//')

  ACTION=$(echo "$HTML" \
    | grep -oiP '<form[^>]+>' \
    | grep -oi "action=[\"'][^\"']*[\"']" \
    | head -1 \
    | sed "s/action=[\"']//;s/[\"']//" || echo "")

  METHOD=$(echo "$HTML" \
    | grep -oiP '<form[^>]+>' \
    | grep -oi "method=[\"'][^\"']*[\"']" \
    | head -1 \
    | sed "s/method=[\"']//;s/[\"']//" \
    | tr '[:lower:]' '[:upper:]' || echo "POST")

  TITLE=$(echo "$HTML" \
    | grep -oiP '(?<=<title>)[^<]+' \
    | head -1 | tr -d '\n\r' | cut -c1-100)

  TECH=""
  echo "$HTML" | grep -qi 'wp-content\|wordpress\|wp-login' && TECH="WordPress"
  echo "$HTML" | grep -qi 'django\|csrfmiddlewaretoken'     && TECH="Django"
  echo "$HTML" | grep -qi 'laravel\|_token.*csrf'           && TECH="Laravel"
  echo "$HTML" | grep -qi 'rails\|authenticity_token'       && TECH="Rails"
  echo "$HTML" | grep -qi 'joomla'                          && TECH="Joomla"
  echo "$HTML" | grep -qi 'drupal'                          && TECH="Drupal"

  echo "${ACTION}|${METHOD:-POST}|${FIELDS}|${TITLE}|${TECH}"
}

# ── Verificar una URL ─────────────────────────────────────────
_check_url() {
  local URL="$1"
  local DOMAIN_ID="$2"
  local PROXY_FLAG="$3"

  local SUBDOMAIN
  SUBDOMAIN=$(echo "$URL" | sed 's|https\?://||;s|[:/].*||')

  local RESPONSE
  RESPONSE=$(curl -sL \
    --max-time 10 \
    --max-filesize 2000000 \
    -A "${SCAN_UA:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36}" \
    -w "\n###STATUS###%{http_code}" \
    ${PROXY_FLAG} \
    "$URL" 2>/dev/null)

  local HTTP_STATUS
  HTTP_STATUS=$(echo "$RESPONSE" | grep -oP '(?<=###STATUS###)\d+' | tail -1)
  local HTML
  HTML=$(echo "$RESPONSE" | sed '/###STATUS###/d')

  [[ -z "$HTML" || "$HTTP_STATUS" == "000" || "$HTTP_STATUS" == "404" ]] && return

  # Descartar URLs con template literals de JS (${var}) — no son URLs reales
  echo "$URL" | grep -qP '\$\{' && return

  local LOGIN_TYPE=""

  # OAuth: solo flujos de autorización reales, no rutas de API que contengan "oauth"
  if echo "$URL" | grep -qiP '/(oauth2?/authorize|connect/authorize|openid-connect/auth|\.well-known/openid)'; then
    LOGIN_TYPE="oauth"
  elif echo "$URL" | grep -qiP '/saml/(sso|login|auth|consume|acs)'; then
    LOGIN_TYPE="saml"
  elif echo "$URL" | grep -qiP '/(sso$|sso/login|sso/auth)'; then
    LOGIN_TYPE="sso"
  elif echo "$HTML" | grep -qi '"token"\|"access_token"\|"jwt"' && \
       echo "$URL" | grep -qiP '/api/'; then
    LOGIN_TYPE="api_auth"
  elif echo "$HTML" | grep -qi "type=[\"']password[\"']"; then
    LOGIN_TYPE="password_form"
  else
    return
  fi

  local ACTION METHOD FIELDS TITLE TECH
  if [[ "$LOGIN_TYPE" == "password_form" ]]; then
    local PARSED
    PARSED=$(_parse_login_form "$HTML") || return
    IFS='|' read -r ACTION METHOD FIELDS TITLE TECH <<< "$PARSED"
  else
    TITLE=$(echo "$HTML" | grep -oiP '(?<=<title>)[^<]+' | head -1 | tr -d '\n\r' | cut -c1-100)
    FIELDS=""; ACTION=""; METHOD="GET"; TECH=""
  fi

  local URL_ESC="${URL//\'/\'\'}"
  local SUB_ESC="${SUBDOMAIN//\'/\'\'}"

  local IS_NEW
  IS_NEW=$(_db_query \
    "SELECT COUNT(*) FROM login_forms
     WHERE domain_id=${DOMAIN_ID} AND url='${URL_ESC}';" 2>/dev/null)

  _db "INSERT OR IGNORE INTO login_forms
    (domain_id,url,subdomain,form_action,form_method,input_fields,login_type,http_status,page_title,tech_hints)
    VALUES(${DOMAIN_ID},'${URL_ESC}','${SUB_ESC}','${ACTION//\'/\'\'}','${METHOD}',
           '${FIELDS//\'/\'\'}','${LOGIN_TYPE}',${HTTP_STATUS:-0},
           '${TITLE//\'/\'\'}','${TECH//\'/\'\'}');" 2>/dev/null || true

  if [[ "${IS_NEW:-0}" == "0" ]]; then
    local EMOJI="🔐"
    [[ "$LOGIN_TYPE" == "oauth"    ]] && EMOJI="🔑"
    [[ "$LOGIN_TYPE" == "saml"     ]] && EMOJI="🏢"
    [[ "$LOGIN_TYPE" == "api_auth" ]] && EMOJI="🔌"

    log_warn "$EMOJI Login form [$LOGIN_TYPE]: $URL"

    _telegram_send "${EMOJI} *Login Form detectado*
🌐 \`${SUBDOMAIN}\`
🔗 \`${URL}\`
📋 Tipo: \`${LOGIN_TYPE}\`
${TECH:+🛠️ Tech: \`${TECH}\`}
${FIELDS:+📝 Campos: \`${FIELDS}\`}
${TITLE:+📄 Título: ${TITLE}}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

    db_add_finding "$DOMAIN_ID" "login_form" "info" \
      "$URL" "$LOGIN_TYPE" "${TECH:+$TECH — }${TITLE}"
  fi
}

# ── Función principal ─────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 12 — $MODULE_DESC: $DOMAIN"

  _init_login_table

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  local ALIVE="$OUT_DIR/subs_alive.txt"
  local URLS_RAW="$OUT_DIR/urls_raw.txt"

  if [[ ! -s "$ALIVE" ]]; then
    log_warn "Sin subdominios alive, saltando"
    return
  fi

  local CHECK_LIST="$OUT_DIR/.login_check.txt"
  > "$CHECK_LIST"

  # ── Fuente 1: URLs ya descubiertas por el crawler ─────────
  # El crawler ya visitó estas páginas — alta precisión, sin trabajo extra.
  local LOGIN_PATTERN='/(login|signin|sign-in|log-in|auth|admin|portal|dashboard|sso|oauth|saml|wp-login|user.login|account.login|access.login|j_spring|users.sign)'

  _db_query \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (url LIKE '%/login%' OR url LIKE '%/signin%'
            OR url LIKE '%/auth%'  OR url LIKE '%/admin%'
            OR url LIKE '%/sso%'   OR url LIKE '%/oauth%'
            OR url LIKE '%/saml%'  OR url LIKE '%/wp-login%'
            OR url LIKE '%/user/login%' OR url LIKE '%/access/login%'
            OR url LIKE '%/users/sign%' OR url LIKE '%/account/login%')
       AND url NOT LIKE '%.js' AND url NOT LIKE '%.css'
       AND url NOT LIKE '%.png' AND url NOT LIKE '%author%'
       AND url NOT LIKE '%\${%'
     ORDER BY first_seen DESC LIMIT 500;" \
    2>/dev/null >> "$CHECK_LIST" || true

  if [[ -s "$URLS_RAW" ]]; then
    grep -iP "$LOGIN_PATTERN" "$URLS_RAW" \
      | grep -ivP '\.(js|css|png|jpg|gif|svg|ico)(\?|$)' \
      | grep -ivP '/author/' \
      | grep -vP '\$\{' \
      >> "$CHECK_LIST" 2>/dev/null || true
  fi

  local FROM_CRAWLER
  FROM_CRAWLER=$(wc -l < "$CHECK_LIST" | tr -d ' ')

  # ── Fuente 2: Probing guiado por tech (solo HTTPS, sin hosts API) ─
  local PROBED_SUBS=0
  local SKIPPED_API=0

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue

    if _is_api_host "$SUB"; then
      ((SKIPPED_API++))
      continue
    fi

    ((PROBED_SUBS++))
    while IFS= read -r LPATH; do
      echo "https://${SUB}${LPATH}" >> "$CHECK_LIST"
    done < <(_paths_for_subdomain "$SUB" "$DOMAIN_ID")

  done < "$ALIVE"

  sort -u "$CHECK_LIST" -o "$CHECK_LIST"
  local TOTAL
  TOTAL=$(wc -l < "$CHECK_LIST" | tr -d ' ')

  log_info "Targets: $FROM_CRAWLER del crawler + probing tech-guided ($PROBED_SUBS hosts web, $SKIPPED_API API saltados) = $TOTAL únicos"
  log_info "Verificando $TOTAL URLs (20 workers paralelos)..."

  # ── Verificación paralela ────────────────────────────────
  local MAX_WORKERS="${LOGIN_PARALLEL:-20}"
  local PIDS=()

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    (
      _check_url "$URL" "$DOMAIN_ID" "$CURL_PROXY" > /dev/null
    ) &
    PIDS+=($!)
    if [[ ${#PIDS[@]} -ge $MAX_WORKERS ]]; then
      wait "${PIDS[0]}" 2>/dev/null || true
      PIDS=("${PIDS[@]:1}")
    fi
  done < "$CHECK_LIST"
  wait "${PIDS[@]}" 2>/dev/null || true

  rm -f "$CHECK_LIST"

  local FOUND
  FOUND=$(_db_query \
    "SELECT COUNT(*) FROM login_forms WHERE domain_id=${DOMAIN_ID};" 2>/dev/null || echo 0)

  if [[ "${FOUND:-0}" -gt 0 ]]; then
    _telegram_send "🔐 *Login Finder — Resumen*
🌐 \`${DOMAIN}\`
🔎 URLs verificadas: ${TOTAL}
🔐 Login forms encontrados: ${FOUND}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi

  log_ok "$MODULE_DESC completado: $FOUND login forms en $TOTAL URLs analizadas"
}
