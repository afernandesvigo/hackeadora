#!/usr/bin/env bash
# ============================================================
#  modules/12_login_finder.sh
#  Fase 12: Detección de formularios de login
#
#  Para cada URL descubierta, hace GET y parsea el DOM:
#    - <input type="password"> → formulario de login
#    - Rutas conocidas: /admin, /login, /signin, /wp-login...
#    - SSO / OAuth: /oauth, /saml, /.well-known/openid-configuration
#    - Campos de formulario (action, method, inputs)
#
#  Guarda en tabla login_forms y notifica por Telegram
# ============================================================

MODULE_NAME="login_finder"
MODULE_DESC="Detección de formularios de login"

# ── Rutas conocidas de login a probar siempre ─────────────────
LOGIN_PATHS=(
  "/login" "/signin" "/sign-in" "/log-in"
  "/admin" "/admin/login" "/administrator"
  "/wp-login.php" "/wp-admin"
  "/user/login" "/users/login" "/user/sign_in"
  "/auth" "/auth/login" "/auth/signin"
  "/account/login" "/accounts/login"
  "/portal" "/portal/login"
  "/dashboard" "/dashboard/login"
  "/panel" "/cpanel" "/control"
  "/login.php" "/login.asp" "/login.aspx" "/login.jsp"
  "/api/login" "/api/auth" "/api/v1/auth" "/api/v2/auth"
  "/.well-known/openid-configuration"
  "/oauth/authorize" "/oauth2/authorize"
  "/saml/login" "/saml2/login"
  "/sso" "/sso/login"
)

# ── Inicializar tabla en SQLite ───────────────────────────────
_init_login_table() {
  sqlite3 "$DB_PATH" <<'SQL'
CREATE TABLE IF NOT EXISTS login_forms (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id    INTEGER NOT NULL REFERENCES domains(id),
  url          TEXT NOT NULL,
  subdomain    TEXT NOT NULL,
  form_action  TEXT,
  form_method  TEXT DEFAULT 'POST',
  input_fields TEXT,    -- JSON: [{name, type, id}...]
  login_type   TEXT,    -- password_form | oauth | saml | sso | api_auth
  http_status  INTEGER,
  page_title   TEXT,
  tech_hints   TEXT,    -- indicios de tecnología (WordPress, Django...)
  found_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(domain_id, url)
);
CREATE INDEX IF NOT EXISTS idx_login_domain ON login_forms(domain_id);
SQL
}

# ── Parsear HTML buscando formularios de login ────────────────
_parse_login_form() {
  local HTML="$1"
  local BASE_URL="$2"

  # ¿Tiene input type=password?
  echo "$HTML" | grep -qi 'type=["\']password["\']' || return 1

  # Extraer campos del formulario
  local FIELDS
  FIELDS=$(echo "$HTML" | grep -oiP '<input[^>]+>' | grep -iv 'hidden\|submit\|button\|csrf\|token' | head -10)

  local NAMES
  NAMES=$(echo "$FIELDS" | grep -oiP 'name=["\'][^"\']+["\']' | sed "s/name=[\"']//;s/[\"']//" | tr '\n' ',' | sed 's/,$//')

  local ACTION
  ACTION=$(echo "$HTML" | grep -oiP '<form[^>]+>' | grep -oi 'action=["\'][^"\']*["\']' | head -1 | sed "s/action=[\"']//;s/[\"']//" || echo "")

  local METHOD
  METHOD=$(echo "$HTML" | grep -oiP '<form[^>]+>' | grep -oi 'method=["\'][^"\']*["\']' | head -1 | sed "s/method=[\"']//;s/[\"']//" | tr '[:lower:]' '[:upper:]' || echo "POST")

  # Título de la página
  local TITLE
  TITLE=$(echo "$HTML" | grep -oiP '(?<=<title>)[^<]+' | head -1 | tr -d '\n\r' | cut -c1-100)

  # Detectar tecnología por indicios
  local TECH=""
  echo "$HTML" | grep -qi 'wp-content\|wordpress\|wp-login' && TECH="WordPress"
  echo "$HTML" | grep -qi 'django\|csrfmiddlewaretoken' && TECH="Django"
  echo "$HTML" | grep -qi 'laravel\|_token.*csrf' && TECH="Laravel"
  echo "$HTML" | grep -qi 'rails\|authenticity_token' && TECH="Rails"
  echo "$HTML" | grep -qi 'joomla' && TECH="Joomla"
  echo "$HTML" | grep -qi 'drupal' && TECH="Drupal"

  echo "${ACTION}|${METHOD}|${NAMES}|${TITLE}|${TECH}"
}

# ── Analizar una URL ──────────────────────────────────────────
_check_url() {
  local URL="$1"
  local DOMAIN_ID="$2"
  local PROXY_FLAG="$3"

  local SUBDOMAIN
  SUBDOMAIN=$(echo "$URL" | sed 's|https\?://||;s|/.*||')

  # GET con curl, siguiendo redirecciones
  local RESPONSE
  RESPONSE=$(curl -sL \
    --max-time 10 \
    --max-filesize 2000000 \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36" \
    -w "\n###STATUS###%{http_code}" \
    ${PROXY_FLAG} \
    "$URL" 2>/dev/null)

  local HTTP_STATUS
  HTTP_STATUS=$(echo "$RESPONSE" | grep -oP '(?<=###STATUS###)\d+' | tail -1)
  local HTML
  HTML=$(echo "$RESPONSE" | sed '/###STATUS###/d')

  [[ -z "$HTML" || "$HTTP_STATUS" == "000" ]] && return

  # ── Detectar tipo de endpoint ─────────────────────────────
  local LOGIN_TYPE=""

  # OAuth / OpenID
  if echo "$URL" | grep -qiP '/oauth|/openid|\.well-known'; then
    LOGIN_TYPE="oauth"
  # SAML
  elif echo "$URL" | grep -qiP '/saml'; then
    LOGIN_TYPE="saml"
  # SSO
  elif echo "$URL" | grep -qiP '/sso'; then
    LOGIN_TYPE="sso"
  # API auth (responde JSON)
  elif echo "$HTML" | grep -qi '"token"\|"access_token"\|"jwt"' && \
       echo "$URL" | grep -qiP '/api/'; then
    LOGIN_TYPE="api_auth"
  # Formulario con password
  elif echo "$HTML" | grep -qi 'type=["\']password["\']'; then
    LOGIN_TYPE="password_form"
  else
    return   # No es un login
  fi

  # ── Parsear detalles del formulario ──────────────────────
  local ACTION METHOD FIELDS TITLE TECH
  if [[ "$LOGIN_TYPE" == "password_form" ]]; then
    local PARSED
    PARSED=$(_parse_login_form "$HTML" "$URL") || return
    IFS='|' read -r ACTION METHOD FIELDS TITLE TECH <<< "$PARSED"
  else
    TITLE=$(echo "$HTML" | grep -oiP '(?<=<title>)[^<]+' | head -1 | tr -d '\n\r' | cut -c1-100)
    FIELDS=""
    ACTION=""
    METHOD="GET"
    TECH=""
  fi

  # ── Guardar en DB ─────────────────────────────────────────
  local URL_ESC="${URL//\'/\'\'}"
  local SUB_ESC="${SUBDOMAIN//\'/\'\'}"
  local ACT_ESC="${ACTION//\'/\'\'}"
  local FLD_ESC="${FIELDS//\'/\'\'}"
  local TTL_ESC="${TITLE//\'/\'\'}"
  local TCH_ESC="${TECH//\'/\'\'}"

  local IS_NEW
  IS_NEW=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM login_forms WHERE domain_id=${DOMAIN_ID} AND url='${URL_ESC}';" 2>/dev/null)

  sqlite3 "$DB_PATH" \
    "INSERT OR IGNORE INTO login_forms
     (domain_id,url,subdomain,form_action,form_method,input_fields,login_type,http_status,page_title,tech_hints)
     VALUES(${DOMAIN_ID},'${URL_ESC}','${SUB_ESC}','${ACT_ESC}','${METHOD}','${FLD_ESC}','${LOGIN_TYPE}',${HTTP_STATUS:-0},'${TTL_ESC}','${TCH_ESC}');" \
    2>/dev/null || true

  # Notificar si es nuevo
  if [[ "${IS_NEW:-0}" == "0" ]]; then
    local EMOJI="🔐"
    [[ "$LOGIN_TYPE" == "oauth" ]] && EMOJI="🔑"
    [[ "$LOGIN_TYPE" == "saml"  ]] && EMOJI="🏢"
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

  echo "$LOGIN_TYPE"
}

# ── Función principal ─────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 12 — $MODULE_DESC: $DOMAIN"

  _init_login_table

  # ── Proxy ────────────────────────────────────────────────
  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}" && \
    log_info "Peticiones DOM enrutadas por ${PROXY_TOOL}"

  local ALIVE="$OUT_DIR/subs_alive.txt"
  local URLS_RAW="$OUT_DIR/urls_raw.txt"

  if [[ ! -s "$ALIVE" ]]; then
    log_warn "Sin subdominios alive, saltando"
    return
  fi

  # ── Construir lista de URLs a analizar ────────────────────
  local CHECK_LIST="$OUT_DIR/.login_check.txt"
  > "$CHECK_LIST"

  # 1. Rutas conocidas sobre cada subdominio alive
  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    for PATH in "${LOGIN_PATHS[@]}"; do
      echo "https://${SUB}${PATH}" >> "$CHECK_LIST"
      echo "http://${SUB}${PATH}"  >> "$CHECK_LIST"
    done
  done < "$ALIVE"

  # 2. URLs ya descubiertas que parecen login
  if [[ -s "$URLS_RAW" ]]; then
    grep -iP '/(login|signin|sign.in|log.in|auth|admin|portal|dashboard|panel|sso|oauth|saml|account)' \
      "$URLS_RAW" >> "$CHECK_LIST" 2>/dev/null || true
  fi

  sort -u "$CHECK_LIST" -o "$CHECK_LIST"
  local TOTAL
  TOTAL=$(wc -l < "$CHECK_LIST" | tr -d ' ')
  log_info "Analizando $TOTAL URLs en busca de login forms..."

  local FOUND=0
  local CHECKED=0

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    ((CHECKED++))

    # Progreso cada 50 URLs
    (( CHECKED % 50 == 0 )) && log_info "[$CHECKED/$TOTAL] analizadas..."

    local RESULT
    RESULT=$(_check_url "$URL" "$DOMAIN_ID" "$CURL_PROXY")
    [[ -n "$RESULT" ]] && ((FOUND++))

  done < "$CHECK_LIST"

  rm -f "$CHECK_LIST"

  # ── Resumen ───────────────────────────────────────────────
  local TOTAL_DB
  TOTAL_DB=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM login_forms WHERE domain_id=${DOMAIN_ID};" 2>/dev/null || echo 0)

  if [[ "$FOUND" -gt 0 ]]; then
    _telegram_send "🔐 *Login Finder — Resumen*
🌐 \`${DOMAIN}\`
🔎 URLs analizadas: ${CHECKED}
🔐 Login forms encontrados: ${FOUND}
📊 Total en DB: ${TOTAL_DB}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi

  log_ok "$MODULE_DESC completado: $FOUND login forms en $CHECKED URLs analizadas"
}
