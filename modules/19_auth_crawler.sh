#!/usr/bin/env bash
# ============================================================
#  modules/19_auth_crawler.sh
#  Fase 19: Crawling autenticado usando credenciales del vault
#
#  Flujo:
#    1. Para cada login form detectado (tabla login_forms)
#    2. Busca credenciales en el vault para ese subdominio
#    3. Si las hay → inicia sesión, obtiene cookie/token
#    4. Crawling autenticado por Caido con la sesión activa
#    5. Pasa los endpoints nuevos a la rueda de scan
#    6. Si no hay creds → Telegram pregunta si las tienes
# ============================================================

MODULE_NAME="auth_crawler"
MODULE_DESC="Crawling autenticado con credenciales del vault"

# ── Helper: cifrado/descifrado via vault.py ───────────────────
_vault_decrypt() {
  local ENC="$1"
  python3 -c "
import sys
sys.path.insert(0, '$(dirname "$0")/../core')
from vault import decrypt
print(decrypt('${ENC//\'/\\\'}'))
" 2>/dev/null
}

_vault_encrypt() {
  local PLAIN="$1"
  python3 -c "
import sys
sys.path.insert(0, '$(dirname "$0")/../core')
from vault import encrypt
print(encrypt('${PLAIN//\'/\\\'}'))
" 2>/dev/null
}

# ── Intentar login en un form ─────────────────────────────────
_do_login() {
  local APP_URL="$1"
  local USERNAME="$2"
  local PASSWORD="$3"
  local AUTH_TYPE="${4:-form}"
  local PROXY_FLAG="$5"
  local COOKIE_JAR="$6"

  local HTTP_STATUS=""

  case "$AUTH_TYPE" in
    form)
      # Primero obtener el form para extraer campos hidden (CSRF, etc.)
      local FORM_HTML
      FORM_HTML=$(curl -sL --max-time 10 \
        -c "$COOKIE_JAR" \
        ${PROXY_FLAG} \
        "$APP_URL" 2>/dev/null)

      # Extraer action del form
      local FORM_ACTION
      FORM_ACTION=$(echo "$FORM_HTML" | grep -oiP '(?<=action=["\'])[^"\']+' | head -1)
      [[ -z "$FORM_ACTION" ]] && FORM_ACTION="$APP_URL"
      # Resolver URL relativa
      echo "$FORM_ACTION" | grep -qP '^https?' || \
        FORM_ACTION="$(echo "$APP_URL" | grep -oP 'https?://[^/]+')\$FORM_ACTION"

      # Extraer campos hidden (CSRF tokens)
      local HIDDEN_FIELDS=""
      while IFS= read -r FIELD; do
        local FNAME FVAL
        FNAME=$(echo "$FIELD" | grep -oiP 'name=["\'][^"\']+["\']' | sed "s/name=[\"']//;s/[\"']//" | head -1)
        FVAL=$(echo "$FIELD"  | grep -oiP 'value=["\'][^"\']*["\']' | sed "s/value=[\"']//;s/[\"']//" | head -1)
        [[ -n "$FNAME" ]] && HIDDEN_FIELDS+="&${FNAME}=${FVAL}"
      done < <(echo "$FORM_HTML" | grep -oiP '<input[^>]+type=["\']hidden["\'][^>]*>' | head -10)

      # Detectar nombres de campos usuario/password
      local USER_FIELD PASS_FIELD
      USER_FIELD=$(echo "$FORM_HTML" | grep -oiP '<input[^>]+(type=["\']?(text|email)["\']?)[^>]*>' | \
        grep -oiP 'name=["\'][^"\']+["\']' | sed "s/name=[\"']//;s/[\"']//" | head -1)
      PASS_FIELD=$(echo "$FORM_HTML" | grep -oiP '<input[^>]+type=["\']password["\'][^>]*>' | \
        grep -oiP 'name=["\'][^"\']+["\']' | sed "s/name=[\"']//;s/[\"']//" | head -1)

      [[ -z "$USER_FIELD" ]] && USER_FIELD="username"
      [[ -z "$PASS_FIELD" ]] && PASS_FIELD="password"

      # POST con las credenciales
      HTTP_STATUS=$(curl -sL --max-time 15 \
        -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
        -o /tmp/.auth_response_$$ \
        -w "%{http_code}" \
        -X POST "$FORM_ACTION" \
        --data-urlencode "${USER_FIELD}=${USERNAME}" \
        --data-urlencode "${PASS_FIELD}=${PASSWORD}" \
        --data "${HIDDEN_FIELDS#&}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36" \
        ${PROXY_FLAG} \
        2>/dev/null)
      ;;

    basic)
      HTTP_STATUS=$(curl -sL --max-time 10 \
        -c "$COOKIE_JAR" \
        -u "${USERNAME}:${PASSWORD}" \
        -o /tmp/.auth_response_$$ \
        -w "%{http_code}" \
        ${PROXY_FLAG} \
        "$APP_URL" 2>/dev/null)
      ;;

    bearer)
      # Intentar obtener token via API
      HTTP_STATUS=$(curl -sL --max-time 10 \
        -c "$COOKIE_JAR" \
        -X POST "$APP_URL" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${USERNAME}\",\"password\":\"${PASSWORD}\"}" \
        -o /tmp/.auth_response_$$ \
        -w "%{http_code}" \
        ${PROXY_FLAG} \
        2>/dev/null)

      # Extraer Bearer token de la respuesta
      local TOKEN
      TOKEN=$(cat /tmp/.auth_response_$$ 2>/dev/null | \
        grep -oP '(?<="token"\s*:\s*")[^"]+|(?<="access_token"\s*:\s*")[^"]+' | head -1)
      [[ -n "$TOKEN" ]] && echo "Bearer:$TOKEN" > "${COOKIE_JAR}.token"
      ;;
  esac

  rm -f /tmp/.auth_response_$$

  # Verificar si el login fue exitoso
  # Éxito: código 200/302 + cookies en el jar
  local COOKIE_COUNT
  COOKIE_COUNT=$(grep -v "^#\|^$" "$COOKIE_JAR" 2>/dev/null | wc -l | tr -d ' ')

  if [[ "$HTTP_STATUS" =~ ^(200|302|301)$ ]] && [[ "$COOKIE_COUNT" -gt 0 ]]; then
    echo "ok"
  else
    echo "fail"
  fi
}

# ── Crawling autenticado ──────────────────────────────────────
_auth_crawl() {
  local BASE_URL="$1"     # https://app.ejemplo.com
  local COOKIE_JAR="$2"
  local DOMAIN_ID="$3"
  local DOMAIN="$4"
  local PROXY_FLAG="$5"
  local OUT_DIR="$6"
  local DEPTH="${CRAWL_DEPTH:-3}"

  local SUBDOMAIN
  SUBDOMAIN=$(echo "$BASE_URL" | sed 's|https\?://||;s|/.*||')

  log_info "Crawling autenticado sobre $BASE_URL (depth=$DEPTH)..."

  local AUTH_URLS="$OUT_DIR/.auth_urls_${SUBDOMAIN//[^a-zA-Z0-9]/_}.txt"
  > "$AUTH_URLS"

  # katana con cookies de sesión
  if command -v "${KATANA_BIN:-katana}" &>/dev/null; then
    # Extraer cookies del jar en formato header
    local COOKIE_HEADER
    COOKIE_HEADER=$(grep -v "^#\|^$" "$COOKIE_JAR" 2>/dev/null | \
      awk '{printf "%s=%s; ", $6, $7}' | sed 's/; $//')

    [[ -n "$COOKIE_HEADER" ]] && \
      timeout 180 "${KATANA_BIN:-katana}" \
        -u "$BASE_URL" \
        -d "$DEPTH" \
        -H "Cookie: ${COOKIE_HEADER}" \
        -silent -jc -kf all \
        ${PROXY_FLAG:+-proxy "$PROXY_FLAG"} \
        -o "$AUTH_URLS" \
        2>/dev/null || true
  fi

  # También gospider con cookies
  if command -v gospider &>/dev/null; then
    local COOKIE_HEADER
    COOKIE_HEADER=$(grep -v "^#\|^$" "$COOKIE_JAR" 2>/dev/null | \
      awk '{printf "%s=%s; ", $6, $7}' | sed 's/; $//')

    [[ -n "$COOKIE_HEADER" ]] && \
      gospider -s "$BASE_URL" -d "$DEPTH" -c 5 -t 10 --quiet \
        -H "Cookie: ${COOKIE_HEADER}" \
        ${PROXY_FLAG:+--proxy "$PROXY_FLAG"} \
        2>/dev/null | grep -oP 'https?://[^\s]+' >> "$AUTH_URLS" || true
  fi

  # Contar y guardar URLs nuevas encontradas autenticado
  local NEW_AUTH=0
  if [[ -s "$AUTH_URLS" ]]; then
    sort -u "$AUTH_URLS" -o "$AUTH_URLS"
    while IFS= read -r URL; do
      [[ -z "$URL" ]] && continue
      local IS_NEW
      IS_NEW=$(db_is_new_url "$DOMAIN_ID" "$URL")
      db_add_url "$DOMAIN_ID" "$URL" "auth_crawler" ""
      [[ "$IS_NEW" == "1" ]] && ((NEW_AUTH++))
    done < "$AUTH_URLS"
    log_ok "Crawling autenticado: $NEW_AUTH URLs nuevas encontradas dentro de la app"
  fi

  rm -f "$AUTH_URLS"
  echo "$NEW_AUTH"
}

# ── Función principal ─────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 19 — $MODULE_DESC: $DOMAIN"

  # Verificar que el vault está operativo
  if [[ -z "${VAULT_KEY:-}" ]]; then
    log_warn "VAULT_KEY no configurada en .env — saltando auth crawler"
    return
  fi

  # Proxy
  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  # Obtener login forms detectados para este dominio
  local LOGIN_FORMS
  LOGIN_FORMS=$(sqlite3 "$DB_PATH" \
    "SELECT id, url, subdomain, login_type FROM login_forms
     WHERE domain_id=${DOMAIN_ID} AND login_type='password_form'
     ORDER BY found_at;" 2>/dev/null)

  if [[ -z "$LOGIN_FORMS" ]]; then
    log_info "Sin login forms password_form detectados para $DOMAIN"
    return
  fi

  local TOTAL_AUTHED=0

  while IFS='|' read -r FORM_ID APP_URL SUBDOMAIN LOGIN_TYPE; do
    [[ -z "$APP_URL" ]] && continue
    log_info "Procesando login: $APP_URL"

    # ── Buscar credenciales en el vault ───────────────────
    local HAS_CREDS
    HAS_CREDS=$(db_vault_has_creds "$DOMAIN_ID" "$SUBDOMAIN")

    if [[ "$HAS_CREDS" == "0" ]]; then
      # No hay creds — notificar por Telegram
      log_info "Sin credenciales en vault para $SUBDOMAIN — notificando..."
      _telegram_send "🔐 *Login form sin credenciales*
🌐 \`${DOMAIN}\`
🎯 Subdominio: \`${SUBDOMAIN}\`
🔗 \`${APP_URL}\`
💡 Añade credenciales desde el dashboard:
   Dashboard → ${DOMAIN} → 🔐 Vault
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
      continue
    fi

    # ── Obtener y descifrar credenciales ──────────────────
    local CRED_ROW
    CRED_ROW=$(db_vault_get "$DOMAIN_ID" "$SUBDOMAIN")
    [[ -z "$CRED_ROW" ]] && continue

    local CRED_ID USERNAME PASSWORD_ENC AUTH_TYPE SESSION_ENC LOGIN_URL
    IFS='|' read -r CRED_ID USERNAME PASSWORD_ENC AUTH_TYPE SESSION_ENC LOGIN_URL \
      <<< "$CRED_ROW"

    local PASSWORD
    PASSWORD=$(_vault_decrypt "$PASSWORD_ENC")
    if [[ -z "$PASSWORD" ]]; then
      log_warn "No se pudo descifrar credencial para $SUBDOMAIN — ¿VAULT_KEY correcta?"
      continue
    fi

    # ── Cookie jar para esta sesión ───────────────────────
    local COOKIE_JAR="$OUT_DIR/.cookies_${SUBDOMAIN//[^a-zA-Z0-9]/_}.txt"
    > "$COOKIE_JAR"

    # Usar sesión cacheada si existe y es reciente (< 4h)
    local USE_CACHED=false
    if [[ -n "$SESSION_ENC" ]]; then
      local SESSION_DATA
      SESSION_DATA=$(_vault_decrypt "$SESSION_ENC" 2>/dev/null)
      if [[ -n "$SESSION_DATA" ]]; then
        echo "$SESSION_DATA" > "$COOKIE_JAR"
        USE_CACHED=true
        log_info "Usando sesión cacheada para $SUBDOMAIN"
      fi
    fi

    # ── Login si no hay sesión válida ─────────────────────
    if ! $USE_CACHED; then
      log_info "Iniciando sesión en $APP_URL como $USERNAME..."
      local LOGIN_RESULT
      LOGIN_RESULT=$(_do_login \
        "$APP_URL" "$USERNAME" "$PASSWORD" "$AUTH_TYPE" \
        "$CURL_PROXY" "$COOKIE_JAR")

      if [[ "$LOGIN_RESULT" == "ok" ]]; then
        log_ok "Login exitoso en $SUBDOMAIN"

        # Cachear la sesión cifrada en el vault
        local SESSION_PLAIN
        SESSION_PLAIN=$(cat "$COOKIE_JAR" 2>/dev/null)
        if [[ -n "$SESSION_PLAIN" ]]; then
          local SESSION_ENC_NEW
          SESSION_ENC_NEW=$(_vault_encrypt "$SESSION_PLAIN")
          db_vault_update_session "$CRED_ID" "$SESSION_ENC_NEW"
        fi

        _telegram_send "✅ *Login exitoso*
🌐 \`${DOMAIN}\`
🎯 \`${SUBDOMAIN}\`
👤 Usuario: \`${USERNAME}\`
🔍 Iniciando crawling autenticado...
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

      else
        log_warn "Login fallido en $SUBDOMAIN — marcando credenciales como inválidas"
        db_vault_invalidate "$CRED_ID"
        _telegram_send "❌ *Login fallido*
🌐 \`${DOMAIN}\`
🎯 \`${SUBDOMAIN}\`
👤 \`${USERNAME}\`
⚠️ Credenciales marcadas como inválidas en el vault
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
        rm -f "$COOKIE_JAR"
        continue
      fi
    fi

    # ── Crawling autenticado ──────────────────────────────
    local BASE_URL="https://${SUBDOMAIN}"
    local NEW_URLS
    NEW_URLS=$(_auth_crawl \
      "$BASE_URL" "$COOKIE_JAR" "$DOMAIN_ID" "$DOMAIN" \
      "$PROXY_URL" "$OUT_DIR")

    ((TOTAL_AUTHED += ${NEW_URLS:-0}))

    if [[ "${NEW_URLS:-0}" -gt 0 ]]; then
      _telegram_send "🔍 *Crawling autenticado completado*
🌐 \`${DOMAIN}\`
🎯 \`${SUBDOMAIN}\`
🆕 URLs nuevas dentro de la app: \`${NEW_URLS}\`
⚡ Entrando en la rueda de nuclei + scan activo
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
    fi

    # Limpiar cookie jar (no dejar sesiones en disco)
    rm -f "$COOKIE_JAR"

    # Limpiar password de memoria
    PASSWORD=""

  done <<< "$LOGIN_FORMS"

  log_ok "$MODULE_DESC completado: $TOTAL_AUTHED URLs nuevas encontradas autenticado"
}
