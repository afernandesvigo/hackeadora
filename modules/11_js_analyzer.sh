#!/usr/bin/env bash
# ============================================================
#  modules/11_js_analyzer.sh
#  Fase 11: Análisis de archivos JavaScript
#
#  Por cada JS encontrado en el crawling:
#    1. Descarga el archivo
#    2. Extrae SECRETS con patrones regex + secretfinder
#    3. Extrae ENDPOINTS (paths de API, rutas, fetch/axios...)
#    4. Inyecta los endpoints nuevos en la tabla urls
#       para que entren en la rueda de nuclei + active_scan
#    5. Notifica por Telegram si encuentra secrets
# ============================================================

MODULE_NAME="js_analyzer"
MODULE_DESC="Análisis de JS — secrets y endpoints"

# ── Patrones de secrets ───────────────────────────────────────
# Formato: "NOMBRE|REGEX"
declare -a SECRET_PATTERNS=(
  # Cloud providers
  "AWS_ACCESS_KEY|AKIA[0-9A-Z]{16}"
  "AWS_SECRET_KEY|(?<=[^A-Za-z0-9])[A-Za-z0-9/+=]{40}(?=[^A-Za-z0-9])"
  "GOOGLE_API_KEY|AIza[0-9A-Za-z\\-_]{35}"
  "GOOGLE_OAUTH|[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"
  "FIREBASE_KEY|AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"
  "AZURE_CONN|DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"
  # Payment
  "STRIPE_LIVE|sk_live_[0-9a-zA-Z]{24,}"
  "STRIPE_PUB|pk_live_[0-9a-zA-Z]{24,}"
  "PAYPAL_TOKEN|access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"
  "BRAINTREE|access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"
  # Auth / tokens
  "GITHUB_TOKEN|gh[pousr]_[A-Za-z0-9_]{36,255}"
  "GITHUB_OAUTH|[0-9a-f]{40}"
  "SLACK_TOKEN|xox[baprs]-([0-9a-zA-Z]{10,48})"
  "SLACK_WEBHOOK|https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"
  "DISCORD_TOKEN|[MN][A-Za-z0-9]{23}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27}"
  "DISCORD_WEBHOOK|https://discord(app)?\\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"
  "TELEGRAM_BOT|[0-9]{8,10}:[A-Za-z0-9_-]{35}"
  "JWT_TOKEN|eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"
  "BEARER_TOKEN|[Bb]earer\\s+[A-Za-z0-9\\-._~+/]+=*"
  # Databases
  "MONGODB_URI|mongodb(\\+srv)?://[^\\s'\"]+"
  "MYSQL_URI|mysql://[^\\s'\"]+"
  "POSTGRES_URI|postgres(ql)?://[^\\s'\"]+"
  "REDIS_URI|redis://[^\\s'\"]+"
  # Generic secrets
  "PRIVATE_KEY|-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY"
  "PASSWORD_VAR|['\"]?password['\"]?\\s*[:=]\\s*['\"][^'\"]{6,}['\"]"
  "API_KEY_VAR|['\"]?api.?key['\"]?\\s*[:=]\\s*['\"][A-Za-z0-9\\-_.]{16,}['\"]"
  "SECRET_VAR|['\"]?secret['\"]?\\s*[:=]\\s*['\"][A-Za-z0-9\\-_.]{8,}['\"]"
  "TOKEN_VAR|['\"]?token['\"]?\\s*[:=]\\s*['\"][A-Za-z0-9\\-_.]{16,}['\"]"
  # Maps / analytics
  "MAPBOX_TOKEN|pk\\.eyJ1[A-Za-z0-9._-]+"
  "SENDGRID_KEY|SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}"
  "TWILIO_SID|AC[a-z0-9]{32}"
  "MAILCHIMP|[0-9a-f]{32}-us[0-9]+"
)

# ── Patrones de endpoints ─────────────────────────────────────
# Extraemos: /api/v1/..., fetch("..."), axios.get("..."), href=, action=, etc.
declare -a ENDPOINT_PATTERNS=(
  # Rutas de API explícitas
  "\"(/api/[^\"\s]{2,100})\""
  "'(/api/[^'\s]{2,100})'"
  "\`(/api/[^\`\s]{2,100})\`"
  # fetch / axios / XMLHttpRequest
  "fetch\(['\"\`]([^'\"\`\s]{3,200})['\"\`]"
  "axios\.[a-z]+\(['\"\`]([^'\"\`\s]{3,200})['\"\`]"
  "XMLHttpRequest[^\"']*[\"']([^\"'\s]{3,200})[\"']"
  "\\.open\(['\"][A-Z]+['\"],\s*['\"]([^'\"]{3,200})['\"]"
  # href / src / action
  "href\s*=\s*['\"]([^'\"#\s]{5,200})['\"]"
  "action\s*=\s*['\"]([^'\"#\s]{5,200})['\"]"
  # Rutas generales
  "path\s*:\s*['\"]([/][^'\"]{2,100})['\"]"
  "url\s*:\s*['\"]([^'\"]{5,200})['\"]"
  "baseURL\s*[=:]\s*['\"\`]([^'\"\`\s]{5,200})['\"\`]"
  "endpoint\s*[=:]\s*['\"\`]([^'\"\`\s]{5,200})['\"\`]"
  # Rutas con método HTTP
  "\.(get|post|put|patch|delete)\(['\"\`]([^'\"\`\s]{3,200})['\"\`]"
)

# ── Helpers ───────────────────────────────────────────────────
_mask_secret() {
  # Muestra primeros 6 y últimos 4 chars, oculta el centro
  local VAL="$1"
  local LEN=${#VAL}
  if [[ $LEN -le 12 ]]; then
    echo "${VAL:0:3}***"
  else
    echo "${VAL:0:6}...${VAL: -4}"
  fi
}

_is_likely_false_positive() {
  local VAL="$1"
  # Descarta placeholders comunes
  local FP_PATTERNS=("your_" "YOUR_" "example" "EXAMPLE" "placeholder"
                     "xxxxxxx" "XXXXXXX" "000000" "111111" "test123"
                     "changeme" "CHANGEME" "<" ">" "\${" "{{")
  for PAT in "${FP_PATTERNS[@]}"; do
    [[ "$VAL" == *"$PAT"* ]] && return 0
  done
  return 1
}

# ── Descarga y análisis de un JS ──────────────────────────────
_analyze_js_file() {
  local JS_URL="$1"
  local DOMAIN_ID="$2"
  local DOMAIN="$3"
  local WORK_DIR="$4"

  local SUBDOMAIN
  SUBDOMAIN=$(echo "$JS_URL" | sed 's|https\?://||;s|/.*||')

  # Nombre de archivo seguro para guardar
  local SAFE_NAME
  SAFE_NAME=$(echo "$JS_URL" | md5sum | cut -d' ' -f1)
  local JS_FILE="$WORK_DIR/${SAFE_NAME}.js"

  # Descargar
  local SIZE=0
  if ! curl -sL --max-time 15 --max-filesize 5000000 \
       -A "Mozilla/5.0 (compatible; Hackeadora/1.0)" \
       -o "$JS_FILE" "$JS_URL" 2>/dev/null; then
    return
  fi

  [[ ! -s "$JS_FILE" ]] && return
  SIZE=$(wc -c < "$JS_FILE" | tr -d ' ')

  # Calcular hash para detectar cambios
  local SHA
  SHA=$(sha256sum "$JS_FILE" | cut -d' ' -f1)

  # Guardar en DB y obtener ID
  local JS_FILE_ID
  JS_FILE_ID=$(db_upsert_js_file "$DOMAIN_ID" "$JS_URL" "$SUBDOMAIN" "$SIZE" "$SHA" 0 0)
  [[ -z "$JS_FILE_ID" ]] && JS_FILE_ID=0

  local SECRET_COUNT=0
  local EP_COUNT=0

  # ── EXTRACCIÓN DE SECRETS ─────────────────────────────────
  for PATTERN_DEF in "${SECRET_PATTERNS[@]}"; do
    local STYPE="${PATTERN_DEF%%|*}"
    local REGEX="${PATTERN_DEF#*|}"

    # grep -P para PCRE, -n para nº línea, -o para solo el match
    while IFS=: read -r LINENUM MATCH; do
      [[ -z "$MATCH" ]] && continue
      _is_likely_false_positive "$MATCH" && continue

      # Extraer contexto (la línea completa, truncada)
      local CONTEXT
      CONTEXT=$(sed -n "${LINENUM}p" "$JS_FILE" 2>/dev/null | cut -c1-200 | tr "'" '"')

      local MASKED
      MASKED=$(_mask_secret "$MATCH")

      local IS_NEW
      IS_NEW=$(db_add_js_secret \
        "$DOMAIN_ID" "$JS_FILE_ID" "$JS_URL" \
        "$STYPE" "$MASKED" "$MATCH" \
        "$LINENUM" "$CONTEXT" "high")

      if [[ "$IS_NEW" == "1" ]]; then
        ((SECRET_COUNT++))
        log_warn "🔑 SECRET [$STYPE] en $JS_URL (línea $LINENUM): $MASKED"

        # Notificación Telegram
        _telegram_send "🔑 *JS Secret encontrado*
🌐 Dominio: \`${DOMAIN}\`
📄 Archivo: \`${JS_URL}\`
🏷️ Tipo: \`${STYPE}\`
🔍 Valor: \`${MASKED}\`
📍 Línea: ${LINENUM}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

        # También como finding en la tabla principal
        db_add_finding "$DOMAIN_ID" "js_secret" "high" \
          "$JS_URL" "$STYPE" "Secret tipo $STYPE en línea $LINENUM: $MASKED"
      fi
    done < <(grep -Pn "$REGEX" "$JS_FILE" 2>/dev/null | head -20 || true)
  done

  # ── EXTRACCIÓN DE ENDPOINTS ───────────────────────────────
  local BASE_ORIGIN
  BASE_ORIGIN=$(echo "$JS_URL" | grep -oP 'https?://[^/]+')

  # Ejecutar secretfinder si está disponible (mejor extractor de endpoints)
  if command -v python3 &>/dev/null && [[ -f "$HOME/tools/SecretFinder/SecretFinder.py" ]]; then
    python3 "$HOME/tools/SecretFinder/SecretFinder.py" \
      -i "$JS_URL" -o cli 2>/dev/null \
    | grep -oP '(?<=endpoint: )[^\s]+' \
    > "$WORK_DIR/.sf_endpoints.txt" 2>/dev/null || true
  fi

  # Regex propia de endpoints
  for EP_REGEX in "${ENDPOINT_PATTERNS[@]}"; do
    grep -oPh "$EP_REGEX" "$JS_FILE" 2>/dev/null \
    | grep -v "^$" \
    | head -100 \
    >> "$WORK_DIR/.ep_raw.txt" || true
  done

  # Limpiar y procesar endpoints
  if [[ -f "$WORK_DIR/.ep_raw.txt" ]] || [[ -f "$WORK_DIR/.sf_endpoints.txt" ]]; then
    cat "$WORK_DIR/.ep_raw.txt" "$WORK_DIR/.sf_endpoints.txt" 2>/dev/null \
    | sort -u \
    | grep -v "^$" \
    | while IFS= read -r EP; do
        # Limpiar el endpoint
        EP=$(echo "$EP" | tr -d "\"'" | sed 's/\\//g' | tr -d ' ')
        [[ -z "$EP" || ${#EP} -lt 3 ]] && continue

        # Construir URL completa si es ruta relativa
        local FULL_URL=""
        if echo "$EP" | grep -qP '^https?://'; then
          # Ya es absoluta — verificar que sea del mismo dominio
          echo "$EP" | grep -qF "$DOMAIN" && FULL_URL="$EP"
        elif echo "$EP" | grep -qP '^/'; then
          # Ruta absoluta → añadir origen
          FULL_URL="${BASE_ORIGIN}${EP}"
        fi

        # Detectar método HTTP si viene en el patrón (ej: .post("/api/...)
        local METHOD=""
        echo "$EP" | grep -qiP '\b(post|put|patch|delete)\b' && \
          METHOD=$(echo "$EP" | grep -oiP '\b(post|put|patch|delete)\b' | head -1 | tr '[:lower:]' '[:upper:]')

        local IS_NEW
        IS_NEW=$(db_add_js_endpoint \
          "$DOMAIN_ID" "$JS_FILE_ID" "$JS_URL" \
          "$EP" "$FULL_URL" "$METHOD" "")

        if [[ "$IS_NEW" == "1" ]]; then
          ((EP_COUNT++))
          log_info "  ↳ endpoint: $EP${FULL_URL:+ → $FULL_URL}"

          # Si tiene URL completa, añadir a la tabla urls para que
          # entre en nuclei + active_scan en el próximo ciclo
          if [[ -n "$FULL_URL" ]]; then
            db_add_url "$DOMAIN_ID" "$FULL_URL" "js_analyzer" ""
          fi
        fi
      done

    rm -f "$WORK_DIR/.ep_raw.txt" "$WORK_DIR/.sf_endpoints.txt"
  fi

  # Actualizar contadores en js_files
  sqlite3 "$DB_PATH" \
    "UPDATE js_files SET endpoints_found=${EP_COUNT}, secrets_found=${SECRET_COUNT}
     WHERE id=${JS_FILE_ID};" 2>/dev/null || true

  rm -f "$JS_FILE"
  echo "$SECRET_COUNT $EP_COUNT"
}

# ── Función principal ─────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 11 — $MODULE_DESC: $DOMAIN"

  local URLS_RAW="$OUT_DIR/urls_raw.txt"
  local ALIVE="$OUT_DIR/subs_alive.txt"

  # ── Recopilar todos los JS conocidos ──────────────────────
  local JS_LIST="$OUT_DIR/.js_list.txt"
  > "$JS_LIST"

  # 1. JS en las URLs ya crawleadas
  if [[ -s "$URLS_RAW" ]]; then
    grep -iP '\.js(\?[^\"]*)?$' "$URLS_RAW" >> "$JS_LIST" 2>/dev/null || true
  fi

  # 2. Descubrir JS adicionales con katana sobre los subdominios alive
  if command -v "${KATANA_BIN:-katana}" &>/dev/null && [[ -s "$ALIVE" ]]; then
    log_info "Descubriendo JS con katana..."
    sed 's|^|https://|' "$ALIVE" \
    | timeout 120 "${KATANA_BIN:-katana}" \
        -l /dev/stdin \
        -d 3 -jc -silent \
        -extension js \
        2>/dev/null \
    >> "$JS_LIST" || true
  fi

  # 3. JS de gau/wayback que no estuvieran ya
  if command -v "${GAU_BIN:-gau}" &>/dev/null; then
    "${GAU_BIN:-gau}" --subs "$DOMAIN" 2>/dev/null \
    | grep -iP '\.js(\?[^\"]*)?$' \
    >> "$JS_LIST" || true
  fi

  sort -u "$JS_LIST" -o "$JS_LIST"
  local TOTAL_JS
  TOTAL_JS=$(wc -l < "$JS_LIST" | tr -d ' ')

  if [[ "$TOTAL_JS" -eq 0 ]]; then
    log_warn "No se encontraron archivos JS para analizar"
    rm -f "$JS_LIST"
    return
  fi

  log_info "$TOTAL_JS archivos JS encontrados — analizando..."

  local WORK_DIR="$OUT_DIR/.js_work"
  mkdir -p "$WORK_DIR"

  local TOTAL_SECRETS=0
  local TOTAL_ENDPOINTS=0
  local ANALYZED=0

  # ── Analizar cada JS ──────────────────────────────────────
  while IFS= read -r JS_URL; do
    [[ -z "$JS_URL" ]] && continue
    ((ANALYZED++))
    log_info "[$ANALYZED/$TOTAL_JS] $JS_URL"

    local RESULT
    RESULT=$(_analyze_js_file "$JS_URL" "$DOMAIN_ID" "$DOMAIN" "$WORK_DIR")
    local S EP
    read -r S EP <<< "$RESULT"
    (( TOTAL_SECRETS   += ${S:-0}  ))
    (( TOTAL_ENDPOINTS += ${EP:-0} ))

  done < "$JS_LIST"

  # ── Marcar endpoints como encolados ───────────────────────
  db_mark_js_endpoints_queued "$DOMAIN_ID"

  rm -rf "$WORK_DIR" "$JS_LIST"

  log_ok "$MODULE_DESC completado:"
  log_ok "  → $ANALYZED JS analizados"
  log_ok "  → $TOTAL_SECRETS secrets encontrados"
  log_ok "  → $TOTAL_ENDPOINTS endpoints extraídos (añadidos a la rueda)"

  if [[ "$TOTAL_SECRETS" -gt 0 ]]; then
    _telegram_send "📊 *JS Analysis — Resumen*
🌐 \`${DOMAIN}\`
📄 JS analizados: ${ANALYZED}
🔑 Secrets: ${TOTAL_SECRETS}
🔗 Endpoints nuevos: ${TOTAL_ENDPOINTS}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi
}
