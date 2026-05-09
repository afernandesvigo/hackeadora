#!/usr/bin/env bash
# ============================================================
#  modules/11_js_analyzer.sh
#  Fase 11: Análisis de archivos JavaScript
#
#  Por cada JS encontrado en el crawling:
#    1. Descarga el archivo
#    2. Extrae SECRETS con patrones regex
#    3. Extrae ENDPOINTS con un único paso Python (capture groups, sin noise)
#    4. Inyecta los endpoints nuevos en la tabla urls
#    5. Notifica por Telegram si encuentra secrets
#    6. Probe HTTP de endpoints sensibles (batch al final)
# ============================================================

MODULE_NAME="js_analyzer"
MODULE_DESC="Análisis de JS — secrets y endpoints"

# ── Patrones de secrets ───────────────────────────────────────
declare -a SECRET_PATTERNS=(
  "AWS_ACCESS_KEY|AKIA[0-9A-Z]{16}"
  "AWS_SECRET_KEY|(?i)(?:aws.?secret|SecretAccessKey|secret.access.key)[\s:=\"']{0,20}([A-Za-z0-9/+=]{40})"
  "GOOGLE_API_KEY|AIza[0-9A-Za-z\\-_]{35}"
  "GOOGLE_OAUTH|[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"
  "FIREBASE_KEY|AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"
  "AZURE_CONN|DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"
  "STRIPE_LIVE|sk_live_[0-9a-zA-Z]{24,}"
  "STRIPE_PUB|pk_live_[0-9a-zA-Z]{24,}"
  "PAYPAL_TOKEN|access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"
  "BRAINTREE|access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"
  "GITHUB_TOKEN|gh[pousr]_[A-Za-z0-9_]{36,255}"
  "SLACK_TOKEN|xox[baprs]-([0-9a-zA-Z]{10,48})"
  "SLACK_WEBHOOK|https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"
  "DISCORD_TOKEN|[MN][A-Za-z0-9]{23}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27}"
  "DISCORD_WEBHOOK|https://discord(app)?\\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"
  "TELEGRAM_BOT|[0-9]{8,10}:[A-Za-z0-9_-]{35}"
  "JWT_TOKEN|eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"
  "BEARER_TOKEN|[Bb]earer\\s+[A-Za-z0-9\\-._~+/]+=*"
  "MONGODB_URI|mongodb(\\+srv)?://[^\\s'\"]+"
  "MYSQL_URI|mysql://[^\\s'\"]+"
  "POSTGRES_URI|postgres(ql)?://[^\\s'\"]+"
  "REDIS_URI|redis://[^\\s'\"]+"
  "PRIVATE_KEY|-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY"
  "PASSWORD_VAR|['\"]?password['\"]?\\s*[:=]\\s*['\"][^'\"]{6,}['\"]"
  "API_KEY_VAR|['\"]?api.?key['\"]?\\s*[:=]\\s*['\"][A-Za-z0-9\\-_.]{16,}['\"]"
  "SECRET_VAR|['\"]?secret['\"]?\\s*[:=]\\s*['\"][A-Za-z0-9\\-_.]{8,}['\"]"
  "TOKEN_VAR|['\"]?token['\"]?\\s*[:=]\\s*['\"][A-Za-z0-9\\-_.]{16,}['\"]"
  "MAPBOX_TOKEN|pk\\.eyJ1[A-Za-z0-9._-]+"
  "SENDGRID_KEY|SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}"
  "TWILIO_SID|AC[a-z0-9]{32}"
  "MAILCHIMP|[0-9a-f]{32}-us[0-9]+"
)

# ── Patrones sensibles para probe HTTP ───────────────────────
declare -a _SENSITIVE_API_PATTERNS=(
  "/api/.*/me(\.json)?$"
  "/api/.*/users?/me"
  "/api/.*/profile(\.json)?$"
  "/api/.*/account(\.json)?$"
  "/api/.*/whoami"
  "/api/.*/session(\.json)?$"
  "/api/.*/token(s)?(\.json)?$"
  "/api/.*/auth/token"
  "/users?/me(\.json)?$"
  "/me\.json$"
)

# ── Helpers ───────────────────────────────────────────────────
_mask_secret() {
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
  local CTX="${2:-}"
  local FP_PATTERNS=("your_" "YOUR_" "example" "EXAMPLE" "placeholder"
                     "xxxxxxx" "XXXXXXX" "000000" "111111" "test123"
                     "changeme" "CHANGEME" "<" ">" "\${" "{{"
                     "REQUEST_ID" "Request ID" "RequestId" "requestId"
                     "correlationId" "traceId" "spanId" "x-amz-request"
                     "X-Request-ID" "CloudFront" "cloudfront")
  for PAT in "${FP_PATTERNS[@]}"; do
    [[ "$VAL" == *"$PAT"* ]] && return 0
    [[ "$CTX" == *"$PAT"* ]] && return 0
  done

  # Bug #12: extraer la parte VALUE (entre comillas) y validar entropy mínima.
  # Patterns como TOKEN_VAR/SECRET_VAR/API_KEY_VAR matchean `name = "value"` —
  # el value debe tener entropy real, no ser un identifier truncado.
  local VALUE_PART
  # Bash 3.2+ regex extract (el último token entre comillas)
  if [[ "$VAL" =~ [\'\"]([^\'\"]+)[\'\"][[:space:]]*$ ]]; then
    VALUE_PART="${BASH_REMATCH[1]}"
  fi
  if [[ -n "$VALUE_PART" ]]; then
    local VLEN=${#VALUE_PART}
    # Mínimo 12 caracteres para considerar secret real
    [[ "$VLEN" -lt 12 ]] && return 0
    # Debe contener al menos un dígito y una letra (entropy básica)
    [[ ! "$VALUE_PART" =~ [0-9] ]] && return 0
    [[ ! "$VALUE_PART" =~ [A-Za-z] ]] && return 0
    # Rechazar identifier-only: solo alphanum lowercase sin separadores → probable nombre var
    if [[ "$VALUE_PART" =~ ^[a-z]+$ ]]; then
      return 0
    fi
  fi
  return 1
}

# ── Extractor de endpoints en Python (un solo paso) ──────────
# Recibe: JS_FILE BASE_ORIGIN DOMAIN
# Devuelve líneas: EP<TAB>FULL_URL<TAB>METHOD  (FULL_URL y METHOD pueden ser vacíos)
_extract_endpoints_py() {
  local JS_FILE="$1"
  local BASE_ORIGIN="$2"
  local DOMAIN="$3"

  python3 - "$JS_FILE" "$BASE_ORIGIN" "$DOMAIN" <<'PYEOF'
import re, sys

js_file, base_origin, domain = sys.argv[1], sys.argv[2], sys.argv[3]

# Rutas de noise a filtrar (framework internals, assets)
NOISE_PATH_RE = re.compile(
    r'^/?(_next/|__next|webpack|node_modules|\.well-known)'
    r'|\.(?:js|css|png|jpg|gif|svg|ico|woff|woff2|ttf|eot|map|webp)(?:\?|$)',
    re.I
)

# Patrones: (compiled_regex, group_index_for_endpoint, method_hint)
PATTERNS = [
    # /api/... in quotes
    (re.compile(r'''["'`](/api/[^"'`\s]{2,150})["'`]'''), 1, None),
    # fetch/axios/http calls
    (re.compile(r'''fetch\(["'`]([^"'`\s]{3,200})["'`]'''), 1, None),
    (re.compile(r'''axios\.(\w+)\(["'`]([^"'`\s]{3,200})["'`]'''), 2, 1),
    (re.compile(r'''XMLHttpRequest[^"']{0,50}["']([^"'\s]{3,200})["']'''), 1, None),
    (re.compile(r'''\.open\(["'][A-Z]+["'],\s*["']([^"']{3,200})["']'''), 1, None),
    # http.get/post/put/patch/delete
    (re.compile(r'''\.(get|post|put|patch|delete)\(["'`]([^"'`\s]{3,200})["'`]''', re.I), 2, 1),
    # href/action/src for non-static paths
    (re.compile(r'''href\s*=\s*["']([^"'#\s]{5,200})["']'''), 1, None),
    (re.compile(r'''action\s*=\s*["']([^"'#\s]{5,200})["']'''), 1, None),
    # url/endpoint/baseURL config
    (re.compile(r'''(?:url|endpoint)\s*:\s*["'`]([^"'`\s]{5,200})["'`]'''), 1, None),
    (re.compile(r'''baseURL\s*[=:]\s*["'`]([^"'`\s]{5,200})["'`]'''), 1, None),
    # path: "/..."
    (re.compile(r'''path\s*:\s*["']([/][^"']{2,100})["']'''), 1, None),
]

try:
    content = open(js_file, encoding='utf-8', errors='ignore').read()
except Exception:
    sys.exit(0)

seen = set()
results = []

for pat, ep_grp, method_grp in PATTERNS:
    for m in pat.finditer(content):
        try:
            ep = m.group(ep_grp)
        except IndexError:
            continue
        if not ep:
            continue

        ep = ep.strip().strip('"\'`').replace('\\/', '/')

        if len(ep) < 3:
            continue
        if NOISE_PATH_RE.search(ep):
            continue

        # Resolve to full URL
        full_url = ''
        if ep.startswith('http://') or ep.startswith('https://'):
            if domain in ep:
                full_url = ep
        elif ep.startswith('/'):
            full_url = base_origin + ep

        # Method hint
        method = ''
        if method_grp:
            try:
                method = m.group(method_grp).upper()
            except IndexError:
                pass
        if method in ('GET', ''):
            method = ''

        key = ep
        if key in seen:
            continue
        seen.add(key)

        results.append(f"{ep}\t{full_url}\t{method}")

for r in results:
    print(r)
PYEOF
}

# ── Probe de endpoint sensible sin autenticación ─────────────
_probe_api_endpoint() {
  local FULL_URL="$1"
  local DOMAIN_ID="$2"
  local DOMAIN="$3"

  local PATH_PART
  PATH_PART=$(echo "$FULL_URL" | sed 's|https\?://[^/]*||')
  local MATCH=false
  for PAT in "${_SENSITIVE_API_PATTERNS[@]}"; do
    [[ "$PATH_PART" =~ $PAT ]] && MATCH=true && break
  done
  [[ "$MATCH" == false ]] && return

  log_info "  🔍 Probando endpoint sin auth: $FULL_URL" >&2

  local TMP_RESP
  TMP_RESP=$(mktemp /tmp/recon_api_XXXXXX.json)

  local STATUS
  STATUS=$(curl -s --max-time 10 --max-redirs 2 \
    -H "Accept: application/json" \
    -H "User-Agent: Mozilla/5.0 (compatible; Hackeadora/1.0)" \
    -o "$TMP_RESP" -w "%{http_code}" \
    "$FULL_URL" 2>/dev/null)

  if [[ "$STATUS" != "200" ]]; then
    rm -f "$TMP_RESP"; return
  fi

  python3 -c "import json; json.load(open('$TMP_RESP'))" 2>/dev/null || {
    rm -f "$TMP_RESP"; return
  }

  local FOUND
  FOUND=$(python3 - "$TMP_RESP" <<'PYEOF' 2>/dev/null
import json, sys
SENSITIVE = ["token","access_token","refresh_token","api_key","secret",
             "password","auth_token","jwt","authenticity_token","csrf_token",
             "session_id","private_key","client_secret","bearer","key"]
found = []
def search(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if any(s in k.lower() for s in SENSITIVE):
                sv = str(v) if v else ""
                if sv and sv.lower() not in ("null","none","","false","true","0"):
                    found.append(f"{k}={sv[:80]}")
            search(v)
    elif isinstance(obj, list):
        for v in obj: search(v)
try:
    search(json.load(open(sys.argv[1])))
except: pass
print("\n".join(found[:10]))
PYEOF
  )

  local BODY_EXCERPT
  BODY_EXCERPT=$(head -c 600 "$TMP_RESP")
  rm -f "$TMP_RESP"

  [[ -z "$FOUND" ]] && {
    log_info "  ℹ️  Endpoint sin auth OK pero sin campos sensibles: $FULL_URL" >&2
    return
  }

  local DETAIL="API endpoint accesible sin autenticación (HTTP $STATUS)
URL: $FULL_URL
Campos sensibles:
$FOUND
Respuesta:
$BODY_EXCERPT"

  log_warn "⚠️  API INFO DISCLOSURE: $FULL_URL" >&2
  log_warn "    Campos: $(echo "$FOUND" | tr '\n' ' ')" >&2

  db_add_finding "$DOMAIN_ID" "api_info_disclosure" "high" \
    "$FULL_URL" "unauthenticated_api" "$DETAIL"

  _telegram_send "⚠️ *API Info Disclosure*
🌐 Dominio: \`${DOMAIN}\`
🎯 URL: \`${FULL_URL}\`
🔓 Accesible sin auth — HTTP ${STATUS}
📋 Campos: \`$(echo "$FOUND" | head -3 | tr '\n' ' ' | cut -c1-200)\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
}

# ── Análisis de un archivo JS ─────────────────────────────────
_analyze_js_file() {
  local JS_URL="$1"
  local DOMAIN_ID="$2"
  local DOMAIN="$3"
  local WORK_DIR="$4"

  local SUBDOMAIN
  SUBDOMAIN=$(echo "$JS_URL" | sed 's|https\?://||;s|/.*||')

  local SAFE_NAME
  SAFE_NAME=$(echo "$JS_URL" | md5sum | cut -d' ' -f1)
  local JS_FILE="$WORK_DIR/${SAFE_NAME}.js"
  local EP_RAW="$WORK_DIR/${SAFE_NAME}.ep.txt"

  if ! curl -sL --max-time 15 --max-filesize 5000000 \
       -A "Mozilla/5.0 (compatible; Hackeadora/1.0)" \
       -o "$JS_FILE" "$JS_URL" 2>/dev/null; then
    return
  fi
  [[ ! -s "$JS_FILE" ]] && return

  local SIZE SHA
  SIZE=$(wc -c < "$JS_FILE" | tr -d ' ')
  SHA=$(sha256sum "$JS_FILE" | cut -d' ' -f1)

  local JS_FILE_ID
  JS_FILE_ID=$(db_upsert_js_file "$DOMAIN_ID" "$JS_URL" "$SUBDOMAIN" "$SIZE" "$SHA" 0 0)
  [[ -z "$JS_FILE_ID" ]] && JS_FILE_ID=0

  local SECRET_COUNT=0
  local EP_COUNT=0

  # ── SECRETS ───────────────────────────────────────────────
  for PATTERN_DEF in "${SECRET_PATTERNS[@]}"; do
    local STYPE="${PATTERN_DEF%%|*}"
    local REGEX="${PATTERN_DEF#*|}"

    while IFS=: read -r LINENUM MATCH; do
      [[ -z "$MATCH" ]] && continue
      local CONTEXT
      CONTEXT=$(sed -n "${LINENUM}p" "$JS_FILE" 2>/dev/null | cut -c1-200 | tr "'" '"')
      _is_likely_false_positive "$MATCH" "$CONTEXT" && continue

      local MASKED
      MASKED=$(_mask_secret "$MATCH")

      local IS_NEW
      IS_NEW=$(db_add_js_secret \
        "$DOMAIN_ID" "$JS_FILE_ID" "$JS_URL" \
        "$STYPE" "$MASKED" "$MATCH" \
        "$LINENUM" "$CONTEXT" "high")

      if [[ "$IS_NEW" == "1" ]]; then
        ((SECRET_COUNT++))
        log_warn "🔑 SECRET [$STYPE] en $JS_URL (línea $LINENUM): $MASKED" >&2
        _telegram_send "🔑 *JS Secret encontrado*
🌐 Dominio: \`${DOMAIN}\`
📄 Archivo: \`${JS_URL}\`
🏷️ Tipo: \`${STYPE}\`
🔍 Valor: \`${MASKED}\`
📍 Línea: ${LINENUM}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
        db_add_finding "$DOMAIN_ID" "js_secret" "high" \
          "$JS_URL" "$STYPE" "Tipo: $STYPE | Línea: $LINENUM | Valor: $MASKED
Archivo: $JS_URL
Contexto: $CONTEXT"
      fi
    done < <(grep -Pn "$REGEX" "$JS_FILE" 2>/dev/null | head -20 || true)
  done

  # ── ENDPOINTS — único paso Python ─────────────────────────
  local BASE_ORIGIN
  BASE_ORIGIN=$(echo "$JS_URL" | grep -oP 'https?://[^/]+')

  _extract_endpoints_py "$JS_FILE" "$BASE_ORIGIN" "$DOMAIN" > "$EP_RAW" 2>/dev/null || true

  if [[ -s "$EP_RAW" ]]; then
    local _FILE_EP_CAP=0
    while IFS=$'\t' read -r EP FULL_URL METHOD; do
      [[ -z "$EP" ]] && continue

      # Cap: no insertar más de 500 endpoints únicos por archivo JS
      [[ $_FILE_EP_CAP -ge 500 ]] && break

      # Strip query string and fragment from endpoint path before inserting
      EP=$(echo "$EP" | sed 's/?.*//;s/#.*//')
      [[ -z "$EP" || "$EP" == "/" ]] && continue
      if [[ -n "$FULL_URL" ]]; then
        FULL_URL=$(echo "$FULL_URL" | sed 's/?.*//;s/#.*//')
      fi

      local IS_NEW
      IS_NEW=$(db_add_js_endpoint \
        "$DOMAIN_ID" "$JS_FILE_ID" "$JS_URL" \
        "$EP" "$FULL_URL" "$METHOD" "")

      if [[ "$IS_NEW" == "1" ]]; then
        ((_FILE_EP_CAP++))
        ((EP_COUNT++))
        log_info "  ↳ $EP${FULL_URL:+ → $FULL_URL}" >&2
        if [[ -n "$FULL_URL" ]]; then
          db_add_url "$DOMAIN_ID" "$FULL_URL" "js_analyzer" ""
        fi
      fi
    done < "$EP_RAW"
  fi
  rm -f "$EP_RAW"

  sqlite3 -init "$_SQLITE_INIT" "$DB_PATH" \
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

  # ── JS únicos: desde urls_raw.txt + DB (sin re-lanzar katana/gau) ──
  local JS_LIST="$OUT_DIR/.js_list.txt"
  > "$JS_LIST"

  # 1. JS en las URLs crawleadas por módulo 05
  if [[ -s "$URLS_RAW" ]]; then
    grep -iP '\.js(\?[^"]*)?$' "$URLS_RAW" >> "$JS_LIST" 2>/dev/null || true
  fi

  # 2. JS en la DB (otros módulos pueden haberlos añadido)
  sqlite3 -init "$_SQLITE_INIT" "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND url GLOB '*.js'
        OR (domain_id=${DOMAIN_ID} AND url GLOB '*.js?*');" \
    2>/dev/null >> "$JS_LIST" || true

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

  # ── Procesar JS en paralelo (MAX_PARALLEL workers) ────────
  # Default bumped 8→16 (Performance fix 2026-05-09). 25 min / 99 hosts → ~5 min con 16 workers.
  local MAX_PARALLEL="${JS_PARALLEL:-16}"
  local COUNT_DIR="$WORK_DIR/.counts"
  mkdir -p "$COUNT_DIR"
  local ACTIVE=0

  while IFS= read -r JS_URL; do
    [[ -z "$JS_URL" ]] && continue
    ((ANALYZED++))
    [[ $(( ANALYZED % 50 )) -eq 0 ]] && log_info "[$ANALYZED/$TOTAL_JS] procesando..."

    local SAFE
    SAFE=$(echo "$JS_URL" | md5sum | cut -d' ' -f1)
    local RESULT_FILE="$COUNT_DIR/${SAFE}.result"

    (
      R=$(_analyze_js_file "$JS_URL" "$DOMAIN_ID" "$DOMAIN" "$WORK_DIR")
      echo "${R:-0 0}" > "$RESULT_FILE"
    ) &
    (( ++ACTIVE ))

    # Throttle: cuando llegamos al límite, esperar a que UN job termine (no a TODOS)
    while (( ACTIVE >= MAX_PARALLEL )); do
      wait -n 2>/dev/null && (( --ACTIVE )) || break
    done
  done < "$JS_LIST"

  # Esperar jobs restantes
  wait 2>/dev/null || true

  # Recopilar contadores de archivos de resultado
  while IFS= read -r -d '' RFILE; do
    local S EP
    read -r S EP < "$RFILE" 2>/dev/null || continue
    (( TOTAL_SECRETS   += ${S:-0}  ))
    (( TOTAL_ENDPOINTS += ${EP:-0} ))
  done < <(find "$COUNT_DIR" -name '*.result' -print0 2>/dev/null)
  rm -rf "$COUNT_DIR"

  # ── Probe HTTP de endpoints sensibles (batch al final) ────
  log_info "Probando endpoints sensibles sin autenticación..."
  sqlite3 -init "$_SQLITE_INIT" "$DB_PATH" \
    "SELECT DISTINCT full_url FROM js_endpoints
     WHERE domain_id=${DOMAIN_ID} AND full_url != ''
     LIMIT 500;" \
    2>/dev/null \
  | while IFS= read -r URL; do
      [[ -z "$URL" ]] && continue
      _probe_api_endpoint "$URL" "$DOMAIN_ID" "$DOMAIN"
    done

  db_mark_js_endpoints_queued "$DOMAIN_ID"

  rm -rf "$WORK_DIR" "$JS_LIST"

  log_ok "$MODULE_DESC completado:"
  log_ok "  → $ANALYZED JS analizados"
  log_ok "  → $TOTAL_SECRETS secrets encontrados"
  log_ok "  → $TOTAL_ENDPOINTS endpoints extraídos"

  if [[ "$TOTAL_SECRETS" -gt 0 ]]; then
    _telegram_send "📊 *JS Analysis — Resumen*
🌐 \`${DOMAIN}\`
📄 JS analizados: ${ANALYZED}
🔑 Secrets: ${TOTAL_SECRETS}
🔗 Endpoints nuevos: ${TOTAL_ENDPOINTS}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi
}
