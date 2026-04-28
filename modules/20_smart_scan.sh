#!/usr/bin/env bash
# ============================================================
#  modules/20_smart_scan.sh
#  Fase 20: Smart Scan guiado por Knowledge Base
#
#  Para cada URL/parámetro descubierto, consulta la KB
#  y lanza tests específicos según:
#    - Nombre del parámetro → SSRF, IDOR, Open Redirect...
#    - Ruta del endpoint    → GraphQL, OAuth, Upload...
#    - Tech detectada       → SSTI según framework, SQLi según DB
#    - Respuesta HTTP       → headers CORS, cache, etc.
#
#  Basado en:
#    - HackerOne Top Reports (frecuencia y bounty real)
#    - PayloadsAllTheThings (payloads actualizados)
#    - HackTricks (metodología de detección)
#    - HowToHunt (patrones de parámetros)
# ============================================================

MODULE_NAME="smart_scan"
MODULE_DESC="Smart Scan guiado por Knowledge Base"

KB_PATH="$(dirname "$0")/../core/knowledge_base.json"

# ── Cargar KB ────────────────────────────────────────────────
_kb_get_vuln() {
  local VULN_ID="$1"
  python3 -c "
import json, sys
kb = json.load(open('${KB_PATH}'))
for v in kb['vulnerabilities']:
    if v['id'] == '${VULN_ID}':
        print(json.dumps(v))
        sys.exit(0)
" 2>/dev/null
}

_kb_match_param() {
  # Devuelve lista de vuln_ids que matchean este parámetro
  local PARAM="$1"
  python3 -c "
import json
kb = json.load(open('${KB_PATH}'))
matches = []
for v in kb['vulnerabilities']:
    params = v.get('trigger_params', [])
    if '${PARAM}'.lower() in [p.lower() for p in params]:
        matches.append(v['id'])
print(' '.join(matches))
" 2>/dev/null
}

_kb_match_path() {
  local PATH_="$1"
  python3 -c "
import json
kb = json.load(open('${KB_PATH}'))
matches = []
for v in kb['vulnerabilities']:
    paths = v.get('trigger_paths', [])
    for p in paths:
        if p.lower() in '${PATH_}'.lower():
            if v['id'] not in matches:
                matches.append(v['id'])
print(' '.join(matches))
" 2>/dev/null
}

_kb_match_tech() {
  local TECH="$1"
  python3 -c "
import json
kb = json.load(open('${KB_PATH}'))
matches = []
for v in kb['vulnerabilities']:
    techs = v.get('trigger_techs', [])
    if 'any' in techs or '${TECH}' in techs:
        matches.append(v['id'])
print(' '.join(matches))
" 2>/dev/null
}

_kb_get_payloads() {
  local VULN_ID="$1"
  python3 -c "
import json
kb = json.load(open('${KB_PATH}'))
for v in kb['vulnerabilities']:
    if v['id'] == '${VULN_ID}':
        for p in v.get('payloads', [])[:5]:
            print(p)
        break
" 2>/dev/null
}

_kb_get_nuclei_tags() {
  local VULN_ID="$1"
  python3 -c "
import json
kb = json.load(open('${KB_PATH}'))
for v in kb['vulnerabilities']:
    if v['id'] == '${VULN_ID}':
        print(','.join(v.get('nuclei_tags', [])))
        break
" 2>/dev/null
}

# ── Tests por tipo de vuln ────────────────────────────────────

_test_ssrf() {
  local URL="$1" PARAM="$2" DOMAIN_ID="$3" DOMAIN="$4"
  log_info "  🔍 SSRF test: $URL?$PARAM"

  # Usar Interactsh o nuestro propio callback si está configurado
  local CALLBACK="${SSRF_CALLBACK:-http://169.254.169.254}"

  # Test básico con nuclei
  if command -v nuclei &>/dev/null; then
    local NUCLEI_OUT
    NUCLEI_OUT=$(nuclei -u "${URL}?${PARAM}=${CALLBACK}" \
      -tags ssrf,oob -silent -json 2>/dev/null | head -5)
    if [[ -n "$NUCLEI_OUT" ]]; then
      log_warn "  ⚡ SSRF finding: $URL"
      echo "$NUCLEI_OUT" | while IFS= read -r LINE; do
        local TEMPLATE SEV
        TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
        SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','?'))" 2>/dev/null)
        notify_nuclei_finding "$DOMAIN" "$TEMPLATE" "$SEV" "$URL" "SSRF via param $PARAM"
        db_add_finding "$DOMAIN_ID" "smart_ssrf" "$SEV" "$URL" "$TEMPLATE" "Param: $PARAM"
      done
    fi
  fi
}

_test_idor() {
  local URL="$1" PARAM="$2" VALUE="$3" DOMAIN_ID="$4" DOMAIN="$5"
  log_info "  🔍 IDOR test: $URL ($PARAM=$VALUE)"

  # Intentar valores adyacentes
  local ORIG_VAL="$VALUE"
  local TEST_VALS=()

  if echo "$VALUE" | grep -qP '^\d+$'; then
    # ID numérico — probar +1 y -1
    TEST_VALS=( $((VALUE + 1)) $((VALUE - 1)) 1 2 3 100 )
  else
    # UUID o string — probar modificaciones básicas
    TEST_VALS=( "1" "2" "admin" "0" "null" )
  fi

  # Obtener respuesta original para comparar
  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  local ORIG_RESPONSE ORIG_LEN ORIG_STATUS
  ORIG_RESPONSE=$(curl -sL --max-time 10 ${CURL_PROXY} \
    -w "\n###STATUS###%{http_code}" "${URL}?${PARAM}=${ORIG_VAL}" 2>/dev/null)
  ORIG_STATUS=$(echo "$ORIG_RESPONSE" | grep -oP '(?<=###STATUS###)\d+' | tail -1)
  ORIG_LEN=${#ORIG_RESPONSE}

  for TEST_VAL in "${TEST_VALS[@]}"; do
    [[ "$TEST_VAL" == "$ORIG_VAL" ]] && continue

    local TEST_RESPONSE TEST_STATUS TEST_LEN
    TEST_RESPONSE=$(curl -sL --max-time 10 ${CURL_PROXY} \
      -w "\n###STATUS###%{http_code}" "${URL}?${PARAM}=${TEST_VAL}" 2>/dev/null)
    TEST_STATUS=$(echo "$TEST_RESPONSE" | grep -oP '(?<=###STATUS###)\d+' | tail -1)
    TEST_LEN=${#TEST_RESPONSE}

    # Posible IDOR si:
    # - Respuesta 200 con contenido diferente al original
    # - Respuesta similar en tamaño (mismo endpoint, datos distintos)
    if [[ "$TEST_STATUS" == "200" ]] && \
       [[ "$ORIG_STATUS" == "200" ]] && \
       [[ "$TEST_LEN" -gt 100 ]] && \
       [[ "$TEST_LEN" != "$ORIG_LEN" ]]; then
      log_warn "  ⚡ Posible IDOR: $URL?$PARAM=$TEST_VAL (len=$TEST_LEN vs orig=$ORIG_LEN)"
      _telegram_send "🎯 *Posible IDOR detectado*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📝 Param: \`${PARAM}\` (${ORIG_VAL} → ${TEST_VAL})
📊 Response: ${TEST_LEN} bytes (original: ${ORIG_LEN})
⚠️ Verificar manualmente
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
      db_add_finding "$DOMAIN_ID" "smart_idor" "medium" \
        "$URL" "idor_param_swap" "Param $PARAM: $ORIG_VAL → $TEST_VAL (diff len)"
    fi
  done
}

_test_open_redirect() {
  local URL="$1" PARAM="$2" DOMAIN_ID="$3" DOMAIN="$4"
  log_info "  🔍 Open Redirect test: $URL?$PARAM"

  local PAYLOADS=(
    "https://evil.com"
    "//evil.com"
    "/\\evil.com"
    "https://evil.com%23.${DOMAIN}"
  )

  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  for PAYLOAD in "${PAYLOADS[@]}"; do
    local RESPONSE STATUS LOCATION
    RESPONSE=$(curl -s --max-time 8 \
      -o /dev/null \
      -w "%{http_code}|%{redirect_url}" \
      ${CURL_PROXY} \
      "${URL}?${PARAM}=${PAYLOAD}" 2>/dev/null)
    STATUS=$(echo "$RESPONSE" | cut -d'|' -f1)
    LOCATION=$(echo "$RESPONSE" | cut -d'|' -f2)

    if [[ "$STATUS" =~ ^(301|302|303|307|308)$ ]] && \
       echo "$LOCATION" | grep -qi "evil.com"; then
      log_warn "  ⚡ Open Redirect confirmado: $URL?$PARAM=$PAYLOAD → $LOCATION"
      _telegram_send "↪️ *Open Redirect confirmado*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📝 Payload: \`${PAYLOAD}\`
🎯 Redirige a: \`${LOCATION}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
      db_add_finding "$DOMAIN_ID" "smart_redirect" "medium" \
        "$URL" "open_redirect" "Param $PARAM redirect to evil.com"
      break
    fi
  done
}

_test_ssti() {
  local URL="$1" PARAM="$2" DOMAIN_ID="$3" DOMAIN="$4"
  log_info "  🔍 SSTI test: $URL?$PARAM"

  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  local PAYLOADS=(
    "{{7*7}}"
    "\${7*7}"
    "#{7*7}"
    "{{7*'7'}}"
    "<%= 7*7 %>"
  )
  local EXPECTED="49"

  for PAYLOAD in "${PAYLOADS[@]}"; do
    local ENCODED
    ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${PAYLOAD}'))" 2>/dev/null || echo "$PAYLOAD")
    local BODY
    BODY=$(curl -sL --max-time 8 ${CURL_PROXY} \
      "${URL}?${PARAM}=${ENCODED}" 2>/dev/null)

    if echo "$BODY" | grep -q "$EXPECTED"; then
      log_warn "  ⚡ SSTI confirmado ($PAYLOAD → $EXPECTED): $URL"
      _telegram_send "🚨 *SSTI confirmado*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📝 Payload: \`${PAYLOAD}\` → \`${EXPECTED}\`
⚠️ Potencial RCE — revisar urgente
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
      db_add_finding "$DOMAIN_ID" "smart_ssti" "critical" \
        "$URL" "ssti" "Payload $PAYLOAD evaluó a $EXPECTED"
      break
    fi
  done
}

_test_cors() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  local ACAO
  ACAO=$(curl -sI --max-time 8 \
    -H "Origin: https://evil.com" \
    ${CURL_PROXY} "$URL" 2>/dev/null | grep -i "Access-Control-Allow-Origin")

  if echo "$ACAO" | grep -qi "evil.com\|\*"; then
    local ACAC
    ACAC=$(curl -sI --max-time 8 \
      -H "Origin: https://evil.com" \
      ${CURL_PROXY} "$URL" 2>/dev/null | grep -i "Access-Control-Allow-Credentials")

    local SEV="low"
    echo "$ACAC" | grep -qi "true" && SEV="high"

    log_warn "  ⚡ CORS misconfig [$SEV]: $URL"
    _telegram_send "🌐 *CORS Misconfiguration*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📊 ${ACAO}
${ACAC:+🔑 ${ACAC}}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
    db_add_finding "$DOMAIN_ID" "smart_cors" "$SEV" \
      "$URL" "cors" "$ACAO"
  fi
}

_test_nuclei_by_tags() {
  local URL="$1" TAGS="$2" DOMAIN_ID="$3" DOMAIN="$4"
  [[ -z "$TAGS" ]] && return
  [[ -z "$URL" ]] && return

  if ! command -v nuclei &>/dev/null; then return; fi

  log_info "  🔍 Nuclei [$TAGS]: $URL"
  local SEVERITY="${NUCLEI_SEVERITY:-medium,high,critical}"
  local PROXY_FLAG=""
  $PROXY_ACTIVE && PROXY_FLAG="-proxy ${PROXY_URL}"

  nuclei \
    -u "$URL" \
    -tags "$TAGS" \
    -severity "$SEVERITY" \
    -silent -json \
    ${PROXY_FLAG} \
    2>/dev/null \
  | while IFS= read -r LINE; do
    [[ -z "$LINE" ]] && continue
    local TEMPLATE SEV HOST
    TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
    SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','?'))" 2>/dev/null)
    HOST=$(echo "$LINE"     | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('matched-at',d.get('host','?')))" 2>/dev/null)
    log_warn "  ⚡ [$SEV] $TEMPLATE @ $HOST"
    notify_nuclei_finding "$DOMAIN" "$TEMPLATE" "$SEV" "$HOST" "Smart scan KB"
    db_add_finding "$DOMAIN_ID" "smart_nuclei" "$SEV" "$HOST" "$TEMPLATE" "Smart KB tags: $TAGS"
  done
}

# ── Función principal ─────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 20 — $MODULE_DESC: $DOMAIN"

  if [[ ! -f "$KB_PATH" ]]; then
    log_warn "knowledge_base.json no encontrada en $KB_PATH"
    return
  fi

  # Proxy
  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  proxy_check

  # Rotador de IPs — ghauri/dalfox usan IP nueva por ejecución
  source "$(dirname "$0")/../core/rotator.sh" 2>/dev/null || true

  local TOTAL_TESTS=0
  local TOTAL_FINDINGS=0

  # ── Obtener URLs con parámetros de la DB ───────────────────
  local PARAM_URLS
  PARAM_URLS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT u.url || '|' || p.param_name
     FROM url_params p
     JOIN urls u ON u.url LIKE '%' || p.url || '%'
     WHERE p.domain_id=${DOMAIN_ID}
     UNION
     SELECT url || '|' || param_name
     FROM url_params
     WHERE domain_id=${DOMAIN_ID}
     LIMIT 200;" 2>/dev/null)

  # También URLs con ? de la tabla urls
  local URLS_WITH_PARAMS
  URLS_WITH_PARAMS=$(sqlite3 "$DB_PATH" \
    "SELECT url FROM urls
     WHERE domain_id=${DOMAIN_ID} AND url LIKE '%?%'
     ORDER BY first_seen DESC LIMIT 100;" 2>/dev/null)

  log_info "Analizando parámetros con KB..."

  # ── Test por parámetros conocidos ─────────────────────────
  while IFS='|' read -r URL PARAM; do
    [[ -z "$URL" || -z "$PARAM" ]] && continue

    # Consultar KB para este parámetro
    local MATCHES
    MATCHES=$(_kb_match_param "$PARAM")
    [[ -z "$MATCHES" ]] && continue

    log_info "Param '$PARAM' → vulns: $MATCHES"
    ((TOTAL_TESTS++))

    for VULN_ID in $MATCHES; do
      local TAGS
      TAGS=$(_kb_get_nuclei_tags "$VULN_ID")

      case "$VULN_ID" in
        SSRF)          _test_ssrf "$URL" "$PARAM" "$DOMAIN_ID" "$DOMAIN" ;;
        OPEN_REDIRECT) _test_open_redirect "$URL" "$PARAM" "$DOMAIN_ID" "$DOMAIN" ;;
        SSTI)          _test_ssti "$URL" "$PARAM" "$DOMAIN_ID" "$DOMAIN" ;;
        SQLI)
          if command -v ghauri &>/dev/null; then
            log_info "  🔍 ghauri SQLi (IP única): $URL?$PARAM"
            local GHAURI_OUT="$OUT_DIR/.ghauri_$$.txt"
            local GHAURI_CMD="ghauri -u '${URL}?${PARAM}=1' --level 1 --batch --silent 2>/dev/null > ${GHAURI_OUT}"

            # Una IP nueva por cada test SQLi
            if rotator_enabled; then
              rotator_exec "$GHAURI_CMD" "$GHAURI_OUT"
            else
              eval "$GHAURI_CMD"
            fi

            if grep -qi "injectable\|vulnerable" "$GHAURI_OUT" 2>/dev/null; then
              log_warn "  ⚡ SQLi detectado por ghauri: $URL?$PARAM"
              _telegram_send "💉 *SQLi detectado — ghauri*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📝 Param: \`${PARAM}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
              db_add_finding "$DOMAIN_ID" "smart_sqli" "critical" \
                "$URL" "ghauri" "Param $PARAM inyectable (ghauri level 1)"
            fi
            rm -f "$GHAURI_OUT"
          else
            [[ -n "$TAGS" ]] && _test_nuclei_by_tags "$URL" "$TAGS" "$DOMAIN_ID" "$DOMAIN"
          fi
          ;;
        XSS_STORED)
          if command -v dalfox &>/dev/null; then
            log_info "  🔍 dalfox XSS (IP única): $URL?$PARAM"
            local DALFOX_OUT="$OUT_DIR/.dalfox_$$.txt"
            local DALFOX_CMD="dalfox url '${URL}?${PARAM}=test' --silence --only-poc g --skip-mining-dom 2>/dev/null > ${DALFOX_OUT}"

            # IP nueva por cada test XSS
            if rotator_enabled; then
              rotator_exec "$DALFOX_CMD" "$DALFOX_OUT"
            else
              eval "$DALFOX_CMD"
            fi

            if [[ -s "$DALFOX_OUT" ]]; then
              local POC
              POC=$(head -1 "$DALFOX_OUT")
              log_warn "  ⚡ XSS detectado por dalfox: $URL?$PARAM"
              _telegram_send "🔴 *XSS detectado — dalfox*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📝 Param: \`${PARAM}\`
💉 PoC: \`${POC:0:200}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
              db_add_finding "$DOMAIN_ID" "smart_xss" "high" \
                "$URL" "dalfox" "XSS en param $PARAM — PoC: ${POC:0:200}"
            fi
            rm -f "$DALFOX_OUT"
          else
            [[ -n "$TAGS" ]] && _test_nuclei_by_tags "$URL" "$TAGS" "$DOMAIN_ID" "$DOMAIN"
          fi
          ;;
        IDOR)
          # Extraer valor actual del parámetro
          local PARAM_VAL
          PARAM_VAL=$(echo "$URL" | grep -oP "(?<=${PARAM}=)[^&]+" | head -1)
          [[ -n "$PARAM_VAL" ]] && \
            _test_idor "$URL" "$PARAM" "$PARAM_VAL" "$DOMAIN_ID" "$DOMAIN"
          ;;
        *)
          [[ -n "$TAGS" ]] && _test_nuclei_by_tags "$URL" "$TAGS" "$DOMAIN_ID" "$DOMAIN"
          ;;
      esac
    done

  done <<< "$PARAM_URLS"

  # ── Test por rutas de endpoints ────────────────────────────
  log_info "Analizando rutas de endpoints con KB..."

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue

    local PATH_PART
    PATH_PART=$(echo "$URL" | sed 's|https\?://[^/]*||;s|?.*||')

    local PATH_MATCHES
    PATH_MATCHES=$(_kb_match_path "$PATH_PART")
    [[ -z "$PATH_MATCHES" ]] && continue

    ((TOTAL_TESTS++))
    log_info "Path '$PATH_PART' → vulns: $PATH_MATCHES"

    for VULN_ID in $PATH_MATCHES; do
      local TAGS
      TAGS=$(_kb_get_nuclei_tags "$VULN_ID")

      case "$VULN_ID" in
        CORS)
          _test_cors "$URL" "$DOMAIN_ID" "$DOMAIN"
          ;;
        GRAPHQL)
          if command -v nuclei &>/dev/null; then
            _test_nuclei_by_tags "$URL" "graphql,exposure" "$DOMAIN_ID" "$DOMAIN"
          fi
          ;;
        FILE_UPLOAD)
          [[ -n "$TAGS" ]] && _test_nuclei_by_tags "$URL" "$TAGS" "$DOMAIN_ID" "$DOMAIN"
          ;;
        OAUTH_MISCONFIG)
          [[ -n "$TAGS" ]] && _test_nuclei_by_tags "$URL" "$TAGS" "$DOMAIN_ID" "$DOMAIN"
          ;;
        *)
          [[ -n "$TAGS" ]] && _test_nuclei_by_tags "$URL" "$TAGS" "$DOMAIN_ID" "$DOMAIN"
          ;;
      esac
    done

  done <<< "$URLS_WITH_PARAMS"

  # ── Test CORS global sobre subdominios alive ───────────────
  local ALIVE="$OUT_DIR/subs_alive.txt"
  if [[ -s "$ALIVE" ]]; then
    log_info "CORS check sobre subdominios alive..."
    while IFS= read -r SUB; do
      [[ -z "$SUB" ]] && continue
      _test_cors "https://${SUB}" "$DOMAIN_ID" "$DOMAIN"
    done < "$ALIVE"
  fi

  TOTAL_FINDINGS=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID} AND type LIKE 'smart_%';" 2>/dev/null || echo 0)

  log_ok "$MODULE_DESC completado: $TOTAL_TESTS targets analizados, $TOTAL_FINDINGS findings"
}
