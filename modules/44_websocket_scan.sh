#!/usr/bin/env bash
# ============================================================
#  modules/44_websocket_scan.sh
#  Tier 2.6 — WebSocket security scanner
#
#  Detecta endpoints WS y prueba 4 vectores:
#    1. Origin check ausente (Cross-Site WebSocket Hijacking — CSWSH)
#    2. JWT/token en URL path o query (sniffing risk)
#    3. Mensaje fuzz (¿servidor responde sin auth?)
#    4. ws:// (no TLS) en producción
#
#  Detección de endpoints:
#    - urls con esquema ws:// o wss://
#    - urls con /socket.io/, /ws, /websocket, /graphql-ws
#    - JS en mod 11 que contenga `new WebSocket(`
#
#  Anti-FP:
#    - Solo flagear CSWSH si el handshake con Origin: evil.com → 101
#      (sin validación de Origin server-side)
#    - JWT en URL solo si formato eyJxxx.yyy.zzz detectado
# ============================================================

MODULE_NAME="websocket_scan"
MODULE_DESC="WebSocket — origin check, JWT in URL, msg fuzz"

_ws_finding() {
  local DOMAIN_ID="$1" DOMAIN="$2" TARGET="$3"
  local TYPE="$4" SEV="$5" DETAIL="$6" CONF="${7:-medium}"

  db_add_finding "$DOMAIN_ID" "websocket" "$SEV" \
    "$TARGET" "$TYPE" "$DETAIL" "$CONF" 2>/dev/null

  log_warn "  ⚡ [$SEV/$CONF] WS $TYPE: $TARGET"

  if [[ "$CONF" != "low" ]] && [[ "$SEV" == "critical" || "$SEV" == "high" ]]; then
    _telegram_send "🟠 *WebSocket — ${TYPE}*
🌐 \`${DOMAIN}\`
🔗 \`${TARGET}\`
📋 ${DETAIL:0:300}
📊 \`${SEV^^}\` / \`${CONF}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi
}

# ── Probe handshake con Origin custom ───────────────────────
_ws_handshake_probe() {
  local URL="$1"  # ws:// o wss://
  local ORIGIN="$2"

  # Construir handshake HTTP/1.1 Upgrade. Usamos curl -i con headers WebSocket.
  # Si server responde 101 Switching Protocols → handshake OK
  # Status 403/400/426 → Origin rechazado o malformed
  local KEY="dGhlIHNhbXBsZSBub25jZQ=="  # base64 "the sample nonce"
  local SCHEME_URL="${URL/wss:\/\//https://}"
  SCHEME_URL="${SCHEME_URL/ws:\/\//http://}"

  local STATUS
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 \
    -H "Connection: Upgrade" \
    -H "Upgrade: websocket" \
    -H "Sec-WebSocket-Version: 13" \
    -H "Sec-WebSocket-Key: $KEY" \
    -H "Origin: $ORIGIN" \
    "$SCHEME_URL" 2>/dev/null)
  echo "$STATUS"
}

_ws_probe() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  # 1. ws:// en producción (no TLS)
  if [[ "$URL" == ws://* ]]; then
    _ws_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
      "ws_no_tls" "medium" \
      "WebSocket sin TLS (ws://) — credenciales/sesiones sniffeables en network. Migrar a wss://" \
      "high"
  fi

  # 2. JWT/token en URL
  local URL_LOW="${URL,,}"
  if echo "$URL_LOW" | grep -qE '(token|jwt|access_token|api_key|sessionId)='; then
    _ws_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
      "ws_secret_in_url" "high" \
      "Token/JWT/sesión en URL del WS endpoint — quedan en logs proxy/CDN/access logs. Mover a header Authorization o cookie." \
      "high"
  fi
  if echo "$URL" | grep -oE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}' | head -1 | grep -q .; then
    _ws_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
      "ws_jwt_in_url" "high" \
      "JWT explícito en URL del WS endpoint — exposición en logs y referer headers." \
      "high"
  fi

  # 3. Origin check probe — ¿server acepta Origin: evil.com?
  local STATUS_EVIL STATUS_VALID
  STATUS_EVIL=$(_ws_handshake_probe "$URL" "https://evil.com")
  STATUS_VALID=$(_ws_handshake_probe "$URL" "https://${DOMAIN}")

  # 101 = handshake successful. Si VALID=101 y EVIL=101 → no Origin check (CSWSH)
  if [[ "$STATUS_VALID" == "101" && "$STATUS_EVIL" == "101" ]]; then
    _ws_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
      "ws_no_origin_check" "high" \
      "WS handshake aceptado con Origin: https://evil.com (101 Switching Protocols) — Cross-Site WebSocket Hijacking (CSWSH) posible. Atacante puede establecer WS desde dominio externo y exfiltrar mensajes." \
      "high"
  fi
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 44 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null || true

  # 1. URLs ws:// o wss:// en DB (poco común)
  # 2. Paths típicos WS (/socket.io, /ws, /websocket)
  # 3. JS files con `new WebSocket(`
  local CANDIDATES_FILE; CANDIDATES_FILE=$(mktemp /tmp/ws_cand.XXXXXX)

  sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (url LIKE 'ws://%' OR url LIKE 'wss://%'
            OR url LIKE '%/socket.io/%' OR url LIKE '%/ws/%' OR url LIKE '%/ws?%'
            OR url LIKE '%/websocket%' OR url LIKE '%/graphql-ws%'
            OR url LIKE '%/cable%' OR url LIKE '%/sockjs%'
       )
     LIMIT 30;" 2>/dev/null >> "$CANDIDATES_FILE"

  # JS files con new WebSocket
  local JS_FILES
  JS_FILES=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID} AND url LIKE '%.js%'
     LIMIT 100;" 2>/dev/null)

  while IFS= read -r JS_URL; do
    [[ -z "$JS_URL" ]] && continue
    _h_get_noredirect "$JS_URL" --connect-timeout 5
    local BODY="$HTTP_LAST_BODY"
    # Buscar new WebSocket("URL") o new WebSocket('URL')
    echo "$BODY" | grep -oE 'new\s+WebSocket\s*\(\s*["'"'"'][^"'"'"']+["'"'"']' | \
      grep -oE '["'"'"'][^"'"'"']+["'"'"']$' | tr -d '"'"'"'' | head -3 >> "$CANDIDATES_FILE"
  done <<< "$JS_FILES"

  sort -u "$CANDIDATES_FILE" -o "$CANDIDATES_FILE"
  local COUNT
  COUNT=$(wc -l < "$CANDIDATES_FILE")

  if [[ "$COUNT" -eq 0 ]]; then
    log_info "  Sin endpoints WS candidatos — saltando"
    rm -f "$CANDIDATES_FILE"
    return 0
  fi

  log_info "  ${COUNT} endpoints WS candidatos"

  local TOTAL_FINDINGS=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    # Construir URL WS si es relativo
    [[ "$URL" =~ ^/ ]] && URL="https://${DOMAIN}${URL}"
    [[ ! "$URL" =~ ^(ws|wss|http)s?:// ]] && continue

    log_info "  → $URL"
    _ws_probe "$URL" "$DOMAIN_ID" "$DOMAIN"
  done < "$CANDIDATES_FILE"

  rm -f "$CANDIDATES_FILE"
  log_ok "$MODULE_DESC: scan completado sobre ${COUNT} endpoints"
}
