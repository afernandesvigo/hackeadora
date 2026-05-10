#!/usr/bin/env bash
# ============================================================
#  modules/41_auth_replay.sh
#  Tier 2.3 — Auth-state IDOR/bypass replay
#
#  Dos fases:
#    B (default): No-cookie replay — re-pedir URLs con shape de "user data"
#                 (/me, /profile, /account, /users/{id}, etc.) sin cookie.
#                 Si responde 200 + body con PII → auth bypass (high).
#
#    A (opt-in):  Cookie A/B swap — si env IDOR_COOKIE_A e IDOR_COOKIE_B están
#                 setteados, repetir URL con cada cookie. Si bodies divergen
#                 pero ambos contienen PII → IDOR cruzado (critical).
#
#  Anti-FP:
#    - Skip catch-all hosts (is_catchall_host)
#    - Skip URLs que ya devuelven 401/403 sin cookie en mod 05 crawler
#    - Body validation con `has_pii_shape` (no flagear sin PII real)
#    - Excluir /static/, /assets/, .css, .js, .png
# ============================================================

MODULE_NAME="auth_replay"
MODULE_DESC="Auth replay — no-cookie bypass (B) + cookie A/B IDOR (A, opt-in)"

# ── Helpers ─────────────────────────────────────────────────
_ar_finding() {
  local DOMAIN_ID="$1" DOMAIN="$2" TARGET="$3"
  local TYPE="$4" SEV="$5" DETAIL="$6" CONF="${7:-medium}"

  db_add_finding "$DOMAIN_ID" "auth_replay" "$SEV" \
    "$TARGET" "$TYPE" "$DETAIL" "$CONF" 2>/dev/null

  local EMOJI="🟠"
  [[ "$SEV" == "critical" ]] && EMOJI="🔴"
  [[ "$SEV" == "medium"   ]] && EMOJI="🟡"

  log_warn "  ⚡ [$SEV/$CONF] auth_replay $TYPE: $TARGET"

  if [[ "$CONF" != "low" ]] && [[ "$SEV" == "critical" || "$SEV" == "high" ]]; then
    _telegram_send "${EMOJI} *Auth Replay — ${TYPE}*
🌐 \`${DOMAIN}\`
🔗 \`${TARGET}\`
📋 ${DETAIL:0:300}
📊 Severity: \`${SEV^^}\` | Confidence: \`${CONF}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi
}

# ── Phase B: no-cookie replay ───────────────────────────────
# Lógica: petición SIN ninguna cookie a una URL que tiene shape user-data.
# Si responde 200 con PII en body → auth bypass.
_replay_no_cookie() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  # Skip URLs estáticas (no son endpoints sensibles)
  if echo "$URL" | grep -qiE '\.(css|js|png|jpg|gif|svg|ico|woff|ttf|map|json)(\?|$)'; then
    return 1
  fi

  # Pedir SIN cookie. _h_get usa el SCAN_UA pero no envía cookies por default.
  # Para asegurar, pasamos -b "" para vaciar cookie jar local.
  _h_get_noredirect "$URL" --connect-timeout 8 -b ""

  local STATUS="$HTTP_LAST_STATUS"
  [[ "$STATUS" != "200" ]] && return 1

  local BODY="${HTTP_LAST_BODY:0:8000}"
  [[ -z "$BODY" || ${#BODY} -lt 50 ]] && return 1

  # Validar PII shape — sin esto el match es FP
  if ! has_pii_shape "$BODY"; then
    return 1
  fi

  # Catch-all guard: si todos los hosts del dominio responden igual sin cookie,
  # podría ser un fallback común (e.g. CDN error con datos genéricos)
  local HOST_BASE
  HOST_BASE=$(echo "$URL" | grep -oP 'https?://[^/]+')
  if is_catchall_host "$HOST_BASE" 2>/dev/null; then
    return 1
  fi

  # Sample del PII detectado (para context)
  local PII_SAMPLE
  PII_SAMPLE=$(echo "$BODY" | grep -oE '"[a-zA-Z]+":\s*"[a-zA-Z0-9._+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"' | head -2 | tr '\n' '|' | head -c 200)
  [[ -z "$PII_SAMPLE" ]] && PII_SAMPLE=$(echo "$BODY" | grep -oE '"(phone|ssn|dni|birthDate)":\s*"[^"]+"' | head -2 | tr '\n' '|' | head -c 200)

  _ar_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
    "no_cookie_pii_disclosure" "high" \
    "Endpoint devuelve PII a request sin cookie/auth — auth bypass. PII detectada: ${PII_SAMPLE} | body size: ${#BODY}B" \
    "high"
  return 0
}

# ── Phase A: cookie A/B swap (opt-in) ───────────────────────
# Solo se activa si IDOR_COOKIE_A e IDOR_COOKIE_B están setteados.
# Lógica: pedir URL con cookie A → record body. Pedir mismo URL con cookie B
# → si body difiere significativamente Y ambos contienen PII → IDOR cruzado.
_replay_cookie_swap() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  # Skip estáticas
  if echo "$URL" | grep -qiE '\.(css|js|png|jpg|gif|svg|ico|woff|ttf|map)(\?|$)'; then
    return 1
  fi

  # Cookie A
  _h_get_noredirect "$URL" --connect-timeout 8 \
    -H "Cookie: ${IDOR_COOKIE_A}"
  local STATUS_A="$HTTP_LAST_STATUS"
  local BODY_A="${HTTP_LAST_BODY:0:8000}"

  [[ "$STATUS_A" != "200" ]] && return 1
  [[ -z "$BODY_A" || ${#BODY_A} -lt 50 ]] && return 1
  has_pii_shape "$BODY_A" || return 1

  # Cookie B
  _h_get_noredirect "$URL" --connect-timeout 8 \
    -H "Cookie: ${IDOR_COOKIE_B}"
  local STATUS_B="$HTTP_LAST_STATUS"
  local BODY_B="${HTTP_LAST_BODY:0:8000}"

  [[ "$STATUS_B" != "200" ]] && return 1
  [[ -z "$BODY_B" ]] && return 1

  # Si body B contiene PII de A → CONFIRMED IDOR (datos del user A leakean al B)
  # Detección: extraer email/phone/ssn de A, buscar en B
  local PII_A
  PII_A=$(echo "$BODY_A" | grep -oE '"[a-zA-Z]+":\s*"[a-zA-Z0-9._+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"' | head -3)
  [[ -z "$PII_A" ]] && PII_A=$(echo "$BODY_A" | grep -oE '"(phone|ssn|dni)":\s*"[^"]+"' | head -3)

  if [[ -n "$PII_A" ]]; then
    local LEAK=false
    while IFS= read -r ITEM; do
      [[ -z "$ITEM" ]] && continue
      # Extraer el valor (entre las últimas comillas)
      local VAL
      VAL=$(echo "$ITEM" | grep -oE '"[^"]+"$' | tr -d '"')
      [[ -z "$VAL" || ${#VAL} -lt 6 ]] && continue
      if echo "$BODY_B" | grep -qF "$VAL"; then
        LEAK=true
        break
      fi
    done <<< "$PII_A"

    if $LEAK; then
      _ar_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
        "idor_cross_user_pii_leak" "critical" \
        "PII del usuario A se devuelve cuando se autentica con cookie B → IDOR cruzado confirmado. Sample leaked: ${PII_A:0:200}" \
        "high"
      return 0
    fi
  fi
  return 1
}

# ── Main ─────────────────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 41 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null || true

  # URLs candidatas: shape de user-data en path o query
  local CANDIDATES
  CANDIDATES=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (
         url LIKE '%/me%' OR url LIKE '%/profile%' OR url LIKE '%/account%'
         OR url LIKE '%/users/%' OR url LIKE '%/customers/%'
         OR url LIKE '%/api/v1/me%' OR url LIKE '%/api/me%'
         OR url LIKE '%/userInfo%' OR url LIKE '%/whoami%'
         OR url LIKE '%user_id=%' OR url LIKE '%customer_id=%'
         OR url LIKE '%accountId=%' OR url LIKE '%/orders/%'
       )
       AND url NOT LIKE '%.css%' AND url NOT LIKE '%.js%'
       AND url NOT LIKE '%.png%' AND url NOT LIKE '%.jpg%'
       AND url NOT LIKE '%.svg%' AND url NOT LIKE '%.ico%'
     LIMIT 100;" 2>/dev/null | sort -u)

  if [[ -z "$CANDIDATES" ]]; then
    log_info "  Sin URLs candidatas (no /me, /profile, /users/, etc. en DB)"
    return 0
  fi

  local COUNT
  COUNT=$(echo "$CANDIDATES" | grep -c .)
  log_info "  ${COUNT} URLs candidatas para auth replay"

  local HAS_COOKIES=false
  if [[ -n "${IDOR_COOKIE_A:-}" ]] && [[ -n "${IDOR_COOKIE_B:-}" ]]; then
    HAS_COOKIES=true
    log_info "  Modo A activo (IDOR_COOKIE_A/B detectadas)"
  else
    log_info "  Modo A inactivo (set IDOR_COOKIE_A e IDOR_COOKIE_B para activar IDOR cruzado)"
  fi

  local TOTAL_FINDINGS=0 PROCESSED=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    ((PROCESSED++))
    [[ $((PROCESSED % 20)) -eq 0 ]] && log_info "  [$PROCESSED/$COUNT] procesando..."

    _replay_no_cookie "$URL" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL_FINDINGS++))
    if $HAS_COOKIES; then
      _replay_cookie_swap "$URL" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL_FINDINGS++))
    fi
  done <<< "$CANDIDATES"

  log_ok "$MODULE_DESC: ${TOTAL_FINDINGS} findings sobre ${PROCESSED} URLs candidatas"
}
