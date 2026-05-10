#!/usr/bin/env bash
# ============================================================
#  modules/43_prototype_pollution.sh
#  Tier 2.5 — Prototype Pollution scanner (client-side via query string)
#
#  Detecta apps Node/JS que aceptan keys polluted (__proto__, constructor) en
#  query strings o JSON body. La pollution puede convertirse en RCE/XSS según
#  el sink (HTML render, eval, child_process).
#
#  Vectores:
#    1. Query: ?__proto__[polluted]=hackeadora_canary_<rand>
#    2. Query: ?constructor[prototype][polluted]=hackeadora_canary_<rand>
#    3. JSON body: {"__proto__":{"polluted":"hackeadora_canary"}}
#
#  Detección:
#    - Re-petición a la URL base SIN el payload → buscar el canary en body.
#      Si el canary aparece en el HTML/JS/JSON del response normal,
#      hay pollution real (la app contaminó Object.prototype).
#
#  Anti-FP:
#    - Skip si el canary aparece SIN haber lanzado el payload (baseline)
#    - Skip catch-all hosts
# ============================================================

MODULE_NAME="prototype_pollution"
MODULE_DESC="Prototype pollution — query/JSON params __proto__ + constructor"

_pp_finding() {
  local DOMAIN_ID="$1" DOMAIN="$2" TARGET="$3"
  local TYPE="$4" SEV="$5" DETAIL="$6" CONF="${7:-medium}"

  db_add_finding "$DOMAIN_ID" "prototype_pollution" "$SEV" \
    "$TARGET" "$TYPE" "$DETAIL" "$CONF" 2>/dev/null

  log_warn "  ⚡ [$SEV/$CONF] PP $TYPE: $TARGET"

  if [[ "$CONF" != "low" ]] && [[ "$SEV" == "critical" || "$SEV" == "high" ]]; then
    _telegram_send "🟠 *Prototype Pollution — ${TYPE}*
🌐 \`${DOMAIN}\`
🔗 \`${TARGET}\`
📋 ${DETAIL:0:300}
📊 \`${SEV^^}\` / \`${CONF}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi
}

_pp_probe() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  # Skip estáticas
  if echo "$URL" | grep -qiE '\.(css|js|png|jpg|gif|svg|ico|woff)(\?|$)'; then
    return 1
  fi

  local CANARY="hackeadora_pp_$(openssl rand -hex 6 2>/dev/null || echo "$RANDOM$RANDOM")"
  local BASE_URL="${URL%%\?*}"

  # Baseline: pedir URL base, ¿canary ya presente? (raro, pero detección)
  _h_get_noredirect "$BASE_URL" --connect-timeout 6
  local BASELINE_BODY="${HTTP_LAST_BODY:0:8000}"
  if echo "$BASELINE_BODY" | grep -qF "$CANARY"; then
    return 1  # canary collision (no debería pasar)
  fi

  # Vector 1: ?__proto__[<random>]=canary
  local PAYLOAD_URL="${BASE_URL}?__proto__[${CANARY}]=hackeadora_polluted"
  _h_get_noredirect "$PAYLOAD_URL" --connect-timeout 6
  local STATUS="$HTTP_LAST_STATUS"
  [[ "$STATUS" != "200" && "$STATUS" != "302" ]] && return 1

  # Pedir URL base de nuevo — si la app contaminó Object.prototype, el canary
  # debería aparecer en cualquier objeto enumerado en el response.
  _h_get_noredirect "$BASE_URL" --connect-timeout 6
  local POLLUTED_BODY="${HTTP_LAST_BODY:0:8000}"

  if echo "$POLLUTED_BODY" | grep -qF "$CANARY"; then
    _pp_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
      "client_side_pp_proto" "high" \
      "Client-side prototype pollution: '?__proto__[${CANARY}]=...' contaminó Object.prototype y aparece en respuesta posterior. Vector: ${PAYLOAD_URL}" \
      "high"
    return 0
  fi

  # Vector 2: constructor.prototype
  local PAYLOAD_CTOR="${BASE_URL}?constructor[prototype][${CANARY}]=hackeadora_polluted"
  _h_get_noredirect "$PAYLOAD_CTOR" --connect-timeout 6
  STATUS="$HTTP_LAST_STATUS"
  [[ "$STATUS" != "200" && "$STATUS" != "302" ]] && return 1

  _h_get_noredirect "$BASE_URL" --connect-timeout 6
  POLLUTED_BODY="${HTTP_LAST_BODY:0:8000}"
  if echo "$POLLUTED_BODY" | grep -qF "$CANARY"; then
    _pp_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
      "client_side_pp_constructor" "high" \
      "Client-side prototype pollution via constructor.prototype.${CANARY}. Vector: ${PAYLOAD_CTOR}" \
      "high"
    return 0
  fi

  # Vector 3: JSON body POST
  local PAYLOAD_JSON='{"__proto__":{"'${CANARY}'":"hackeadora_polluted"}}'
  _h_post_noredirect "$BASE_URL" "$PAYLOAD_JSON" --connect-timeout 6 \
    -H "Content-Type: application/json"
  STATUS="$HTTP_LAST_STATUS"
  [[ "$STATUS" != "200" && "$STATUS" != "201" && "$STATUS" != "204" ]] && return 1

  _h_get_noredirect "$BASE_URL" --connect-timeout 6
  POLLUTED_BODY="${HTTP_LAST_BODY:0:8000}"
  if echo "$POLLUTED_BODY" | grep -qF "$CANARY"; then
    _pp_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
      "server_side_pp_json" "critical" \
      "Server-side prototype pollution via JSON body __proto__. RCE-capable si la app pasa el objeto a child_process/eval/template render. Vector: ${PAYLOAD_JSON}" \
      "high"
    return 0
  fi

  return 1
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 43 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null || true

  # URLs candidatas: API endpoints que pueden parsear query/JSON params
  local CANDIDATES
  CANDIDATES=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (
         url LIKE '%/api/%' OR url LIKE '%/v1/%' OR url LIKE '%/v2/%'
         OR url LIKE '%/graphql%' OR url LIKE '%?%'
       )
       AND url NOT LIKE '%.css%' AND url NOT LIKE '%.js%'
       AND url NOT LIKE '%.png%' AND url NOT LIKE '%.jpg%'
       AND url NOT LIKE '%.svg%' AND url NOT LIKE '%.ico%'
     LIMIT 50;" 2>/dev/null | sort -u)

  if [[ -z "$CANDIDATES" ]]; then
    log_info "  Sin URLs API candidatas — saltando"
    return 0
  fi

  local COUNT
  COUNT=$(echo "$CANDIDATES" | grep -c .)
  log_info "  ${COUNT} URLs candidatas para PP"

  local TOTAL_FINDINGS=0 PROCESSED=0
  # Filtro previo: catch-all skip
  declare -A SKIPPED_HOSTS
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    ((PROCESSED++))

    local HOST_BASE
    HOST_BASE=$(echo "$URL" | grep -oP 'https?://[^/]+')
    if [[ -z "${SKIPPED_HOSTS[$HOST_BASE]+x}" ]]; then
      if is_catchall_host "$HOST_BASE" 2>/dev/null; then
        SKIPPED_HOSTS[$HOST_BASE]=1
      else
        SKIPPED_HOSTS[$HOST_BASE]=0
      fi
    fi
    [[ "${SKIPPED_HOSTS[$HOST_BASE]}" == "1" ]] && continue

    _pp_probe "$URL" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL_FINDINGS++))
  done <<< "$CANDIDATES"

  log_ok "$MODULE_DESC: ${TOTAL_FINDINGS} PP confirmados sobre ${PROCESSED} URLs"
}
