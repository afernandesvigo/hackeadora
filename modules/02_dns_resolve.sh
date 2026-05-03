#!/usr/bin/env bash
# ============================================================
#  modules/02_dns_resolve.sh
#  Fase 2: Resolución DNS — clasifica alive / dead
#  Herramientas: dnsx, httpx
# ============================================================
# API pública del módulo:
#   module_run <domain> <domain_id> <output_dir>
#   Lee:    <output_dir>/subs_raw.txt
#   Escribe en:
#     <output_dir>/subs_alive.txt        → resuelven + HTTP accesible
#     <output_dir>/subs_dead.txt         → no resuelven / NXDOMAIN
#     <output_dir>/subs_blanket403.txt   → alive pero CDN/WAF bloquea todo
#     <output_dir>/subs_httpx.json       → metadata HTTP completa
# ============================================================

MODULE_NAME="dns_resolve"
MODULE_DESC="Resolución DNS y clasificación alive/dead"

# ── Detecta si un host devuelve siempre el mismo 4xx para cualquier path ─
# Devuelve 0 (blanket) si ≥3/4 probes aleatorias comparten status+body_len
_check_blanket_403() {
  local HOST_URL="$1"   # https://sub.example.com
  local ROOT_STATUS="$2"

  # Solo aplicar a hosts que ya devolvieron 4xx en la raíz
  [[ ! "$ROOT_STATUS" =~ ^4 ]] && return 1

  local MATCH=0
  local ROOT_LEN
  ROOT_LEN=$(curl -s --max-time 6 -A "${SCAN_UA:-Mozilla/5.0}" \
    -o /dev/null -w "%{size_download}" "${HOST_URL}/" 2>/dev/null)

  for _ in 1 2 3 4; do
    local RAND_PATH
    RAND_PATH="$(openssl rand -hex 6)"
    local STATUS LEN
    STATUS=$(curl -s --max-time 6 -A "${SCAN_UA:-Mozilla/5.0}" \
      -o /tmp/.b403_$$ -w "%{http_code}" "${HOST_URL}/${RAND_PATH}" 2>/dev/null)
    LEN=$(wc -c < /tmp/.b403_$$ 2>/dev/null || echo 0)
    rm -f /tmp/.b403_$$

    if [[ "$STATUS" == "$ROOT_STATUS" && "$LEN" == "$ROOT_LEN" ]]; then
      ((MATCH++))
    fi
  done

  [[ "$MATCH" -ge 3 ]] && return 0 || return 1
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  local RAW="$OUT_DIR/subs_raw.txt"
  local ALIVE="$OUT_DIR/subs_alive.txt"
  local DEAD="$OUT_DIR/subs_dead.txt"
  local BLANKET="$OUT_DIR/subs_blanket403.txt"
  local HTTPX_JSON="$OUT_DIR/subs_httpx.json"
  local DNS_RESOLVED="$OUT_DIR/.dns_resolved.txt"

  > "$ALIVE"; > "$DEAD"; > "$BLANKET"; > "$HTTPX_JSON"

  log_phase "Módulo 02 — $MODULE_DESC: $DOMAIN"

  if [[ ! -s "$RAW" ]]; then
    log_warn "subs_raw.txt vacío, saltando resolución"
    return
  fi

  local THREADS="${RESOLVE_THREADS:-50}"

  # ── Paso 1: Resolución DNS con dnsx ───────────────────────
  if command -v "${DNSX_BIN:-dnsx}" &>/dev/null; then
    log_info "Resolviendo DNS con dnsx ($THREADS threads)..."
    "${DNSX_BIN:-dnsx}" \
      -l "$RAW" \
      -silent \
      -o "$DNS_RESOLVED" \
      -t "$THREADS" \
      2>/dev/null \
    || log_warn "dnsx: error en ejecución"
  else
    log_warn "dnsx no encontrado, usando todos los subdominios para httpx"
    cp "$RAW" "$DNS_RESOLVED"
  fi

  # ── Paso 2: Prueba HTTP con httpx ─────────────────────────
  if command -v "${HTTPX_BIN:-httpx}" &>/dev/null; then
    log_info "Probando HTTP con httpx..."
    "${HTTPX_BIN:-httpx}" \
      -l "$DNS_RESOLVED" \
      -silent \
      -json \
      -status-code \
      -title \
      -tech-detect \
      -ip \
      -threads "$THREADS" \
      -o "$HTTPX_JSON" \
      2>/dev/null \
    || log_warn "httpx: error en ejecución"

    if [[ -s "$HTTPX_JSON" ]]; then
      jq -r '.url' "$HTTPX_JSON" 2>/dev/null \
        | sed 's|https\?://||' \
        | sed 's|/.*||' \
        | sort -u \
        > "$ALIVE"
    fi
  else
    log_warn "httpx no encontrado, usando resultado de dnsx como alive"
    cp "$DNS_RESOLVED" "$ALIVE" 2>/dev/null || true
  fi

  # ── Clasificar dead ───────────────────────────────────────
  comm -23 \
    <(sort "$RAW") \
    <(sort "$ALIVE") \
    > "$DEAD" 2>/dev/null || true

  # ── Actualizar base de datos ──────────────────────────────
  log_info "Actualizando base de datos..."
  local NEW_COUNT=0

  if [[ -s "$HTTPX_JSON" ]] && command -v jq &>/dev/null; then
    while IFS= read -r LINE; do
      local SUB IP STATUS TITLE
      SUB=$(echo "$LINE"    | jq -r '.input // .url' | sed 's|https\?://||;s|/.*||')
      IP=$(echo "$LINE"     | jq -r '.host // ""')
      STATUS=$(echo "$LINE" | jq -r '.status_code // ""')
      TITLE=$(echo "$LINE"  | jq -r '.title // ""' | tr -d "'")

      local IS_NEW
      IS_NEW=$(db_is_new_subdomain "$DOMAIN_ID" "$SUB")
      db_add_subdomain "$DOMAIN_ID" "$SUB" "$IP" "alive" "$STATUS" "$TITLE"
      db_update_subdomain_status "$DOMAIN_ID" "$SUB" "alive" "$STATUS" "$IP" "$TITLE"

      if [[ "$IS_NEW" == "1" ]]; then
        ((NEW_COUNT++))
        notify_new_subdomain "$DOMAIN" "$SUB"
      fi
    done < "$HTTPX_JSON"
  else
    while IFS= read -r SUB; do
      [[ -z "$SUB" ]] && continue
      local IS_NEW
      IS_NEW=$(db_is_new_subdomain "$DOMAIN_ID" "$SUB")
      db_add_subdomain "$DOMAIN_ID" "$SUB" "" "alive" "" ""
      if [[ "$IS_NEW" == "1" ]]; then
        ((NEW_COUNT++))
        notify_new_subdomain "$DOMAIN" "$SUB"
      fi
    done < "$ALIVE"
  fi

  # Marcar dead
  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    db_add_subdomain "$DOMAIN_ID" "$SUB" "" "dead" "" ""
    db_update_subdomain_status "$DOMAIN_ID" "$SUB" "dead" "" "" ""
  done < "$DEAD"

  # ── Paso 3: Detectar blanket-403 ─────────────────────────
  # Subdominio que devuelve siempre el mismo 4xx (CDN/WAF bloqueando la IP)
  # → se saca de subs_alive.txt para no desperdiciar módulos de testing
  local BLANKET_COUNT=0
  local ALIVE_TMP="$OUT_DIR/.subs_alive_filtered.txt"
  > "$ALIVE_TMP"

  if [[ -s "$HTTPX_JSON" ]] && command -v jq &>/dev/null; then
    while IFS= read -r SUB; do
      [[ -z "$SUB" ]] && continue

      local ROOT_STATUS
      ROOT_STATUS=$(jq -r --arg s "$SUB" \
        'select((.input // .url) | test($s)) | .status_code // ""' \
        "$HTTPX_JSON" 2>/dev/null | head -1)

      if [[ "$ROOT_STATUS" =~ ^4 ]]; then
        local SCHEME="https"
        if _check_blanket_403 "${SCHEME}://${SUB}" "$ROOT_STATUS"; then
          log_warn "⛔ Blanket-${ROOT_STATUS}: ${SUB} — WAF/CDN bloquea toda la IP, saltando módulos de testing"
          echo "$SUB" >> "$BLANKET"
          db_mark_blanket_403 "$DOMAIN_ID" "$SUB"
          _telegram_send "⛔ *Blanket-${ROOT_STATUS} detectado*
🌐 \`${DOMAIN}\`
🎯 Subdominio: \`${SUB}\`
🚧 CDN/WAF bloquea todos los paths desde esta IP
💡 Prueba con round-robin de IPs (AWS/rotator)
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
          ((BLANKET_COUNT++))
          continue
        fi
      fi

      echo "$SUB" >> "$ALIVE_TMP"
    done < "$ALIVE"

    mv "$ALIVE_TMP" "$ALIVE"
  fi

  local ALIVE_COUNT DEAD_COUNT
  ALIVE_COUNT=$(wc -l < "$ALIVE" | tr -d ' ')
  DEAD_COUNT=$(wc -l < "$DEAD"  | tr -d ' ')

  local SUMMARY="$ALIVE_COUNT alive, $DEAD_COUNT dead, $NEW_COUNT nuevos"
  [[ "$BLANKET_COUNT" -gt 0 ]] && SUMMARY+=" (${BLANKET_COUNT} blanket-4xx excluidos)"
  log_ok "$MODULE_DESC completado: $SUMMARY"
  rm -f "$DNS_RESOLVED"
}
