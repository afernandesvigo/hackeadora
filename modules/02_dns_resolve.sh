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
#     <output_dir>/subs_alive.txt   → resuelven + HTTP OK
#     <output_dir>/subs_dead.txt    → no resuelven / NXDOMAIN
#     <output_dir>/subs_httpx.json  → metadata HTTP completa
# ============================================================

MODULE_NAME="dns_resolve"
MODULE_DESC="Resolución DNS y clasificación alive/dead"

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  local RAW="$OUT_DIR/subs_raw.txt"
  local ALIVE="$OUT_DIR/subs_alive.txt"
  local DEAD="$OUT_DIR/subs_dead.txt"
  local HTTPX_JSON="$OUT_DIR/subs_httpx.json"
  local DNS_RESOLVED="$OUT_DIR/.dns_resolved.txt"

  > "$ALIVE"; > "$DEAD"; > "$HTTPX_JSON"

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

    # Extraer alive desde JSON de httpx
    if [[ -s "$HTTPX_JSON" ]]; then
      jq -r '.url' "$HTTPX_JSON" 2>/dev/null \
        | sed 's|https\?://||' \
        | sed 's|/.*||' \
        | sort -u \
        > "$ALIVE"
    fi
  else
    # Fallback: si no hay httpx, usar los resueltos por dnsx
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

  # Procesar alive con metadata de httpx
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

  local ALIVE_COUNT DEAD_COUNT
  ALIVE_COUNT=$(wc -l < "$ALIVE" | tr -d ' ')
  DEAD_COUNT=$(wc -l < "$DEAD" | tr -d ' ')

  log_ok "$MODULE_DESC completado: $ALIVE_COUNT alive, $DEAD_COUNT dead, $NEW_COUNT nuevos"
  rm -f "$DNS_RESOLVED"
}
