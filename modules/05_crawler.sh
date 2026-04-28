#!/usr/bin/env bash
# ============================================================
#  modules/05_crawler.sh
#  Fase 5: Crawling de URLs — todo el tráfico pasa por proxy
#  Herramientas: katana, gau, waybackurls, gospider
# ============================================================

MODULE_NAME="crawler"
MODULE_DESC="Crawling y descubrimiento de URLs (via proxy)"

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  local ALIVE="$OUT_DIR/subs_alive.txt"
  local URLS_RAW="$OUT_DIR/urls_raw.txt"
  local URLS_NEW="$OUT_DIR/urls_new.txt"
  local TMP="$OUT_DIR/.crawl_tmp"
  mkdir -p "$TMP"
  > "$URLS_RAW"; > "$URLS_NEW"

  log_phase "Módulo 05 — $MODULE_DESC: $DOMAIN"

  if [[ ! -s "$ALIVE" ]]; then
    log_warn "subs_alive.txt vacío, saltando crawling"
    return
  fi

  # ── Cargar y verificar proxy ──────────────────────────────
  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  proxy_check
  $PROXY_ACTIVE && log_info "Tráfico de crawling enrutado por ${PROXY_TOOL}: ${PROXY_URL}"

  local DEPTH="${CRAWL_DEPTH:-3}"
  local TIMEOUT="${CRAWL_TIMEOUT:-300}"

  # ── katana ────────────────────────────────────────────────
  if command -v "${KATANA_BIN:-katana}" &>/dev/null; then
    log_info "katana (depth=$DEPTH)..."
    sed 's|^|https://|' "$ALIVE" > "$TMP/katana_input.txt"

    local KATANA_PROXY=""
    $PROXY_ACTIVE && KATANA_PROXY="-proxy ${PROXY_URL}"

    timeout "$TIMEOUT" \
      "${KATANA_BIN:-katana}" \
        -l "$TMP/katana_input.txt" \
        -d "$DEPTH" \
        -silent \
        -jc \
        -kf all \
        -o "$TMP/katana.txt" \
        ${KATANA_PROXY} \
        2>/dev/null \
    || log_warn "katana: timeout o error"
  else
    log_warn "katana no encontrado, saltando"
  fi

  # ── gospider ──────────────────────────────────────────────
  if command -v gospider &>/dev/null; then
    log_info "gospider..."
    local GOSPIDER_PROXY=""
    $PROXY_ACTIVE && GOSPIDER_PROXY="--proxy ${PROXY_URL}"

    gospider \
      -S "$ALIVE" \
      -d "$DEPTH" \
      -c 10 \
      -t 20 \
      --no-redirect \
      -q \
      ${GOSPIDER_PROXY} \
      > "$TMP/gospider_raw.txt" 2>/dev/null \
    || log_warn "gospider: error o sin resultados"

    grep -oP 'https?://[^\s]+' "$TMP/gospider_raw.txt" \
      > "$TMP/gospider.txt" 2>/dev/null || true
  else
    log_warn "gospider no encontrado, saltando"
  fi

  # ── gau (histórico — no pasa por proxy, es consulta a APIs) ─
  if command -v "${GAU_BIN:-gau}" &>/dev/null; then
    log_info "gau (URLs históricas)..."
    "${GAU_BIN:-gau}" --subs "$DOMAIN" \
      > "$TMP/gau.txt" 2>/dev/null \
    || log_warn "gau: error o sin resultados"
  else
    log_warn "gau no encontrado, saltando"
  fi

  # ── waybackurls (histórico — igual, no proxy) ─────────────
  if command -v waybackurls &>/dev/null; then
    log_info "waybackurls..."
    echo "$DOMAIN" | waybackurls \
      > "$TMP/wayback.txt" 2>/dev/null \
    || log_warn "waybackurls: error o sin resultados"
  else
    log_warn "waybackurls no encontrado, saltando"
  fi

  # ── Merge, filtrar y deduplicar ───────────────────────────
  log_info "Consolidando URLs..."
  cat "$TMP"/*.txt 2>/dev/null \
    | grep -oP 'https?://[^\s"<>]+' \
    | grep -iE "(${DOMAIN//./\\.})" \
    | grep -vE '\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|css|js\.map)$' \
    | sort -u \
    > "$URLS_RAW"

  # ── Detectar nuevas URLs y guardar en DB ──────────────────
  local NEW_COUNT=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    local IS_NEW
    IS_NEW=$(db_is_new_url "$DOMAIN_ID" "$URL")
    db_add_url "$DOMAIN_ID" "$URL" "crawler" ""
    if [[ "$IS_NEW" == "1" ]]; then
      echo "$URL" >> "$URLS_NEW"
      ((NEW_COUNT++))
    fi
  done < "$URLS_RAW"

  local TOTAL
  TOTAL=$(wc -l < "$URLS_RAW" | tr -d ' ')
  rm -rf "$TMP"
  log_ok "$MODULE_DESC completado: $TOTAL URLs totales, $NEW_COUNT nuevas"
}
