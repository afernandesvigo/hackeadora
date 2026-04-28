#!/usr/bin/env bash
# ============================================================
#  modules/05_crawler.sh
#  Fase 5: Crawling exhaustivo de URLs
#  Herramientas: katana (normal + headless), gospider,
#                hakrawler, gau, waybackurls
# ============================================================

MODULE_NAME="crawler"
MODULE_DESC="Crawling exhaustivo de URLs"

# ── Deduplicar targets por contenido ─────────────────────────
# Fingerprint = IP + MD5(body homepage)
# Mismo IP + mismo contenido → mismo vhost → crawl una sola vez
# Mismo IP + distinto contenido → virtual hosts distintos → crawl ambos
_dedup_crawl_targets() {
  local ALIVE="$1"
  local OUT="$2"

  > "$OUT"

  local TOTAL
  TOTAL=$(wc -l < "$ALIVE" | tr -d ' ')
  log_info "Deduplicando $TOTAL subdominios por IP + contenido..."

  declare -A _SEEN_FP  # fingerprint(ip:md5) → subdominio representativo

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue

    # Resolver IP
    local IP
    IP=$(dig +short "$SUB" 2>/dev/null | grep -oP '^\d+\.\d+\.\d+\.\d+' | head -1)

    if [[ -z "$IP" ]]; then
      # Sin IP resoluble (CNAME externo, wildcard…) → incluir siempre
      echo "$SUB" >> "$OUT"
      continue
    fi

    # MD5 del body de la homepage (los primeros 50KB bastan para fingerprint)
    local MD5
    MD5=$(curl -sL --max-time 10 \
      -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
      "https://${SUB}" 2>/dev/null \
      | head -c 51200 | md5sum | cut -d' ' -f1)

    # Si curl falló o devolvió body vacío, no podemos comparar → incluir
    if [[ -z "$MD5" || "$MD5" == "d41d8cd98f00b204e9800998ecf8427e" ]]; then
      echo "$SUB" >> "$OUT"
      continue
    fi

    local FP="${IP}:${MD5}"

    if [[ -n "${_SEEN_FP[$FP]:-}" ]]; then
      log_info "  ⏭ $SUB duplica ${_SEEN_FP[$FP]} (IP $IP, MD5 ${MD5:0:8}…) — omitido"
    else
      _SEEN_FP[$FP]="$SUB"
      echo "$SUB" >> "$OUT"
    fi
  done < "$ALIVE"

  local FINAL
  FINAL=$(wc -l < "$OUT" | tr -d ' ')
  local SKIPPED=$(( TOTAL - FINAL ))
  log_info "Dedup: $TOTAL → $FINAL subdominios únicos ($SKIPPED duplicados omitidos)"
}

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

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  $PROXY_ACTIVE && log_info "Tráfico enrutado por ${PROXY_TOOL}: ${PROXY_URL}"

  local DEPTH="${CRAWL_DEPTH:-5}"
  local TIMEOUT="${CRAWL_TIMEOUT:-600}"

  # ── Deduplicar targets antes de crawlear ──────────────────
  local DEDUP_LIST="$TMP/targets_dedup.txt"
  _dedup_crawl_targets "$ALIVE" "$DEDUP_LIST"

  # Preparar lista con https:// para herramientas que lo necesitan
  sed 's|^|https://|' "$DEDUP_LIST" > "$TMP/targets.txt"

  local KATANA_PROXY="" GOSPIDER_PROXY="" HAKRAWLER_PROXY=""
  if $PROXY_ACTIVE; then
    KATANA_PROXY="-proxy ${PROXY_URL}"
    GOSPIDER_PROXY="--proxy ${PROXY_URL}"
    HAKRAWLER_PROXY="-proxy ${PROXY_URL}"
  fi

  # ── katana — crawl estático + JS ─────────────────────────
  if command -v "${KATANA_BIN:-katana}" &>/dev/null; then
    log_info "katana (depth=$DEPTH, JS crawl)..."
    timeout "$TIMEOUT" \
      "${KATANA_BIN:-katana}" \
        -list "$TMP/targets.txt" \
        -d "$DEPTH" \
        -silent \
        -jc \
        -aff \
        -c 50 \
        -p 10 \
        -rd 5 \
        -o "$TMP/katana_static.txt" \
        ${KATANA_PROXY} \
        2>/dev/null \
    || log_warn "katana: timeout o error"
  else
    log_warn "katana no encontrado, saltando"
  fi

  # ── katana headless — SPAs, JS dinámico ──────────────────
  if command -v "${KATANA_BIN:-katana}" &>/dev/null && \
     (command -v chromium-browser &>/dev/null || command -v chromium &>/dev/null || command -v google-chrome &>/dev/null); then
    log_info "katana headless (SPAs / JS dinámico)..."
    timeout "$TIMEOUT" \
      "${KATANA_BIN:-katana}" \
        -list "$TMP/targets.txt" \
        -d "$DEPTH" \
        -silent \
        -jc \
        -aff \
        -hl \
        -nos \
        -c 10 \
        -p 5 \
        -o "$TMP/katana_headless.txt" \
        ${KATANA_PROXY} \
        2>/dev/null \
    || log_warn "katana headless: timeout o error"
  else
    log_info "katana headless: chromium no disponible, saltando"
  fi

  # ── gospider — spider con extracción de forms y JS ───────
  if command -v gospider &>/dev/null; then
    log_info "gospider (depth=$DEPTH)..."
    timeout "$TIMEOUT" \
      gospider \
        -S "$DEDUP_LIST" \
        -d "$DEPTH" \
        -c 20 \
        -t 50 \
        --js \
        --sitemap \
        --robots \
        -q \
        ${GOSPIDER_PROXY} \
        2>/dev/null \
    | grep -oP 'https?://[^\s"<>\]]+' \
    > "$TMP/gospider.txt" \
    || log_warn "gospider: error o sin resultados"
  else
    log_warn "gospider no encontrado, saltando"
  fi

  # ── hakrawler — crawl rápido con extracción de endpoints ─
  if command -v hakrawler &>/dev/null; then
    log_info "hakrawler..."
    timeout "$TIMEOUT" \
      bash -c "cat '$TMP/targets.txt' | hakrawler -d $DEPTH -t 20 -subs ${HAKRAWLER_PROXY} 2>/dev/null" \
    > "$TMP/hakrawler.txt" \
    || log_warn "hakrawler: error o sin resultados"
  else
    log_warn "hakrawler no encontrado, saltando"
  fi

  # ── gau — URLs históricas (Archive.org, CommonCrawl, etc) ─
  if command -v "${GAU_BIN:-gau}" &>/dev/null; then
    log_info "gau (histórico)..."
    timeout 120 \
      "${GAU_BIN:-gau}" \
        --subs \
        --threads 10 \
        "$DOMAIN" \
    > "$TMP/gau.txt" 2>/dev/null \
    || log_warn "gau: error o sin resultados"
  else
    log_warn "gau no encontrado, saltando"
  fi

  # ── waybackurls — Wayback Machine ─────────────────────────
  if command -v waybackurls &>/dev/null; then
    log_info "waybackurls..."
    timeout 120 \
      bash -c "echo '$DOMAIN' | waybackurls 2>/dev/null" \
    > "$TMP/wayback.txt" \
    || log_warn "waybackurls: error o sin resultados"
  else
    log_warn "waybackurls no encontrado, saltando"
  fi

  # ── robots.txt y sitemap.xml (solo targets únicos) ────────
  log_info "Extrayendo robots.txt y sitemap.xml..."
  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    curl -sL --max-time 10 "${BASE}/robots.txt" 2>/dev/null \
      | grep -oP '(?<=Allow: |Disallow: )/[^\s]+' \
      | sed "s|^|${BASE}|" \
      >> "$TMP/robots.txt" || true
    curl -sL --max-time 10 "${BASE}/sitemap.xml" 2>/dev/null \
      | grep -oP 'https?://[^\s<>]+' \
      >> "$TMP/sitemap.txt" || true
    curl -sL --max-time 10 "${BASE}/sitemap_index.xml" 2>/dev/null \
      | grep -oP 'https?://[^\s<>]+\.xml' \
      | while read -r SMAP; do
          curl -sL --max-time 10 "$SMAP" 2>/dev/null \
            | grep -oP 'https?://[^\s<>]+' \
            >> "$TMP/sitemap.txt" || true
        done
  done < "$DEDUP_LIST"

  # ── Merge, filtrar y deduplicar URLs ─────────────────────
  log_info "Consolidando URLs..."
  cat "$TMP"/*.txt 2>/dev/null \
    | grep -oP 'https?://[^\s"<>\]\[{}]+' \
    | grep -iE "(${DOMAIN//./\\.})" \
    | grep -vE '\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|css\.map|js\.map|zip|tar|gz|pdf|mp4|mp3|avi|webp)(\?.*)?$' \
    | sed 's/#.*//' \
    | sort -u \
    > "$URLS_RAW"

  # ── Guardar en DB ─────────────────────────────────────────
  local NEW_COUNT=0 TOTAL=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    ((TOTAL++))
    local IS_NEW
    IS_NEW=$(db_is_new_url "$DOMAIN_ID" "$URL")
    db_add_url "$DOMAIN_ID" "$URL" "crawler" ""
    if [[ "$IS_NEW" == "1" ]]; then
      echo "$URL" >> "$URLS_NEW"
      ((NEW_COUNT++))
    fi
  done < "$URLS_RAW"

  rm -rf "$TMP"
  log_ok "$MODULE_DESC completado: $TOTAL URLs totales, $NEW_COUNT nuevas"
}
