#!/usr/bin/env bash
# ============================================================
#  modules/05_crawler.sh
#  Fase 5: Crawling exhaustivo de URLs
#  Herramientas: katana (estático + headless), gau, waybackurls
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

    local IP
    IP=$(dig +short "$SUB" 2>/dev/null | grep -oP '^\d+\.\d+\.\d+\.\d+' | head -1)

    if [[ -z "$IP" ]]; then
      echo "$SUB" >> "$OUT"
      continue
    fi

    local MD5
    MD5=$(curl -sL --max-time 10 \
      -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
      "https://${SUB}" 2>/dev/null \
      | head -c 51200 | md5sum | cut -d' ' -f1)

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
  log_info "Dedup: $TOTAL → $FINAL subdominios únicos ($((TOTAL - FINAL)) duplicados omitidos)"
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

  # En modo single-target (1 subdominio), usar el subdominio específico para
  # herramientas históricas (gau, waybackurls) en vez del dominio raíz.
  # Esto evita descargar URLs de todos los subdominios del dominio.
  local HIST_TARGET="$DOMAIN"
  local SINGLE_SUB=""
  if [[ "$(wc -l < "$ALIVE" | tr -d ' ')" == "1" ]]; then
    SINGLE_SUB=$(head -1 "$ALIVE" | tr -d '[:space:]')
    [[ -n "$SINGLE_SUB" ]] && HIST_TARGET="$SINGLE_SUB"
    log_info "Modo single-target: histórico limitado a $HIST_TARGET"
  fi

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  proxy_check
  $PROXY_ACTIVE && log_info "Tráfico enrutado por ${PROXY_TOOL}: ${PROXY_URL}"

  local DEPTH="${CRAWL_DEPTH:-5}"
  local TIMEOUT="${CRAWL_TIMEOUT:-600}"
  local TIMEOUT_HEADLESS="${CRAWL_TIMEOUT_HEADLESS:-300}"
  local KATANA_PROXY=""
  $PROXY_ACTIVE && KATANA_PROXY="-proxy ${PROXY_URL}"

  # ── Deduplicar targets antes de crawlear ──────────────────
  local DEDUP_LIST="$TMP/targets_dedup.txt"
  _dedup_crawl_targets "$ALIVE" "$DEDUP_LIST"

  # Lista con https:// para katana
  sed 's|^|https://|' "$DEDUP_LIST" > "$TMP/targets.txt"

  local KATANA_DEPTH=$(( DEPTH > 3 ? 3 : DEPTH ))

  # ── katana estático + JS ──────────────────────────────────
  # -jc  : extrae endpoints de JS
  # -aff : captura todos los campos de formularios como parámetros
  # -kf robotstxt,sitemapxml : parsea robots.txt y sitemap.xml de cada host
  # -rl 150 : rate limit respetuoso con el scope
  # -timeout 15 : evita que hosts lentos bloqueen el pipeline
  if command -v "${KATANA_BIN:-katana}" &>/dev/null; then
    log_info "katana estático (depth=$KATANA_DEPTH, JS + forms + robots/sitemap)..."
    local KATANA_UA_FLAG=""
    [[ -n "${SCAN_UA:-}" ]] && KATANA_UA_FLAG="-H 'User-Agent: ${SCAN_UA}'"
    timeout "$TIMEOUT" \
      "${KATANA_BIN:-katana}" \
        -list    "$TMP/targets.txt" \
        -d       "$KATANA_DEPTH" \
        -jc \
        -aff \
        -kf      all \
        -c       30 \
        -p       5 \
        -rl      150 \
        -timeout 15 \
        -silent \
        -o       "$TMP/katana_static.txt" \
        ${KATANA_PROXY} \
        ${KATANA_UA_FLAG:+-H "User-Agent: ${SCAN_UA}"} \
        >/dev/null 2>/dev/null \
    && log_ok "katana estático: $(wc -l < "$TMP/katana_static.txt" 2>/dev/null || echo 0) URLs" \
    || log_warn "katana estático: timeout o error"
  else
    log_warn "katana no encontrado — instala: go install github.com/projectdiscovery/katana/cmd/katana@latest"
  fi

  # ── katana headless — DESACTIVADO del pipeline principal ─────
  # Lanzar manualmente: CRAWL_HEADLESS=1 bash recon.sh <domain>
  if [[ "${CRAWL_HEADLESS:-0}" == "1" ]]; then
    if command -v "${KATANA_BIN:-katana}" &>/dev/null && \
       (command -v chromium-browser &>/dev/null || command -v chromium &>/dev/null || command -v google-chrome &>/dev/null); then

      local HEADLESS_TARGETS="$TMP/targets_headless.txt"
      > "$HEADLESS_TARGETS"
      while IFS= read -r URL; do
        (
          CT=$(curl -sL --max-time 8 -A "Mozilla/5.0" \
            -o /dev/null -w "%{content_type}" "$URL" 2>/dev/null)
          [[ "$CT" == *"text/html"* ]] && echo "$URL"
        ) &
      done < "$TMP/targets.txt" | sort > "$HEADLESS_TARGETS"
      wait

      local HL_COUNT
      HL_COUNT=$(wc -l < "$HEADLESS_TARGETS" | tr -d ' ')

      if [[ "$HL_COUNT" -eq 0 ]]; then
        log_info "katana headless: sin hosts HTML — saltando"
      else
        log_info "katana headless depth=1 ($HL_COUNT hosts HTML)..."
        timeout "$TIMEOUT_HEADLESS" \
          "${KATANA_BIN:-katana}" \
            -list    "$HEADLESS_TARGETS" \
            -d       1 \
            -jc \
            -aff \
            -hl \
            -nos \
            -c       15 \
            -p       5 \
            -rl      80 \
            -timeout 20 \
            -silent \
            -o       "$TMP/katana_headless.txt" \
            ${KATANA_PROXY} \
            >/dev/null 2>/dev/null
        log_ok "katana headless: $(wc -l < "$TMP/katana_headless.txt" 2>/dev/null || echo 0) URLs (${TIMEOUT_HEADLESS}s cap)"
      fi
    else
      log_warn "katana headless: chromium no disponible"
    fi
  else
    log_info "katana headless: desactivado (activa con CRAWL_HEADLESS=1)"
  fi

  # ── gau — URLs históricas (Archive.org, CommonCrawl, etc) ─
  if command -v "${GAU_BIN:-gau}" &>/dev/null; then
    log_info "gau (histórico)..."
    local GAU_SUBS_FLAG="--subs"
    [[ -n "$SINGLE_SUB" ]] && GAU_SUBS_FLAG=""  # single-target: no expandir subs
    timeout 120 \
      "${GAU_BIN:-gau}" $GAU_SUBS_FLAG --threads 10 "$HIST_TARGET" \
    > "$TMP/gau.txt" 2>/dev/null \
    || log_warn "gau: error o sin resultados"
    log_ok "gau: $(wc -l < "$TMP/gau.txt" 2>/dev/null || echo 0) URLs históricas"
  else
    log_warn "gau no encontrado, saltando"
  fi

  # ── waybackurls — Wayback Machine ─────────────────────────
  if command -v waybackurls &>/dev/null; then
    log_info "waybackurls..."
    timeout 120 \
      bash -c "echo '${HIST_TARGET}' | waybackurls 2>/dev/null" \
    > "$TMP/wayback.txt" \
    || log_warn "waybackurls: error o sin resultados"
    log_ok "waybackurls: $(wc -l < "$TMP/wayback.txt" 2>/dev/null || echo 0) URLs"
  else
    log_warn "waybackurls no encontrado, saltando"
  fi

  # ── Consolidar, filtrar y guardar ─────────────────────────
  log_info "Consolidando URLs..."

  # Paso 1 — extracción y filtros básicos
  # Regex: captura URL completa (path + extensión + query string completo).
  # Excluye markup y comillas pero conserva ?, =, & y . para no truncar params.
  # Filtra recursos estáticos que no aportan superficie de ataque.
  local RAW_PRE="$TMP/urls_pre_dedup.txt"
  # DOMAIN_RE: escapa el punto para usarlo en regex (mysugr.com → mysugr\.com)
  local DOMAIN_RE="${DOMAIN//./\\.}"
  # En single-target, filtrar solo URLs del subdominio específico
  local HOST_RE
  if [[ -n "$SINGLE_SUB" ]]; then
    HOST_RE="${SINGLE_SUB//./\\.}"
  else
    HOST_RE="([a-z0-9_-]+\\.)*${DOMAIN_RE}"
  fi

  cat "$TMP"/*.txt 2>/dev/null \
    | grep -oP 'https?://[^\s"'"'"'<>\]\[{}]+' \
    | grep -iP "^https?://${HOST_RE}([/:#?]|$)" \
    | grep -vE '\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|otf|css\.map|js\.map|zip|tar\.gz|gz|pdf|mp4|mp3|avi|webm|webp)(\?[^\s]*)?$' \
    | sed 's/#[^?]*//' \
    | sed -E 's/([?&])_rsc=[^&]*(&|$)/\2/g; s/\?&/?/g; s/[?&]$//' \
    | sort -u \
    > "$RAW_PRE"

  local PRE_COUNT
  PRE_COUNT=$(wc -l < "$RAW_PRE" | tr -d ' ')

  # Paso 2 — deduplicación semántica por (scheme, host, path, nombres de params)
  # /api/users?id=1  \
  # /api/users?id=2   → mismo endpoint → conservar solo la primera ocurrencia
  # /api/users?id=3  /
  # También normaliza: host en minúsculas, trailing slash en path, orden de params.
  python3 - "$RAW_PRE" <<'PYEOF' | sort > "$URLS_RAW"
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Parámetros internos de frameworks que no aportan superficie de ataque
NOISE_PARAMS = {
    '_rsc',        # Next.js React Server Components
    '__nextjs_original_pathname',
    '_next',
}

def strip_noise(query):
    """Devuelve (query_limpio, params_dict) sin los params de ruido."""
    params = parse_qs(query, keep_blank_values=True)
    clean  = {k: v for k, v in params.items() if k not in NOISE_PARAMS}
    return urlencode(clean, doseq=True), clean

seen = set()
for line in open(sys.argv[1]):
    url = line.strip()
    if not url:
        continue
    try:
        p = urlparse(url)
        clean_query, clean_params = strip_noise(p.query)
        param_names = frozenset(clean_params.keys())
        key = (
            p.scheme.lower(),
            p.netloc.lower(),
            p.path.rstrip('/') or '/',
            param_names,
        )
        if key not in seen:
            seen.add(key)
            # Reconstruir URL sin los params de ruido
            clean_url = urlunparse((
                p.scheme, p.netloc, p.path,
                p.params, clean_query, ''
            ))
            print(clean_url)
    except Exception:
        print(url)
PYEOF

  local POST_COUNT
  POST_COUNT=$(wc -l < "$URLS_RAW" | tr -d ' ')
  log_info "Dedup semántico: $PRE_COUNT → $POST_COUNT URLs únicas ($(( PRE_COUNT - POST_COUNT )) duplicados por valor eliminados)"

  local TOTAL=0 NEW_COUNT=0
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
