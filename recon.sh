#!/usr/bin/env bash
# ============================================================
#  Hackeadora — Entrypoint principal
#  Autores: Claude (Anthropic) & Antonio Fernandes
#
#  Uso:
#    ./recon.sh empresa.com                        → scan completo
#    ./recon.sh empresa.com --target app.empresa.com → subdominio específico
#    ./recon.sh empresa.com --schedule             → loop cada 12h
#    ./recon.sh empresa.com --modules=20,22,23     → módulos concretos
#    ./recon.sh empresa.com --skip-modules=06,08   → excluir módulos del scan completo
#    ./recon.sh empresa.com --target app.empresa.com --modules=22,23,24
#    ./recon.sh --test-telegram                    → probar Telegram
#    ./recon.sh --stats empresa.com                → ver stats de DB
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── PATH — incluir directorios de herramientas Go y locales ──
export PATH="$PATH:/root/go/bin:/root/.local/bin:/usr/local/go/bin"

# ── Cargar configuración ──────────────────────────────────────
CONFIG="$SCRIPT_DIR/config.env"
if [[ ! -f "$CONFIG" ]]; then
  echo "[!] config.env no encontrado. Ejecuta: cp config.env.example config.env"
  exit 1
fi
source "$CONFIG"

# ── Parsear argumentos ────────────────────────────────────────
DOMAIN=""
TARGET_SUB=""      # subdominio específico (--target)
SCHEDULE=false
ONLY_MODULES=""
SKIP_MODULES=""
FORCE_BREACH=false
SHOW_STATS=false
SOCKS_PROXY_HOST=""

for ARG in "$@"; do
  case "$ARG" in
    --schedule)         SCHEDULE=true ;;
    --force-breach)     FORCE_BREACH=true ;;
    --modules=*)        ONLY_MODULES="${ARG#*=}" ;;
    --skip-modules=*)   SKIP_MODULES="${ARG#*=}" ;;
    --target=*)         TARGET_SUB="${ARG#*=}" ;;
    --socks-proxy)      SOCKS_PROXY_HOST="217.76.52.109" ;;
    --socks-proxy=*)    SOCKS_PROXY_HOST="${ARG#*=}" ;;
    --test-telegram)
      source "$SCRIPT_DIR/core/logger.sh"
      source "$SCRIPT_DIR/core/notify.sh"
      notify_test; exit 0 ;;
    --stats)            SHOW_STATS=true ;;
    --help|-h)
      sed -n 's/^#  //p' "$0" | head -20
      exit 0 ;;
    --*)                echo "[!] Opción desconocida: $ARG"; exit 1 ;;
    *)                  DOMAIN="$ARG" ;;
  esac
done

if [[ -z "$DOMAIN" ]] && [[ "$SHOW_STATS" == false ]]; then
  echo "Uso: $0 <dominio> [--target=sub.dominio.com] [--schedule] [--modules=01,02]"
  exit 1
fi

# ── Setup del scan ────────────────────────────────────────────
_setup_scan() {
  local DOM="$1"
  local SCAN_DATE
  SCAN_DATE="$(date '+%Y%m%d_%H%M%S')"
  OUT_DIR="${OUTPUT_BASE:-$SCRIPT_DIR/output}/${DOM}/${SCAN_DATE}"
  mkdir -p "$OUT_DIR"

  LOG_FILE="$OUT_DIR/recon.log"
  source "$SCRIPT_DIR/core/logger.sh"
  source "$SCRIPT_DIR/core/notify.sh"
  source "$SCRIPT_DIR/core/db.sh"
  source "$SCRIPT_DIR/core/proxy.sh"       2>/dev/null || true
  source "$SCRIPT_DIR/core/watchdog.sh"    2>/dev/null || true
  source "$SCRIPT_DIR/core/http_analyzer.sh" 2>/dev/null || true
  source "$SCRIPT_DIR/core/rotator.sh"    2>/dev/null || true

  if [[ -n "${SOCKS_PROXY_HOST:-}" ]]; then
    socks_tunnel_start "$SOCKS_PROXY_HOST"
    trap 'socks_tunnel_stop' EXIT
  fi

  db_init
  db_add_domain "$DOM"
  DOMAIN_ID=$(db_get_domain_id "$DOM")

  if [[ -n "${PRESEED_SUBS_RAW:-}" ]] && [[ -s "$PRESEED_SUBS_RAW" ]]; then
    cp "$PRESEED_SUBS_RAW" "$OUT_DIR/subs_raw.txt"
    log_info "Pre-seeded subs_raw.txt desde $PRESEED_SUBS_RAW ($(wc -l < "$OUT_DIR/subs_raw.txt") subs)"
  fi
  if [[ -n "${PRESEED_SUBS_ALIVE:-}" ]] && [[ -s "$PRESEED_SUBS_ALIVE" ]]; then
    cp "$PRESEED_SUBS_ALIVE" "$OUT_DIR/subs_alive.txt"
    log_info "Pre-seeded subs_alive.txt desde $PRESEED_SUBS_ALIVE ($(wc -l < "$OUT_DIR/subs_alive.txt") subs)"
  fi
}

# ── Ejecutar un módulo ────────────────────────────────────────
run_module() {
  # run_module es immune a set -e: cualquier fallo interno no mata el pipeline
  set +e

  local MOD_FILE="$1"
  local MOD_PATH="$SCRIPT_DIR/modules/${MOD_FILE}.sh"
  local MOD_NUM="${MOD_FILE%%_*}"

  if [[ -n "$SKIP_MODULES" ]]; then
    IFS=',' read -ra SKIPPED <<< "$SKIP_MODULES"
    for M in "${SKIPPED[@]}"; do
      if [[ "$MOD_NUM" == "$M" ]]; then
        log_debug "Saltando módulo $MOD_FILE (--skip-modules)"
        set -e; return 0
      fi
    done
  fi

  if [[ -n "$ONLY_MODULES" ]]; then
    local RUN=false
    IFS=',' read -ra SELECTED <<< "$ONLY_MODULES"
    for M in "${SELECTED[@]}"; do
      [[ "$MOD_NUM" == "$M" ]] && RUN=true && break
    done
    if [[ "$RUN" == false ]]; then
      log_debug "Saltando módulo $MOD_FILE"
      set -e; return 0
    fi
  fi

  if [[ ! -f "$MOD_PATH" ]]; then
    log_warn "Módulo no encontrado: $MOD_PATH"
    set -e; return 0
  fi

  source "$MOD_PATH" 2>/dev/null || true
  local SCAN_ID
  SCAN_ID=$(db_scan_start "$DOMAIN_ID" "$MOD_FILE" 2>/dev/null) || SCAN_ID=0

  local MOD_TIMEOUT
  MOD_TIMEOUT=$(_wd_get_timeout "$MOD_FILE" 2>/dev/null || echo 600)

  local MOD_EXIT=0
  if [[ "${WATCHDOG_ENABLED:-true}" == "true" ]] && type watchdog_run &>/dev/null 2>&1; then
    watchdog_run "$MOD_FILE" "$MOD_TIMEOUT" \
      bash -c "source '$MOD_PATH' && module_run '${TARGET_SUB:-$DOMAIN}' '$DOMAIN_ID' '$OUT_DIR'"
    MOD_EXIT=$?
  else
    module_run "${TARGET_SUB:-$DOMAIN}" "$DOMAIN_ID" "$OUT_DIR"
    MOD_EXIT=$?
  fi

  if [[ "$MOD_EXIT" -eq 0 ]]; then
    db_scan_end "$SCAN_ID" "ok" 2>/dev/null || true
  else
    db_scan_end "$SCAN_ID" "error" 2>/dev/null || true
    log_error "Módulo $MOD_FILE terminó con error (código $MOD_EXIT) — continuando pipeline"
  fi

  unset -f module_run MODULE_NAME MODULE_DESC 2>/dev/null || true
  set -e
}

# ── Preparar modo single-target ───────────────────────────────
# Cuando se pasa --target, pre-populamos la DB y los archivos
# de output para que los módulos trabajen solo sobre ese subdominio.
_setup_single_target() {
  local SUB="$1"

  log_phase "Modo single-target: $SUB"

  # Insertar el subdominio en la DB como alive directamente
  db_add_subdomain "$DOMAIN_ID" "$SUB" "" "alive" "" ""

  # Crear subs_alive.txt con solo este subdominio
  echo "$SUB" > "$OUT_DIR/subs_alive.txt"
  echo "$SUB" > "$OUT_DIR/subs_raw.txt"
  > "$OUT_DIR/subs_dead.txt"

  # Verificar si responde HTTP y actualizar metadata
  if command -v httpx &>/dev/null; then
    log_info "Verificando $SUB con httpx..."
    local HTTPX_INFO
    HTTPX_INFO=$(echo "$SUB" | httpx -silent -json -status-code -title -tech-detect -ip \
      ${SCAN_UA:+-H "User-Agent: ${SCAN_UA}"} 2>/dev/null | head -1)
    if [[ -n "$HTTPX_INFO" ]]; then
      local HTTP_STATUS IP TITLE
      HTTP_STATUS=$(echo "$HTTPX_INFO" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('status_code',''))" 2>/dev/null)
      IP=$(echo "$HTTPX_INFO"    | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('host',''))" 2>/dev/null)
      TITLE=$(echo "$HTTPX_INFO" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('title',''))" 2>/dev/null)
      db_update_subdomain_status "$DOMAIN_ID" "$SUB" "alive" "$HTTP_STATUS" "$IP" "$TITLE"
      log_ok "$SUB → HTTP $HTTP_STATUS ${IP:+($IP)} ${TITLE:+\"$TITLE\"}"
      echo "$HTTPX_INFO" > "$OUT_DIR/subs_httpx.json"

      # Abortar si Cloudflare Bot Management bloquea el target raíz
      local TECH_LIST
      TECH_LIST=$(echo "$HTTPX_INFO" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(' '.join(d.get('tech',[])))" 2>/dev/null)
      if echo "$TECH_LIST" | grep -qi "Cloudflare Bot Management"; then
        # Confirmar con body check
        local CF_BODY
        CF_BODY=$(curl -s -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 "https://${SUB}/" 2>/dev/null | head -c 1000)
        if echo "$CF_BODY" | grep -qi "Just a moment\|cf-browser-verification\|cf_chl\|Checking your browser"; then
          log_warn "⛔ Cloudflare Bot Management activo en $SUB — scan abortado (target inaccesible para herramientas automatizadas)"
          _telegram_send "⛔ *Scan abortado*
🎯 Target: \`${SUB}\`
🚧 Cloudflare Bot Management bloquea todo tráfico automatizado
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
          exit 0
        fi
      fi
    fi
  fi

  _telegram_send "🎯 *Single-target scan*
🌐 Dominio: \`${DOMAIN}\`
🎯 Target: \`${SUB}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
}

# ── Pipeline principal ────────────────────────────────────────
_run_pipeline() {
  local DOM="$1"

  _setup_scan "$DOM"

  if [[ -n "$TARGET_SUB" ]]; then
    # ── MODO SINGLE-TARGET ──────────────────────────────────
    # Saltamos los módulos de descubrimiento (01-03) y partimos
    # directamente desde el subdominio indicado.
    log_phase "Hackeadora — Single-target scan: $TARGET_SUB"
    _setup_single_target "$TARGET_SUB"
    notify_scan_start "${DOM} → ${TARGET_SUB}"

    # Solo módulos de análisis — no descubrimiento
    # Primero crawl + recon, nuclei al final con más contexto
    run_module "05_crawler"
    run_module "06_active_scan"
    run_module "08_screenshots"
    run_module "09_tech_detect"
    run_module "10_tech_fingerprint"
    run_module "11_js_analyzer"
    run_module "12_login_finder"
    run_module "13_port_scan"
    run_module "19_auth_crawler"
    run_module "15_param_discovery"

    # Testing modules are independent — run in parallel (WAL mode handles concurrent writes)
    log_phase "Fase de testing en paralelo (módulos 20-37)..."
    ( run_module "20_smart_scan"    ) & _PID_20=$!
    ( run_module "21_business_logic") & _PID_21=$!
    ( run_module "22_cors_check"    ) & _PID_22=$!
    ( run_module "23_403_bypass"    ) & _PID_23=$!
    ( run_module "24_http_smuggling") & _PID_24=$!
    ( run_module "25_cms_scan"      ) & _PID_25=$!
    ( run_module "26_path_confusion") & _PID_26=$!
    ( run_module "27_blind_xss"              ) & _PID_27=$!
    ( run_module "28_cache_attacks"          ) & _PID_28=$!
    ( run_module "29_api_auth_scan"          ) & _PID_29=$!
    ( run_module "30_spring_config"          ) & _PID_30=$!
    ( run_module "31_keycloak_enum"          ) & _PID_31=$!
    ( run_module "32_csp_analysis"           ) & _PID_32=$!
    ( run_module "33_password_reset_poison"  ) & _PID_33=$!
    ( run_module "34_race_condition"         ) & _PID_34=$!
    ( run_module "35_oidc_oauth_scan"        ) & _PID_35=$!
    ( run_module "36_spa_config_exposure"    ) & _PID_36=$!
    ( run_module "37_aem_jcr_scan"           ) & _PID_37=$!
    wait $_PID_20 $_PID_21 $_PID_22 $_PID_23 $_PID_24 \
         $_PID_25 $_PID_26 $_PID_27 $_PID_28 $_PID_29 \
         $_PID_30 $_PID_31 $_PID_32 $_PID_33 $_PID_34 \
         $_PID_35 $_PID_36 $_PID_37 2>/dev/null || true
    log_ok "Testing paralelo completado"

    run_module "04_nuclei_scan"
    run_module "07_nuclei_urls"

    # GraphQL scan — introspection, batching, sensitive fields (Tier 2.2)
    run_module "39_graphql_scan"

    # CVE matcher — cruza tech_name+version contra cve_catalog (Tier 2.1)
    run_module "40_cve_matcher"

    # Auth-state IDOR replay — no-cookie bypass + cookie A/B swap opt-in (Tier 2.3)
    run_module "41_auth_replay"

    # XXE — file:// LFI + OOB canary en endpoints XML (Tier 2.4)
    run_module "42_xxe_scan"

    # Prototype pollution — query/JSON __proto__ + constructor (Tier 2.5)
    run_module "43_prototype_pollution"

    # WebSocket — origin check, JWT en URL, ws:// no-TLS (Tier 2.6)
    run_module "44_websocket_scan"

    # Verificación post-pipeline (Mejora D del refactor 2026-05-09)
    run_module "99_verify_findings"

  else
    # ── MODO COMPLETO ───────────────────────────────────────
    log_phase "Hackeadora — Scan completo: $DOM"
    notify_scan_start "$DOM"

    # Descubrimiento
    run_module "01_subdomain_enum"
    run_module "02_dns_resolve"
    run_module "03_takeover"

    # Crawl + recon (alimentan a nuclei)
    run_module "05_crawler"
    run_module "06_active_scan"
    run_module "08_screenshots"
    run_module "09_tech_detect"
    run_module "10_tech_fingerprint"
    run_module "11_js_analyzer"
    run_module "12_login_finder"
    run_module "13_port_scan"
    BREACH_FORCE="${FORCE_BREACH:-false}" run_module "14_breach_lookup"
    run_module "16_github_dorking"
    run_module "17_cloud_enum"
    run_module "18_asn_discovery"
    run_module "19_auth_crawler"
    run_module "15_param_discovery"

    # Testing modules are independent — run in parallel (WAL mode handles concurrent writes)
    log_phase "Fase de testing en paralelo (módulos 20-37)..."
    ( run_module "20_smart_scan"    ) & _PID_20=$!
    ( run_module "21_business_logic") & _PID_21=$!
    ( run_module "22_cors_check"    ) & _PID_22=$!
    ( run_module "23_403_bypass"    ) & _PID_23=$!
    ( run_module "24_http_smuggling") & _PID_24=$!
    ( run_module "25_cms_scan"      ) & _PID_25=$!
    ( run_module "26_path_confusion") & _PID_26=$!
    ( run_module "27_blind_xss"              ) & _PID_27=$!
    ( run_module "28_cache_attacks"          ) & _PID_28=$!
    ( run_module "29_api_auth_scan"          ) & _PID_29=$!
    ( run_module "30_spring_config"          ) & _PID_30=$!
    ( run_module "31_keycloak_enum"          ) & _PID_31=$!
    ( run_module "32_csp_analysis"           ) & _PID_32=$!
    ( run_module "33_password_reset_poison"  ) & _PID_33=$!
    ( run_module "34_race_condition"         ) & _PID_34=$!
    ( run_module "35_oidc_oauth_scan"        ) & _PID_35=$!
    ( run_module "36_spa_config_exposure"    ) & _PID_36=$!
    ( run_module "37_aem_jcr_scan"           ) & _PID_37=$!
    wait $_PID_20 $_PID_21 $_PID_22 $_PID_23 $_PID_24 \
         $_PID_25 $_PID_26 $_PID_27 $_PID_28 $_PID_29 \
         $_PID_30 $_PID_31 $_PID_32 $_PID_33 $_PID_34 \
         $_PID_35 $_PID_36 $_PID_37 2>/dev/null || true
    log_ok "Testing paralelo completado"

    # Nuclei al final — con todos los subdominios y URLs ya descubiertos
    run_module "04_nuclei_scan"
    run_module "07_nuclei_urls"

    # GraphQL scan — introspection, batching, sensitive fields (Tier 2.2)
    run_module "39_graphql_scan"

    # CVE matcher — cruza tech_name+version contra cve_catalog (Tier 2.1)
    run_module "40_cve_matcher"

    # Auth-state IDOR replay — no-cookie bypass + cookie A/B swap opt-in (Tier 2.3)
    run_module "41_auth_replay"

    # XXE — file:// LFI + OOB canary en endpoints XML (Tier 2.4)
    run_module "42_xxe_scan"

    # Prototype pollution — query/JSON __proto__ + constructor (Tier 2.5)
    run_module "43_prototype_pollution"

    # WebSocket — origin check, JWT en URL, ws:// no-TLS (Tier 2.6)
    run_module "44_websocket_scan"

    # Verificación post-pipeline (Mejora D del refactor 2026-05-09)
    run_module "99_verify_findings"
  fi

  # ── AI Advisor al final (siempre, si está configurado) ─────
  if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    log_phase "AI Advisor — análisis final"
    python3 "$SCRIPT_DIR/core/ai_advisor.py" --domain "$DOMAIN" 2>/dev/null || true
  else
    log_info "AI Advisor: configura ANTHROPIC_API_KEY en .env para activarlo"
  fi

  # ── Tech registry suggestions — para nutrir el catálogo iterativamente ──
  local SUGG_FILE="$OUT_DIR/tech_suggestions.txt"
  if [[ -s "$SUGG_FILE" ]]; then
    local SUGG_COUNT
    SUGG_COUNT=$(sort -u "$SUGG_FILE" | wc -l | tr -d ' ')
    log_info "📚 Tech registry: $SUGG_COUNT markers desconocidos para review"
    log_info "   Review:  ./tools/tech_review.sh $SUGG_FILE"
    log_info "   Añadir:  ./tools/tech_add.sh \"Name\" category 'header_re' 'body_re' 'url_probes' 'status_ok'"
    _telegram_send "📚 *Tech registry — review pendiente*
🌐 \`${DOMAIN}\`
🆕 Markers desconocidos: \`${SUGG_COUNT}\`
📝 \`./tools/tech_review.sh ${SUGG_FILE}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi

  # ── Stats finales ─────────────────────────────────────────
  local STATS
  STATS=$(db_stats "$DOMAIN_ID")
  log_phase "Scan completado — $STATS"

  local SUBS_COUNT URLS_COUNT
  SUBS_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM subdomains WHERE domain_id=${DOMAIN_ID};" 2>/dev/null || echo "?")
  URLS_COUNT=$(sqlite3  "$DB_PATH" "SELECT COUNT(*) FROM urls      WHERE domain_id=${DOMAIN_ID};" 2>/dev/null || echo "?")

  local TARGET_LABEL="${TARGET_SUB:-$DOM}"
  notify_scan_end "$TARGET_LABEL" "$SUBS_COUNT" "$URLS_COUNT"
  log_ok "Output guardado en: $OUT_DIR"
}

# ── Stats mode ────────────────────────────────────────────────
if [[ "$SHOW_STATS" == true ]]; then
  source "$SCRIPT_DIR/core/logger.sh"
  source "$SCRIPT_DIR/core/db.sh"
  db_init
  db_add_domain "$DOMAIN"
  DOMAIN_ID=$(db_get_domain_id "$DOMAIN")
  echo "$(db_stats "$DOMAIN_ID")"
  exit 0
fi

# ── Modo single scan ──────────────────────────────────────────
if [[ "$SCHEDULE" == false ]]; then
  _run_pipeline "$DOMAIN"
  exit 0
fi

# ── Modo scheduler ────────────────────────────────────────────
INTERVAL_H="${SCHEDULE_HOURS:-12}"
INTERVAL_S=$(( INTERVAL_H * 3600 ))

echo "Modo scheduler: scan de ${TARGET_SUB:-$DOMAIN} cada ${INTERVAL_H}h"
echo "Ctrl+C para detener"

while true; do
  _run_pipeline "$DOMAIN"
  echo "Próximo scan en ${INTERVAL_H}h ($(date -d "+${INTERVAL_H} hours" '+%Y-%m-%d %H:%M:%S'))"
  sleep "$INTERVAL_S"
done
