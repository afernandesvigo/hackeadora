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
#    ./recon.sh empresa.com --target app.empresa.com --modules=22,23,24
#    ./recon.sh --test-telegram                    → probar Telegram
#    ./recon.sh --stats empresa.com                → ver stats de DB
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
FORCE_BREACH=false
SHOW_STATS=false

for ARG in "$@"; do
  case "$ARG" in
    --schedule)       SCHEDULE=true ;;
    --force-breach)   FORCE_BREACH=true ;;
    --modules=*)      ONLY_MODULES="${ARG#*=}" ;;
    --target=*)       TARGET_SUB="${ARG#*=}" ;;
    --test-telegram)
      source "$SCRIPT_DIR/core/logger.sh"
      source "$SCRIPT_DIR/core/notify.sh"
      notify_test; exit 0 ;;
    --stats)          SHOW_STATS=true ;;
    --help|-h)
      sed -n 's/^#  //p' "$0" | head -20
      exit 0 ;;
    --*)              echo "[!] Opción desconocida: $ARG"; exit 1 ;;
    *)                DOMAIN="$ARG" ;;
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
  source "$SCRIPT_DIR/core/watchdog.sh"    2>/dev/null || true
  source "$SCRIPT_DIR/core/http_analyzer.sh" 2>/dev/null || true

  db_init
  db_add_domain "$DOM"
  DOMAIN_ID=$(db_get_domain_id "$DOM")
}

# ── Ejecutar un módulo ────────────────────────────────────────
run_module() {
  local MOD_FILE="$1"
  local MOD_PATH="$SCRIPT_DIR/modules/${MOD_FILE}.sh"
  local MOD_NUM="${MOD_FILE%%_*}"

  if [[ -n "$ONLY_MODULES" ]]; then
    local RUN=false
    IFS=',' read -ra SELECTED <<< "$ONLY_MODULES"
    for M in "${SELECTED[@]}"; do
      [[ "$MOD_NUM" == "$M" ]] && RUN=true && break
    done
    [[ "$RUN" == false ]] && { log_debug "Saltando módulo $MOD_FILE"; return; }
  fi

  [[ ! -f "$MOD_PATH" ]] && { log_warn "Módulo no encontrado: $MOD_PATH"; return; }

  source "$MOD_PATH"
  local SCAN_ID
  SCAN_ID=$(db_scan_start "$DOMAIN_ID" "$MOD_FILE")

  # Obtener timeout para este módulo
  local MOD_TIMEOUT
  MOD_TIMEOUT=$(_wd_get_timeout "$MOD_FILE" 2>/dev/null || echo 600)

  # Ejecutar con watchdog (timeout + resource monitor)
  if type watchdog_run &>/dev/null 2>&1; then
    watchdog_run "$MOD_FILE" "$MOD_TIMEOUT"       bash -c "source '$MOD_PATH' && module_run '$DOMAIN' '$DOMAIN_ID' '$OUT_DIR'"
    local MOD_EXIT=$?
  else
    module_run "$DOMAIN" "$DOMAIN_ID" "$OUT_DIR"
    local MOD_EXIT=$?
  fi

  if [[ "$MOD_EXIT" -eq 0 ]]; then
    db_scan_end "$SCAN_ID" "ok"
  else
    db_scan_end "$SCAN_ID" "error"
    log_error "Módulo $MOD_FILE terminó con error (código $MOD_EXIT) — continuando pipeline"
  fi

  unset -f module_run MODULE_NAME MODULE_DESC 2>/dev/null || true
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
    HTTPX_INFO=$(echo "$SUB" | httpx -silent -json -status-code -title -tech-detect -ip 2>/dev/null | head -1)
    if [[ -n "$HTTPX_INFO" ]]; then
      local HTTP_STATUS IP TITLE
      HTTP_STATUS=$(echo "$HTTPX_INFO" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('status_code',''))" 2>/dev/null)
      IP=$(echo "$HTTPX_INFO"    | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('host',''))" 2>/dev/null)
      TITLE=$(echo "$HTTPX_INFO" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('title',''))" 2>/dev/null)
      db_update_subdomain_status "$DOMAIN_ID" "$SUB" "alive" "$HTTP_STATUS" "$IP" "$TITLE"
      log_ok "$SUB → HTTP $HTTP_STATUS ${IP:+($IP)} ${TITLE:+\"$TITLE\"}"
      echo "$HTTPX_INFO" > "$OUT_DIR/subs_httpx.json"
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
    run_module "04_nuclei_scan"
    run_module "05_crawler"
    run_module "06_active_scan"
    run_module "07_nuclei_urls"
    run_module "08_screenshots"
    run_module "09_tech_detect"
    run_module "10_tech_fingerprint"
    run_module "11_js_analyzer"
    run_module "12_login_finder"
    run_module "13_port_scan"
    run_module "15_param_discovery"
    run_module "19_auth_crawler"
    run_module "20_smart_scan"
    run_module "21_business_logic"
    run_module "22_cors_check"
    run_module "23_403_bypass"
    run_module "24_http_smuggling"

  else
    # ── MODO COMPLETO (comportamiento original) ─────────────
    log_phase "Hackeadora — Scan completo: $DOM"
    notify_scan_start "$DOM"

    run_module "01_subdomain_enum"
    run_module "02_dns_resolve"
    run_module "03_takeover"
    run_module "04_nuclei_scan"
    run_module "05_crawler"
    run_module "06_active_scan"
    run_module "07_nuclei_urls"
    run_module "08_screenshots"
    run_module "09_tech_detect"
    run_module "10_tech_fingerprint"
    run_module "11_js_analyzer"
    run_module "12_login_finder"
    run_module "13_port_scan"
    BREACH_FORCE="${FORCE_BREACH:-false}" run_module "14_breach_lookup"
    run_module "15_param_discovery"
    run_module "16_github_dorking"
    run_module "17_cloud_enum"
    run_module "18_asn_discovery"
    run_module "19_auth_crawler"
    run_module "20_smart_scan"
    run_module "21_business_logic"
    run_module "22_cors_check"
    run_module "23_403_bypass"
    run_module "24_http_smuggling"
  fi

  # ── AI Advisor al final (siempre, si está configurado) ─────
  if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    log_phase "AI Advisor — análisis final"
    python3 "$SCRIPT_DIR/core/ai_advisor.py" --domain "$DOMAIN" 2>/dev/null || true
  else
    log_info "AI Advisor: configura ANTHROPIC_API_KEY en .env para activarlo"
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
