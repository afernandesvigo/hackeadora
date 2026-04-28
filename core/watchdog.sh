#!/usr/bin/env bash
# ============================================================
#  core/watchdog.sh — Supervisor de procesos del pipeline
#
#  Tres mecanismos de control:
#    1. Timeout por módulo (configurable en config.env)
#    2. Límite de CPU/memoria por proceso
#    3. Heartbeat — si un módulo no reporta actividad
#       en N segundos, se mata y el pipeline continúa
#
#  Uso:
#    source core/watchdog.sh
#    watchdog_run <modulo> <timeout_segundos> <comando...>
#
#  O desde recon.sh:
#    run_module_safe "04_nuclei_scan" 1800   # max 30 min
# ============================================================

# ── Timeouts por defecto (segundos) ──────────────────────────
declare -A MODULE_TIMEOUTS=(
  [01_subdomain_enum]=600      # 10 min
  [02_dns_resolve]=300         # 5 min
  [03_takeover]=300            # 5 min
  [04_nuclei_scan]=1800        # 30 min
  [05_crawler]=600             # 10 min
  [06_active_scan]=1800        # 30 min
  [07_nuclei_urls]=1800        # 30 min
  [08_screenshots]=300         # 5 min
  [09_tech_detect]=300         # 5 min
  [10_tech_fingerprint]=600    # 10 min
  [11_js_analyzer]=600         # 10 min
  [12_login_finder]=600        # 10 min
  [13_port_scan]=900           # 15 min
  [14_breach_lookup]=120       # 2 min
  [15_param_discovery]=600     # 10 min
  [16_github_dorking]=300      # 5 min
  [17_cloud_enum]=600          # 10 min
  [18_asn_discovery]=900       # 15 min
  [19_auth_crawler]=900        # 15 min
  [20_smart_scan]=1800         # 30 min
  [21_business_logic]=600      # 10 min
  [22_cors_check]=600          # 10 min
  [23_403_bypass]=600          # 10 min
  [24_http_smuggling]=900      # 15 min
  [26_path_confusion]=1800    # 30 min
  [27_blind_xss]=1200        # 20 min
  [28_cache_attacks]=1800    # 30 min — cache poisoning + deception
  [DEFAULT]=600                # 10 min fallback
)

# ── Estado del watchdog ───────────────────────────────────────
WATCHDOG_LOG="${LOG_FILE:-/tmp/hackeadora_watchdog.log}"
WATCHDOG_PID_FILE="/tmp/hackeadora_watchdog_$$.pid"
WATCHDOG_ENABLED="${WATCHDOG_ENABLED:-true}"
MAX_CPU_PERCENT="${MAX_CPU_PERCENT:-90}"   # % CPU máximo por proceso
MAX_MEM_MB="${MAX_MEM_MB:-2048}"           # MB memoria máxima

# ── Registro de PIDs activos ──────────────────────────────────
declare -A ACTIVE_PIDS  # modulo → PID
declare -A START_TIMES  # modulo → timestamp inicio

# ── Logging del watchdog ──────────────────────────────────────
_wd_log() {
  local LEVEL="$1"; shift
  local MSG="$*"
  local TS
  TS=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[$TS] [WATCHDOG][$LEVEL] $MSG" >> "$WATCHDOG_LOG" 2>/dev/null || true
  [[ "$LEVEL" == "WARN" || "$LEVEL" == "ERROR" ]] && \
    echo -e "\033[1;33m[WD:$LEVEL]\033[0m $MSG"
}

# ── Obtener timeout para un módulo ───────────────────────────
_wd_get_timeout() {
  local MODULE="$1"
  local BASE
  BASE=$(echo "$MODULE" | cut -d'_' -f1-3)  # ej: 04_nuclei_scan

  # Primero buscar en config.env si hay override
  local CONFIG_KEY="TIMEOUT_${MODULE^^}"
  CONFIG_KEY="${CONFIG_KEY//[^A-Z0-9_]/_}"
  local OVERRIDE="${!CONFIG_KEY:-}"
  [[ -n "$OVERRIDE" ]] && echo "$OVERRIDE" && return

  # Luego en el mapa de defaults
  echo "${MODULE_TIMEOUTS[$BASE]:-${MODULE_TIMEOUTS[DEFAULT]}}"
}

# ── Matar un proceso y todos sus hijos ───────────────────────
_wd_kill_tree() {
  local PID="$1"
  local SIGNAL="${2:-TERM}"
  local REASON="${3:-timeout}"

  if [[ -z "$PID" ]] || ! kill -0 "$PID" 2>/dev/null; then
    return 0
  fi

  _wd_log "WARN" "Matando proceso $PID y descendientes (razón: $REASON)"

  # Obtener todos los descendientes
  local PIDS
  PIDS=$(pgrep -P "$PID" 2>/dev/null || true)

  # Matar hijos primero
  for CHILD in $PIDS; do
    _wd_kill_tree "$CHILD" "$SIGNAL" "$REASON"
  done

  # Matar el proceso padre
  kill -"$SIGNAL" "$PID" 2>/dev/null || true

  # Si sigue vivo tras 3s, SIGKILL
  sleep 3
  if kill -0 "$PID" 2>/dev/null; then
    _wd_log "WARN" "Proceso $PID no respondió a SIG$SIGNAL — enviando SIGKILL"
    kill -KILL "$PID" 2>/dev/null || true
  fi
}

# ── Monitor de CPU/memoria en background ─────────────────────
_wd_resource_monitor() {
  local PID="$1"
  local MODULE="$2"
  local TIMEOUT="$3"

  local START
  START=$(date +%s)

  while kill -0 "$PID" 2>/dev/null; do
    local NOW
    NOW=$(date +%s)
    local ELAPSED=$(( NOW - START ))

    # ── Check timeout ─────────────────────────────────────
    if [[ "$ELAPSED" -ge "$TIMEOUT" ]]; then
      _wd_log "WARN" "TIMEOUT: módulo $MODULE superó ${TIMEOUT}s — matando PID $PID"
      _wd_kill_tree "$PID" "TERM" "timeout_${TIMEOUT}s"

      # Notificar por Telegram si está disponible
      if type _telegram_send &>/dev/null 2>&1; then
        _telegram_send "⏰ *Watchdog — Timeout*
📦 Módulo: \`${MODULE}\`
⏱ Límite: \`${TIMEOUT}s\`
🔄 El pipeline continúa con el siguiente módulo
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
      fi
      return 1
    fi

    # ── Check CPU ─────────────────────────────────────────
    local CPU_PCT
    CPU_PCT=$(ps -p "$PID" -o %cpu --no-headers 2>/dev/null | tr -d ' ' | cut -d'.' -f1)
    if [[ -n "$CPU_PCT" && "$CPU_PCT" -gt "$MAX_CPU_PERCENT" ]]; then
      _wd_log "WARN" "CPU alta: módulo $MODULE al ${CPU_PCT}% (max ${MAX_CPU_PERCENT}%)"
      # No matar — solo advertir. Si persiste 60s más, entonces matar
    fi

    # ── Check memoria ──────────────────────────────────────
    local MEM_MB
    MEM_MB=$(ps -p "$PID" -o rss --no-headers 2>/dev/null | awk '{print int($1/1024)}')
    if [[ -n "$MEM_MB" && "$MEM_MB" -gt "$MAX_MEM_MB" ]]; then
      _wd_log "WARN" "Memoria excesiva: módulo $MODULE usa ${MEM_MB}MB (max ${MAX_MEM_MB}MB) — matando"
      _wd_kill_tree "$PID" "TERM" "memory_${MEM_MB}MB"

      if type _telegram_send &>/dev/null 2>&1; then
        _telegram_send "💾 *Watchdog — Memoria excesiva*
📦 Módulo: \`${MODULE}\`
💾 Uso: \`${MEM_MB}MB\` (límite: ${MAX_MEM_MB}MB)
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
      fi
      return 1
    fi

    sleep 10
  done

  return 0
}

# ── Ejecutar módulo con watchdog ──────────────────────────────
# Uso: watchdog_run <module_name> [timeout_override] -- <command>
watchdog_run() {
  local MODULE="$1"; shift
  local TIMEOUT

  # Timeout override opcional como segundo argumento
  if [[ "$1" =~ ^[0-9]+$ ]]; then
    TIMEOUT="$1"; shift
  else
    TIMEOUT=$(_wd_get_timeout "$MODULE")
  fi

  if [[ ! "$WATCHDOG_ENABLED" == "true" ]]; then
    # Watchdog desactivado — ejecutar directamente
    "$@"
    return $?
  fi

  _wd_log "INFO" "Iniciando $MODULE (timeout: ${TIMEOUT}s, max_cpu: ${MAX_CPU_PERCENT}%, max_mem: ${MAX_MEM_MB}MB)"

  local START
  START=$(date +%s)

  # Ejecutar en background
  "$@" &
  local PID=$!
  ACTIVE_PIDS[$MODULE]=$PID
  START_TIMES[$MODULE]=$START

  # Lanzar monitor de recursos en background
  _wd_resource_monitor "$PID" "$MODULE" "$TIMEOUT" &
  local MONITOR_PID=$!

  # Esperar a que termine el proceso principal
  local EXIT_CODE=0
  wait "$PID" 2>/dev/null || EXIT_CODE=$?

  # Matar el monitor
  kill "$MONITOR_PID" 2>/dev/null || true
  wait "$MONITOR_PID" 2>/dev/null || true

  # Limpiar
  unset ACTIVE_PIDS[$MODULE]
  unset START_TIMES[$MODULE]

  local END NOW ELAPSED
  END=$(date +%s)
  ELAPSED=$(( END - START ))

  if [[ "$EXIT_CODE" -eq 0 ]]; then
    _wd_log "INFO" "OK: $MODULE completado en ${ELAPSED}s"
  elif [[ "$EXIT_CODE" -eq 143 || "$EXIT_CODE" -eq 137 ]]; then
    # 143 = SIGTERM, 137 = SIGKILL
    _wd_log "WARN" "KILLED: $MODULE terminado por watchdog tras ${ELAPSED}s"
    EXIT_CODE=0  # No propagar el error — el pipeline continúa
  else
    _wd_log "WARN" "ERROR: $MODULE salió con código $EXIT_CODE tras ${ELAPSED}s"
  fi

  return $EXIT_CODE
}

# ── Trampa de salida — limpiar todos los procesos activos ─────
watchdog_cleanup() {
  _wd_log "INFO" "Limpieza watchdog — matando procesos activos..."
  for MODULE in "${!ACTIVE_PIDS[@]}"; do
    local PID="${ACTIVE_PIDS[$MODULE]}"
    _wd_log "WARN" "Limpiando proceso zombie: $MODULE (PID $PID)"
    _wd_kill_tree "$PID" "TERM" "pipeline_exit"
  done

  # Limpiar instancias AWS si el rotador está activo
  if [[ -f "$BASE_DIR/core/cloud_rotator.py" ]] && command -v python3 &>/dev/null; then
    python3 "$BASE_DIR/core/cloud_rotator.py" --cleanup 2>/dev/null || true
  fi

  rm -f "$WATCHDOG_PID_FILE"
}

# ── Estado del watchdog ───────────────────────────────────────
watchdog_status() {
  echo "Watchdog activo. Procesos monitorizados:"
  if [[ ${#ACTIVE_PIDS[@]} -eq 0 ]]; then
    echo "  Sin procesos activos"
    return
  fi
  for MODULE in "${!ACTIVE_PIDS[@]}"; do
    local PID="${ACTIVE_PIDS[$MODULE]}"
    local START="${START_TIMES[$MODULE]}"
    local ELAPSED=$(( $(date +%s) - START ))
    local TIMEOUT
    TIMEOUT=$(_wd_get_timeout "$MODULE")
    echo "  $MODULE — PID $PID — ${ELAPSED}s / ${TIMEOUT}s"
  done
}

# ── Registrar trampas al hacer source ────────────────────────
trap watchdog_cleanup EXIT INT TERM

_wd_log "INFO" "Watchdog cargado (timeouts configurados para ${#MODULE_TIMEOUTS[@]} módulos)"
