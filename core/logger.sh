#!/usr/bin/env bash
# ============================================================
#  core/logger.sh — Sistema de logging centralizado
#  Se incluye con: source core/logger.sh
# ============================================================

# Niveles: DEBUG=0 INFO=1 WARN=2 ERROR=3
declare -A _LOG_LEVELS=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3)
_LOG_LEVEL_NUM="${_LOG_LEVELS[${LOG_LEVEL:-INFO}]}"

# Colores
_L_DEBUG='\033[0;35m'
_L_INFO='\033[0;36m'
_L_WARN='\033[1;33m'
_L_ERROR='\033[0;31m'
_L_OK='\033[0;32m'
_L_RESET='\033[0m'
_L_BOLD='\033[1m'

# LOG_FILE debe estar definido antes de hacer source de este archivo
# o se usará /tmp/recon.log como fallback
LOG_FILE="${LOG_FILE:-/tmp/recon.log}"

_log() {
  local LEVEL="$1"; shift
  local MSG="$*"
  local LEVEL_NUM="${_LOG_LEVELS[$LEVEL]:-1}"
  local TIMESTAMP
  TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"
  local COLOR_VAR="_L_${LEVEL}"
  local COLOR="${!COLOR_VAR:-}"

  # Siempre escribir al archivo (sin colores)
  echo "[$TIMESTAMP] [$LEVEL] $MSG" >> "$LOG_FILE" 2>/dev/null || true

  # Mostrar en consola solo si nivel >= configurado
  if [[ $LEVEL_NUM -ge $_LOG_LEVEL_NUM ]]; then
    echo -e "${COLOR}[${LEVEL:0:1}]${_L_RESET} ${MSG}"
  fi
}

log_debug() { _log "DEBUG" "$@"; }
log_info()  { _log "INFO"  "$@"; }
log_warn()  { _log "WARN"  "$@"; }
log_error() { _log "ERROR" "$@"; }
log_ok()    { echo -e "${_L_OK}[✓]${_L_RESET} $*"; echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OK] $*" >> "$LOG_FILE" 2>/dev/null || true; }

# Separador de fase
log_phase() {
  local MSG="$*"
  echo -e "\n${_L_BOLD}${_L_INFO}══════════════════════════════════════${_L_RESET}"
  echo -e "${_L_BOLD}  ⟶  ${MSG}${_L_RESET}"
  echo -e "${_L_BOLD}${_L_INFO}══════════════════════════════════════${_L_RESET}\n"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [PHASE] $MSG" >> "$LOG_FILE" 2>/dev/null || true
}
