#!/usr/bin/env bash
# ============================================================
#  core/rotator.sh — Wrapper bash para rotación de IPs
#  Se incluye con: source core/rotator.sh
#
#  Funciones disponibles:
#    rotator_enabled      → true/false
#    rotator_exec         → ejecutar comando en instancia remota
#    rotator_should_rotate → comprueba si toca rotar
#    rotator_increment    → incrementa contador de peticiones
# ============================================================

# ── Estado del rotador ────────────────────────────────────────
ROTATOR_ENABLED=false
ROTATOR_REQUEST_COUNT=0
ROTATOR_INTERVAL="${ROTATION_INTERVAL:-500}"
ROTATOR_SCRIPT="$(dirname "$0")/../core/cloud_rotator.py"
ROTATOR_STATE_FILE="$(dirname "$0")/../data/rotator_state.json"

# ── Inicializar ───────────────────────────────────────────────
rotator_init() {
  # Verificar si está configurado
  if [[ -z "${AWS_ACCESS_KEY_ID:-}" ]] || [[ -z "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
    log_debug "Rotador desactivado (sin credenciales AWS)"
    ROTATOR_ENABLED=false
    return
  fi

  if ! command -v python3 &>/dev/null; then
    ROTATOR_ENABLED=false
    return
  fi

  # Verificar boto3
  if ! python3 -c "import boto3" 2>/dev/null; then
    log_warn "boto3 no instalado — rotador desactivado. Instala: pip3 install boto3"
    ROTATOR_ENABLED=false
    return
  fi

  ROTATOR_ENABLED=true

  # Leer contador actual
  if [[ -f "$ROTATOR_STATE_FILE" ]]; then
    ROTATOR_REQUEST_COUNT=$(python3 -c \
      "import json; d=json.load(open('${ROTATOR_STATE_FILE}')); print(d.get('request_count',0))" \
      2>/dev/null || echo 0)
  fi

  log_info "Rotador de IPs activado (intervalo: ${ROTATOR_INTERVAL} peticiones)"
}

rotator_enabled() {
  $ROTATOR_ENABLED
}

# ── Incrementar contador ──────────────────────────────────────
rotator_increment() {
  local N="${1:-1}"
  ((ROTATOR_REQUEST_COUNT += N))

  # Persistir en el state file
  python3 -c "
import json
try:
    f = '${ROTATOR_STATE_FILE}'
    d = json.load(open(f)) if __import__('os').path.exists(f) else {}
    d['request_count'] = ${ROTATOR_REQUEST_COUNT}
    json.dump(d, open(f,'w'), indent=2)
except: pass
" 2>/dev/null || true
}

# ── ¿Toca rotar? ──────────────────────────────────────────────
rotator_should_rotate() {
  $ROTATOR_ENABLED || return 1
  [[ $ROTATOR_REQUEST_COUNT -gt 0 ]] && \
  [[ $(( ROTATOR_REQUEST_COUNT % ROTATOR_INTERVAL )) -eq 0 ]]
}

# ── Ejecutar comando en instancia remota ─────────────────────
# Uso: rotator_exec "nuclei -l targets.txt -o /tmp/out.json" "/tmp/out.json"
rotator_exec() {
  local CMD="$1"
  local COLLECT="${2:-}"

  if ! $ROTATOR_ENABLED; then
    log_debug "Rotador inactivo — ejecutando localmente"
    eval "$CMD"
    return $?
  fi

  log_info "Rotador: ejecutando desde nueva IP en AWS..."
  log_info "Comando: ${CMD:0:80}..."

  local PYTHON_ARGS=("--exec" "$CMD")
  [[ -n "$COLLECT" ]] && PYTHON_ARGS+=("--collect" "$COLLECT")
  [[ -n "${AWS_AMI_ID:-}" ]] && PYTHON_ARGS+=("--no-bootstrap")

  if python3 "$ROTATOR_SCRIPT" "${PYTHON_ARGS[@]}"; then
    log_ok "Rotador: ejecución remota completada"
    rotator_increment 1
    return 0
  else
    log_warn "Rotador: ejecución remota falló — fallback a local"
    eval "$CMD"
    return $?
  fi
}

# ── Test de conectividad ──────────────────────────────────────
rotator_test() {
  python3 "$ROTATOR_SCRIPT" --test
}

# Inicializar al hacer source
rotator_init
