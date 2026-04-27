#!/usr/bin/env bash
# ============================================================
#  core/proxy.sh — Configuración de proxy pasivo
#  Soporta: Caido (puerto 8181) y Burp Suite (puerto 8080)
#  Se incluye con: source core/proxy.sh
# ============================================================

# ── Detectar proxy activo ─────────────────────────────────────
PROXY_TOOL="${PROXY_TOOL:-caido}"   # caido | burp | none
PROXY_HOST="${PROXY_HOST:-caido}"   # hostname dentro de Docker
PROXY_PORT="${PROXY_PORT:-8181}"
PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"

# Burp por defecto usa 8080
if [[ "${PROXY_TOOL}" == "burp" ]]; then
  PROXY_PORT="${PROXY_PORT:-8080}"
  PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"
fi

# ── Verificar que el proxy responde ──────────────────────────
proxy_is_up() {
  curl -s --max-time 3 \
    --proxy "$PROXY_URL" \
    "http://example.com" \
    -o /dev/null 2>/dev/null
  return $?
}

proxy_check() {
  if [[ "${PROXY_TOOL}" == "none" ]]; then
    log_info "Proxy desactivado (PROXY_TOOL=none)"
    PROXY_ACTIVE=false
    return
  fi

  if proxy_is_up; then
    log_ok "Proxy ${PROXY_TOOL} activo en ${PROXY_URL}"
    PROXY_ACTIVE=true
  else
    log_warn "Proxy ${PROXY_TOOL} NO responde en ${PROXY_URL} — continuando sin proxy"
    PROXY_ACTIVE=false
  fi
}

# ── Flags para cada herramienta ───────────────────────────────
# Uso: katana ${KATANA_PROXY_FLAGS[@]} ...
proxy_flags_katana()   { $PROXY_ACTIVE && echo "-proxy ${PROXY_URL}" || echo ""; }
proxy_flags_gospider() { $PROXY_ACTIVE && echo "--proxy ${PROXY_URL}" || echo ""; }
proxy_flags_ffuf()     { $PROXY_ACTIVE && echo "-replay-proxy ${PROXY_URL}" || echo ""; }
proxy_flags_curl()     { $PROXY_ACTIVE && echo "--proxy ${PROXY_URL}" || echo ""; }
proxy_flags_httpx()    { $PROXY_ACTIVE && echo "-http-proxy ${PROXY_URL}" || echo ""; }
proxy_flags_nuclei()   { $PROXY_ACTIVE && echo "-proxy ${PROXY_URL}" || echo ""; }

# Variable de entorno estándar (la recogen la mayoría de tools)
proxy_export_env() {
  if $PROXY_ACTIVE; then
    export http_proxy="$PROXY_URL"
    export https_proxy="$PROXY_URL"
    export HTTP_PROXY="$PROXY_URL"
    export HTTPS_PROXY="$PROXY_URL"
    # Sin proxy para localhost
    export no_proxy="127.0.0.1,localhost"
    export NO_PROXY="127.0.0.1,localhost"
    log_info "Proxy exportado al entorno: ${PROXY_URL}"
  fi
}

proxy_unexport_env() {
  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY
}

# Inicializar al hacer source
PROXY_ACTIVE=false
