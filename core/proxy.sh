#!/usr/bin/env bash
# ============================================================
#  core/proxy.sh — Configuración de proxy pasivo
#  Soporta: Caido (puerto 8181), Burp Suite (puerto 8080)
#           y SOCKS5 vía SSH (--socks-proxy)
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

# ── SOCKS5 vía SSH ────────────────────────────────────────────
SOCKS_PORT="${SOCKS_PORT:-9050}"
SOCKS_ACTIVE=false
PROXYCHAINS_CMD=""

_socks_write_conf() {
  cat > /tmp/proxychains_hackeadora.conf << 'EOF'
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
quiet_mode

[ProxyList]
socks5 127.0.0.1 9050
EOF
}

socks_tunnel_start() {
  local HOST="$1"
  local PORT="${SOCKS_PORT}"
  local PASS="${SOCKS_PROXY_PASS:-}"

  pkill -f "ssh -D ${PORT}" 2>/dev/null || true
  sleep 0.5

  _socks_write_conf

  log_info "Levantando túnel SOCKS5 → root@${HOST}:${PORT}..."
  if [[ -n "$PASS" ]]; then
    sshpass -p "$PASS" ssh -D "${PORT}" -N \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        -o ServerAliveInterval=60 \
        "root@${HOST}" & disown
  else
    ssh -D "${PORT}" -N \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        -o ServerAliveInterval=60 \
        "root@${HOST}" & disown
  fi
  sleep 2

  local SSH_PID
  SSH_PID=$(pgrep -f "ssh -D ${PORT}" | head -1)
  if [[ -n "$SSH_PID" ]] && kill -0 "$SSH_PID" 2>/dev/null; then
    SOCKS_ACTIVE=true
    export PROXYCHAINS_CMD="proxychains4 -f /tmp/proxychains_hackeadora.conf"
    export http_proxy="socks5://127.0.0.1:${PORT}"
    export https_proxy="socks5://127.0.0.1:${PORT}"
    export HTTP_PROXY="socks5://127.0.0.1:${PORT}"
    export HTTPS_PROXY="socks5://127.0.0.1:${PORT}"
    # Telegram y localhost van directo, sin pasar por el proxy
    export no_proxy="127.0.0.1,localhost,api.telegram.org"
    export NO_PROXY="127.0.0.1,localhost,api.telegram.org"
    log_ok "SOCKS5 activo — tráfico HTTP y DNS enrutado por ${HOST}"
  else
    log_warn "No se pudo establecer túnel SOCKS5 — continuando sin proxy"
    SOCKS_ACTIVE=false
  fi
}

socks_tunnel_stop() {
  pkill -f "ssh -D ${SOCKS_PORT}" 2>/dev/null || true
  SOCKS_ACTIVE=false
  PROXYCHAINS_CMD=""
  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY PROXYCHAINS_CMD
  log_info "Túnel SOCKS5 detenido"
}
