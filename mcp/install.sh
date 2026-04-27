#!/usr/bin/env bash
# ============================================================
#  mcp/install.sh — Instalador de servidores MCP de Hackeadora
#  Autores: Claude (Anthropic) & Antonio Fernandes
#
#  Instala y configura los 5 MCP servers externos:
#    - filesystem  :3001
#    - github      :3002
#    - playwright  :3003
#    - telegram    :3004
#    - nvd         :3005
#
#  Uso: sudo bash mcp/install.sh
# ============================================================

set -euo pipefail

MCP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$MCP_DIR")"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()    { echo -e "${GREEN}[✓]${RESET} $*"; }
info()  { echo -e "${CYAN}[→]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
fail()  { echo -e "${RED}[✗]${RESET} $*"; exit 1; }
title() { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

# ── Detectar usuario no-root para instalar servicios ─────────
INSTALL_USER="${SUDO_USER:-$(whoami)}"
INSTALL_HOME=$(eval echo "~${INSTALL_USER}")

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════╗"
echo "║   Hackeadora — MCP Servers Installer     ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${RESET}"

[[ "$(id -u)" -ne 0 ]] && fail "Ejecuta con sudo"

# ── 1. Node.js ────────────────────────────────────────────────
title "Node.js"
if command -v node &>/dev/null; then
  NODE_VER=$(node --version)
  ok "Node.js ya instalado: $NODE_VER"
  # Verificar versión mínima (18)
  NODE_MAJOR=$(echo "$NODE_VER" | tr -d 'v' | cut -d'.' -f1)
  if [[ "$NODE_MAJOR" -lt 18 ]]; then
    warn "Node.js $NODE_VER es demasiado antiguo. Instalando Node.js 20..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
  fi
else
  info "Instalando Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
  ok "Node.js instalado: $(node --version)"
fi

# ── 2. Playwright system dependencies ────────────────────────
title "Playwright dependencies"
info "Instalando dependencias de sistema para Playwright..."
apt-get install -y \
  libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
  libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 \
  libxfixes3 libxrandr2 libgbm1 libasound2 \
  libxss1 libgtk-3-0 2>/dev/null || true
ok "Dependencias de Playwright instaladas"

# ── 3. Instalar dependencias npm de cada MCP ─────────────────
title "Dependencias npm"
for SRV in filesystem github playwright telegram nvd; do
  info "npm install — $SRV..."
  cd "$MCP_DIR/$SRV"
  su -c "npm install --silent" "$INSTALL_USER" 2>/dev/null || \
    npm install --silent
  ok "$SRV — dependencias instaladas"
done

# ── 4. Playwright browsers ────────────────────────────────────
title "Playwright browsers"
info "Instalando Chromium para Playwright..."
cd "$MCP_DIR/playwright"
su -c "npx playwright install chromium" "$INSTALL_USER" 2>/dev/null || \
  npx playwright install chromium
ok "Chromium instalado"

# ── 5. Pedir configuración ────────────────────────────────────
title "Configuración"

# Leer variables existentes del .env si existe
ENV_FILE="$ROOT/.env"
[[ ! -f "$ENV_FILE" ]] && ENV_FILE="$ROOT/config.env"

get_env() {
  local KEY="$1" DEFAULT="${2:-}"
  grep -oP "(?<=^${KEY}=).+" "$ENV_FILE" 2>/dev/null | head -1 || echo "$DEFAULT"
}

HACKEADORA_OUTPUT=$(get_env "OUTPUT_BASE" "$ROOT/output")
HACKEADORA_DATA=$(get_env "DB_PATH"    "$ROOT/data")
HACKEADORA_DATA=$(dirname "$HACKEADORA_DATA" 2>/dev/null || echo "$ROOT/data")
TELEGRAM_BOT=$(get_env "TELEGRAM_BOT_TOKEN" "")
TELEGRAM_CHAT=$(get_env "TELEGRAM_CHAT_ID"  "")
GITHUB_TOKEN=$(get_env "GITHUB_TOKEN"        "")
PROXY_URL=$(get_env "PROXY_URL"              "")

echo ""
echo -e "${CYAN}[?] Directorios de Hackeadora${RESET}"
echo -e "    Output dir (${HACKEADORA_OUTPUT}):"
read -r INPUT_OUTPUT
HACKEADORA_OUTPUT="${INPUT_OUTPUT:-$HACKEADORA_OUTPUT}"

echo -e "    Data dir (${HACKEADORA_DATA}):"
read -r INPUT_DATA
HACKEADORA_DATA="${INPUT_DATA:-$HACKEADORA_DATA}"

echo ""
echo -e "${CYAN}[?] NVD API Key (opcional, para más rate limit)${RESET}"
echo -e "    Obtén una gratis en: https://nvd.nist.gov/developers/request-an-api-key"
echo -e "    Deja vacío para usar sin key (más lento):"
read -rs NVD_API_KEY
echo ""

# ── 6. Crear archivo de configuración de MCPs ────────────────
title "Archivo de configuración"
cat > "$MCP_DIR/mcp.env" << ENVEOF
# ============================================================
#  Hackeadora MCP Servers — Configuración
#  Generado por install.sh
# ============================================================

# Directorios de Hackeadora
HACKEADORA_OUTPUT=${HACKEADORA_OUTPUT}
HACKEADORA_DATA=${HACKEADORA_DATA}

# Tokens (copiados del .env principal)
TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT}
TELEGRAM_CHAT_ID=${TELEGRAM_CHAT}
GITHUB_TOKEN=${GITHUB_TOKEN}

# Proxy Caido/Burp para Playwright
HACKEADORA_PROXY=${PROXY_URL}

# NVD API Key (opcional)
NVD_API_KEY=${NVD_API_KEY}

# Puertos de los servidores MCP
MCP_FILESYSTEM_PORT=3001
MCP_GITHUB_PORT=3002
MCP_PLAYWRIGHT_PORT=3003
MCP_TELEGRAM_PORT=3004
MCP_NVD_PORT=3005
ENVEOF
chmod 600 "$MCP_DIR/mcp.env"
chown "$INSTALL_USER:$INSTALL_USER" "$MCP_DIR/mcp.env"
ok "mcp.env creado"

# ── 7. Crear servicios systemd ────────────────────────────────
title "Servicios systemd"

declare -A MCP_PORTS=(
  [filesystem]=3001
  [github]=3002
  [playwright]=3003
  [telegram]=3004
  [nvd]=3005
)

for SRV in filesystem github playwright telegram nvd; do
  PORT="${MCP_PORTS[$SRV]}"
  SERVICE="hackeadora-mcp-${SRV}"

  cat > "/etc/systemd/system/${SERVICE}.service" << SVCEOF
[Unit]
Description=Hackeadora MCP Server — ${SRV}
After=network.target
Wants=network.target

[Service]
Type=simple
User=${INSTALL_USER}
WorkingDirectory=${MCP_DIR}/${SRV}
EnvironmentFile=${MCP_DIR}/mcp.env
ExecStart=/usr/bin/node ${MCP_DIR}/${SRV}/index.js
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hackeadora-mcp-${SRV}

# Permisos de acceso a directorios de Hackeadora
ReadOnlyPaths=${HACKEADORA_OUTPUT}
ReadOnlyPaths=${HACKEADORA_DATA}

[Install]
WantedBy=multi-user.target
SVCEOF

  systemctl daemon-reload
  systemctl enable "$SERVICE" 2>/dev/null || true
  systemctl restart "$SERVICE" 2>/dev/null || true

  # Verificar que arrancó
  sleep 1
  if systemctl is-active --quiet "$SERVICE"; then
    ok "$SERVICE arrancado (puerto $PORT)"
  else
    warn "$SERVICE — problemas al arrancar. Ver: journalctl -u $SERVICE -n 20"
  fi
done

# ── 8. Crear script de estado ─────────────────────────────────
cat > "$MCP_DIR/status.sh" << 'STATUSEOF'
#!/usr/bin/env bash
echo "═══════════════════════════════════"
echo "  Hackeadora MCP Servers — Status"
echo "═══════════════════════════════════"
for SRV in filesystem github playwright telegram nvd; do
  STATUS=$(systemctl is-active "hackeadora-mcp-${SRV}" 2>/dev/null || echo "inactive")
  COLOR="\033[0;32m"; [[ "$STATUS" != "active" ]] && COLOR="\033[0;31m"
  echo -e "  ${COLOR}${STATUS}\033[0m — hackeadora-mcp-${SRV}"
done
echo ""
echo "Logs: journalctl -u hackeadora-mcp-<nombre> -f"
echo "Stop: sudo systemctl stop hackeadora-mcp-<nombre>"
STATUSEOF
chmod +x "$MCP_DIR/status.sh"
chown "$INSTALL_USER:$INSTALL_USER" "$MCP_DIR/status.sh"

# ── 9. Actualizar ai_advisor.py con config de MCPs ───────────
title "Integrando MCPs con AI Advisor"
MCP_CONFIG_FILE="$ROOT/core/mcp_config.json"
cat > "$MCP_CONFIG_FILE" << MCPEOF
{
  "mcpServers": {
    "hackeadora-filesystem": {
      "command": "node",
      "args": ["${MCP_DIR}/filesystem/index.js"],
      "env": {
        "HACKEADORA_OUTPUT": "${HACKEADORA_OUTPUT}",
        "HACKEADORA_DATA":   "${HACKEADORA_DATA}"
      }
    },
    "hackeadora-github": {
      "command": "node",
      "args": ["${MCP_DIR}/github/index.js"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    },
    "hackeadora-playwright": {
      "command": "node",
      "args": ["${MCP_DIR}/playwright/index.js"],
      "env": {
        "HACKEADORA_PROXY": "${PROXY_URL}"
      }
    },
    "hackeadora-telegram": {
      "command": "node",
      "args": ["${MCP_DIR}/telegram/index.js"],
      "env": {
        "TELEGRAM_BOT_TOKEN": "${TELEGRAM_BOT}",
        "TELEGRAM_CHAT_ID":   "${TELEGRAM_CHAT}"
      }
    },
    "hackeadora-nvd": {
      "command": "node",
      "args": ["${MCP_DIR}/nvd/index.js"],
      "env": {
        "NVD_API_KEY": "${NVD_API_KEY}"
      }
    }
  }
}
MCPEOF
chown "$INSTALL_USER:$INSTALL_USER" "$MCP_CONFIG_FILE"
ok "mcp_config.json creado"

# ── 10. Resumen final ─────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║   MCP Servers instalados correctamente   ║${RESET}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════╝${RESET}"
echo ""
echo "  Estado:    bash mcp/status.sh"
echo "  Logs:      journalctl -u hackeadora-mcp-filesystem -f"
echo "  Config:    mcp/mcp.env"
echo ""
echo -e "  ${CYAN}Servidores activos:${RESET}"
echo "    filesystem  → node mcp/filesystem/index.js  (lee outputs de Hackeadora)"
echo "    github      → node mcp/github/index.js      (repos públicos + dorking)"
echo "    playwright  → node mcp/playwright/index.js  (navegador real + login)"
echo "    telegram    → node mcp/telegram/index.js    (notificaciones ricas)"
echo "    nvd         → node mcp/nvd/index.js         (CVEs por tech/versión)"
echo ""
echo -e "  ${YELLOW}Para usar con Claude Code:${RESET}"
echo "    claude --mcp-config core/mcp_config.json"
