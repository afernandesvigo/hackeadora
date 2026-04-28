#!/usr/bin/env bash
# ============================================================
#  Hackeadora — Quickstart
#  Autores: Claude (Anthropic) & Antonio Fernandes
# ============================================================
set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'; BOLD='\033[1m'

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════╗"
echo "║   🕵️  Hackeadora — Quickstart        ║"
echo "╚══════════════════════════════════════╝"
echo -e "${RESET}"

# Verificar dependencias del host
command -v docker        &>/dev/null || { echo "❌ Docker no instalado"; exit 1; }
command -v docker compose &>/dev/null || { echo "❌ Docker Compose no instalado (v2 requerido)"; exit 1; }

# Config
if [[ ! -f .env ]]; then
  cp .env.example .env
  echo -e "${YELLOW}[!] Edita .env con tu token de Telegram antes de continuar${RESET}"
  echo -e "    ${CYAN}nano .env${RESET}"
  exit 0
fi

# Targets
if [[ ! -f data/targets.txt ]]; then
  mkdir -p data
  echo -e "${YELLOW}[!] Añade dominios a data/targets.txt (uno por línea)${RESET}"
  echo "ejemplo.com" > data/targets.txt
  echo -e "    ${CYAN}nano data/targets.txt${RESET}"
fi

echo -e "${GREEN}[→]${RESET} Construyendo imágenes (primera vez tarda ~10 min)..."
docker compose build

echo -e "${GREEN}[→]${RESET} Arrancando servicios..."
docker compose up -d

echo ""
echo -e "${GREEN}✓ Hackeadora corriendo${RESET}"
echo -e "  Dashboard : ${CYAN}http://localhost:8080${RESET}"
echo -e "  Caido UI  : ${CYAN}http://localhost:7070${RESET}"
echo -e "  Targets   : ${CYAN}data/targets.txt${RESET}"
echo ""
echo -e "Logs: ${CYAN}docker compose logs -f${RESET}"
echo -e "Stop: ${CYAN}docker compose down${RESET}"
