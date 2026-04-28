#!/usr/bin/env bash
# ============================================================
#  Hackeadora — Instalador
#  Uso:
#    bash install.sh            → herramientas core (~5 min)
#    bash install.sh --full     → todo, incluyendo opcionales
#    bash install.sh --check    → verificar instalación
#    bash install.sh --go-only  → solo instalar Go
# ============================================================

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$HOME/.local/bin"
GO_VERSION="1.22.4"

FULL=false
CHECK_ONLY=false
GO_ONLY=false

for arg in "$@"; do
  case "$arg" in
    --full)      FULL=true ;;
    --check)     CHECK_ONLY=true ;;
    --go-only)   GO_ONLY=true ;;
    --help|-h)
      sed -n '2,6p' "$0" | sed 's/^#  \?//'
      exit 0 ;;
  esac
done

# ── Colores ──────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()    { echo -e "${GREEN}[✓]${RESET} $*"; }
info()  { echo -e "${CYAN}[→]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
fail()  { echo -e "${RED}[✗]${RESET} $*"; exit 1; }
title() { echo -e "\n${BOLD}${CYAN}── $* ──${RESET}"; }

# ── Detectar distro ──────────────────────────────────────────
detect_distro() {
  if   command -v apt-get &>/dev/null; then echo "debian"
  elif command -v dnf     &>/dev/null; then echo "fedora"
  elif command -v pacman  &>/dev/null; then echo "arch"
  else fail "Distro no soportada. Instala manualmente: git curl wget unzip python3 sqlite3 jq"
  fi
}

# ── Paquetes del sistema ──────────────────────────────────────
install_system_packages() {
  title "Paquetes del sistema"
  local DISTRO
  DISTRO=$(detect_distro)
  local PKGS="git curl wget unzip tar python3 python3-pip sqlite3 jq make gcc"

  case "$DISTRO" in
    debian)
      info "apt-get update..."
      apt-get update -qq
      apt-get install -y $PKGS build-essential libpcap-dev 2>/dev/null
      ;;
    fedora)
      dnf install -y $PKGS gcc libpcap-devel 2>/dev/null ;;
    arch)
      pacman -Sy --noconfirm $PKGS libpcap 2>/dev/null ;;
  esac
  ok "Paquetes del sistema listos"
}

# ── Go ────────────────────────────────────────────────────────
install_go() {
  title "Go $GO_VERSION"

  if command -v go &>/dev/null; then
    local CURRENT
    CURRENT=$(go version | awk '{print $3}' | sed 's/go//')
    if [[ "$(printf '%s\n' "$GO_VERSION" "$CURRENT" | sort -V | head -1)" == "$GO_VERSION" ]]; then
      ok "Go $CURRENT ya instalado"
      return
    fi
    warn "Actualizando Go a $GO_VERSION..."
  fi

  local ARCH
  ARCH=$(uname -m)
  [[ "$ARCH" == "x86_64" ]]  && ARCH="amd64"
  [[ "$ARCH" == "aarch64" ]] && ARCH="arm64"

  local TARBALL="go${GO_VERSION}.linux-${ARCH}.tar.gz"
  info "Descargando Go $GO_VERSION..."
  wget -q --show-progress "https://go.dev/dl/$TARBALL" -O "/tmp/$TARBALL"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "/tmp/$TARBALL"
  rm "/tmp/$TARBALL"

  if ! grep -q '/usr/local/go/bin' /etc/profile.d/go.sh 2>/dev/null; then
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' > /etc/profile.d/go.sh
    chmod +x /etc/profile.d/go.sh
  fi

  export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
  ok "Go $GO_VERSION instalado"
}

# ── Helper: instalar herramienta Go ──────────────────────────
install_go_tool() {
  local NAME="$1"
  local PKG="$2"
  local BIN="${3:-$NAME}"

  if command -v "$BIN" &>/dev/null; then
    ok "$NAME ya instalado"
    return
  fi

  info "Instalando $NAME..."
  if go install "$PKG" 2>/dev/null; then
    [[ -f "$HOME/go/bin/$BIN" ]] && cp "$HOME/go/bin/$BIN" "$INSTALL_DIR/" 2>/dev/null || true
    ok "$NAME instalado"
  else
    warn "$NAME: fallo en instalación, continúa..."
  fi
}

# ── Herramientas core (esenciales para el pipeline básico) ───
install_core_tools() {
  title "Herramientas core"
  mkdir -p "$INSTALL_DIR"
  export PATH="$PATH:$INSTALL_DIR:/usr/local/go/bin:$HOME/go/bin"

  # Subdominios
  install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"

  # Resolución / HTTP
  install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  install_go_tool "dnsx"  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"

  # Takeover
  install_go_tool "subzy"   "github.com/PentestPad/subzy@latest"
  install_go_tool "subjack" "github.com/haccer/subjack@latest"

  # Nuclei (scanner principal)
  install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

  # Crawling / URLs
  install_go_tool "katana"      "github.com/projectdiscovery/katana/cmd/katana@latest"
  install_go_tool "gau"         "github.com/lc/gau/v2/cmd/gau@latest"
  install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"

  # Fuzzing
  install_go_tool "ffuf" "github.com/ffuf/ffuf/v2@latest"

  # Utils
  install_go_tool "anew"      "github.com/tomnomnom/anew@latest"
  install_go_tool "qsreplace" "github.com/tomnomnom/qsreplace@latest"
  install_go_tool "unfurl"    "github.com/tomnomnom/unfurl@latest"
  install_go_tool "gowitness" "github.com/sensepost/gowitness@latest"
}

# ── Herramientas opcionales (--full) ─────────────────────────
install_full_tools() {
  title "Herramientas opcionales (--full)"
  export PATH="$PATH:$INSTALL_DIR:/usr/local/go/bin:$HOME/go/bin"

  # Enumeración avanzada
  install_go_tool "amass"      "github.com/owasp-amass/amass/v4/...@master"
  install_go_tool "asnmap"     "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
  install_go_tool "mapcidr"    "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"

  # Crawling extra
  install_go_tool "hakrawler" "github.com/hakluke/hakrawler@latest"
  install_go_tool "gospider"  "github.com/jaeles-project/gospider@latest"

  # Tech detect / secrets
  install_go_tool "webanalyze" "github.com/rverton/webanalyze/cmd/webanalyze@latest"
  install_go_tool "trufflehog" "github.com/trufflesecurity/trufflehog/v3@latest"

  # whatweb
  if ! command -v whatweb &>/dev/null; then
    local DISTRO
    DISTRO=$(detect_distro)
    case "$DISTRO" in
      debian) apt-get install -y whatweb 2>/dev/null && ok "whatweb instalado" || warn "whatweb: instala manualmente" ;;
      fedora) dnf install -y whatweb 2>/dev/null && ok "whatweb instalado" || warn "whatweb: instala manualmente" ;;
      arch)   pacman -Sy --noconfirm whatweb 2>/dev/null && ok "whatweb instalado" || warn "whatweb: instala manualmente" ;;
    esac
  else
    ok "whatweb ya instalado"
  fi

  # masscan
  if ! command -v masscan &>/dev/null; then
    info "Compilando masscan desde fuente..."
    apt-get install -y libpcap-dev 2>/dev/null || true
    git clone -q https://github.com/robertdavidgraham/masscan /tmp/masscan_src
    make -C /tmp/masscan_src -j"$(nproc)" 2>/dev/null
    cp /tmp/masscan_src/bin/masscan "$INSTALL_DIR/"
    rm -rf /tmp/masscan_src
    ok "masscan instalado"
  else
    ok "masscan ya instalado"
  fi

  # bbot
  if ! command -v bbot &>/dev/null; then
    pip3 install bbot --break-system-packages -q 2>/dev/null \
      || pip3 install bbot -q 2>/dev/null \
      || warn "bbot: instala manualmente con pip3"
    ok "bbot instalado"
  else
    ok "bbot ya instalado"
  fi

  # cloud_enum
  if ! command -v cloud_enum &>/dev/null && [[ ! -f /usr/local/bin/cloud_enum ]]; then
    git clone -q https://github.com/initstring/cloud_enum.git /opt/cloud_enum 2>/dev/null \
      && ln -sf /opt/cloud_enum/cloud_enum.py /usr/local/bin/cloud_enum \
      && pip3 install --break-system-packages -r /opt/cloud_enum/requirements.txt -q 2>/dev/null \
      && ok "cloud_enum instalado" \
      || warn "cloud_enum: instala manualmente"
  else
    ok "cloud_enum ya instalado"
  fi

  # SecretFinder
  local SF_DIR="$HOME/tools/SecretFinder"
  if [[ ! -d "$SF_DIR" ]]; then
    git clone -q https://github.com/m4ll0k/SecretFinder.git "$SF_DIR" 2>/dev/null \
      && pip3 install --break-system-packages -r "$SF_DIR/requirements.txt" -q 2>/dev/null \
      && ok "SecretFinder instalado" \
      || warn "SecretFinder: instala manualmente"
  else
    ok "SecretFinder ya instalado"
  fi

  # paramspider + arjun
  pip3 install paramspider arjun --break-system-packages -q 2>/dev/null || true
  ok "paramspider y arjun instalados"
}

# ── Python deps ───────────────────────────────────────────────
install_python_deps() {
  title "Python"
  pip3 install requests fastapi uvicorn cryptography --break-system-packages -q 2>/dev/null \
    || pip3 install requests fastapi uvicorn cryptography -q 2>/dev/null \
    || true
  ok "Dependencias Python instaladas"

  local KB="$ROOT/core/knowledge_base.json"
  if [[ -f "$KB" ]]; then
    local VULN_COUNT
    VULN_COUNT=$(python3 -c "import json; kb=json.load(open('$KB')); print(len(kb.get('vulnerabilities',[])))" 2>/dev/null || echo "?")
    ok "Knowledge Base: $VULN_COUNT vulnerabilidades"
  else
    warn "knowledge_base.json no encontrada en core/"
  fi
}

# ── Nuclei templates ──────────────────────────────────────────
update_nuclei_templates() {
  title "Nuclei templates"
  if command -v nuclei &>/dev/null; then
    info "Actualizando templates..."
    nuclei -update-templates -silent 2>/dev/null && ok "Templates actualizados" || warn "Templates: fallo en actualización"
  else
    warn "nuclei no disponible, saltando templates"
  fi
}

# ── Estructura del proyecto ───────────────────────────────────
setup_project() {
  title "Estructura del proyecto"
  mkdir -p "$ROOT/data" "$ROOT/output"
  ok "Directorios data/ y output/ listos"

  if [[ ! -f "$ROOT/config.env" ]]; then
    cp "$ROOT/config.env.example" "$ROOT/config.env"
    warn "config.env creado desde config.env.example — edítalo para añadir tokens"
  else
    ok "config.env ya existe"
  fi
}

# ── PATH persistente ──────────────────────────────────────────
setup_path() {
  title "PATH"
  local PROFILE=""
  [[ -f "$HOME/.zshrc" ]]  && PROFILE="$HOME/.zshrc"
  [[ -f "$HOME/.bashrc" ]] && PROFILE="$HOME/.bashrc"

  if [[ -n "$PROFILE" ]] && ! grep -q "HACKEADORA_PATH" "$PROFILE" 2>/dev/null; then
    cat >> "$PROFILE" <<'EOF'

# Hackeadora tools — HACKEADORA_PATH
export PATH="$PATH:$HOME/.local/bin:/usr/local/go/bin:$HOME/go/bin"
EOF
    ok "PATH añadido a $PROFILE"
  fi
  export PATH="$PATH:$INSTALL_DIR:/usr/local/go/bin:$HOME/go/bin"
}

# ── Verificación ──────────────────────────────────────────────
verify_installation() {
  title "Verificación"
  local CORE_TOOLS=(subfinder httpx dnsx nuclei katana gau ffuf anew subzy)
  local MISSING=()

  for t in "${CORE_TOOLS[@]}"; do
    if command -v "$t" &>/dev/null; then
      ok "$t → $(command -v "$t")"
    else
      warn "$t → NO ENCONTRADO"
      MISSING+=("$t")
    fi
  done

  echo ""
  if [[ ${#MISSING[@]} -eq 0 ]]; then
    ok "Todas las herramientas core están disponibles"
  else
    warn "Faltan: ${MISSING[*]}"
    warn "Reinicia la terminal y comprueba que ~/.local/bin está en PATH"
  fi
}

# ── Main ──────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════╗"
echo "║   Hackeadora — Instalador            ║"
echo "╚══════════════════════════════════════╝"
echo -e "${RESET}"

[[ "$(id -u)" -ne 0 ]] && warn "No eres root. Algunos pasos pueden requerir sudo."

if $CHECK_ONLY; then
  export PATH="$PATH:$INSTALL_DIR:/usr/local/go/bin:$HOME/go/bin"
  verify_installation
  exit 0
fi

if $GO_ONLY; then
  install_system_packages
  install_go
  setup_path
  exit 0
fi

install_system_packages
install_go
install_core_tools
$FULL && install_full_tools
install_python_deps
update_nuclei_templates
setup_project
setup_path
verify_installation

echo -e "\n${GREEN}${BOLD}Instalación completada.${RESET}"
if $FULL; then
  echo -e "Modo: ${CYAN}completo (core + opcionales)${RESET}"
else
  echo -e "Modo: ${CYAN}core${RESET} — usa ${BOLD}--full${RESET} para herramientas opcionales (amass, bbot, masscan…)"
fi
echo -e "\nSiguiente paso:"
echo -e "  ${CYAN}nano config.env${RESET}  # añade tu token de Telegram (opcional)"
echo -e "  ${CYAN}./recon.sh --test-telegram${RESET}  # verificar notificaciones"
echo -e "  ${CYAN}./recon.sh testphp.vulnweb.com --modules=09${RESET}  # primera prueba"
