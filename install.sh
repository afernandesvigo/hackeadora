#!/usr/bin/env bash
# ============================================================
#  ReconFlow — Instalador de dependencias
#  Soporta: Ubuntu/Debian, Fedora/RHEL, Arch Linux
#  Uso: sudo ./install.sh [--tools-only] [--go-only]
# ============================================================

set -euo pipefail

# ── Colores ──────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
info() { echo -e "${CYAN}[→]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
fail() { echo -e "${RED}[✗]${RESET} $*"; exit 1; }
title(){ echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

INSTALL_DIR="$HOME/.local/bin"
GO_VERSION="1.22.4"
TOOLS_ONLY=false
GO_ONLY=false

for arg in "$@"; do
  [[ "$arg" == "--tools-only" ]] && TOOLS_ONLY=true
  [[ "$arg" == "--go-only" ]]    && GO_ONLY=true
done

# ── Detectar distro ──────────────────────────────────────────
detect_distro() {
  if   command -v apt-get &>/dev/null; then echo "debian"
  elif command -v dnf     &>/dev/null; then echo "fedora"
  elif command -v pacman  &>/dev/null; then echo "arch"
  else fail "Distro no soportada. Instala manualmente: git curl wget unzip python3 sqlite3 jq"; fi
}

# ── Paquetes del sistema ──────────────────────────────────────
install_system_packages() {
  title "Paquetes del sistema"
  local DISTRO
  DISTRO=$(detect_distro)
  local PKGS="git curl wget unzip tar python3 python3-pip sqlite3 jq make gcc"

  case "$DISTRO" in
    debian)
      info "Actualizando apt..."
      apt-get update -qq
      # shellcheck disable=SC2086
      apt-get install -y $PKGS build-essential libpcap-dev 2>/dev/null
      ;;
    fedora)
      # shellcheck disable=SC2086
      dnf install -y $PKGS gcc libpcap-devel 2>/dev/null
      ;;
    arch)
      # shellcheck disable=SC2086
      pacman -Sy --noconfirm $PKGS libpcap 2>/dev/null
      ;;
  esac
  ok "Paquetes del sistema instalados"
}

# ── Go ────────────────────────────────────────────────────────
install_go() {
  title "Go $GO_VERSION"

  if command -v go &>/dev/null; then
    local CURRENT
    CURRENT=$(go version | awk '{print $3}' | sed 's/go//')
    info "Go ya instalado: $CURRENT"
    # Actualizar si la versión es menor
    if [[ "$(printf '%s\n' "$GO_VERSION" "$CURRENT" | sort -V | head -1)" == "$GO_VERSION" ]]; then
      ok "Versión de Go suficiente"
      return
    fi
    warn "Actualizando Go a $GO_VERSION..."
  fi

  local ARCH
  ARCH=$(uname -m)
  [[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
  [[ "$ARCH" == "aarch64" ]] && ARCH="arm64"

  local TARBALL="go${GO_VERSION}.linux-${ARCH}.tar.gz"
  local URL="https://go.dev/dl/$TARBALL"

  info "Descargando Go desde $URL..."
  wget -q --show-progress "$URL" -O "/tmp/$TARBALL"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "/tmp/$TARBALL"
  rm "/tmp/$TARBALL"

  # PATH global
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
    ok "$NAME ya instalado ($(command -v "$BIN"))"
    return
  fi

  info "Instalando $NAME..."
  if go install "$PKG" 2>/dev/null; then
    # Mover a INSTALL_DIR si no está en PATH
    if [[ -f "$HOME/go/bin/$BIN" ]]; then
      cp "$HOME/go/bin/$BIN" "$INSTALL_DIR/" 2>/dev/null || true
    fi
    ok "$NAME instalado"
  else
    warn "$NAME: fallo en instalación, continúa..."
  fi
}

# ── Helper: instalar desde release GitHub ────────────────────
install_github_release() {
  local NAME="$1"
  local REPO="$2"    # usuario/repo
  local PATTERN="$3" # glob del asset, ej: "*linux_amd64.zip"
  local BIN="${4:-$NAME}"

  if command -v "$BIN" &>/dev/null; then
    ok "$NAME ya instalado"
    return
  fi

  info "Descargando $NAME desde GitHub releases..."
  local URL
  URL=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" \
    | jq -r ".assets[] | select(.name | test(\"${PATTERN}\")) | .browser_download_url" \
    | head -1)

  if [[ -z "$URL" ]]; then
    warn "$NAME: no se encontró asset en GitHub, saltando..."
    return
  fi

  local TMP="/tmp/${NAME}_install"
  mkdir -p "$TMP"
  wget -q --show-progress "$URL" -O "$TMP/asset"

  if file "$TMP/asset" | grep -q "Zip"; then
    unzip -qo "$TMP/asset" -d "$TMP"
  elif file "$TMP/asset" | grep -q "gzip\|tar"; then
    tar -xzf "$TMP/asset" -C "$TMP"
  else
    cp "$TMP/asset" "$TMP/$BIN"
  fi

  local FOUND
  FOUND=$(find "$TMP" -type f -name "$BIN" | head -1)
  if [[ -n "$FOUND" ]]; then
    cp "$FOUND" "$INSTALL_DIR/$BIN"
    chmod +x "$INSTALL_DIR/$BIN"
    ok "$NAME instalado en $INSTALL_DIR/$BIN"
  else
    warn "$NAME: binario no encontrado en el asset"
  fi
  rm -rf "$TMP"
}

# ── Herramientas de recon ─────────────────────────────────────
install_recon_tools() {
  title "Herramientas de recon (Go)"
  mkdir -p "$INSTALL_DIR"

  # Asegurar que INSTALL_DIR está en PATH para este script
  export PATH="$PATH:$INSTALL_DIR:/usr/local/go/bin:$HOME/go/bin"

  # ── Enumeración de subdominios ──
  install_go_tool "subfinder"    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  install_go_tool "amass"        "github.com/owasp-amass/amass/v4/...@master"
  install_go_tool "assetfinder"  "github.com/tomnomnom/assetfinder@latest"
  install_go_tool "findomain"    "github.com/Findomain/Findomain@latest" || true  # puede tardar

  # ── Resolución / HTTP ──
  install_go_tool "httpx"  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  install_go_tool "dnsx"   "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"

  # ── Takeover ──
  install_go_tool "subzy"  "github.com/PentestPad/subzy@latest"
  install_go_tool "subjack" "github.com/haccer/subjack@latest"

  # ── Nuclei ──
  install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

  # ── Crawling / URLs ──
  install_go_tool "katana"       "github.com/projectdiscovery/katana/cmd/katana@latest"
  install_go_tool "gau"          "github.com/lc/gau/v2/cmd/gau@latest"
  install_go_tool "waybackurls"  "github.com/tomnomnom/waybackurls@latest"
  install_go_tool "hakrawler"    "github.com/hakluke/hakrawler@latest"

  # ── Active scan / fuzzing ──
  install_go_tool "ffuf"  "github.com/ffuf/ffuf/v2@latest"
  install_go_tool "gospider" "github.com/jaeles-project/gospider@latest"

  # ── Otros utils ──
  install_go_tool "anew"    "github.com/tomnomnom/anew@latest"
  install_go_tool "qsreplace" "github.com/tomnomnom/qsreplace@latest"
  install_go_tool "unfurl"  "github.com/tomnomnom/unfurl@latest"
  install_go_tool "gowitness"   "github.com/sensepost/gowitness@latest"
  install_go_tool "webanalyze"  "github.com/rverton/webanalyze/cmd/webanalyze@latest"
  install_go_tool "asnmap"     "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
  install_go_tool "trufflehog" "github.com/trufflesecurity/trufflehog/v3@latest"
  install_go_tool "mapcidr"    "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"

  # SecretFinder (Python — extractor de endpoints/secrets en JS)
  local SF_DIR="$HOME/tools/SecretFinder"
  if [[ ! -d "$SF_DIR" ]]; then
    info "Instalando SecretFinder..."
    git clone -q https://github.com/m4ll0k/SecretFinder.git "$SF_DIR" 2>/dev/null \
      && pip3 install --break-system-packages -r "$SF_DIR/requirements.txt" -q 2>/dev/null \
      && ok "SecretFinder instalado" \
      || warn "SecretFinder: instala manualmente desde github.com/m4ll0k/SecretFinder"
  else
    ok "SecretFinder ya instalado"
  fi
}

# ── whatweb ───────────────────────────────────────────────────
install_whatweb() {
  title "whatweb"
  if command -v whatweb &>/dev/null; then ok "whatweb ya instalado"; return; fi
  local DISTRO
  DISTRO=$(detect_distro)
  case "$DISTRO" in
    debian) apt-get install -y whatweb 2>/dev/null && ok "whatweb instalado" || warn "whatweb: instala manualmente" ;;
    fedora) dnf install -y whatweb 2>/dev/null && ok "whatweb instalado" || warn "whatweb: instala manualmente" ;;
    arch)   pacman -Sy --noconfirm whatweb 2>/dev/null && ok "whatweb instalado" || warn "whatweb: instala manualmente" ;;
  esac
}

# ── masscan ───────────────────────────────────────────────────
install_masscan() {
  title "masscan"
  if command -v masscan &>/dev/null; then ok "masscan ya instalado"; return; fi
  local DISTRO
  DISTRO=$(detect_distro)
  case "$DISTRO" in
    debian)
      apt-get install -y masscan 2>/dev/null && ok "masscan instalado" || {
        # Compilar desde fuente si el paquete no está
        warn "Compilando masscan desde fuente..."
        apt-get install -y git gcc make libpcap-dev 2>/dev/null
        git clone -q https://github.com/robertdavidgraham/masscan /tmp/masscan_src
        make -C /tmp/masscan_src -j"$(nproc)" 2>/dev/null
        cp /tmp/masscan_src/bin/masscan "$INSTALL_DIR/"
        rm -rf /tmp/masscan_src
        ok "masscan compilado e instalado"
      }
      ;;
    fedora)
      dnf install -y masscan 2>/dev/null && ok "masscan instalado" || {
        dnf install -y git gcc make libpcap-devel 2>/dev/null
        git clone -q https://github.com/robertdavidgraham/masscan /tmp/masscan_src
        make -C /tmp/masscan_src -j"$(nproc)" 2>/dev/null
        cp /tmp/masscan_src/bin/masscan "$INSTALL_DIR/"
        rm -rf /tmp/masscan_src
        ok "masscan compilado"
      }
      ;;
    arch)
      pacman -Sy --noconfirm masscan 2>/dev/null && ok "masscan instalado" || {
        pacman -Sy --noconfirm git gcc make libpcap 2>/dev/null
        git clone -q https://github.com/robertdavidgraham/masscan /tmp/masscan_src
        make -C /tmp/masscan_src -j"$(nproc)" 2>/dev/null
        cp /tmp/masscan_src/bin/masscan "$INSTALL_DIR/"
        rm -rf /tmp/masscan_src
        ok "masscan compilado"
      }
      ;;
  esac
}

# ── bbot (Python) ─────────────────────────────────────────────
install_bbot() {
  title "bbot (Python)"
  if command -v bbot &>/dev/null; then
    ok "bbot ya instalado"
    return
  fi
  info "Instalando bbot via pip..."
  pip3 install bbot --break-system-packages 2>/dev/null \
    || pip3 install bbot 2>/dev/null \
    || pipx install bbot 2>/dev/null \
    || warn "bbot: fallo en instalación, instálalo manualmente: pip3 install bbot"
  ok "bbot instalado"
}

# ── Nuclei templates ──────────────────────────────────────────
update_nuclei_templates() {
  title "Nuclei templates"
  if command -v nuclei &>/dev/null; then
    info "Actualizando nuclei-templates..."
    nuclei -update-templates 2>/dev/null && ok "Templates actualizados"
  else
    warn "nuclei no disponible, saltando templates"
  fi
}

# ── Python deps del proyecto ──────────────────────────────────
install_python_deps() {
  title "Python dependencies del proyecto"
  pip3 install requests fastapi uvicorn cryptography 2>/dev/null \
    || pip3 install --break-system-packages requests fastapi uvicorn 2>/dev/null \
    || true
  ok "Dependencias Python instaladas"

  # Verificar KB
  if [[ ! -f "$ROOT/core/knowledge_base.json" ]]; then
    warn "knowledge_base.json no encontrada"
  else
    ok "Knowledge Base presente ($(python3 -c "import json; kb=json.load(open('$ROOT/core/knowledge_base.json')); print(len(kb.get(\"vulnerabilities\",[]))) " 2>/dev/null || echo "?") vulns)"
  fi
}

# ── PATH persistente para el usuario ─────────────────────────
setup_path() {
  title "Configuración de PATH"
  local PROFILE=""
  [[ -f "$HOME/.zshrc" ]]  && PROFILE="$HOME/.zshrc"
  [[ -f "$HOME/.bashrc" ]] && PROFILE="$HOME/.bashrc"

  if [[ -n "$PROFILE" ]] && ! grep -q "$INSTALL_DIR" "$PROFILE" 2>/dev/null; then
    echo "export PATH=\"\$PATH:$INSTALL_DIR:/usr/local/go/bin:\$HOME/go/bin\"" >> "$PROFILE"
    ok "PATH añadido a $PROFILE"
  fi
  ok "Ejecuta: source $PROFILE  o reinicia la terminal"
}

# ── Verificación final ────────────────────────────────────────
verify_installation() {
  title "Verificación"
  local TOOLS=(subfinder httpx dnsx nuclei katana gau subzy ffuf anew)
  local MISSING=()

  for t in "${TOOLS[@]}"; do
    if command -v "$t" &>/dev/null; then
      ok "$t → $(command -v "$t")"
    else
      warn "$t → NO ENCONTRADO"
      MISSING+=("$t")
    fi
  done

  if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Herramientas no instaladas: ${MISSING[*]}"
    warn "Revisa los errores arriba o instálalas manualmente"
  else
    ok "¡Todo instalado correctamente!"
  fi
}

# ── Main ──────────────────────────────────────────────────────
main() {
  echo -e "${BOLD}${CYAN}"
  echo "╔══════════════════════════════════════╗"
  echo "║   ReconFlow — Instalador v1.0        ║"
  echo "╚══════════════════════════════════════╝"
  echo -e "${RESET}"

  [[ "$(id -u)" -ne 0 ]] && warn "No eres root. Algunos pasos pueden fallar."

  if $GO_ONLY; then
    install_go
    return
  fi

  if ! $TOOLS_ONLY; then
    install_system_packages
    install_go
  else
    export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin:$INSTALL_DIR"
  fi

  install_recon_tools
  install_masscan
  install_bbot
  install_whatweb

  # cloud_enum
  title "cloud_enum"
  if ! command -v cloud_enum &>/dev/null; then
    info "Instalando cloud_enum..."
    pip3 install cloud-enum --break-system-packages -q 2>/dev/null \
      || git clone -q https://github.com/initstring/cloud_enum.git /opt/cloud_enum 2>/dev/null \
      && ln -sf /opt/cloud_enum/cloud_enum.py /usr/local/bin/cloud_enum 2>/dev/null \
      && pip3 install --break-system-packages -r /opt/cloud_enum/requirements.txt -q 2>/dev/null \
      || warn "cloud_enum: instala manualmente"
    ok "cloud_enum listo"
  else
    ok "cloud_enum ya instalado"
  fi

  # AWS CLI
  title "AWS CLI (para rotación de IPs)"
  if command -v aws &>/dev/null; then
    ok "AWS CLI ya instalado ($(aws --version 2>&1 | head -1))"
  else
    info "Instalando AWS CLI v2..."
    local ARCH
    ARCH=$(uname -m)
    [[ "$ARCH" == "aarch64" ]] && ARCH="aarch64" || ARCH="x86_64"
    curl -sL "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" -o /tmp/awscliv2.zip
    unzip -q /tmp/awscliv2.zip -d /tmp/awscli_install
    /tmp/awscli_install/aws/install 2>/dev/null ||       /tmp/awscli_install/aws/install --update 2>/dev/null
    rm -rf /tmp/awscliv2.zip /tmp/awscli_install
    ok "AWS CLI instalado"
  fi

  # Acunetix python client deps
  pip3 install urllib3 --break-system-packages -q 2>/dev/null || true

  # Preguntar config Acunetix
  echo ""
  echo -e "${YELLOW}[?] ¿Configurar Acunetix API? (s/N)${RESET}"
  read -r CONFIGURE_ACX
  if [[ "${CONFIGURE_ACX,,}" == "s" ]]; then
    echo -e "${CYAN}URL de Acunetix (default: https://localhost:3443):${RESET}"
    read -r ACX_URL_INPUT
    ACX_URL_INPUT="${ACX_URL_INPUT:-https://localhost:3443}"
    echo -e "${CYAN}API Key de Acunetix:${RESET}"
    read -rs ACX_KEY_INPUT
    echo ""

    local ENV_FILE="$ROOT/.env"
    [[ ! -f "$ENV_FILE" ]] && ENV_FILE="$ROOT/config.env"

    grep -q "ACUNETIX_URL" "$ENV_FILE" 2>/dev/null &&       sed -i "s|ACUNETIX_URL=.*|ACUNETIX_URL=${ACX_URL_INPUT}|" "$ENV_FILE" ||       echo "ACUNETIX_URL=${ACX_URL_INPUT}" >> "$ENV_FILE"

    grep -q "ACUNETIX_API_KEY" "$ENV_FILE" 2>/dev/null &&       sed -i "s|ACUNETIX_API_KEY=.*|ACUNETIX_API_KEY=${ACX_KEY_INPUT}|" "$ENV_FILE" ||       echo "ACUNETIX_API_KEY=${ACX_KEY_INPUT}" >> "$ENV_FILE"

    ok "Acunetix configurado"
    info "Test: python3 core/acunetix.py --test"
  fi

  # boto3
  pip3 install boto3 --break-system-packages -q 2>/dev/null ||     pip3 install boto3 -q 2>/dev/null || true
  ok "boto3 instalado"

  # Preguntar si configurar AWS ahora
  echo ""
  echo -e "${YELLOW}[?] ¿Configurar credenciales AWS para rotación de IPs? (s/N)${RESET}"
  read -r CONFIGURE_AWS
  if [[ "${CONFIGURE_AWS,,}" == "s" ]]; then
    echo -e "${CYAN}AWS Access Key ID:${RESET}"
    read -r AWS_KEY_INPUT
    echo -e "${CYAN}AWS Secret Access Key:${RESET}"
    read -rs AWS_SECRET_INPUT
    echo ""
    echo -e "${CYAN}Región AWS (default: eu-west-1):${RESET}"
    read -r AWS_REGION_INPUT
    AWS_REGION_INPUT="${AWS_REGION_INPUT:-eu-west-1}"

    # Guardar en .env si existe, sino en config.env
    local ENV_FILE="$ROOT/.env"
    [[ ! -f "$ENV_FILE" ]] && ENV_FILE="$ROOT/config.env"

    grep -q "AWS_ACCESS_KEY_ID" "$ENV_FILE" 2>/dev/null &&       sed -i "s|AWS_ACCESS_KEY_ID=.*|AWS_ACCESS_KEY_ID=${AWS_KEY_INPUT}|" "$ENV_FILE" ||       echo "AWS_ACCESS_KEY_ID=${AWS_KEY_INPUT}" >> "$ENV_FILE"

    grep -q "AWS_SECRET_ACCESS_KEY" "$ENV_FILE" 2>/dev/null &&       sed -i "s|AWS_SECRET_ACCESS_KEY=.*|AWS_SECRET_ACCESS_KEY=${AWS_SECRET_INPUT}|" "$ENV_FILE" ||       echo "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_INPUT}" >> "$ENV_FILE"

    grep -q "AWS_REGION" "$ENV_FILE" 2>/dev/null &&       sed -i "s|AWS_REGION=.*|AWS_REGION=${AWS_REGION_INPUT}|" "$ENV_FILE" ||       echo "AWS_REGION=${AWS_REGION_INPUT}" >> "$ENV_FILE"

    ok "Credenciales AWS guardadas en $ENV_FILE"
    info "Ejecuta './core/build_ami.sh' para crear una AMI pre-configurada (recomendado)"
  else
    info "Rotación de IPs desactivada. Configura AWS_ACCESS_KEY_ID en .env cuando quieras."
  fi

  # paramspider + arjun
  title "paramspider + arjun"
  pip3 install paramspider arjun --break-system-packages -q 2>/dev/null || true
  ok "paramspider y arjun instalados"
  install_python_deps
  update_nuclei_templates
  setup_path
  verify_installation

  echo -e "\n${GREEN}${BOLD}Instalación completada.${RESET}"
  echo -e "Configura tu token de Telegram: ${CYAN}cp config.env.example config.env && nano config.env${RESET}"
}

main "$@"
