#!/usr/bin/env bash
# ============================================================
#  core/build_ami.sh — Construye una AMI pre-configurada
#  con todas las herramientas de Hackeadora instaladas.
#
#  Ejecutar UNA SOLA VEZ para tener instancias que arrancan
#  en segundos en lugar de esperar el bootstrap (~8 min).
#
#  Uso: ./core/build_ami.sh
#  Resultado: AMI ID guardado en config.env y .env
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

source "$ROOT/config.env" 2>/dev/null || true

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
info() { echo -e "${CYAN}[→]${RESET} $*"; }
fail() { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════╗"
echo "║   Hackeadora — Build AMI             ║"
echo "╚══════════════════════════════════════╝"
echo -e "${RESET}"

# Verificar dependencias
command -v python3  &>/dev/null || fail "python3 no encontrado"
command -v aws      &>/dev/null || fail "AWS CLI no encontrado (instala con: ./install.sh)"

# Verificar credenciales AWS
if ! aws sts get-caller-identity &>/dev/null; then
  fail "Sin credenciales AWS. Configura AWS_ACCESS_KEY_ID y AWS_SECRET_ACCESS_KEY en .env"
fi

REGION="${AWS_REGION:-eu-west-1}"
INSTANCE_TYPE="t3.small"
KEY_PAIR="${AWS_KEY_PAIR:-hackeadora}"

info "Región: $REGION"
info "Tipo de instancia: $INSTANCE_TYPE"

# ── 1. Lanzar instancia base ──────────────────────────────────
info "Lanzando instancia base para construir AMI..."

# Obtener AMI Ubuntu 22.04 más reciente
BASE_AMI=$(aws ec2 describe-images \
  --region "$REGION" \
  --owners 099720109477 \
  --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" \
            "Name=state,Values=available" \
  --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' \
  --output text 2>/dev/null)

[[ -z "$BASE_AMI" ]] && fail "No se encontró AMI base Ubuntu 22.04"
info "AMI base: $BASE_AMI"

# Security group
SG_ID=$(aws ec2 describe-security-groups \
  --region "$REGION" \
  --filters "Name=group-name,Values=hackeadora-scanner" \
  --query 'SecurityGroups[0].GroupId' \
  --output text 2>/dev/null || echo "None")

if [[ "$SG_ID" == "None" || -z "$SG_ID" ]]; then
  SG_ID=$(aws ec2 create-security-group \
    --region "$REGION" \
    --group-name "hackeadora-scanner" \
    --description "Hackeadora scanner" \
    --query 'GroupId' --output text)
  info "Security group creado: $SG_ID"
fi

# Lanzar instancia (on-demand para build — más estable)
INSTANCE_ID=$(aws ec2 run-instances \
  --region "$REGION" \
  --image-id "$BASE_AMI" \
  --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_PAIR" \
  --security-group-ids "$SG_ID" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=hackeadora-ami-builder},{Key=Project,Value=hackeadora}]" \
  --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=20,VolumeType=gp3,DeleteOnTermination=true}" \
  --query 'Instances[0].InstanceId' \
  --output text 2>/dev/null)

info "Instancia lanzada: $INSTANCE_ID"

# Esperar running
info "Esperando estado 'running'..."
aws ec2 wait instance-running --region "$REGION" --instance-ids "$INSTANCE_ID"

PUBLIC_IP=$(aws ec2 describe-instances \
  --region "$REGION" \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text)

ok "Instancia en $PUBLIC_IP"

# ── 2. Instalar todas las herramientas via SSH ─────────────────
KEY_FILE="$ROOT/data/${KEY_PAIR}.pem"
[[ ! -f "$KEY_FILE" ]] && fail "Key file no encontrado: $KEY_FILE"

info "Esperando SSH disponible..."
for i in {1..30}; do
  ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    "ubuntu@$PUBLIC_IP" "echo ok" &>/dev/null && break
  sleep 10
done

info "Instalando herramientas (esto tarda ~10 minutos)..."
ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no "ubuntu@$PUBLIC_IP" << 'REMOTE'
set -e
export DEBIAN_FRONTEND=noninteractive

echo "[1/6] Sistema base..."
apt-get update -qq
apt-get install -y curl wget git jq unzip python3 python3-pip \
  libpcap-dev build-essential masscan whatweb 2>/dev/null

echo "[2/6] Go 1.22..."
wget -q https://go.dev/dl/go1.22.4.linux-amd64.tar.gz -O /tmp/go.tar.gz
tar -C /usr/local -xzf /tmp/go.tar.gz
export PATH=$PATH:/usr/local/go/bin:/root/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin:/root/go/bin' >> /root/.bashrc

echo "[3/6] Herramientas Go..."
for tool in \
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
  "github.com/projectdiscovery/httpx/cmd/httpx@latest" \
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" \
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
  "github.com/projectdiscovery/katana/cmd/katana@latest" \
  "github.com/projectdiscovery/asnmap/cmd/asnmap@latest" \
  "github.com/ffuf/ffuf/v2@latest" \
  "github.com/lc/gau/v2/cmd/gau@latest" \
  "github.com/tomnomnom/waybackurls@latest" \
  "github.com/tomnomnom/anew@latest" \
  "github.com/jaeles-project/gospider@latest" \
  "github.com/hahwul/dalfox/v2@latest" \
  "github.com/PentestPad/subzy@latest" \
  "github.com/sensepost/gowitness@latest" \
  "github.com/rverton/webanalyze/cmd/webanalyze@latest"; do
  go install "$tool" 2>/dev/null || true
done

echo "[4/6] Python tools..."
pip3 install --break-system-packages \
  paramspider arjun bbot requests 2>/dev/null || true

echo "[5/6] Nuclei templates..."
/root/go/bin/nuclei -update-templates -silent 2>/dev/null || true

echo "[6/6] Señal de ready..."
touch /tmp/hackeadora_ready
echo "Bootstrap completado"
REMOTE

ok "Herramientas instaladas"

# ── 3. Crear AMI desde la instancia ───────────────────────────
info "Creando AMI..."
AMI_TIMESTAMP=$(date '+%Y%m%d-%H%M')
NEW_AMI_ID=$(aws ec2 create-image \
  --region "$REGION" \
  --instance-id "$INSTANCE_ID" \
  --name "hackeadora-scanner-${AMI_TIMESTAMP}" \
  --description "Hackeadora scanner pre-built — ${AMI_TIMESTAMP}" \
  --no-reboot \
  --query 'ImageId' \
  --output text)

info "Esperando que la AMI esté disponible (puede tardar 5-10 min)..."
aws ec2 wait image-available --region "$REGION" --image-ids "$NEW_AMI_ID"
ok "AMI creada: $NEW_AMI_ID"

# ── 4. Terminar instancia de build ────────────────────────────
info "Terminando instancia de build..."
aws ec2 terminate-instances --region "$REGION" --instance-ids "$INSTANCE_ID" &>/dev/null
ok "Instancia terminada"

# ── 5. Guardar AMI ID en config ───────────────────────────────
# En config.env
if grep -q "AWS_AMI_ID" "$ROOT/config.env" 2>/dev/null; then
  sed -i "s|AWS_AMI_ID=.*|AWS_AMI_ID=${NEW_AMI_ID}|" "$ROOT/config.env"
else
  echo "AWS_AMI_ID=${NEW_AMI_ID}" >> "$ROOT/config.env"
fi

# En .env
if [[ -f "$ROOT/.env" ]]; then
  if grep -q "AWS_AMI_ID" "$ROOT/.env"; then
    sed -i "s|AWS_AMI_ID=.*|AWS_AMI_ID=${NEW_AMI_ID}|" "$ROOT/.env"
  else
    echo "AWS_AMI_ID=${NEW_AMI_ID}" >> "$ROOT/.env"
  fi
fi

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║   AMI lista: ${NEW_AMI_ID}${RESET}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════╝${RESET}"
echo ""
echo "Guardado en config.env y .env"
echo "Las próximas instancias arrancarán en ~30 segundos en lugar de ~10 minutos"
