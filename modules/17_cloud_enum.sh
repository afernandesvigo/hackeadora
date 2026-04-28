#!/usr/bin/env bash
# ============================================================
#  modules/17_cloud_enum.sh
#  Fase 17: Enumeración de assets en cloud (S3, Azure, GCP)
#
#  Técnica: generar variaciones del nombre del dominio/org
#  y probar si existen buckets/blobs públicos o mal configurados
#
#  Herramientas:
#    - cloud_enum (Python): S3 + Azure + GCP simultáneo
#    - s3scanner: verificación de permisos S3
#    - Peticiones directas HTTP como fallback
# ============================================================

MODULE_NAME="cloud_enum"
MODULE_DESC="Enumeración de assets en cloud (S3/Azure/GCP)"

# ── Generar variaciones de nombre para buckets ────────────────
_generate_mutations() {
  local DOMAIN="$1"   # empresa.com
  local ORG="$2"      # empresa

  cat << MUTATIONS
${ORG}
${ORG}-backup
${ORG}-backups
${ORG}-dev
${ORG}-development
${ORG}-staging
${ORG}-stage
${ORG}-prod
${ORG}-production
${ORG}-test
${ORG}-testing
${ORG}-assets
${ORG}-static
${ORG}-media
${ORG}-uploads
${ORG}-files
${ORG}-data
${ORG}-logs
${ORG}-archive
${ORG}-cdn
${ORG}-images
${ORG}-img
${ORG}-public
${ORG}-private
${ORG}-internal
${ORG}-api
${ORG}-app
${ORG}-web
${ORG}-www
${ORG}-mail
${ORG}-email
${ORG}-admin
${ORG}-config
${ORG}-secrets
${DOMAIN}
www.${DOMAIN}
static.${DOMAIN}
assets.${DOMAIN}
media.${DOMAIN}
cdn.${DOMAIN}
files.${DOMAIN}
uploads.${DOMAIN}
MUTATIONS
}

# ── Verificar bucket S3 ───────────────────────────────────────
_check_s3() {
  local BUCKET="$1"
  local URL="https://${BUCKET}.s3.amazonaws.com"

  local RESPONSE
  RESPONSE=$(curl -s --max-time 8 -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)

  case "$RESPONSE" in
    200) echo "open" ;;        # Listado público — critical
    403) echo "protected" ;;   # Existe pero privado — info
    301|307) echo "redirect" ;; # Redirige — info
    404|*) echo "" ;;          # No existe
  esac
}

# ── Verificar Azure Blob ──────────────────────────────────────
_check_azure() {
  local NAME="$1"
  local URL="https://${NAME}.blob.core.windows.net"

  local RESPONSE
  RESPONSE=$(curl -s --max-time 8 -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)

  case "$RESPONSE" in
    200|400) echo "exists" ;;
    403) echo "protected" ;;
    *) echo "" ;;
  esac
}

# ── Verificar GCP Storage ─────────────────────────────────────
_check_gcp() {
  local BUCKET="$1"
  local URL="https://storage.googleapis.com/${BUCKET}"

  local RESPONSE
  RESPONSE=$(curl -s --max-time 8 -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)

  case "$RESPONSE" in
    200) echo "open" ;;
    403) echo "protected" ;;
    *) echo "" ;;
  esac
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 17 — $MODULE_DESC: $DOMAIN"

  local ORG
  ORG=$(echo "$DOMAIN" | cut -d'.' -f1)

  # ── cloud_enum si está disponible ─────────────────────────
  if command -v cloud_enum &>/dev/null; then
    log_info "cloud_enum sobre $ORG / $DOMAIN..."
    local CE_OUT="$OUT_DIR/.cloud_enum_out.txt"

    cloud_enum \
      -k "$ORG" \
      -k "$DOMAIN" \
      --disable-azure-websites \
      -l "$CE_OUT" \
      2>/dev/null || true

    if [[ -s "$CE_OUT" ]]; then
      while IFS= read -r LINE; do
        [[ -z "$LINE" ]] && continue
        echo "$LINE" | grep -qiP 'OPEN|open|public|accessible' || continue

        local PROVIDER="aws"
        echo "$LINE" | grep -qi "azure" && PROVIDER="azure"
        echo "$LINE" | grep -qi "google\|gcs\|googleapis" && PROVIDER="gcp"

        local ASSET_URL
        ASSET_URL=$(echo "$LINE" | grep -oP 'https?://[^\s]+' | head -1)
        [[ -z "$ASSET_URL" ]] && continue

        sqlite3 "$DB_PATH" \
          "INSERT OR IGNORE INTO cloud_assets(domain_id,asset_url,provider,asset_type,status)
           VALUES(${DOMAIN_ID},'${ASSET_URL//\'/\'\'}','${PROVIDER}','bucket','open');" \
          2>/dev/null || true

        log_warn "☁️  OPEN bucket [$PROVIDER]: $ASSET_URL"
        _telegram_send "☁️ *Cloud Asset ABIERTO*
🌐 \`${DOMAIN}\`
☁️ Provider: \`${PROVIDER^^}\`
🔗 \`${ASSET_URL}\`
⚠️ Acceso público — reportar como finding
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

        db_add_finding "$DOMAIN_ID" "cloud_bucket" "high" \
          "$ASSET_URL" "cloud_enum" "Bucket/blob $PROVIDER accesible públicamente"

      done < "$CE_OUT"
      rm -f "$CE_OUT"
    fi
  else
    log_warn "cloud_enum no encontrado — usando verificación directa"
  fi

  # ── Verificación directa con mutaciones ───────────────────
  log_info "Probando variaciones de nombre en S3/Azure/GCP..."
  local MUTATIONS
  MUTATIONS=$(_generate_mutations "$DOMAIN" "$ORG")
  local TOTAL_MUT
  TOTAL_MUT=$(echo "$MUTATIONS" | wc -l | tr -d ' ')
  local CHECKED=0
  local FOUND=0

  while IFS= read -r NAME; do
    [[ -z "$NAME" ]] && continue
    ((CHECKED++))
    (( CHECKED % 20 == 0 )) && log_info "[$CHECKED/$TOTAL_MUT] variaciones probadas..."

    # S3
    local S3_STATUS
    S3_STATUS=$(_check_s3 "$NAME")
    if [[ -n "$S3_STATUS" ]]; then
      local S3_URL="https://${NAME}.s3.amazonaws.com"
      local SEVERITY="info"
      [[ "$S3_STATUS" == "open" ]] && SEVERITY="high"

      sqlite3 "$DB_PATH" \
        "INSERT OR IGNORE INTO cloud_assets(domain_id,asset_url,provider,asset_type,status)
         VALUES(${DOMAIN_ID},'${S3_URL}','aws','s3','${S3_STATUS}');" \
        2>/dev/null || true

      ((FOUND++))
      log_warn "☁️  S3 [${S3_STATUS}]: $S3_URL"

      if [[ "$S3_STATUS" == "open" ]]; then
        _telegram_send "☁️ *S3 Bucket ABIERTO*
🌐 \`${DOMAIN}\`
🔗 \`${S3_URL}\`
⚠️ Listado público — HIGH finding
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
        db_add_finding "$DOMAIN_ID" "cloud_bucket" "high" "$S3_URL" "s3:open" "S3 bucket con listado público"
      fi
    fi

    # Azure (solo para algunos nombres — es más lento)
    if (( CHECKED % 3 == 0 )); then
      local AZ_STATUS
      AZ_STATUS=$(_check_azure "$NAME")
      if [[ -n "$AZ_STATUS" ]]; then
        local AZ_URL="https://${NAME}.blob.core.windows.net"
        sqlite3 "$DB_PATH" \
          "INSERT OR IGNORE INTO cloud_assets(domain_id,asset_url,provider,asset_type,status)
           VALUES(${DOMAIN_ID},'${AZ_URL}','azure','blob','${AZ_STATUS}');" \
          2>/dev/null || true
        ((FOUND++))
        log_info "☁️  Azure Blob [${AZ_STATUS}]: $AZ_URL"
      fi
    fi

    # GCP
    local GCP_STATUS
    GCP_STATUS=$(_check_gcp "$NAME")
    if [[ -n "$GCP_STATUS" ]]; then
      local GCP_URL="https://storage.googleapis.com/${NAME}"
      sqlite3 "$DB_PATH" \
        "INSERT OR IGNORE INTO cloud_assets(domain_id,asset_url,provider,asset_type,status)
         VALUES(${DOMAIN_ID},'${GCP_URL}','gcp','gcs','${GCP_STATUS}');" \
        2>/dev/null || true
      ((FOUND++))
      [[ "$GCP_STATUS" == "open" ]] && \
        log_warn "☁️  GCP Storage ABIERTO: $GCP_URL" || \
        log_info "☁️  GCP Storage [${GCP_STATUS}]: $GCP_URL"
    fi

  done <<< "$MUTATIONS"

  log_ok "$MODULE_DESC completado: $FOUND cloud assets encontrados de $CHECKED variaciones"
}
