#!/usr/bin/env bash
# ============================================================
#  modules/16_github_dorking.sh
#  Fase 16: Búsqueda de secrets y endpoints en GitHub
#
#  Herramientas:
#    - trufflehog: escaneo de repos por secrets
#    - gh CLI / GitHub API: búsqueda de código por dominio
#    - gitdorker: dorks automatizados en GitHub Search
#
#  Requiere: GITHUB_TOKEN en config.env (gratis en github.com)
# ============================================================

MODULE_NAME="github_dorking"
MODULE_DESC="GitHub dorking — secrets y endpoints en repos públicos"

# Dorks de GitHub Search para bug bounty
declare -a GH_DORKS=(
  "\"DOMINIO\" password"
  "\"DOMINIO\" secret"
  "\"DOMINIO\" api_key"
  "\"DOMINIO\" apikey"
  "\"DOMINIO\" token"
  "\"DOMINIO\" private_key"
  "\"DOMINIO\" jdbc"
  "\"DOMINIO\" db_password"
  "\"DOMINIO\" connectionString"
  "\"DOMINIO\" smtp_pass"
  "\"DOMINIO\" Authorization: Bearer"
  "\"DOMINIO\" internal"
  "\"DOMINIO\" staging"
  "\"DOMINIO\" dev.DOMINIO"
  "\"DOMINIO\" .env"
  "\"DOMINIO\" config.yml"
  "\"DOMINIO\" credentials"
  "\"DOMINIO\" BEGIN RSA PRIVATE KEY"
  "org:ORGNAME password"
  "org:ORGNAME secret"
  "org:ORGNAME token"
)

# ── GitHub Search API ─────────────────────────────────────────
_github_search() {
  local QUERY="$1"
  local TOKEN="${GITHUB_TOKEN:-}"

  local AUTH_HEADER=""
  [[ -n "$TOKEN" ]] && AUTH_HEADER="-H \"Authorization: Bearer ${TOKEN}\""

  local ENCODED
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${QUERY}'))" 2>/dev/null || \
            echo "$QUERY" | sed 's/ /%20/g;s/"/%22/g;s/:/%3A/g')

  curl -s \
    --max-time 15 \
    -H "Accept: application/vnd.github.v3+json" \
    ${TOKEN:+-H "Authorization: Bearer ${TOKEN}"} \
    "https://api.github.com/search/code?q=${ENCODED}&per_page=10" \
    2>/dev/null
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 16 — $MODULE_DESC: $DOMAIN"

  if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    log_warn "GITHUB_TOKEN no configurado — búsqueda sin autenticar (límite: 10 req/min)"
    log_warn "Configura un token en config.env para mejor cobertura"
  fi

  # Extraer org del dominio (ej: empresa.com → empresa)
  local ORG
  ORG=$(echo "$DOMAIN" | cut -d'.' -f1)

  local NEW_FINDINGS=0
  local RATE_LIMIT_HIT=false

  # ── 1. GitHub Search API con dorks ────────────────────────
  log_info "Ejecutando ${#GH_DORKS[@]} dorks en GitHub Search..."

  for DORK_TMPL in "${GH_DORKS[@]}"; do
    $RATE_LIMIT_HIT && break

    # Sustituir DOMINIO y ORGNAME
    local DORK="${DORK_TMPL//DOMINIO/$DOMAIN}"
    DORK="${DORK//ORGNAME/$ORG}"

    local RESULT
    RESULT=$(_github_search "$DORK")

    # Detectar rate limit
    if echo "$RESULT" | grep -q "rate limit\|secondary rate"; then
      log_warn "GitHub rate limit alcanzado — esperando 60s..."
      sleep 60
      RESULT=$(_github_search "$DORK")
    fi

    local TOTAL_COUNT
    TOTAL_COUNT=$(echo "$RESULT" | jq -r '.total_count // 0' 2>/dev/null || echo 0)
    [[ "$TOTAL_COUNT" -eq 0 ]] && continue

    log_warn "🎯 Dork '$DORK' → $TOTAL_COUNT resultados"

    # Procesar cada resultado
    echo "$RESULT" | jq -c '.items[]?' 2>/dev/null | while IFS= read -r ITEM; do
      local REPO_URL FILE_PATH HTML_URL
      REPO_URL=$(echo "$ITEM" | jq -r '.repository.html_url // ""')
      FILE_PATH=$(echo "$ITEM" | jq -r '.path // ""')
      HTML_URL=$(echo "$ITEM"  | jq -r '.html_url // ""')

      [[ -z "$REPO_URL" ]] && continue

      # Filtrar repos que son listas públicas de dominios — siempre contienen cualquier dominio activo
      local REPO_NAME="${REPO_URL##*/}"
      if echo "${REPO_NAME}/${FILE_PATH}" | grep -qiE \
        "top.?1m|top.?million|tranco|alexa|domain.?list|new.?domain|PIIxel|majestic|\
invalid_html|crawl.?result|Analysis_Tranco|Tranco1M|domainlist|all-domain"; then
        continue
      fi

      # Determinar tipo de finding
      local FTYPE="secret"
      echo "$DORK" | grep -qi "password\|secret\|key\|token\|credential\|private" && FTYPE="secret"
      echo "$DORK" | grep -qi "internal\|staging\|dev\." && FTYPE="endpoint"
      echo "$DORK" | grep -qi "jdbc\|connectionString\|db_" && FTYPE="credential"
      echo "$FILE_PATH" | grep -qi "\.env\|config\|yml\|yaml" && FTYPE="config"

      local CONTEXT="Repo: ${REPO_URL} | File: ${FILE_PATH}"

      local BEFORE
      BEFORE=$(sqlite3 "$DB_PATH" \
        "SELECT COUNT(*) FROM github_findings
         WHERE domain_id=${DOMAIN_ID} AND repo_url='${REPO_URL//\'/\'\'}' AND file_path='${FILE_PATH//\'/\'\'}';" \
        2>/dev/null || echo "1")

      sqlite3 "$DB_PATH" \
        "INSERT OR IGNORE INTO github_findings
         (domain_id,repo_url,file_path,finding_type,content,severity)
         VALUES(${DOMAIN_ID},'${REPO_URL//\'/\'\'}','${FILE_PATH//\'/\'\'}',
                '${FTYPE}','${CONTEXT//\'/\'\'}','high');" \
        2>/dev/null || true

      if [[ "${BEFORE:-1}" == "0" ]]; then
        ((NEW_FINDINGS++))
        log_warn "  📁 ${FTYPE}: $REPO_URL → $FILE_PATH"
        _telegram_send "🐙 *GitHub Finding — ${FTYPE}*
🌐 \`${DOMAIN}\`
🔍 Dork: \`${DORK:0:80}\`
📁 Repo: ${REPO_URL}
📄 Archivo: \`${FILE_PATH}\`
🔗 ${HTML_URL}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

        db_add_finding "$DOMAIN_ID" "github" "high" \
          "$REPO_URL" "github_dork" "${FTYPE}: ${FILE_PATH}"
      fi
    done

    # Rate limiting — GitHub permite 30 búsquedas/min autenticado, 10 sin auth
    sleep "$([[ -n "$GITHUB_TOKEN" ]] && echo 2 || echo 7)"

  done

  # ── 2. Trufflehog sobre repos del org ─────────────────────
  if command -v trufflehog &>/dev/null; then
    log_info "trufflehog sobre organización ${ORG}..."
    local TH_OUT="$OUT_DIR/.trufflehog_out.json"

    timeout 120 trufflehog \
      github \
      --org="$ORG" \
      --json \
      --no-verification \
      ${GITHUB_TOKEN:+--token="$GITHUB_TOKEN"} \
      2>/dev/null \
    | head -100 \
    > "$TH_OUT" || true

    if [[ -s "$TH_OUT" ]]; then
      while IFS= read -r LINE; do
        [[ -z "$LINE" ]] && continue
        local DETECTOR SOURCE_ID REPO
        DETECTOR=$(echo "$LINE" | jq -r '.DetectorName // "unknown"' 2>/dev/null)
        SOURCE_ID=$(echo "$LINE" | jq -r '.SourceMetadata.Data.Github.link // ""' 2>/dev/null)
        REPO=$(echo "$LINE"     | jq -r '.SourceMetadata.Data.Github.repository // ""' 2>/dev/null)

        [[ -z "$SOURCE_ID" ]] && continue

        local BEFORE
        BEFORE=$(sqlite3 "$DB_PATH" \
          "SELECT COUNT(*) FROM github_findings
           WHERE domain_id=${DOMAIN_ID} AND repo_url='${REPO//\'/\'\'}' AND finding_type='trufflehog_${DETECTOR}';" \
          2>/dev/null || echo "1")

        sqlite3 "$DB_PATH" \
          "INSERT OR IGNORE INTO github_findings
           (domain_id,repo_url,file_path,finding_type,content,severity)
           VALUES(${DOMAIN_ID},'${REPO//\'/\'\'}','','trufflehog_${DETECTOR}',
                  '${SOURCE_ID//\'/\'\'}','critical');" \
          2>/dev/null || true

        if [[ "${BEFORE:-1}" == "0" ]]; then
          ((NEW_FINDINGS++))
          log_warn "🔑 trufflehog [$DETECTOR]: $SOURCE_ID"
          _telegram_send "🔑 *Trufflehog — Secret verificado*
🌐 \`${DOMAIN}\`
🏷️ Tipo: \`${DETECTOR}\`
🔗 ${SOURCE_ID}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

          db_add_finding "$DOMAIN_ID" "github_secret" "critical" \
            "$SOURCE_ID" "trufflehog:$DETECTOR" "Secret verificado en repo público"
        fi
      done < "$TH_OUT"
      rm -f "$TH_OUT"
    fi
  else
    log_warn "trufflehog no encontrado — instala: go install github.com/trufflesecurity/trufflehog/v3@latest"
  fi

  log_ok "$MODULE_DESC completado: $NEW_FINDINGS findings nuevos en GitHub"
}
