#!/usr/bin/env bash
# ============================================================
#  modules/32_csp_analysis.sh
#  Fase 32: Análisis automático de Content-Security-Policy
#
#  Detecta misconfigurations que anulan la protección XSS:
#    - form-action wildcard (*) → exfiltración de formularios
#    - script-src unsafe-inline / unsafe-eval → CSP inútil vs XSS
#    - default-src unsafe-* → fallback permisivo
#    - Dominios UAT/staging en CSP de producción
#    - frame-ancestors ausente o permisivo (clickjacking)
#    - object-src ausente o * (Flash/plugin injection)
#    - base-uri ausente (base tag injection)
#    - Endpoints externos no verificados en script-src
#
#  No requiere herramientas externas — solo curl + python3.
# ============================================================

MODULE_NAME="csp_analysis"
MODULE_DESC="Análisis de Content-Security-Policy"

# ── Palabras clave que indican endpoints de staging/UAT ───────
_CSP_UAT_PATTERNS=(
  "-uat\." "\.uat\." "-uat$" "uat\." "\.stg\." "-stg\."
  "\.staging\." "-staging\." "\.dev\." "-dev\."
  "\.sandbox\." "-sandbox\." "\.test\." "-test\."
  "\.qa\." "-qa\." "\.demo\." "-demo\."
  "localhost" "127\.0\.0\.1" "192\.168\." "10\."
)

# ── Registrar finding en DB ───────────────────────────────────
_csp_finding() {
  local DOMAIN_ID="$1" DOMAIN="$2" URL="$3"
  local ISSUE="$4" SEVERITY="$5" DETAIL="$6"

  save_finding "$DOMAIN_ID" "$DOMAIN" \
    "CSP Misconfiguration" "$SEVERITY" \
    "$URL" "$ISSUE" "$DETAIL" \
    "csp_analysis" 2>/dev/null || true

  local ICON="⚠️"
  [[ "$SEVERITY" == "high" ]]     && ICON="🔴"
  [[ "$SEVERITY" == "critical" ]] && ICON="🚨"
  [[ "$SEVERITY" == "medium" ]]   && ICON="🟡"
  [[ "$SEVERITY" == "low" ]]      && ICON="🔵"

  log_warn "  $ICON [$SEVERITY] $ISSUE"
  log_info "     $DETAIL"
}

# ── Análisis de una URL concreta ──────────────────────────────
_analyze_csp_url() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3" PROXY_FLAG="$4"  # PROXY_FLAG ignorado

  _h_head "$URL"
  local CSP
  CSP=$(echo "$HTTP_LAST_HEADERS" | grep -i "^content-security-policy:" | head -1 | sed 's/^[^:]*://;s/\r//')

  if [[ -z "$CSP" ]]; then
    # Algunos servidores solo envían CSP en respuestas GET
    _h_get "$URL"
    CSP=$(echo "$HTTP_LAST_HEADERS" | grep -i "^content-security-policy:" | head -1 | sed 's/^[^:]*://;s/\r//')
  fi

  [[ -z "$CSP" ]] && return

  log_info "  CSP encontrada en $URL"

  python3 - "$URL" "$DOMAIN_ID" "$DOMAIN" "$CSP" << 'PYEOF'
import sys, re

url        = sys.argv[1]
domain_id  = sys.argv[2]
domain     = sys.argv[3]
csp        = sys.argv[4]

issues = []

# Parsear directivas
directives = {}
for part in csp.split(';'):
    part = part.strip()
    if not part:
        continue
    tokens = part.split()
    if tokens:
        directives[tokens[0].lower()] = tokens[1:]

def directive_values(name):
    return directives.get(name, directives.get('default-src', []))

def has_token(name, token):
    return token in directive_values(name)

def directive_str(name):
    return ' '.join(directive_values(name))

# ── 1. form-action con wildcard ───────────────────────────────
form_action_vals = directives.get('form-action', [])
if '*' in form_action_vals:
    issues.append(('high',
        'form-action wildcard (*)',
        'form-action contiene *: cualquier origen puede recibir envíos de formularios. '
        'Con cualquier HTML injection el atacante puede redirigir credenciales/pagos a su servidor sin bloqueo del navegador.'))
elif not form_action_vals:
    issues.append(('medium',
        'form-action no definido',
        'Sin form-action explícito el navegador permite enviar formularios a cualquier origen. '
        'Definir form-action \'self\' o lista explícita.'))

# ── 2. unsafe-inline / unsafe-eval en script-src ─────────────
for directive_name in ('script-src', 'default-src'):
    vals = directives.get(directive_name, [])
    if "'unsafe-inline'" in vals:
        issues.append(('high',
            f"'{directive_name}' unsafe-inline",
            f"'unsafe-inline' en {directive_name} anula completamente la protección XSS de la CSP. "
            "Cualquier XSS inline ejecuta sin restricción. Migrar a nonce o hash."))
    if "'unsafe-eval'" in vals:
        issues.append(('medium',
            f"'{directive_name}' unsafe-eval",
            f"'unsafe-eval' en {directive_name} permite eval(), new Function(), setTimeout(string). "
            "Amplía superficie de explotación si hay XSS."))

# ── 3. Dominios UAT/staging en CSP de producción ─────────────
uat_patterns = [
    r'-uat\.', r'\.uat\.', r'-uat$', r'^uat\.',
    r'\.stg\.', r'-stg\.', r'\.staging\.', r'-staging\.',
    r'\.dev\.', r'-dev\.', r'\.sandbox\.', r'-sandbox\.',
    r'\.test\.', r'-test\.', r'\.qa\.', r'-qa\.',
    r'localhost', r'127\.0\.0\.1',
]
for dname, vals in directives.items():
    for v in vals:
        if v.startswith("'") or v in ('*', 'data:', 'blob:', 'https:', 'http:'):
            continue
        for pat in uat_patterns:
            if re.search(pat, v, re.IGNORECASE):
                issues.append(('medium',
                    f"Endpoint UAT/staging en {dname}",
                    f"Origen '{v}' en directiva '{dname}' parece ser un entorno de UAT/staging. "
                    "Si ese entorno es comprometido, el atacante puede servir JS malicioso en producción."))
                break

# ── 4. frame-ancestors ausente o permisivo ───────────────────
fa = directives.get('frame-ancestors', [])
if not fa:
    issues.append(('medium',
        'frame-ancestors no definido',
        "Sin frame-ancestors la página puede ser embebida en iframes por cualquier origen (clickjacking). "
        "Añadir: frame-ancestors 'self'"))
elif '*' in fa or 'https:' in fa or 'http:' in fa:
    issues.append(('medium',
        'frame-ancestors permisivo',
        f"frame-ancestors contiene '{' '.join(fa)}' — permite embedding desde orígenes amplios."))

# ── 5. object-src permisivo ───────────────────────────────────
obj = directives.get('object-src', directive_values('default-src'))
if '*' in obj or not directives.get('object-src'):
    issues.append(('low',
        'object-src ausente o wildcard',
        "object-src no restrictivo permite plugins (Flash, Java applets) como vector de inyección. "
        "Añadir: object-src 'none'"))

# ── 6. base-uri no restringido ────────────────────────────────
bu = directives.get('base-uri', [])
if not bu:
    issues.append(('low',
        'base-uri no definido',
        "Sin base-uri un atacante con HTML injection puede inyectar <base href=...> "
        "y redirigir todos los paths relativos a un servidor controlado."))
elif '*' in bu:
    issues.append(('medium',
        'base-uri wildcard',
        "base-uri con * permite inyección de <base href> desde cualquier origen."))

# ── 7. Wildcards amplios en script-src ───────────────────────
script_vals = directives.get('script-src', directives.get('default-src', []))
for v in script_vals:
    if v in ('https:', 'http:', '*') and not v.startswith("'"):
        issues.append(('high',
            f"script-src con comodín amplio: {v}",
            f"'{v}' en script-src permite cargar scripts desde cualquier HTTPS origin. "
            "Equivale a no tener CSP para XSS basado en scripts externos."))
        break

# ── Output para shell ─────────────────────────────────────────
for severity, issue, detail in issues:
    print(f"ISSUE|{severity}|{issue}|{detail}")

if not issues:
    print("OK|CSP bien configurada")
PYEOF
}

# ── Función principal ─────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 32 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  local TOTAL_ISSUES=0

  # Analizar todas las URLs activas (subdominios alive)
  local SUBS
  SUBS=$(sqlite3 "$DB_PATH" \
    "SELECT subdomain FROM subdomains
     WHERE domain_id=${DOMAIN_ID} AND status='alive';" 2>/dev/null)

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE="https://${SUB}"
    log_info "Analizando CSP: $BASE"

    local OUTPUT
    OUTPUT=$(_analyze_csp_url "$BASE" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY" 2>/dev/null)

    while IFS= read -r LINE; do
      [[ -z "$LINE" ]] && continue
      if [[ "$LINE" == OK* ]]; then
        log_ok "  CSP correcta en $SUB"
        continue
      fi
      IFS='|' read -r _ SEVERITY ISSUE DETAIL <<< "$LINE"
      [[ -z "$SEVERITY" ]] && continue
      _csp_finding "$DOMAIN_ID" "$DOMAIN" "$BASE" "$ISSUE" "$SEVERITY" "$DETAIL"
      ((TOTAL_ISSUES++))
    done <<< "$OUTPUT"

    # Analizar también la página de login si existe
    local LOGIN_URL
    LOGIN_URL=$(sqlite3 "$DB_PATH" \
      "SELECT url FROM login_forms
       WHERE domain_id=${DOMAIN_ID} AND url LIKE '%${SUB}%'
       LIMIT 1;" 2>/dev/null)
    if [[ -n "$LOGIN_URL" && "$LOGIN_URL" != "$BASE" && "$LOGIN_URL" != "$BASE/" ]]; then
      local LOGIN_OUTPUT
      LOGIN_OUTPUT=$(_analyze_csp_url "$LOGIN_URL" "$DOMAIN_ID" "$DOMAIN" "$CURL_PROXY" 2>/dev/null)
      while IFS= read -r LINE; do
        [[ -z "$LINE" || "$LINE" == OK* ]] && continue
        IFS='|' read -r _ SEVERITY ISSUE DETAIL <<< "$LINE"
        [[ -z "$SEVERITY" ]] && continue
        _csp_finding "$DOMAIN_ID" "$DOMAIN" "$LOGIN_URL" \
          "$ISSUE (login page)" "$SEVERITY" "$DETAIL"
        ((TOTAL_ISSUES++))
      done <<< "$LOGIN_OUTPUT"
    fi

  done <<< "$SUBS"

  if [[ "$TOTAL_ISSUES" -gt 0 ]]; then
    _telegram_send "🔒 *CSP Analysis — $TOTAL_ISSUES issue(s)*
🌐 \`${DOMAIN}\`
📋 Issues: \`${TOTAL_ISSUES}\`
💡 Revisar findings en DB
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi

  log_ok "$MODULE_DESC completado: $TOTAL_ISSUES misconfiguraciones detectadas"
}
