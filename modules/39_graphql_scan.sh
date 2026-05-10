#!/usr/bin/env bash
# ============================================================
#  modules/39_graphql_scan.sh
#  Tier 2.2 — GraphQL security scanner
#
#  Endpoints detectados desde DB (technologies+urls). Probes:
#    1. Introspection (__schema) — si responde schema → info disclosure (medium)
#    2. Field suggestions ("Did you mean") — habilitado en producción → leak menor (low)
#    3. Alias batching — N queries en 1 → rate-limit bypass / brute-force (medium)
#    4. Sensitive field names — schema contiene password/apiKey/token/etc (high)
#    5. Mutations no-auth — POST mutation crítica responde 200 sin auth (critical)
#
#  Requisitos:
#    - Tier 1.6 tech registry detecta GraphQL en mod 10 Capa C
#    - Crawler poblo urls con paths /graphql/etc
#
#  Anti-FP (consistente con Tier 1.5):
#    - Body validation obligatoria (response debe ser JSON con shape graphql)
#    - confidence=high si schema realmente devuelto
#    - confidence=medium si solo error JSON (likely GraphQL pero sin payload)
# ============================================================

MODULE_NAME="graphql_scan"
MODULE_DESC="GraphQL — introspection + suggestions + batching + sensitive fields"

# ── Helpers ─────────────────────────────────────────────────
_gql_finding() {
  local DOMAIN_ID="$1" DOMAIN="$2" TARGET="$3"
  local TYPE="$4" SEV="$5" DETAIL="$6" CONF="${7:-medium}"

  db_add_finding "$DOMAIN_ID" "graphql" "$SEV" \
    "$TARGET" "$TYPE" "$DETAIL" "$CONF" 2>/dev/null

  local EMOJI="🟠"
  [[ "$SEV" == "critical" ]] && EMOJI="🔴"
  [[ "$SEV" == "medium"   ]] && EMOJI="🟡"
  [[ "$SEV" == "low"      ]] && EMOJI="🔵"
  [[ "$SEV" == "info"     ]] && EMOJI="ℹ️"

  log_warn "  ⚡ [$SEV/$CONF] GraphQL $TYPE: $TARGET"

  # Telegram solo confidence>=medium AND severity>=high
  if [[ "$CONF" != "low" ]] && [[ "$SEV" == "critical" || "$SEV" == "high" ]]; then
    _telegram_send "${EMOJI} *GraphQL — ${TYPE}*
🌐 \`${DOMAIN}\`
🔗 \`${TARGET}\`
📋 ${DETAIL:0:300}
📊 Severity: \`${SEV^^}\` | Confidence: \`${CONF}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi
}

# ── 1. Introspection probe ──────────────────────────────────
_gql_introspection() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  local QUERY='{"query":"{__schema{queryType{name} mutationType{name} types{name kind fields{name type{name kind}}}}}"}'
  _h_post_noredirect "$URL" "$QUERY" --connect-timeout 8 \
    -H "Content-Type: application/json" \
    -H "Accept: application/json"

  local STATUS="$HTTP_LAST_STATUS"
  [[ "$STATUS" != "200" ]] && return 1

  # Validar JSON shape de respuesta GraphQL
  local BODY="${HTTP_LAST_BODY:0:5000}"
  if ! echo "$BODY" | grep -qE '"data"|"errors"'; then
    return 1
  fi

  # Schema completo → introspection enabled
  if echo "$BODY" | grep -qE '"__schema"|"queryType"|"mutationType"|"types"'; then
    # Extraer info útil del schema
    local TYPES_COUNT MUTATIONS
    TYPES_COUNT=$(echo "$BODY" | python3 -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    types = d.get('data',{}).get('__schema',{}).get('types',[])
    print(len(types))
except: print('?')
" 2>/dev/null)
    MUTATIONS=$(echo "$BODY" | python3 -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    mt = d.get('data',{}).get('__schema',{}).get('mutationType')
    print(mt.get('name','None') if mt else 'None')
except: print('?')
" 2>/dev/null)

    _gql_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
      "introspection_enabled" "medium" \
      "GraphQL introspection HABILITADA — schema disclosure. Types: ${TYPES_COUNT}, MutationType: ${MUTATIONS}. Atacante puede mapear toda la API y descubrir mutaciones sin documentación pública." \
      "high"

    # Guardar schema para próximas fases (sensitive fields probe)
    echo "$BODY" > "${OUT_DIR}/.gql_schema_$(echo "$URL" | md5sum | cut -d' ' -f1).json"
    return 0
  fi

  return 1
}

# ── 2. Field suggestions probe ──────────────────────────────
_gql_suggestions() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  # Query con typo deliberado para activar "Did you mean"
  local QUERY='{"query":"{ __typenameXYZ }"}'
  _h_post_noredirect "$URL" "$QUERY" --connect-timeout 8 \
    -H "Content-Type: application/json" \
    -H "Accept: application/json"

  [[ "$HTTP_LAST_STATUS" != "200" && "$HTTP_LAST_STATUS" != "400" ]] && return 1

  local BODY="${HTTP_LAST_BODY:0:2000}"
  # "Did you mean" indica field suggestions habilitados
  if echo "$BODY" | grep -qiE '"did you mean"|"didYouMean"|"suggestion"'; then
    _gql_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
      "field_suggestions_enabled" "low" \
      "GraphQL field suggestions habilitadas — atacante puede inferir field names sin introspection. Query con typo devuelve 'Did you mean'. Ej: ${BODY:0:200}" \
      "medium"
    return 0
  fi
  return 1
}

# ── 3. Alias batching probe ─────────────────────────────────
_gql_batching() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  # 5 aliases del mismo query simple — si servidor procesa todos, batching habilitado
  local QUERY='{"query":"{ a:__typename b:__typename c:__typename d:__typename e:__typename }"}'
  _h_post_noredirect "$URL" "$QUERY" --connect-timeout 8 \
    -H "Content-Type: application/json" \
    -H "Accept: application/json"

  [[ "$HTTP_LAST_STATUS" != "200" ]] && return 1

  local BODY="${HTTP_LAST_BODY:0:2000}"
  # Si las 5 aliases responden, batching enabled
  local ALIAS_COUNT
  ALIAS_COUNT=$(echo "$BODY" | grep -oE '"[a-e]"\s*:' | wc -l)
  if [[ "$ALIAS_COUNT" -ge 5 ]]; then
    _gql_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
      "alias_batching_enabled" "medium" \
      "GraphQL alias batching habilitado — atacante puede ejecutar N queries/mutations en 1 request → bypass rate-limits, brute force credentials. Test: ${ALIAS_COUNT} alias respondieron en 1 query." \
      "high"
    return 0
  fi
  return 1
}

# ── 4. Sensitive field discovery (necesita schema) ───────────
_gql_sensitive_fields() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  local SCHEMA_FILE="${OUT_DIR}/.gql_schema_$(echo "$URL" | md5sum | cut -d' ' -f1).json"
  [[ ! -s "$SCHEMA_FILE" ]] && return 1

  # Patrones de fields sensibles: credenciales, PII, tokens
  local SENSITIVE_PATTERN='password|passwd|secret|apiKey|api_key|accessToken|refresh_token|privateKey|sessionToken|jwt|ssn|creditCard|bankAccount|emailVerified|phoneNumber|dateOfBirth|nationalId'

  local FOUND
  FOUND=$(python3 -c "
import json, sys, re
try:
    d = json.load(open('$SCHEMA_FILE'))
    types = d.get('data',{}).get('__schema',{}).get('types',[])
    pattern = re.compile(r'$SENSITIVE_PATTERN', re.IGNORECASE)
    hits = []
    for t in types:
        tname = t.get('name','')
        if tname.startswith('__'): continue
        for f in t.get('fields') or []:
            fname = f.get('name','')
            if pattern.search(fname):
                hits.append(f'{tname}.{fname}')
    print('|'.join(hits[:20]))
except Exception as e:
    print('')
" 2>/dev/null)

  if [[ -n "$FOUND" ]]; then
    local COUNT
    COUNT=$(echo "$FOUND" | tr '|' '\n' | grep -c .)
    _gql_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
      "sensitive_fields_in_schema" "high" \
      "GraphQL schema expone fields sensibles (${COUNT}): ${FOUND:0:300} — verificar autorización en queries que devuelven estos fields." \
      "high"
    return 0
  fi
  return 1
}

# ── 5. Mutations sin auth ───────────────────────────────────
_gql_mutation_unauth() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  local SCHEMA_FILE="${OUT_DIR}/.gql_schema_$(echo "$URL" | md5sum | cut -d' ' -f1).json"
  [[ ! -s "$SCHEMA_FILE" ]] && return 1

  # Identificar mutations críticas (delete*, create*, update*, set*)
  local CRITICAL_MUT
  CRITICAL_MUT=$(python3 -c "
import json, sys, re
try:
    d = json.load(open('$SCHEMA_FILE'))
    schema = d.get('data',{}).get('__schema',{})
    mt = schema.get('mutationType')
    if not mt: print(''); sys.exit()
    types = schema.get('types',[])
    mut_type = next((t for t in types if t.get('name')==mt.get('name')), None)
    if not mut_type: print(''); sys.exit()
    pattern = re.compile(r'^(delete|remove|drop|reset|admin|create|update|set)', re.IGNORECASE)
    hits = [f.get('name','') for f in (mut_type.get('fields') or []) if pattern.search(f.get('name',''))]
    print('|'.join(hits[:5]))
except Exception:
    print('')
" 2>/dev/null)

  [[ -z "$CRITICAL_MUT" ]] && return 1

  # NOTA: NO ejecutamos las mutations destructivas. Solo reportamos su existencia
  # y confianza menor (medium) — explotación real requiere análisis manual.
  local COUNT
  COUNT=$(echo "$CRITICAL_MUT" | tr '|' '\n' | grep -c .)
  _gql_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
    "critical_mutations_in_schema" "medium" \
    "GraphQL schema expone mutations críticas (${COUNT}): ${CRITICAL_MUT:0:300} — confirmar si requieren auth (manual). NO ejecutado por seguridad." \
    "medium"
  return 0
}

# ── Main ─────────────────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 39 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null || true

  # Endpoints GraphQL: tech registry + urls crawleadas
  local ENDPOINTS
  ENDPOINTS=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM technologies
     WHERE domain_id=${DOMAIN_ID} AND tech_name='GraphQL'
    UNION
    SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (url LIKE '%/graphql%' OR url LIKE '%/api/graphql%'
            OR url LIKE '%/v1/graphql%' OR url LIKE '%/graphiql%')
       AND url NOT LIKE '%.json%'
       AND url NOT LIKE '%.js%'
    LIMIT 20;" 2>/dev/null | sort -u)

  if [[ -z "$ENDPOINTS" ]]; then
    log_info "  Sin endpoints GraphQL detectados — saltando"
    return 0
  fi

  local COUNT
  COUNT=$(echo "$ENDPOINTS" | grep -c .)
  log_info "  Probando ${COUNT} endpoints GraphQL..."

  local TOTAL_FINDINGS=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    log_info "  → $URL"

    # Strip trailing query params si los hay
    URL="${URL%%\?*}"

    _gql_introspection      "$URL" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL_FINDINGS++))
    _gql_suggestions        "$URL" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL_FINDINGS++))
    _gql_batching           "$URL" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL_FINDINGS++))
    _gql_sensitive_fields   "$URL" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL_FINDINGS++))
    _gql_mutation_unauth    "$URL" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL_FINDINGS++))
  done <<< "$ENDPOINTS"

  # Cleanup schemas guardados
  rm -f "${OUT_DIR}"/.gql_schema_*.json

  log_ok "$MODULE_DESC: ${TOTAL_FINDINGS} findings sobre ${COUNT} endpoints"
}
