#!/usr/bin/env bash
# ============================================================
#  modules/21_business_logic.sh
#  Fase 21: Inferencia de lógica de negocio y tests automáticos
#
#  1. Observa endpoints, params y flujos ya descubiertos
#  2. Infiere entidades de negocio (pagos, cupones, roles...)
#  3. Lanza tests específicos por tipo de entidad
#  4. Registra sugerencias para el AI Advisor
# ============================================================

MODULE_NAME="business_logic"
MODULE_DESC="Inferencia y tests de lógica de negocio"

# ── Patrones de entidades de negocio ─────────────────────────
# Formato: "TIPO|patrones de path/param separados por coma"
declare -gA ENTITY_PATTERNS=(
  [payment]="payment,checkout,cart,order,purchase,buy,billing,invoice,charge,refund,stripe,paypal,braintree"
  [coupon]="coupon,discount,promo,voucher,code,offer,deal,rebate,redeem"
  [role]="role,permission,admin,privilege,access,scope,tier,plan,level,grant"
  [subscription]="subscription,subscribe,plan,membership,tier,renewal,trial,upgrade,downgrade"
  [upload]="upload,file,attachment,document,import,media,avatar,image,photo,logo"
  [user]="user,account,profile,register,signup,login,auth,session,password,email"
  [order]="order,basket,cart,item,product,quantity,price,stock,inventory"
  [api_key]="api_key,token,secret,credential,key,access_token,client_id,client_secret"
  [transfer]="transfer,send,withdraw,deposit,balance,fund,credit,debit,wallet,amount"
  [report]="report,export,download,generate,pdf,csv,analytics,statistics,data"
)

# ── Detectar flujos de negocio reales en los endpoints ───────
# Dado un JSON array de URLs, agrupa por prefijo y detecta secuencias
# de acción (add→confirm→pay→complete) para que el AI Advisor entienda
# qué procesos multipasos tiene la aplicación, no solo qué keywords matchean.
_detect_entity_flows() {
  local ENTITY_TYPE="$1"
  local ENDPOINTS_JSON="$2"
  local PARAMS_JSON="$3"

  python3 - "$ENTITY_TYPE" "$ENDPOINTS_JSON" "$PARAMS_JSON" 2>/dev/null <<'PYEOF'
import json, sys
from urllib.parse import urlparse
from collections import defaultdict

entity_type = sys.argv[1]
try:
    urls    = json.loads(sys.argv[2])
    params  = json.loads(sys.argv[3])
except Exception:
    print("[]"); sys.exit(0)

if not urls:
    print("[]"); sys.exit(0)

# Palabras de acción ordenadas por fase del flujo (0=inicio … 3=fin)
ACTION_PHASES = [
    (0, ['add','create','new','start','init','register','begin','open']),
    (1, ['review','confirm','verify','validate','check','preview','summary']),
    (2, ['process','pay','submit','execute','send','apply','use','redeem']),
    (3, ['complete','success','done','finish','callback','return','result']),
]
WORD_TO_PHASE = {w: ph for ph, words in ACTION_PHASES for w in words}

flows = []

# Flujo 1: agrupar por host + 2 primeros segmentos de path
groups = defaultdict(list)
for url in urls:
    try:
        p = urlparse(url)
        parts = [x for x in p.path.split('/') if x]
        prefix = p.netloc + "/" + "/".join(parts[:2])
        groups[prefix].append(url)
    except Exception:
        continue

for prefix, grp in groups.items():
    if len(grp) < 2:
        continue
    steps = []
    for u in sorted(set(grp)):
        last = [x for x in urlparse(u).path.split('/') if x]
        step = last[-1] if last else ""
        if step and step not in steps:
            steps.append(step)
    if len(steps) >= 2:
        flows.append({
            "name": f"{entity_type}_flow",
            "base_path": prefix,
            "steps": steps[:8],
            "endpoint_count": len(grp),
            "params_seen": params[:8],
        })

# Flujo 2: secuencia de acciones entre URLs distintas del mismo host
by_host = defaultdict(list)
for url in urls:
    try:
        p = urlparse(url)
        path_lower = p.path.lower()
        phase = next((WORD_TO_PHASE[w] for w in WORD_TO_PHASE if w in path_lower), None)
        if phase is not None:
            action = next(w for w in WORD_TO_PHASE if w in path_lower)
            by_host[p.netloc].append({"url": url, "phase": phase, "action": action})
    except Exception:
        continue

for host, actions in by_host.items():
    if len(actions) < 2:
        continue
    actions_sorted = sorted(actions, key=lambda x: (x["phase"], x["url"]))
    flows.append({
        "name": f"{entity_type}_action_sequence",
        "host": host,
        "steps": [a["action"] for a in actions_sorted[:6]],
        "urls":  [a["url"]    for a in actions_sorted[:6]],
        "params_seen": params[:8],
    })

# Deduplicar por steps
seen, unique = set(), []
for f in flows:
    key = str(f.get("steps", []))
    if key not in seen:
        seen.add(key)
        unique.append(f)

print(json.dumps(unique[:4]))
PYEOF
}

# ── Detectar entidades en URLs y params ───────────────────────
_detect_entities() {
  local DOMAIN_ID="$1"
  local SINGLE_SUB="${2:-}"  # optional: restrict to specific host
  local ENTITIES_FOUND=()

  local HOST_FILTER=""
  local PARAM_HOST_FILTER=""
  if [[ -n "$SINGLE_SUB" ]]; then
    HOST_FILTER="AND (url LIKE 'https://${SINGLE_SUB}/%' OR url LIKE 'https://${SINGLE_SUB}?%' OR url = 'https://${SINGLE_SUB}')"
    PARAM_HOST_FILTER="AND (url LIKE 'https://${SINGLE_SUB}/%' OR url LIKE 'https://${SINGLE_SUB}?%' OR url = 'https://${SINGLE_SUB}')"
  fi

  # Leer todas las URLs y params del dominio
  local ALL_URLS
  ALL_URLS=$(sqlite3 "$DB_PATH" \
    "SELECT url FROM urls WHERE domain_id=${DOMAIN_ID} ${HOST_FILTER};" 2>/dev/null)
  local ALL_PARAMS
  ALL_PARAMS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT p.param_name FROM url_params p
     JOIN urls u ON (u.url = p.url OR u.url LIKE p.url || '?%')
     WHERE p.domain_id=${DOMAIN_ID} ${PARAM_HOST_FILTER/AND (url/AND (u.url};" 2>/dev/null)
  local ALL_ENDPOINTS
  ALL_ENDPOINTS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT endpoint FROM js_endpoints WHERE domain_id=${DOMAIN_ID};" 2>/dev/null)

  local COMBINED_TEXT
  COMBINED_TEXT=$(echo "$ALL_URLS $ALL_PARAMS $ALL_ENDPOINTS" | tr ' ' '\n' | sort -u)

  for ENTITY_TYPE in "${!ENTITY_PATTERNS[@]}"; do
    local PATTERNS="${ENTITY_PATTERNS[$ENTITY_TYPE]}"
    local MATCHED_ENDPOINTS=()
    local MATCHED_PARAMS=()

    IFS=',' read -ra PATS <<< "$PATTERNS"
    for PAT in "${PATS[@]}"; do
      # Buscar en URLs
      local MATCHED_URLS
      MATCHED_URLS=$(echo "$ALL_URLS" | grep -i "$PAT" | head -20)
      while IFS= read -r URL; do
        [[ -n "$URL" ]] && MATCHED_ENDPOINTS+=("$URL")
      done <<< "$MATCHED_URLS"

      # Buscar en params
      local MATCHED_P
      MATCHED_P=$(echo "$ALL_PARAMS" | grep -i "$PAT" | head -20)
      while IFS= read -r P; do
        [[ -n "$P" ]] && MATCHED_PARAMS+=("$P")
      done <<< "$MATCHED_P"
    done

    if [[ ${#MATCHED_ENDPOINTS[@]} -gt 0 ]] || [[ ${#MATCHED_PARAMS[@]} -gt 0 ]]; then
      # Deduplicar
      local UNIQ_ENDPOINTS
      UNIQ_ENDPOINTS=$(printf '%s\n' "${MATCHED_ENDPOINTS[@]}" | sort -u | head -20)
      local UNIQ_PARAMS
      UNIQ_PARAMS=$(printf '%s\n' "${MATCHED_PARAMS[@]}" | sort -u | head -20)

      local EP_JSON
      EP_JSON=$(echo "$UNIQ_ENDPOINTS" | python3 -c "import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null || echo "[]")
      local P_JSON
      P_JSON=$(echo "$UNIQ_PARAMS" | python3 -c "import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null || echo "[]")

      # Inferir reglas de riesgo según tipo
      local RULES_JSON
      RULES_JSON=$(_infer_rules "$ENTITY_TYPE" "$UNIQ_PARAMS")

      # Detectar flujos de negocio reales (secuencias de endpoints)
      local FLOWS_JSON
      FLOWS_JSON=$(_detect_entity_flows "$ENTITY_TYPE" "$EP_JSON" "$P_JSON")

      # Calcular risk score
      local RISK=0
      case "$ENTITY_TYPE" in
        payment|transfer) RISK=90 ;;
        coupon)           RISK=75 ;;
        role)             RISK=85 ;;
        api_key)          RISK=80 ;;
        upload)           RISK=70 ;;
        subscription)     RISK=65 ;;
        *)                RISK=50 ;;
      esac

      sqlite3 "$DB_PATH" \
        "INSERT OR REPLACE INTO business_entities
         (domain_id,entity_type,entity_name,endpoints,params,flows,rules_inferred,risk_score)
         VALUES(${DOMAIN_ID},'${ENTITY_TYPE}','${ENTITY_TYPE}',
                '${EP_JSON//\'/\'\'}','${P_JSON//\'/\'\'}',
                '${FLOWS_JSON//\'/\'\'}','${RULES_JSON//\'/\'\'}',${RISK});" 2>/dev/null || true

      ENTITIES_FOUND+=("$ENTITY_TYPE")
      log_info "  Entidad detectada: $ENTITY_TYPE (${#MATCHED_ENDPOINTS[@]} endpoints, ${#MATCHED_PARAMS[@]} params)"
    fi
  done

  printf '%s\n' "${ENTITIES_FOUND[@]}"
}

# ── Inferir reglas de negocio según tipo ─────────────────────
_infer_rules() {
  local TYPE="$1"
  local PARAMS="$2"

  local RULES=()
  case "$TYPE" in
    payment)
      RULES=(
        "¿Acepta amount negativo o cero?"
        "¿Validación de currency en servidor?"
        "¿Race condition en double-spend?"
        "¿Parámetro price modificable en request?"
        "¿Refund sin límite de veces?"
      )
      ;;
    coupon)
      RULES=(
        "¿Cupón reutilizable por mismo usuario?"
        "¿Cupón aplicable a cualquier usuario?"
        "¿Race condition en aplicación simultánea?"
        "¿Amount del cupón modificable?"
        "¿Cupón válido tras expiración?"
      )
      ;;
    role)
      RULES=(
        "¿Escalada horizontal de roles?"
        "¿Parámetro role/admin modificable?"
        "¿Endpoints de admin accesibles sin rol?"
        "¿IDOR en asignación de roles?"
        "¿JWT con role claim manipulable?"
      )
      ;;
    subscription)
      RULES=(
        "¿Downgrade sin perder acceso inmediatamente?"
        "¿Trial infinito por cancelación y re-registro?"
        "¿Plan premium accesible con plan básico?"
        "¿Race condition en upgrade/downgrade?"
      )
      ;;
    upload)
      RULES=(
        "¿Extensión validada solo en cliente?"
        "¿Tamaño sin límite en servidor?"
        "¿Path traversal en filename?"
        "¿Acceso a archivos de otros usuarios?"
        "¿SVG/HTML ejecutable tras upload?"
      )
      ;;
    transfer)
      RULES=(
        "¿Transfer con amount negativo?"
        "¿Race condition → double transfer?"
        "¿Validación de balance en servidor?"
        "¿IDOR en account_id destino?"
        "¿Overflow en amount?"
      )
      ;;
    api_key)
      RULES=(
        "¿API key con scope excesivo?"
        "¿Regeneración sin invalidar la anterior?"
        "¿API key de otro usuario accesible?"
        "¿Límite de rate por key bypasseable?"
      )
      ;;
    *)
      RULES=("¿Acceso no autorizado?", "¿IDOR en parámetros?", "¿Validación solo en cliente?")
      ;;
  esac

  python3 -c "import json; print(json.dumps($(printf '%s\n' "${RULES[@]}" | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))'  2>/dev/null || echo '[]')))" 2>/dev/null \
    || echo "[]"
}

# ── Tests por tipo de entidad ─────────────────────────────────

_test_payment_entity() {
  local DOMAIN_ID="$1" DOMAIN="$2" ENTITY_ID="$3"
  local ENDPOINTS
  ENDPOINTS=$(sqlite3 "$DB_PATH" \
    "SELECT endpoints FROM business_entities WHERE id=${ENTITY_ID};" 2>/dev/null)

  log_info "  Testing payment/transfer entity..."

  # Obtener endpoints de checkout/payment
  local PAYMENT_URLS
  PAYMENT_URLS=$(sqlite3 "$DB_PATH" \
    "SELECT url FROM urls WHERE domain_id=${DOMAIN_ID}
     AND (url LIKE '%payment%' OR url LIKE '%checkout%'
          OR url LIKE '%order%' OR url LIKE '%cart%')
     LIMIT 10;" 2>/dev/null)

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue

    # Test: ¿acepta amount negativo?
    local PARAMS_IN_URL
    PARAMS_IN_URL=$(echo "$URL" | grep -oP '[?&](amount|price|total|cost)=\K[^&]+' | head -1)
    if [[ -n "$PARAMS_IN_URL" ]]; then
      local BASE_URL="${URL%%[?]*}"
      local QUERY="${URL#*\?}"

      local NEG_QUERY
      NEG_QUERY=$(echo "$QUERY" | sed 's/\(amount\|price\|total\|cost\)=[0-9.]*/\1=-1/g')

      local RESP
      RESP=$(curl -sL --max-time 8 "${BASE_URL}?${NEG_QUERY}" -o /dev/null -w "%{http_code}" 2>/dev/null)

      if [[ "$RESP" == "200" ]]; then
        log_warn "  ⚡ Posible: amount negativo aceptado en $URL"
        sqlite3 "$DB_PATH" \
          "INSERT INTO business_tests(domain_id,entity_id,test_type,target_url,result,detail)
           VALUES(${DOMAIN_ID},${ENTITY_ID},'price_manipulation','${URL//\'/\'\'}',
                  'interesting','HTTP 200 con amount=-1');" 2>/dev/null || true
        db_add_finding "$DOMAIN_ID" "business_logic" "high" \
          "$URL" "price_manipulation" "Endpoint acepta amount negativo (HTTP 200)"
        _telegram_send "💰 *Business Logic — Price Manipulation*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
💡 Acepta amount negativo → HTTP 200
⚠️ Verificar manualmente
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
      fi
    fi

  done <<< "$PAYMENT_URLS"
}

_test_coupon_entity() {
  local DOMAIN_ID="$1" DOMAIN="$2" ENTITY_ID="$3"
  log_info "  Testing coupon entity..."

  local COUPON_URLS
  COUPON_URLS=$(sqlite3 "$DB_PATH" \
    "SELECT url FROM urls WHERE domain_id=${DOMAIN_ID}
     AND (url LIKE '%coupon%' OR url LIKE '%promo%'
          OR url LIKE '%discount%' OR url LIKE '%redeem%')
     LIMIT 5;" 2>/dev/null)

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    sqlite3 "$DB_PATH" \
      "INSERT OR IGNORE INTO business_tests(domain_id,entity_id,test_type,target_url,result,detail)
       VALUES(${DOMAIN_ID},${ENTITY_ID},'coupon_reuse','${URL//\'/\'\'}',
              'pending','Candidato para test de reutilización de cupón');" 2>/dev/null || true

    # Registrar como sugerencia de AI
    sqlite3 "$DB_PATH" \
      "INSERT OR IGNORE INTO ai_suggestions
       (domain_id,suggestion_type,priority,title,description,affected_urls,ai_model)
       VALUES(${DOMAIN_ID},'ai_depth',3,
              'Test de reutilización de cupón',
              'El endpoint ${URL} maneja cupones/descuentos. Tests recomendados: reutilización, race condition, amount manipulation, cupón de otro usuario.',
              '[\"${URL//\'/\"}\"]','haiku');" 2>/dev/null || true
  done <<< "$COUPON_URLS"
}

_test_role_entity() {
  local DOMAIN_ID="$1" DOMAIN="$2" ENTITY_ID="$3"
  log_info "  Testing role/permission entity..."

  # Buscar endpoints con role/admin en params
  local ROLE_URLS
  ROLE_URLS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT u.url FROM urls u
     JOIN url_params p ON p.url = u.url OR u.url LIKE '%' || p.url || '%'
     WHERE u.domain_id=${DOMAIN_ID}
       AND p.param_name IN ('role','admin','permission','scope','level','tier','plan')
     LIMIT 10;" 2>/dev/null)

  # También endpoints /admin/* que resuelven sin autenticación
  # Excluir rutas de auth — devolver 200 en login/signin es normal
  local ADMIN_URLS
  ADMIN_URLS=$(sqlite3 "$DB_PATH" \
    "SELECT url FROM urls WHERE domain_id=${DOMAIN_ID}
     AND (url LIKE '%/admin%' OR url LIKE '%/administrator%'
          OR url LIKE '%/superuser%' OR url LIKE '%/root%')
     AND url NOT LIKE '%/auth/%' AND url NOT LIKE '%/login%'
     AND url NOT LIKE '%/signin%' AND url NOT LIKE '%/sign_in%'
     AND url NOT LIKE '%/logout%'
     LIMIT 10;" 2>/dev/null)

  local ALL_ROLE_URLS
  # Excluir también las URLs de role_urls que sean rutas de auth
  ALL_ROLE_URLS=$(echo -e "$ROLE_URLS\n$ADMIN_URLS" | sort -u \
    | grep -ivP '/(auth|login|signin|sign_in|logout)(/|$|\?)' || true)

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue

    local RESPONSE HTTP_STATUS BODY
    RESPONSE=$(curl -sL --max-time 8 "$URL" \
      -w "\n###STATUS###%{http_code}" 2>/dev/null)
    HTTP_STATUS=$(echo "$RESPONSE" | grep -oP '(?<=###STATUS###)\d+' | tail -1)
    BODY=$(echo "$RESPONSE" | sed '/###STATUS###/d')

    [[ "$HTTP_STATUS" != "200" ]] && continue

    # Si el body contiene un formulario de login o redirect JS, es FP
    # Cubre: HTML login form, cualquier window.location redirect, meta-refresh, texto auth típico
    if echo "$BODY" | grep -qiP 'type="password"|type='"'"'password'"'"'|window\.location(\.(href|replace|assign))?\s*[=\(]|you must (sign|log) in|<meta[^>]+refresh[^>]*(login|signin)|location\.href\s*='; then
      continue
    fi
    # Body vacío o demasiado pequeño → JS-rendered, no verificable sin headless
    if [[ "${#BODY}" -lt 300 ]]; then
      continue
    fi
    # Si el body parece ser solo un script de redirect (< 2KB y contiene location)
    if [[ "${#BODY}" -lt 2000 ]] && echo "$BODY" | grep -qi 'location'; then
      continue
    fi

    log_warn "  ⚡ Endpoint admin/role accesible: $URL (HTTP 200)"
    sqlite3 "$DB_PATH" \
      "INSERT INTO business_tests(domain_id,entity_id,test_type,target_url,result,detail)
       VALUES(${DOMAIN_ID},${ENTITY_ID},'unauthorized_access','${URL//\'/\'\'}',
              'interesting','Admin endpoint HTTP 200 sin login form');" 2>/dev/null || true
    db_add_finding "$DOMAIN_ID" "business_logic" "high" \
      "$URL" "unauthorized_admin" "Endpoint admin accesible sin formulario de login (HTTP 200)"

    # Sugerencia de AI para escalada de roles
    sqlite3 "$DB_PATH" \
      "INSERT OR IGNORE INTO ai_suggestions
       (domain_id,suggestion_type,priority,title,description,affected_urls,ai_model)
       VALUES(${DOMAIN_ID},'ai_depth',2,
              'Análisis de escalada de privilegios',
              'Detectadas entidades de role/permission. Un LLM puede analizar los flujos de autorización y detectar bypasses que los regex no ven.',
              '[\"${URL//\'/\"}\"]','sonnet');" 2>/dev/null || true
  done <<< "$ALL_ROLE_URLS"
}

_test_upload_entity() {
  local DOMAIN_ID="$1" DOMAIN="$2" ENTITY_ID="$3"
  log_info "  Testing upload entity..."

  local UPLOAD_URLS
  UPLOAD_URLS=$(sqlite3 "$DB_PATH" \
    "SELECT url FROM urls WHERE domain_id=${DOMAIN_ID}
     AND (url LIKE '%upload%' OR url LIKE '%file%'
          OR url LIKE '%attachment%' OR url LIKE '%import%')
     LIMIT 5;" 2>/dev/null)

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    sqlite3 "$DB_PATH" \
      "INSERT OR IGNORE INTO ai_suggestions
       (domain_id,suggestion_type,priority,title,description,affected_urls,ai_model)
       VALUES(${DOMAIN_ID},'ai_depth',3,
              'Análisis de endpoint de upload',
              'El endpoint ${URL} acepta archivos. Tests recomendados: SVG con XSS, PHP con null byte, path traversal en filename, archivos de otros usuarios (IDOR).',
              '[\"${URL//\'/\"}\"]','haiku');" 2>/dev/null || true
  done <<< "$UPLOAD_URLS"
}

_test_race_conditions() {
  local DOMAIN_ID="$1" DOMAIN="$2"
  log_info "  Testing race condition candidates..."

  # Endpoints que modifican estado — candidatos a race condition
  local STATE_URLS
  STATE_URLS=$(sqlite3 "$DB_PATH" \
    "SELECT url FROM urls WHERE domain_id=${DOMAIN_ID}
     AND (url LIKE '%/apply%' OR url LIKE '%/redeem%'
          OR url LIKE '%/transfer%' OR url LIKE '%/purchase%'
          OR url LIKE '%/confirm%' OR url LIKE '%/claim%'
          OR url LIKE '%/use%')
     LIMIT 10;" 2>/dev/null)

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    log_info "  Candidato race condition: $URL"
    sqlite3 "$DB_PATH" \
      "INSERT OR IGNORE INTO ai_suggestions
       (domain_id,suggestion_type,priority,title,description,affected_urls,ai_model)
       VALUES(${DOMAIN_ID},'ai_depth',2,
              'Race condition candidate',
              'El endpoint ${URL} modifica estado y es candidato a race condition. Probar con Turbo Intruder (Burp) o ffuf paralelo.',
              '[\"${URL//\'/\"}\"]','haiku');" 2>/dev/null || true
  done <<< "$STATE_URLS"
}

# ── Función principal ─────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 21 — $MODULE_DESC: $DOMAIN"

  # Detect single-target mode for scoping
  local ALIVE_FILE="$OUT_DIR/subs_alive.txt"
  local _SINGLE_SUB=""
  if [[ -s "$ALIVE_FILE" && "$(wc -l < "$ALIVE_FILE" | tr -d ' ')" == "1" ]]; then
    _SINGLE_SUB=$(head -1 "$ALIVE_FILE" | tr -d '[:space:]')
  fi

  # ── Detectar entidades ─────────────────────────────────────
  log_info "Inferiendo modelo de negocio..."
  local ENTITIES
  mapfile -t ENTITIES < <(_detect_entities "$DOMAIN_ID" "$_SINGLE_SUB")

  if [[ ${#ENTITIES[@]} -eq 0 ]]; then
    log_info "No se detectaron entidades de negocio relevantes"
    return
  fi

  log_ok "Entidades detectadas: ${ENTITIES[*]}"

  # ── Tests por entidad ──────────────────────────────────────
  for ENTITY_TYPE in "${ENTITIES[@]}"; do
    [[ -z "$ENTITY_TYPE" ]] && continue

    local ENTITY_ID
    ENTITY_ID=$(sqlite3 "$DB_PATH" \
      "SELECT id FROM business_entities
       WHERE domain_id=${DOMAIN_ID} AND entity_type='${ENTITY_TYPE}';" 2>/dev/null | head -1)
    [[ -z "$ENTITY_ID" ]] && ENTITY_ID=0

    case "$ENTITY_TYPE" in
      payment|transfer) _test_payment_entity "$DOMAIN_ID" "$DOMAIN" "$ENTITY_ID" ;;
      coupon)           _test_coupon_entity  "$DOMAIN_ID" "$DOMAIN" "$ENTITY_ID" ;;
      role)             _test_role_entity    "$DOMAIN_ID" "$DOMAIN" "$ENTITY_ID" ;;
      upload)           _test_upload_entity  "$DOMAIN_ID" "$DOMAIN" "$ENTITY_ID" ;;
    esac
  done

  # ── Race condition sweep global ────────────────────────────
  _test_race_conditions "$DOMAIN_ID" "$DOMAIN"

  local TOTAL_ENTITIES TOTAL_SUGGESTIONS
  TOTAL_ENTITIES=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM business_entities WHERE domain_id=${DOMAIN_ID};" 2>/dev/null || echo 0)
  TOTAL_SUGGESTIONS=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM ai_suggestions WHERE domain_id=${DOMAIN_ID};" 2>/dev/null || echo 0)

  # Exportar resumen estructurado para AI Advisor
  local BL_JSON="$OUT_DIR/business_logic.json"
  python3 - "$DB_PATH" "$DOMAIN_ID" "$DOMAIN" > "$BL_JSON" 2>/dev/null <<'PYEOF'
import sqlite3, json, sys

db_path, dom_id, domain = sys.argv[1], int(sys.argv[2]), sys.argv[3]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

entities = conn.execute(
    """SELECT entity_type, risk_score, endpoints, params, flows, rules_inferred
       FROM business_entities WHERE domain_id=? ORDER BY risk_score DESC""",
    (dom_id,)
).fetchall()

def pj(v):
    try: return json.loads(v or "[]")
    except: return []

output = {
    "domain": domain,
    "entity_count": len(entities),
    "entities": [
        {
            "type":      r["entity_type"],
            "risk":      r["risk_score"],
            "endpoints": pj(r["endpoints"]),
            "params":    pj(r["params"]),
            "flows":     pj(r["flows"]),
            "rules":     pj(r["rules_inferred"]),
        }
        for r in entities
    ],
}
print(json.dumps(output, indent=2, ensure_ascii=False))
conn.close()
PYEOF
  log_ok "Business logic exportado: $BL_JSON"

  if [[ "$TOTAL_ENTITIES" -gt 0 ]]; then
    _telegram_send "🏢 *Business Logic Analysis*
🌐 \`${DOMAIN}\`
📊 Entidades detectadas: \`${TOTAL_ENTITIES}\`
💡 Sugerencias IA generadas: \`${TOTAL_SUGGESTIONS}\`
🎯 Entidades: ${ENTITIES[*]}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi

  log_ok "$MODULE_DESC completado: $TOTAL_ENTITIES entidades, $TOTAL_SUGGESTIONS sugerencias"
}
