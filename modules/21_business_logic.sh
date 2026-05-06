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

    local RESPONSE HTTP_STATUS BODY EFFECTIVE_URL
    RESPONSE=$(curl -sL --max-time 8 "$URL" \
      -w "\n###STATUS###%{http_code}\n###EFF###%{url_effective}" 2>/dev/null)
    HTTP_STATUS=$(echo "$RESPONSE" | grep -oP '(?<=###STATUS###)\d+' | tail -1)
    EFFECTIVE_URL=$(echo "$RESPONSE" | grep -oP '(?<=###EFF###).*' | tail -1)
    BODY=$(echo "$RESPONSE" | sed '/###STATUS###/d; /###EFF###/d')

    [[ "$HTTP_STATUS" != "200" ]] && continue

    # Si el redirect salió del dominio target, es FP (e.g. duckling → github.com)
    local TARGET_DOMAIN
    TARGET_DOMAIN=$(echo "$URL" | grep -oP 'https?://\K[^/?#]+' | sed 's/^www\.//')
    if [[ -n "$EFFECTIVE_URL" ]] && ! echo "$EFFECTIVE_URL" | grep -q "$TARGET_DOMAIN"; then
      continue
    fi

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

# ── Construir mapa compacto de superficie para análisis AI ───
_build_url_surface() {
  local DOMAIN_ID="$1"
  local SINGLE_SUB="${2:-}"

  python3 - "$DB_PATH" "$DOMAIN_ID" "$SINGLE_SUB" 2>/dev/null <<'PYEOF'
import sqlite3, json, sys
from urllib.parse import urlparse
from collections import defaultdict

db_path, dom_id, single_sub = sys.argv[1], int(sys.argv[2]), sys.argv[3]
conn = sqlite3.connect(db_path)

extra = ""
if single_sub:
    extra = f" AND (url LIKE 'https://{single_sub}/%' OR url LIKE 'https://{single_sub}?%')"

urls   = [r[0] for r in conn.execute(f"SELECT url FROM urls WHERE domain_id=?{extra} LIMIT 2000", (dom_id,)).fetchall()]
params = [r[0] for r in conn.execute("SELECT DISTINCT param_name FROM url_params WHERE domain_id=? LIMIT 100", (dom_id,)).fetchall()]
js_ep  = [r[0] for r in conn.execute("SELECT DISTINCT endpoint FROM js_endpoints WHERE domain_id=? LIMIT 100", (dom_id,)).fetchall()]

SKIP_EXT = {'.js','.css','.png','.jpg','.gif','.svg','.ico','.woff','.woff2','.ttf','.map','.json'}
SKIP_PFX = {'static','assets','_next','__webpack','node_modules','vendor','fonts','images','img'}

groups = defaultdict(int)
for url in urls:
    try:
        p = urlparse(url)
        parts = [x for x in p.path.split('/') if x]
        if not parts or parts[0].lower() in SKIP_PFX:
            continue
        if any(parts[-1].lower().endswith(e) for e in SKIP_EXT):
            continue
        key = '/'.join(parts[:3])
        groups[key] += 1
    except Exception:
        continue

top = sorted(groups.items(), key=lambda x: -x[1])[:50]
print(json.dumps({
    "path_groups":  dict(top),
    "params":       params[:60],
    "js_endpoints": [e for e in js_ep[:40] if not any(e.endswith(x) for x in SKIP_EXT)],
    "total_urls":   len(urls),
}))
conn.close()
PYEOF
}

# ── Descubrimiento de entidades con IA (sin lista fija) ───────
# Si no hay ANTHROPIC_API_KEY cae a la detección heurística.
# Claude Haiku identifica cualquier tipo de entidad de negocio
# que encuentre en la estructura de URLs/params/JS de la app.
_discover_entities_ai() {
  local DOMAIN_ID="$1"
  local DOMAIN="$2"
  local SINGLE_SUB="${3:-}"

  if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    log_info "  Sin ANTHROPIC_API_KEY — detección heurística"
    _detect_entities "$DOMAIN_ID" "$SINGLE_SUB"
    return
  fi

  log_info "  Identificando entidades de negocio con IA (Haiku)..."

  local SURFACE
  SURFACE=$(_build_url_surface "$DOMAIN_ID" "$SINGLE_SUB")

  if [[ -z "$SURFACE" ]] || python3 -c "import json,sys; d=json.loads(sys.argv[1]); exit(0 if d.get('total_urls',0)>0 else 1)" "$SURFACE" 2>/dev/null || false; then
    :
  else
    log_warn "  Sin URLs — usando heurística"
    _detect_entities "$DOMAIN_ID" "$SINGLE_SUB"
    return
  fi

  # El heredoc con f-strings Python (""") no puede ir dentro de $() en bash.
  # Usamos un tempfile para evitar el problema de parseo.
  local _AI_TMP="/tmp/_hackeadora_bl_$$.json"
  python3 - "$ANTHROPIC_API_KEY" "$DOMAIN" "$SURFACE" > "$_AI_TMP" 2>/dev/null <<'PYEOF'
import json, sys, requests

api_key, domain = sys.argv[1], sys.argv[2]
try:
    surface = json.loads(sys.argv[3])
except Exception:
    print("{}"); sys.exit(0)

system = (
    "You are a security researcher analyzing a web application's URL structure "
    "to identify its business domain entities for bug bounty testing. "
    "Be exhaustive and domain-specific — go beyond generic e-commerce terms. "
    "Respond ONLY with valid JSON, no markdown."
)

path_groups_str = json.dumps(surface.get('path_groups', {}), indent=2)
params_str      = json.dumps(surface.get('params', []))
js_ep_str       = json.dumps(surface.get('js_endpoints', []))
total_urls      = surface.get('total_urls', 0)

prompt = (
    "Application: " + domain + "\n\n"
    "URL path groups (path -> hit count):\n" + path_groups_str + "\n\n"
    "Query parameters across all URLs:\n" + params_str + "\n\n"
    "JavaScript API endpoints:\n" + js_ep_str + "\n\n"
    "Total URLs crawled: " + str(total_urls) + "\n\n"
    "Identify all business entities this application manages.\n"
    "Use domain-specific names (e.g. insulin_order, insurance_claim, fund_transfer).\n\n"
    'Return JSON:\n'
    '{\n'
    '  "app_type": "what this application does in 1 sentence",\n'
    '  "entities": [\n'
    '    {\n'
    '      "entity_type": "snake_case_name",\n'
    '      "name": "Human Readable Name",\n'
    '      "description": "what this entity represents",\n'
    '      "endpoints": ["relevant/paths"],\n'
    '      "params": ["relevant_param_names"],\n'
    '      "risk_score": 75,\n'
    '      "attack_surface": ["specific concern 1"]\n'
    '    }\n'
    '  ]\n'
    '}'
)

try:
    r = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 1500,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=45,
    )
    if r.status_code != 200:
        print("{}"); sys.exit(0)
    raw = r.json()["content"][0]["text"].strip()
    raw = raw.lstrip("```json").lstrip("```").rstrip("```").strip()
    print(raw)
except Exception as e:
    print("[!] " + str(e), file=sys.stderr)
    print("{}")
PYEOF
  local AI_RESULT
  AI_RESULT=$(cat "$_AI_TMP" 2>/dev/null || echo "{}")
  rm -f "$_AI_TMP"

  # Validate and save to DB (tempfile evita problema de bash con """ en $())
  local _SAVE_TMP="/tmp/_hackeadora_save_$$.txt"
  python3 - "$DB_PATH" "$DOMAIN_ID" "$AI_RESULT" > "$_SAVE_TMP" 2>/dev/null <<'PYEOF'
import sqlite3, json, sys

db_path, dom_id = sys.argv[1], int(sys.argv[2])
try:
    data = json.loads(sys.argv[3])
except Exception:
    print(""); sys.exit(0)

entities = data.get("entities", []) if isinstance(data, dict) else []
if not entities:
    print(""); sys.exit(0)

conn = sqlite3.connect(db_path)
conn.execute("PRAGMA busy_timeout=15000;")
names = []
for e in entities:
    etype = str(e.get("entity_type", "")).strip()
    if not etype:
        continue
    eps   = json.dumps(e.get("endpoints", []))
    pms   = json.dumps(e.get("params", []))
    risk  = max(0, min(100, int(e.get("risk_score", 50) or 50)))
    rules = json.dumps(e.get("attack_surface", []))
    name  = e.get("name", etype)
    conn.execute(
        "INSERT OR REPLACE INTO business_entities"
        "(domain_id,entity_type,entity_name,endpoints,params,flows,rules_inferred,risk_score)"
        " VALUES(?,?,?,?,?,'[]',?,?)",
        (dom_id, etype, name, eps, pms, rules, risk)
    )
    names.append(etype)
conn.commit()
conn.close()
print('\n'.join(names))
PYEOF
  local SAVED_ENTITIES
  SAVED_ENTITIES=$(cat "$_SAVE_TMP" 2>/dev/null || echo "")
  rm -f "$_SAVE_TMP"

  if [[ -z "$SAVED_ENTITIES" ]]; then
    log_warn "  IA sin entidades útiles — usando heurística"
    _detect_entities "$DOMAIN_ID" "$SINGLE_SUB"
    return
  fi

  # Detect flows for each AI-discovered entity and update DB
  while IFS= read -r ETYPE; do
    [[ -z "$ETYPE" ]] && continue
    local EP_JSON P_JSON
    EP_JSON=$(sqlite3 "$DB_PATH" "SELECT endpoints FROM business_entities WHERE domain_id=${DOMAIN_ID} AND entity_type='${ETYPE//\'/\'\'}';" 2>/dev/null || echo "[]")
    P_JSON=$(sqlite3  "$DB_PATH" "SELECT params    FROM business_entities WHERE domain_id=${DOMAIN_ID} AND entity_type='${ETYPE//\'/\'\'}';" 2>/dev/null || echo "[]")
    local FLOWS_JSON
    FLOWS_JSON=$(_detect_entity_flows "$ETYPE" "$EP_JSON" "$P_JSON")
    sqlite3 "$DB_PATH" \
      "UPDATE business_entities SET flows='${FLOWS_JSON//\'/\'\'}'
       WHERE domain_id=${DOMAIN_ID} AND entity_type='${ETYPE//\'/\'\'}';" 2>/dev/null || true
  done <<< "$SAVED_ENTITIES"

  local APP_TYPE
  APP_TYPE=$(echo "$AI_RESULT" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('app_type',''))" 2>/dev/null || echo "")
  [[ -n "$APP_TYPE" ]] && log_info "  Tipo de aplicación: $APP_TYPE"

  echo "$SAVED_ENTITIES"
}

# ── Buscar formularios de registro ────────────────────────────
_find_registration_forms() {
  local DOMAIN_ID="$1"
  local SINGLE_SUB="${2:-}"

  local HOST_FILTER=""
  [[ -n "$SINGLE_SUB" ]] && HOST_FILTER=" AND (url LIKE 'https://${SINGLE_SUB}/%' OR url LIKE 'https://${SINGLE_SUB}?%')"

  sqlite3 "$DB_PATH" 2>/dev/null \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID} ${HOST_FILTER}
       AND (  url LIKE '%/register%'      OR url LIKE '%/signup%'
           OR url LIKE '%/sign-up%'       OR url LIKE '%/sign_up%'
           OR url LIKE '%/join%'          OR url LIKE '%/create-account%'
           OR url LIKE '%/create_account%' OR url LIKE '%/new-account%'
           OR url LIKE '%/enroll%'        OR url LIKE '%/registration%'
           OR url LIKE '%/onboarding%'    OR url LIKE '%/get-started%'
           OR url LIKE '%/open-account%'  OR url LIKE '%/new-user%')
       AND url NOT LIKE '%/api/%'
       AND url NOT LIKE '%.js%'
     ORDER BY length(url)
     LIMIT 10;"
}

# ── Intentar registro automático en un formulario ────────────
# Todo el parseo HTML y la detección de éxito van a Python (tempfiles)
# para evitar problemas de quoting en bash con regexes y heredocs.
_attempt_registration() {
  local DOMAIN_ID="$1"
  local DOMAIN="$2"
  local REG_URL="$3"
  local PROXY_FLAG="${4:-}"

  local SUBDOMAIN
  SUBDOMAIN=$(echo "$REG_URL" | sed 's|https\?://||;s|[:/].*||')

  # Saltar si ya hay credenciales válidas para este subdominio
  local HAS_CREDS
  HAS_CREDS=$(sqlite3 "$DB_PATH" 2>/dev/null \
    "SELECT COUNT(*) FROM auth_credentials
     WHERE domain_id=${DOMAIN_ID} AND subdomain='${SUBDOMAIN//\'/\'\'}' AND valid=1;" || echo 0)
  if [[ "${HAS_CREDS:-0}" -gt 0 ]]; then
    log_info "  Ya registrado en $SUBDOMAIN — saltando"
    return
  fi

  log_info "  Analizando formulario de registro: $REG_URL"

  # Credenciales de test deterministas por target
  local HASH
  HASH=$(printf '%s%s' "$DOMAIN" "$SUBDOMAIN" | md5sum | cut -c1-8)
  local TEST_EMAIL="bbtest_${HASH}@mailinator.com"
  local TEST_PASS="T3stP@ss_${HASH}!"
  local TEST_NAME="BbTest${HASH^}"

  # Tempfiles para evitar heredocs dentro de $()
  local _REG_HTML="/tmp/reg_html_$$.html"
  local _REG_FORM="/tmp/reg_form_$$.txt"
  local _REG_VAULT="/tmp/reg_vault_$$.txt"
  local _COOKIE_JAR="/tmp/reg_cookies_$$.txt"

  # Fetch página de registro
  curl -sL --max-time 12 \
    -A "${SCAN_UA:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36}" \
    -c "$_COOKIE_JAR" ${PROXY_FLAG} "$REG_URL" 2>/dev/null | head -c 150000 > "$_REG_HTML"

  if [[ ! -s "$_REG_HTML" ]]; then
    rm -f "$_REG_HTML" "$_COOKIE_JAR"
    return
  fi

  # Parsear form: extrae FORM_ACTION y POST_DATA en JSON
  # Delega completamente a Python para evitar quoting hell en bash
  python3 - "$_REG_HTML" "$TEST_EMAIL" "$TEST_PASS" "$TEST_NAME" > "$_REG_FORM" 2>/dev/null <<'PYEOF'
import sys, re, json
from urllib.parse import urlencode

html_file, email, password, name = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(html_file) as f:
    html = f.read()

# Check for password field
if not re.search(r'type=["\x27]password["\x27]', html, re.I):
    print(json.dumps({"has_form": False}))
    sys.exit(0)

# Extract form action
action = ""
m = re.search(r'<form[^>]+action=["\x27]([^"\x27\s>]+)', html, re.I)
if m:
    action = m.group(1)

# Extract CSRF
csrf = ""
for pat in [
    r'name=["\x27](?:csrf_token|_token|authenticity_token|csrfmiddlewaretoken|__RequestVerificationToken)["\x27][^>]*value=["\x27]([^"\x27]+)',
    r'value=["\x27]([^"\x27]+)["\x27][^>]*name=["\x27](?:csrf_token|_token|authenticity_token|csrfmiddlewaretoken)',
]:
    m = re.search(pat, html, re.I)
    if m:
        csrf = m.group(1)
        break

# Parse input fields
inputs = re.findall(r'<input[^>]+>', html, re.I)
data = {}

EMAIL_N = {'email','username','user','login','mail','email_address','user_email','identifier','correo'}
PASS_N  = {'password','pass','pwd','passwd','password1','new_password'}
PASS2_N = {'password2','confirm_password','password_confirmation','retype_password','repeat_password','pass_confirm'}
FNAME_N = {'first_name','firstname','fname','given_name','nombre'}
LNAME_N = {'last_name','lastname','lname','surname','apellido','apellidos'}
NAME_N  = {'name','full_name','fullname','display_name','nickname'}
CSRF_N  = {'csrf_token','_token','authenticity_token','csrfmiddlewaretoken','csrf','__requestverificationtoken'}

for inp in inputs:
    nm = re.search(r'\bname=["\x27]([^"\x27]+)["\x27]', inp, re.I)
    tp = re.search(r'\btype=["\x27]([^"\x27]+)["\x27]', inp, re.I)
    vl = re.search(r'\bvalue=["\x27]([^"\x27]*)["\x27]', inp, re.I)
    if not nm:
        continue
    n = nm.group(1)
    t = (tp.group(1) if tp else 'text').lower()
    v = vl.group(1) if vl else ''
    nl = n.lower()

    if t == 'hidden':
        data[n] = csrf if (nl in CSRF_N and csrf) else v
    elif t == 'submit':
        data[n] = v or 'Register'
    elif t == 'checkbox':
        data[n] = '1'
    elif nl in EMAIL_N or 'email' in nl or 'mail' in nl:
        data[n] = email
    elif nl in PASS2_N or ('confirm' in nl and 'pass' in nl):
        data[n] = password
    elif nl in PASS_N or t == 'password':
        data[n] = password
    elif nl in FNAME_N:
        data[n] = 'BbTest'
    elif nl in LNAME_N:
        data[n] = 'Security'
    elif nl in NAME_N or 'name' in nl:
        data[n] = name
    elif nl in CSRF_N:
        data[n] = csrf if csrf else v
    elif 'phone' in nl or 'mobile' in nl or 'tel' in nl:
        data[n] = '+34600000001'
    elif 'birth' in nl or 'dob' in nl:
        data[n] = '1990-01-01'
    elif t == 'text':
        data[n] = name

print(json.dumps({"has_form": True, "action": action, "post_data": urlencode(data)}))
PYEOF

  # Leer resultado del parseo
  local HAS_FORM FORM_ACTION POST_DATA
  HAS_FORM=$(python3 -c "import json,sys; d=json.load(open('${_REG_FORM}')); print(d.get('has_form',False))" 2>/dev/null || echo "False")
  FORM_ACTION=$(python3 -c "import json,sys; d=json.load(open('${_REG_FORM}')); print(d.get('action',''))" 2>/dev/null || echo "")
  POST_DATA=$(python3 -c "import json,sys; d=json.load(open('${_REG_FORM}')); print(d.get('post_data',''))" 2>/dev/null || echo "")
  rm -f "$_REG_HTML"

  if [[ "$HAS_FORM" != "True" ]]; then
    rm -f "$_REG_FORM" "$_COOKIE_JAR"
    _telegram_send "📋 *Registro sin formulario HTML*
🌐 \`${DOMAIN}\`
🔗 \`${REG_URL}\`
ℹ️ Posible OAuth/SSO — registro manual necesario
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
    return
  fi
  rm -f "$_REG_FORM"

  if [[ -z "$POST_DATA" ]]; then
    rm -f "$_COOKIE_JAR"
    _telegram_send "📋 *Registro encontrado — acción manual*
🌐 \`${DOMAIN}\`
🔗 \`${REG_URL}\`
⚠️ No se pudieron extraer campos del formulario
🔑 Credenciales sugeridas:
  Email:    \`${TEST_EMAIL}\`
  Password: \`${TEST_PASS}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
    return
  fi

  # Determinar URL de destino del POST
  local POST_URL="$REG_URL"
  if [[ -n "$FORM_ACTION" ]]; then
    if echo "$FORM_ACTION" | grep -q '^https\?://'; then
      POST_URL="$FORM_ACTION"
    elif echo "$FORM_ACTION" | grep -q '^/'; then
      local ORIGIN
      ORIGIN=$(echo "$REG_URL" | grep -oP 'https?://[^/]+')
      POST_URL="${ORIGIN}${FORM_ACTION}"
    fi
  fi

  # Enviar formulario
  local RAW_RESP
  RAW_RESP=$(curl -sL --max-time 15 \
    -A "${SCAN_UA:-Mozilla/5.0}" \
    -b "$_COOKIE_JAR" -c "$_COOKIE_JAR" \
    -X POST ${PROXY_FLAG} \
    --data "$POST_DATA" \
    -w "\n###STATUS###%{http_code}###URL###%{url_effective}" \
    "$POST_URL" 2>/dev/null)

  local HTTP_STATUS FINAL_URL RESP_BODY
  HTTP_STATUS=$(echo "$RAW_RESP" | grep -oP '(?<=###STATUS###)\d+' | tail -1)
  FINAL_URL=$(echo "$RAW_RESP"   | grep -oP '(?<=###URL###).+'    | tail -1)
  RESP_BODY=$(echo "$RAW_RESP"   | sed '/###STATUS###/d')

  rm -f "$_COOKIE_JAR"

  # Detectar éxito
  local SUCCESS=false SUCCESS_REASON=""
  if echo "$FINAL_URL" | grep -qiP '/(dashboard|home|profile|account|welcome|app(/|$)|portal|inicio)'; then
    SUCCESS=true; SUCCESS_REASON="redirect a ${FINAL_URL}"
  elif echo "$RESP_BODY" | grep -qiP 'welcome|thank you|successfully|account created|verify your email|confirm.*email|check.*inbox|activat'; then
    SUCCESS=true; SUCCESS_REASON="mensaje de éxito en respuesta"
  elif [[ "$HTTP_STATUS" =~ ^2 ]] && ! echo "$RESP_BODY" | grep -qiP 'already (exists|registered|taken)|invalid|error|failed|incorrect'; then
    SUCCESS=true; SUCCESS_REASON="HTTP ${HTTP_STATUS} sin errores"
  fi

  local NEEDS_VERIFY=false
  echo "$RESP_BODY" | grep -qiP 'verify|confirm.*email|check.*inbox|activat' && NEEDS_VERIFY=true

  if [[ "$SUCCESS" == true ]]; then
    # Cifrar contraseña (XOR+base64) vía tempfile para evitar heredoc en $()
    python3 - "$TEST_PASS" > "$_REG_VAULT" 2>/dev/null <<'PYVAULT'
import base64, os, sys
key = os.environ.get('VAULT_KEY', 'hackeadora').encode()
pwd = sys.argv[1].encode()
cycle = (key * (len(pwd) // len(key) + 1))[:len(pwd)]
enc = bytes(a ^ b for a, b in zip(pwd, cycle))
print(base64.b64encode(enc).decode())
PYVAULT
    local PASS_ENC
    PASS_ENC=$(cat "$_REG_VAULT" 2>/dev/null || printf '%s' "$TEST_PASS" | base64)
    rm -f "$_REG_VAULT"

    db_vault_add "$DOMAIN_ID" "$DOMAIN" "$SUBDOMAIN" \
      "$REG_URL" "$TEST_EMAIL" "$PASS_ENC" "form" \
      "auto-registered${NEEDS_VERIFY:+ — email verification pending}" 2>/dev/null || true

    local VERIFY_NOTE=""
    if [[ "$NEEDS_VERIFY" == true ]]; then
      VERIFY_NOTE="
📧 Requiere verificación en: \`${TEST_EMAIL}\`
   Bandeja: https://www.mailinator.com/v4/public/inboxes.jsp?to=bbtest_${HASH}"
    fi

    _telegram_send "✅ *Registro automático exitoso*
🌐 \`${DOMAIN}\`
🔗 \`${REG_URL}\`
📧 Email: \`${TEST_EMAIL}\`
🔑 Pass:  \`${TEST_PASS}\`
✅ ${SUCCESS_REASON}${VERIFY_NOTE}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

    log_ok "  Registrado: ${TEST_EMAIL} en ${SUBDOMAIN}"
    local FINDING_DETAIL="Cuenta creada: ${TEST_EMAIL} — ${SUCCESS_REASON}"
    db_add_finding "$DOMAIN_ID" "business_logic" "info" \
      "$REG_URL" "auto_registered" "$FINDING_DETAIL"

  else
    _telegram_send "📋 *Registro encontrado — verificar manualmente*
🌐 \`${DOMAIN}\`
🔗 \`${REG_URL}\`
📊 HTTP ${HTTP_STATUS:-?} — resultado no confirmado
🔑 Credenciales usadas:
  Email:    \`${TEST_EMAIL}\`
  Password: \`${TEST_PASS}\`
⚠️ Comprueba si el registro fue exitoso
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

    log_info "  Registro no confirmado en $SUBDOMAIN — notificado"
  fi
}

# ── Encolar sugerencia AI para entidad descubierta dinámicamente
_queue_ai_suggestion_for_entity() {
  local DOMAIN_ID="$1"
  local ENTITY_TYPE="$2"
  python3 - "$DB_PATH" "$DOMAIN_ID" "$ENTITY_TYPE" 2>/dev/null <<'PYEOF'
import sqlite3, sys
db_path, dom_id, etype = sys.argv[1], int(sys.argv[2]), sys.argv[3]
conn = sqlite3.connect(db_path)
conn.execute("PRAGMA busy_timeout=15000;")
row = conn.execute(
    "SELECT rules_inferred FROM business_entities WHERE domain_id=? AND entity_type=?",
    (dom_id, etype)
).fetchone()
attack_surface = (row[0] or "[]") if row else "[]"
conn.execute(
    "INSERT OR IGNORE INTO ai_suggestions"
    "(domain_id,suggestion_type,priority,title,description,affected_urls,ai_model)"
    " VALUES(?,?,?,?,?,?,?)",
    (dom_id, 'ai_depth', 3, f'Análisis entidad: {etype}',
     f'Entidad IA. Attack surface: {attack_surface}', '[]', 'sonnet')
)
conn.commit()
conn.close()
PYEOF
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

  # ── Descubrir entidades (IA si hay API key, heurística si no) ─
  log_info "Identificando modelo de negocio..."
  local ENTITIES
  mapfile -t ENTITIES < <(_discover_entities_ai "$DOMAIN_ID" "$DOMAIN" "$_SINGLE_SUB")

  if [[ ${#ENTITIES[@]} -eq 0 ]]; then
    log_info "No se detectaron entidades de negocio"
  else
    log_ok "Entidades detectadas: ${ENTITIES[*]}"

    # ── Tests por entidad ────────────────────────────────────
    for ENTITY_TYPE in "${ENTITIES[@]}"; do
      [[ -z "$ENTITY_TYPE" ]] && continue

      local ENTITY_ID
      ENTITY_ID=$(sqlite3 "$DB_PATH" \
        "SELECT id FROM business_entities
         WHERE domain_id=${DOMAIN_ID} AND entity_type='${ENTITY_TYPE}';" 2>/dev/null | head -1)
      [[ -z "$ENTITY_ID" ]] && ENTITY_ID=0

      # Tests específicos para tipos conocidos
      case "$ENTITY_TYPE" in
        payment|transfer) _test_payment_entity "$DOMAIN_ID" "$DOMAIN" "$ENTITY_ID" ;;
        coupon)           _test_coupon_entity  "$DOMAIN_ID" "$DOMAIN" "$ENTITY_ID" ;;
        role)             _test_role_entity    "$DOMAIN_ID" "$DOMAIN" "$ENTITY_ID" ;;
        upload)           _test_upload_entity  "$DOMAIN_ID" "$DOMAIN" "$ENTITY_ID" ;;
        *)
          # Tipo dinámico descubierto por IA → sugerencia para AI Advisor
          _queue_ai_suggestion_for_entity "$DOMAIN_ID" "$ENTITY_TYPE"
          ;;
      esac
    done
  fi

  # ── Race condition sweep global ────────────────────────────
  _test_race_conditions "$DOMAIN_ID" "$DOMAIN"

  # ── Registro automático ─────────────────────────────────────
  log_info "Buscando formularios de registro..."
  local PROXY_FLAG=""
  type proxy_check &>/dev/null && PROXY_FLAG="${PROXY_CURL_FLAG:-}"

  local REG_URLS
  mapfile -t REG_URLS < <(_find_registration_forms "$DOMAIN_ID" "$_SINGLE_SUB")
  if [[ ${#REG_URLS[@]} -eq 0 ]]; then
    log_info "No se encontraron formularios de registro"
  else
    log_info "Formularios de registro encontrados: ${#REG_URLS[@]}"
    for REG_URL in "${REG_URLS[@]}"; do
      [[ -z "$REG_URL" ]] && continue
      _attempt_registration "$DOMAIN_ID" "$DOMAIN" "$REG_URL" "$PROXY_FLAG"
    done
  fi

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
