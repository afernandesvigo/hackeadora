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
declare -A ENTITY_PATTERNS=(
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

# ── Detectar entidades en URLs y params ───────────────────────
_detect_entities() {
  local DOMAIN_ID="$1"
  local ENTITIES_FOUND=()

  # Leer todas las URLs y params del dominio
  local ALL_URLS
  ALL_URLS=$(sqlite3 "$DB_PATH" \
    "SELECT url FROM urls WHERE domain_id=${DOMAIN_ID};" 2>/dev/null)
  local ALL_PARAMS
  ALL_PARAMS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT param_name FROM url_params WHERE domain_id=${DOMAIN_ID};" 2>/dev/null)
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
      MATCHED_URLS=$(echo "$ALL_URLS" | grep -i "$PAT" | head -5)
      while IFS= read -r URL; do
        [[ -n "$URL" ]] && MATCHED_ENDPOINTS+=("$URL")
      done <<< "$MATCHED_URLS"

      # Buscar en params
      local MATCHED_P
      MATCHED_P=$(echo "$ALL_PARAMS" | grep -i "$PAT" | head -5)
      while IFS= read -r P; do
        [[ -n "$P" ]] && MATCHED_PARAMS+=("$P")
      done <<< "$MATCHED_P"
    done

    if [[ ${#MATCHED_ENDPOINTS[@]} -gt 0 ]] || [[ ${#MATCHED_PARAMS[@]} -gt 0 ]]; then
      # Deduplicar
      local UNIQ_ENDPOINTS
      UNIQ_ENDPOINTS=$(printf '%s\n' "${MATCHED_ENDPOINTS[@]}" | sort -u | head -10)
      local UNIQ_PARAMS
      UNIQ_PARAMS=$(printf '%s\n' "${MATCHED_PARAMS[@]}" | sort -u | head -10)

      local EP_JSON
      EP_JSON=$(echo "$UNIQ_ENDPOINTS" | python3 -c "import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null || echo "[]")
      local P_JSON
      P_JSON=$(echo "$UNIQ_PARAMS" | python3 -c "import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null || echo "[]")

      # Inferir reglas de riesgo según tipo
      local RULES_JSON
      RULES_JSON=$(_infer_rules "$ENTITY_TYPE" "$UNIQ_PARAMS")

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
         (domain_id,entity_type,entity_name,endpoints,params,rules_inferred,risk_score)
         VALUES(${DOMAIN_ID},'${ENTITY_TYPE}','${ENTITY_TYPE}',
                '${EP_JSON//\'/\'\'}','${P_JSON//\'/\'\'}',
                '${RULES_JSON//\'/\'\'}',${RISK});" 2>/dev/null || true

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
  local ADMIN_URLS
  ADMIN_URLS=$(sqlite3 "$DB_PATH" \
    "SELECT url FROM urls WHERE domain_id=${DOMAIN_ID}
     AND (url LIKE '%/admin%' OR url LIKE '%/administrator%'
          OR url LIKE '%/superuser%' OR url LIKE '%/root%')
     LIMIT 10;" 2>/dev/null)

  local ALL_ROLE_URLS
  ALL_ROLE_URLS=$(echo -e "$ROLE_URLS\n$ADMIN_URLS" | sort -u)

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    local STATUS
    STATUS=$(curl -sL --max-time 8 "$URL" -o /dev/null -w "%{http_code}" 2>/dev/null)

    if [[ "$STATUS" == "200" ]]; then
      log_warn "  ⚡ Endpoint admin/role accesible: $URL (HTTP 200)"
      sqlite3 "$DB_PATH" \
        "INSERT INTO business_tests(domain_id,entity_id,test_type,target_url,result,detail)
         VALUES(${DOMAIN_ID},${ENTITY_ID},'unauthorized_access','${URL//\'/\'\'}',
                'interesting','Admin endpoint HTTP 200 sin auth verificada');" 2>/dev/null || true
      db_add_finding "$DOMAIN_ID" "business_logic" "high" \
        "$URL" "unauthorized_admin" "Endpoint admin accesible (HTTP 200)"
    fi

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

  # ── Detectar entidades ─────────────────────────────────────
  log_info "Inferiendo modelo de negocio..."
  local ENTITIES
  mapfile -t ENTITIES < <(_detect_entities "$DOMAIN_ID")

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
