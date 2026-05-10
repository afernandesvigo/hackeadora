#!/usr/bin/env bash
# ============================================================
#  modules/51_deserialization.sh — Tier 3.5 Insecure deserialization
#
#  Detección por tech stack (technologies table). Sin ejecutar gadgets reales
#  destructivos — solo probes de detección + OOB con DESERIAL_CANARY env.
#
#  Targets:
#    - Java: ViewState ASP.NET, JSESSIONID con valor base64-serialized
#    - .NET: __VIEWSTATE con valor que parece serialized
#    - Python: pickle hex/base64 en cookies
#    - Ruby: Marshal en cookies
#    - PHP: __wakeup en cookie/session, unserialize markers
# ============================================================

MODULE_NAME="deserialization"
MODULE_DESC="Insecure deserialization — Java/Net/Python/Ruby/PHP markers"

_des_finding() {
  db_add_finding "$1" "deserialization" "$5" "$3" "$4" "$6" "${7:-medium}" 2>/dev/null
  log_warn "  ⚡ [$5/${7:-medium}] Deser $4: $3"
  if [[ "${7:-medium}" != "low" ]] && [[ "$5" == "critical" || "$5" == "high" ]]; then
    _telegram_send "🟠 *Deser — $4*
🌐 \`$2\`
🔗 \`$3\`
📋 ${6:0:280}
📊 \`${5^^}\` / \`${7:-medium}\`" 2>/dev/null || true
  fi
}

_des_check_host() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"
  _h_get_noredirect "$URL" --connect-timeout 6
  local HEADERS="$HTTP_LAST_HEADERS" BODY="${HTTP_LAST_BODY:0:5000}"

  # 1. ASP.NET ViewState (sin __EVENTVALIDATION → unsigned)
  if echo "$BODY" | grep -qE 'name="__VIEWSTATE"\s+value="[A-Za-z0-9+/=]{50,}"'; then
    if ! echo "$BODY" | grep -qE 'name="__VIEWSTATEENCRYPTED"|name="__EVENTVALIDATION"'; then
      _des_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "aspnet_viewstate_unsigned" "high" \
        "ASP.NET __VIEWSTATE presente sin __VIEWSTATEENCRYPTED/EVENTVALIDATION → unsigned ViewState. ysoserial.net puede generar gadget RCE (TextFormattingRunProperties, etc.)" \
        "medium"
      return 0
    fi
  fi

  # 2. Java JSESSIONID con valor base64 que parece Java serialized (rO0AB...)
  if echo "$HEADERS" | grep -qiE '^Set-Cookie:.*JSESSIONID=rO0AB'; then
    _des_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "java_serialized_cookie" "critical" \
      "JSESSIONID contiene valor 'rO0AB' (Java ObjectOutputStream serialized) — RCE via gadget chain ysoserial. Cookie: $(echo "$HEADERS" | grep -i '^set-cookie' | head -1 | head -c 200)" \
      "high"
    return 0
  fi

  # 3. PHP unserialize markers en cookies/body
  if echo "$BODY" | grep -qE 's:[0-9]+:"[^"]+";.*O:[0-9]+:"[A-Za-z_\\\\]+":[0-9]+:\{'; then
    _des_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "php_unserialize_in_response" "medium" \
      "PHP serialized object detectado en response body — verificar si la app usa unserialize() en input controlado por user." \
      "medium"
  fi

  # 4. Ruby Marshal en cookies (header session=BAh7B...)
  if echo "$HEADERS" | grep -qiE '^Set-Cookie:.*=BAh[A-Za-z0-9+/=]+--'; then
    _des_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "ruby_marshal_cookie" "high" \
      "Cookie con prefijo 'BAh' (Ruby Marshal serialized) — Rails session vulnerable a Marshal RCE si secret_key_base leaked." \
      "medium"
    return 0
  fi

  # 5. Python pickle (poco común pero detectable: pickle proto markers c__main__)
  if echo "$BODY" | grep -qE '^\\x80\\x[0-9a-f]{2}|c__main__|cposix\\nsystem'; then
    _des_finding "$DOMAIN_ID" "$DOMAIN" "$URL" "python_pickle_detected" "high" \
      "Pickle markers detectados (\\x80 proto byte, c__main__) — RCE via pickle.loads()." \
      "medium"
  fi

  return 1
}

module_run() {
  local DOMAIN="$1" DOMAIN_ID="$2" OUT_DIR="$3"
  log_phase "Módulo 51 — $MODULE_DESC: $DOMAIN"
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null

  # Hosts con tech vulnerable
  local TARGETS
  TARGETS=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT s.subdomain FROM subdomains s
    LEFT JOIN technologies t ON t.subdomain=s.subdomain AND t.domain_id=s.domain_id
    WHERE s.domain_id=${DOMAIN_ID} AND s.status='alive'
      AND (t.tech_name LIKE '%Tomcat%' OR t.tech_name LIKE '%JBoss%' OR t.tech_name LIKE '%WildFly%'
           OR t.tech_name LIKE '%WebLogic%' OR t.tech_name LIKE '%WebSphere%'
           OR t.tech_name LIKE '%ASP.NET%' OR t.tech_name LIKE '%IIS%'
           OR t.tech_name LIKE '%Rails%' OR t.tech_name LIKE '%Django%'
           OR t.tech_name LIKE '%Java%' OR t.tech_name LIKE '%Spring%'
           OR t.tech_name LIKE '%PHP%')
    LIMIT 30;" 2>/dev/null | sort -u)
  [[ -z "$TARGETS" ]] && { log_info "  Sin techs vulnerables a deserialization detectadas"; return 0; }

  local TOTAL=0
  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    _des_check_host "https://${SUB}/" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL++))
  done <<< "$TARGETS"
  log_ok "$MODULE_DESC: $TOTAL detecciones"
}
