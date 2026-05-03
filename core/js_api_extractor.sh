#!/usr/bin/env bash
# ============================================================
#  core/js_api_extractor.sh
#  Extractor de configuración de API desde bundles JS minificados
# ============================================================

# ── Write the Python parser to a temp file once at source time ─
_JS_PARSE_SCRIPT="/tmp/.js_api_parse_$$.py"
cat > "$_JS_PARSE_SCRIPT" << 'PYEOF'
import re, json, sys

content = sys.stdin.read()

result = {
    "api_base_url": None,
    "auth_header": None,
    "auth_prefix": "Bearer",
    "token_name": None,
    "cookie_names": [],
    "roles": [],
    "login_url": None,
    "login_body": None,
    "force_params": {},
    "endpoints": [],
}

# ── API base URL ───────────────────────────────────────────────
api_patterns = [
    r"""apiUrl\s*[:"=]\s*["']([/\w.\-]{3,80}(?:/[^"'\s]{0,60})?)""",
    r"""baseUrl\s*[:"=]\s*["']([/\w.\-]{3,80}(?:/[^"'\s]{0,60})?)""",
    r"""baseURL\s*[:"=]\s*["']([/\w.\-]{3,80}(?:/[^"'\s]{0,60})?)""",
    r"""API_BASE\s*[:"=]\s*["']([/\w.\-]{3,80}(?:/[^"'\s]{0,60})?)""",
    r"""API_URL\s*[:"=]\s*["']([/\w.\-]{3,80}(?:/[^"'\s]{0,60})?)""",
    r"""(?:apiBase|api_base)\s*[:"=]\s*["']([/\w.\-]{3,80}(?:/[^"'\s]{0,60})?)""",
    r"""(?:restBase|rest_base|restUrl)\s*[:"=]\s*["']([/\w.\-]{3,80}(?:/[^"'\s]{0,60})?)""",
]
api_candidates = {}
for pat in api_patterns:
    for m in re.findall(pat, content):
        m = m.rstrip("/") + "/"
        if re.search(r"/api/|/rest/|/v\d/|/services?/|/ws/", m, re.I):
            api_candidates[m] = api_candidates.get(m, 0) + 3
        elif "/" in m and len(m) > 4:
            api_candidates[m] = api_candidates.get(m, 0) + 1

# Path prefix frequency: most-repeated /a/b/c/d/ containing /api/ or /v1/
for m in re.findall(r"""["']([/][a-zA-Z0-9_\-]{2,30}/(?:[a-zA-Z0-9_\-]{2,30}/){1,4})["']""", content):
    if re.search(r"/api/|/rest/|/v\d+/", m, re.I):
        api_candidates[m] = api_candidates.get(m, 0) + 1

if api_candidates:
    result["api_base_url"] = max(api_candidates, key=api_candidates.get)

# ── Auth header name ──────────────────────────────────────────
auth_hdr_patterns = [
    r"""headerName\s*[:"=]\s*["']([A-Za-z][\-A-Za-z0-9]{3,40})["']""",
    r"""\.set\s*\(\s*["']([A-Za-z][\-A-Za-z0-9]{3,40})["']\s*,\s*["'](?:Bearer|Token)""",
    r"""headers\.append\s*\(\s*["']([A-Za-z][\-A-Za-z0-9]{3,40})["']\s*,""",
]
for pat in auth_hdr_patterns:
    m = re.search(pat, content)
    if m:
        result["auth_header"] = m.group(1)
        break
if not result["auth_header"]:
    c_custom = len(re.findall(r"Authentication[^a-z]", content))
    c_std    = len(re.findall(r"Authorization[^a-z]", content))
    if c_custom > c_std:
        result["auth_header"] = "Authentication"
    elif c_std > 0:
        result["auth_header"] = "Authorization"

# ── Auth prefix ───────────────────────────────────────────────
pfx_m = re.search(r"""headerPrefix\s*[:"=]\s*["']([A-Za-z]{2,20})["']""", content)
if pfx_m:
    result["auth_prefix"] = pfx_m.group(1)
else:
    pfx_m = re.search(r"""["'](Bearer|Token|JWT|Basic)\s*["'+]""", content, re.I)
    if pfx_m:
        result["auth_prefix"] = pfx_m.group(1)

# ── Token storage name ────────────────────────────────────────
tok_patterns = [
    r"""tokenName\s*[:"=]\s*["']([^"'\s]{4,80})["']""",
    r"""tokenKey\s*[:"=]\s*["']([^"'\s]{4,80})["']""",
    r"""localStorage\.(?:get|set)Item\s*\(\s*["']([^"'\s]{4,60})["']""",
    r"""sessionStorage\.(?:get|set)Item\s*\(\s*["']([^"'\s]{4,60})["']""",
    r"""(ng2-webstorage\|[a-zA-Z_\-]{3,40})""",
]
for pat in tok_patterns:
    m = re.search(pat, content)
    if m:
        result["token_name"] = m.group(1)
        break

# ── Cookie names ──────────────────────────────────────────────
cookie_hits = set()
for m in re.finditer(r"""(?:cookie|Cookie)\s*[.[(]\s*["']([a-zA-Z_][a-zA-Z0-9_\-]{2,40})["']""", content):
    name = m.group(1)
    if not re.search(r"^(path|domain|secure|httponly|samesite|expires|max.age)$", name, re.I):
        cookie_hits.add(name)
result["cookie_names"] = sorted(cookie_hits)[:10]

# ── Roles ─────────────────────────────────────────────────────
roles = set()
for m in re.finditer(r"""["'](ROLE_[A-Z_]{3,40})["']""", content):
    roles.add(m.group(1))
for m in re.finditer(r"""hasRole\s*\(\s*["']([A-Za-z_]{3,40})["']""", content):
    roles.add(m.group(1))
result["roles"] = sorted(roles)

# ── Login endpoint ────────────────────────────────────────────
# Priority: public/login > auth/login > /login (not followed by / = not token refresh)
login_candidates = []
for m in re.finditer(r"""["']([^"'\s]{0,30}login[^"'\s]{0,20})["']""", content, re.I):
    ep = m.group(1)
    if len(ep) >= 80 or ep.startswith("http"): continue
    ep = ep.strip("/")
    if not ep: continue
    # Prefer public/login, score by specificity
    if re.search(r"^public/login$", ep, re.I): score = 3
    elif re.search(r"public.+login", ep, re.I): score = 2
    elif re.search(r"login$", ep, re.I): score = 1  # login at end (not login/token)
    elif re.search(r"login/token|token/login|refresh", ep, re.I): score = -1  # skip token refresh
    else: score = 0
    if score >= 0:
        login_candidates.append((score, ep))
if login_candidates:
    login_candidates.sort(key=lambda x: -x[0])
    result["login_url"] = login_candidates[0][1]

# ── Login body fields ─────────────────────────────────────────
body_fields = {}
for pat, dval in [
    (r"""(?:identificador|username|user|email|nif)\s*[:"=][^,;}\n]{0,60}""", "__USERNAME__"),
    (r"""(?:contrasenya|password|pass|pwd)\s*[:"=][^,;}\n]{0,60}""", "__PASSWORD__"),
    (r"""isAdminAuth\s*[:"=]\s*(false|true)""", "false"),
]:
    m = re.search(pat, content, re.I)
    if m:
        k = re.split(r"[:\s=]", m.group(0))[0].strip().strip("\"'`")
        body_fields[k] = False if dval == "false" else dval
if body_fields:
    result["login_body"] = json.dumps(body_fields)

# ── Force/bypass params ───────────────────────────────────────
force_params = {}
for m in re.finditer(r"(force[A-Za-z]+|bypassSession|skipSession|isForce)\s*[:\s=]+\s*(true|false|\d+)", content, re.I):
    k = m.group(1)
    v = m.group(2)
    force_params[k] = True if v == "true" else (False if v == "false" else int(v))
result["force_params"] = force_params

# ── Endpoints (relative paths in HTTP calls) ─────────────────
seen_ep = set()
for m in re.finditer(r"""(?:get|post|put|patch|delete|request)\s*\(\s*["']([^"'\s<>{}]{4,120})["']""", content, re.I):
    ep = m.group(1)
    if re.search(r"\.(png|jpg|gif|svg|woff|css|map|ico|html)$", ep, re.I):
        continue
    if ep not in seen_ep:
        seen_ep.add(ep)
        result["endpoints"].append(ep)
result["endpoints"] = result["endpoints"][:200]

print(json.dumps(result))
PYEOF

# Clean up the temp script on exit
trap 'rm -f "$_JS_PARSE_SCRIPT"' EXIT

# ── Extract API config from a JS file via stdin ───────────────
_js_api_parse() {
  python3 "$_JS_PARSE_SCRIPT"
}

# ── Download + extract from a single JS URL ───────────────────
js_api_extract_from_url() {
  local DOMAIN_ID="$1"
  local SUBDOMAIN="$2"
  local JS_URL="$3"

  local TMP_JS
  TMP_JS=$(mktemp /tmp/jsapi_XXXXXX.js)
  local STATUS
  STATUS=$(curl -s -A "${SCAN_UA:-Mozilla/5.0}" --max-time 30 \
    -w "%{http_code}" -o "$TMP_JS" "$JS_URL" 2>/dev/null)

  if [[ "$STATUS" != "200" ]] || [[ ! -s "$TMP_JS" ]]; then
    rm -f "$TMP_JS"
    return 1
  fi

  local RESULT
  RESULT=$(python3 "$_JS_PARSE_SCRIPT" < "$TMP_JS" 2>/dev/null)
  rm -f "$TMP_JS"
  [[ -z "$RESULT" ]] && return 1

  local API_BASE AUTH_HDR AUTH_PFX TOKEN_NAME COOKIES ROLES LOGIN_URL LOGIN_BODY FORCE EP_COUNT

  API_BASE=$(echo "$RESULT"   | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('api_base_url') or '')" 2>/dev/null)
  AUTH_HDR=$(echo "$RESULT"   | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('auth_header') or '')" 2>/dev/null)
  AUTH_PFX=$(echo "$RESULT"   | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('auth_prefix') or 'Bearer')" 2>/dev/null)
  TOKEN_NAME=$(echo "$RESULT" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('token_name') or '')" 2>/dev/null)
  COOKIES=$(echo "$RESULT"    | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(json.dumps(d.get('cookie_names', [])))" 2>/dev/null)
  ROLES=$(echo "$RESULT"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(json.dumps(d.get('roles', [])))" 2>/dev/null)
  LOGIN_URL=$(echo "$RESULT"  | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('login_url') or '')" 2>/dev/null)
  LOGIN_BODY=$(echo "$RESULT" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('login_body') or '')" 2>/dev/null)
  FORCE=$(echo "$RESULT"      | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(json.dumps(d.get('force_params', {})))" 2>/dev/null)
  EP_COUNT=$(echo "$RESULT"   | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(len(d.get('endpoints', [])))" 2>/dev/null)

  if [[ -n "$API_BASE" || -n "$AUTH_HDR" || -n "$LOGIN_URL" ]]; then
    db_upsert_api_config "$DOMAIN_ID" "$SUBDOMAIN" "$JS_URL" \
      "$API_BASE" "$AUTH_HDR" "$AUTH_PFX" "$TOKEN_NAME" \
      "$COOKIES" "$ROLES" "$LOGIN_URL" "$LOGIN_BODY" "$FORCE" "${EP_COUNT:-0}"
    return 0
  fi
  return 1
}

# ── Scan all JS bundles for a subdomain ───────────────────────
js_api_extract_all() {
  local DOMAIN_ID="$1"
  local SUBDOMAIN="$2"
  local BASE_URL="${3:-https://${SUBDOMAIN}}"
  local FOUND=0

  local JS_URLS
  JS_URLS=$(sqlite3 "${DB_PATH}" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND (url LIKE '%.bundle.js' OR url LIKE '%.chunk.js'
            OR url LIKE '%main%.js' OR url LIKE '%vendor%.js'
            OR url LIKE '%app%.js' OR url LIKE '%runtime%.js')
       AND (url LIKE '%${SUBDOMAIN}%')
     ORDER BY first_seen DESC LIMIT 20;" 2>/dev/null)

  local HTML
  HTML=$(curl -sL -A "${SCAN_UA:-Mozilla/5.0}" --max-time 15 "$BASE_URL/" 2>/dev/null | head -c 50000)
  local SCRIPT_SRCS
  SCRIPT_SRCS=$(echo "$HTML" | grep -oP '(?<=src=")[^"]+\.js[^"]*' | head -20)

  local ALL_URLS
  ALL_URLS=$(printf '%s\n' $JS_URLS $SCRIPT_SRCS | sort -u | head -30)

  while IFS= read -r JSURL; do
    [[ -z "$JSURL" ]] && continue
    if [[ "$JSURL" != http* ]]; then
      JSURL="${BASE_URL}/${JSURL#/}"
    fi
    local SIZE
    SIZE=$(curl -sI -A "${SCAN_UA:-Mozilla/5.0}" --max-time 8 "$JSURL" 2>/dev/null \
      | grep -i 'content-length' | grep -oP '\d+' | head -1)
    if [[ -n "$SIZE" && "$SIZE" -lt 20000 ]]; then continue; fi

    if js_api_extract_from_url "$DOMAIN_ID" "$SUBDOMAIN" "$JSURL"; then
      ((FOUND++))
      log_info "  [js_api] Config extraída de $JSURL"
    fi
  done <<< "$ALL_URLS"

  return $( [[ "$FOUND" -gt 0 ]] && echo 0 || echo 1 )
}
