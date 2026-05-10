#!/usr/bin/env python3
"""
core/tech_detector.py — detector de tecnologías basado en registry declarativo.

Lee:
  core/tech_registry.json   (built-in, ~98 entries)
  data/tech_registry_custom.json (user-extensible)

Uso CLI:
  echo '<headers>\n\n<body>' | python3 core/tech_detector.py URL
    → emite líneas: TECH_NAME\tCATEGORY\tCVE_FAMILY\tMATCH_REASON

  python3 core/tech_detector.py --probe-host https://x.com
    → fetch HEAD/GET noredirect, evalúa registry, emite matches

  python3 core/tech_detector.py --suggest /tmp/headers /tmp/body URL
    → analiza pero también emite líneas SUGGEST: para markers desconocidos
"""

import json
import os
import re
import sys
import urllib.request
import urllib.error
import ssl
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent.parent
REGISTRY_BUILTIN = SCRIPT_DIR / "core" / "tech_registry.json"
REGISTRY_CUSTOM = SCRIPT_DIR / "data" / "tech_registry_custom.json"


def load_registry():
    """Merge built-in + custom registry. Custom entries can override built-in by name."""
    entries = []
    seen_names = set()

    for path in [REGISTRY_CUSTOM, REGISTRY_BUILTIN]:
        if not path.exists():
            continue
        try:
            with open(path) as f:
                data = json.load(f)
            for entry in data:
                name = entry.get("name", "").strip()
                if not name or name in seen_names:
                    continue
                # Validar campos esperados
                entry.setdefault("header_re", "")
                entry.setdefault("body_re", "")
                entry.setdefault("url_probes", [])
                entry.setdefault("url_status_ok", "")
                entry.setdefault("category", "unknown")
                entry.setdefault("cve_family", "")
                entries.append(entry)
                seen_names.add(name)
        except Exception as e:
            print(f"[tech_detector] WARN: error loading {path}: {e}", file=sys.stderr)
    return entries


def http_fetch(url, timeout=8, follow=False):
    """GET (no -L) → return (status_code, headers_dict, body_str). Tolerant to errors."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        },
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = resp.status
            headers = dict(resp.headers.items())
            body = resp.read(200_000).decode("utf-8", errors="ignore")
            return status, headers, body
    except urllib.error.HTTPError as e:
        # 4xx/5xx still useful — read body
        try:
            body = e.read(200_000).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        headers = dict(e.headers.items()) if e.headers else {}
        return e.code, headers, body
    except (urllib.error.URLError, ssl.SSLError, ConnectionError, TimeoutError, Exception):
        return 0, {}, ""


def headers_to_text(headers):
    """Format headers dict to text suitable for line-anchored regex."""
    return "\n".join(f"{k}: {v}" for k, v in headers.items())


def extract_version(headers_text, body, version_re):
    """Aplica version_re sobre headers + body, devuelve grupo 1 (versión) o ''.

    Convención: version_re tiene EXACTAMENTE un grupo de captura `(\\d[\\d.]+)`
    o similar. Match en headers gana sobre body.
    """
    if not version_re:
        return ""
    try:
        for source in (headers_text or "", body or ""):
            m = re.search(version_re, source, re.MULTILINE | re.IGNORECASE)
            if m and m.groups():
                v = m.group(1).strip()
                if v:
                    return v
    except re.error:
        pass
    return ""


def evaluate_entry(entry, base_url, headers_text, body, http_get_fn):
    """Return list of (match_reason) strings if entry matches, [] otherwise.

    http_get_fn: callable(url) → (status, headers, body) — used for url_probes."""
    reasons = []

    header_re = entry.get("header_re", "")
    body_re = entry.get("body_re", "")
    url_probes = entry.get("url_probes", [])
    status_ok = entry.get("url_status_ok", "")

    # Header match (multiline anchored)
    if header_re and headers_text:
        try:
            if re.search(header_re, headers_text, re.MULTILINE | re.IGNORECASE):
                reasons.append("header")
        except re.error:
            pass

    # Body match
    if body_re and body:
        try:
            if re.search(body_re, body, re.IGNORECASE):
                reasons.append("body")
        except re.error:
            pass

    # URL probes — SIEMPRE requieren body_re match (refactor 2026-05-09).
    # Si entry no define body_re, url_probes son IGNORADOS para evitar FPs
    # masivos en hosts auth-gated que devuelven 200/302/401/403 universalmente.
    #
    # Bug fix: status 30x (redirect) descartado para url_probes — el body del
    # 302 incluye el path probado reflejado como Location y matchea body_re
    # falsamente. Solo aceptar status terminales (200, 401, 403, 400 para APIs).
    if url_probes and status_ok and body_re:
        ok_codes = set(s.strip() for s in status_ok.split(",") if s.strip())
        # Filtrar redirects: NUNCA aceptar 30x para url_probes (FP en catch-all auth gates)
        ok_codes -= {"301", "302", "303", "307", "308"}
        if not ok_codes:
            return reasons
        for probe in url_probes:
            probe_url = base_url.rstrip("/") + probe
            ps, ph, pb = http_get_fn(probe_url)
            if str(ps) not in ok_codes:
                continue
            # Adicional: filtrar matches donde body_re matchee SOLO en el path reflejado.
            # Si el body es corto (<500B) Y body_re matches ÚNICAMENTE en el segmento
            # del propio probe path, asumir reflexión espuria.
            if pb and len(pb) < 500:
                # Si quitando el path del body sigue habiendo match → match real
                stripped = pb.replace(probe, "")
                try:
                    if not re.search(body_re, stripped, re.IGNORECASE):
                        continue  # match era solo el path reflejado
                except re.error:
                    pass
            try:
                if re.search(body_re, pb or "", re.IGNORECASE):
                    reasons.append(f"url_probe:{probe}({ps})+body_match")
                    break
            except re.error:
                pass

    return reasons


def detect_unknown_markers(headers_text, body):
    """Detectar señales no cubiertas por el registry — sugerencias de nuevas techs."""
    suggestions = []

    # Server header desconocido (no Apache/nginx/IIS)
    server = ""
    for line in headers_text.split("\n"):
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
            break
    if server and not re.search(r"^(Apache|nginx|Microsoft-IIS|cloudflare|AmazonS3|LiteSpeed|Jetty|Varnish|gws|sffe|WebLogic|Sucuri|Incapsula|AkamaiGHost)", server, re.IGNORECASE):
        suggestions.append(f"unknown_server: {server}")

    # X-Powered-By desconocido
    for line in headers_text.split("\n"):
        if line.lower().startswith("x-powered-by:"):
            value = line.split(":", 1)[1].strip()
            if value and not re.search(r"^(PHP|ASP\.NET|Express|Next\.js|Phusion|JBoss|WildFly|Undertow|Servlet)", value, re.IGNORECASE):
                suggestions.append(f"unknown_x_powered_by: {value}")

    # Custom X-* headers (señal de framework/admin tool específico)
    for line in headers_text.split("\n"):
        m = re.match(r"^(X-[A-Za-z][\w-]+):", line)
        if m:
            hdr = m.group(1)
            if not re.search(r"^X-(Frame-Options|Content-Type-Options|XSS-Protection|Powered-By|Cache|Forwarded|Real-IP|Request-Id|Correlation-Id|Trace-Id|Amz-|Azure-|Forwarded-For|Forwarded-Host|Vhost|CQ-|AEM-|Adobe-|Sling-|Dispatcher|Generator|Drupal-|Magento-|Magnolia-|Umbraco-|Hippo-|Sitecore-|SharePoint|Confluence-|Jenkins|Gitlab-|AUSERNAME|AREQUESTID|ShardId|Shopify-|Bc-Apigateway|Dw-Request|Iinfo|WA-Info|Akamai-|Sucuri-|Tomcat-|Application-Context|Litespeed-|Cf-|Fastly-)", hdr, re.IGNORECASE):
                suggestions.append(f"unknown_custom_header: {hdr}")

    # Generator meta tag con valor no cubierto
    m = re.search(r'<meta\s+name="generator"\s+content="([^"]+)"', body, re.IGNORECASE)
    if m:
        gen = m.group(1)
        if not re.search(r"(WordPress|Drupal|Joomla|Hugo|Jekyll|Gatsby|Next\.js|Hexo|Pelican|MkDocs|MediaWiki|Bitrix|Plone|TYPO3|Bolt|October|Craft|Statamic|Discourse)", gen, re.IGNORECASE):
            suggestions.append(f"unknown_generator: {gen}")

    return suggestions


def is_catchall_host(base_url):
    """Probe 2 random paths. Catch-all if both return 200 + similar body length.

    Excepción: si el body contiene markers de framework empresarial conocido
    (AEM, SharePoint, Drupal admin, etc.), NO catch-all — es auth gate real.
    """
    import secrets
    rand1 = secrets.token_hex(6)
    rand2 = secrets.token_hex(6)
    base = base_url.rstrip("/")

    s1, h1, b1 = http_fetch(f"{base}/HACKEADORA_NX_{rand1}", timeout=5, follow=False)
    if s1 in (301, 302, 303, 307, 308):
        loc = h1.get("Location", "") or h1.get("location", "")
        if loc and base not in loc:
            return True
    if s1 != 200 or len(b1) <= 500:
        return False

    s2, h2, b2 = http_fetch(f"{base}/api/v1/{rand2}", timeout=5, follow=False)
    if s2 != 200 or len(b2) <= 500:
        return False

    diff = abs(len(b1) - len(b2))
    threshold = max(100, len(b1) // 20)
    if diff >= threshold:
        return False

    # Both 200, similar length → check if body has framework markers
    framework_markers = re.compile(
        r'AEM Sign In|Apache Sling|granite\.author|cq:Page|cq:template|<title>POST data'
        r'|sharepoint|drupal\.behaviors|Magento_|magentoStorefrontEvents'
        r'|bloomreach|<title>Hippo|hippo:|/libs/granite|/etc/clientlibs',
        re.IGNORECASE,
    )
    if framework_markers.search(b1 or "") or framework_markers.search(b2 or ""):
        return False  # auth gate de framework real

    return True


def detect(base_url, headers_text, body, registry, suggest=False, allow_url_probes=True):
    """Main entry. Returns (matches, suggestions).

    If host is catch-all (SPA / generic 200), url_probes are restricted to
    those that REQUIRE body_re match — prevents JBoss/WebSphere/etc FPs on SPAs.
    """
    matches = []

    # Catch-all detection (cached for the host)
    catchall = False
    if allow_url_probes:
        try:
            catchall = is_catchall_host(base_url)
        except Exception:
            catchall = False

    # Cache para url_probes (no re-fetch dentro del mismo host)
    probe_cache = {}

    def cached_get(url):
        if url not in probe_cache:
            probe_cache[url] = http_fetch(url, timeout=6, follow=False)
        return probe_cache[url]

    for entry in registry:
        # En catch-all hosts, deshabilitar url_probes que no exijan body_re match.
        # Header-only y body_re-only matches OK.
        entry_eval = entry
        if catchall and entry.get("url_probes") and not entry.get("body_re"):
            # Crear copia sin url_probes para evitar FP por status 200 universal
            entry_eval = {**entry, "url_probes": []}

        reasons = evaluate_entry(entry_eval, base_url, headers_text, body, cached_get)
        if reasons:
            # Tier 2.7: extraer versión si entry define version_re
            version = extract_version(headers_text, body, entry.get("version_re", ""))
            matches.append({
                "name": entry["name"],
                "category": entry["category"],
                "cve_family": entry.get("cve_family", ""),
                "version": version,
                "reason": ",".join(reasons),
            })

    suggestions = []
    if suggest:
        suggestions = detect_unknown_markers(headers_text, body)
        if catchall:
            suggestions.append("note: catch-all host — url_probes sin body_re fueron deshabilitados")

    return matches, suggestions


def main_cli():
    args = sys.argv[1:]
    if not args:
        print("Usage:\n  cat <headers_then_blank_then_body> | tech_detector.py URL\n  tech_detector.py --probe-host URL\n  tech_detector.py --suggest URL", file=sys.stderr)
        sys.exit(1)

    suggest_flag = False
    if args[0] == "--suggest":
        suggest_flag = True
        args = args[1:]

    if args[0] == "--probe-host":
        if len(args) < 2:
            print("--probe-host requires URL", file=sys.stderr)
            sys.exit(1)
        url = args[1]
        status, headers, body = http_fetch(url, follow=False)
        headers_text = headers_to_text(headers)
    else:
        url = args[0]
        # stdin: headers, blank line, body
        raw = sys.stdin.read()
        if "\n\n" in raw:
            headers_text, body = raw.split("\n\n", 1)
        else:
            headers_text, body = raw, ""

    registry = load_registry()
    matches, suggestions = detect(url, headers_text, body, registry, suggest=suggest_flag)

    for m in matches:
        # Format: MATCH\tname\tcategory\tcve_family\tversion\treason
        print(f"MATCH\t{m['name']}\t{m['category']}\t{m['cve_family']}\t{m.get('version','')}\t{m['reason']}")

    for s in suggestions:
        print(f"SUGGEST\t{s}")


if __name__ == "__main__":
    main_cli()
