# Security Report: Internal Port Disclosure in ASP.NET Error Response — `secure.disnat.com`

**Target:** Desjardins `secure.disnat.com` (YesWeHack bug bounty)  
**Severity:** Low  
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)  
**URL in scope:** `*.disnat.com`

---

## Summary

`secure.disnat.com` (an ASP.NET Web API application) returns JSON error responses that include the full internal URL with a non-standard port number. This discloses internal infrastructure details (port `44313`) that should not be visible in external-facing error messages.

---

## Steps to Reproduce

```bash
curl -s "https://secure.disnat.com/api/v1"
```

**Response:**
```json
{"Message":"No HTTP resource was found that matches the request URI 'https://secure.disnat.com:44313/api/v1'."}
```

Any path under `/api/` returns this same error format with the internal port exposed:

```bash
curl -s "https://secure.disnat.com/api/v1/accounts"
# {"Message":"No HTTP resource was found that matches the request URI 'https://secure.disnat.com:44313/api/v1/accounts'."}

curl -s "https://secure.disnat.com/api/session/begin"
# {"Message":"No HTTP resource was found that matches the request URI 'https://secure.disnat.com:44313/api/session/begin'."}
```

---

## Information Disclosed

1. **Internal port `44313`**: The backend ASP.NET application is bound to port 44313 internally. This is consistent with an IIS Express development server port.
2. **Technology**: ASP.NET Web API (classic, not Core) — the `"Message"` key and error format are unique to `System.Web.Http`.
3. **Route structure**: The API routes can be enumerated, and all non-existent routes return a consistent 404 JSON response that confirms the API routing structure.

---

## Remediation

1. **Suppress the internal URL from error responses**: In `WebApiConfig.cs` or `ExceptionFilterAttribute`, replace the default error formatter to not include the raw `Request.RequestUri` in external error messages.

2. **Return a generic 404**: Replace the ASP.NET Web API default 404 response with a generic error:
   ```json
   {"error": "Not found"}
   ```

---

## Timeline

- Discovery: 2026-05-03
- Report sent: 2026-05-03
