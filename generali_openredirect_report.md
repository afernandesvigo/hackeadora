# Open Redirect via Subdomain Confusion in `sourceURL` Parameter — www.ssogf.generali.fr

**Target**: www.ssogf.generali.fr (in-scope)  
**Type**: Open Redirect  
**Severity**: Medium  
**Authentication Required**: No  

---

## Summary

The Generali SSO (`www.ssogf.generali.fr`, powered by Ilex Sign&go) accepts a `sourceURL` parameter that controls post-logout and post-login redirect destinations. The domain validation uses a substring check — it allows any URL whose hostname contains `.generali.fr.` — instead of verifying the URL is an actual Generali domain. An attacker who controls any domain (e.g., `attacker.es`) can create a subdomain like `monespace.generali.fr.attacker.es` and redirect authenticated users to their server after logout, or unauthenticated users to their server after login.

---

## Root Cause

The server validates the `sourceURL` parameter with a check equivalent to:

```
hostname.contains(".generali.fr.")
```

This passes for `monespace.generali.fr.attacker.es` because the string `.generali.fr.` appears in the subdomain chain. DNS allows any domain owner to create deep subdomains (e.g., `monespace.generali.fr.attacker.es` is a valid subdomain of `attacker.es`), so no registration under `generali.fr` is required.

---

## Reproduction Steps

### Step 1 — Proof of Bypass (Logout — confirmed 302)

```bash
curl -sI "https://www.ssogf.generali.fr/user/auth/logout?sourceURL=https://monespace.generali.fr.fernandes.es/"
```

**Expected (secure)**: Redirect to an authorized Generali domain, or error.  
**Actual**:
```
HTTP/1.1 302
Location: https://monespace.generali.fr.fernandes.es/
```

The server redirects to the attacker-controlled domain without any further validation. Confirmed live against the production SSO.

### Step 2 — Pre-Authentication `sourceURL` Stored in Session (Login Flow)

The `sourceURL` parameter is accepted and persisted server-side through the entire authentication flow:

```bash
curl -sI "https://www.ssogf.generali.fr/user/auth?sourceURL=https://monespace.generali.fr.fernandes.es/"
# HTTP 200 — "Welcome to GENERALI" login page

curl -sI "https://www.ssogf.generali.fr/user/auth/chooseschema?schema=ssogf256&sourceURL=https://monespace.generali.fr.fernandes.es/"
# HTTP 200 — login form; all page links carry sourceURL in session
```

Every link on the returned pages (language switcher, "Back to authentication") carries the malicious `sourceURL` through the session, indicating the server stores it for use as the post-login redirect destination. Confirmation of the post-login 302 requires valid credentials.

**Attack URL:**
```
https://www.ssogf.generali.fr/user/auth?sourceURL=https://monespace.generali.fr.fernandes.es/
```

### Step 3 — Bypass Confirmation (No Generali Subdomain Needed)

Any hostname containing `.generali.fr.` as a substring passes the validation:

| sourceURL | Result |
|-----------|--------|
| `https://evil.com/` | Blocked → UnauthorizedDomain |
| `https://monespace.generali.fr.fernandes.es/` | **Allowed → 302 to attacker domain** |
| `https://ssogf.generali.fr.fernandes.es/` | **Allowed → 302 to attacker domain** |
| `https://a.generali.fr.fernandes.es/` | **Allowed → 302 to attacker domain** |

### Step 4 — DNS Setup (No Generali Access Required)

The bypass domain is a subdomain of the attacker's own domain:

1. Control any domain (e.g., `attacker.es`)
2. Add DNS record: `monespace.generali.fr.attacker.es. IN A <attacker_IP>`
3. This is a valid DNS subdomain of `attacker.es` — no access to `generali.fr` DNS needed

The subdomain `monespace.generali.fr.fernandes.es` was used to verify this finding. It resolves and the redirect lands on the researcher's own server.

---

## Attack Scenario

**Phishing after authentication (highest impact vector):**

1. Attacker registers `attacker.es` and creates DNS: `monespace.generali.fr.attacker.es A <attacker_IP>`  
2. Hosts a fake Generali customer portal at that address  
3. Sends victim the URL:  
   `https://www.ssogf.generali.fr/user/auth?sourceURL=https://monespace.generali.fr.attacker.es/`  
4. Victim sees the legitimate Generali SSO at `www.ssogf.generali.fr` and logs in with real credentials  
5. After successful authentication, the SSO redirects to `https://monespace.generali.fr.attacker.es/`  
6. The attacker's page (which visually mimics `monespace.generali.fr`) can:
   - Prompt for "re-authentication" → credential theft  
   - Display a fake "security alert" → social engineering  
   - Capture any authorization codes or tokens passed via URL fragment post-auth  

**Plausibility**: The initial URL is on `www.ssogf.generali.fr` (the real, official SSO domain). A victim who authenticates on the legitimate Generali login page has no reason to expect the post-login destination to be fraudulent.

---

## Impact

- **Credential theft**: Victim authenticates on the real Generali SSO, then lands on an attacker-controlled page where credentials or session details can be harvested  
- **Session hijacking risk**: Any tokens, authorization codes, or sensitive parameters appended to the post-login redirect URL are exposed to the attacker  
- **Trust exploitation**: The attack begins on an official Generali domain, bypassing most user-side phishing awareness  
- **No account required**: Fully exploitable against unauthenticated users

---

## Affected Endpoints

| Endpoint | Redirect Confirmed |
|----------|-------------------|
| `https://www.ssogf.generali.fr/user/auth/logout?sourceURL=<bypass>` | **Yes — 302 without credentials** |
| `https://www.ssogf.generali.fr/user/auth?sourceURL=<bypass>` | Stored in session; 302 expected post-login |
| `https://www.ssogf.generali.fr/user/auth/chooseschema?schema=ssogf256&sourceURL=<bypass>` | Stored in session; 302 expected post-login |

---

## Recommended Fix

Replace the substring check with proper hostname validation:

```java
// ❌ Vulnerable
sourceURL.contains(".generali.fr.")

// ✅ Fix: extract the registered domain and compare
String host = new URL(sourceURL).getHost();
String registeredDomain = getRegisteredDomain(host); // e.g. InternetDomainName.from(host).topPrivateDomain()
if (!ALLOWED_REGISTERED_DOMAINS.contains(registeredDomain)) {
    // reject
}
// ALLOWED_REGISTERED_DOMAINS = { "generali.fr", "lamedicale.fr", ... }
```

Alternatively, use an explicit allowlist of full hostnames (`monespace.generali.fr`, `www.generali.fr`, etc.).

---

*Discovered: 2026-05-03*
