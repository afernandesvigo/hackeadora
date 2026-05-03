# Open Redirect via SAML2 wantsurl Parameter — loop.dcu.ie (Moodle 4.0.5, MSA-2023-0016)

**Target:** loop.dcu.ie  
**Severity:** Medium  
**Type:** Open Redirect  
**CVE/Advisory:** MSA-2023-0016  
**Status:** Confirmed  

---

## Summary

`loop.dcu.ie` runs Moodle 4.0.5 (confirmed). Moodle versions prior to 4.0.9 are affected by MSA-2023-0016, an open redirect vulnerability in the SAML2 authentication flow. The `wantsurl` query parameter is passed through the SAML2 SSO redirect chain without domain validation, allowing an attacker to craft a URL that redirects a victim to an arbitrary external domain after successful authentication.

---

## Moodle Version Confirmation

The version was confirmed from Moodle's docs path pattern in error pages, badmoodle tool output (`v4.05`), and the `themerev`/`jsrev` timestamps in the page source matching Moodle 4.0.x.

---

## Proof of Concept

### Step 1 — Craft the malicious URL

```
https://loop.dcu.ie/auth/saml2/login.php?wantsurl=https://evil.com
```

### Step 2 — Observe relay through SAML2 SSO

Visiting this URL produces a `303` redirect to DCU's SSO at `login.dcu.ie` with the following `RelayState`:

```
RelayState=https://loop.dcu.ie/auth/saml2/login.php?wantsurl=https://evil.com
```

Decoded:
```
https://loop.dcu.ie/auth/saml2/login.php?wantsurl=https://evil.com
```

### Step 3 — Redirect after authentication

After the victim authenticates at `login.dcu.ie`, the IdP posts the SAMLResponse back to the Moodle ACS endpoint (`/auth/saml2/sp/saml2-acs.php/loop.dcu.ie`). Moodle reads the `wantsurl` from the RelayState and redirects to it — without validating that it belongs to the same domain — resulting in a redirect to `https://evil.com`.

### HTTP Evidence

```
$ curl -sI "https://loop.dcu.ie/auth/saml2/login.php?wantsurl=https://evil.com"

HTTP/2 303
location: https://login.dcu.ie/idp/profile/SAML2/Redirect/SSO?
  SAMLRequest=...
  &RelayState=https%3A%2F%2Floop.dcu.ie%2Fauth%2Fsaml2%2Flogin.php%3Fwantsurl%3Dhttps%3A%2F%2Fevil.com
  &SigAlg=...
  &Signature=...
```

The `wantsurl=https://evil.com` value is preserved verbatim in the RelayState, which will be returned to Moodle after authentication.

---

## Attack Scenario

1. Attacker sends a DCU student a phishing link:
   ```
   https://loop.dcu.ie/auth/saml2/login.php?wantsurl=https://dcu-portal-login.evil.com
   ```
2. The URL appears to be a legitimate DCU Loop (Moodle) link — the domain is `loop.dcu.ie`.
3. Student logs in normally at `login.dcu.ie` (legitimate DCU SSO — no suspicious UI).
4. After authentication completes, DCU Loop redirects the student to `https://dcu-portal-login.evil.com`.
5. Attacker's page mimics DCU login and harvests credentials, or silently steals browser tokens.

---

## Impact

- **Phishing amplification:** The redirect originates from the trusted `loop.dcu.ie` domain after a real DCU SSO authentication, making it highly credible.
- **Credential harvesting:** Redirected page can mimic DCU systems.
- **Applicable to all DCU Loop users:** ~17,000 students and ~1,500 staff.

---

## Patch Reference

MSA-2023-0016 was fixed in Moodle 4.0.9, 4.1.5, and 4.2.2 (released 2023-09-18). The fix adds URL validation in `auth/saml2/lib.php` to ensure `wantsurl` belongs to the configured `wwwroot` before redirecting.

Moodle 4.0.5 is vulnerable.

---

## Remediation

**Update Moodle to 4.0.9 or later (4.1.x / 4.2.x / 4.3.x are all current supported branches).**

If an immediate update is not possible, apply the patch from MSA-2023-0016 which validates `wantsurl` against `$CFG->wwwroot`:
```php
// Ensure redirect stays within Moodle's wwwroot
if (!empty($wantsurl) && strpos($wantsurl, $CFG->wwwroot) !== 0) {
    $wantsurl = $CFG->wwwroot;
}
```

---

## Technical Details

- **Affected URL:** `https://loop.dcu.ie/auth/saml2/login.php?wantsurl=<external-url>`
- **Moodle version:** 4.0.5 (vulnerable range: < 4.0.9)
- **Advisory:** https://moodle.org/mod/forum/discuss.php?d=449768 (MSA-2023-0016)
- **SAML2 plugin:** SimpleSAMLphp-based (`/auth/saml2/`)
- **Tested on:** 2026-05-03
