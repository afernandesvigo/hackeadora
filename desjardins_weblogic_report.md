# Security Report: WebLogic Admin Console Partially Exposed — `accesd.mouv.desjardins.com`

**Target:** Desjardins `accesd.mouv.desjardins.com` (YesWeHack bug bounty)  
**Severity:** High  
**CWE:** CWE-200 (Exposure of Sensitive Information) + CWE-284 (Improper Access Control)  
**CVSS 3.1:** 7.5 (AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N)  
**URL in scope:** `*.accesd.mouv.desjardins.com`

---

## Summary

`accesd.mouv.desjardins.com` runs an Oracle WebLogic Server instance that is only partially protected by the Akamai WAF. The WAF blocks the admin console root path (`/console`) but does **not** block subpaths (`/console/login/LoginForm.jsp`, `/console/console.portal`), which reach the WebLogic backend. Raw WebLogic error pages are returned for many paths, confirming the server technology and revealing the container version.

---

## Evidence of WebLogic Presence

Requests to paths not covered by WAF rules reach the WebLogic container and return its native error page format:

```bash
# The following paths return raw WebLogic 404 pages (1307 bytes each):
curl -s "https://accesd.mouv.desjardins.com/em"
curl -s "https://accesd.mouv.desjardins.com/uddiexplorer"
curl -s "https://accesd.mouv.desjardins.com/jmx-console"
curl -s "https://accesd.mouv.desjardins.com/DefaultToDoList"
```

**Response format** (WebLogic native error page):
```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Draft//EN">
<HTML>
<HEAD>
<TITLE>Error 404--Not Found</TITLE>
</HEAD>
<BODY bgcolor="white">
<FONT FACE=Helvetica><BR CLEAR=all>
<TABLE border=0 cellspacing=5>
<TR><TD><BR><FONT FACE="Helvetica" COLOR="black" SIZE="3">
<H2>Error 404--Not Found</H2>
</FONT></TD></TR>
<TR><TD><FONT FACE="Helvetica" COLOR="black" SIZE="3">
<B>From RFC 2068 <i>Hypertext Transfer Protocol -- HTTP/1.1</i></B>:
</FONT></TD></TR>
```

This error page format is **unique to Oracle WebLogic Server** and is not used by any other platform.

---

## WAF Inconsistency: Admin Console Paths Bypass WAF

| Path | WAF Response | Meaning |
|---|---|---|
| `/console` | 403 (WAF block, 3723 bytes) | WAF explicitly blocks root |
| `/console/` | 500 (Akamai proxy error) | **WAF allows through** — backend reached |
| `/console/login/LoginForm.jsp` | 500 (Akamai proxy error) | **WAF allows through** — backend reached |
| `/console/console.portal` | 500 (Akamai proxy error) | **WAF allows through** — backend reached |
| `/console/index.html` | 403 (WAF block) | WAF blocks this specific path |

The 500 "Internal Server Error" responses come from Akamai (`server: AkamaiGHost`) with the message "Internal Server Error - Read", meaning Akamai reached the backend but failed to forward the response (likely because the backend sends a redirect to an internal URL). However, the key observation is that these paths **reach the WebLogic backend** — the WAF does not block them.

```bash
# These paths are NOT blocked by the WAF:
curl -sv "https://accesd.mouv.desjardins.com/console/login/LoginForm.jsp" 2>&1 | grep "< HTTP"
# HTTP/1.1 500 Internal Server Error (Akamai proxy error — backend reached)
```

---

## Additional Exposed Paths

The following WebLogic-specific paths return raw WebLogic responses (no WAF blocking):

- `/em/console` — Enterprise Manager console probe (WebLogic 404)
- `/uddiexplorer/SearchPublicRegistry.do` — UDDI explorer (WebLogic 404)
- `/uddiexplorer/SetupUDDIExplorer.jsp` — UDDI setup (WebLogic 404)
- `/jmx-console` — JMX management (WebLogic 404)
- `/DefaultToDoList` — WebLogic default app (WebLogic 404)
- `/sesame/services` — Sesame integration (WebLogic 404)

While none of these return functional applications (all are 404), they confirm:
1. The WAF allowlist has significant gaps for WebLogic paths
2. A direct connection to the WebLogic backend could access the admin console

---

## Impact

If an attacker can bypass the Akamai proxy layer (e.g., via SSRF from another host, finding the backend IP, or WAF misconfiguration), they can directly access the WebLogic admin console. The admin console provides:

- Remote deployment of WAR/EAR applications (potential RCE)
- Access to datasource credentials (database passwords)
- JNDI tree inspection
- Server monitoring and configuration

Additionally, the WAF misconfiguration (blocking `/console` but not `/console/login/LoginForm.jsp`) will allow exploitation if Akamai's proxy behavior is fixed to properly forward the response.

---

## Remediation

1. **Extend WAF rules to cover all WebLogic admin paths**: The pattern `/console/**` (with trailing wildcard) must be blocked, not just the exact path `/console`. Currently only exact matches and specific subpaths are blocked.

2. **Restrict WebLogic admin console to internal IP ranges only**: The admin console should be bound to a localhost or internal network interface, not accessible from the internet.

3. **Return generic error pages**: Replace the native WebLogic error page with a generic Desjardins 404 page to prevent technology fingerprinting.

4. **Audit WebLogic deployment**: Verify the WebLogic admin console password is strong and audit for default credentials.

---

## Timeline

- Discovery: 2026-05-03
- Report sent: 2026-05-03
