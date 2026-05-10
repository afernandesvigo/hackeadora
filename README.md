# 🔍 Hackeadora

> Pipeline automatizado de Bug Bounty — **64 módulos** · validators anti-FP · auto-explotación · bot Telegram bidireccional

**Autores:** Claude (Anthropic) & Antonio Fernandes
**Licencia:** MIT

---

## ¿Qué es?

Hackeadora es un pipeline completo de bug bounty que corre autónomo en VPS. Combina herramientas del sector (nuclei, subfinder, katana, ghauri, dalfox, trufflehog…) con detection layers propios, un **registry de tecnologías** declarativo (102 entries) y un **catálogo curado de CVEs** (41 entries) extensibles, **validators anti-FP** con catch-all guard, **mod 98 auto-explotación** sobre findings high-confidence, y **bot Telegram bidireccional** para hablar con Claude (vía `claude -p` headless) sobre el scan en curso.

```bash
./recon.sh empresa.com                                # scan completo
./recon.sh empresa.com --target app.empresa.com       # single target
./recon.sh empresa.com --modules=20,22,29             # módulos específicos
PRESEED_SUBS_ALIVE=/tmp/seed.txt ./recon.sh d.com --skip-modules=01  # con preseed
```

---

## Filosofía anti-FP (Tier 1.5+)

Tras un scan piloto encontró ~71% FPs en findings critical/high, se aplicó refactor exhaustivo:

- **`core/finding_validators.sh`**: 9 helpers compartidos (`_validate_aem_exposed`, `_validate_actuator_response`, `_validate_web_xml`, `_validate_manifest`, `_validate_canary_in_body`, `_validate_idor_diff`, `is_catchall_host` con caché in-memory + on-disk + framework markers exception, `is_idempotent_endpoint`, `is_oauth_authorize_path`, `is_salesforce_lightning_body`, `has_pii_shape`, `is_synthetic_endpoint`, `is_nuclei_finding_actionable`).
- **`HTTP_NO_REDIRECT`** + wrappers `_h_*_noredirect` en `core/http_analyzer.sh` — evitan que `30x` con `-L` falsifique 200.
- **Columna `confidence`** en findings (`high|medium|low|unverified`). Telegram solo notifica `confidence>=high`.
- **Dedup** por `(domain, type, target, template)` con upsert si nueva confidence es mejor.
- **Caché on-disk** de `is_catchall_host` por scan (`${OUT_DIR}/.catchall_cache.txt`).
- **Mod 99 verify post-pipeline**: re-valida critical/high con confidence baja → downgrade automático si falla validator estricto.
- **OOB confirmation** vía `a.dominio.es` (configurable, dominio canary) para OAuth redirect, JWT jku, SSRF, SAML XSLT.

---

## Tech registry — detección genérica + iterativa

`core/tech_registry.json` (versionado) + `data/tech_registry_custom.json` (gitignored, extensible per-env).

**102 entries en 16 categorías**: cms, ecommerce, webserver, appserver, framework, sso, devops, cdn, api, admin, analytics, payment, marketing, support, waf, auth.

Cada entry: `name`, `category`, `header_re`, `body_re`, `url_probes`, `url_status_ok`, `version_re` (Tier 2.7 — extracción de versión), `cve_family`.

**`core/tech_detector.py`** — matcher con anti-FP estricto:
- 2-probe `is_catchall_host` con framework marker exception (rescata AEM auth-gated)
- `body_re` obligatorio en `url_probes`
- Excluye 30x de `url_status_ok` (evita FP por canonicalization redirects)
- Filtra match si body es solo path reflejado del probe

**Flujo iterativo de nutrición**:
1. Cada scan emite `${OUT_DIR}/tech_suggestions.txt` con markers desconocidos
2. Telegram avisa al cierre del scan
3. `./tools/tech_review.sh <suggestions.txt>` → agrupa + propone comandos `tech_add.sh`
4. `./tools/tech_add.sh "Name" category 'header_re' 'body_re' 'url_probes' 'status_ok'` → append a custom
5. Próximo scan ya detecta esa tech

---

## CVE matcher (mod 40)

`core/cve_catalog.json` (versionado, 41 CVEs curados de techs principales: Tomcat, Spring, Apache, Liferay, Confluence, Jenkins, GitLab, SAP, WebLogic, etc.) + `data/cve_catalog_custom.json` (extensible).

**`core/cve_matcher.py`** — version range parser (formato `"9.0.0-9.0.98,10.0.0-10.1.34"` o `"<6.4.4"`).

- `confidence=medium` si `version_in_range` específico
- `confidence=low` si `versions_affected="*"` (aplica a todas)
- Forward-only substring match (`Apache HTTPd` no matchea entry de `Apache Tomcat`)
- Sin versión detectada → 0 matches (evita FP masivo)

**Loop iterativo**: `./tools/cve_add.sh CVE-XXXX-NNNNN "Tech" severity "Title" "version_range" "Desc" "PoC" "Ref"` → próximo scan matchea.

---

## Los 64 módulos

### Fase 1 — Descubrimiento de superficie
| # | Módulo |
|---|--------|
| 01 | Subdomain enum (subfinder, amass, bbot, assetfinder, findomain) |
| 02 | DNS resolve (dnsx + httpx) |
| 03 | Takeover (subzy, subjack) |
| 17 | Cloud assets (cloud_enum — S3, Azure, GCP) |
| 18 | ASN discovery (asnmap, BGPView) |

### Fase 2 — Recon activo
| # | Módulo |
|---|--------|
| 04/07 | Nuclei subs / Nuclei URLs (neutralizados — Bug #14: 0 findings históricos en 30min/scan) |
| 05 | Crawler (katana, gau, waybackurls, gospider) |
| 06 | Active scan (ffuf dir fuzzing) |
| 08 | Screenshots (gowitness) |
| 09/10 | Tech detect (whatweb + webanalyze + **Capa C registry** custom) |
| 11 | JS analyzer (SecretFinder + trufflehog `--only-verified`) |
| 12 | Login finder |
| 13 | Port scan (masscan + httpx) |
| 14 | Breach lookup (Dehashed) |
| 15 | Param discovery (paramspider + arjun + fuzz custom) |
| 16 | GitHub dorking (Bug #7: co-ocurrencia obligatoria con dominio target) |
| 19 | Auth crawler con cookies vault (AES-256-GCM) |

### Fase 3 — Detección de vulnerabilidades (con anti-FP validators)
| # | Módulo |
|---|--------|
| 20 | Smart scan (KB + ghauri + dalfox + nuclei tech-based) |
| 21 | Business logic (entities + flows + AI Advisor) |
| 22 | CORS misconfig + body confirm |
| 23 | 403/401 bypass (path/header/method) |
| 24 | HTTP smuggling (timing 3-sample median + ratio 3x, anti-FP carga paralela) |
| 25 | CMS scan tech-aware (WordPress, AEM, Liferay, SAP, Spring, Hippo, OpenCMS, etc.) |
| 26 | Path confusion (Orange Tsai: nginx + Apache + Tomcat + Spring + Apache CVE-2024-3847x) |
| 27 | Blind XSS (EZXSS self-hosted, payload_id por campo) |
| 28 | Cache attacks (Web Cache Poisoning + WCD) |
| 29 | Vuln-specific (JWT, OAuth, GraphQL, IDOR exports, Deserial, SMTP, Dependency) |
| 30 | Spring Cloud Config server scanner |
| 31 | Keycloak / OAuth2 server enum |
| 32 | CSP analysis |
| 33 | Password reset poisoning (Bug #2: técnicas A/B exigen canary reflejado) |
| 34 | Race condition (skip GET/HEAD/SAML/OAuth/health/static assets) |
| 35 | OIDC/OAuth scan (pre-filter por nombre + discovery probe paralelo: 84% reducción) |
| 36 | SPA runtime config exposure (environment.json) |
| 37 | AEM JCR Deep (Sling selectors + DAM + CVE-2025-24813, check 0 lee tech registry) |
| 38 | Path audit unificado (`core/path_mutations.sh` con 119 mutaciones + clustering) |

### Tier 2 — Detección extendida
| # | Módulo |
|---|--------|
| **39** | GraphQL (introspection + field suggestions + alias batching + sensitive fields + mutations) |
| **40** | **Tech→CVE matcher** (catalog-based, reemplaza nuclei deadweight) |
| **41** | Auth-state IDOR replay (no-cookie bypass + opt-in cookie A/B con `IDOR_COOKIE_A/B`) |
| **42** | XXE (file:///etc/passwd + Windows + parameter entity + OOB canary `XXE_CANARY`) |
| **43** | Prototype pollution (query `?__proto__[X]` + JSON body + canary unique) |
| **44** | WebSocket (CSWSH Origin: evil → 101, JWT/token in URL, `ws://` no-TLS) |
| **45** | JWT (alg:none, weak HS256 wordlist 24 secrets, kid path traversal, jku SSRF opt-in) |
| **46** | SAML SP (signature stripping, NameID comment injection, XSLT transform OOB) |

### Tier 3 — Coverage map OWASP/PortSwigger
| # | Módulo |
|---|--------|
| **47** | SSRF deep (cloud metadata AWS/GCP/Azure + protocol smuggling + OOB `SSRF_CANARY`) |
| **48** | NoSQL injection (`$ne`, `$gt`, form-encoded, regex blind) |
| **49** | OAuth deep (redirect_uri parsing diff con `OAUTH_CANARY_DOMAIN=a.dominio.es` + verificación nginx logs, state CSRF, scope escalation, dynamic registration) |
| **50** | File upload bypass (extension/content-type/SVG XSS + canary roundtrip) |
| **51** | Insecure deserialization (Java rO0AB, ASP.NET ViewState, Ruby Marshal, Python pickle) |
| **52** | SSTI per-engine (Jinja2, Twig, Freemarker, Velocity, Handlebars, Pebble) |
| **53** | LDAP/XPath injection |
| **54** | CRLF/email injection (header anclado a `^X-Hackeadora-Injected:`) |
| **55** | Mass assignment (is_admin/role/permissions injection) |
| **56** | Cookie audit (Secure/HttpOnly/SameSite/__Host- prefix) |
| **57** | Clickjacking (XFO + CSP frame-ancestors) |

### Tier 4 — Coverage extras + auto-explotación
| # | Módulo |
|---|--------|
| **58** | DOM XSS static (source→sink flow analysis en JS sin headless) |
| **59** | PostMessage origin laxness |
| **60** | Web Cache Deception deep (extension confusion + path tricks) |
| **61** | ORM injection (HQL/JPA, ActiveRecord, Sequelize errors) |
| **62** | GraphQL DoS (deep nesting + alias amplification 50x) |

### Verificación + chain
| # | Módulo |
|---|--------|
| **99** | Verify findings post-pipeline — re-valida critical/high con confidence baja, downgrade automático |
| **98** | **Active exploit chain** — sobre findings `confidence='high'` ejecuta gadgets: SSRF→cloud creds, JWT alg:none→admin replay, AEM JCR→canary write+read, CORS→HTML PoC, IDOR→ID enumeration. Output en `${OUT_DIR}/exploit/` |

---

## Bot Telegram bidireccional (Tier 4.3)

`core/telegram_bot.py` — daemon long-polling, coexiste con notifications:

**Slash commands locales** (instant, 0 cost):
- `/help` — listado
- `/status` — scans activos + findings recientes
- `/active` — procesos recon.sh + tiempos
- `/findings <dom> [N]` — top N findings de dominio
- `/last [N]` — últimos N findings cualquier dominio
- `/exploit_chain <dom>` — gadgets de mod 98
- `/scope [dom]` — listas scope BBP guardadas
- `/tail <dom> [N]` — últimas N líneas del recon.log

**Free-form** → spawn `claude -p` headless con contexto del scan inyectado (DB findings + scans activos). Usa subscription, **0 coste API**.

```bash
nohup python3 -u core/telegram_bot.py > /tmp/telegram_bot.log 2>&1 &
```

Auth: `TELEGRAM_AUTHORIZED_CHATS=12345,67890` env.

---

## SQL view `host_stack` para AI Advisor

Vista consolidada por host con techs agrupadas:

```sql
SELECT subdomain, techs, categories FROM host_stack
WHERE domain_id=(SELECT id FROM domains WHERE domain='target.com');
```

`core/ai_advisor.py:get_host_stack()` la consume para enriquecer el contexto enviado al modelo Claude.

---

## Knowledge Base + KB CVE

- `core/knowledge_base.json` — 50 vulnerabilidades documentadas de PortSwigger 2024/2025, BlackHat 2024, DEF CON 32/33, OWASP LLM Top 10 2025.
- `core/cve_catalog.json` — 41 CVEs curados con `versions_affected` parseable.
- KB se actualiza mensualmente desde HackerOne Hacktivity API + nuclei-templates (`core/kb_updater.py`).

---

## Scope BBP guardado

`data/scopes/<programa>.txt` — lista de dominios in-scope.
`data/scopes/<programa>_excludes.txt` — patrones de findings out-of-scope (e.g. mobile-only, conocidos duplicados).

```bash
PRESEED_SUBS_ALIVE=data/scopes/empresa.txt ./recon.sh empresa.com --skip-modules=01
```

---

## PoC Generator

`python3 core/poc_generator.py --finding-id 42` — HTML con request/response + curl reproducible + screenshot + impacto + referencias.

---

## AI Advisor — Human-in-the-Loop

Briefing automático tras cada scan + 3-5 preguntas Telegram con botones inline para inferir contexto de negocio. Regenera análisis con Claude Sonnet basado en respuestas.

Consume desde DB: findings + entities + tech stack + host_stack view + juicy_params + login_forms + GitHub findings + breach data.

```bash
python3 core/ai_advisor.py --domain empresa.com --full-analysis
```

---

## Integraciones externas

- **Acunetix** — DAST comercial bajo demanda
- **AWS IP rotation** — módulos ruidosos con IP nueva por ejecución (spot t3.small)
- **EZXSS** — Blind XSS self-hosted con payload_id único por campo
- **Trufflehog** — `--only-verified` en mod 11
- **Caido/Burp** — proxy del tráfico activo (config.env)
- **Telegram bot** — comandos + Q&A vía `claude -p`

---

## MCP Servers

5 servidores Node.js externos accesibles desde Claude Code:

| Server | Puerto | Función |
|---|---|---|
| filesystem | 3001 | Lee outputs de Hackeadora |
| github | 3002 | Repos públicos, commits, secrets |
| playwright | 3003 | Navegador real, login autenticado |
| telegram | 3004 | Notificaciones ricas |
| nvd | 3005 | CVEs por tecnología y versión |

---

## Instalación

### Docker (recomendado)
```bash
git clone https://github.com/afernandesvigo/hackeadora.git
cd hackeadora
cp config.env.example config.env  # editar tokens
docker compose up -d
```

### VPS nativa
```bash
sudo bash install.sh
cp config.env.example config.env  # editar tokens
source config.env
./recon.sh empresa.com
```

---

## Configuración mínima

```bash
# config.env — gitignored
TELEGRAM_BOT_TOKEN=tu_token
TELEGRAM_CHAT_ID=tu_chat_id
TELEGRAM_AUTHORIZED_CHATS=tu_chat_id  # bot bidireccional

# Recomendado
ANTHROPIC_API_KEY=          # AI Advisor
GITHUB_TOKEN=               # GitHub dorking
DEHASHED_EMAIL=
DEHASHED_API_KEY=
ACUNETIX_URL=
ACUNETIX_API_KEY=
AWS_ACCESS_KEY_ID=          # IP rotation
AWS_SECRET_ACCESS_KEY=
EZXSS_URL=
EZXSS_DOMAIN=
WPSCAN_API_TOKEN=
NVD_API_KEY=

# Canaries opt-in (defaults sensatos)
OAUTH_CANARY_DOMAIN=a.dominio.es        # default; tu dominio si lo controlas
OAUTH_CANARY_LOG_PATH=/var/log/nginx/access.log
SSRF_CANARY=                              # opt-in para mod 47
JWT_CANARY=                               # opt-in para mod 45
XXE_CANARY=                               # opt-in para mod 42
IDOR_COOKIE_A=                            # opt-in para mod 41
IDOR_COOKIE_B=
```

---

## CLI extendido

```bash
./recon.sh empresa.com                              # scan completo
./recon.sh empresa.com --target app.empresa.com     # single target
./recon.sh empresa.com --modules=20,40,49           # módulos específicos
./recon.sh empresa.com --skip-modules=01,04,07      # excluir
./recon.sh empresa.com --schedule                   # loop cada 12h
./recon.sh --test-telegram
./recon.sh --stats empresa.com

# Tools de nutrición iterativa
./tools/tech_review.sh output/<dom>/<ts>/tech_suggestions.txt
./tools/tech_add.sh "Tech Name" category 'header_re' 'body_re' '/probe' '200'
./tools/cve_add.sh CVE-2024-XXXX "Tech" critical "Title" "1.0-2.0" "Desc" "PoC" "URL"

# Bot
nohup python3 -u core/telegram_bot.py > /tmp/telegram_bot.log 2>&1 &
```

---

## Filosofía

- **Tech-aware** — cada herramienta solo corre si la tech está presente
- **Anti-FP first** — validators con catch-all guard + body shape obligatorio + OOB confirmation
- **Iterativo** — registry y CVE catalog crecen scan a scan vía CLI helpers
- **Confidence-based** — 4 niveles, Telegram solo notifica `>=high`
- **Respetuoso** — rate limiting, Retry-After, no reintentar 404s
- **Limpio** — Acunetix borra scan/target tras recoger
- **Trazable** — todo el tráfico pasa por Caido/Burp si configurado
- **Seguro** — credenciales AES-256-GCM, env-based, gitignored
- **Colaborativo** — bot Telegram bidireccional con `claude -p` para Q&A en vivo

---

## Requisitos

- Ubuntu 22.04+ / Debian 12+
- Docker + Docker Compose (recomendado)
- 2GB RAM mínimo, 4GB recomendado
- Node.js 18+ (MCPs externos)
- Python 3.10+
- Claude Code CLI 2.x (para bot Telegram free-form Q&A)
- nginx + dominio público con DNS apuntando a la VPS (para OOB canaries: OAuth/SSRF/JWT/XXE/SAML)

---

## Licencia

MIT — para bug bounty y pentesting autorizado únicamente.

---

*Claude (Anthropic) & Antonio Fernandes — Hackeadora 2026*
