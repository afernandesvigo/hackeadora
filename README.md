`# 🔍 Hackeadora

> Pipeline automatizado de Bug Bounty — 32 módulos · 50 vulnerabilidades · PoC con evidencia real

**Autores:** Claude (Anthropic) & Antonio Fernandes
**Licencia:** MIT

---

## ¿Qué es?

Hackeadora es un pipeline completo de bug bounty que corre de forma autónoma en una VPS. Combina herramientas del sector (nuclei, subfinder, katana, ghauri, dalfox, trufflehog...) con análisis de IA (Claude Haiku/Sonnet) y una Knowledge Base con técnicas de BlackHat, DEF CON y PortSwigger Top 10 2023-2025.

```bash
./recon.sh empresa.com                           # scan completo
./recon.sh empresa.com --target app.empresa.com  # single target
./recon.sh empresa.com --modules=20,22,29        # módulos específicos
```

---

## Arquitectura

```
hackeadora/
├── recon.sh                # Pipeline principal (32 módulos)
├── install.sh              # Instalador de herramientas
├── docker-compose.yml / Dockerfile
├── config.env.example
│
├── core/
│   ├── db.sh               # SQLite helpers (20+ tablas)
│   ├── logger.sh           # Logging por niveles
│   ├── notify.sh           # Notificaciones Telegram
│   ├── proxy.sh            # Integración Caido/Burp
│   ├── watchdog.sh         # Supervisor anti-zombie
│   ├── http_analyzer.sh    # Análisis 404/429/500
│   ├── vault.py            # AES-256-GCM credenciales
│   ├── rotator.sh          # IP rotation (AWS spot)
│   ├── cloud_rotator.py    # Instancias AWS t3.small
│   ├── acunetix.py         # Cliente API Acunetix DAST
│   ├── ai_advisor.py       # Claude Haiku/Sonnet + Human-in-the-Loop
│   ├── blindxss_callback.py# Receptor callbacks EZXSS
│   ├── poc_generator.py    # PoC con evidencia real
│   ├── kb_updater.py       # Actualización mensual KB
│   └── knowledge_base.json # 50 vulnerabilidades documentadas
│
├── modules/                # 32 módulos del pipeline
├── web/                    # Dashboard FastAPI + HTML
├── mcp/                    # 5 MCP servers externos (Node.js)
├── blindxss/               # Setup EZXSS self-hosted
└── data/recon.db           # SQLite
```

---

## Los 32 módulos

### Fase 1 — Descubrimiento de superficie
| Módulo | Herramientas |
|--------|-------------|
| 01 Subdomain enum | subfinder, amass, bbot, assetfinder, findomain |
| 02 DNS resolve | dnsx + httpx |
| 03 Takeover | subzy, subjack |
| 17 Cloud assets | cloud_enum — S3, Azure, GCP |
| 18 ASN discovery | asnmap, BGPView API |

### Fase 2 — Recon activo
| Módulo | Herramientas | Notas |
|--------|-------------|-------|
| 04 Nuclei subs | nuclei | templates sobre subdominios |
| 05 Crawler | katana, gau, waybackurls, gospider | via Caido/Burp |
| 06 Active scan | ffuf | dir fuzzing + replay-proxy |
| 07 Nuclei URLs | nuclei | sobre URLs nuevas |
| 08 Screenshots | gowitness | |
| 09/10 Tech detect | whatweb, webanalyze (Wappalyzer), httpx | versiones exactas |
| 11 JS analyzer | SecretFinder + trufflehog --only-verified | secrets verificados activos |
| 12 Login finder | python3 parser | OAuth, SAML, SSO, forgot-password |
| 13 Port scan | masscan + httpx | NET_RAW cap |
| 14 Breach lookup | Dehashed API | primera vez por dominio |
| 15 Param discovery | paramspider + arjun | params jugosos |
| 16 GitHub dorking | GitHub Search API + trufflehog | repos públicos |
| 19 Auth crawler | katana con cookies vault | credenciales AES-256-GCM |

### Fase 3 — Detección de vulnerabilidades
| Módulo | Técnica | Notas |
|--------|---------|-------|
| 20 Smart scan | KB + nuclei + ghauri + dalfox | SQLi, XSS, SSRF, SSTI... |
| 21 Business logic | coupon, payment, role, upload | entities inferidos |
| 22 CORS check | curl | 9 técnicas de bypass |
| 23 403 bypass | curl | path/header/method |
| 24 HTTP Smuggling | smuggler.py + nuclei | solo si CDN/proxy detectado |
| 25 CMS scan | wpscan, joomscan, aem-hacker, log4j-scan | **tech-aware** |
| 26 Path confusion | curl + nuclei | Orange Tsai: nginx/Apache/Tomcat/Spring |
| 27 Blind XSS | EZXSS self-hosted | payload_id único por campo |
| 28 Cache attacks | curl + nuclei | Web Cache Poisoning + WCD |
| 29 Vuln specific | python3 | JWT, OAuth, GraphQL, IDOR exports, Deserial, SMTP, Dependency |
| 30 LLM scan | curl + python3 | OWASP LLM Top 10 2025 |
| 31 JS framework | python3 | React/Next.js/Angular/Vue |
| 32 DOM XSS | python3 source→sink | PoC HTML funcional por source |

---

## Tech-awareness

Cada módulo solo se activa si la tecnología fue detectada por el módulo 10:

| Técnica | Requiere |
|---------|----------|
| WPScan | WordPress detectado |
| aem-hacker | AEM/Adobe o URLs /crx/ en DB |
| Log4Shell | Java/Tomcat/Spring o URLs .jsp |
| React2Shell | Next.js/React o URLs /_next/ |
| Nginx off-by-slash | Server: nginx en headers |
| Cache attacks | X-Cache/CF-Cache-Status presentes |
| HTTP Smuggling | CDN/proxy en tech fingerprinting |
| LLM scan | endpoints /chat /api/ai o widgets en HTML |
| DOM XSS | archivos .js en URLs crawleadas |

---

## Knowledge Base — 50 vulnerabilidades

Técnicas documentadas de conferencias 2023-2025:

**PortSwigger Top 10 2024:**
Apache Confusion Attacks (Orange Tsai, #1) · Web Cache Deception wildcard (#9) · Cookie Tossing OAuth Hijack (#10) · SQL Injection Protocol Level (DEF CON 32)

**PortSwigger Top 10 2025:**
SAML Void Canonicalization (CVE-2025-66568) · Funky Chunks HTTP Smuggling (DEF CON 33) · Cross-Site WebSocket Hijacking · Parser Differentials (#10)

**BlackHat 2024:**
GitHub Actions Runner Takeover ($100k bounty) · React2Shell (CVE-2025-55182)

**Del concurso de vulnerabilidades:**
IDOR en exports · GraphQL batching · OAuth redirect bypass · Insecure Deserialization · JWT attacks · Password Reset Poisoning · SMTP Injection · Dependency Confusion · DOM XSS

**OWASP LLM Top 10 2025:**
LLM01 Prompt Injection · LLM07 System Prompt Leak · LLM06 Excessive Agency · LLM08 Indirect Injection · LLM-to-SSRF chaining · AI Supply Chain

**CVEs de servidor:**
CVE-2025-24813 (Tomcat) · CVE-2025-55752 (Tomcat) · CVE-2024-38819 (Spring) · CVE-2025-66568 (ruby-saml) · CVE-2021-44228 (Log4Shell)

La KB se actualiza mensualmente desde HackerOne Hacktivity API, PayloadsAllTheThings y nuclei-templates.

---

## PoC Generator

Para cada finding genera un documento HTML con evidencia real:

```bash
python3 core/poc_generator.py --domain empresa.com --list
python3 core/poc_generator.py --finding-id 42
python3 core/poc_generator.py --domain empresa.com --all --severity high
```

Cada PoC incluye:
- Request/response HTTP real capturado en el momento
- Comando curl reproducible y copiable
- Pasos numerados específicos para ese finding
- Screenshot del subdominio (si gowitness la capturó)
- Impacto de negocio generado por AI Advisor
- Referencias de conferencias donde se documentó la técnica

Para DOM XSS, la PoC es funcional según el source detectado:
- `location.hash` → URL directa con payload
- `document.referrer` → snippet JS con Referer malicioso
- `window.name` → apertura con name seteado
- `postMessage` → iframe con mensaje inyectado

---

## AI Advisor — Human-in-the-Loop

Al final de cada scan, el AI Advisor genera un briefing automático y hace 3-5 preguntas por Telegram con botones inline:

```
🤖 AI Advisor — Briefing listo
🌐 acmecorp.com

🏢 Negocio inferido: fintech (confianza: high)
⚡ Findings: 4 críticos · 18 altos
💣 Chains detectados: 3

❓ Pregunta 1 de 4:
Los endpoints /api/transfer manejan amount= y to=
¿Son transacciones reales de dinero?

[💰 Dinero real]  [🧪 Sandbox]  [❓ No sé]
```

Con tus respuestas regenera el análisis completo con Claude Sonnet:
- Top findings priorizados por impacto de negocio (no solo severidad técnica)
- Chains con pasos concretos y estimación de bounty
- Quick wins y orden de reporte recomendado

```bash
# Lanzar manualmente
python3 core/ai_advisor.py --domain empresa.com --full-analysis
python3 core/ai_advisor.py --domain empresa.com --silent-briefing
```

---

## Integraciones externas

**Acunetix** — DAST comercial bajo demanda. Botón en el dashboard. Limpia scan y target automáticamente.

**IP Rotation AWS** — módulos ruidosos usan IP nueva por ejecución (spot t3.small).

**EZXSS** — Blind XSS self-hosted con `payload_id` único por campo para identificar exactamente de dónde viene cada callback.

**Trufflehog** — segunda pasada de verificación en módulo 11. Solo reporta secrets activos (`--only-verified`). Sin tokens adicionales necesarios.

---

## MCP Servers

5 servidores externos en la VPS, accesibles desde Claude Code:

| Server | Puerto | Función |
|--------|--------|---------|
| filesystem | 3001 | Lee outputs de Hackeadora |
| github | 3002 | Repos públicos, commits, secrets |
| playwright | 3003 | Navegador real, login autenticado |
| telegram | 3004 | Notificaciones ricas |
| nvd | 3005 | CVEs por tecnología y versión |

```bash
sudo bash mcp/install.sh
bash mcp/status.sh
claude --mcp-config core/mcp_config.json
```

---

## Instalación

### Docker (recomendado)
```bash
git clone https://github.com/afernandesvigo/hackeadora.git
cd hackeadora
cp config.env.example config.env
# Editar config.env con tus tokens
docker compose up -d
```

### VPS nativa
```bash
sudo bash install.sh
cp config.env.example config.env
source config.env
./recon.sh empresa.com
```

---

## Configuración mínima

```bash
# config.env
TELEGRAM_BOT_TOKEN=tu_token
TELEGRAM_CHAT_ID=tu_chat_id

# Recomendado
ANTHROPIC_API_KEY=        # AI Advisor (Claude Haiku/Sonnet)
GITHUB_TOKEN=             # GitHub dorking + módulo 16
DEHASHED_EMAIL=           # Breach lookup
DEHASHED_API_KEY=
ACUNETIX_URL=https://localhost:3443
ACUNETIX_API_KEY=
AWS_ACCESS_KEY_ID=        # IP rotation
AWS_SECRET_ACCESS_KEY=
EZXSS_URL=                # Blind XSS
EZXSS_DOMAIN=             # Dominio del servidor EZXSS
WPSCAN_API_TOKEN=         # 25 req/día gratis
NVD_API_KEY=              # CVE lookup (opcional)
```

---

## Uso

```bash
./recon.sh empresa.com                           # scan completo
./recon.sh empresa.com --target app.empresa.com  # single target
./recon.sh empresa.com --modules=20,22,23,24     # módulos específicos
./recon.sh empresa.com --schedule                # loop cada 12h
./recon.sh empresa.com --force-breach            # forzar Dehashed
./recon.sh --test-telegram
./recon.sh --stats empresa.com
```

---

## Filosofía

- **Tech-aware** — cada herramienta solo corre si la tecnología está presente
- **Respetuoso** — rate limiting, Retry-After, no reintentar 404s
- **Limpio** — Acunetix borra scan y target tras recoger los datos
- **Trazable** — todo el tráfico pasa por Caido/Burp
- **Seguro** — credenciales cifradas AES-256-GCM, nunca en claro en DB
- **Colaborativo** — Human-in-the-Loop via Telegram para contexto de negocio

---

## Requisitos

- Ubuntu 22.04+ / Debian 12+
- Docker + Docker Compose
- 2GB RAM mínimo, 4GB recomendado
- Node.js 18+ (MCPs externos)
- Python 3.10+

---

## Licencia

MIT — para bug bounty y pentesting autorizado únicamente.

---

*Claude (Anthropic) & Antonio Fernandes*


*Hecho con 🖤 por Claude & Antonio Fernandes*
