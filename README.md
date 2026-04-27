# 🔍 Hackeadora

> Pipeline automatizado de Bug Bounty — 28 módulos de recon y detección de vulnerabilidades

**Autores:** Claude (Anthropic) & Antonio Fernandes  
**Licencia:** MIT

---

## ¿Qué es Hackeadora?

Hackeadora es un pipeline completo de bug bounty diseñado para ejecutarse de forma autónoma en una VPS, respetando el scope del programa y minimizando el ruido contra el objetivo. Combina herramientas del sector (nuclei, subfinder, katana, ghauri, dalfox...) con análisis de IA (Claude Haiku/Sonnet) y una Knowledge Base actualizable con técnicas de BlackHat, DEF CON y PortSwigger Top 10.

```bash
./recon.sh empresa.com
```

---

## Arquitectura

```
hackeadora/
├── recon.sh                # Pipeline principal (28 módulos)
├── install.sh              # Instalador de herramientas
├── quickstart.sh           # Docker quickstart
├── docker-compose.yml
├── Dockerfile
├── config.env.example
│
├── core/                   # Infraestructura
│   ├── db.sh               # SQLite helpers (20+ tablas)
│   ├── logger.sh           # Logging por niveles
│   ├── notify.sh           # Notificaciones Telegram
│   ├── proxy.sh            # Integración Caido/Burp
│   ├── watchdog.sh         # Supervisor anti-zombie
│   ├── http_analyzer.sh    # Análisis inteligente 404/429/500
│   ├── vault.py            # AES-256-GCM cifrado credenciales
│   ├── rotator.sh          # IP rotation (AWS spot)
│   ├── cloud_rotator.py    # Instancias AWS t3.small
│   ├── acunetix.py         # Cliente API Acunetix
│   ├── ai_advisor.py       # Claude Haiku/Sonnet
│   ├── blindxss_callback.py# Receptor callbacks EZXSS
│   ├── poc_generator.py    # Generador de PoC con evidencia real
│   ├── kb_updater.py       # Actualización mensual KB
│   └── knowledge_base.json # 33 vulnerabilidades documentadas
│
├── modules/                # 28 módulos del pipeline
├── web/                    # Dashboard FastAPI + HTML
├── mcp/                    # 5 MCP servers externos (Node.js)
├── blindxss/               # Setup EZXSS self-hosted
└── data/recon.db           # SQLite
```

---

## Los 28 módulos

### Fase 1 — Descubrimiento de superficie
| Módulo | Herramientas | Notas |
|--------|-------------|-------|
| 01 Subdomain enum | subfinder, amass, bbot, assetfinder, findomain | |
| 02 DNS resolve | dnsx, httpx | alive/dead + metadata |
| 03 Takeover | subzy, subjack | alerta Telegram inmediata |
| 17 Cloud assets | cloud_enum, checks directos | S3, Azure, GCP |
| 18 ASN discovery | asnmap, BGPView API | CIDRs → masscan → httpx |

### Fase 2 — Recon activo
| Módulo | Herramientas | Notas |
|--------|-------------|-------|
| 04 Nuclei subs | nuclei | solo subdominios nuevos |
| 05 Crawler | katana, gau, waybackurls, gospider | por proxy Caido/Burp |
| 06 Active scan | ffuf | -replay-proxy, http_analyzer |
| 07 Nuclei URLs | nuclei | URLs nuevas |
| 08 Screenshots | gowitness | |
| 09/10 Tech detect | whatweb, webanalyze (Wappalyzer), httpx | versiones exactas |
| 11 JS analyzer | SecretFinder + regex propios | 30+ patrones de secrets |
| 12 Login finder | curl + DOM parsing | OAuth, SAML, SSO |
| 13 Port scan | masscan + httpx | NET_RAW cap |
| 14 Breach lookup | Dehashed API | solo primera vez |
| 15 Param discovery | paramspider + arjun | params jugosos |
| 16 GitHub dorking | GitHub Search API + trufflehog | |
| 19 Auth crawler | katana + gospider con cookies | vault AES-256-GCM |

### Fase 3 — Detección de vulnerabilidades
| Módulo | Herramientas | Notas |
|--------|-------------|-------|
| 20 Smart scan | KB + nuclei + ghauri + dalfox | SQLi, XSS, SSRF, SSTI... |
| 21 Business logic | sqlite + curl | payment, coupon, role, upload |
| 22 CORS check | curl | 9 técnicas |
| 23 403 bypass | curl | path/header/method bypass |
| 24 HTTP Smuggling | smuggler.py + nuclei | solo si CDN/proxy detectado |
| 25 CMS scan | wpscan, joomscan, droopescan, aem-hacker, log4j-scan | tech-aware |
| 26 Path confusion | curl + nuclei | Orange Tsai nginx/Apache/Tomcat/Spring |
| 27 Blind XSS | EZXSS self-hosted | payload_id único por campo |
| 28 Cache attacks | curl + nuclei | Web Cache Poisoning + WCD |

---

## Tech-awareness

Cada módulo solo se activa si la tecnología correspondiente fue detectada por el módulo 10:

| Técnica | Requiere detección previa |
|---------|--------------------------|
| WPScan | WordPress en tech fingerprinting |
| joomscan | Joomla en tech fingerprinting |
| aem-hacker | AEM/Adobe o URLs /crx/ crawleadas |
| Log4Shell | Java/Tomcat/Spring en tech o URLs .jsp/.action |
| React2Shell | Next.js/React en tech o URLs /_next/ crawleadas |
| Nginx off-by-slash | Server: nginx en headers |
| Apache Confusion | Server: Apache en headers |
| Tomcat ..;/ | JSESSIONID/Tomcat en headers |
| Cache attacks | X-Cache/CF-Cache-Status en respuestas |
| HTTP Smuggling | CDN/proxy en tech fingerprinting |

---

## Knowledge Base — 33 vulnerabilidades

Técnicas documentadas en conferencias de seguridad 2023-2025:

**PortSwigger Top 10 2024:**
- Apache Confusion Attacks — Orange Tsai, BlackHat 2024 (#1)
- Web Cache Deception wildcard (#9)
- Cookie Tossing → OAuth Hijack (#10)
- SQL Injection at Protocol Level — DEF CON 32

**PortSwigger Top 10 2025:**
- SAML Void Canonicalization — CVE-2025-66568/66567
- Funky Chunks HTTP Smuggling — DEF CON 33
- Cross-Site WebSocket Hijacking
- Parser Differentials (#10)

**BlackHat 2024:**
- GitHub Actions Self-Hosted Runner Takeover
- React2Shell — CVE-2025-55182/66478

**CVEs de servidor:**
- Tomcat ..;/ — CVE-2025-24813
- Tomcat RewriteValve — CVE-2025-55752
- Spring Path Traversal — CVE-2024-38819
- Apache CVE-2024-38475/38476/38477/39573

La KB se actualiza automáticamente cada mes desde HackerOne Hacktivity API, PayloadsAllTheThings y nuclei-templates.

---

## PoC Generator

Genera documentos HTML con evidencia real listos para HackerOne:

```bash
# Listar findings disponibles
python3 core/poc_generator.py --domain empresa.com --list

# Generar PoC para un finding
python3 core/poc_generator.py --finding-id 42

# Todas las PoCs de un dominio
python3 core/poc_generator.py --domain empresa.com --all --severity high
```

Cada PoC incluye: request real capturado, response con evidencia, curl reproducible, pasos numerados, screenshot, impacto de negocio y referencias de conferencias.

---

## Integraciones externas

**Acunetix** — DAST comercial bajo demanda, limpia scan y target automáticamente.

**IP Rotation AWS** — módulos ruidosos (ghauri, dalfox, React2Shell) usan IP nueva por ejecución.

**EZXSS** — Blind XSS self-hosted con payload_id único por campo para identificar exactamente de dónde viene cada callback.

---

## MCP Servers

5 servidores MCP externos en la VPS, accesibles desde Claude Code:

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

# Opcional pero recomendado
ANTHROPIC_API_KEY=        # AI Advisor (Claude Haiku/Sonnet)
GITHUB_TOKEN=             # GitHub dorking + módulo 16
DEHASHED_EMAIL=           # Breach lookup
DEHASHED_API_KEY=
ACUNETIX_URL=https://localhost:3443
ACUNETIX_API_KEY=
AWS_ACCESS_KEY_ID=        # IP rotation
AWS_SECRET_ACCESS_KEY=
EZXSS_URL=                # Blind XSS callbacks
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

## Watchdog

Supervisor de procesos anti-zombie:
- Timeout por módulo (10-30 min según el módulo)
- Monitor de CPU/memoria por proceso
- Limpieza de instancias AWS abiertas al salir
- El pipeline continúa aunque un módulo falle

```bash
WATCHDOG_ENABLED=true
MAX_CPU_PERCENT=90
MAX_MEM_MB=2048
```

---

## Filosofía

- **Tech-aware** — cada herramienta solo corre si la tecnología está presente
- **Respetuoso** — rate limiting, Retry-After, no reintentar 404s
- **Limpio** — Acunetix borra scan y target tras recoger los datos
- **Trazable** — todo el tráfico pasa por Caido/Burp
- **Seguro** — credenciales cifradas AES-256-GCM, nunca en claro en DB

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
