# 🕵️ Hackeadora

> Pipeline automatizado y modular de bug hunting continuo.
> 22 módulos, inteligencia de negocio, AI advisor y dashboard web completo.

**Autores:** Claude (Anthropic) & Antonio Fernandes  
**Licencia:** MIT

---

## ¿Qué hace?

Hackeadora ejecuta un ciclo de reconocimiento completo sobre uno o varios dominios, con inteligencia creciente en cada fase:

### Fase 1 — Descubrimiento de superficie
1. **Enumeración de subdominios** — subfinder, amass, bbot, assetfinder, findomain
2. **Resolución DNS** — dnsx + httpx → alive/dead
3. **Subdomain Takeover** — subzy + subjack → Telegram inmediato
4. **Nuclei sobre subdominios nuevos**
5. **Crawling** — katana, gau, waybackurls, gospider → por proxy Caido/Burp
6. **Directory fuzzing** — ffuf por proxy → nuevas URLs a la rueda
7. **Nuclei sobre URLs nuevas**
8. **Screenshots** — gowitness
9. **Tech detection** — whatweb
10. **Tech fingerprinting** — Wappalyzer por URL con versiones (triaje CVE)

### Fase 2 — Análisis profundo
11. **JS Analyzer** — secrets (30+ patrones) + endpoints → rueda de scan
12. **Login Finder** — DOM parsing, OAuth, SAML, SSO, API auth
13. **Port Scan** — masscan sobre puertos web no estándar → httpx verify
14. **Breach Lookup** — Dehashed API (solo primera vez, actualización manual)

### Fase 3 — Superficie ampliada (Bloque A)
15. **Param Discovery** — paramspider + arjun → parámetros ocultos
16. **GitHub Dorking** — GitHub Search API + trufflehog sobre la org
17. **Cloud Enum** — S3/Azure/GCP bucket enumeration con mutaciones
18. **ASN Discovery** — asnmap + BGPView → rangos IP → masscan

### Fase 4 — Autenticación y lógica
19. **Auth Crawler** — credenciales del vault cifrado (AES-256-GCM) → crawling autenticado por Caido
20. **Smart Scan** — guiado por Knowledge Base: SSRF, IDOR, Open Redirect, SSTI, CORS...
21. **Business Logic** — inferencia de entidades (payment, coupon, role...) + tests automáticos
22. **AI Advisor** — Claude Haiku/Sonnet al final del scan (opcional, requiere API key)

---

## 🐳 Docker (recomendado)

```bash
git clone https://github.com/afernandesvigo/hackeadora.git
cd hackeadora
cp .env.example .env
nano .env                    # tokens Telegram, Dehashed, GitHub, Anthropic
mkdir -p data
echo "ejemplo.com" > data/targets.txt
chmod +x quickstart.sh && ./quickstart.sh
```

| Contenedor | Función | Puerto |
|---|---|---|
| hackeadora-web | Dashboard + Telegram webhook | 8080 |
| hackeadora-worker | Procesa confirmaciones Telegram | — |
| hackeadora-recon | Loop de recon cada N horas | — |
| hackeadora-caido | Proxy pasivo | 8181 / UI:7070 |
| hackeadora-kb-updater | Actualización mensual de KB | — |

---

## Instalación manual (sin Docker)

```bash
cp config.env.example config.env
nano config.env
sudo ./install.sh
./recon.sh --test-telegram
```

---

## Estructura

```
hackeadora/
├── Dockerfile / docker-compose.yml / quickstart.sh
├── install.sh / recon.sh / config.env.example / .env.example
│
├── core/
│   ├── db.sh              # SQLite: 15+ tablas
│   ├── logger.sh          # Logging centralizado
│   ├── notify.sh          # Telegram tipado
│   ├── proxy.sh           # Caido/Burp helper
│   ├── vault.py           # AES-256-GCM cifrado de credenciales
│   ├── knowledge_base.json # 15 tipos de vuln con payloads y patrones
│   ├── kb_updater.py      # Actualizador mensual automático de KB
│   └── ai_advisor.py      # Claude Haiku/Sonnet para análisis y chains
│
├── modules/
│   ├── 01_subdomain_enum.sh
│   ├── 02_dns_resolve.sh
│   ├── 03_takeover.sh
│   ├── 04_nuclei_scan.sh
│   ├── 05_crawler.sh         # con proxy Caido/Burp
│   ├── 06_active_scan.sh     # ffuf con -replay-proxy
│   ├── 07_nuclei_urls.sh
│   ├── 08_screenshots.sh
│   ├── 09_tech_detect.sh
│   ├── 10_tech_fingerprint.sh
│   ├── 11_js_analyzer.sh
│   ├── 12_login_finder.sh
│   ├── 13_port_scan.sh
│   ├── 14_breach_lookup.sh
│   ├── 15_param_discovery.sh
│   ├── 16_github_dorking.sh
│   ├── 17_cloud_enum.sh
│   ├── 18_asn_discovery.sh
│   ├── 19_auth_crawler.sh
│   ├── 20_smart_scan.sh
│   ├── 21_business_logic.sh
│   └── TEMPLATE.sh
│
└── web/
    ├── app.py             # FastAPI — 25+ endpoints
    ├── start.sh
    └── static/index.html  # Dashboard single-file
```

---

## Base de datos (SQLite)

| Tabla | Contenido |
|---|---|
| domains | Dominios monitorizados |
| subdomains | Subdominios con IP, status, tech |
| urls | URLs con fuente y estado nuclei |
| findings | Vulnerabilidades con severidad |
| technologies | Tech + versión por URL (triaje CVE) |
| js_files | JS analizados con SHA256 |
| js_secrets | Secrets encontrados (enmascarados) |
| js_endpoints | Endpoints extraídos de JS |
| login_forms | Login forms con tipo (form/OAuth/SAML/SSO) |
| port_findings | Servicios web en puertos no estándar |
| breach_findings | Emails en filtraciones (Dehashed) |
| url_params | Parámetros descubiertos por URL |
| github_findings | Secrets/endpoints en repos públicos |
| cloud_assets | Buckets S3/Azure/GCP |
| asn_ranges | Rangos IP por ASN |
| auth_credentials | Credenciales cifradas AES-256-GCM |
| business_entities | Entidades de negocio inferidas |
| business_tests | Tests de lógica ejecutados |
| ai_suggestions | Sugerencias del AI Advisor |
| confirm_queue | Confirmaciones pendientes Telegram |
| scan_history | Historial de fases por dominio |

---

## Dashboard web

```bash
./web/start.sh   # http://localhost:8080
```

### Vistas globales (sidebar)
- **Overview** — stats de todos los dominios
- **All Findings** — vulnerabilidades por severidad
- **🔬 Technologies** — fingerprinting + buscador CVE (tech+versión → URLs afectadas)
- **🔑 JS Secrets** — secrets por tipo y dominio
- **🔐 Login Forms** — formularios de auth detectados
- **⚠️ Breaches** — emails en filtraciones
- **🎯 Parámetros** — params ocultos descubiertos
- **🐙 GitHub** — findings en repos públicos
- **☁️ Cloud Assets** — buckets abiertos/protegidos
- **🗺️ ASN/IP Ranges** — superficie más allá del DNS
- **🔒 Vault** — gestión de credenciales cifradas
- **🧠 Knowledge Base** — 15 tipos de vuln con patrones + botón de actualización
- **🤖 AI Advisor** — sugerencias IA priorizadas + coste estimado

### Vistas por dominio (pestañas)
Subdominios · URLs · Findings · Timeline · Screenshots · 🔬 Tech · 🔑 JS · 🔐 Logins · 🔌 Ports · ⚠️ Breaches · 🔒 Vault · 🏢 Business · 🤖 AI

---

## Knowledge Base + Auto-actualización

La KB (`core/knowledge_base.json`) contiene 15 tipos de vulnerabilidades con:
- Frecuencia en HackerOne y bounty promedio
- Parámetros y rutas que las triggean
- Payloads reales de PayloadsAllTheThings
- Tags de nuclei asociados

Se actualiza automáticamente cada mes desde:
- HackerOne Hacktivity API (reportes divulgados)
- GitHub commits de PayloadsAllTheThings y HowToHunt
- Nuclei templates nuevos

```bash
python3 core/kb_updater.py           # actualización normal
python3 core/kb_updater.py --force   # forzar aunque sea reciente
python3 core/kb_updater.py --dry-run # ver cambios sin guardar
```

---

## AI Advisor (opcional)

Requiere `ANTHROPIC_API_KEY` en `.env`. Sin ella, el pipeline funciona igual.

```bash
# Análisis de oportunidades (Haiku, ~$0.001-0.005)
python3 core/ai_advisor.py --domain empresa.com

# + Chains de vulnerabilidades (Sonnet, ~$0.05-0.10)
python3 core/ai_advisor.py --domain empresa.com --run-chains

# Borrador reporte H1 (Sonnet, ~$0.05-0.15)
python3 core/ai_advisor.py --domain empresa.com --report <finding_id>
```

El advisor se ejecuta automáticamente al final de cada scan y genera:
- Dónde la IA aporta más profundidad que las herramientas automáticas
- Cadenas de vulnerabilidades combinando findings existentes
- Borradores de reportes H1 listos para enviar

---

## Proxy (Caido / Burp)

Todo el tráfico activo (katana, gospider, ffuf) pasa por el proxy:

```env
PROXY_TOOL=caido    # caido | burp | none
PROXY_HOST=caido    # hostname Docker (misma VPS)
PROXY_PORT=8181     # Caido:8181 / Burp:8080
```

---

## Vault de credenciales

Credenciales de prueba cifradas con AES-256-GCM. Nunca en claro en la DB.

```bash
# Generar VAULT_KEY segura
openssl rand -base64 32
```

Gestión desde el dashboard → 🔒 Vault o por dominio → pestaña Vault.
Al encontrar un login form sin credenciales → Telegram notifica para añadirlas.

---

## Uso

```bash
./recon.sh empresa.com              # scan único
./recon.sh empresa.com --schedule   # loop cada 12h
./recon.sh empresa.com --modules=01,02,15  # módulos específicos
./recon.sh --test-telegram          # probar Telegram
./recon.sh --stats empresa.com      # ver stats DB
```

---

## Añadir un módulo nuevo

```bash
cp modules/TEMPLATE.sh modules/22_mi_modulo.sh
# implementar module_run()
# en recon.sh añadir:
run_module "22_mi_modulo"
```

---

## Variables de entorno (.env)

```env
# Obligatorias
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...

# Recomendadas
GITHUB_TOKEN=...           # dorking + trufflehog sin rate limit
VAULT_KEY=...              # cifrado de credenciales (openssl rand -base64 32)

# Opcionales
ANTHROPIC_API_KEY=...      # AI Advisor (~$0.01-0.15 por dominio)
DEHASHED_EMAIL=...         # breach lookup
DEHASHED_API_KEY=...
SSRF_CALLBACK=...          # interactsh o servidor propio
MASSCAN_RATE=1000          # paquetes/seg para port scan
```

---

## Herramientas instaladas

| Categoría | Herramientas |
|---|---|
| Subdominios | subfinder, amass, bbot, assetfinder, findomain |
| DNS / HTTP | dnsx, httpx |
| Takeover | subzy, subjack |
| Vuln scan | nuclei + templates + ghauri (SQLi) + dalfox (XSS) |
| Crawling | katana, gau, waybackurls, gospider, hakrawler |
| Fuzzing | ffuf |
| Screenshots | gowitness |
| Tech | whatweb, webanalyze (Wappalyzer) |
| JS | SecretFinder + patrones PCRE propios |
| Params | paramspider, arjun |
| Recon ASN | asnmap, mapcidr |
| Secrets | trufflehog |
| Cloud | cloud_enum |
| Port scan | masscan |
| Utilidades | anew, qsreplace, unfurl, jq, sqlite3 |
| Web API | fastapi, uvicorn, cryptography |

---

## Roadmap

- [ ] Worker Telegram — botones inline para confirmar scans activos
- [ ] Módulo 22 — CORS checker dedicado
- [ ] Módulo 23 — 403 bypass automatizado
- [ ] Módulo 24 — HTTP Request Smuggling
- [ ] Módulo 25 — GraphQL introspection + IDOR
- [ ] Exportar findings a PDF / CSV
- [ ] Autenticación en el dashboard
- [ ] Modo multi-tenant (varios hunters)

---

*Hecho con 🖤 por Claude & Antonio Fernandes*
