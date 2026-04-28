#!/usr/bin/env bash
# ============================================================
#  core/db.sh — Gestión de base de datos SQLite
#  Se incluye con: source core/db.sh
# ============================================================

# Requiere: DB_PATH definido en config.env

# ── Inicialización ────────────────────────────────────────────
db_init() {
  mkdir -p "$(dirname "$DB_PATH")"
  sqlite3 "$DB_PATH" <<'SQL'
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- Dominios raíz monitorizados
CREATE TABLE IF NOT EXISTS domains (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  domain    TEXT UNIQUE NOT NULL,
  added_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_scan DATETIME
);

-- Subdominios descubiertos
CREATE TABLE IF NOT EXISTS subdomains (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id   INTEGER NOT NULL REFERENCES domains(id),
  subdomain   TEXT NOT NULL,
  ip          TEXT,
  status      TEXT CHECK(status IN ('alive','dead','unknown')) DEFAULT 'unknown',
  http_status INTEGER,
  title       TEXT,
  tech        TEXT,           -- JSON array de tecnologías detectadas
  first_seen  DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_seen   DATETIME DEFAULT CURRENT_TIMESTAMP,
  nuclei_done INTEGER DEFAULT 0,
  UNIQUE(domain_id, subdomain)
);

-- URLs descubiertas
CREATE TABLE IF NOT EXISTS urls (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id   INTEGER NOT NULL REFERENCES domains(id),
  url         TEXT NOT NULL,
  status_code INTEGER,
  content_type TEXT,
  source      TEXT,           -- katana | gau | wayback | gospider
  first_seen  DATETIME DEFAULT CURRENT_TIMESTAMP,
  nuclei_done INTEGER DEFAULT 0,
  UNIQUE(domain_id, url)
);

-- Findings (vulns / takeovers)
CREATE TABLE IF NOT EXISTS findings (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id   INTEGER NOT NULL REFERENCES domains(id),
  type        TEXT NOT NULL,  -- nuclei | takeover | active_scan
  severity    TEXT,
  target      TEXT NOT NULL,
  template    TEXT,
  detail      TEXT,
  notified    INTEGER DEFAULT 0,
  found_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Tecnologías detectadas por URL
CREATE TABLE IF NOT EXISTS technologies (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id   INTEGER NOT NULL REFERENCES domains(id),
  url         TEXT NOT NULL,
  subdomain   TEXT NOT NULL,
  tech_name   TEXT NOT NULL,
  tech_version TEXT,
  category    TEXT,
  confidence  INTEGER DEFAULT 100,
  source      TEXT DEFAULT 'wappalyzer',
  first_seen  DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_seen   DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(domain_id, url, tech_name)
);

CREATE INDEX IF NOT EXISTS idx_tech_name    ON technologies(tech_name);
CREATE INDEX IF NOT EXISTS idx_tech_version ON technologies(tech_name, tech_version);
CREATE INDEX IF NOT EXISTS idx_tech_domain  ON technologies(domain_id);

-- Historial de scans
CREATE TABLE IF NOT EXISTS scan_history (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id   INTEGER NOT NULL REFERENCES domains(id),
  phase       TEXT NOT NULL,
  started_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
  finished_at DATETIME,
  status      TEXT DEFAULT 'running',
  summary     TEXT            -- JSON con stats del scan
);
SQL
  log_ok "Base de datos inicializada: $DB_PATH"
  db_init_js
}

# ── Helpers SQL ───────────────────────────────────────────────
_db() { sqlite3 "$DB_PATH" "$@"; }

_db_query() {
  sqlite3 -separator '|' "$DB_PATH" "$@"
}

# ── Dominios ──────────────────────────────────────────────────
db_add_domain() {
  local DOMAIN="$1"
  _db "INSERT OR IGNORE INTO domains(domain) VALUES('${DOMAIN}');"
  _db "UPDATE domains SET last_scan=CURRENT_TIMESTAMP WHERE domain='${DOMAIN}';"
}

db_get_domain_id() {
  local DOMAIN="$1"
  _db "SELECT id FROM domains WHERE domain='${DOMAIN}';" | head -1
}

# ── Subdominios ───────────────────────────────────────────────
db_add_subdomain() {
  local DOMAIN_ID="$1"
  local SUBDOMAIN="$2"
  local IP="${3:-}"
  local STATUS="${4:-unknown}"
  local HTTP="${5:-}"
  local TITLE="${6:-}"

  _db "INSERT OR IGNORE INTO subdomains(domain_id,subdomain,ip,status,http_status,title)
       VALUES(${DOMAIN_ID},'${SUBDOMAIN}','${IP}','${STATUS}','${HTTP}','${TITLE}');
       UPDATE subdomains SET last_seen=CURRENT_TIMESTAMP
       WHERE domain_id=${DOMAIN_ID} AND subdomain='${SUBDOMAIN}';"
}

# Devuelve 1 si el subdominio es nuevo (recién insertado), 0 si ya existía
db_is_new_subdomain() {
  local DOMAIN_ID="$1"
  local SUBDOMAIN="$2"
  local COUNT
  COUNT=$(_db "SELECT COUNT(*) FROM subdomains
               WHERE domain_id=${DOMAIN_ID} AND subdomain='${SUBDOMAIN}'
               AND date(first_seen) = date('now');")
  [[ "$COUNT" -gt 0 ]] && echo "1" || echo "0"
}

db_get_subdomain_nuclei_pending() {
  local DOMAIN_ID="$1"
  _db_query "SELECT subdomain FROM subdomains
             WHERE domain_id=${DOMAIN_ID} AND status='alive' AND nuclei_done=0;"
}

db_mark_subdomain_nuclei_done() {
  local DOMAIN_ID="$1"
  local SUBDOMAIN="$2"
  _db "UPDATE subdomains SET nuclei_done=1
       WHERE domain_id=${DOMAIN_ID} AND subdomain='${SUBDOMAIN}';"
}

db_update_subdomain_status() {
  local DOMAIN_ID="$1"
  local SUBDOMAIN="$2"
  local STATUS="$3"    # alive | dead
  local HTTP="${4:-}"
  local IP="${5:-}"
  local TITLE="${6:-}"
  _db "UPDATE subdomains SET status='${STATUS}', http_status='${HTTP}',
       ip='${IP}', title='${TITLE}', last_seen=CURRENT_TIMESTAMP
       WHERE domain_id=${DOMAIN_ID} AND subdomain='${SUBDOMAIN}';"
}

# ── URLs ──────────────────────────────────────────────────────
db_add_url() {
  local DOMAIN_ID="$1"
  local URL="$2"
  local SOURCE="${3:-unknown}"
  local STATUS="${4:-}"

  _db "INSERT OR IGNORE INTO urls(domain_id,url,source,status_code)
       VALUES(${DOMAIN_ID},'${URL}','${SOURCE}','${STATUS}');"
}

# Devuelve 1 si la URL es nueva
db_is_new_url() {
  local DOMAIN_ID="$1"
  local URL="$2"
  local COUNT
  COUNT=$(_db "SELECT COUNT(*) FROM urls
               WHERE domain_id=${DOMAIN_ID} AND url='${URL}'
               AND date(first_seen) = date('now');")
  [[ "$COUNT" -gt 0 ]] && echo "1" || echo "0"
}

db_get_urls_nuclei_pending() {
  local DOMAIN_ID="$1"
  _db_query "SELECT url FROM urls WHERE domain_id=${DOMAIN_ID} AND nuclei_done=0;"
}

db_mark_url_nuclei_done() {
  local DOMAIN_ID="$1"
  local URL="$2"
  _db "UPDATE urls SET nuclei_done=1
       WHERE domain_id=${DOMAIN_ID} AND url='${URL//\'/\'\'}' ;"
}

# ── Findings ──────────────────────────────────────────────────
db_add_finding() {
  local DOMAIN_ID="$1"
  local TYPE="$2"
  local SEVERITY="$3"
  local TARGET="$4"
  local TEMPLATE="${5:-}"
  local DETAIL="${6:-}"
  _db "INSERT INTO findings(domain_id,type,severity,target,template,detail,notified)
       VALUES(${DOMAIN_ID},'${TYPE}','${SEVERITY}','${TARGET}','${TEMPLATE}','${DETAIL//\'/\'\'}',1);"
}

# ── Stats ─────────────────────────────────────────────────────
db_stats() {
  local DOMAIN_ID="$1"
  local SUBS ALIVE URLS FINDINGS
  SUBS=$(_db    "SELECT COUNT(*) FROM subdomains WHERE domain_id=${DOMAIN_ID};")
  ALIVE=$(_db   "SELECT COUNT(*) FROM subdomains WHERE domain_id=${DOMAIN_ID} AND status='alive';")
  URLS=$(_db    "SELECT COUNT(*) FROM urls       WHERE domain_id=${DOMAIN_ID};")
  FINDINGS=$(_db "SELECT COUNT(*) FROM findings  WHERE domain_id=${DOMAIN_ID};")
  echo "Subdominios: ${SUBS} (alive: ${ALIVE}) | URLs: ${URLS} | Findings: ${FINDINGS}"
}

# ── Scan history ──────────────────────────────────────────────
db_scan_start() {
  local DOMAIN_ID="$1"
  local PHASE="$2"
  _db "INSERT INTO scan_history(domain_id,phase) VALUES(${DOMAIN_ID},'${PHASE}');"
  _db "SELECT last_insert_rowid();"
}

db_scan_end() {
  local SCAN_ID="$1"
  local STATUS="${2:-ok}"
  local SUMMARY="${3:-}"
  _db "UPDATE scan_history SET finished_at=CURRENT_TIMESTAMP,
       status='${STATUS}', summary='${SUMMARY//\'/\'\'}'
       WHERE id=${SCAN_ID};"
}

# ── Technologies ──────────────────────────────────────────────

db_upsert_tech() {
  # db_upsert_tech <domain_id> <url> <subdomain> <tech_name> <version> <category> <confidence> <source>
  local DOMAIN_ID="$1"
  local URL="$2"
  local SUBDOMAIN="$3"
  local TECH_NAME="$4"
  local VERSION="${5:-}"
  local CATEGORY="${6:-}"
  local CONFIDENCE="${7:-100}"
  local SOURCE="${8:-wappalyzer}"

  # Escapar comillas simples
  local URL_ESC="${URL//\'/\'\'}"
  local TECH_ESC="${TECH_NAME//\'/\'\'}"
  local VER_ESC="${VERSION//\'/\'\'}"
  local CAT_ESC="${CATEGORY//\'/\'\'}"
  local SUB_ESC="${SUBDOMAIN//\'/\'\'}"

  _db "INSERT INTO technologies(domain_id,url,subdomain,tech_name,tech_version,category,confidence,source)
       VALUES(${DOMAIN_ID},'${URL_ESC}','${SUB_ESC}','${TECH_ESC}','${VER_ESC}','${CAT_ESC}',${CONFIDENCE},'${SOURCE}')
       ON CONFLICT(domain_id,url,tech_name) DO UPDATE SET
         tech_version=excluded.tech_version,
         category=excluded.category,
         confidence=excluded.confidence,
         last_seen=CURRENT_TIMESTAMP;"
}

db_search_tech() {
  # db_search_tech <tech_name_pattern>  → devuelve filas de technologies + domain
  local PATTERN="${1//%/}"   # quitar % por si acaso, lo añadimos nosotros
  sqlite3 -separator '|' "$DB_PATH" \
    "SELECT t.tech_name, t.tech_version, t.url, t.subdomain, t.category, t.confidence, d.domain, t.last_seen
     FROM technologies t JOIN domains d ON d.id=t.domain_id
     WHERE t.tech_name LIKE '%${PATTERN}%'
     ORDER BY t.tech_name, t.tech_version, d.domain;"
}

db_tech_stats() {
  # Top tecnologías globales
  _db "SELECT tech_name, tech_version, COUNT(*) as hits
       FROM technologies
       GROUP BY tech_name, tech_version
       ORDER BY hits DESC LIMIT 50;"
}

# ══════════════════════════════════════════════════════════════
#  JS Analysis tables
# ══════════════════════════════════════════════════════════════

db_init_js() {
  sqlite3 "$DB_PATH" <<'SQL'
PRAGMA journal_mode=WAL;

-- Archivos JS descubiertos y analizados
CREATE TABLE IF NOT EXISTS js_files (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id     INTEGER NOT NULL REFERENCES domains(id),
  url           TEXT NOT NULL,
  subdomain     TEXT NOT NULL,
  size_bytes    INTEGER,
  sha256        TEXT,               -- para detectar cambios entre scans
  analyzed_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
  endpoints_found INTEGER DEFAULT 0,
  secrets_found   INTEGER DEFAULT 0,
  UNIQUE(domain_id, url)
);

-- Secrets encontrados en JS
CREATE TABLE IF NOT EXISTS js_secrets (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id   INTEGER NOT NULL REFERENCES domains(id),
  js_file_id  INTEGER REFERENCES js_files(id),
  js_url      TEXT NOT NULL,
  secret_type TEXT NOT NULL,   -- AWS_KEY | GH_TOKEN | GOOGLE_API | STRIPE | genérico...
  secret_value TEXT NOT NULL,  -- valor enmascarado (primeros/últimos chars)
  secret_raw  TEXT,            -- valor completo (opcional, puede omitirse por seguridad)
  line_number INTEGER,
  context     TEXT,            -- línea de código alrededor del secret
  severity    TEXT DEFAULT 'high',
  notified    INTEGER DEFAULT 0,
  found_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(domain_id, js_url, secret_type, secret_value)
);

-- Endpoints extraídos de JS (entran en la rueda de scan)
CREATE TABLE IF NOT EXISTS js_endpoints (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id   INTEGER NOT NULL REFERENCES domains(id),
  js_file_id  INTEGER REFERENCES js_files(id),
  js_url      TEXT NOT NULL,        -- JS donde se encontró
  endpoint    TEXT NOT NULL,        -- endpoint extraído
  full_url    TEXT,                 -- URL completa si se pudo construir
  method      TEXT,                 -- GET|POST|PUT... si se detectó
  params      TEXT,                 -- parámetros detectados (JSON)
  first_seen  DATETIME DEFAULT CURRENT_TIMESTAMP,
  added_to_queue INTEGER DEFAULT 0, -- 1 = ya entró en el pipeline de URLs
  UNIQUE(domain_id, js_url, endpoint)
);

CREATE INDEX IF NOT EXISTS idx_js_secrets_type   ON js_secrets(secret_type);
CREATE INDEX IF NOT EXISTS idx_js_secrets_domain ON js_secrets(domain_id);
CREATE INDEX IF NOT EXISTS idx_js_endpoints_dom  ON js_endpoints(domain_id);
SQL
  log_ok "Tablas JS inicializadas"
  db_init_surface
}

# ── JS Files ──────────────────────────────────────────────────
db_upsert_js_file() {
  local DOMAIN_ID="$1" URL="$2" SUBDOMAIN="$3"
  local SIZE="${4:-0}" SHA="${5:-}" EP="${6:-0}" SEC="${7:-0}"
  local URL_ESC="${URL//\'/\'\'}"
  local SUB_ESC="${SUBDOMAIN//\'/\'\'}"
  local SHA_ESC="${SHA//\'/\'\'}"
  _db "INSERT INTO js_files(domain_id,url,subdomain,size_bytes,sha256,endpoints_found,secrets_found)
       VALUES(${DOMAIN_ID},'${URL_ESC}','${SUB_ESC}',${SIZE},'${SHA_ESC}',${EP},${SEC})
       ON CONFLICT(domain_id,url) DO UPDATE SET
         sha256=excluded.sha256, size_bytes=excluded.size_bytes,
         endpoints_found=excluded.endpoints_found,
         secrets_found=excluded.secrets_found,
         analyzed_at=CURRENT_TIMESTAMP;"
  _db "SELECT id FROM js_files WHERE domain_id=${DOMAIN_ID} AND url='${URL_ESC}';"
}

# ── JS Secrets ────────────────────────────────────────────────
db_add_js_secret() {
  local DOMAIN_ID="$1" JS_FILE_ID="$2" JS_URL="$3"
  local TYPE="$4" VALUE_MASKED="$5" VALUE_RAW="$6"
  local LINE="${7:-0}" CONTEXT="${8:-}" SEVERITY="${9:-high}"
  local URL_ESC="${JS_URL//\'/\'\'}"
  local VAL_ESC="${VALUE_MASKED//\'/\'\'}"
  local RAW_ESC="${VALUE_RAW//\'/\'\'}"
  local CTX_ESC="${CONTEXT//\'/\'\'}"
  # Devuelve 1 si fue nuevo
  local BEFORE
  BEFORE=$(_db "SELECT COUNT(*) FROM js_secrets WHERE domain_id=${DOMAIN_ID} AND js_url='${URL_ESC}' AND secret_type='${TYPE}' AND secret_value='${VAL_ESC}';")
  _db "INSERT OR IGNORE INTO js_secrets
       (domain_id,js_file_id,js_url,secret_type,secret_value,secret_raw,line_number,context,severity,notified)
       VALUES(${DOMAIN_ID},${JS_FILE_ID},'${URL_ESC}','${TYPE}','${VAL_ESC}','${RAW_ESC}',${LINE},'${CTX_ESC}','${SEVERITY}',0);"
  [[ "$BEFORE" == "0" ]] && echo "1" || echo "0"
}

# ── JS Endpoints ──────────────────────────────────────────────
db_add_js_endpoint() {
  local DOMAIN_ID="$1" JS_FILE_ID="$2" JS_URL="$3"
  local ENDPOINT="$4" FULL_URL="${5:-}" METHOD="${6:-}" PARAMS="${7:-}"
  local URL_ESC="${JS_URL//\'/\'\'}"
  local EP_ESC="${ENDPOINT//\'/\'\'}"
  local FU_ESC="${FULL_URL//\'/\'\'}"
  local PM_ESC="${PARAMS//\'/\'\'}"
  local BEFORE
  BEFORE=$(_db "SELECT COUNT(*) FROM js_endpoints WHERE domain_id=${DOMAIN_ID} AND js_url='${URL_ESC}' AND endpoint='${EP_ESC}';")
  _db "INSERT OR IGNORE INTO js_endpoints
       (domain_id,js_file_id,js_url,endpoint,full_url,method,params,added_to_queue)
       VALUES(${DOMAIN_ID},${JS_FILE_ID},'${URL_ESC}','${EP_ESC}','${FU_ESC}','${METHOD}','${PM_ESC}',0);"
  [[ "$BEFORE" == "0" ]] && echo "1" || echo "0"
}

db_get_js_endpoints_pending() {
  local DOMAIN_ID="$1"
  _db_query "SELECT endpoint, full_url FROM js_endpoints
             WHERE domain_id=${DOMAIN_ID} AND added_to_queue=0 AND full_url != '';"
}

db_mark_js_endpoints_queued() {
  local DOMAIN_ID="$1"
  _db "UPDATE js_endpoints SET added_to_queue=1
       WHERE domain_id=${DOMAIN_ID} AND added_to_queue=0;"
}

# ══════════════════════════════════════════════════════════════
#  Confirmation queue — para confirmaciones por Telegram
# ══════════════════════════════════════════════════════════════

db_init_queue() {
  sqlite3 "$DB_PATH" <<'SQL'
PRAGMA journal_mode=WAL;

-- Cola de confirmaciones pendientes vía Telegram
CREATE TABLE IF NOT EXISTS confirm_queue (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id    INTEGER NOT NULL REFERENCES domains(id),
  domain       TEXT NOT NULL,
  target       TEXT NOT NULL,      -- subdominio, URL o endpoint
  target_type  TEXT NOT NULL,      -- subdomain | url | js_endpoint
  status       TEXT DEFAULT 'pending',  -- pending | approved_full | approved_nuclei | rejected | expired
  telegram_msg_id INTEGER,         -- ID del mensaje de Telegram con botones
  created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
  responded_at DATETIME,
  scan_done    INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_queue_status ON confirm_queue(status);
CREATE INDEX IF NOT EXISTS idx_queue_msg    ON confirm_queue(telegram_msg_id);
SQL
}

db_queue_add() {
  # db_queue_add <domain_id> <domain> <target> <target_type>
  # Devuelve el ID del registro
  local DOMAIN_ID="$1" DOMAIN="$2" TARGET="$3" TYPE="$4"
  local T_ESC="${TARGET//\'/\'\'}"
  local D_ESC="${DOMAIN//\'/\'\'}"

  # No encolar si ya hay uno pending para el mismo target
  local EXISTING
  EXISTING=$(_db "SELECT COUNT(*) FROM confirm_queue
                  WHERE domain='${D_ESC}' AND target='${T_ESC}' AND status='pending';")
  if [[ "$EXISTING" -gt 0 ]]; then
    _db "SELECT id FROM confirm_queue WHERE domain='${D_ESC}' AND target='${T_ESC}' AND status='pending';"
    return
  fi

  _db "INSERT INTO confirm_queue(domain_id,domain,target,target_type)
       VALUES(${DOMAIN_ID},'${D_ESC}','${T_ESC}','${TYPE}');"
  _db "SELECT last_insert_rowid();"
}

db_queue_set_msg_id() {
  local QUEUE_ID="$1" MSG_ID="$2"
  _db "UPDATE confirm_queue SET telegram_msg_id=${MSG_ID} WHERE id=${QUEUE_ID};"
}

db_queue_respond() {
  local MSG_ID="$1" STATUS="$2"   # approved_full | approved_nuclei | rejected
  _db "UPDATE confirm_queue
       SET status='${STATUS}', responded_at=CURRENT_TIMESTAMP
       WHERE telegram_msg_id=${MSG_ID} AND status='pending';"
  # Devolver target y domain para que el worker sepa qué lanzar
  _db_query "SELECT id, domain, target, target_type, domain_id
             FROM confirm_queue WHERE telegram_msg_id=${MSG_ID};"
}

db_queue_mark_done() {
  local QUEUE_ID="$1"
  _db "UPDATE confirm_queue SET scan_done=1 WHERE id=${QUEUE_ID};"
}

db_queue_expire_old() {
  # Expirar confirmaciones sin respuesta después de 24h
  _db "UPDATE confirm_queue SET status='expired'
       WHERE status='pending'
       AND created_at < datetime('now', '-24 hours');"
}

db_queue_pending() {
  _db_query "SELECT * FROM confirm_queue WHERE status='pending' ORDER BY created_at;"
}

# ══════════════════════════════════════════════════════════════
#  Bloque A — Tablas de descubrimiento de superficie ampliada
# ══════════════════════════════════════════════════════════════

db_init_surface() {
  sqlite3 "$DB_PATH" <<'SQL'
PRAGMA journal_mode=WAL;

-- Parámetros descubiertos por URL
CREATE TABLE IF NOT EXISTS url_params (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id   INTEGER NOT NULL REFERENCES domains(id),
  url         TEXT NOT NULL,
  param_name  TEXT NOT NULL,
  source      TEXT DEFAULT 'paramspider', -- paramspider | arjun | crawler
  first_seen  DATETIME DEFAULT CURRENT_TIMESTAMP,
  nuclei_done INTEGER DEFAULT 0,
  UNIQUE(domain_id, url, param_name)
);

-- Findings de GitHub dorking
CREATE TABLE IF NOT EXISTS github_findings (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id   INTEGER NOT NULL REFERENCES domains(id),
  repo_url    TEXT NOT NULL,
  file_path   TEXT,
  finding_type TEXT NOT NULL, -- secret | endpoint | credential | config
  content     TEXT,           -- fragmento relevante (sin secrets completos)
  severity    TEXT DEFAULT 'high',
  found_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(domain_id, repo_url, file_path, finding_type)
);

-- Cloud assets encontrados
CREATE TABLE IF NOT EXISTS cloud_assets (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id   INTEGER NOT NULL REFERENCES domains(id),
  asset_url   TEXT NOT NULL,
  provider    TEXT NOT NULL,  -- aws | azure | gcp
  asset_type  TEXT NOT NULL,  -- s3 | blob | gcs | cloudfront
  status      TEXT,           -- open | protected | not_found
  size_hint   TEXT,
  found_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(domain_id, asset_url)
);

-- Rangos IP / ASN descubiertos
CREATE TABLE IF NOT EXISTS asn_ranges (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id   INTEGER NOT NULL REFERENCES domains(id),
  asn         TEXT NOT NULL,
  org         TEXT,
  cidr        TEXT NOT NULL,
  country     TEXT,
  found_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  scanned     INTEGER DEFAULT 0,
  UNIQUE(domain_id, cidr)
);

CREATE INDEX IF NOT EXISTS idx_params_domain   ON url_params(domain_id);
CREATE INDEX IF NOT EXISTS idx_params_url      ON url_params(url);
CREATE INDEX IF NOT EXISTS idx_github_domain   ON github_findings(domain_id);
CREATE INDEX IF NOT EXISTS idx_cloud_domain    ON cloud_assets(domain_id);
CREATE INDEX IF NOT EXISTS idx_asn_domain      ON asn_ranges(domain_id);
SQL
  log_ok "Tablas Bloque A inicializadas"
  db_init_blindxss
  db_init_poc
  db_init_acunetix
  db_init_business
  db_init_vault
}

# ══════════════════════════════════════════════════════════════
#  Auth Vault — credenciales de prueba por subdominio
# ══════════════════════════════════════════════════════════════

db_init_vault() {
  sqlite3 "$DB_PATH" <<'SQL'
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS auth_credentials (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id     INTEGER NOT NULL REFERENCES domains(id),
  domain        TEXT NOT NULL,       -- dominio raíz: empresa.com
  subdomain     TEXT NOT NULL,       -- subdominio exacto: app.empresa.com
  app_url       TEXT NOT NULL,       -- URL del login form
  username      TEXT NOT NULL,
  password_enc  TEXT NOT NULL,       -- AES cifrado con VAULT_KEY
  auth_type     TEXT DEFAULT 'form', -- form | basic | bearer | cookie
  session_data  TEXT,                -- cookie/token activo (cifrado)
  valid         INTEGER DEFAULT 1,   -- 1=válidas, 0=expiradas/incorrectas
  last_used     DATETIME,
  last_verified DATETIME,
  notes         TEXT,
  added_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(domain_id, subdomain, username)
);

CREATE INDEX IF NOT EXISTS idx_vault_domain    ON auth_credentials(domain_id);
CREATE INDEX IF NOT EXISTS idx_vault_subdomain ON auth_credentials(subdomain);
SQL
}

# ── Helpers vault ─────────────────────────────────────────────
db_vault_get() {
  # db_vault_get <domain_id> <subdomain>
  # Devuelve la primera credencial válida para ese subdominio
  local DOMAIN_ID="$1"
  local SUBDOMAIN="$2"
  _db_query "SELECT id, username, password_enc, auth_type, session_data, app_url
             FROM auth_credentials
             WHERE domain_id=${DOMAIN_ID}
               AND subdomain='${SUBDOMAIN//\'/\'\'}'
               AND valid=1
             LIMIT 1;"
}

db_vault_has_creds() {
  local DOMAIN_ID="$1"
  local SUBDOMAIN="$2"
  local COUNT
  COUNT=$(_db "SELECT COUNT(*) FROM auth_credentials
               WHERE domain_id=${DOMAIN_ID}
                 AND subdomain='${SUBDOMAIN//\'/\'\'}' AND valid=1;")
  [[ "$COUNT" -gt 0 ]] && echo "1" || echo "0"
}

db_vault_add() {
  local DOMAIN_ID="$1" DOMAIN="$2" SUBDOMAIN="$3"
  local APP_URL="$4" USERNAME="$5" PASSWORD_ENC="$6"
  local AUTH_TYPE="${7:-form}" NOTES="${8:-}"
  _db "INSERT OR REPLACE INTO auth_credentials
       (domain_id,domain,subdomain,app_url,username,password_enc,auth_type,notes)
       VALUES(${DOMAIN_ID},'${DOMAIN//\'/\'\'}','${SUBDOMAIN//\'/\'\'}',
              '${APP_URL//\'/\'\'}','${USERNAME//\'/\'\'}','${PASSWORD_ENC//\'/\'\'}',
              '${AUTH_TYPE}','${NOTES//\'/\'\'}');"
}

db_vault_update_session() {
  local CRED_ID="$1" SESSION_ENC="$2"
  _db "UPDATE auth_credentials SET session_data='${SESSION_ENC//\'/\'\'}',
       last_used=CURRENT_TIMESTAMP WHERE id=${CRED_ID};"
}

db_vault_invalidate() {
  local CRED_ID="$1"
  _db "UPDATE auth_credentials SET valid=0 WHERE id=${CRED_ID};"
}

db_vault_list() {
  local DOMAIN_ID="$1"
  _db_query "SELECT id, subdomain, app_url, username, auth_type, valid,
                    last_used, last_verified, notes
             FROM auth_credentials
             WHERE domain_id=${DOMAIN_ID}
             ORDER BY subdomain;"
}

# ══════════════════════════════════════════════════════════════
#  Business Logic + AI Advisor tables
# ══════════════════════════════════════════════════════════════

db_init_business() {
  sqlite3 "$DB_PATH" <<'SQL'
PRAGMA journal_mode=WAL;

-- Entidades de negocio inferidas del dominio
CREATE TABLE IF NOT EXISTS business_entities (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id   INTEGER NOT NULL REFERENCES domains(id),
  entity_type TEXT NOT NULL,   -- payment|coupon|role|subscription|upload|user|order|api
  entity_name TEXT NOT NULL,   -- nombre inferido (ej: "coupon", "subscription_plan")
  endpoints   TEXT,            -- JSON array de endpoints relacionados
  params      TEXT,            -- JSON array de parámetros detectados
  flows       TEXT,            -- JSON array de flujos detectados
  rules_inferred TEXT,         -- JSON array de reglas de negocio inferidas
  risk_score  INTEGER DEFAULT 0, -- 0-100
  first_seen  DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(domain_id, entity_type, entity_name)
);

-- Tests de lógica de negocio ejecutados
CREATE TABLE IF NOT EXISTS business_tests (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id   INTEGER NOT NULL REFERENCES domains(id),
  entity_id   INTEGER REFERENCES business_entities(id),
  test_type   TEXT NOT NULL,   -- price_manipulation|coupon_reuse|role_escalation|race_condition|etc
  target_url  TEXT NOT NULL,
  result      TEXT,            -- passed|failed|interesting|error
  detail      TEXT,
  executed_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Sugerencias del AI Advisor
CREATE TABLE IF NOT EXISTS ai_suggestions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id   INTEGER NOT NULL REFERENCES domains(id),
  scan_date   DATETIME DEFAULT CURRENT_TIMESTAMP,
  suggestion_type TEXT NOT NULL, -- ai_depth|chain|report_draft
  priority    INTEGER DEFAULT 5, -- 1=critical, 10=low
  title       TEXT NOT NULL,
  description TEXT NOT NULL,
  affected_urls TEXT,           -- JSON
  estimated_cost_usd REAL,
  ai_model    TEXT,             -- haiku|sonnet
  status      TEXT DEFAULT 'pending', -- pending|sent_to_ai|done
  ai_response TEXT              -- respuesta del LLM si se lanzó
);

CREATE INDEX IF NOT EXISTS idx_biz_domain  ON business_entities(domain_id);
CREATE INDEX IF NOT EXISTS idx_btest_domain ON business_tests(domain_id);
CREATE INDEX IF NOT EXISTS idx_ai_domain   ON ai_suggestions(domain_id);
SQL
}

# ══════════════════════════════════════════════════════════════
#  Acunetix integration tables
# ══════════════════════════════════════════════════════════════

db_init_acunetix() {
  sqlite3 "$DB_PATH" <<'SQL'
PRAGMA journal_mode=WAL;

-- Scans lanzados en Acunetix
CREATE TABLE IF NOT EXISTS acunetix_scans (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id       INTEGER NOT NULL REFERENCES domains(id),
  subdomain       TEXT NOT NULL,
  acunetix_scan_id TEXT,           -- ID del scan en Acunetix
  acunetix_target_id TEXT,         -- ID del target en Acunetix
  status          TEXT DEFAULT 'queued', -- queued|running|completed|failed
  started_at      DATETIME,
  finished_at     DATETIME,
  findings_count  INTEGER DEFAULT 0,
  requested_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Vulnerabilidades encontradas por Acunetix
CREATE TABLE IF NOT EXISTS acunetix_findings (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id       INTEGER NOT NULL REFERENCES domains(id),
  scan_id         INTEGER REFERENCES acunetix_scans(id),
  subdomain       TEXT NOT NULL,
  vuln_id         TEXT,            -- ID interno Acunetix
  name            TEXT NOT NULL,
  severity        TEXT,            -- critical|high|medium|low|info
  confidence      TEXT,            -- certain|firm|tentative
  url             TEXT,
  parameter       TEXT,
  request         TEXT,            -- HTTP request (truncado)
  response        TEXT,            -- HTTP response snippet
  detail          TEXT,
  recommendation  TEXT,
  cvss_score      REAL,
  cwe             TEXT,
  notified        INTEGER DEFAULT 0,
  found_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(domain_id, scan_id, vuln_id)
);

CREATE INDEX IF NOT EXISTS idx_acx_scans_domain   ON acunetix_scans(domain_id);
CREATE INDEX IF NOT EXISTS idx_acx_findings_domain ON acunetix_findings(domain_id);
CREATE INDEX IF NOT EXISTS idx_acx_findings_sev    ON acunetix_findings(severity);
SQL
}

# ══════════════════════════════════════════════════════════════
#  Blind XSS tables
# ══════════════════════════════════════════════════════════════
db_init_blindxss() {
  sqlite3 "$DB_PATH" <<'SQL'
PRAGMA journal_mode=WAL;

-- Payloads inyectados con su identificador único
CREATE TABLE IF NOT EXISTS blindxss_payloads (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id    INTEGER NOT NULL REFERENCES domains(id),
  payload_id   TEXT NOT NULL UNIQUE,   -- hash único ej: a3f7b2c1
  subdomain    TEXT NOT NULL,
  target_url   TEXT NOT NULL,          -- URL donde se inyectó
  field_type   TEXT NOT NULL,          -- header|form_field|comment|import|useragent
  field_name   TEXT,                   -- nombre del campo concreto
  injected_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
  fired        INTEGER DEFAULT 0,      -- 0=pendiente, 1=disparado
  fired_at     DATETIME,
  fired_from   TEXT,                   -- URL donde se disparó (panel admin, etc.)
  fired_ip     TEXT,                   -- IP desde donde se disparó
  fired_ua     TEXT,                   -- User-Agent del admin que lo vio
  fired_cookies TEXT,                  -- Cookies capturadas (si las hay)
  fired_dom    TEXT,                   -- Fragmento del DOM donde se disparó
  notified     INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_blindxss_domain    ON blindxss_payloads(domain_id);
CREATE INDEX IF NOT EXISTS idx_blindxss_payload   ON blindxss_payloads(payload_id);
CREATE INDEX IF NOT EXISTS idx_blindxss_fired     ON blindxss_payloads(fired);
SQL
}

# ══════════════════════════════════════════════════════════════
#  PoC Evidence table — almacena request/response reales
# ══════════════════════════════════════════════════════════════
db_init_poc() {
  sqlite3 "$DB_PATH" <<'SQL'
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS poc_evidence (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id    INTEGER REFERENCES findings(id),
  domain_id     INTEGER NOT NULL REFERENCES domains(id),
  vuln_type     TEXT NOT NULL,
  target_url    TEXT NOT NULL,
  -- Request capturado
  req_method    TEXT,
  req_headers   TEXT,
  req_body      TEXT,
  -- Response capturado
  resp_status   INTEGER,
  resp_headers  TEXT,
  resp_body     TEXT,   -- truncado a 5KB para no saturar la DB
  -- Evidencia específica del tipo de vuln
  evidence_type TEXT,   -- cors_header|xss_reflected|sqli_error|redirect|etc
  evidence_data TEXT,   -- el dato concreto que prueba la vuln
  -- Reproducibilidad
  curl_command  TEXT,   -- comando curl listo para copiar
  captured_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_poc_finding  ON poc_evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_poc_domain   ON poc_evidence(domain_id);
CREATE INDEX IF NOT EXISTS idx_poc_vuln     ON poc_evidence(vuln_type);
SQL
}
