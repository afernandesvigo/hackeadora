#!/usr/bin/env bash
# ============================================================
#  modules/14_breach_lookup.sh
#  Fase 14: Consulta de filtraciones de datos (Dehashed API)
#
#  Para cada dominio objetivo, consulta Dehashed buscando
#  emails corporativos en filtraciones conocidas.
#
#  FINALIDAD: Reportar exposición de datos como finding
#  legítimo en programas de bug bounty — NO para intentar
#  autenticación ni credential stuffing.
#
#  Requiere: DEHASHED_EMAIL y DEHASHED_API_KEY en config.env
#  Docs API: https://www.dehashed.com/docs
# ============================================================

MODULE_NAME="breach_lookup"
MODULE_DESC="Consulta de filtraciones de datos (Dehashed)"

# ── Inicializar tabla ─────────────────────────────────────────
_init_breach_table() {
  sqlite3 "$DB_PATH" <<'SQL'
CREATE TABLE IF NOT EXISTS breach_findings (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id     INTEGER NOT NULL REFERENCES domains(id),
  email         TEXT NOT NULL,
  username      TEXT,
  breach_source TEXT,          -- nombre de la filtración/base de datos
  hashed_pw     TEXT,          -- hash (nunca plaintext)
  has_password  INTEGER DEFAULT 0,  -- 1 si hay hash (no guardamos el valor)
  ip_address    TEXT,
  phone         TEXT,
  address       TEXT,
  found_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(domain_id, email, breach_source)
);
CREATE INDEX IF NOT EXISTS idx_breach_domain ON breach_findings(domain_id);
CREATE INDEX IF NOT EXISTS idx_breach_email  ON breach_findings(email);
SQL
}

# ── Consultar Dehashed API ────────────────────────────────────
_query_dehashed() {
  local DOMAIN="$1"
  local OUT_FILE="$2"

  if [[ -z "${DEHASHED_EMAIL:-}" ]] || [[ -z "${DEHASHED_API_KEY:-}" ]]; then
    log_warn "DEHASHED_EMAIL / DEHASHED_API_KEY no configurados en config.env"
    return 1
  fi

  log_info "Consultando Dehashed para @${DOMAIN}..."

  # API v1 — búsqueda por dominio en el campo email
  local RESPONSE
  RESPONSE=$(curl -s \
    --max-time 30 \
    -H "Accept: application/json" \
    -u "${DEHASHED_EMAIL}:${DEHASHED_API_KEY}" \
    "https://api.dehashed.com/search?query=email%3A%40${DOMAIN}&size=100" \
    2>/dev/null)

  if [[ -z "$RESPONSE" ]]; then
    log_warn "Dehashed: sin respuesta"
    return 1
  fi

  # Verificar errores de API
  local ERROR
  ERROR=$(echo "$RESPONSE" | jq -r '.message // ""' 2>/dev/null)
  if [[ -n "$ERROR" ]] && [[ "$ERROR" != "null" ]]; then
    log_warn "Dehashed API error: $ERROR"
    return 1
  fi

  echo "$RESPONSE" > "$OUT_FILE"

  local TOTAL
  TOTAL=$(echo "$RESPONSE" | jq -r '.total // 0' 2>/dev/null)
  log_info "Dehashed: $TOTAL entradas encontradas para @${DOMAIN}"
  echo "$TOTAL"
}

# ── Función principal ─────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"
  local FORCE="${4:-${BREACH_FORCE:-false}}"   # true = forzar aunque ya haya datos

  log_phase "Módulo 14 — $MODULE_DESC: $DOMAIN"

  # ── Solo correr en la primera vez (o si se fuerza) ────────
  local EXISTING
  EXISTING=$(sqlite3 "$DB_PATH"     "SELECT COUNT(*) FROM breach_findings WHERE domain_id=${DOMAIN_ID};" 2>/dev/null || echo "0")

  if [[ "$EXISTING" -gt 0 ]] && [[ "$FORCE" != "true" ]]; then
    log_info "Breach lookup ya realizado para $DOMAIN ($EXISTING entradas). Saltando."
    log_info "Para forzar actualización usa el botón en el dashboard."
    return
  fi

  local DEHASHED_OUT="$OUT_DIR/dehashed_results.json"
  local TOTAL
  TOTAL=$(_query_dehashed "$DOMAIN" "$DEHASHED_OUT") || return

  if [[ "${TOTAL:-0}" -eq 0 ]]; then
    log_ok "Sin filtraciones conocidas para @${DOMAIN}"
    rm -f "$DEHASHED_OUT"
    return
  fi

  # ── Procesar y guardar resultados ─────────────────────────
  local NEW_COUNT=0
  local SOURCES=()
  local EMAILS_AFFECTED=()

  while IFS= read -r ENTRY; do
    [[ -z "$ENTRY" ]] && continue

    local EMAIL USERNAME SOURCE HAS_PW IP PHONE ADDRESS
    EMAIL=$(echo "$ENTRY"    | jq -r '.email // ""')
    USERNAME=$(echo "$ENTRY" | jq -r '.username // ""')
    SOURCE=$(echo "$ENTRY"   | jq -r '.database_name // "unknown"')
    # Solo guardamos SI hay hash, no el hash en sí — por privacidad
    local PW_VAL
    PW_VAL=$(echo "$ENTRY"   | jq -r '.password // ""')
    HAS_PW=0
    [[ -n "$PW_VAL" ]] && HAS_PW=1
    IP=$(echo "$ENTRY"      | jq -r '.ip_address // ""')
    PHONE=$(echo "$ENTRY"   | jq -r '.phone // ""')
    ADDRESS=$(echo "$ENTRY" | jq -r '.address // ""')

    [[ -z "$EMAIL" ]] && continue
    # Solo emails del dominio objetivo
    echo "$EMAIL" | grep -qi "@${DOMAIN}$" || continue

    local EMAIL_ESC="${EMAIL//\'/\'\'}"
    local USER_ESC="${USERNAME//\'/\'\'}"
    local SRC_ESC="${SOURCE//\'/\'\'}"
    local IP_ESC="${IP//\'/\'\'}"

    local BEFORE
    BEFORE=$(sqlite3 "$DB_PATH" \
      "SELECT COUNT(*) FROM breach_findings
       WHERE domain_id=${DOMAIN_ID} AND email='${EMAIL_ESC}' AND breach_source='${SRC_ESC}';" 2>/dev/null || echo "1")

    sqlite3 "$DB_PATH" \
      "INSERT OR IGNORE INTO breach_findings
       (domain_id,email,username,breach_source,has_password,ip_address,phone,address)
       VALUES(${DOMAIN_ID},'${EMAIL_ESC}','${USER_ESC}','${SRC_ESC}',
              ${HAS_PW},'${IP_ESC}','${PHONE//\'/\'\'}','${ADDRESS//\'/\'\'}');" \
      2>/dev/null || true

    if [[ "${BEFORE:-0}" == "0" ]]; then
      ((NEW_COUNT++))
      SOURCES+=("$SOURCE")
      EMAILS_AFFECTED+=("$EMAIL")
    fi

  done < <(jq -c '.entries[]?' "$DEHASHED_OUT" 2>/dev/null)

  # ── Estadísticas ──────────────────────────────────────────
  local UNIQUE_SOURCES
  UNIQUE_SOURCES=$(printf '%s\n' "${SOURCES[@]}" | sort -u | tr '\n' ',' | sed 's/,$//')
  local UNIQUE_EMAILS
  UNIQUE_EMAILS=$(printf '%s\n' "${EMAILS_AFFECTED[@]}" | sort -u | wc -l | tr -d ' ')
  local HAS_PW_COUNT
  HAS_PW_COUNT=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM breach_findings WHERE domain_id=${DOMAIN_ID} AND has_password=1;" 2>/dev/null || echo 0)

  if [[ "$NEW_COUNT" -gt 0 ]]; then
    # Guardar como finding de severidad según si hay hashes
    local SEVERITY="medium"
    [[ "$HAS_PW_COUNT" -gt 0 ]] && SEVERITY="high"

    db_add_finding "$DOMAIN_ID" "breach" "$SEVERITY" \
      "@${DOMAIN}" "dehashed" \
      "${UNIQUE_EMAILS} emails en ${#SOURCES[@]} filtraciones: ${UNIQUE_SOURCES:0:200}"

    # Notificar por Telegram
    _telegram_send "⚠️ *Filtración de datos detectada*
🌐 Dominio: \`${DOMAIN}\`
📧 Emails afectados: \`${UNIQUE_EMAILS}\`
📊 Entradas nuevas: \`${NEW_COUNT}\`
${HAS_PW_COUNT:+🔒 Con hash de contraseña: \`${HAS_PW_COUNT}\`}
🗄️ Fuentes: ${UNIQUE_SOURCES:0:300}
⚠️ *Reportar a la empresa como exposición de datos*
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

    log_warn "⚠ $UNIQUE_EMAILS emails de @${DOMAIN} en filtraciones conocidas"
    log_warn "  Fuentes: ${UNIQUE_SOURCES:0:100}"
  fi

  rm -f "$DEHASHED_OUT"
  log_ok "$MODULE_DESC completado: $NEW_COUNT entradas nuevas de filtración"
}
