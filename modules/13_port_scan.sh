#!/usr/bin/env bash
# ============================================================
#  modules/13_port_scan.sh
#  Fase 13: Detección de servicios web en puertos no estándar
#
#  Flujo:
#    1. masscan sobre subdominios alive → puertos web comunes
#    2. httpx verifica cuáles tienen web real
#    3. Los nuevos servicios entran en la DB como subdominios
#       y se añaden a la rueda completa de scan
#    4. Telegram notifica cada nuevo servicio encontrado
# ============================================================

MODULE_NAME="port_scan"
MODULE_DESC="Detección de servicios web en puertos no estándar (masscan)"

# Puertos web a escanear (excluimos 80 y 443 — ya los cubre el pipeline normal)
WEB_PORTS="8080,8443,8888,8000,8008,8081,8082,8083,8090,8888,
           3000,3001,3002,3003,3030,3306,
           4000,4443,4848,
           5000,5001,5601,
           6000,6060,6443,
           7000,7001,7002,7070,7080,7443,7878,
           9000,9001,9090,9091,9200,9300,9443,
           10000,10443,
           15672,16080,
           18080,18443,
           20000,28017"

# Limpiar espacios/saltos de la lista
WEB_PORTS=$(echo "$WEB_PORTS" | tr -d ' \n')

# ── Inicializar tabla ─────────────────────────────────────────
_init_ports_table() {
  sqlite3 "$DB_PATH" <<'SQL'
CREATE TABLE IF NOT EXISTS port_findings (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id   INTEGER NOT NULL REFERENCES domains(id),
  subdomain   TEXT NOT NULL,
  ip          TEXT NOT NULL,
  port        INTEGER NOT NULL,
  protocol    TEXT DEFAULT 'tcp',
  service_url TEXT,         -- https?://subdomain:port
  http_status INTEGER,
  http_title  TEXT,
  tech        TEXT,
  banner      TEXT,
  first_seen  DATETIME DEFAULT CURRENT_TIMESTAMP,
  added_to_pipeline INTEGER DEFAULT 0,
  UNIQUE(domain_id, subdomain, port)
);
CREATE INDEX IF NOT EXISTS idx_ports_domain ON port_findings(domain_id);
CREATE INDEX IF NOT EXISTS idx_ports_port   ON port_findings(port);
SQL
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 13 — $MODULE_DESC: $DOMAIN"

  _init_ports_table

  # ── Verificar masscan ─────────────────────────────────────
  if ! command -v masscan &>/dev/null; then
    log_warn "masscan no encontrado — instala con: sudo apt install masscan"
    log_warn "o: sudo ./install.sh"
    return
  fi

  local ALIVE="$OUT_DIR/subs_alive.txt"
  if [[ ! -s "$ALIVE" ]]; then
    log_warn "Sin subdominios alive, saltando port scan"
    return
  fi

  # ── Resolver IPs de subdominios alive ─────────────────────
  # masscan trabaja sobre IPs, necesitamos resolverlas
  local IP_MAP="$OUT_DIR/.ip_map.txt"       # ip|subdomain
  local IP_LIST="$OUT_DIR/.masscan_ips.txt" # solo IPs (para masscan)
  > "$IP_MAP"; > "$IP_LIST"

  log_info "Resolviendo IPs de subdominios alive..."
  while IFS= read -r SUB; do
    [[ -z "$SUB" ]] && continue
    local IP
    # Intentar con dnsx primero, fallback a host
    if command -v dnsx &>/dev/null; then
      IP=$(echo "$SUB" | dnsx -silent -a -resp-only 2>/dev/null | head -1)
    fi
    [[ -z "$IP" ]] && IP=$(host "$SUB" 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}')
    [[ -z "$IP" ]] && continue

    # Evitar IPs privadas / loopback (no tiene sentido escanearlas)
    echo "$IP" | grep -qP '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.)' && continue

    echo "${IP}|${SUB}" >> "$IP_MAP"
    echo "$IP" >> "$IP_LIST"
  done < "$ALIVE"

  sort -u "$IP_LIST" -o "$IP_LIST"
  local IP_COUNT
  IP_COUNT=$(wc -l < "$IP_LIST" | tr -d ' ')

  if [[ "$IP_COUNT" -eq 0 ]]; then
    log_warn "No se resolvieron IPs válidas, saltando"
    rm -f "$IP_MAP" "$IP_LIST"
    return
  fi

  log_info "$IP_COUNT IPs únicas para escanear"

  # ── Rotador de IPs (opcional) ──────────────────────────────
  source "$(dirname "$0")/../core/rotator.sh" 2>/dev/null || true
  if rotator_enabled && [[ "$IP_COUNT" -gt 50 ]]; then
    log_info "Rotador activo para masscan — scan distribuido en múltiples IPs"
  fi

  # ── Masscan ───────────────────────────────────────────────
  local MASSCAN_OUT="$OUT_DIR/masscan_results.json"
  local RATE="${MASSCAN_RATE:-1000}"   # paquetes/seg — conservador por defecto

  log_info "Lanzando masscan (rate=${RATE} pps) sobre puertos: ${WEB_PORTS:0:60}..."

  # masscan necesita root — intentar con sudo si no somos root
  local SUDO=""
  [[ "$(id -u)" -ne 0 ]] && SUDO="sudo"

  $SUDO masscan \
    -iL "$IP_LIST" \
    -p "$WEB_PORTS" \
    --rate "$RATE" \
    --open \
    -oJ "$MASSCAN_OUT" \
    --exclude 255.255.255.255 \
    2>/dev/null \
  || {
    log_warn "masscan falló — ¿falta sudo o NET_RAW capability?"
    rm -f "$IP_MAP" "$IP_LIST"
    return
  }

  if [[ ! -s "$MASSCAN_OUT" ]]; then
    log_info "masscan: no se encontraron puertos abiertos"
    rm -f "$IP_MAP" "$IP_LIST" "$MASSCAN_OUT"
    return
  fi

  # ── Parsear resultados masscan ────────────────────────────
  # Formato JSON: [{"ip":"1.2.3.4","ports":[{"port":8080,"proto":"tcp",...}]}]
  local OPEN_PORTS="$OUT_DIR/.open_ports.txt"  # ip:port
  > "$OPEN_PORTS"

  # Masscan JSON puede no ser válido si se interrumpe — parsear con python
  python3 - << PYEOF >> "$OPEN_PORTS" 2>/dev/null || \
  jq -r '.[] | .ip as $ip | .ports[] | "\($ip):\(.port)"' "$MASSCAN_OUT" 2>/dev/null >> "$OPEN_PORTS" || true
import json, sys
try:
    raw = open('${MASSCAN_OUT}').read().rstrip(',\n ]') + ']'
    data = json.loads(raw)
    for entry in data:
        ip = entry.get('ip','')
        for p in entry.get('ports',[]):
            print(f"{ip}:{p['port']}")
except Exception as e:
    sys.exit(0)
PYEOF

  sort -u "$OPEN_PORTS" -o "$OPEN_PORTS"
  local OPEN_COUNT
  OPEN_COUNT=$(wc -l < "$OPEN_PORTS" | tr -d ' ')
  log_info "masscan: $OPEN_COUNT puertos abiertos encontrados"

  if [[ "$OPEN_COUNT" -eq 0 ]]; then
    log_info "No se encontraron puertos web adicionales"
    rm -f "$IP_MAP" "$IP_LIST" "$MASSCAN_OUT" "$OPEN_PORTS"
    return
  fi

  # ── Construir URLs para httpx ─────────────────────────────
  # Para cada ip:port, buscar el subdominio correspondiente
  local HTTPX_TARGETS="$OUT_DIR/.httpx_ports.txt"
  > "$HTTPX_TARGETS"

  while IFS=: read -r IP PORT; do
    [[ -z "$IP" || -z "$PORT" ]] && continue

    # Buscar subdominios que resuelven a esa IP
    local SUBS_FOR_IP
    SUBS_FOR_IP=$(grep "^${IP}|" "$IP_MAP" | cut -d'|' -f2)

    if [[ -n "$SUBS_FOR_IP" ]]; then
      while IFS= read -r SUB; do
        echo "https://${SUB}:${PORT}" >> "$HTTPX_TARGETS"
        echo "http://${SUB}:${PORT}"  >> "$HTTPX_TARGETS"
      done <<< "$SUBS_FOR_IP"
    else
      # Si no hay subdominio conocido, usar la IP directamente
      echo "https://${IP}:${PORT}" >> "$HTTPX_TARGETS"
      echo "http://${IP}:${PORT}"  >> "$HTTPX_TARGETS"
    fi
  done < "$OPEN_PORTS"

  sort -u "$HTTPX_TARGETS" -o "$HTTPX_TARGETS"

  # ── httpx verifica cuáles tienen web real ─────────────────
  log_info "Verificando servicios web con httpx..."
  local HTTPX_OUT="$OUT_DIR/.httpx_ports_result.json"

  # Cargar proxy si está activo
  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  proxy_check
  local HTTPX_PROXY=""
  $PROXY_ACTIVE && HTTPX_PROXY="-http-proxy ${PROXY_URL}"

  "${HTTPX_BIN:-httpx}" \
    -l "$HTTPX_TARGETS" \
    -silent \
    -json \
    -status-code \
    -title \
    -tech-detect \
    -ip \
    -threads 30 \
    -timeout 10 \
    ${HTTPX_PROXY} \
    -o "$HTTPX_OUT" \
    2>/dev/null || true

  if [[ ! -s "$HTTPX_OUT" ]]; then
    log_info "httpx: ningún servicio web respondió en puertos alternativos"
    rm -f "$IP_MAP" "$IP_LIST" "$MASSCAN_OUT" "$OPEN_PORTS" "$HTTPX_TARGETS"
    return
  fi

  # ── Procesar y guardar en DB ──────────────────────────────
  local NEW_SERVICES=0

  while IFS= read -r LINE; do
    [[ -z "$LINE" ]] && continue

    local SERVICE_URL IP_ADDR HTTP_STATUS TITLE TECH PORT_NUM SUB
    SERVICE_URL=$(echo "$LINE" | jq -r '.url // ""')
    IP_ADDR=$(echo "$LINE"    | jq -r '.host // ""')
    HTTP_STATUS=$(echo "$LINE" | jq -r '.status_code // 0')
    TITLE=$(echo "$LINE"      | jq -r '.title // ""' | tr -d "'")
    TECH=$(echo "$LINE"       | jq -r '[.technologies[]?.name] | join(", ")' 2>/dev/null || echo "")

    [[ -z "$SERVICE_URL" ]] && continue

    # Extraer puerto y subdominio de la URL
    PORT_NUM=$(echo "$SERVICE_URL" | grep -oP ':\d+' | tr -d ':' | head -1)
    SUB=$(echo "$SERVICE_URL" | sed 's|https\?://||;s|:.*||')
    [[ -z "$PORT_NUM" ]] && continue

    # Verificar si ya existía
    local BEFORE
    BEFORE=$(sqlite3 "$DB_PATH" \
      "SELECT COUNT(*) FROM port_findings
       WHERE domain_id=${DOMAIN_ID} AND subdomain='${SUB//\'/\'\'}' AND port=${PORT_NUM};" 2>/dev/null || echo "1")

    sqlite3 "$DB_PATH" \
      "INSERT OR IGNORE INTO port_findings
       (domain_id,subdomain,ip,port,service_url,http_status,http_title,tech,added_to_pipeline)
       VALUES(${DOMAIN_ID},'${SUB//\'/\'\'}','${IP_ADDR}',${PORT_NUM},
              '${SERVICE_URL//\'/\'\'}',${HTTP_STATUS},'${TITLE//\'/\'\'}','${TECH//\'/\'\'}',0);" \
      2>/dev/null || true

    if [[ "${BEFORE:-0}" == "0" ]]; then
      ((NEW_SERVICES++))
      log_warn "🌐 Nuevo servicio web: $SERVICE_URL (HTTP $HTTP_STATUS) ${TITLE:+— $TITLE}"

      # ── Añadir a la rueda de scan ───────────────────────
      # 1. Como subdominio con puerto en la tabla urls
      db_add_url "$DOMAIN_ID" "$SERVICE_URL" "port_scan" "$HTTP_STATUS"

      # 2. Guardar tech si se detectó
      if [[ -n "$TECH" ]]; then
        db_upsert_tech "$DOMAIN_ID" "$SERVICE_URL" "$SUB" \
          "$(echo "$TECH" | cut -d',' -f1)" "" "" "80" "httpx" 2>/dev/null || true
      fi

      # 3. Notificar por Telegram
      _telegram_send "🌐 *Servicio web en puerto no estándar*
🎯 \`${SUB}\`
🔗 \`${SERVICE_URL}\`
🔌 Puerto: \`${PORT_NUM}\`
📊 HTTP: \`${HTTP_STATUS}\`
${TITLE:+📄 Título: ${TITLE}}
${TECH:+🛠️ Tech: ${TECH}}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

      db_add_finding "$DOMAIN_ID" "port_scan" "info" \
        "$SERVICE_URL" "port:${PORT_NUM}" "${TITLE:-sin título}"
    fi

  done < "$HTTPX_OUT"

  # Marcar como añadidos al pipeline
  sqlite3 "$DB_PATH" \
    "UPDATE port_findings SET added_to_pipeline=1
     WHERE domain_id=${DOMAIN_ID} AND added_to_pipeline=0;" 2>/dev/null || true

  rm -f "$IP_MAP" "$IP_LIST" "$MASSCAN_OUT" "$OPEN_PORTS" "$HTTPX_TARGETS" "$HTTPX_OUT"

  if [[ "$NEW_SERVICES" -gt 0 ]]; then
    _telegram_send "🔌 *Port Scan — Resumen*
🌐 \`${DOMAIN}\`
🆕 Nuevos servicios web: ${NEW_SERVICES}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi

  log_ok "$MODULE_DESC completado: $NEW_SERVICES nuevos servicios web en puertos alternativos"
}
