#!/usr/bin/env bash
# ============================================================
#  modules/18_asn_discovery.sh
#  Fase 18: Descubrimiento de rangos IP por ASN
#
#  Técnica usada por Jhaddix: encontrar todos los activos
#  de una empresa buscando sus rangos de IP en BGP,
#  independientemente de si tienen DNS o no.
#
#  Herramientas:
#    - asnmap: resolución dominio → ASN → CIDRs
#    - BGP.he.net / BGPVIEW API como fuente
#    - masscan sobre los CIDRs para puertos web
# ============================================================

MODULE_NAME="asn_discovery"
MODULE_DESC="Descubrimiento de rangos IP por ASN"

# ── Buscar ASN por dominio via BGPView API ────────────────────
_lookup_asn_bgpview() {
  local DOMAIN="$1"

  # Resolver IP del dominio
  local IP
  IP=$(dig +short "$DOMAIN" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
  [[ -z "$IP" ]] && return

  # Buscar ASN por IP
  local ASN_DATA
  ASN_DATA=$(curl -s --max-time 10 \
    "https://api.bgpview.io/ip/${IP}" 2>/dev/null)

  echo "$ASN_DATA" | jq -r '
    .data.prefixes[]? |
    "\(.asn.asn)|\(.asn.name // "unknown")|\(.prefix)|\(.country_code // "")"
  ' 2>/dev/null || true
}

# ── Buscar más CIDRs del mismo ASN ────────────────────────────
_get_asn_prefixes() {
  local ASN="$1"

  curl -s --max-time 15 \
    "https://api.bgpview.io/asn/${ASN}/prefixes" 2>/dev/null \
  | jq -r '.data.ipv4_prefixes[]? | "\(.prefix)|\(.name // "")"' 2>/dev/null || true
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 18 — $MODULE_DESC: $DOMAIN"

  local NEW_RANGES=0
  local ALL_CIDRS="$OUT_DIR/asn_cidrs.txt"
  > "$ALL_CIDRS"

  # ── asnmap si está disponible ──────────────────────────────
  if command -v asnmap &>/dev/null; then
    log_info "asnmap sobre $DOMAIN..."
    asnmap -d "$DOMAIN" -silent 2>/dev/null \
      > "$OUT_DIR/.asnmap_out.txt" || true

    if [[ -s "$OUT_DIR/.asnmap_out.txt" ]]; then
      cat "$OUT_DIR/.asnmap_out.txt" >> "$ALL_CIDRS"
      log_info "asnmap: $(wc -l < "$OUT_DIR/.asnmap_out.txt" | tr -d ' ') CIDRs encontrados"
    fi
    rm -f "$OUT_DIR/.asnmap_out.txt"
  else
    log_warn "asnmap no encontrado — usando BGPView API"
  fi

  # ── BGPView API como fuente adicional ──────────────────────
  log_info "Consultando BGPView API para $DOMAIN..."
  local ASN_INFO
  ASN_INFO=$(_lookup_asn_bgpview "$DOMAIN")

  if [[ -n "$ASN_INFO" ]]; then
    local ASNS_FOUND=()

    while IFS='|' read -r ASN ORG CIDR COUNTRY; do
      [[ -z "$ASN" || -z "$CIDR" ]] && continue

      # Evitar rangos muy grandes (>65536 IPs — /16 o menor)
      local PREFIX_LEN
      PREFIX_LEN=$(echo "$CIDR" | cut -d'/' -f2)
      [[ "${PREFIX_LEN:-0}" -lt 16 ]] && \
        log_warn "CIDR muy grande ($CIDR) — saltando para no sobresaturar" && continue

      echo "$CIDR" >> "$ALL_CIDRS"

      local BEFORE
      BEFORE=$(sqlite3 "$DB_PATH" \
        "SELECT COUNT(*) FROM asn_ranges WHERE domain_id=${DOMAIN_ID} AND cidr='${CIDR//\'/\'\'}';" \
        2>/dev/null || echo "1")

      sqlite3 "$DB_PATH" \
        "INSERT OR IGNORE INTO asn_ranges(domain_id,asn,org,cidr,country)
         VALUES(${DOMAIN_ID},'AS${ASN}','${ORG//\'/\'\'}','${CIDR}','${COUNTRY}');" \
        2>/dev/null || true

      if [[ "${BEFORE:-1}" == "0" ]]; then
        ((NEW_RANGES++))
        log_info "  AS${ASN} (${ORG}): $CIDR [$COUNTRY]"
      fi

      # Guardar ASN único para buscar más prefixes
      [[ ! " ${ASNS_FOUND[*]} " =~ " ${ASN} " ]] && ASNS_FOUND+=("$ASN")

    done <<< "$ASN_INFO"

    # Buscar todos los prefixes de cada ASN encontrado
    for ASN in "${ASNS_FOUND[@]}"; do
      log_info "Buscando todos los prefixes de AS${ASN}..."
      sleep 1  # rate limit BGPView

      _get_asn_prefixes "$ASN" | while IFS='|' read -r CIDR NAME; do
        [[ -z "$CIDR" ]] && continue

        local PREFIX_LEN
        PREFIX_LEN=$(echo "$CIDR" | cut -d'/' -f2)
        [[ "${PREFIX_LEN:-0}" -lt 16 ]] && continue

        echo "$CIDR" >> "$ALL_CIDRS"
        sqlite3 "$DB_PATH" \
          "INSERT OR IGNORE INTO asn_ranges(domain_id,asn,org,cidr)
           VALUES(${DOMAIN_ID},'AS${ASN}','${NAME//\'/\'\'}','${CIDR}');" \
          2>/dev/null || true
      done
    done
  fi

  sort -u "$ALL_CIDRS" -o "$ALL_CIDRS"
  local TOTAL_CIDRS
  TOTAL_CIDRS=$(wc -l < "$ALL_CIDRS" | tr -d ' ')

  if [[ "$TOTAL_CIDRS" -eq 0 ]]; then
    log_info "No se encontraron rangos ASN para $DOMAIN"
    return
  fi

  log_info "$TOTAL_CIDRS CIDRs únicos — lanzando masscan sobre puertos web..."

  # ── masscan sobre los CIDRs descubiertos ──────────────────
  if command -v masscan &>/dev/null && [[ -s "$ALL_CIDRS" ]]; then
    local MASSCAN_ASN_OUT="$OUT_DIR/masscan_asn.json"
    local RATE="${MASSCAN_RATE:-500}"  # más conservador sobre rangos grandes

    local SUDO=""
    [[ "$(id -u)" -ne 0 ]] && SUDO="sudo"

    $SUDO masscan \
      -iL "$ALL_CIDRS" \
      -p "80,443,8080,8443,8888,3000,8000,9090,5000" \
      --rate "$RATE" \
      --open \
      -oJ "$MASSCAN_ASN_OUT" \
      --exclude 255.255.255.255 \
      2>/dev/null || log_warn "masscan sobre ASN falló"

    if [[ -s "$MASSCAN_ASN_OUT" ]]; then
      local ASN_HOSTS
      ASN_HOSTS=$(python3 -c "
import json, sys
try:
    raw = open('${MASSCAN_ASN_OUT}').read().rstrip(',\n ]') + ']'
    data = json.loads(raw)
    for e in data:
        for p in e.get('ports',[]):
            print(f\"{e['ip']}:{p['port']}\")
except: pass" 2>/dev/null | wc -l | tr -d ' ')

      log_info "masscan ASN: $ASN_HOSTS hosts con puertos web abiertos"

      # Pasar por httpx para verificar web real
      python3 -c "
import json, sys
try:
    raw = open('${MASSCAN_ASN_OUT}').read().rstrip(',\n ]') + ']'
    data = json.loads(raw)
    for e in data:
        for p in e.get('ports',[]):
            print(f\"http://{e['ip']}:{p['port']}\")
            print(f\"https://{e['ip']}:{p['port']}\")
except: pass" 2>/dev/null \
      | sort -u \
      | "${HTTPX_BIN:-httpx}" \
          -silent -status-code -title -json \
          -threads 30 -timeout 8 \
          -o "$OUT_DIR/asn_web_services.json" \
          2>/dev/null || true

      if [[ -s "$OUT_DIR/asn_web_services.json" ]]; then
        local WEB_COUNT
        WEB_COUNT=$(wc -l < "$OUT_DIR/asn_web_services.json" | tr -d ' ')
        log_warn "🌐 $WEB_COUNT servicios web en rangos ASN de $DOMAIN"

        _telegram_send "🌐 *ASN Discovery — Servicios web*
🌐 \`${DOMAIN}\`
📊 CIDRs escaneados: ${TOTAL_CIDRS}
🔌 Servicios web encontrados: ${WEB_COUNT}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true

        # Añadir a la DB de URLs
        jq -r '.url' "$OUT_DIR/asn_web_services.json" 2>/dev/null | \
          while IFS= read -r URL; do
            [[ -z "$URL" ]] && continue
            db_add_url "$DOMAIN_ID" "$URL" "asn_scan" ""
          done
      fi
      rm -f "$MASSCAN_ASN_OUT"
    fi
  fi

  if [[ "$NEW_RANGES" -gt 0 ]]; then
    _telegram_send "🗺️ *ASN Discovery*
🌐 \`${DOMAIN}\`
📊 Rangos IP nuevos: \`${NEW_RANGES}\`
🔢 CIDRs totales: \`${TOTAL_CIDRS}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi

  log_ok "$MODULE_DESC completado: $NEW_RANGES rangos nuevos, $TOTAL_CIDRS CIDRs totales"
}
