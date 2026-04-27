#!/usr/bin/env bash
# ============================================================
#  modules/15_param_discovery.sh
#  Fase 15: Descubrimiento de parámetros ocultos
#
#  Herramientas:
#    - paramspider: extrae params de Wayback Machine por dominio
#    - arjun: fuzzing activo de parámetros en cada URL
#
#  Los parámetros nuevos entran en la rueda:
#    → nuclei con templates de sqli/xss/ssrf/idor/lfi
#    → guardados en url_params para análisis manual
# ============================================================

MODULE_NAME="param_discovery"
MODULE_DESC="Descubrimiento de parámetros ocultos (paramspider + arjun)"

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 15 — $MODULE_DESC: $DOMAIN"

  local URLS_RAW="$OUT_DIR/urls_raw.txt"
  local ALIVE="$OUT_DIR/subs_alive.txt"
  local PARAMS_OUT="$OUT_DIR/params_found.txt"
  > "$PARAMS_OUT"

  # Proxy
  source "$(dirname "$0")/../core/proxy.sh" 2>/dev/null || true
  proxy_check

  local TOTAL_PARAMS=0
  local NEW_PARAMS=0

  # ── 1. ParamSpider — extrae params de Wayback/CommonCrawl ─
  if command -v paramspider &>/dev/null; then
    log_info "paramspider sobre $DOMAIN..."
    local PS_OUT="$OUT_DIR/.paramspider_out"
    mkdir -p "$PS_OUT"

    paramspider \
      -d "$DOMAIN" \
      -o "$PS_OUT/params.txt" \
      --quiet \
      2>/dev/null || true

    # También sobre subdominios si paramspider soporta -l
    if [[ -s "$ALIVE" ]]; then
      paramspider \
        -l "$ALIVE" \
        -o "$PS_OUT/params_subs.txt" \
        --quiet \
        2>/dev/null || true
    fi

    cat "$PS_OUT"/*.txt 2>/dev/null | sort -u >> "$PARAMS_OUT"
    rm -rf "$PS_OUT"
    log_info "paramspider: $(wc -l < "$PARAMS_OUT" | tr -d ' ') URLs con params"
  else
    log_warn "paramspider no encontrado — instala: pip3 install paramspider"
  fi

  # ── 2. URLs con params del crawler previo ─────────────────
  if [[ -s "$URLS_RAW" ]]; then
    grep -P '\?' "$URLS_RAW" >> "$PARAMS_OUT" 2>/dev/null || true
    sort -u "$PARAMS_OUT" -o "$PARAMS_OUT"
  fi

  # ── 3. Arjun — fuzzing activo de params ocultos ───────────
  if command -v arjun &>/dev/null && [[ -s "$ALIVE" ]]; then
    log_info "arjun fuzzing activo sobre subdominios alive..."
    local ARJUN_OUT="$OUT_DIR/.arjun_results.json"
    local ARJUN_TARGETS="$OUT_DIR/.arjun_targets.txt"

    # Targets: raíces de subdominios + rutas con params ya conocidos
    sed 's|^|https://|' "$ALIVE" > "$ARJUN_TARGETS"

    local ARJUN_PROXY=""
    $PROXY_ACTIVE && ARJUN_PROXY="--proxy $PROXY_URL"

    arjun \
      -i "$ARJUN_TARGETS" \
      -oJ "$ARJUN_OUT" \
      --stable \
      -t 5 \
      ${ARJUN_PROXY} \
      2>/dev/null || true

    # Extraer URLs con params encontrados por arjun
    if [[ -s "$ARJUN_OUT" ]] && command -v jq &>/dev/null; then
      jq -r 'to_entries[] | .key + "?" + (.value | join("=FUZZ&")) + "=FUZZ"' \
        "$ARJUN_OUT" 2>/dev/null >> "$PARAMS_OUT" || true
    fi
    rm -f "$ARJUN_OUT" "$ARJUN_TARGETS"
  else
    log_warn "arjun no encontrado — instala: pip3 install arjun"
  fi

  sort -u "$PARAMS_OUT" -o "$PARAMS_OUT"
  TOTAL_PARAMS=$(wc -l < "$PARAMS_OUT" | tr -d ' ')
  log_info "$TOTAL_PARAMS URLs con parámetros encontradas"

  # ── 4. Guardar en DB y añadir a la rueda ──────────────────
  while IFS= read -r PARAM_URL; do
    [[ -z "$PARAM_URL" ]] && continue

    # Extraer base URL y nombre de params
    local BASE="${PARAM_URL%%\?*}"
    local QUERY="${PARAM_URL#*\?}"

    # Guardar cada param individualmente
    echo "$QUERY" | tr '&' '\n' | while IFS='=' read -r PNAME _; do
      [[ -z "$PNAME" ]] && continue
      local PNAME_CLEAN="${PNAME// /}"

      local BEFORE
      BEFORE=$(sqlite3 "$DB_PATH" \
        "SELECT COUNT(*) FROM url_params
         WHERE domain_id=${DOMAIN_ID} AND url='${BASE//\'/\'\'}' AND param_name='${PNAME_CLEAN//\'/\'\'}';" \
        2>/dev/null || echo "1")

      sqlite3 "$DB_PATH" \
        "INSERT OR IGNORE INTO url_params(domain_id,url,param_name,source)
         VALUES(${DOMAIN_ID},'${BASE//\'/\'\'}','${PNAME_CLEAN//\'/\'\'}','param_discovery');" \
        2>/dev/null || true

      [[ "${BEFORE:-1}" == "0" ]] && ((NEW_PARAMS++))
    done

    # Añadir URL completa a la rueda de URLs para nuclei
    db_add_url "$DOMAIN_ID" "$PARAM_URL" "param_discovery" ""

  done < "$PARAMS_OUT"

  # ── 5. Notificar si hay params interesantes ───────────────
  # Params de alta relevancia para vulns
  local JUICY_PARAMS
  JUICY_PARAMS=$(grep -ioP '[?&](url|redirect|next|dest|target|path|file|page|include|
    src|href|link|load|fetch|request|uri|site|html|data|ref|return|callback|
    id|user|uid|account|admin|token|key|api|secret|pass|pwd|auth|session|
    cmd|exec|command|query|search|q|input|debug|test|env)\b' \
    "$PARAMS_OUT" 2>/dev/null \
    | sed 's/[?&]//' | sort -u | tr '\n' ', ' | sed 's/,$//')

  if [[ -n "$JUICY_PARAMS" ]]; then
    log_warn "🎯 Parámetros jugosos detectados: $JUICY_PARAMS"
    _telegram_send "🎯 *Parámetros interesantes encontrados*
🌐 \`${DOMAIN}\`
📊 Total URLs con params: \`${TOTAL_PARAMS}\`
🆕 Parámetros nuevos: \`${NEW_PARAMS}\`
⚡ Jugosos: \`${JUICY_PARAMS:0:300}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi

  log_ok "$MODULE_DESC completado: $TOTAL_PARAMS URLs, $NEW_PARAMS params nuevos"
}
