#!/usr/bin/env bash
# ============================================================
#  modules/10_tech_fingerprint.sh
#  Fase 10: Fingerprinting de tecnologías y versiones
#
#  Estrategia en capas:
#    1. webanalyze  (Wappalyzer rules en Go, más rápido)
#    2. httpx -tech-detect (fallback si no hay webanalyze)
#    3. whatweb     (fallback adicional con versiones)
#
#  Se ejecuta sobre CADA URL/directorio descubierto, no solo
#  sobre subdominios raíz — así capturamos tech distinta
#  en paths como /wp-admin, /api/v2, /phpmyadmin, etc.
# ============================================================

MODULE_NAME="tech_fingerprint"
MODULE_DESC="Fingerprinting de tecnologías y versiones"

# ── Instalar webanalyze si no está ────────────────────────────
_ensure_webanalyze() {
  if command -v webanalyze &>/dev/null; then return 0; fi
  log_info "Instalando webanalyze (Wappalyzer para CLI)..."
  go install github.com/rverton/webanalyze/cmd/webanalyze@latest 2>/dev/null \
    && log_ok "webanalyze instalado" \
    || { log_warn "webanalyze: fallo en instalación"; return 1; }
}

# Descarga/actualiza las reglas de Wappalyzer
_update_wappalyzer_rules() {
  local RULES_DIR="$HOME/.webanalyze"
  mkdir -p "$RULES_DIR"
  local RULES="$RULES_DIR/technologies.json"

  # Actualizar si tiene más de 7 días o no existe
  if [[ ! -f "$RULES" ]] || find "$RULES" -mtime +7 | grep -q .; then
    log_info "Actualizando reglas Wappalyzer..."
    curl -sL "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/a.json" \
      -o "$RULES_DIR/tech_a.json" 2>/dev/null || true
    # webanalyze descarga automáticamente si no encuentra el archivo
    webanalyze -update 2>/dev/null || true
  fi
}

# ── Parser de salida webanalyze ───────────────────────────────
# Formato: URL  TechName Version  Category
_parse_webanalyze() {
  local LINE="$1"
  local DOMAIN_ID="$2"

  # webanalyze -output csv: url,tech,version,category,confidence
  IFS=',' read -r URL TECH VERSION CATEGORY CONFIDENCE <<< "$LINE"
  [[ -z "$URL" || -z "$TECH" ]] && return

  # Limpiar espacios
  URL="${URL// /}"; TECH="${TECH// /}"; VERSION="${VERSION// /}"
  CATEGORY="${CATEGORY// /}"; CONFIDENCE="${CONFIDENCE// /}"

  local SUBDOMAIN
  SUBDOMAIN=$(echo "$URL" | sed 's|https\?://||;s|/.*||')

  db_upsert_tech "$DOMAIN_ID" "$URL" "$SUBDOMAIN" \
    "$TECH" "$VERSION" "$CATEGORY" "${CONFIDENCE:-100}" "wappalyzer"
}

# ── Parser de salida httpx -json ──────────────────────────────
_parse_httpx_tech() {
  local JSON_LINE="$1"
  local DOMAIN_ID="$2"

  local URL TECHS
  URL=$(echo "$JSON_LINE" | jq -r '.url // ""')
  [[ -z "$URL" ]] && return

  local SUBDOMAIN
  SUBDOMAIN=$(echo "$URL" | sed 's|https\?://||;s|/.*||')

  # httpx devuelve: {"technologies": [{"name":"nginx","version":"1.18"},...]}
  echo "$JSON_LINE" | jq -c '.technologies[]? // empty' 2>/dev/null | while IFS= read -r T; do
    local TNAME TVER TCAT
    TNAME=$(echo "$T" | jq -r '.name // ""')
    TVER=$(echo "$T"  | jq -r '.version // ""')
    TCAT=$(echo "$T"  | jq -r '.category // ""')
    [[ -z "$TNAME" ]] && continue
    db_upsert_tech "$DOMAIN_ID" "$URL" "$SUBDOMAIN" \
      "$TNAME" "$TVER" "$TCAT" "80" "httpx"
  done
}

# ── Parser de salida whatweb -json ────────────────────────────
_parse_whatweb() {
  local JSON_LINE="$1"
  local DOMAIN_ID="$2"

  local TARGET
  TARGET=$(echo "$JSON_LINE" | jq -r '.target // ""')
  [[ -z "$TARGET" ]] && return

  local SUBDOMAIN
  SUBDOMAIN=$(echo "$TARGET" | sed 's|https\?://||;s|/.*||')

  echo "$JSON_LINE" | jq -r '.plugins | to_entries[] | "\(.key)|\(.value.version[0] // "")"' \
    2>/dev/null | while IFS='|' read -r TNAME TVER; do
    [[ -z "$TNAME" ]] && continue
    db_upsert_tech "$DOMAIN_ID" "$TARGET" "$SUBDOMAIN" \
      "$TNAME" "$TVER" "" "70" "whatweb"
  done
}

# ── Función principal ─────────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 10 — $MODULE_DESC: $DOMAIN"

  local ALIVE="$OUT_DIR/subs_alive.txt"
  local URLS_RAW="$OUT_DIR/urls_raw.txt"

  if [[ ! -s "$ALIVE" ]]; then
    log_warn "Sin subdominios alive, saltando"
    return
  fi

  # Construir lista de targets: subdominios + URLs únicas por subdominio
  # (no lanzamos sobre TODAS las urls, solo una muestra representativa por path depth)
  local TARGETS="$OUT_DIR/.tech_targets.txt"
  > "$TARGETS"

  # 1. Subdominios raíz (https://sub.domain.com)
  sed 's|^|https://|' "$ALIVE" >> "$TARGETS"

  # 2. URLs con paths únicos (máximo 3 niveles, deduplicadas por "directorio base")
  if [[ -s "$URLS_RAW" ]]; then
    # Extraer paths únicos hasta el 2º nivel: /a/b/... → /a/b
    grep -oP 'https?://[^/]+(/[^/?#]+){1,2}' "$URLS_RAW" 2>/dev/null \
      | sort -u \
      | head -500 \
      >> "$TARGETS" || true
  fi

  sort -u "$TARGETS" -o "$TARGETS"
  local TARGET_COUNT
  TARGET_COUNT=$(wc -l < "$TARGETS" | tr -d ' ')
  log_info "Analizando tecnologías en $TARGET_COUNT targets..."

  local TECH_OUT="$OUT_DIR/tech_results.csv"
  > "$TECH_OUT"
  local TOTAL_FOUND=0

  # ── Capa 1: webanalyze (Wappalyzer) ──────────────────────
  if _ensure_webanalyze 2>/dev/null; then
    _update_wappalyzer_rules
    log_info "Ejecutando webanalyze (Wappalyzer)..."
    local WA_OUT="$OUT_DIR/.webanalyze_raw.csv"

    webanalyze \
      -hosts "$TARGETS" \
      -output csv \
      -workers 20 \
      -crawl 0 \
      2>/dev/null \
    > "$WA_OUT" || true

    if [[ -s "$WA_OUT" ]]; then
      local WA_COUNT=0
      while IFS= read -r LINE; do
        [[ -z "$LINE" || "$LINE" == url* ]] && continue  # saltar header
        _parse_webanalyze "$LINE" "$DOMAIN_ID"
        echo "$LINE" >> "$TECH_OUT"
        ((WA_COUNT++))
      done < "$WA_OUT"
      log_ok "webanalyze: $WA_COUNT entradas de tecnología"
      ((TOTAL_FOUND += WA_COUNT))
      rm -f "$WA_OUT"
    fi
  else
    log_warn "webanalyze no disponible"
  fi

  # ── Capa 2: httpx -tech-detect (complementa con versiones HTTP) ──
  if command -v "${HTTPX_BIN:-httpx}" &>/dev/null; then
    log_info "httpx tech-detect como capa adicional..."
    local HX_OUT="$OUT_DIR/.httpx_tech.json"

    "${HTTPX_BIN:-httpx}" \
      -l "$TARGETS" \
      -tech-detect \
      -json \
      -silent \
      -threads 30 \
      -o "$HX_OUT" \
      2>/dev/null || true

    if [[ -s "$HX_OUT" ]]; then
      local HX_COUNT=0
      while IFS= read -r LINE; do
        _parse_httpx_tech "$LINE" "$DOMAIN_ID"
        ((HX_COUNT++))
      done < "$HX_OUT"
      log_ok "httpx tech-detect: $HX_COUNT URLs procesadas"
      rm -f "$HX_OUT"
    fi
  fi

  # ── Capa 3: whatweb (para versiones específicas) ──────────
  if command -v whatweb &>/dev/null; then
    log_info "whatweb para detección de versiones..."
    local WW_OUT="$OUT_DIR/.whatweb_tech.json"

    # Solo sobre subdominios raíz (whatweb es más lento)
    while IFS= read -r SUB; do
      [[ -z "$SUB" ]] && continue
      whatweb \
        --aggression 1 \
        --quiet \
        --log-json=/dev/stdout \
        "https://${SUB}" \
        2>/dev/null
    done < "$ALIVE" > "$WW_OUT" || true

    if [[ -s "$WW_OUT" ]]; then
      while IFS= read -r LINE; do
        [[ -z "$LINE" ]] && continue
        _parse_whatweb "$LINE" "$DOMAIN_ID"
      done < "$WW_OUT"
      log_ok "whatweb: versiones extraídas"
      rm -f "$WW_OUT"
    fi
  fi

  # ── Resumen en log ────────────────────────────────────────
  TOTAL_FOUND=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(DISTINCT tech_name||url) FROM technologies WHERE domain_id=${DOMAIN_ID};" 2>/dev/null || echo "?")

  local TOP_TECHS
  TOP_TECHS=$(sqlite3 "$DB_PATH" \
    "SELECT tech_name || COALESCE(' ' || tech_version, '') || ' (' || COUNT(*) || ')'
     FROM technologies WHERE domain_id=${DOMAIN_ID}
     GROUP BY tech_name, tech_version ORDER BY COUNT(*) DESC LIMIT 5;" \
    2>/dev/null | paste -sd ', ' || echo "")

  log_ok "$MODULE_DESC completado: $TOTAL_FOUND detecciones"
  [[ -n "$TOP_TECHS" ]] && log_info "Top techs: $TOP_TECHS"

  rm -f "$TARGETS"
}
