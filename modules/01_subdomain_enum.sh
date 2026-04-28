#!/usr/bin/env bash
# ============================================================
#  modules/01_subdomain_enum.sh
#  Fase 1: Descubrimiento de subdominios
#  Herramientas: subfinder, amass, bbot, assetfinder, findomain
# ============================================================
# API pública del módulo:
#   module_run <domain> <domain_id> <output_dir>
#   Escribe en: <output_dir>/subs_raw.txt  (un subdominio por línea)
# ============================================================

MODULE_NAME="subdomain_enum"
MODULE_DESC="Enumeración de subdominios"

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  local RAW="$OUT_DIR/subs_raw.txt"
  local TMP="$OUT_DIR/.tmp_subs"
  mkdir -p "$TMP"
  > "$RAW"

  log_phase "Módulo 01 — $MODULE_DESC: $DOMAIN"

  # ── subfinder ──────────────────────────────────────────────
  if command -v "${SUBFINDER_BIN:-subfinder}" &>/dev/null; then
    log_info "subfinder..."
    "${SUBFINDER_BIN:-subfinder}" -d "$DOMAIN" -silent \
      -o "$TMP/subfinder.txt" 2>/dev/null \
      || log_warn "subfinder: error o sin resultados"
  else
    log_warn "subfinder no encontrado, saltando"
  fi

  # ── assetfinder ────────────────────────────────────────────
  if command -v assetfinder &>/dev/null; then
    log_info "assetfinder..."
    assetfinder --subs-only "$DOMAIN" \
      > "$TMP/assetfinder.txt" 2>/dev/null \
      || log_warn "assetfinder: error o sin resultados"
  else
    log_warn "assetfinder no encontrado, saltando"
  fi

  # ── amass (modo pasivo, rápido) ────────────────────────────
  if command -v "${AMASS_BIN:-amass}" &>/dev/null; then
    log_info "amass (modo pasivo)..."
    "${AMASS_BIN:-amass}" enum -passive -d "$DOMAIN" \
      -o "$TMP/amass.txt" 2>/dev/null \
      || log_warn "amass: error o sin resultados"
  else
    log_warn "amass no encontrado, saltando"
  fi

  # ── findomain ──────────────────────────────────────────────
  if command -v findomain &>/dev/null; then
    log_info "findomain..."
    findomain -t "$DOMAIN" -q \
      > "$TMP/findomain.txt" 2>/dev/null \
      || log_warn "findomain: error o sin resultados"
  else
    log_warn "findomain no encontrado, saltando"
  fi

  # ── bbot ───────────────────────────────────────────────────
  if command -v "${BBOT_BIN:-bbot}" &>/dev/null; then
    log_info "bbot (subdomain scan)..."
    "${BBOT_BIN:-bbot}" -t "$DOMAIN" \
      -m subdomain-enum \
      -o "$TMP/bbot_out" \
      --silent 2>/dev/null \
    && grep -oP '[\w\.-]+\.'"${DOMAIN//./\\.}" \
         "$TMP/bbot_out/output.txt" 2>/dev/null \
       > "$TMP/bbot.txt" \
    || log_warn "bbot: error o sin resultados"
  else
    log_warn "bbot no encontrado, saltando"
  fi

  # ── Merge y deduplicar ─────────────────────────────────────
  log_info "Consolidando resultados..."
  cat "$TMP"/*.txt 2>/dev/null \
    | grep -v "^$" \
    | grep -iE "^[a-z0-9._-]+\\.${DOMAIN//./\\.}$" \
    | sort -u \
    > "$RAW"

  local COUNT
  COUNT=$(wc -l < "$RAW" | tr -d ' ')
  log_ok "$MODULE_DESC completado: $COUNT subdominios únicos encontrados"

  # Limpiar temporales
  rm -rf "$TMP"

  # Exportar para el pipeline
  echo "$COUNT"
}
