#!/usr/bin/env bash
# ============================================================
#  modules/01_subdomain_enum.sh
#  Fase 1: Descubrimiento de subdominios
#  Herramientas: subfinder, amass, bbot, assetfinder, findomain
#                + DNS brute-force + mutaciones por nomenclatura
# ============================================================
# API pública del módulo:
#   module_run <domain> <domain_id> <output_dir>
#   Escribe en: <output_dir>/subs_raw.txt  (un subdominio por línea)
#
# Variables de entorno opcionales:
#   SUBDOMAIN_ENUM_DEPTH=3        — rondas recursivas (0 = solo raíz)
#   SUBDOMAIN_ENUM_PARALLEL=20    — jobs concurrentes por ronda
#   SUBDOMAIN_WORDLIST=path       — wordlist para brute-force
#   SUBDOMAIN_BRUTE_MAX_DEPTH=3   — profundidad máxima del subdominio sobre el
#                                   que se hace bruteforce (sub1.sub2.sub3.dom.tld
#                                   = depth 3). Por encima, solo se aceptan
#                                   subs descubiertos pasivamente, sin generar
#                                   nuevos niveles via wordlist.
#   BBOT_TIMEOUT=600              — timeout bbot en segundos
# ============================================================

MODULE_NAME="subdomain_enum"
MODULE_DESC="Enumeración de subdominios"

# ── Comprueba si un hostname resuelve DNS ──────────────────
_resolves() {
  ${PROXYCHAINS_CMD:-} dig +short +timeout=3 +tries=1 "$1" 2>/dev/null | grep -qE '[0-9a-fA-F:.]'
}

# ── Cuenta niveles de subdomain bajo el dominio raíz ────────
# foo.bar.example.com con root example.com → 2
# example.com con root example.com → 0
_subdomain_depth() {
  local TARGET="$1" ROOT="$2"
  # Ya es el root o no termina en él → depth 0 (no aplica)
  [[ "$TARGET" == "$ROOT" ]] && { echo 0; return; }
  [[ "$TARGET" != *".${ROOT}" ]] && { echo 0; return; }
  local PREFIX="${TARGET%.${ROOT}}"
  # Cuenta segmentos del prefix: separadores '.' + 1
  local DOTS="${PREFIX//[^.]/}"
  echo $(( ${#DOTS} + 1 ))
}

# ── Resolver una lista de candidatos → solo los que tienen DNS
# Usa dnsx si disponible (miles/seg), luego puredns, luego dig paralelo.
_resolve_list() {
  local INPUT="$1"
  local OUTPUT="$2"
  local ROOT_DOMAIN="$3"
  local SAFE_PAT
  SAFE_PAT=$(echo "$ROOT_DOMAIN" | sed 's/\./\\./g')

  [[ ! -s "$INPUT" ]] && return 0

  if command -v dnsx &>/dev/null; then
    ${PROXYCHAINS_CMD:-} dnsx -l "$INPUT" -silent 2>/dev/null \
      | grep -iE "^[a-z0-9._-]+\.${SAFE_PAT}$" >> "$OUTPUT" || true
  elif command -v puredns &>/dev/null; then
    ${PROXYCHAINS_CMD:-} puredns resolve "$INPUT" -q 2>/dev/null \
      | grep -iE "^[a-z0-9._-]+\.${SAFE_PAT}$" >> "$OUTPUT" || true
  else
    local JOBS=0
    while IFS= read -r CAND; do
      [[ -z "$CAND" ]] && continue
      ( _resolves "$CAND" && echo "$CAND" >> "$OUTPUT" ) &
      JOBS=$(( JOBS + 1 ))
      if [[ $JOBS -ge 50 ]]; then wait; JOBS=0; fi
    done < "$INPUT"
    wait
  fi
}

# ── Brute-force con wordlist pequeña ──────────────────────
# Genera ${WORD}.${TARGET}. Si TARGET ya está en el límite de profundidad
# (SUBDOMAIN_BRUTE_MAX_DEPTH, default 3), el resultado superaría el límite
# y se salta — evita expansión combinatoria sub1.sub2.sub3.sub4....
_enum_bruteforce() {
  local TARGET="$1"
  local OUT_FILE="$2"
  local ROOT_DOMAIN="$3"
  local WORDLIST="${SUBDOMAIN_WORDLIST:-${SCRIPT_DIR}/data/subdomains_small.txt}"
  local MAX_DEPTH="${SUBDOMAIN_BRUTE_MAX_DEPTH:-3}"

  [[ ! -f "$WORDLIST" ]] && return 0

  local TARGET_DEPTH
  TARGET_DEPTH=$(_subdomain_depth "$TARGET" "$ROOT_DOMAIN")
  # Bruteforce añade 1 nivel; saltar si ya estamos en el límite
  if [[ "$TARGET_DEPTH" -ge "$MAX_DEPTH" ]]; then
    return 0
  fi

  local CANDS
  CANDS=$(mktemp)
  sed '/^$/d; /^#/d' "$WORDLIST" | while IFS= read -r WORD; do
    echo "${WORD}.${TARGET}"
  done > "$CANDS"

  _resolve_list "$CANDS" "$OUT_FILE" "$ROOT_DOMAIN"
  rm -f "$CANDS"
}

# ── Generador de mutaciones ────────────────────────────────
# Extrae los labels de subdominios ya encontrados y genera
# variantes combinando esos labels con palabras comunes de entorno.
# Ejemplo: api.domain.tld → dev-api, staging-api, api-v2, api-prod…
_enum_mutate() {
  local KNOWN_FILE="$1"
  local OUT_FILE="$2"
  local ROOT_DOMAIN="$3"
  local SAFE_PAT
  SAFE_PAT=$(echo "$ROOT_DOMAIN" | sed 's/\./\\./g')

  # 1. Extraer labels únicos de subdominios conocidos
  local LABELS
  LABELS=$(mktemp)
  grep -v "^${ROOT_DOMAIN}$" "$KNOWN_FILE" \
    | sed "s/\.${SAFE_PAT}$//" \
    | tr '.' '\n' \
    | tr '-' '\n' \
    | grep -E '^[a-z0-9]{2,}$' \
    | sort -u > "$LABELS"

  # 2. Añadir palabras de entorno canónicas
  cat >> "$LABELS" << 'ENVWORDS'
dev
staging
prod
test
uat
qa
sandbox
preprod
demo
beta
alpha
preview
canary
internal
admin
api
app
web
mobile
v1
v2
v3
old
new
legacy
backup
us
eu
ap
ENVWORDS
  sort -u "$LABELS" -o "$LABELS"

  # 3. Para cada subdomain conocido, generar variantes del primer label
  local CANDS
  CANDS=$(mktemp)

  while IFS= read -r SUB; do
    [[ "$SUB" == "$ROOT_DOMAIN" ]] && continue
    local SUB_PART="${SUB%.${ROOT_DOMAIN}}"
    local FIRST="${SUB_PART%%.*}"
    local REST="${SUB_PART#*.}"
    [[ "$REST" == "$FIRST" ]] && REST=""

    local PARENT
    [[ -n "$REST" ]] && PARENT="${REST}.${ROOT_DOMAIN}" || PARENT="${ROOT_DOMAIN}"

    # Variantes: sustituir el primer label por cada label conocido
    while IFS= read -r LBL; do
      [[ "$LBL" == "$FIRST" ]] && continue
      echo "${LBL}.${PARENT}"
      # Separador guion: dev-api, staging-api, api-prod
      echo "${LBL}-${FIRST}.${PARENT}"
      echo "${FIRST}-${LBL}.${PARENT}"
    done < "$LABELS"

    # Patrón numérico: v1→v2..v9, api-01→api-02..api-09
    if [[ "$FIRST" =~ ^(.*[^0-9])([0-9]+)$ ]]; then
      local BASE="${BASH_REMATCH[1]}"
      local NUM="${BASH_REMATCH[2]}"
      local PAD=${#NUM}
      for i in $(seq 1 9); do
        [[ "$i" == "$((10#$NUM))" ]] && continue
        printf "${BASE}%0${PAD}d.${PARENT}\n" "$i"
      done
    fi

  done < "$KNOWN_FILE" | sort -u > "$CANDS"

  # 4. Quitar los ya conocidos y resolver el resto
  local NEW_CANDS
  NEW_CANDS=$(mktemp)
  comm -23 <(sort "$CANDS") <(sort "$KNOWN_FILE") > "$NEW_CANDS"

  local N_CANDS
  N_CANDS=$(wc -l < "$NEW_CANDS" | tr -d ' ')
  log_info "  Mutaciones: resolviendo ${N_CANDS} candidatos..."

  _resolve_list "$NEW_CANDS" "$OUT_FILE" "$ROOT_DOMAIN"
  rm -f "$CANDS" "$NEW_CANDS" "$LABELS"
}

# ── Enumeración rápida para rondas recursivas ──────────────
# Solo subfinder + assetfinder: amass y bbot demasiado lentos para iterar.
_enum_fast() {
  local TARGET="$1"
  local OUT_FILE="$2"
  local ROOT_DOMAIN="$3"
  local SAFE_PAT
  SAFE_PAT=$(echo "$ROOT_DOMAIN" | sed 's/\./\\./g')

  if command -v "${SUBFINDER_BIN:-subfinder}" &>/dev/null; then
    ${PROXYCHAINS_CMD:-} "${SUBFINDER_BIN:-subfinder}" -d "$TARGET" -silent 2>/dev/null \
      | grep -iE "^[a-z0-9._-]+\.${SAFE_PAT}$" >> "$OUT_FILE" || true
  fi

  if command -v assetfinder &>/dev/null; then
    ${PROXYCHAINS_CMD:-} assetfinder --subs-only "$TARGET" 2>/dev/null \
      | grep -iE "^[a-z0-9._-]+\.${SAFE_PAT}$" >> "$OUT_FILE" || true
  fi
}

# ── Módulo principal ───────────────────────────────────────
module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  local RAW="$OUT_DIR/subs_raw.txt"
  local TMP="$OUT_DIR/.tmp_subs"
  mkdir -p "$TMP"
  > "$RAW"

  log_phase "Módulo 01 — $MODULE_DESC: $DOMAIN"

  # ── Ronda 0: herramientas pasivas en paralelo ──────────────
  if command -v "${SUBFINDER_BIN:-subfinder}" &>/dev/null; then
    log_info "subfinder..."
    ${PROXYCHAINS_CMD:-} "${SUBFINDER_BIN:-subfinder}" -d "$DOMAIN" -silent \
      -o "$TMP/subfinder.txt" 2>/dev/null || true &
  else
    log_warn "subfinder no encontrado, saltando"
  fi

  if command -v assetfinder &>/dev/null; then
    log_info "assetfinder..."
    ${PROXYCHAINS_CMD:-} assetfinder --subs-only "$DOMAIN" \
      > "$TMP/assetfinder.txt" 2>/dev/null || true &
  else
    log_warn "assetfinder no encontrado, saltando"
  fi

  if command -v "${AMASS_BIN:-amass}" &>/dev/null; then
    log_info "amass (pasivo)..."
    ${PROXYCHAINS_CMD:-} "${AMASS_BIN:-amass}" enum -passive -d "$DOMAIN" \
      -o "$TMP/amass.txt" 2>/dev/null || true &
  else
    log_warn "amass no encontrado, saltando"
  fi

  if command -v findomain &>/dev/null; then
    log_info "findomain..."
    ${PROXYCHAINS_CMD:-} findomain -t "$DOMAIN" -q \
      > "$TMP/findomain.txt" 2>/dev/null || true &
  else
    log_warn "findomain no encontrado, saltando"
  fi

  if command -v "${BBOT_BIN:-bbot}" &>/dev/null; then
    log_info "bbot (subdomain-enum, timeout ${BBOT_TIMEOUT:-600}s)..."
    (
      timeout "${BBOT_TIMEOUT:-600}" \
        "${BBOT_BIN:-bbot}" -t "$DOMAIN" \
          -p subdomain-enum \
          -om subdomains \
          -o "$TMP/bbot_out" \
          -s -y 2>/dev/null || true
      find "$TMP/bbot_out" -name "subdomains.txt" 2>/dev/null \
        | xargs cat 2>/dev/null \
        > "$TMP/bbot.txt"
    ) || true &
  else
    log_warn "bbot no encontrado, saltando"
  fi

  # Brute-force sobre el dominio raíz en paralelo con lo anterior
  log_info "brute-force (wordlist)..."
  ( _enum_bruteforce "$DOMAIN" "$TMP/bruteforce.txt" "$DOMAIN" ) &

  log_info "Esperando ronda 0..."
  wait

  # ── Merge inicial ──────────────────────────────────────────
  local SAFE_PAT
  SAFE_PAT=$(echo "$DOMAIN" | sed 's/\./\\./g')
  echo "$DOMAIN" > "$RAW"
  cat "$TMP"/*.txt 2>/dev/null \
    | grep -v "^$" \
    | grep -iE "^[a-z0-9._-]+\.${SAFE_PAT}$" \
    >> "$RAW"
  sort -u "$RAW" -o "$RAW"

  # ── Mutaciones sobre la ronda 0 ───────────────────────────
  log_info "Generando mutaciones por nomenclatura..."
  _enum_mutate "$RAW" "$TMP/mutations.txt" "$DOMAIN"
  if [[ -s "$TMP/mutations.txt" ]]; then
    cat "$TMP/mutations.txt" >> "$RAW"
    sort -u "$RAW" -o "$RAW"
    local MUT_COUNT
    MUT_COUNT=$(wc -l < "$TMP/mutations.txt" | tr -d ' ')
    log_info "  Mutaciones añadidas: $MUT_COUNT nuevos subdominios"
  fi

  # ── Rondas recursivas ──────────────────────────────────────
  # Cada subdomain descubierto se usa como target de una nueva ronda
  # de enumeración rápida + brute-force para encontrar mayor profundidad.
  local MAX_DEPTH="${SUBDOMAIN_ENUM_DEPTH:-3}"
  local MAX_PARALLEL="${SUBDOMAIN_ENUM_PARALLEL:-20}"
  local ENUMERATED="$TMP/.enumerated"
  echo "$DOMAIN" > "$ENUMERATED"

  local ROUND=0
  while [[ $ROUND -lt $MAX_DEPTH ]]; do
    ROUND=$(( ROUND + 1 ))

    local NEW_TARGETS
    NEW_TARGETS=$(comm -23 <(sort "$RAW") <(sort "$ENUMERATED") \
      | grep -v "^$" || true)

    local N_NEW
    N_NEW=$(echo "$NEW_TARGETS" | grep -c . 2>/dev/null || echo 0)
    [[ "$N_NEW" -eq 0 ]] && break

    log_info "Ronda recursiva $ROUND/$MAX_DEPTH — ${N_NEW} targets..."

    local ROUND_FILE="$TMP/recursive_r${ROUND}.txt"
    > "$ROUND_FILE"

    local JOBS=0
    while IFS= read -r TARGET; do
      [[ -z "$TARGET" ]] && continue
      echo "$TARGET" >> "$ENUMERATED"
      _resolves "$TARGET" || continue

      (
        _enum_fast "$TARGET" "$ROUND_FILE" "$DOMAIN"
        _enum_bruteforce "$TARGET" "$ROUND_FILE" "$DOMAIN"
      ) &
      JOBS=$(( JOBS + 1 ))
      if [[ $JOBS -ge $MAX_PARALLEL ]]; then wait; JOBS=0; fi
    done <<< "$NEW_TARGETS"
    wait

    local NEW_COUNT=0
    if [[ -s "$ROUND_FILE" ]]; then
      NEW_COUNT=$(comm -23 <(sort -u "$ROUND_FILE") <(sort "$RAW") \
        | grep -c . 2>/dev/null || echo 0)
      if [[ $NEW_COUNT -gt 0 ]]; then
        cat "$ROUND_FILE" >> "$RAW"
        sort -u "$RAW" -o "$RAW"

        # Mutaciones sobre los nuevos hallazgos de esta ronda
        local MUT_R="$TMP/mutations_r${ROUND}.txt"
        _enum_mutate "$RAW" "$MUT_R" "$DOMAIN"
        if [[ -s "$MUT_R" ]]; then
          cat "$MUT_R" >> "$RAW"
          sort -u "$RAW" -o "$RAW"
        fi

        log_info "  Ronda $ROUND: +$NEW_COUNT subdominios"
      fi
    fi

    [[ $NEW_COUNT -eq 0 ]] && break
  done

  local COUNT
  COUNT=$(wc -l < "$RAW" | tr -d ' ')
  log_ok "$MODULE_DESC completado: $COUNT subdominios únicos (${ROUND} rondas)"

  # Notificar resumen + subdominios jugosos a Telegram
  local HIGHLIGHTS
  HIGHLIGHTS=$(grep -iE \
    'staging|stage|preprod|dev\.|qa\.|uat\.|admin|password|secret|internal|intranet|vpn|citrix|git\.|jenkins|jira|confluence|api\.|b2b|portal|cloudapp|backoffice|corp|legado|legacy|test\.' \
    "$RAW" 2>/dev/null | head -20 | tr '\n' '\n' || true)

  local TG_MSG="🌐 *Subdomain enum completado*
🎯 \`${DOMAIN}\`
📊 Total: *${COUNT}* subdominios únicos

🔍 *Destacados:*
\`\`\`
${HIGHLIGHTS:-ninguno}
\`\`\`
📅 $(date '+%Y-%m-%d %H:%M:%S')"

  _telegram_send "$TG_MSG" 2>/dev/null || true

  rm -rf "$TMP"
  echo "$COUNT"
}
