#!/usr/bin/env bash
# ============================================================
#  modules/38_path_audit.sh
#  Fase 38: Path mutation audit — diferencial unificado
#
#  Aplica el catálogo completo de core/path_mutations.sh
#  (normalization + encoding + confusion + tricks + suffix +
#   header-bypass + method-bypass) sobre URLs candidatas y
#  reporta SOLO divergencias significativas vs el baseline.
#
#  Cómo difiere de 23 (403_bypass) y 26 (path_confusion):
#   - 23 testa solo paths que ya dan 403/401 con técnicas fijas.
#   - 26 testa solo subs cuya tech matchea (Apache/Tomcat/...).
#   - 38 corre las 120 mutaciones del catálogo unificado sobre
#     un set auto-seleccionado (admin + API + 403/401 + jugosas)
#     y agrupa respuestas idénticas para reducir ruido.
#
#  Selección de targets (auto):
#    a) Paths admin/protegidos detectados por el crawler
#    b) Endpoints de API (/api/, /v1/, /graphql, /rest)
#    c) URLs que en la DB ya dieron 401 o 403
#    d) Paths sensibles bien-conocidos (/actuator, /.env, /.git,
#       /WEB-INF/web.xml, /server-status, etc.) probados sobre
#       cada subdominio alive
#
#  Para cada target:
#    1. Baseline: fetch del path original
#    2. Mutate-all: 120 variantes vía core/path_mutations.sh
#    3. Diff-test: clasificar divergencias (auth_bypass,
#       source_disclosure, parser_confusion, etc.)
#    4. Cluster: agrupar mutaciones con misma respuesta →
#       una representante por cluster
#    5. Reportar como finding con curl reproducible
# ============================================================

MODULE_NAME="path_audit"
MODULE_DESC="Path mutation audit (normalization + confusion + tricks + bypasses)"

# ── Paths bien-conocidos a probar sobre cada sub alive ───────
# Conservador para no inflar el scope: paths que casi siempre
# son admin/internos. El catálogo de mutaciones expande cada uno.
_PA_WELL_KNOWN_PATHS=(
  "/admin"
  "/administrator"
  "/admin/login"
  "/admin/dashboard"
  "/console"
  "/manager"
  "/manager/html"
  "/host-manager"
  "/dashboard"
  "/internal"
  "/private"
  "/actuator"
  "/actuator/env"
  "/actuator/heapdump"
  "/.env"
  "/.git/config"
  "/.git/HEAD"
  "/.svn/entries"
  "/.aws/credentials"
  "/server-status"
  "/server-info"
  "/nginx_status"
  "/phpinfo.php"
  "/info.php"
  "/WEB-INF/web.xml"
  "/META-INF/MANIFEST.MF"
  "/web.config"
  "/app.config"
  "/swagger-ui.html"
  "/swagger-ui/"
  "/api-docs"
  "/v2/api-docs"
  "/openapi.json"
  "/graphql"
  "/graphiql"
)

# ── Audit de una URL: baseline + 120 mutaciones + cluster ────
_path_audit_url() {
  local FULL_URL="$1"
  local DOMAIN_ID="$2"
  local DOMAIN="$3"

  local BASE_HOST PURE_PATH
  BASE_HOST=$(echo "$FULL_URL" | grep -oP '^https?://[^/]+')
  [[ -z "$BASE_HOST" ]] && return
  local AFTER_HOST="${FULL_URL#$BASE_HOST}"
  PURE_PATH="${AFTER_HOST%%\?*}"
  [[ -z "$PURE_PATH" ]] && PURE_PATH="/"

  # Skip rutas estáticas obvias (no dan signal interesante)
  [[ "$PURE_PATH" =~ \.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|pdf|zip|tar|gz)(\?|$) ]] && return

  # Baseline
  _h_get "${BASE_HOST}${PURE_PATH}"
  local B_S="$HTTP_LAST_STATUS"
  local B_L="${#HTTP_LAST_BODY}"
  local B_BODY="${HTTP_LAST_BODY:0:2000}"
  local B_HDRS="$HTTP_LAST_HEADERS"

  # Sin respuesta → skip
  [[ "$B_S" == "000" || -z "$B_S" ]] && return

  # Si baseline es FP (CF Access, SPA shell) → no hay nada que auditar
  if is_likely_fp_response "$BASE_HOST" "$B_BODY" "$B_HDRS"; then
    return
  fi

  log_info "  audit: ${BASE_HOST}${PURE_PATH} (baseline=$B_S, ${B_L}b)"

  # Clusters: agrupa mutaciones con respuesta similar
  declare -A CLUSTERS
  local TESTED=0 UNIQUE_FINDINGS=0

  while IFS=$'\t' read -r CLASS MPATH EXTRA; do
    [[ -z "$CLASS" ]] && continue
    ((TESTED++))

    case "$CLASS" in
      method-bypass)
        _h_method "$EXTRA" "${BASE_HOST}${MPATH}"
        ;;
      header-bypass)
        _h_get "${BASE_HOST}${MPATH}" -H "$EXTRA"
        ;;
      *)
        _h_get "${BASE_HOST}${MPATH}" --path-as-is
        ;;
    esac

    local M_S="$HTTP_LAST_STATUS"
    local M_L="${#HTTP_LAST_BODY}"
    local M_BODY="${HTTP_LAST_BODY:0:2000}"
    local M_HDRS="$HTTP_LAST_HEADERS"

    # Clasificar
    local DIFF
    DIFF=$(_path_diff_test "$B_S" "$B_L" "$M_S" "$M_L" "$M_BODY" "$M_HDRS" "$BASE_HOST")
    local SEV="${DIFF%%|*}"
    [[ "$SEV" == "none" ]] && continue

    # Cluster key: status + length-bucket (100b) + first-200b-hash
    local BODY_HASH
    BODY_HASH=$(echo -n "${M_BODY:0:200}" | md5sum 2>/dev/null | cut -c1-8)
    local KEY="${M_S}:$((M_L / 100)):${BODY_HASH}"

    if [[ -n "${CLUSTERS[$KEY]:-}" ]]; then
      # Ya hay representante — incrementar contador (campo final)
      local PREV="${CLUSTERS[$KEY]}"
      local PREV_COUNT="${PREV##*|count=}"
      local NEW_COUNT=$((PREV_COUNT + 1))
      CLUSTERS[$KEY]="${PREV%|count=*}|count=${NEW_COUNT}"
      continue
    fi

    ((UNIQUE_FINDINGS++))

    local VERDICT="${DIFF#*|}"
    local LABEL="${VERDICT%%|*}"
    local REASON="${VERDICT#*|}"

    # Construir curl reproducible
    local CURL_CMD
    case "$CLASS" in
      method-bypass)
        CURL_CMD="curl -sk -X ${EXTRA} '${BASE_HOST}${MPATH}'"
        ;;
      header-bypass)
        CURL_CMD="curl -sk -H '${EXTRA}' '${BASE_HOST}${MPATH}'"
        ;;
      *)
        CURL_CMD="curl -sk --path-as-is '${BASE_HOST}${MPATH}'"
        ;;
    esac

    CLUSTERS[$KEY]="${CLASS}|${MPATH}|${EXTRA}|${SEV}|${LABEL}|${REASON}|${CURL_CMD}|count=1"

    log_warn "  ⚡ [$SEV] $LABEL"
    log_warn "    target: ${BASE_HOST}${PURE_PATH} (baseline=$B_S → mutation=$M_S)"
    log_warn "    via ${CLASS}: ${MPATH:0:80} ${EXTRA:0:60}"
    log_warn "    reason: ${REASON:0:140}"

    db_add_finding "$DOMAIN_ID" "path_audit" "$SEV" \
      "${BASE_HOST}${PURE_PATH}" "${LABEL}:${CLASS}" \
      "${REASON} | mutation_path=${MPATH} | mutation_extra=${EXTRA} | baseline=${B_S} mutation=${M_S} | curl: ${CURL_CMD}"

    if [[ "$SEV" =~ ^(critical|high|medium)$ ]]; then
      _telegram_send "🛡️ *Path Audit — ${LABEL}*
🌐 \`${DOMAIN}\`
🔗 \`${BASE_HOST}${PURE_PATH}\`
📋 Severidad: \`${SEV}\`
🎯 Class: \`${CLASS}\`
💡 ${REASON:0:200}
🧪 \`${CURL_CMD:0:200}\`
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
    fi
  done < <(_path_mutate_all "$PURE_PATH")

  if [[ "$UNIQUE_FINDINGS" -gt 0 ]]; then
    log_ok "  audit ${PURE_PATH}: ${UNIQUE_FINDINGS} clusters únicos (${TESTED} mutaciones probadas)"
  fi
}

# ── Auto-selección de targets ────────────────────────────────
_pa_collect_targets() {
  local DOMAIN_ID="$1"
  local OUT_DIR="$2"
  local TARGETS_FILE="$3"

  > "$TARGETS_FILE"

  # 1) URLs que en la DB ya dieron 401/403 (alto valor: ya hay ACL)
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND status_code IN (401, 403)
       AND url NOT LIKE '%FUZZ%'
     LIMIT 50;" 2>/dev/null >> "$TARGETS_FILE" || true

  # 2) URLs admin/console/dashboard descubiertas por crawler
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND url NOT LIKE '%FUZZ%'
       AND url NOT LIKE '%.css%' AND url NOT LIKE '%.js%' AND url NOT LIKE '%.png%'
       AND (
         url LIKE '%/admin%'   OR url LIKE '%/console%'
         OR url LIKE '%/dashboard%' OR url LIKE '%/manager%'
         OR url LIKE '%/internal%'  OR url LIKE '%/private%'
         OR url LIKE '%/actuator%'  OR url LIKE '%/.git%'
         OR url LIKE '%/.env%'      OR url LIKE '%/WEB-INF%'
         OR url LIKE '%/META-INF%'  OR url LIKE '%/web.config%'
         OR url LIKE '%/server-status%' OR url LIKE '%/phpinfo%'
       )
     LIMIT 80;" 2>/dev/null >> "$TARGETS_FILE" || true

  # 3) Endpoints de API descubiertos (suele ser donde hay ACL distinta)
  sqlite3 "$DB_PATH" \
    "SELECT DISTINCT url FROM urls
     WHERE domain_id=${DOMAIN_ID}
       AND url NOT LIKE '%FUZZ%'
       AND url NOT LIKE '%.css%' AND url NOT LIKE '%.js%'
       AND (
         url LIKE '%/api/%'   OR url LIKE '%/v1/%'
         OR url LIKE '%/v2/%' OR url LIKE '%/v3/%'
         OR url LIKE '%/rest/%' OR url LIKE '%/graphql%'
         OR url LIKE '%/swagger%' OR url LIKE '%/api-docs%'
         OR url LIKE '%/openapi%'
       )
     LIMIT 50;" 2>/dev/null >> "$TARGETS_FILE" || true

  # 4) Paths bien-conocidos sobre cada sub alive (probe ad-hoc)
  local ALIVE_FILE="$OUT_DIR/subs_alive.txt"
  if [[ -s "$ALIVE_FILE" ]]; then
    while IFS= read -r SUB; do
      [[ -z "$SUB" ]] && continue
      for WP in "${_PA_WELL_KNOWN_PATHS[@]}"; do
        echo "https://${SUB}${WP}"
      done
    done < "$ALIVE_FILE" >> "$TARGETS_FILE" || true
  fi

  # Dedup + cap final
  sort -u "$TARGETS_FILE" -o "$TARGETS_FILE"

  # Cap de seguridad para no eternizar el scan
  local MAX_TARGETS="${PATH_AUDIT_MAX_TARGETS:-300}"
  local N_BEFORE
  N_BEFORE=$(wc -l < "$TARGETS_FILE" | tr -d ' ')
  if [[ "$N_BEFORE" -gt "$MAX_TARGETS" ]]; then
    head -n "$MAX_TARGETS" "$TARGETS_FILE" > "${TARGETS_FILE}.cap"
    mv "${TARGETS_FILE}.cap" "$TARGETS_FILE"
    log_warn "  Cap aplicado: $N_BEFORE → $MAX_TARGETS targets (sube PATH_AUDIT_MAX_TARGETS para más)"
  fi
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 38 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/proxy.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/path_mutations.sh" 2>/dev/null || {
    log_error "core/path_mutations.sh no disponible"
    return 1
  }
  proxy_check 2>/dev/null || true

  local TARGETS_FILE="$OUT_DIR/.path_audit_targets.txt"
  _pa_collect_targets "$DOMAIN_ID" "$OUT_DIR" "$TARGETS_FILE"

  local N
  N=$(wc -l < "$TARGETS_FILE" | tr -d ' ')
  if [[ "$N" -eq 0 ]]; then
    log_info "Sin targets para auditar"
    rm -f "$TARGETS_FILE"
    return 0
  fi

  log_info "Auditando $N targets con catálogo unificado de mutaciones..."

  local FINDINGS_BEFORE
  FINDINGS_BEFORE=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings WHERE domain_id=${DOMAIN_ID} AND type='path_audit';" \
    2>/dev/null || echo 0)

  # Procesado secuencial por target — la paralelización dentro de cada
  # target la hace _h_get respetando rate-limit global. Si quisieramos
  # paralelizar entre targets, necesitaríamos una tabla compartida; por
  # ahora secuencial es defensivo (no satura el host objetivo).
  local DONE=0
  while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue
    ((DONE++))
    [[ $((DONE % 10)) -eq 0 ]] && log_info "  progreso: $DONE/$N targets"
    _path_audit_url "$URL" "$DOMAIN_ID" "$DOMAIN"
  done < "$TARGETS_FILE"

  local FINDINGS_AFTER
  FINDINGS_AFTER=$(sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM findings WHERE domain_id=${DOMAIN_ID} AND type='path_audit';" \
    2>/dev/null || echo 0)
  local NEW=$(( FINDINGS_AFTER - FINDINGS_BEFORE ))

  log_ok "$MODULE_DESC completado: ${NEW} findings nuevos en ${N} targets"

  rm -f "$TARGETS_FILE"
}
