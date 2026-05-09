#!/usr/bin/env bash
# ============================================================
#  modules/99_verify_findings.sh
#  Mejora D — verification pass post-pipeline.
#
#  Misión: antes de que el AI Advisor o el reviewer humano vea los
#  findings, recorrer los critical/high con confidence != high y
#  re-verificar con heurística estricta (validators).
#  - Si pasa → confidence=high (queda crítico/high)
#  - Si falla → confidence=low + severity=info (queda en DB pero sin ruido)
#
#  No reproba TODO el pipeline — solo los findings de tipos que tienen
#  validator definido (cms_scan, spring_actuator, path_confusion).
# ============================================================

MODULE_NAME="verify_findings"
MODULE_DESC="Verification pass — re-validar critical/high con confidence baja"

_verify_finding() {
  local FID="$1" TYPE="$2" TARGET="$3" TEMPLATE="$4" SEVERITY="$5"

  # Solo re-validamos templates que tienen un validator estrictoknown
  case "$TEMPLATE" in
    aem_check|aem_jcr_write|aem_jcr_partial_put)
      _h_get_noredirect "$TARGET" --connect-timeout 8
      [[ "$HTTP_LAST_STATUS" == "200" ]] && _validate_aem_exposed && return 0
      return 1
      ;;
    spring_actuator)
      _h_get_noredirect "$TARGET" --connect-timeout 8
      [[ "$HTTP_LAST_STATUS" == "200" ]] && _validate_actuator_response && return 0
      return 1
      ;;
    tomcat_semicolon|tomcat_semicolon_traversal|tomcat_semicolon_direct|tomcat_semicolon_waf_bypass|spring_traversal)
      _h_get "$TARGET" --connect-timeout 8
      [[ "$HTTP_LAST_STATUS" != "200" ]] && return 1
      # web.xml/MANIFEST/actuator validators según target
      if echo "$TARGET" | grep -qi "web\.xml"; then
        _validate_web_xml && return 0
      elif echo "$TARGET" | grep -qi "MANIFEST"; then
        _validate_manifest && return 0
      elif echo "$TARGET" | grep -qi "/actuator/"; then
        _validate_actuator_response && return 0
      fi
      return 1
      ;;
    *)
      # Sin validator: dejar como está
      return 2
      ;;
  esac
}

module_run() {
  local DOMAIN="$1"
  local DOMAIN_ID="$2"
  local OUT_DIR="$3"

  log_phase "Módulo 99 — $MODULE_DESC: $DOMAIN"

  source "${SCRIPT_DIR}/core/http_analyzer.sh" 2>/dev/null || true
  source "${SCRIPT_DIR}/core/finding_validators.sh" 2>/dev/null || true

  # Dedup deshabilitado durante verify para no saltarse re-inserts/updates
  export FINDING_DEDUP_DISABLED=1

  local CANDIDATES
  CANDIDATES=$(sqlite3 "$DB_PATH" -separator $'\t' \
    "SELECT id, type, target, template, severity FROM findings
     WHERE domain_id=${DOMAIN_ID}
       AND severity IN ('critical','high')
       AND (confidence IS NULL OR confidence IN ('unverified','low','medium'))
       AND template IN (
         'aem_check','aem_jcr_write','aem_jcr_partial_put',
         'spring_actuator',
         'tomcat_semicolon','tomcat_semicolon_traversal',
         'tomcat_semicolon_direct','tomcat_semicolon_waf_bypass',
         'spring_traversal'
       );" 2>/dev/null)

  if [[ -z "$CANDIDATES" ]]; then
    log_info "  Sin findings critical/high pendientes de verificar"
    unset FINDING_DEDUP_DISABLED
    return 0
  fi

  local TOTAL=0 UPGRADED=0 DOWNGRADED=0
  while IFS=$'\t' read -r FID FTYPE FTARGET FTEMPLATE FSEV; do
    [[ -z "$FID" ]] && continue
    ((TOTAL++))

    _verify_finding "$FID" "$FTYPE" "$FTARGET" "$FTEMPLATE" "$FSEV"
    local RC=$?

    if [[ $RC -eq 0 ]]; then
      sqlite3 "$DB_PATH" "UPDATE findings SET confidence='high' WHERE id=${FID};" 2>/dev/null
      ((UPGRADED++))
    elif [[ $RC -eq 1 ]]; then
      sqlite3 "$DB_PATH" \
        "UPDATE findings SET confidence='low', severity='info',
         detail=detail || ' [auto-downgrade: validator estricto rechazó re-prueba]'
         WHERE id=${FID};" 2>/dev/null
      ((DOWNGRADED++))
    fi
  done <<< "$CANDIDATES"

  unset FINDING_DEDUP_DISABLED

  log_ok "$MODULE_DESC: ${TOTAL} findings re-validados — ${UPGRADED} upgrades, ${DOWNGRADED} downgrades"

  if [[ "$DOWNGRADED" -gt 0 ]]; then
    _telegram_send "🧹 *Verify findings — limpieza FPs*
🌐 \`${DOMAIN}\`
✅ Upgrades a high confidence: ${UPGRADED}
⬇️  Downgrades critical/high → info: ${DOWNGRADED}
📊 Total re-validado: ${TOTAL}
📅 $(date '+%Y-%m-%d %H:%M:%S')" 2>/dev/null || true
  fi
}
