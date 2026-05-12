#!/usr/bin/env bash
# Batch paralelo — Workday Bug Bounty (HackerOne)
# Scope CSV: scopes_for_workday_at_2026-05-05_16_30_47_UTC.csv
# Solo targets eligible_for_bounty=true && eligible_for_submission=true
# Excluye evisort.dev y peakon.com (ya escaneados)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="$SCRIPT_DIR/output/batch_workday_${TIMESTAMP}"
mkdir -p "$LOG_DIR"
LOG_MAIN="$LOG_DIR/batch.log"

MAX_PARALLEL=4  # 4 procesos en paralelo (8 cores disponibles)

# formato: "dominio_base|target"
targets=(
  # workdaybugbounty.com
  "workdaybugbounty.com|bb1.workdaybugbounty.com"
  "workdaybugbounty.com|treasuremap.workdaybugbounty.com"
  # workday.com
  "workday.com|workday.com"
  "workday.com|forms.workday.com"
  # workdayspend.com (WSS apps — critical)
  "workdayspend.com|bb1.bugbounty.workdayspend.com"
  "workdayspend.com|bb1.dm.bugbounty.workdayspend.com"
  "workdayspend.com|bb1.pp.bugbounty.workdayspend.com"
  "workdayspend.com|bb1.sp.bugbounty.workdayspend.com"
  # proteusaws00037.spc.megaleo.com (Megaleo/Workday infra — critical)
  "proteusaws00037.spc.megaleo.com|e2.proteusaws00037.spc.megaleo.com"
  "proteusaws00037.spc.megaleo.com|enterprise-services1.proteusaws00037.spc.megaleo.com"
  "proteusaws00037.spc.megaleo.com|esba.proteusaws00037.spc.megaleo.com"
  "proteusaws00037.spc.megaleo.com|esba-test.proteusaws00037.spc.megaleo.com"
  "proteusaws00037.spc.megaleo.com|esbc.proteusaws00037.spc.megaleo.com"
  "proteusaws00037.spc.megaleo.com|esbc-test.proteusaws00037.spc.megaleo.com"
  "proteusaws00037.spc.megaleo.com|esbg.proteusaws00037.spc.megaleo.com"
  "proteusaws00037.spc.megaleo.com|esbg-test.proteusaws00037.spc.megaleo.com"
  "proteusaws00037.spc.megaleo.com|esbi.proteusaws00037.spc.megaleo.com"
  "proteusaws00037.spc.megaleo.com|esbi-test.proteusaws00037.spc.megaleo.com"
  "proteusaws00037.spc.megaleo.com|identity.proteusaws00037.spc.megaleo.com"
  "proteusaws00037.spc.megaleo.com|ox.proteusaws00037.spc.megaleo.com"
  "proteusaws00037.spc.megaleo.com|proteusaws00037.spc.megaleo.com"
  "proteusaws00037.spc.megaleo.com|queue-services1.proteusaws00037.spc.megaleo.com"
  "proteusaws00037.spc.megaleo.com|services1.proteusaws00037.spc.megaleo.com"
  "proteusaws00037.spc.megaleo.com|sso.proteusaws00037.spc.megaleo.com"
  "proteusaws00037.spc.megaleo.com|wats.proteusaws00037.spc.megaleo.com"
  # megaleosite.com
  "proteusaws00037.spc.megaleosite.com|proteusaws00037.spc.megaleosite.com"
)

total=${#targets[@]}
echo "[workday-batch] Iniciando $total targets en paralelo (max $MAX_PARALLEL) — $(date)" | tee "$LOG_MAIN"
echo "[workday-batch] Log dir: $LOG_DIR" | tee -a "$LOG_MAIN"

# Semáforo simple con array de PIDs activos
pids=()

run_target() {
  local domain="$1" target="$2" n="$3"
  local log="$LOG_DIR/$(echo "$target" | tr '/' '_').log"
  echo "[+] [$n/$total] Iniciando $target  (base: $domain)" | tee -a "$LOG_MAIN"
  bash "$SCRIPT_DIR/recon.sh" "$domain" --target="$target" >"$log" 2>&1
  local exit_code=$?
  if [[ $exit_code -eq 0 ]]; then
    echo "[✓] [$n/$total] $target COMPLETADO" | tee -a "$LOG_MAIN"
  else
    echo "[!] [$n/$total] $target FALLÓ (exit $exit_code)" | tee -a "$LOG_MAIN"
  fi
}

export -f run_target
export SCRIPT_DIR LOG_DIR LOG_MAIN total

for i in "${!targets[@]}"; do
  IFS='|' read -r domain target <<< "${targets[$i]}"
  n=$((i+1))

  # Esperar si ya hay MAX_PARALLEL procesos corriendo
  while [[ ${#pids[@]} -ge $MAX_PARALLEL ]]; do
    new_pids=()
    for pid in "${pids[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then
        new_pids+=("$pid")
      fi
    done
    pids=("${new_pids[@]}")
    [[ ${#pids[@]} -ge $MAX_PARALLEL ]] && sleep 5
  done

  run_target "$domain" "$target" "$n" &
  pids+=($!)
done

# Esperar a que terminen todos
echo "[workday-batch] Esperando a que finalicen los últimos procesos..." | tee -a "$LOG_MAIN"
wait

echo "" | tee -a "$LOG_MAIN"
echo "[workday-batch] TODOS LOS TARGETS COMPLETADOS — $(date)" | tee -a "$LOG_MAIN"
echo "[workday-batch] Log completo: $LOG_MAIN"

# Resumen de findings
echo "" | tee -a "$LOG_MAIN"
echo "=== FINDINGS WORKDAY ===" | tee -a "$LOG_MAIN"
sqlite3 "$SCRIPT_DIR/data/recon.db" \
  "SELECT f.severity, f.type, f.target, substr(f.detail,1,80)
   FROM findings f
   JOIN domains d ON f.domain_id = d.id
   WHERE d.domain IN (
     'workdaybugbounty.com','workday.com','workdayspend.com',
     'proteusaws00037.spc.megaleo.com','proteusaws00037.spc.megaleosite.com'
   )
   ORDER BY CASE f.severity
     WHEN 'critical' THEN 1 WHEN 'high' THEN 2
     WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END;" \
  2>/dev/null | tee -a "$LOG_MAIN" || true
