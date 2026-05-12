#!/usr/bin/env bash
# Batch — Generali Bug Bounty (YesWeHack)
# Scope: data/scopes/generali.txt (27 targets)
# Lanzamiento limitado para no saturar la máquina (load 187 en el run anterior).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="$SCRIPT_DIR/output/batch_generali_${TIMESTAMP}"
mkdir -p "$LOG_DIR"
LOG_MAIN="$LOG_DIR/batch.log"

MAX_PARALLEL="${MAX_PARALLEL:-2}"
export MAX_PORT_PARALLEL="${MAX_PORT_PARALLEL:-2}"

# base por target (la mayoría → generali.fr)
declare -A base_for=(
  [generalifrprod-prod.apigee.net]=apigee.net
  [www.lamedicale.fr]=lamedicale.fr
  [monespace.lamedicale.fr]=lamedicale.fr
)

targets=()
while IFS= read -r t; do
  [[ -z "$t" ]] && continue
  base="${base_for[$t]:-generali.fr}"
  targets+=("$base|$t")
done < "$SCRIPT_DIR/data/scopes/generali.txt"

total=${#targets[@]}
echo "[generali-batch] Iniciando $total targets (max $MAX_PARALLEL paralelo, MAX_PORT_PARALLEL=$MAX_PORT_PARALLEL) — $(date)" | tee "$LOG_MAIN"
echo "[generali-batch] Log dir: $LOG_DIR" | tee -a "$LOG_MAIN"

pids=()

run_target() {
  local domain="$1" target="$2" n="$3"
  local log="$LOG_DIR/${target}.log"
  echo "[+] [$n/$total] Iniciando $target  (base: $domain)" | tee -a "$LOG_MAIN"
  bash "$SCRIPT_DIR/recon.sh" "$domain" --target="$target" >"$log" 2>&1
  local rc=$?
  if [[ $rc -eq 0 ]]; then
    echo "[✓] [$n/$total] $target COMPLETADO" | tee -a "$LOG_MAIN"
  else
    echo "[!] [$n/$total] $target FALLÓ (exit $rc)" | tee -a "$LOG_MAIN"
  fi
}

export -f run_target
export SCRIPT_DIR LOG_DIR LOG_MAIN total

for i in "${!targets[@]}"; do
  IFS='|' read -r domain target <<< "${targets[$i]}"
  n=$((i+1))

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

echo "[generali-batch] Esperando a que finalicen los últimos procesos..." | tee -a "$LOG_MAIN"
wait

echo "" | tee -a "$LOG_MAIN"
echo "[generali-batch] DONE — $(date)" | tee -a "$LOG_MAIN"
echo "[generali-batch] Log completo: $LOG_MAIN"

# Resumen findings
echo "" | tee -a "$LOG_MAIN"
echo "=== FINDINGS GENERALI ===" | tee -a "$LOG_MAIN"
sqlite3 "$SCRIPT_DIR/data/recon.db" \
  "SELECT f.severity, f.type, f.target, substr(f.detail,1,80)
   FROM findings f
   JOIN domains d ON f.domain_id = d.id
   WHERE d.domain IN ('generali.fr','lamedicale.fr','apigee.net')
   ORDER BY CASE f.severity
     WHEN 'critical' THEN 1 WHEN 'high' THEN 2
     WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END;" \
  2>/dev/null | tee -a "$LOG_MAIN" || true
