#!/usr/bin/env bash
# Batch RESUME — Generali (21 targets restantes tras parche SPA-skip 2026-05-11)
# Reutiliza LOG_DIR original para preservar findings de los 6 ya completados.
# MAX_PARALLEL=4 (vs 2 original) — máquina 8 cores soporta más con SPA-skip activo.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/output/batch_generali_20260510_193138"
LOG_MAIN="$LOG_DIR/batch.log"

MAX_PARALLEL="${MAX_PARALLEL:-4}"
export MAX_PORT_PARALLEL="${MAX_PORT_PARALLEL:-2}"

# Targets restantes (21) — tras kill del batch original 2026-05-11
declare -A base_for=(
  [generalifrprod-prod.apigee.net]=apigee.net
  [www.lamedicale.fr]=lamedicale.fr
  [monespace.lamedicale.fr]=lamedicale.fr
)

targets=(
  "generali.fr|www.objectif-business.generali.fr"
  "generali.fr|www.espace.patrimoine.generali.fr"
  "generali.fr|www.refpostal.generali.fr"
  "generali.fr|annuaire.generali.fr"
  "generali.fr|www.tigre.generali.fr"
  "generali.fr|www.visualiseur.generali.fr"
  "generali.fr|genbox.generali.fr"
  "generali.fr|gapi.generali.fr"
  "generali.fr|stella.generali.fr"
  "generali.fr|signature.generali.fr"
  "generali.fr|sign.generali.fr"
  "generali.fr|www.ob-medicale.generali.fr"
  "generali.fr|ensemble-face-aux-risques.generali.fr"
  "generali.fr|filip.generali.fr"
  "generali.fr|www.glive.generali.fr"
  "generali.fr|dossier-client.generali.fr"
  "generali.fr|dendrobate.generali.fr"
  "lamedicale.fr|www.lamedicale.fr"
  "lamedicale.fr|monespace.lamedicale.fr"
  "generali.fr|www.nomineo.generali.fr"
  "generali.fr|www.dashboard.nomineo.generali.fr"
)

total=${#targets[@]}
echo "[generali-resume] Iniciando $total targets restantes (max $MAX_PARALLEL paralelo) — $(date)" | tee -a "$LOG_MAIN"
echo "[generali-resume] SPA-skip activo en mods 21,23,28,34,37,49 + WAF block en mod 20" | tee -a "$LOG_MAIN"

pids=()

run_target() {
  local domain="$1" target="$2" n="$3"
  local log="$LOG_DIR/${target}.log"
  echo "[+] [$n/$total] [resume] Iniciando $target  (base: $domain)" | tee -a "$LOG_MAIN"
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

echo "[generali-resume] Esperando últimos procesos..." | tee -a "$LOG_MAIN"
wait

echo "" | tee -a "$LOG_MAIN"
echo "[generali-resume] DONE — $(date)" | tee -a "$LOG_MAIN"

# Resumen
echo "" | tee -a "$LOG_MAIN"
echo "=== FINDINGS GENERALI (RESUME) ===" | tee -a "$LOG_MAIN"
sqlite3 "$SCRIPT_DIR/data/recon.db" \
  "SELECT f.severity, COUNT(*) FROM findings f
   JOIN domains d ON f.domain_id = d.id
   WHERE d.domain IN ('generali.fr','lamedicale.fr','apigee.net')
   GROUP BY f.severity;" 2>/dev/null | tee -a "$LOG_MAIN" || true
