#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="$SCRIPT_DIR/output/batch_rocketmoney_${TIMESTAMP}"
mkdir -p "$LOG_DIR"
LOG_MAIN="$LOG_DIR/batch.log"

MAX_PARALLEL="${MAX_PARALLEL:-3}"
export MAX_PORT_PARALLEL="${MAX_PORT_PARALLEL:-2}"

targets=(
  "rocketmoney.dev|app.rocketmoney.dev"
  "rocketmoney.dev|client-api.rocketmoney.dev"
  "rocketmoney.dev|secure-api.rocketmoney.dev"
  "rocketmoney.dev|secure-api.admin.rocketmoney.dev"
  "rocketmoney.dev|admin.rocketmoney.dev"
  "rocketmoney.dev|ai.rocketmoney.dev"
  "rocketmoney.dev|rewards.rocketmoney.dev"
  "rocketmoney.dev|webhooks.rocketmoney.dev"
  "rocketmoney.dev|test.rocketmoney.dev"
  "rocketmoney.dev|www.rocketmoney.dev"
)

total=${#targets[@]}
echo "[rocketmoney-batch] Iniciando $total targets (max $MAX_PARALLEL paralelo) — $(date)" | tee "$LOG_MAIN"
echo "[rocketmoney-batch] LOG_DIR: $LOG_DIR" | tee -a "$LOG_MAIN"

pids=()

run_target() {
  local domain="$1" target="$2" n="$3"
  local log="$LOG_DIR/${target}.log"
  echo "[+] [$n/$total] Iniciando $target" | tee -a "$LOG_MAIN"
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
      kill -0 "$pid" 2>/dev/null && new_pids+=("$pid")
    done
    pids=("${new_pids[@]}")
    [[ ${#pids[@]} -ge $MAX_PARALLEL ]] && sleep 5
  done
  run_target "$domain" "$target" "$n" &
  pids+=($!)
done

wait
echo "[rocketmoney-batch] DONE — $(date)" | tee -a "$LOG_MAIN"
