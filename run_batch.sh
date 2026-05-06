#!/usr/bin/env bash
# Batch scan — run sequentially, notify on completion
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$SCRIPT_DIR/output/batch_icann_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$SCRIPT_DIR/output"

targets=(
  "reverse-servers.org|www.reverse-servers.org"
  "internic.net|www.internic.net"
  "icann.org|www.icann.org"
  "iana.org|www.iana.org"
  "icann.org|www.dns.icann.org"
  "icann.org|whois.icann.org"
  "icann.org|webrdapct.icann.org"
  "icann.org|travelrequestform.icann.org"
  "icann.org|travelrequest-api.icann.org"
  "icann.org|transform-url.icann.org"
  "iana.org|tools.iana.org"
  "icann.org|tally.icann.org"
  "icann.org|stats.research.icann.org"
  "icann.org|stats.dns.icann.org"
  "iana.org|sle-dashboard.iana.org"
)

total=${#targets[@]}
echo "[batch] Iniciando $total targets — $(date)" | tee -a "$LOG"

for i in "${!targets[@]}"; do
  IFS='|' read -r domain target <<< "${targets[$i]}"
  n=$((i+1))
  echo "" | tee -a "$LOG"
  echo "════════════════════════════════════════════════" | tee -a "$LOG"
  echo "[$n/$total] $target  (dominio base: $domain)" | tee -a "$LOG"
  echo "════════════════════════════════════════════════" | tee -a "$LOG"
  bash "$SCRIPT_DIR/recon.sh" "$domain" --target="$target" 2>&1 | tee -a "$LOG" || \
    echo "[!] recon.sh salió con error en $target" | tee -a "$LOG"
done

echo "" | tee -a "$LOG"
echo "[batch] TODOS LOS TARGETS COMPLETADOS — $(date)" | tee -a "$LOG"
echo "[batch] Log completo: $LOG"
