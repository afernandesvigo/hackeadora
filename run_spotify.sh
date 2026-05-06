#!/usr/bin/env bash
# ============================================================
#  Batch paralelo — Spotify Bug Bounty (público)
#  Todos los dominios se escanean simultáneamente.
#  Cada dominio escribe su propio log en output/<domain>/.
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BATCH_LOG="$SCRIPT_DIR/output/batch_spotify_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$SCRIPT_DIR/output"

# ── Targets ────────────────────────────────────────────────
# Formato: "domain|target"
#   domain = dominio base (para DB y módulo 01 de enumeración)
#   target = vacío → scan completo; valor → --target=<value> (single-target)
declare -a TARGETS=(
  "eyeofthestormers.com|"
  "lifeatspotify.com|"
  "sonalytic.com|"
  "spotify.design|"
  "spotifycharts.com|"
  "spotifycodes.com|"
  "spotifycs.my.salesforce.com|spotifycs.my.salesforce.com"
  "spotifyforpartners.com|"
  "spotifyforvendors.com|"
  "spotifynewsroom.jp|"
  "spotifyonstage.com|"
  "spotifyvault.com|"
  "timetoplayfair.com|"
)

TOTAL=${#TARGETS[@]}
echo "[spotify] Lanzando $TOTAL targets en paralelo — $(date)" | tee -a "$BATCH_LOG"
echo "[spotify] Log maestro: $BATCH_LOG" | tee -a "$BATCH_LOG"

declare -A PIDS

# ── Lanzar todos en paralelo ───────────────────────────────
for ENTRY in "${TARGETS[@]}"; do
  IFS='|' read -r DOMAIN TARGET_SUB <<< "$ENTRY"

  DOM_LOG="$SCRIPT_DIR/output/${DOMAIN}/recon_batch.log"
  mkdir -p "$SCRIPT_DIR/output/${DOMAIN}"

  if [[ -n "$TARGET_SUB" ]]; then
    echo "[spotify] ▶ $DOMAIN  (--target=$TARGET_SUB)" | tee -a "$BATCH_LOG"
    bash "$SCRIPT_DIR/recon.sh" "$DOMAIN" "--target=$TARGET_SUB" \
      >> "$DOM_LOG" 2>&1 &
  else
    echo "[spotify] ▶ $DOMAIN  (scan completo)" | tee -a "$BATCH_LOG"
    bash "$SCRIPT_DIR/recon.sh" "$DOMAIN" \
      >> "$DOM_LOG" 2>&1 &
  fi

  PIDS["$DOMAIN"]=$!
done

echo "" | tee -a "$BATCH_LOG"
echo "[spotify] Todos lanzados. Esperando finalización..." | tee -a "$BATCH_LOG"

# ── Esperar y reportar estado de cada uno ─────────────────
FAILED=()
for DOMAIN in "${!PIDS[@]}"; do
  PID=${PIDS[$DOMAIN]}
  if wait "$PID"; then
    echo "[spotify] ✓ $DOMAIN — completado" | tee -a "$BATCH_LOG"
  else
    echo "[spotify] ✗ $DOMAIN — terminó con error (revisar output/${DOMAIN}/recon_batch.log)" | tee -a "$BATCH_LOG"
    FAILED+=("$DOMAIN")
  fi
done

echo "" | tee -a "$BATCH_LOG"
if [[ ${#FAILED[@]} -eq 0 ]]; then
  echo "[spotify] BATCH COMPLETADO SIN ERRORES — $(date)" | tee -a "$BATCH_LOG"
else
  echo "[spotify] BATCH COMPLETADO CON ERRORES en: ${FAILED[*]} — $(date)" | tee -a "$BATCH_LOG"
fi

echo "[spotify] Logs individuales en output/<domain>/recon_batch.log"
