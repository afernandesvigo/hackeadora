#!/usr/bin/env bash
# ============================================================
#  web/start.sh — Arranca el dashboard de ReconFlow
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

# Cargar config para DB_PATH y OUTPUT_BASE
source "$ROOT/config.env" 2>/dev/null || true

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8080}"

echo "───────────────────────────────────────"
echo "  ReconFlow Dashboard"
echo "  http://${HOST}:${PORT}"
echo "───────────────────────────────────────"

# Instalar dependencias Python si faltan
pip3 install fastapi uvicorn --break-system-packages -q 2>/dev/null \
  || pip3 install fastapi uvicorn -q 2>/dev/null \
  || true

export RECONFLOW_DB="${DB_PATH:-$ROOT/data/recon.db}"
export RECONFLOW_OUTPUT="${OUTPUT_BASE:-$ROOT/output}"

cd "$SCRIPT_DIR"
exec uvicorn app:app \
  --host "$HOST" \
  --port "$PORT" \
  --workers 1 \
  --log-level warning
