#!/usr/bin/env bash
set -euo pipefail

# Start the WWFI demo, metrics, and admin dashboard services together.

WWFI_PORT="${WWFI_PORT:-8000}"
METRICS_PORT="${METRICS_PORT:-9090}"
DASHBOARD_PORT="${DASHBOARD_PORT:-8087}"
WWFI_TOKEN="${WWFI_TOKEN:-demo-token}"

echo "[wwfi] starting demo site on :$WWFI_PORT"
python /opt/wwfi/scripts/demo_backend.py --port "$WWFI_PORT" &

echo "[wwfi] starting metrics endpoint on :$METRICS_PORT"
python /opt/wwfi/scripts/metrics_server.py --host 0.0.0.0 --port "$METRICS_PORT" --registry-file /data/config/registry.json &

echo "[wwfi] starting admin dashboard on :$DASHBOARD_PORT"
WWFI_TOKEN="$WWFI_TOKEN" python /opt/wwfi/scripts/dashboard_server.py --host 0.0.0.0 --port "$DASHBOARD_PORT" &

trap 'kill $(jobs -p) 2>/dev/null || true' EXIT
wait