#!/usr/bin/env bash
set -euo pipefail

# WWFI healthcheck for the metrics endpoint (used by systemd and monitoring).
# Exits 0 when the service is healthy, 1 otherwise.
# Usage: healthcheck.sh [endpoint-url]
URL="${1:-http://127.0.0.1:9090/metrics}"
TIMEOUT="${HTTP_TIMEOUT:-3}"

for metric in "wwfi_published_domains" "wwfi_active_sessions"; do
  if ! curl -fsS --max-time "$TIMEOUT" "$URL" | grep -q "^$metric "; then
    echo "[wwfi-health] missing metric: $metric" >&2
    exit 1
  fi
done

echo "[wwfi-health] ok"
exit 0