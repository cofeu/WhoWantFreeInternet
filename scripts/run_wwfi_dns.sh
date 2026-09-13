#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="/tmp/wwfi-dns"
RECORDS=(
  "demo.local=127.0.0.1:8443"
  "shop.local=127.0.0.1:8080"
)

cd "$ROOT_DIR"
. .venv/bin/activate
PYTHONPATH=src python -m wwfi.dns_service --output-dir "$OUTPUT_DIR" ${RECORDS[@]/#/--record } >/tmp/wwfi-dns.log 2>&1

mkdir -p /etc/dnsmasq.d
cat > /etc/dnsmasq.d/wwfi.conf <<'EOF'
address=/demo.local/127.0.0.1
address=/shop.local/127.0.0.1
EOF

systemctl restart dnsmasq || service dnsmasq restart || echo "dnsmasq not installed or not running; use the generated /tmp/wwfi-dns files manually"

printf 'WWFI DNS generated to %s\n' "$OUTPUT_DIR"
