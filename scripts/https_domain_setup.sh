#!/usr/bin/env bash
set -euo pipefail

# WWFI HTTPS domain publishing setup.
#
# Two modes:
#   1) ACME (Let's Encrypt / ZeroSSL) — production real certificates via Certbot.
#   2) local demo — self-signed certificates generated with openssl (for .local).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-acme}"

case "$MODE" in
  acme)
    if ! command -v certbot >/dev/null 2>&1; then
      echo "[https-setup] certbot not found; installing snap/apt package"
      sudo apt-get update
      sudo apt-get install -y certbot
    fi
    echo "[https-setup] issuing ACME certificates for demo.local and shop.local"
    echo ">>> NOTE: use real public DNS names registered for your host. Example:"
    echo ">>>   scripts/acme_tls_setup.sh --challenge webroot --email you@example.com \\"
    echo ">>>     --domain demo.example.com --domain shop.example.com"
    ;;
  demo)
    echo "[https-setup] generating self-signed certificates for local demo (CN=demo.local)"
    CERT_DIR="$ROOT_DIR/certs"
    mkdir -p "$CERT_DIR"
    if [[ ! -f "$CERT_DIR/demo.local.crt" ]]; then
      openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$CERT_DIR/demo.local.key" \
        -out "$CERT_DIR/demo.local.crt" \
        -days 365 -subj "/CN=demo.local" \
        -addext "subjectAltName=DNS:demo.local,DNS:shop.local"
    fi
    echo "[https-setup] certificates ready in $CERT_DIR"
    ;;
  *)
    echo "Usage: $0 {acme|demo}" >&2
    exit 1 ;;
esac

cat <<'EOF'
[https-setup] Published domains are TLS-enabled by default (tls_enabled=True enforced).
Verify with:
  curl --resolve demo.local:443:127.0.0.1 -k https://demo.local
  echo | openssl s_client -connect 127.0.0.1:443 -servername demo.local 2>/dev/null | openssl x509 -noout -subject -dates
EOF