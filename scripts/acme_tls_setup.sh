#!/usr/bin/env bash
set -euo pipefail

# WWFI ACME/TLS setup with Certbot (Let's Encrypt / ZeroSSL).
#
# Usage:
#   acme_tls_setup.sh --challenge http01|webroot --email YOU@EXAMPLE.COM --domain a.example.com [--domain b.example.com] [--webroot /var/www/html]
#   acme_tls_setup.sh --challenge dns01 --email YOU@EXAMPLE.COM --domain *.example.com
#
# The challenge types:
#   http01   - requires port 80 reachable (certbot standalone)
#   webroot  - nginx/Caddy serves /.well-known/acme-challenge from a webroot
#   dns01    - DNS TXT record; recommended for wildcard / .local-style names

EMAIL=""
MODE="http01"
WEBROOT=""
DOMAINS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --email) EMAIL="$2"; shift 2 ;;
    --challenge) MODE="$2"; shift 2 ;;
    --webroot) WEBROOT="$2"; shift 2 ;;
    --domain) DOMAINS+=("$2"); shift 2 ;;
    *) echo "ERROR: unknown argument '$1'" >&2; exit 1 ;;
  esac
done

if [[ -z "$EMAIL" || ${#DOMAINS[@]} -eq 0 ]]; then
  echo "ERROR: --email and at least one --domain are required" >&2
  echo "Usage: acme_tls_setup.sh --challenge http01|webroot|dns01 --email YOU@EXAMPLE.COM --domain app.example.com" >&2
  exit 1
fi

LIVE_DIR="/etc/letsencrypt/live"
DOMAIN_ARGS=()
CERT_ARGS=()
for d in "${DOMAINS[@]}"; do
  DOMAIN_ARGS+=("-d" "$d")
  CERT_ARGS+=("$d")
done

case "$MODE" in
  http01)
    echo "[acme] requesting certificate with standalone HTTP-01"
    sudo certbot certonly --standalone --keep-until-expiring --agree-tos \
      --email "$EMAIL" "${DOMAIN_ARGS[@]}"
    ;;
  webroot)
    if [[ -z "$WEBROOT" ]]; then
      echo "ERROR: --webroot is required for webroot challenge" >&2
      exit 1
    fi
    echo "[acme] requesting certificate with webroot challenge"
    sudo certbot certonly --webroot --webroot-path "$WEBROOT" --keep-until-expiring \
      --agree-tos --email "$EMAIL" "${DOMAIN_ARGS[@]}"
    ;;
  dns01)
    echo "[acme] requesting certificate with DNS-01 challenge"
    echo ">>> Add TXT records below when prompted (create the record, then press Enter)."
    sudo certbot certonly --manual --preferred-challenges dns --agree-tos \
      --email "$EMAIL" "${DOMAIN_ARGS[@]}"
    ;;
  *)
    echo "ERROR: unknown challenge type '$MODE'" >&2
    exit 1 ;;
esac

echo "[acme] copy issued certificates into the WWFI cert dir"
CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/certs"
mkdir -p "$CERT_DIR"
for d in "${CERT_ARGS[@]}"; do
  main="${d#\*.}"
  sudo install -m 0644 "$LIVE_DIR/$main/fullchain.pem" "$CERT_DIR/$main.crt"
  sudo install -m 0600 "$LIVE_DIR/$main/privkey.pem" "$CERT_DIR/$main.key"
  echo "[acme] installed $CERT_DIR/$main.crt and $CERT_DIR/$main.key"
done

echo "[acme] verify with:"
for d in "${DOMAINS[@]}"; do
  echo "  curl --resolve $d:443:127.0.0.1 https://$d"
  echo "  echo | openssl s_client -connect 127.0.0.1:443 -servername $d 2>/dev/null | openssl x509 -noout -subject -dates"
done