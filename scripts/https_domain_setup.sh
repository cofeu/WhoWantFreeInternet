#!/usr/bin/env bash
set -euo pipefail

# WWFI HTTPS publishing — the operator CHOOSES the SSL source per domain:
#
#   acme          real Let's Encrypt / ZeroSSL certificate. Requires a publicly
#                 resolvable DNS name + port 80 reachable (http01) or TXT access
#                 (dns01). USE THIS FOR THE PUBLIC NET. (cofeu.org is not on
#                 public DNS — it cannot pass ACME validation from this machine.)
#   ca            default. Issued against the WWFI Local Root CA (certs/ca.*).
#                 Trusted by any device importing certs/ca.crt (Firefox, an
#                 Android CA profile, etc.); ideal for the private net.
#   self-signed   zero-trust-dev fallback: openssl -x509, no CA involved.
#
# Usage:
#   scripts/https_domain_setup.sh acme      demo.example.com shop.example.com
#   scripts/https_domain_setup.sh ca        cofeu.org
#   scripts/https_domain_setup.sh self-signed cofeu.org

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="$ROOT_DIR/certs"
MODE="${1:?Usage: https_domain_setup.sh acme|ca|self-signed + domain list}"
shift || true

if [[ "$MODE" != "ca" && "$MODE" != "acme" && "$MODE" != "self-signed" ]]; then
  echo "ERROR: mode must be one of {acme|ca|self-signed}" >&2
  exit 1
fi

if [[ ${#@} -eq 0 ]]; then
  echo "ERROR: supply at least one domain" >&2
  exit 1
fi
DOMAINS=("$@")

case "$MODE" in
  acme)
    if ! command -v certbot >/dev/null 2>&1; then
      echo "[https-setup] certbot not found; installing via apt"
      sudo apt-get update
      sudo apt-get install -y certbot
    fi
    echo "[https-setup] ACME mode selected — requires a PUBLIC domain (not cofeu.org/.local)."
    read -rp "Let's Encrypt contact e-mail: " EMAIL
    read -rp "Challenge type [http01|webroot|dns01]: " CHALLENGE
    CHALLENGE="${CHALLENGE:-http01}"
    ARGS=("--challenge" "$CHALLENGE" "--email" "$EMAIL")
    for d in "${DOMAINS[@]}"; do
      ARGS+=("--domain" "$d")
    done
    if [[ "$CHALLENGE" == "webroot" ]]; then
      read -rp "Webroot path (e.g. /var/www/html): " WEBROOT
      ARGS+=("--webroot" "$WEBROOT")
    fi
    exec "$ROOT_DIR/scripts/acme_tls_setup.sh" "${ARGS[@]}"
    ;;
  ca)
    mkdir -p "$CERT_DIR"
    if [[ ! -f "$CERT_DIR/ca.key" || ! -f "$CERT_DIR/ca.crt" ]]; then
      echo "[https-setup] creating WWFI Local Root CA in $CERT_DIR"
      openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
        -days 3650 -subj "/CN=WWFI Local Root CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
    fi
    for d in "${DOMAINS[@]}"; do
      echo "[https-setup] issuing CA-signed cert for $d"
      python3 "$ROOT_DIR/scripts/https_serve.py" --domain "$d" --tls-mode ca --issue-only
    done
    echo "[https-setup] certs ready in $CERT_DIR — import $CERT_DIR/ca.crt as a trusted
      root on every client (Firefox: Settings -> Certificates; Android: CA
      certificate profile; system: install to /usr/local/share/ca-certificates)."
    ;;
  self-signed)
    for d in "${DOMAINS[@]}"; do
      echo "[https-setup] generating self-signed cert for $d"
      python3 "$ROOT_DIR/scripts/https_serve.py" --domain "$d" --tls-mode self-signed --issue-only
    done
    echo "[https-setup] self-signed certs ready in $CERT_DIR/self-signed — verify with -k."
    ;;
esac