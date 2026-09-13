#!/usr/bin/env bash
set -euo pipefail

# WWFI certificate renewal / key rotation.
#
# 1. Renews certificates via Certbot (ACME) when they need renewal.
# 2. Rotates new certificates + keys into the WWFI cert dir with timestamped backups.
# 3. Reloads nginx/caddy so new certs are picked up.
#
# Rollback (restore previous certificate):
#   sudo mv certs/backups/<domain>-<timestamp>.pem certs/<domain>.crt
#   sudo cp certs/backups/<domain>-<timestamp>.key certs/<domain>.key   (if kept)
#   sudo nginx -s reload
#
# Usage:
#   scripts/rotate_certificates.sh [--renew-always] [--cert-dir DIR]
#   scripts/rotate_certificates.sh list

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${CERT_DIR:-$ROOT/certs}"
BACKUP_DIR="$CERT_DIR/backups"
RENEW_ALWAYS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --renew-always) RENEW_ALWAYS=1; shift ;;
    --cert-dir) CERT_DIR="$2"; BACKUP_DIR="$CERT_DIR/backups"; shift 2 ;;
    list)
      echo "Installed certificates:"
      for f in "$CERT_DIR"/*.crt; do
        [[ -f "$f" ]] || continue
        printf "  %-28s expires %s\n" "$(basename "$f")" "$(openssl x509 -in "$f" -noout -enddate | cut -d= -f2)"
      done
      echo "Backups in $BACKUP_DIR:"
      ls -1 "$BACKUP_DIR" 2>/dev/null | sed 's/^/  /' || echo "  (none)"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

mkdir -p "$CERT_DIR" "$BACKUP_DIR"

command -v certbot >/dev/null 2>&1 || { echo "certbot not installed; skipping ACME renewal."; }

needs_renewal() {
  local domain="$1"
  [[ "$RENEW_ALWAYS" -eq 1 ]] && return 0
  [[ -f "$CERT_DIR/$domain.crt" ]] || return 0
  local remaining
  remaining=$(openssl x509 -in "$CERT_DIR/$domain.crt" -noout -checkend 2592000 && echo ok || echo renew)
  [[ "$remaining" != "ok" ]]
}

rotate_domain() {
  local domain="$1"
  if ! needs_renewal "$domain"; then
    echo "[rotate] $domain certificate is valid for more than 30 days; skipped"
    return 0
  fi
  echo "[rotate] renewing $domain"
  sudo certbot renew --cert-name "$domain" 2>/dev/null || sudo certbot certonly --standalone -d "$domain" --keep-until-expiring --agree-tos --non-interactive --email whee || true

  local main="${domain#\*.}"
  if [[ ! -f "/etc/letsencrypt/live/$main/fullchain.pem" ]]; then
    echo "[rotate] no new certificate available for $domain" >&2
    return 1
  fi

  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  if [[ -f "$CERT_DIR/$main.crt" ]]; then
    cp "$CERT_DIR/$main.crt" "$BACKUP_DIR/$main-$stamp.crt"
  fi
  if [[ -f "$CERT_DIR/$main.key" ]]; then
    cp "$CERT_DIR/$main.key" "$BACKUP_DIR/$main-$stamp.key"
  fi
  sudo install -m 0644 "/etc/letsencrypt/live/$main/fullchain.pem" "$CERT_DIR/$main.crt"
  sudo install -m 0600 "/etc/letsencrypt/live/$main/privkey.pem" "$CERT_DIR/$main.key"
  echo "[rotate] rotated $main -> backup $main-$stamp"
}

for crt in "$CERT_DIR"/*.crt; do
  [[ -f "$crt" ]] || continue
  domain="$(basename "$crt" .crt)"
  rotate_domain "$domain"
done

if command -v nginx >/dev/null 2>&1; then
  nginx -t && (nginx -s reload || systemctl reload nginx || service nginx reload || true)
fi
if command -v caddy >/dev/null 2>&1; then
  systemctl reload caddy || true
fi

echo "[rotate] complete. Inspect with: scripts/rotate_certificates.sh list"