# WWFI Certificate Lifecycle & Key Rotation

WWFI treats certificates as renewable resources, not static files. The
`CertificateManager` (`src/wwfi/certs.py`) tracks state, while
`scripts/rotate_certificates.sh` drives ACME renewal and rotation on disk.

## State tracking (`src/wwfi/certs.py`)

| Feature | API |
|---|---|
| Register a certificate | `CertificateManager.register(cert_pem, domain=...)` |
| Reports `True` when renewal is due | `manager.needs_renewal(domain, days_before=30)` |
| Load new cert and archive the old one | `manager.rotate(domain, new_cert_pem, new_path=...)` |
| Restore the most recent backup | `manager.rollback(domain)` |
| List all tracked certs | `manager.list_certificates()` |

Rotation always stores a copy of the previous certificate (and key, when the
shell script is used) under `certs/backups/<domain>-<timestamp>.{crt,key}`.

## Automated renewal

### Certbot + systemd-timer (recommended)

```bash
sudo cp systemd/wwfi-dns.service systemd/wwfi-cert-renew.service \
        systemd/wwfi-cert-renew.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wwfi-cert-renew.timer
```

The timer runs the renewal twice a day; certbot renews only when close to
expiry, and the rotate script reloads nginx/caddy afterwards.

### Manual run

```bash
scripts/rotate_certificates.sh                 # renew only expiring certs
scripts/rotate_certificates.sh --renew-always  # force renewal
scripts/rotate_certificates.sh list            # show expiry dates + backups
```

### Cron alternative

```cron
0 3 * * *  root  /opt/wwfi/scripts/rotate_certificates.sh >> /var/log/wwfi-certs.log 2>&1
```

## Key rotation (new CA / new key)

1. Generate a fresh key and certificate (ACME creates both):

   ```bash
   sudo certbot certonly --standalone -d demo.example.com --renew-by-default
   ```

2. Rotate into place (keeps a backup):

   ```bash
   bash scripts/rotate_certificates.sh --renew-always
   ```

3. For client-certs (mTLS), rotate the client CA key and re-issue client certs:

   ```bash
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
     -keyout certs/ca.key -out certs/ca.crt -days 3650 -nodes -subj "/CN=WWFI CA"
   ```

## Rollback

If a rotated certificate breaks a service:

```bash
# 1. Find the backup
ls certs/backups/

# 2. Restore (example for demo.local, timestamp 20260913T030000Z)
sudo cp certs/backups/demo.local-20260913T030000Z.crt certs/demo.local.crt
sudo cp certs/backups/demo.local-20260913T030000Z.key certs/demo.local.key

# 3. Reload the TLS termination layer
sudo nginx -s reload        # nginx
sudo systemctl reload caddy # caddy

# 4. Verify
curl --resolve demo.local:443:127.0.0.1 -k https://demo.local
```

Programmatically the same flow is `manager.rotate(...)` then `manager.rollback(...)`,
covered by `tests/test_cert_lifecycle.py`.

## Monitoring

The metrics endpoint exposes `wwfi_cert_days_remaining` and
`wwfi_cert_expiring`; alert `WWFICertificateExpiring` and
`WWFICertificateExpired` fire from `monitoring/wwfi-alerts.yml`.