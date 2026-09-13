# WWFI Operations

Quick operational guide for the tools shipped in this repository.

## Contents

1. [Admin dashboard](#admin-dashboard)
2. [Metrics & monitoring](#metrics--monitoring)
3. [ACME TLS + reverse proxy](#acme-tls--reverse-proxy)
4. [DNS over TLS/HTTPS](#dns-over-tls-https)
5. [Certificates](#certificates)
6. [Local demo with Docker](#local-demo-with-docker)
7. [systemd & cloud-init](#systemd--cloud-init)
8. [OCI with Terraform](#oci-with-terraform)
9. [Local DNS via install.sh](#local-dns-via-installsh)
10. [HTTPS demo server + CA-signed certs](#https-demo-server--ca-signed-certs)

---

## Admin dashboard

```bash
WWFI_TOKEN="change-me" python scripts/dashboard_server.py --host 0.0.0.0 --port 8087
```

Endpoints:

| Endpoint        | Auth   | Description                          |
|-----------------|--------|--------------------------------------|
| `/`             | token  | Dashboard UI                         |
| `/api/domains`  | token  | Published domain + backend + version |
| `/api/records`  | token  | Local DNS records                    |
| `/api/certs`    | token  | Certificate fingerprints + expiry    |
| `/api/metrics`  | token  | Prometheus text metrics              |
| `/api/health`   | public | Liveness probe                       |

Auth: `Authorization: Bearer <token>` or `?token=<token>`. The dashboard
assembles state from `SiteRegistry`, `LocalDNS`, and `CertificateManager`
(see `wwfi.dashboard.DashboardState`).

---

## Metrics & monitoring

```bash
python scripts/metrics_server.py --host 0.0.0.0 --port 9090
curl http://127.0.0.1:9090/metrics
```

- `monitoring/prometheus.yml` — scrape config for the endpoint
- `monitoring/wwfi-alerts.yml` — alert rules (expiring/expired certs, rejected sessions, node down)
- `monitoring/grafana-dashboard.json` — import into Grafana
- `scripts/healthcheck.sh` — systemd/container health check against `/metrics`

Exported series: `wwfi_published_domains`, `wwfi_active_sessions`,
`wwfi_rejected_sessions_total`, `wwfi_cert_days_remaining`,
`wwfi_cert_expiring`. The exporter is stdlib-only (no `prometheus_client`).

---

## ACME TLS + reverse proxy

Issue a certificate:

```bash
scripts/https_domain_setup.sh acme                 # installs certbot if missing
scripts/acme_tls_setup.sh --challenge webroot --email you@example.com \
  --domain demo.example.com --domain shop.example.com
```

Generate SNI vhosts (single IP, many domains):

```bash
scripts/generate_reverse_proxy.sh --reload \
  demo.example.com=127.0.0.1:8000 \
  shop.example.com=127.0.0.1:8080

scripts/generate_reverse_proxy.sh --engine caddy demo.example.com=127.0.0.1:8000
```

Verify:

```bash
curl --resolve demo.example.com:443:127.0.0.1 https://demo.example.com
echo | openssl s_client -connect 127.0.0.1:443 -servername demo.example.com 2>/dev/null \
  | openssl x509 -noout -subject -dates
```

Caddy auto-issues and renews its own ACME certificates (`configs/Caddyfile`).

---

## DNS over TLS/HTTPS

```bash
sudo scripts/setup_doh_dot.sh dot    # stubby (DoT)
sudo scripts/setup_doh_dot.sh doh    # cloudflared (DoH)

dig @127.0.0.1 demo.local +short       # local WWFI name, still works
dig @127.0.0.1 example.com             # forwarded, encrypted end-to-end
# dig @127.0.0.1 demo.local +https     # native DoH where supported
```

See `docs/doh-dot.md` for details.

---

## Certificates

```bash
scripts/rotate_certificates.sh            # renew only what's due
scripts/rotate_certificates.sh --renew-always
scripts/rotate_certificates.sh list       # expiry + backups

sudo cp systemd/wwfi-cert-renew.service systemd/wwfi-cert-renew.timer /etc/systemd/system/
sudo systemctl enable --now wwfi-cert-renew.timer
```

Rollback: restore `certs/backups/<domain>-<stamp>.{crt,key}` and reload nginx/caddy.
See `docs/certificate-lifecycle.md`.

---

## Local demo with Docker

```bash
docker compose up --build

# demo backend
curl http://127.0.0.1:8000
# metrics
curl http://127.0.0.1:9090/metrics
# dashboard (token: WWFI_TOKEN env, default demo-token)
curl -H "Authorization: Bearer demo-token" http://127.0.0.1:8087/api/domains
# local DNS
dig @127.0.0.1 demo.local +short
```

Compose runs `wwfi` (demo + metrics + dashboard), `dnsmasq` (ports 53/5380),
and `nginx` (ports 80/443 with the generated SNI sites from `configs/`).

---

## systemd & cloud-init

```bash
sudo cp systemd/wwfi-dns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wwfi-dns
```

`cloud-init.yaml` is the OCI/cloud-init user-data: it installs packages,
clones the repo, runs `scripts/install.sh`, registers `wwfi-dns.service`,
and generates the nginx reverse proxy sites.

---

## OCI with Terraform

```bash
cd terraform
export TF_VAR_tenancy_ocid="..."
 export TF_VAR_compartment_ocid="..."
 export TF_VAR_ssh_public_key="$(cat ~/.ssh/id_ed25519.pub)"
 terraform init && terraform apply
 ssh ubuntu@"$(terraform output -raw public_ip)"
 ```

## Local DNS via install.sh

`bash scripts/install.sh` writes WWFI address records to `/etc/dnsmasq.d/wwfi.conf`
(`demo.local`, `shop.local`, `cofeu.org` -> `127.0.0.1` by default) and **restarts
dnsmasq** so they take effect. On first run it also generates the WWFI root CA
(`certs/ca.crt` + `certs/ca.key`) and installs it into the system trust store and
the NSS database. Override domains/addresses:

```bash
WWFI_DOMAINS="shop.local=10.0.0.5 internal.wwfi=10.0.0.9" bash scripts/install.sh
```

Extra `address=/domain/ip` lines can be added in `configs/dnsmasq-records.conf`
(merged automatically). What the installer deliberately does **not** touch, so
existing networking is never broken:

- `/etc/resolv.conf` / systemd-resolved configuration
- DHCP serving (dnsmasq runs in plain caching-DNS mode)
- upstream port-forwarding: unknown queries still go to the previous resolvers

Clients on the LAN resolve WWFI domains automatically once a router delivers the
WWFI host as DNS (DHCP option 6) or its address is set in NetworkManager.
Remove everything applied by reinstalling DNS state:

```bash
bash scripts/install.sh --uninstall
```

## HTTPS demo server + CA-signed certs

`scripts/https_serve.py` serves a directory over HTTPS for a local domain and
**issues the certificate itself**:

```bash
python scripts/https_serve.py --domain cofeu.org --port 8443          # CA  = WWFI Local Root CA
python scripts/https_serve.py --domain demo.local --port 9443 --dir www
python scripts/https_serve.py --domain cofeu.org --reissue            # force new cert
```

- If `certs/ca.key` + `certs/ca.crt` exist, the issued certificate is signed by
  the WWFI root CA, so trusting `certs/ca.crt` once unlocks every domain.
- If the CA keys are missing, it falls back to a self-signed certificate.
- A systemd service for the standard demo is provided in
  `systemd/wwfi-https-443.service` (`https://cofeu.org` on :443, serves the repo
  root so `test.html` is reachable):

```bash
sudo cp systemd/wwfi-https-443.service /etc/systemd/system/
sudo systemctl enable --now wwfi-https-443
echo '127.0.0.1 cofeu.org' | sudo tee -a /etc/hosts   # only if not resolved via dnsmasq
```

Verify the served chain:

```bash
echo | openssl s_client -connect 127.0.0.1:443 -servername cofeu.org 2>/dev/null \
  | openssl x509 -noout -issuer    # CN = WWFI Local Root CA
```

See `terraform/README.md`.