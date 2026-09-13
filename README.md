# WWFI — WhoWantFreeInternet

WWFI is a local-first, security-first, self-hosted network platform prototype. It provides:

- encrypted local DNS
- private identity-based routing (CIP / NIP)
- local AI policy decisions
- protected site publishing
- secure, domain-driven access without depending on public internet exposure

The core principle:

- IP addresses are not trust
- identity and encryption are trust
- ports are not public doors by default
- every domain is published behind a protected route

---

## Quick start

### Option A — full local install (DNS + CA trust)

**Linux / macOS** (bash):

```bash
git clone https://github.com/cofeu/WhoWantFreeInternet.git
cd WhoWantFreeInternet

bash scripts/install.sh
```

- **Linux**: installs/configures `dnsmasq`, generates the **WWFI Local Root CA**
  if missing, installs it into the system trust store and NSS db, restarts
  dnsmasq so records apply without rebooting, and never touches
  `/etc/resolv.conf`, DHCP serving, or upstream forwarding.
- **macOS**: uses Homebrew for `dnsmasq`, binds it via `brew services`
  (as root so it can open port 53), points macOS resolvers at `127.0.0.1`
  (`networksetup`, original DNS saved to `.dns_wwfi_backup`), and installs the
  CA into the **system Keychain** (`security add-trusted-cert`) — Safari, Chrome,
  and curl all trust every WWFI domain after one command.

**Windows** (PowerShell, run as Administrator):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/install.ps1
```

Maps WWFI domains in the hosts file and adds the CA to the Windows **Root**
certificate store (`certutil.exe`) — Edge/Chrome/IE trust all WWFI domains.

Remove everything an installer applied:

```bash
bash scripts/install.sh --uninstall
# or Windows:
powershell -ExecutionPolicy Bypass -File scripts/install.ps1 -Uninstall
```

> Windows note: the hosts file maps exact names (no wildcards/ports). For a real
> local DNS server on Windows use WSL2 (`bash scripts/install.sh` inside WSL) or
> a DNS proxy such as Acrylic. macOS/Linux get a full dnsmasq resolver.

### Option B — Docker demo

```bash
docker compose up -d
```

Runs the demo backend, Prometheus metrics, and the Flask admin dashboard
with no host-side changes.

---

## Certificates & trust model (one CA, every domain)

WWFI uses a single local **root CA** (`certs/ca.crt`, `CN=WWFI Local Root CA`).
Every site certificate is signed by this CA — including automatically by
`scripts/https_serve.py` (if `certs/ca.key` exists, it signs with the CA instead
of falling back to self-signed).

Trust the CA **once** and every WWFI-signed domain is trusted automatically —
`cofeu.org`, `demo.local`, and any future domain:

| Store                          | Who reads it                                  | How it is installed                       |
| ------------------------------ | --------------------------------------------- | ---------------------------------------- |
| System (`/usr/local/share/ca-certificates`) | curl, git, Python, Docker (Linux)             | `scripts/install.sh` (automatic)         |
| NSS (`~/.pki/nssdb`)           | Chromium-based browsers, NSS tools (Linux)    | `scripts/install.sh` (automatic)         |
| macOS system Keychain          | Safari, Chrome, curl, most macOS apps         | `scripts/install.sh` (automatic)         |
| Windows Root store             | Edge, Chrome, IE (Windows)                    | `scripts/install.ps1` (automatic)        |
| Google Chrome (own root store) | google-chrome on Linux                        | one-time `chrome://settings/certificates` → **Authorities** → Import `certs/ca.crt` |
| Firefox (profile store)        | firefox                                       | Firefox policy `Certificates.ImportEnterpriseRoots` or manual import |

For **public domains you control**, skip all of this: issue a real certificate
with Let's Encrypt (`scripts/acme_tls_setup.sh`) and every browser in the world
trusts it with zero client-side configuration.

---

## Modules

The project includes working prototype modules for the foundational layers:

- Secure transport session layer
- CIP/NIP identity routing
- Local DNS resolution (hosts / dnsmasq / stubby-DoT exports)
- Pub Config registry (with signed remote sync)
- Local AI policy decision engine
- HTTPS site publishing model
- Manifest signing and verification (Ed25519)
- mTLS client certificate authorization (CA based)
- Certificate lifecycle, renewal, and rollback
- Prometheus metrics exporter (stdlib, no dependencies)
- Flask admin dashboard with token auth

---

## Validation

This project uses pytest.

```bash
cd WhoWantFreeInternet
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

Current result: **83 tests passed**.

---

## Operations and tooling

| Tool | Purpose |
| ---- | ------- |
| `scripts/install.sh` | venv + editable install + dnsmasq records + CA trust (Linux & macOS) |
| `scripts/install.ps1` | Windows installer: venv + hosts mappings + Root cert store |
| `scripts/https_serve.py` | HTTPS static server; auto-issues CA-signed certs for a domain |
| `scripts/https_domain_setup.sh {acme\|demo}` | ACME Certbot or self-signed demo certs |
| `scripts/acme_tls_setup.sh` | Let's Encrypt issuance (http01 / webroot / dns01) |
| `scripts/generate_reverse_proxy.sh` | Nginx/Caddy SNI vhost generation + reload |
| `scripts/setup_doh_dot.sh {dot\|doh}` | stubby / cloudflared encrypted resolver bridge |
| `scripts/rotate_certificates.sh` | renewal, key rotation, backups, rollback |
| `scripts/metrics_server.py` | Prometheus `/metrics` endpoint on :9090 |
| `scripts/dashboard_server.py` | Flask admin dashboard on :8087 (token auth) |
| `scripts/wwfi_background_service.py` | periodic local DNS refresh service |
| `systemd/` | `wwfi-dns.service`, cert renewal service + timer, HTTPS demo service |
| `cloud-init.yaml` | OCI / cloud-init node bootstrap |
| `terraform/` | OCI VCN + subnet + security list + compute + provisioning |
| `Dockerfile` + `docker-compose.yml` | one-command local demo |
| `monitoring/` | Prometheus config, alert rules, Grafana dashboard |
| `docs/` | DoH/DoT, certificate lifecycle, operations guides |

---

## Repository hygiene

- **Secrets are never committed.** Private keys (`*.key`, `*.pem`), env files,
  `.env`, and Terraform state (`.tfstate*`, `.tfvars`) are gitignored.
- **`certs/` is gitignored.** Everything in it (the root CA and site certs) is
  regenerated by `scripts/install.sh`. Never push `ca.key`.
- `configs/sites-available/` and `configs/sites-enabled/` are generated output
  of `scripts/generate_reverse_proxy.sh` and are not tracked; the hand-written
  templates (`configs/Caddyfile`, `configs/dnsmasq.conf`,
  `configs/nginx/wwwfi.conf`) live in `configs/`.
- Runtime-issued demo site certs are not artifacts of the repository; treat the
  repo as a template that provisions its own PKI on first run.

---

## Roadmap

See [`ROADMAP.md`](ROADMAP.md) for the tiered development plan. Domain design
follows: secure transport → CIP/NIP routing → local DNS → Pub Config → local AI
policy → hardening, signed configs, and release automation.

---

WWFI is a private, encrypted, local-first network model where domains, configs,
and access decisions are protected by identity, policy, and cryptographic
transport — designed to work even without public internet dependency.