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

## WWFI Client extension (Chrome)

The browser client lives in `extension/`. It is a Manifest V3 Chrome extension that:

- generates a **non-extractable device identity** (ECDSA P-256, private key stays
  in IndexedDB and can never be exported) and sends its SHA-256 fingerprint as
  `X-WWFI-Identity` on every request to a WWFI domain;
- attaches `X-WWFI-Host` and an optional `X-WWFI-Token` so the mesh gateway can
  make per-request identity + policy decisions;
- is the **browser-side name plane client**: it syncs the domain registry from
  the local WWFI mesh node's control API (`/api/domains`) and enforces policy —
  unknown WWFI-ish hosts (`*.local`, pinned domains) are blocked unless routed;
  the popup shows served domains and recent denials.

Load it unpacked:

1. `chrome://extensions` → enable **Developer mode**.
2. **Load unpacked** → select the `extension/` directory.
3. Enable the extension and open the **Settings (options)** page: set the WWFI
   control API URL of your local mesh node (default `http://127.0.0.1:8123`),
   an optional API token, and per-domain routing pins. Press **Sync registry now**.

Reachability itself is handled by the local mesh node (data plane), so
`cofeu.org`, `yi.cket`, `demo.local`, etc. are reachable through the encrypted
mesh even when they live on a private IP; the extension adds identity + policy
on top.

---

## WWFI Mesh (name plane + data plane)

WWFI separates two problems that DNS alone cannot solve:

- **Name plane — "where do I connect?"** `yi.cket` → node + route. Answered by
  the WWFI Mesh (`src/wwfi/mesh.py`, daemon `scripts/wwfi_mesh_node.py`). Every
  WWFI client is both a resolver **and** a network node, so the registry is
  distributed across trusted peers instead of one central DNS server.
- **Data plane — "how do I really reach it?"** An encrypted **mTLS tunnel**
  between WWFI nodes. DNS returning `10.37.4.21` is useless from the open
  internet — a home private IP is only reachable through the mesh.

```
                WWFI Mesh
                    │
       ┌────────────┼────────────┐
       │            │            │
     cofeu        Yusuf        Yicket
   cofeu.org     yi.cket     shop.local
       │            │            │
       └────── encrypted mTLS mesh ──────┘
```

Mesh demo — a remote client reaches Yusuf's private home server by domain:

```bash
python3 scripts/wwfi_mesh_node.py ca-init --dir certs          # bootstrap mesh CA
python3 scripts/wwfi_mesh_node.py init --state ~/.wwfi/yusuf.json \
    --node yusuf --ca-dir certs                                 # client identity
python3 scripts/wwfi_mesh_node.py init --state ~/.wwfi/yicket.json \
    --node yicket --ca-dir certs                                # home node identity
python3 scripts/wwfi_mesh_node.py route add --state ~/.wwfi/yicket.json \
    --domain yi.cket --target 10.37.4.21 --target-port 80       # publish home server
python3 scripts/wwfi_mesh_node.py peer add --state ~/.wwfi/yusuf.json \
    --peer yicket --endpoint 192.168.1.50:9443                  # join the mesh
python3 scripts/wwfi_mesh_node.py forward --state ~/.wwfi/yusuf.json \
    --domain yi.cket --local-port 8900                          # tunnel to the domain
curl http://127.0.0.1:8900/                                     # reach the home server
```

Trust model: every node has an Ed25519 identity (`init`), same key used for the
mTLS certificate, signed by the WWFI Mesh CA. A node with a cert from a
different CA cannot join (verified in `tests/test_mesh.py`).

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

### You choose the SSL source — per domain (`--tls-mode`)

Every published domain carries an operator-chosen TLS source. Serve or setup a
site with any of the three modes; `auto` prefers `acme`, then `ca`, then
`self-signed`.

| mode           | source                                 | where certs live       | trust                        | use when                                  |
|----------------|----------------------------------------|------------------------|------------------------------|-------------------------------------------|
| `acme`         | Let's Encrypt / ZeroSSL (Certbot)      | `certs/acme/<domain>`  | all public clients (real CA) | the domain is a real, public DNS name     |
| `ca`           | WWFI Local Root CA                     | `certs/<domain>`       | clients importing `ca.crt`   | the private net (default)                 |
| `self-signed`  | openssl, no CA                         | `certs/self-signed`    | verify with `-k`             | dev fallback                              |

Issue + choose in one step:

```bash
scripts/https_domain_setup.sh acme       app.example.com   # real public cert (Certbot)
scripts/https_domain_setup.sh ca         cofeu.org          # WWFI Local Root CA
scripts/https_domain_setup.sh self-signed cofeu.org         # dev only
```

Then serve with the chosen source (default `--tls-mode auto`):

```bash
sudo python3 scripts/https_serve.py --domain app.example.com --tls-mode acme --port 443
```

Notes:

- `acme` requires the domain to be **resolvable on public DNS** and reachable for
  the chosen challenge (`cofeu.org` and `*.local` cannot pass ACME validation —
  HTTP-01 would fail). DNS-01 works for wildcards and names you can add TXT
  records to.
- `ca` is enforced as the default everywhere (`Site.tls_mode`, `resolve_cert_paths`,
  `https_serve.py --tls-mode`): you still get TLS on the LAN, no public CA needed.

For **public domains you control**, skip all of this: issue a real certificate
with Let's Encrypt (`scripts/acme_tls_setup.sh`) and every browser in the world
trusts it with zero client-side configuration.

---

## Domain Admin Panel (remote management)

The mesh node's control API (`/api/domains`, `/api/forward`, etc.) can be exposed
on a public IP (e.g. an Oracle Free Tier VM) and protected by a static Bearer
token. A small **admin panel** (`/admin`) lets you add/remove published domains
via a web UI, protected by username+password.

Setup (run once on the node):

```bash
# 1. create admin user + generate API token (file is gitignored, never committed)
python3 scripts/wwfi_mesh_node.py admin init --user <name> --password <strong-pw>

# 2. run the node with public control API + the generated token
#    --control-address 0.0.0.0:8123  binds the name plane to all interfaces
#    --token $TOKEN                   protects the API (extension gateway)
python3 scripts/wwfi_mesh_node.py node --state ~/.wwfi/oracle.json \
  --control-address 0.0.0.0:8123 --token "$TOKEN"
```

Then in the extension options set the gateway to `http://<oracle-ip>:8123` and
the same token. The admin panel is at `http://<oracle-ip>:8123/admin`.

**Security notes:**

- `configs/admin.json` (created by `admin init`) contains the **password hash**,
  session secret, and API token. It is `chmod 600` and **gitignored** — never
  commit it. The repo's `.gitignore` explicitly excludes `configs/admin.json`.
- When the control API is bound to a non-loopback address, **the token is
  mandatory**; without it every request is denied (even from loopback).
- The admin panel login uses a stateless HMAC-signed session cookie
  (`HttpOnly; SameSite=Strict`). Logout clears the cookie client-side.

### Example: Oracle Free Tier deployment

1. Spin up an ARM (Ampere A1) Free Tier instance. Reserve a **Public IPv4** (1 free).
2. Open Security List ingress for `80/tcp, 443/tcp, 8123/tcp`.
3. Point your public domain (e.g. `app.example.com`) to the Oracle IP via DNS `A`.
4. On the instance, clone the repo and run the setup:

```bash
# install deps (certbot, python, etc.)
sudo apt-get update && sudo apt-get install -y certbot python3-venv
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,web]"

# mesh CA + node identity
python3 scripts/wwfi_mesh_node.py ca-init --dir certs
python3 scripts/wwfi_mesh_node.py init --state ~/.wwfi/oracle.json \
  --node oracle --ca-dir certs --cert-dir certs

# admin panel + API token
python3 scripts/wwfi_mesh_node.py admin init --user admin --password '...'

# publish the public domain with Let's Encrypt (ACME)
python3 scripts/https_domain_setup.sh acme app.example.com

# run the mesh node (data plane mTLS listener on 9443, control API on 8123)
python3 scripts/wwfi_mesh_node.py node --state ~/.wwfi/oracle.json \
  --bind-address 0.0.0.0:9443 --control-address 0.0.0.0:8123 --token "$TOKEN"
```

5. The site is served over HTTPS with a real Let's Encrypt cert at `https://app.example.com`
   (zero client config). The mesh name plane resolves it for any extension pointing
   gateway at `http://<oracle-ip>:8123` with the token.
6. (Optional) systemd unit: `systemd/wwfi-mesh.service` (adapt `WorkingDirectory`, `User`,
   `ExecStart`).

---

## Modules

The project includes working prototype modules for the foundational layers:

- Secure transport session layer
- CIP/NIP identity routing
- WWFI Mesh: distributed resolver (name plane) + encrypted mTLS tunnels (data plane)
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

Current result: **89 tests passed** (including WWFI mesh end-to-end forward,
resolve, and mTLS rejection).

---

## Operations and tooling

| Tool | Purpose |
| ---- | ------- |
| `scripts/install.sh` | venv + editable install + dnsmasq records + CA trust (Linux & macOS) |
| `scripts/install.ps1` | Windows installer: venv + hosts mappings + Root cert store |
| `scripts/wwfi_mesh_node.py` | WWFI mesh node daemon + CLI (identity, peers, routes, tunnel, resolve) |
| `extension/` | Chrome MV3 WWFI client (identity + routing + policy); load unpacked |
| `systemd/wwfi-mesh.service` | run the mesh node as a persistent service |
| `scripts/https_serve.py` | HTTPS static server; `--tls-mode acme|ca|self-signed|auto`, auto-issues certs |
| `scripts/https_domain_setup.sh {acme\|ca\|self-signed}` | operator-chosen SSL source + cert issue |
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