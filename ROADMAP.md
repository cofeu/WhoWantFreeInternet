# WWFI Roadmap

## Phase 0 - Foundation
- define the local-first security model
- define CIP and NIP clearly
- decide on identity, routing, and trust rules
- set the end-to-end encryption standard

## Phase 1 - Secure Transport
- build encrypted tunnel/session layer
- require identity validation before port access
- establish per-port policy enforcement
- ensure traffic remains encrypted even if the IP is known

## Phase 2 - Local Addressing and Routing
- implement CIP/NIP mapping layer
- route local network identities securely
- isolate internal services from public exposure

## Phase 3 - Local DNS
- build private DNS resolution
- add local hostname mapping
- support encrypted domain resolution

## Phase 4 - Config Publication
- design Pub Config publish model
- allow users to add domains and rules on their own devices
- ensure config delivery is signed and verified

## Phase 5 - Local AI Layer
- create local reasoning and policy engine
- use AI to support access decisions and anomaly detection
- keep all inference local

## Phase 6 - Hardening
- enforce port encryption and trust policies
- add audit logs and signed config validation
- support fail-closed access rules

### Implemented extras
- Ed25519 signed manifests (`sign_manifest` / `verify_manifest`)
- PubConfig remote sync with version/conflict resolution (`SiteRegistry.sync`)
- mTLS client certificate authorization (`ServiceGate` + `verify_client_certificate`)
- Certificate lifecycle / rotation / rollback (`CertificateManager`, `scripts/rotate_certificates.sh`)
- Prometheus metrics exporter + Grafana dashboard + alert rules
- Flask admin dashboard (token auth)
- ACME (Certbot) + Nginx/Caddy SNI automation
- DoH/DoT local resolver bridge (stubby / cloudflared)
- systemd units + cloud-init bootstrap + OCI Terraform
- Docker + docker-compose one-command demo

## Phase 7 - Release
- test local deployment in isolated environments
- validate traffic compromise scenarios
- publish secure default configuration templates

## Security principle

The system must never rely on a known IP as the primary form of protection. IPs are only routing metadata. The actual enforcement must be based on:
- end-to-end encryption
- identity verification
- signed configuration
- per-port access policy
- fail-closed security defaults


