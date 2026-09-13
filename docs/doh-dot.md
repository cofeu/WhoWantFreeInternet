# WWFI DoH / DoT Local Resolver

WWFI binds a local DNS service on `127.0.0.1:5353` and can be bridged to
encrypted upstream resolvers so all *non-local* lookups travel over
DNS-over-TLS (DoT) or DNS-over-HTTPS (DoH).

```
client ──> dnsmasq :53  (local .local records + forwarding)
            │
            ├─> stubby :5353          (DoT → 1.1.1.1 / 8.8.8.8)
            └─> cloudflared :5053     (DoH → https://1.1.1.1/dns-query)
```

## Installation (DoT via stubby)

```bash
sudo scripts/setup_doh_dot.sh dot
```

The script:

1. installs `stubby`,
2. writes `/etc/stubby/stubby.yml` (exported by `wwfi.dns_service.LocalDNSService.export_stubby`),
3. points dnsmasq at `127.0.0.1#5353`,
4. restarts `stubby` and `dnsmasq`.

## Installation (DoH via cloudflared)

```bash
sudo scripts/setup_doh_dot.sh doh
```

This installs `cloudflared`, runs `cloudflared proxy-dns` on `127.0.0.1:5053`,
and points dnsmasq at it.

## Verification

```bash
# Encrypted upstream path (DoT)
dig @127.0.0.1 -p 5353 example.com

# DoH bridge
dig @127.0.0.1 -p 5053 cloudflare.com +noall +answer

# Full resolver: local WWFI name + external name
dig @127.0.0.1 demo.local +short
dig @127.0.0.1 example.com

# Native DoH where supported (dig ≥ 9.16 with +https)
dig @127.0.0.1 demo.local +https
```

## Manual dnsmasq → stubby bridge

```bash
sudo tee /etc/stubby/stubby.yml >/dev/null <<'EOF'
stubby:
  listen_addresses:
    - 127.0.0.1@5353
  tls_authentication: GETDNS_AUTHENTICATION_REQUIRED
  dns_transport_list:
    - GETDNS_TRANSPORT_TLS
  upstream_recursive_servers:
    - address_data: 1.1.1.1
      tls_auth_name: cloudflare-dns.com
    - address_data: 8.8.8.8
      tls_auth_name: dns.google
EOF

sudo tee /etc/dnsmasq.d/wwfi-upstream.conf >/dev/null <<'EOF'
server=127.0.0.1#5353
server=127.0.0.1#5353
EOF

sudo systemctl restart stubby dnsmasq
```

## Notes

- Local `.local` names stay resolved by dnsmasq without ever leaving the host.
- External queries are encrypted end-to-end; dnsmasq only sees the plaintext
  question for the names it serves.
- DoT and DoH both authenticate the upstream with certificate pinning
  (`tls_auth_name`), not just the IP.