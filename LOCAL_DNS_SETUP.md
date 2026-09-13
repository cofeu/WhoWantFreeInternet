# WWFI Local DNS Setup

This document explains how to run the WWFI DNS layer as a background local service and attach it to the main machine.

## 1. Add the local DNS service configuration

Example JSON:

```json
{
  "host": "127.0.0.1",
  "port": 5353,
  "records": {
    "demo.local": "127.0.0.1:8443",
    "shop.local": "127.0.0.1:8080"
  }
}
```

## 2. Export hosts file entries

The generated hosts file looks like:

```text
127.0.0.1 demo.local
127.0.0.1 shop.local
```

## 3. Export dnsmasq entries

The generated dnsmasq block looks like:

```text
address=/demo.local/127.0.0.1
address=/shop.local/127.0.0.1
```

## 4. Install as background local resolver

For Linux, the practical approach is:

- install dnsmasq
- copy the generated entries into a config file
- start the service in background
- or use systemd-resolved or a local resolver service

Example:

```bash
sudo apt-get install dnsmasq
sudo mkdir -p /etc/dnsmasq.d
sudo tee /etc/dnsmasq.d/wwfi.conf <<'EOF'
address=/demo.local/127.0.0.1
address=/shop.local/127.0.0.1
EOF
sudo systemctl restart dnsmasq
```

## 5. Add to the main machine

Then either:
- use the local machine hosts file
- or use the local resolver as the default DNS for the machine

This gives the main host a local DNS system that resolves WWFI domains without requiring a public internet resolver.

## 6. Runtime idea

The WWFI service can run in background and periodically refresh the config from a registry or a signed manifest. The local resolver then automatically picks up the new domain entries.
