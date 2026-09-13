from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict


@dataclass
class DNSServiceConfig:
    host: str = "127.0.0.1"
    port: int = 5353
    records: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"host": self.host, "port": self.port, "records": self.records}

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")


class LocalDNSService:
    def __init__(self, config: DNSServiceConfig | None = None):
        self.config = config or DNSServiceConfig()
        self.records = self.config.records

    def add_record(self, domain: str, target: str) -> None:
        self.records[domain] = target

    @staticmethod
    def _normalize_target(target: str) -> str:
        return target.split(":", 1)[0]

    def export_hosts(self) -> str:
        lines = []
        for domain, target in sorted(self.records.items()):
            ip = self._normalize_target(target)
            lines.append(f"{ip} {domain}")
        return "\n".join(lines)

    def export_dnsmasq(self) -> str:
        lines = []
        for domain, target in sorted(self.records.items()):
            ip = self._normalize_target(target)
            lines.append(f"address=/{domain}/{ip}")
        return "\n".join(lines)

    def export_stubby(self) -> str:
        lines = [
            "stubby:",
            "  listen_addresses:",
            "    - 127.0.0.1@5353",
            "  tls_authentication: GETDNS_AUTHENTICATION_REQUIRED",
            "  dns_transport_list:",
            "    - GETDNS_TRANSPORT_TLS",
            "  upstream_recursive_servers:",
            "    - address_data: 1.1.1.1",
            "      tls_auth_name: cloudflare-dns.com",
            "    - address_data: 8.8.8.8",
            "      tls_auth_name: dns.google",
        ]
        return "\n".join(lines)

    def export_config(self) -> dict:
        return {"host": self.config.host, "port": self.config.port, "records": dict(self.records)}

    def write_files(self, output_dir: str | Path) -> dict:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        hosts_path = output_path / "wwfi.hosts"
        dnsmasq_path = output_path / "wwfi-dnsmasq.conf"
        stubby_path = output_path / "wwfi-stubby.yml"
        hosts_path.write_text(self.export_hosts() + "\n", encoding="utf-8")
        dnsmasq_path.write_text(self.export_dnsmasq() + "\n", encoding="utf-8")
        stubby_path.write_text(self.export_stubby() + "\n", encoding="utf-8")
        return {
            "hosts": str(hosts_path),
            "dnsmasq": str(dnsmasq_path),
            "stubby": str(stubby_path),
            "config": self.export_config(),
        }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate WWFI local DNS files for dnsmasq or hosts integration.")
    parser.add_argument("--output-dir", default="/tmp/wwfi-dns", help="Directory to write generated DNS files.")
    parser.add_argument("--record", action="append", default=[], help="Domain mapping in the form domain=ip:port")
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    service = LocalDNSService()
    for record in args.record:
        domain, target = record.split("=", 1)
        service.add_record(domain.strip(), target.strip())

    if not service.records:
        service.add_record("demo.local", "127.0.0.1:8443")

    result = service.write_files(args.output_dir)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
