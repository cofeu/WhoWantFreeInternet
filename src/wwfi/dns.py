from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class LocalRecord:
    domain: str
    target: str
    ttl: int = 60
    encrypted: bool = True


@dataclass
class LocalDNS:
    records: Dict[str, LocalRecord] = field(default_factory=dict)

    def add_record(self, domain: str, target: str, ttl: int = 60, encrypted: bool = True) -> LocalRecord:
        record = LocalRecord(domain=domain, target=target, ttl=ttl, encrypted=encrypted)
        self.records[domain] = record
        return record

    def resolve(self, domain: str) -> LocalRecord | None:
        return self.records.get(domain)

    def requires_encryption(self, domain: str) -> bool:
        record = self.resolve(domain)
        if record is None:
            return False
        return record.encrypted

    def as_hosts_file(self) -> str:
        lines = []
        for domain, record in sorted(self.records.items()):
            target = record.target.split(":")[0]
            lines.append(f"{target} {domain}")
        return "\n".join(lines)
