from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class PubConfig:
    domain: str
    target: str
    encrypted: bool = True
    signed: bool = False
    metadata: Dict[str, str] = field(default_factory=dict)

    def verify_signature(self) -> bool:
        return self.signed

    def is_accessible(self) -> bool:
        return self.encrypted and self.verify_signature()


@dataclass
class PubConfigStore:
    items: Dict[str, PubConfig] = field(default_factory=dict)

    def publish(self, domain: str, target: str, encrypted: bool = True, signed: bool = False, **metadata) -> PubConfig:
        config = PubConfig(domain=domain, target=target, encrypted=encrypted, signed=signed, metadata=dict(metadata))
        self.items[domain] = config
        return config

    def resolve(self, domain: str) -> PubConfig | None:
        return self.items.get(domain)
