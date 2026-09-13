from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256


@dataclass
class Certificate:
    domain: str
    fingerprint: str = field(init=False)

    def __post_init__(self):
        self.fingerprint = sha256(self.domain.encode("utf-8")).hexdigest()[:32]


@dataclass
class Site:
    domain: str
    backend: str
    tls_enabled: bool = True
    certificate: Certificate = field(init=False)

    def __post_init__(self):
        if not self.domain:
            raise ValueError("Domain is required")
        if self.tls_enabled is False and self.domain:
            raise ValueError("All published domains must use TLS and HTTPS by default")
        self.certificate = Certificate(self.domain)

    @property
    def url(self) -> str:
        return f"https://{self.domain}"


class SiteManager:
    def __init__(self):
        self.sites: dict[str, Site] = {}

    def publish_site(self, domain: str, backend: str, tls_enabled: bool = True) -> Site:
        if not domain:
            raise ValueError("Domain is required")
        if tls_enabled is False:
            raise ValueError("A published domain must be TLS-enabled")

        site = Site(domain=domain, backend=backend, tls_enabled=True)
        self.sites[domain] = site
        return site

    def resolve(self, domain: str) -> Site | None:
        return self.sites.get(domain)
