from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

TLS_MODE_ACME = "acme"
TLS_MODE_CA = "ca"
TLS_MODE_SELF_SIGNED = "self-signed"
TLS_MODES = (TLS_MODE_ACME, TLS_MODE_CA, TLS_MODE_SELF_SIGNED)


def resolve_cert_paths(domain: str, tls_mode: str, cert_dir: str | Path) -> tuple[Path, Path]:
    """Return (cert_path, key_path) for the operator-chosen SSL source.

    - ``acme``       real Let's Encrypt / ZeroSSL certificate (``certs/acme/``,
                     public DNS + certbot required — see scripts/acme_tls_setup.sh)
    - ``ca``         signed by the WWFI Local Root CA (``certs/``, default)
    - ``self-signed`` dev fallback (``certs/self-signed/``)

    Raises an error if the operator asked for ``acme`` but no certificate has
    been issued yet.
    """
    if tls_mode not in TLS_MODES:
        raise ValueError(f"unknown tls_mode {tls_mode!r}; choose one of {TLS_MODES}")
    base = Path(cert_dir)
    if tls_mode == TLS_MODE_ACME:
        cert, key = base / "acme" / f"{domain}.crt", base / "acme" / f"{domain}.key"
        if not cert.exists() or not key.exists():
            raise OSError(
                f"tls_mode=acme requested for {domain} but no ACME certificate found "
                f"({cert}). Run: scripts/acme_tls_setup.sh --challenge webroot|dns01 "
                "--email YOU@EXAMPLE.COM --domain {domain}"
            )
        return cert, key
    if tls_mode == TLS_MODE_CA:
        return base / f"{domain}.crt", base / f"{domain}.key"
    return base / "self-signed" / f"{domain}.crt", base / "self-signed" / f"{domain}.key"


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
    tls_mode: str = TLS_MODE_CA
    certificate: Certificate = field(init=False)

    def __post_init__(self):
        if not self.domain:
            raise ValueError("Domain is required")
        if self.tls_enabled is False and self.domain:
            raise ValueError("All published domains must use TLS and HTTPS by default")
        if self.tls_mode not in TLS_MODES:
            raise ValueError(f"unknown tls_mode {self.tls_mode!r}; choose one of {TLS_MODES}")
        self.certificate = Certificate(self.domain)

    @property
    def url(self) -> str:
        return f"https://{self.domain}"


class SiteManager:
    def __init__(self):
        self.sites: dict[str, Site] = {}

    def publish_site(self, domain: str, backend: str, tls_enabled: bool = True, tls_mode: str = TLS_MODE_CA) -> Site:
        if not domain:
            raise ValueError("Domain is required")
        if tls_enabled is False:
            raise ValueError("A published domain must be TLS-enabled")
        if tls_mode not in TLS_MODES:
            raise ValueError(f"unknown tls_mode {tls_mode!r}; choose one of {TLS_MODES}")

        site = Site(domain=domain, backend=backend, tls_enabled=True, tls_mode=tls_mode)
        self.sites[domain] = site
        return site

    def resolve(self, domain: str) -> Site | None:
        return self.sites.get(domain)
