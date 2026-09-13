from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PublishedSite:
    domain: str
    local_backend: str
    host_backend: str
    tls_enabled: bool
    identity: str
    port: int
    https_url: str
    curl_command: str
    wget_command: str


class DomainPublisher:
    def __init__(self):
        self.published: dict[str, PublishedSite] = {}

    def publish(
        self,
        *,
        domain: str,
        local_backend: str,
        host_backend: str,
        tls_enabled: bool = True,
        identity: str | None = None,
        port: int = 443,
    ) -> PublishedSite:
        if not domain:
            raise ValueError("Domain is required")
        if tls_enabled is False:
            raise ValueError("Published domains must use TLS")
        if not identity:
            raise ValueError("Identity is required for publishing")

        site = PublishedSite(
            domain=domain,
            local_backend=local_backend,
            host_backend=host_backend,
            tls_enabled=tls_enabled,
            identity=identity,
            port=port,
            https_url=f"https://{domain}",
            curl_command=(
                f"curl --resolve {domain}:{port}:127.0.0.1 "
                f"-k -H 'Host: {domain}' https://{domain}"
            ),
            wget_command=(
                f"wget --no-check-certificate --header='Host: {domain}' "
                f"https://{domain}"
            ),
        )
        self.published[domain] = site
        return site

    def resolve(self, domain: str) -> PublishedSite | None:
        return self.published.get(domain)
