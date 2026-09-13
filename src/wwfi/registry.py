from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Dict, Iterable, List, Tuple

from .manifest import ConfigManifest, RemoteManifest, verify_manifest


@dataclass
class LocalConfig:
    domain: str
    backend: str
    tls_enabled: bool = True
    identity: str | None = None
    port: int | None = None


@dataclass
class HostConfig:
    domain: str
    backend: str
    tls_enabled: bool = True
    identity: str | None = None
    port: int | None = None
    protected: bool = True


@dataclass(frozen=True)
class SyncResult:
    applied: Tuple[str, ...]
    skipped: Tuple[Tuple[str, str], ...]
    rejected: Tuple[Tuple[str, str], ...]


def _coerce_remote(raw) -> RemoteManifest:
    if isinstance(raw, RemoteManifest):
        return raw
    if isinstance(raw, ConfigManifest):
        return RemoteManifest(**asdict(raw))
    return RemoteManifest(**raw)


@dataclass
class SiteRegistry:
    local: Dict[str, LocalConfig] = field(default_factory=dict)
    host: Dict[str, HostConfig] = field(default_factory=dict)
    versions: Dict[str, int] = field(default_factory=dict)

    def register_site(
        self,
        domain: str,
        local_backend: str,
        host_backend: str,
        *,
        tls_enabled: bool = True,
        identity: str | None = None,
        port: int | None = None,
    ) -> tuple[LocalConfig, HostConfig]:
        if not domain:
            raise ValueError("Domain is required.")
        if tls_enabled is False:
            raise ValueError("Published site must use TLS by default.")

        local_cfg = LocalConfig(
            domain=domain,
            backend=local_backend,
            tls_enabled=tls_enabled,
            identity=identity,
            port=port,
        )
        host_cfg = HostConfig(
            domain=domain,
            backend=host_backend,
            tls_enabled=tls_enabled,
            identity=identity,
            port=port,
            protected=True,
        )

        self.local[domain] = local_cfg
        self.host[domain] = host_cfg
        self.versions[domain] = self.versions.get(domain, 0) + 1
        return local_cfg, host_cfg

    def resolve_local(self, domain: str) -> LocalConfig | None:
        return self.local.get(domain)

    def resolve_host(self, domain: str) -> HostConfig | None:
        return self.host.get(domain)

    def sync(
        self,
        remote_manifests: Iterable,
        *,
        verify_signatures: bool = True,
        public_key: str | None = None,
    ) -> SyncResult:
        if verify_signatures and not public_key:
            raise ValueError("public_key must be provided when verify_signatures=True")

        applied: List[str] = []
        skipped: List[Tuple[str, str]] = []
        rejected: List[Tuple[str, str]] = []

        for raw in remote_manifests:
            manifest = _coerce_remote(raw)

            if verify_signatures:
                if manifest.public_key and public_key and manifest.public_key != public_key:
                    rejected.append((manifest.domain, "key_mismatch"))
                    continue
                if not verify_manifest(manifest, public_key):
                    rejected.append((manifest.domain, "bad_signature"))
                    continue

            if manifest.version <= 0:
                rejected.append((manifest.domain, "invalid_version"))
                continue

            local_backend = manifest.local_backend or manifest.backend
            host_backend = manifest.host_backend or manifest.backend
            current_version = self.versions.get(manifest.domain, 0)

            if manifest.version < current_version:
                skipped.append((manifest.domain, "stale_version"))
                continue
            if manifest.version == current_version:
                existing = self.local.get(manifest.domain)
                if existing is not None and existing.backend != local_backend:
                    skipped.append((manifest.domain, "version_conflict"))
                else:
                    skipped.append((manifest.domain, "already_current"))
                continue

            self.register_site(
                manifest.domain,
                local_backend=local_backend,
                host_backend=host_backend,
                tls_enabled=manifest.tls_enabled,
                identity=manifest.identity,
                port=manifest.port,
            )
            self.versions[manifest.domain] = manifest.version
            applied.append(manifest.domain)

        return SyncResult(
            applied=tuple(applied),
            skipped=tuple(skipped),
            rejected=tuple(rejected),
        )