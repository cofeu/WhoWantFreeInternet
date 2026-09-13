import pytest

from wwfi.manifest import ConfigManifest, RemoteManifest, generate_manifest_keys, sign_manifest
from wwfi.registry import SiteRegistry


@pytest.fixture
def signed_registry_manifests():
    private_pem, public_pem = generate_manifest_keys()

    def build(domain, backend, version, local=None, host=None, tamper=False):
        manifest = RemoteManifest(
            domain=domain,
            backend=backend,
            local_backend=local or backend,
            host_backend=host or backend,
            version=version,
            public_key=public_pem,
        )
        sign_manifest(manifest, private_pem)
        if tamper:
            manifest.backend = f"10.9.9.9:{manifest.backend.rsplit(':', 1)[-1]}"
        return manifest

    return {"private": private_pem, "public": public_pem, "build": build}


def test_sync_applies_newer_version_than_local(signed_registry_manifests):
    registry = SiteRegistry()
    registry.register_site("demo.local", "127.0.0.1:8000", "10.0.0.15:8080")

    result = registry.sync(
        [signed_registry_manifests["build"]("demo.local", "127.0.0.1:9000", version=2)],
        public_key=signed_registry_manifests["public"],
    )

    assert result.applied == ("demo.local",)
    assert registry.resolve_local("demo.local").backend == "127.0.0.1:9000"
    assert registry.versions["demo.local"] == 2


def test_sync_skips_stale_version(signed_registry_manifests):
    registry = SiteRegistry()
    result = registry.sync(
        [signed_registry_manifests["build"]("shop.local", "127.0.0.1:3000", version=3)],
        public_key=signed_registry_manifests["public"],
    )
    assert result.applied == ("shop.local",)
    assert registry.versions["shop.local"] == 3

    stale = registry.sync(
        [signed_registry_manifests["build"]("shop.local", "127.0.0.1:999", version=2)],
        public_key=signed_registry_manifests["public"],
    )
    assert stale.applied == ()
    assert stale.skipped == (("shop.local", "stale_version"),)
    assert registry.resolve_local("shop.local").backend == "127.0.0.1:3000"


def test_sync_detects_version_conflict(signed_registry_manifests):
    registry = SiteRegistry()
    result = registry.sync(
        [signed_registry_manifests["build"]("chat.local", "127.0.0.1:8080", version=1)],
        public_key=signed_registry_manifests["public"],
    )
    assert result.applied == ("chat.local",)

    conflict = registry.sync(
        [signed_registry_manifests["build"]("chat.local", "127.0.0.1:9090", version=1)],
        public_key=signed_registry_manifests["public"],
    )
    assert conflict.skipped == (("chat.local", "version_conflict"),)
    assert registry.resolve_local("chat.local").backend == "127.0.0.1:8080"


def test_sync_rejects_tampered_signature(signed_registry_manifests):
    registry = SiteRegistry()
    tampered = signed_registry_manifests["build"]("evil.local", "127.0.0.1:666", version=1, tamper=True)

    result = registry.sync([tampered], public_key=signed_registry_manifests["public"])

    assert result.rejected == (("evil.local", "bad_signature"),)
    assert "evil.local" not in registry.local


def test_sync_requires_public_key_when_verification_enabled():
    registry = SiteRegistry()
    with pytest.raises(ValueError):
        registry.sync([], public_key=None)


def test_sync_rejects_key_mismatch():
    private_pem, public_pem = generate_manifest_keys()
    _, other_public = generate_manifest_keys()
    registry = SiteRegistry()

    manifest = RemoteManifest(domain="demo.local", backend="127.0.0.1:8000", version=1, public_key=other_public)
    sign_manifest(manifest, private_pem)

    result = registry.sync([manifest], public_key=public_pem)

    assert result.rejected == (("demo.local", "key_mismatch"),)


def test_sync_applies_plain_config_manifest(signed_registry_manifests):
    registry = SiteRegistry()
    manifest = ConfigManifest(domain="mail.local", backend="127.0.0.1:2525", version=1, public_key=signed_registry_manifests["public"])
    sign_manifest(manifest, signed_registry_manifests["private"])

    result = registry.sync([manifest], public_key=signed_registry_manifests["public"])

    assert result.applied == ("mail.local",)
    assert registry.resolve_local("mail.local").backend == "127.0.0.1:2525"