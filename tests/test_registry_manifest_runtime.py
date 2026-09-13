from wwfi.manifest import ConfigManifest
from wwfi.registry import SiteRegistry
from wwfi.runtime import LanguageAdapter


def test_site_registry_tracks_local_and_host_configs():
    registry = SiteRegistry()
    local_cfg, host_cfg = registry.register_site(
        "demo.local",
        local_backend="127.0.0.1:8000",
        host_backend="10.0.0.15:8080",
        tls_enabled=True,
        identity="alice",
        port=443,
    )

    assert local_cfg.domain == "demo.local"
    assert host_cfg.domain == "demo.local"
    assert registry.resolve_local("demo.local").backend == "127.0.0.1:8000"
    assert registry.resolve_host("demo.local").protected is True


def test_manifest_serializes_and_deserializes():
    manifest = ConfigManifest(domain="demo.local", backend="127.0.0.1:8000", tls_enabled=True, identity="alice", port=443)

    payload = manifest.to_json()
    restored = ConfigManifest.from_json(payload)

    assert restored.domain == "demo.local"
    assert restored.identity == "alice"
    assert restored.port == 443


def test_runtime_supports_multiple_languages():
    runtime = LanguageAdapter.build("node", "nodejs")

    assert runtime.language == "node"
    assert runtime.supports_tls is True
    assert "rust" in LanguageAdapter.supported_languages()
