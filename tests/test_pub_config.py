import pytest

from wwfi.registry import SiteRegistry


def test_pub_config_hosts_local_and_host_entries_for_same_domain():
    registry = SiteRegistry()
    local_cfg, host_cfg = registry.register_site(
        "shop.local",
        local_backend="127.0.0.1:3000",
        host_backend="10.0.0.25:3000",
        tls_enabled=True,
        identity="merchant",
        port=443,
    )

    assert local_cfg.domain == "shop.local"
    assert host_cfg.domain == "shop.local"
    assert local_cfg.backend == "127.0.0.1:3000"
    assert host_cfg.backend == "10.0.0.25:3000"


def test_pub_config_rejects_unencrypted_publish():
    registry = SiteRegistry()

    with pytest.raises(ValueError):
        registry.register_site(
            "demo.local",
            local_backend="127.0.0.1:8000",
            host_backend="10.0.0.8:8000",
            tls_enabled=False,
        )


def test_pub_config_can_be_resolved_from_host_and_local_views():
    registry = SiteRegistry()
    registry.register_site("chat.local", "127.0.0.1:8080", "10.0.0.7:8080", tls_enabled=True, identity="alice")

    assert registry.resolve_local("chat.local").backend == "127.0.0.1:8080"
    assert registry.resolve_host("chat.local").backend == "10.0.0.7:8080"
