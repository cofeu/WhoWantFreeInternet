from wwfi.config import PubConfigStore
from wwfi.dns import LocalDNS
from wwfi.router import RouteManager, RoutePolicy


def test_dns_resolves_secure_domain():
    dns = LocalDNS()
    dns.add_record("hello.local", "10.0.0.9", ttl=120, encrypted=True)

    record = dns.resolve("hello.local")

    assert record is not None
    assert record.target == "10.0.0.9"
    assert dns.requires_encryption("hello.local") is True


def test_pub_config_requires_signed_and_encrypted_access():
    store = PubConfigStore()
    store.publish("demo.local", "10.0.0.15", encrypted=True, signed=True, owner="alice")

    cfg = store.resolve("demo.local")

    assert cfg is not None
    assert cfg.is_accessible() is True


def test_route_manager_requires_encrypted_and_identity_validated_route():
    manager = RouteManager(RoutePolicy(require_identity=True, enforce_encryption=True, allow_private_routes=True))

    route = manager.add_route("device-a", "service-b", encrypted=True, identity="alice")

    assert route.source == "device-a"
    assert manager.resolve("device-a").destination == "service-b"
