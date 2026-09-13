import pytest

from wwfi.identity import CIPNIPRouter


def test_cip_nip_rejects_unknown_private_mapping():
    router = CIPNIPRouter()

    with pytest.raises(KeyError):
        router.resolve("unknown.local")


def test_cip_nip_routes_private_identity_to_backend():
    router = CIPNIPRouter()
    router.register("alice.local", "127.0.0.1:8000", private_ip="10.0.0.2")

    route = router.resolve("alice.local")

    assert route["backend"] == "127.0.0.1:8000"
    assert route["private_ip"] == "10.0.0.2"


def test_cip_nip_rejects_unencrypted_route_for_private_target():
    router = CIPNIPRouter()

    with pytest.raises(PermissionError):
        router.register("bad.local", "127.0.0.1:8000", private_ip="10.0.0.3", encrypted=False)
