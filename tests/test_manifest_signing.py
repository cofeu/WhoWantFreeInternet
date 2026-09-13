import pytest

from wwfi.manifest import (
    ConfigManifest,
    RemoteManifest,
    generate_manifest_keys,
    read_key,
    save_key,
    sign_manifest,
    sign_manifest_file,
    verify_manifest,
    verify_manifest_file,
)


@pytest.fixture
def keys():
    private_pem, public_pem = generate_manifest_keys()
    return {"private": private_pem, "public": public_pem}


def test_generated_keys_are_distinct_and_valid(keys):
    assert keys["private"] != keys["public"]
    assert "PRIVATE KEY" in keys["private"]
    assert "PUBLIC KEY" in keys["public"]


def test_sign_and_verify_roundtrip(keys):
    manifest = ConfigManifest(domain="demo.local", backend="127.0.0.1:8443")
    signed = sign_manifest(manifest, keys["private"])

    assert signed.signature
    assert verify_manifest(signed, keys["public"]) is True


def test_tampered_manifest_fails_verification(keys):
    manifest = ConfigManifest(domain="demo.local", backend="127.0.0.1:8443")
    sign_manifest(manifest, keys["private"])
    manifest.backend = "10.0.0.99:8443"

    assert verify_manifest(manifest, keys["public"]) is False


def test_manifest_without_signature_is_rejected(keys):
    manifest = ConfigManifest(domain="demo.local", backend="127.0.0.1:8443")

    assert verify_manifest(manifest, keys["public"]) is False


def test_wrong_public_key_fails_verification(keys):
    _, other_public = generate_manifest_keys()
    manifest = ConfigManifest(domain="demo.local", backend="127.0.0.1:8443")
    sign_manifest(manifest, keys["private"])

    assert verify_manifest(manifest, other_public) is False
    assert verify_manifest(manifest, keys["public"]) is True


def test_key_mismatch_guard_on_manifest(keys):
    _, other_public = generate_manifest_keys()
    manifest = ConfigManifest(domain="demo.local", backend="127.0.0.1:8443")
    sign_manifest(manifest, keys["private"])
    manifest.public_key = other_public
    expected = keys["public"]

    assert verify_manifest(manifest, expected) is False


def test_remote_manifest_signs_local_and_host_backends(keys):
    manifest = RemoteManifest(
        domain="shop.local",
        backend="127.0.0.1:3000",
        local_backend="127.0.0.1:3000",
        host_backend="10.0.0.25:3000",
        version=3,
    )
    sign_manifest(manifest, keys["private"])

    assert verify_manifest(manifest, keys["public"]) is True


def test_sign_and_verify_manifest_file(tmp_path, keys):
    manifest = ConfigManifest(domain="chat.local", backend="127.0.0.1:8080", version=2)
    private_path = tmp_path / "signing.key"
    public_path = tmp_path / "signing.pub"
    save_key(keys["private"], private_path)
    save_key(keys["public"], public_path)

    manifest_path = tmp_path / "manifest.json"
    payload = sign_manifest_file(manifest, private_path, manifest_path)

    assert payload == manifest_path.read_text(encoding="utf-8").strip()
    assert verify_manifest_file(payload, public_path) is True

    tampered = manifest_path.read_text(encoding="utf-8").replace("chat.local", "evil.local")
    assert verify_manifest_file(tampered, public_path) is False


def test_manifest_from_json_roundtrip(keys):
    manifest = ConfigManifest(domain="demo.local", backend="127.0.0.1:8443", identity="alice", version=5)
    sign_manifest(manifest, keys["private"])

    restored = ConfigManifest.from_json(manifest.to_json())

    assert restored.domain == "demo.local"
    assert restored.identity == "alice"
    assert restored.version == 5
    assert restored.signature == manifest.signature