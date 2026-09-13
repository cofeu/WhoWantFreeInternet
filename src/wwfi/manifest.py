from __future__ import annotations

import base64
import json
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

_SIGNATURE_FIELDS = ("signature", "public_key")


@dataclass
class ConfigManifest:
    domain: str
    backend: str
    tls_enabled: bool = True
    identity: str | None = None
    port: int | None = None
    version: int = 1
    signature: str | None = None
    public_key: str | None = None

    def canonical(self) -> Dict[str, Any]:
        data = asdict(self)
        for key in _SIGNATURE_FIELDS:
            data.pop(key, None)
        return {key: value for key, value in data.items() if value is not None}

    def signable_bytes(self) -> bytes:
        return json.dumps(self.canonical(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_json(cls, payload: str) -> "ConfigManifest":
        return cls(**json.loads(payload))


@dataclass
class RemoteManifest(ConfigManifest):
    local_backend: str | None = None
    host_backend: str | None = None


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------


def generate_manifest_keys() -> tuple[str, str]:
    private = ed25519.Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem.decode("ascii"), public_pem.decode("ascii")


def load_private_key(pem: str) -> ed25519.Ed25519PrivateKey:
    private = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    if not isinstance(private, ed25519.Ed25519PrivateKey):
        raise TypeError("Private key is not an Ed25519 key.")
    return private


def load_public_key(pem: str) -> ed25519.Ed25519PublicKey:
    public = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(public, ed25519.Ed25519PublicKey):
        raise TypeError("Public key is not an Ed25519 key.")
    return public


def save_key(pem: str, path: str | Path) -> None:
    Path(path).write_text(pem.rstrip() + "\n", encoding="utf-8")


def read_key(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------


def sign_bytes(payload: bytes, private_pem: str) -> str:
    signature = load_private_key(private_pem).sign(payload)
    return base64.b64encode(signature).decode("ascii")


def verify_bytes(payload: bytes, signature_b64: str, public_pem: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64)
        load_public_key(public_pem).verify(signature, payload)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def sign_manifest(manifest: ConfigManifest, private_pem: str) -> ConfigManifest:
    manifest.signature = sign_bytes(manifest.signable_bytes(), private_pem)
    return manifest


def verify_manifest(manifest: ConfigManifest, public_pem: str) -> bool:
    if not manifest.signature:
        return False
    if manifest.public_key and manifest.public_key != public_pem:
        return False
    return verify_bytes(manifest.signable_bytes(), manifest.signature, public_pem)


def sign_manifest_file(
    manifest: ConfigManifest,
    private_key_path: str | Path,
    output_path: str | Path | None = None,
) -> str:
    private_pem = read_key(private_key_path)
    signed = sign_manifest(manifest, private_pem)
    payload = signed.to_json()
    if output_path is not None:
        Path(output_path).write_text(payload + "\n", encoding="utf-8")
    return payload


def verify_manifest_file(
    payload: str,
    public_key_path: str | Path,
) -> bool:
    public_pem = read_key(public_key_path)
    manifest = ConfigManifest.from_json(payload)
    return verify_manifest(manifest, public_pem)