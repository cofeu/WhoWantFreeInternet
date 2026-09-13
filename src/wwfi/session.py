from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SessionPolicy:
    require_identity: bool = True
    require_encryption: bool = True


class SecureSession:
    def __init__(self, policy: SessionPolicy):
        self.policy = policy

    def open(self, *, identity: str | None, encrypted: bool, payload: bytes) -> dict:
        if self.policy.require_identity and not identity:
            raise PermissionError("Identity is required for secure session open.")

        if self.policy.require_encryption and not encrypted:
            raise PermissionError("Encrypted session is required.")

        if not payload:
            raise ValueError("Payload cannot be empty.")

        return {
            "identity": identity,
            "encrypted": encrypted,
            "payload": payload,
        }
