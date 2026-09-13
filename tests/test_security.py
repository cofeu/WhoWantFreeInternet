import pytest

from wwfi.security import AccessPolicy, ServiceGate


def test_ip_without_identity_is_denied():
    gate = ServiceGate(
        AccessPolicy(require_identity=True, require_encryption=True, allow_known_ip=False)
    )

    with pytest.raises(PermissionError):
        gate.authorize(ip="10.0.0.4", identity=None, encrypted=False, session_id=None)


def test_known_ip_still_requires_encrypted_session():
    gate = ServiceGate(
        AccessPolicy(require_identity=True, require_encryption=True, allow_known_ip=True)
    )

    with pytest.raises(PermissionError):
        gate.authorize(ip="10.0.0.4", identity="device-1", encrypted=False, session_id="sess-1")


def test_encrypted_authorized_session_is_allowed():
    gate = ServiceGate(
        AccessPolicy(require_identity=True, require_encryption=True, allow_known_ip=True)
    )

    allowed = gate.authorize(ip="10.0.0.4", identity="device-1", encrypted=True, session_id="sess-1")

    assert allowed is True
