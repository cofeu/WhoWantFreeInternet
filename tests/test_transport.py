import pytest

from wwfi.session import SecureSession, SessionPolicy


def test_encrypted_session_requires_identity_and_crypto():
    policy = SessionPolicy(require_identity=True, require_encryption=True)
    session = SecureSession(policy)

    with pytest.raises(PermissionError):
        session.open(identity=None, encrypted=False, payload=b"test")


def test_valid_encrypted_session_is_opened():
    policy = SessionPolicy(require_identity=True, require_encryption=True)
    session = SecureSession(policy)

    handle = session.open(identity="alice", encrypted=True, payload=b"secret")

    assert handle["identity"] == "alice"
    assert handle["encrypted"] is True
    assert handle["payload"] == b"secret"


def test_session_rejects_plain_payload_for_protected_port():
    policy = SessionPolicy(require_identity=True, require_encryption=True)
    session = SecureSession(policy)

    with pytest.raises(PermissionError):
        session.open(identity="alice", encrypted=False, payload=b"plain")
