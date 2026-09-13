import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from wwfi.security import (
    AccessPolicy,
    ClientCertificate,
    ServiceGate,
    parse_client_certificate,
    verify_client_certificate,
)


def _pem_pub(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _pem_priv(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode("ascii")


def _build_ca(cn: str = "WWFI Test CA"):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _build_client(ca_key, ca_cert, cn: str, *, expires_at: datetime.datetime):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(expires_at - datetime.timedelta(days=60))
        .not_valid_after(expires_at)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return _pem_pub(cert), _pem_priv(key)


@pytest.fixture
def mtls_environment():
    ca_key, ca_cert = _build_ca()
    untrusted_key, untrusted_cert = _build_ca("WWFI Untrusted CA")
    now = datetime.datetime.now(datetime.timezone.utc)

    client_pem, _ = _build_client(ca_key, ca_cert, "device-1", expires_at=now + datetime.timedelta(days=30))
    untrusted_client_pem, _ = _build_client(untrusted_key, untrusted_cert, "evil-device", expires_at=now + datetime.timedelta(days=30))
    expired_pem, _ = _build_client(ca_key, ca_cert, "expired-device", expires_at=now - datetime.timedelta(days=10))

    return {
        "ca_pem": _pem_pub(ca_cert),
        "client_pem": client_pem,
        "untrusted_client_pem": untrusted_client_pem,
        "expired_client_pem": expired_pem,
    }


def _gate(mtls_env, **overrides):
    defaults = dict(
        require_identity=True,
        require_encryption=True,
        allow_known_ip=True,
        require_mtls=True,
        trust_ca_pem=mtls_env["ca_pem"],
    )
    defaults.update(overrides)
    return ServiceGate(AccessPolicy(**defaults))


def test_mtls_client_with_valid_cert_is_allowed(mtls_environment):
    gate = _gate(mtls_environment)
    allowed = gate.authorize(
        ip="10.0.0.4",
        identity="device-1",
        encrypted=True,
        session_id="sess-1",
        client_cert_pem=mtls_environment["client_pem"],
    )
    assert allowed is True


def test_mtls_requires_client_certificate(mtls_environment):
    gate = _gate(mtls_environment)
    with pytest.raises(PermissionError):
        gate.authorize(
            ip="10.0.0.4",
            identity="device-1",
            encrypted=True,
            session_id="sess-1",
            client_cert_pem=None,
        )


def test_mtls_rejects_cert_from_untrusted_ca(mtls_environment):
    gate = _gate(mtls_environment)
    with pytest.raises(PermissionError):
        gate.authorize(
            ip="10.0.0.4",
            identity="evil-device",
            encrypted=True,
            session_id="sess-1",
            client_cert_pem=mtls_environment["untrusted_client_pem"],
        )


def test_mtls_rejects_expired_client_cert(mtls_environment):
    gate = _gate(mtls_environment)
    with pytest.raises(PermissionError):
        gate.authorize(
            ip="10.0.0.4",
            identity="expired-device",
            encrypted=True,
            session_id="sess-1",
            client_cert_pem=mtls_environment["expired_client_pem"],
        )


def test_mtls_with_allow_expired_cert_grants_access(mtls_environment):
    gate = _gate(mtls_environment, allow_expired_cert=True)
    allowed = gate.authorize(
        ip="10.0.0.4",
        identity="expired-device",
        encrypted=True,
        session_id="sess-1",
        client_cert_pem=mtls_environment["expired_client_pem"],
    )
    assert allowed is True


def test_mtls_requires_trusted_ca_configured():
    gate = ServiceGate(
        AccessPolicy(
            require_identity=True,
            require_encryption=True,
            require_mtls=True,
            trust_ca_pem=None,
        )
    )
    with pytest.raises(PermissionError):
        gate.authorize(
            ip="10.0.0.4",
            identity="device-1",
            encrypted=True,
            session_id="sess-1",
            client_cert_pem="-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----",
        )


def test_parse_client_certificate_extracts_fields(mtls_environment):
    parsed = parse_client_certificate(mtls_environment["client_pem"])
    assert isinstance(parsed, ClientCertificate)
    assert parsed.subject == "CN=device-1"
    assert parsed.issuer == "CN=WWFI Test CA"
    assert len(parsed.fingerprint) == 64
    assert parsed.serial > 0
    assert parsed.is_valid_at() is True


def test_verify_client_certificate_rejects_garbage():
    assert verify_client_certificate("not-a-cert", "not-a-ca") is False


def test_mtls_gate_still_enforces_identity_and_encryption(mtls_environment):
    gate = _gate(mtls_environment)
    with pytest.raises(PermissionError):
        gate.authorize(
            ip="10.0.0.4",
            identity=None,
            encrypted=True,
            session_id="sess-1",
            client_cert_pem=mtls_environment["client_pem"],
        )
    with pytest.raises(PermissionError):
        gate.authorize(
            ip="10.0.0.4",
            identity="device-1",
            encrypted=False,
            session_id="sess-1",
            client_cert_pem=mtls_environment["client_pem"],
        )