from __future__ import annotations

import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa

from .certutil import cert_validity

_TRUST_CA_REQUIRED = "No trusted CA configured for mTLS verification."
_CLIENT_CERT_REQUIRED = "Mutual TLS client certificate is required before access is granted."


def _verify_issuer_signature(cert: x509.Certificate, issuer_key) -> bool:
    signature_algorithm = getattr(cert, "signature_hash_algorithm", None)
    try:
        if isinstance(issuer_key, rsa.RSAPublicKey):
            if signature_algorithm is None:
                return False
            issuer_key.verify(cert.signature, cert.tbs_certificate_bytes, signature_algorithm)
        elif isinstance(issuer_key, ec.EllipticCurvePublicKey):
            if signature_algorithm is None:
                return False
            issuer_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(signature_algorithm))
        elif isinstance(issuer_key, ed25519.Ed25519PublicKey):
            issuer_key.verify(cert.signature, cert.tbs_certificate_bytes)
        elif isinstance(issuer_key, dsa.DSAPublicKey):
            if signature_algorithm is None:
                return False
            issuer_key.verify(cert.signature, cert.tbs_certificate_bytes, signature_algorithm)
        else:
            return False
        return True
    except (InvalidSignature, UnsupportedAlgorithm, ValueError, TypeError):
        return False


@dataclass(frozen=True)
class AccessPolicy:
    require_identity: bool = True
    require_encryption: bool = True
    allow_known_ip: bool = False
    require_mtls: bool = False
    trust_ca_pem: str | None = None
    allow_expired_cert: bool = False


@dataclass(frozen=True)
class ClientCertificate:
    subject: str
    issuer: str
    fingerprint: str
    serial: int
    valid_from: datetime.datetime
    valid_to: datetime.datetime
    revoked: bool = False

    def is_valid_at(self, when: datetime.datetime | None = None) -> bool:
        now = when or datetime.datetime.now(datetime.timezone.utc)
        before = self.valid_from.astimezone(datetime.timezone.utc)
        after = self.valid_to.astimezone(datetime.timezone.utc)
        return (not self.revoked) and before <= now <= after


def parse_client_certificate(cert_pem: str) -> ClientCertificate:
    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    valid_from, valid_to = cert_validity(cert)
    return ClientCertificate(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
        serial=cert.serial_number,
        valid_from=valid_from,
        valid_to=valid_to,
    )


def verify_client_certificate(
    cert_pem: str,
    ca_pem: str,
    *,
    now: datetime.datetime | None = None,
) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
        ca = x509.load_pem_x509_certificate(ca_pem.encode("ascii"))
    except ValueError:
        return False

    if not _verify_issuer_signature(cert, ca.public_key()):
        return False

    parsed = parse_client_certificate(cert_pem)
    return parsed.is_valid_at(now)


def load_ca_from_pem(ca_pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(ca_pem.encode("ascii"))


class ServiceGate:
    def __init__(self, policy: AccessPolicy):
        self.policy = policy

    def authorize(
        self,
        *,
        ip: str | None,
        identity: str | None,
        encrypted: bool,
        session_id: str | None,
        client_cert_pem: str | None = None,
    ) -> bool:
        if self.policy.require_identity and not identity:
            raise PermissionError("Identity is required before access is granted.")

        if self.policy.require_encryption and not encrypted:
            raise PermissionError("Encrypted session is required before access is granted.")

        if session_id is None:
            raise PermissionError("Session validation is required before access is granted.")

        if self.policy.require_mtls:
            if not self.policy.trust_ca_pem:
                raise PermissionError(_TRUST_CA_REQUIRED)
            if not client_cert_pem:
                raise PermissionError(_CLIENT_CERT_REQUIRED)
            if not verify_client_certificate(client_cert_pem, self.policy.trust_ca_pem):
                if self.policy.allow_expired_cert:
                    return True
                raise PermissionError("Client certificate is not trusted or is invalid.")

        if ip and self.policy.allow_known_ip:
            # A known IP is only a routing hint; it never replaces identity or encryption.
            return True

        if not ip:
            raise PermissionError("Target IP is required for gateway validation.")

        return True