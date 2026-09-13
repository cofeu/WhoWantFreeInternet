import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from wwfi.certutil import cert_validity
from wwfi.certs import (
    CertificateManager,
    certificate_fingerprint,
    parse_certificate_record,
)


def _cert_pem(cn: str, *, valid_days: int, serial: int = 1) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


@pytest.fixture
def long_lived():
    return _cert_pem("demo.local", valid_days=365, serial=100)


@pytest.fixture
def expiring_soon():
    return _cert_pem("expiring.local", valid_days=10, serial=101)


@pytest.fixture
def replacement():
    return _cert_pem("demo.local", valid_days=400, serial=200)


@pytest.fixture
def cert_dir(tmp_path):
    return tmp_path / "certs"


def test_parse_record_extracts_domain_and_dates(long_lived):
    record = parse_certificate_record(long_lived)

    assert record.domain == "demo.local"
    assert record.serial == 100
    assert record.not_after > record.not_before


def test_fingerprint_is_hex_sha256(long_lived):
    fingerprint = certificate_fingerprint(long_lived)
    assert len(fingerprint) == 64
    assert int(fingerprint, 16) >= 0


def test_needs_renewal_flags_short_lifetime(expiring_soon, long_lived):
    short = CertificateManager()
    short.register(expiring_soon)

    long = CertificateManager()
    long.register(long_lived)

    assert short.needs_renewal("expiring.local") is True
    assert long.needs_renewal("demo.local") is False


def test_needs_renewal_unknown_domain_returns_true():
    manager = CertificateManager()
    assert manager.needs_renewal("missing.local") is True


def test_rotate_updates_record_and_preserves_old_backup(cert_dir, long_lived, replacement):
    manager = CertificateManager(cert_dir)
    original_path = cert_dir / "demo.local.pem"
    original_path.write_text(long_lived, encoding="utf-8")
    manager.register(long_lived, domain="demo.local", path=str(original_path))

    rotated = manager.rotate("demo.local", replacement, new_path=str(cert_dir / "demo.local.pem"))

    assert rotated is manager.records["demo.local"]
    assert rotated.serial == 200
    assert rotated.fingerprint == certificate_fingerprint(replacement)
    assert len(manager.backups["demo.local"]) == 1
    assert any((cert_dir / "backups").iterdir())


def test_rollback_restores_previous_certificate(cert_dir, long_lived, replacement):
    manager = CertificateManager(cert_dir)
    manager.register(long_lived, domain="demo.local")
    manager.rotate("demo.local", replacement, new_path=str(cert_dir / "demo.local.pem"))

    restored = manager.rollback("demo.local")

    assert restored is not None
    assert restored.fingerprint == certificate_fingerprint(long_lived)
    assert manager.records["demo.local"].fingerprint == certificate_fingerprint(long_lived)


def test_rollback_without_backup_returns_none(long_lived):
    manager = CertificateManager()
    manager.register(long_lived, domain="demo.local")

    assert manager.rollback("demo.local") is None


def test_list_certificates_returns_all(long_lived):
    manager = CertificateManager()
    manager.register(long_lived, domain="demo.local")
    manager.register(_cert_pem("shop.local", valid_days=100), domain="shop.local")

    assert set(manager.list_certificates()) == {"demo.local", "shop.local"}


def test_cert_validity_falls_back_when_utc_accessors_missing():
    naive_before = datetime.datetime(2026, 1, 1, 12, 0, 0)
    naive_after = datetime.datetime(2027, 1, 1, 12, 0, 0)

    class FakeCert:
        not_valid_before = naive_before
        not_valid_after = naive_after

    before, after = cert_validity(FakeCert())

    assert before.tzinfo == datetime.timezone.utc
    assert after.tzinfo == datetime.timezone.utc
    assert before.hour == 12
    assert after.year == 2027


def test_cert_validity_prefers_utc_accessors_when_present():
    aware_before = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
    aware_after = datetime.datetime(2027, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)

    class FakeCert:
        not_valid_before_utc = aware_before
        not_valid_after_utc = aware_after
        not_valid_before = aware_before - datetime.timedelta(days=30)
        not_valid_after = aware_after + datetime.timedelta(days=30)

    before, after = cert_validity(FakeCert())

    assert before == aware_before
    assert after == aware_after