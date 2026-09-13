import pytest

from wwfi.dns import LocalDNS


def test_local_dns_resolves_secure_domain():
    dns = LocalDNS()
    dns.add_record("app.local", "127.0.0.1:8000", encrypted=True)

    record = dns.resolve("app.local")

    assert record is not None
    assert record.target == "127.0.0.1:8000"
    assert dns.requires_encryption("app.local") is True


def test_local_dns_rejects_unencrypted_domain_for_secure_network():
    dns = LocalDNS()
    dns.add_record("unsafe.local", "127.0.0.1:8000", encrypted=False)

    assert dns.requires_encryption("unsafe.local") is False


def test_local_dns_missing_domain_raises_none():
    dns = LocalDNS()

    assert dns.resolve("missing.local") is None
