from wwfi.certs import CertificateManager, parse_certificate_record
from wwfi.dns import LocalDNS
from wwfi.metrics import (
    MetricsRegistry,
    wwfi_certificate_metrics,
    wwfi_domain_metrics,
    wwfi_session_metrics,
)
from wwfi.registry import SiteRegistry


def _make_cert(domain, days_left):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_left))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def test_registry_exports_prometheus_text_format():
    registry = MetricsRegistry()
    registry.inc("wwfi_rejected_sessions_total", "Total rejected session attempts")
    registry.gauge("wwfi_active_sessions", "Active sessions", value=3)

    text = registry.text()

    assert "# TYPE wwfi_rejected_sessions_total counter" in text
    assert "wwfi_rejected_sessions_total 1.0" in text
    assert "# TYPE wwfi_active_sessions gauge" in text
    assert "wwfi_active_sessions 3.0" in text


def test_counter_accumulates_with_labels():
    registry = MetricsRegistry()
    registry.inc("wwfi_sync_applies_total", "Applied syncs", {"domain": "demo.local"})
    registry.inc("wwfi_sync_applies_total", "Applied syncs", {"domain": "demo.local"})
    registry.inc("wwfi_sync_applies_total", "Applied syncs", {"domain": "shop.local"})

    text = registry.text()

    assert 'wwfi_sync_applies_total{domain="demo.local"} 2.0' in text
    assert 'wwfi_sync_applies_total{domain="shop.local"} 1.0' in text


def test_gauge_overwrites_previous_value():
    registry = MetricsRegistry()
    registry.gauge("wwfi_active_sessions", "Active sessions", value=5)
    registry.gauge("wwfi_active_sessions", "Active sessions", value=2)

    assert "wwfi_active_sessions 2.0" in registry.text()


def test_wwfi_domain_metrics_reports_each_published_domain():
    registry = MetricsRegistry()
    registry_local = SiteRegistry()
    registry_local.register_site("demo.local", "127.0.0.1:8000", "10.0.0.15:8000")

    wwfi_domain_metrics(registry, registry_local.local)

    text = registry.text()
    assert 'wwfi_published_domains{domain="demo.local"} 1.0' in text
    assert 'wwfi_published_domains{instance="total"} 1.0' in text


def test_wwfi_certificate_metrics_reports_days_remaining():
    registry = MetricsRegistry()
    manager = CertificateManager()
    manager.register(_make_cert("demo.local", days_left=15), domain="demo.local")

    wwfi_certificate_metrics(registry, manager.records)

    text = registry.text()
    assert 'wwfi_cert_expiring{domain="demo.local"} 1.0' in text


def test_wwfi_session_metrics_records_state():
    registry = MetricsRegistry()
    wwfi_session_metrics(registry, active_sessions=7, rejected_sessions=2)

    text = registry.text()
    assert "wwfi_active_sessions 7.0" in text
    assert "wwfi_rejected_sessions_total 2.0" in text


def test_health_returns_metrics_text():
    registry = MetricsRegistry()
    assert registry.health() == registry.text()