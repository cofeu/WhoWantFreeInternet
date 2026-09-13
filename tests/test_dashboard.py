import datetime

import pytest

flask = pytest.importorskip("flask")

from wwfi.certs import CertificateManager
from wwfi.dashboard import DashboardState, create_app
from wwfi.dns import LocalDNS
from wwfi.registry import SiteRegistry


def _make_cert(domain):
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
        .not_valid_after(now + datetime.timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


@pytest.fixture
def state():
    state = DashboardState()
    state.registry.register_site("demo.local", "127.0.0.1:8000", "10.0.0.15:8000", identity="alice")
    state.dns.add_record("shop.local", "127.0.0.1:8080", ttl=120)
    state.certificates.register(_make_cert("demo.local"), domain="demo.local")
    return state


@pytest.fixture
def client(state):
    app = create_app(token="sekret-token", state=state)
    return app.test_client()


def test_health_endpoint_is_public(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_domain_endpoint_requires_token(client):
    assert client.get("/api/domains").status_code == 401


def test_domains_endpoint_lists_published_sites(client):
    response = client.get("/api/domains", headers={"Authorization": "Bearer sekret-token"})
    assert response.status_code == 200
    data = response.get_json()
    assert data[0]["domain"] == "demo.local"
    assert data[0]["host_backend"] == "10.0.0.15:8000"
    assert data[0]["identity"] == "alice"


def test_records_endpoint_lists_dns_records(client):
    response = client.get("/api/records", headers={"Authorization": "Bearer sekret-token"})
    data = response.get_json()
    assert any(record["domain"] == "shop.local" and record["target"] == "127.0.0.1:8080" and record["ttl"] == 120 for record in data)


def test_certs_endpoint_reports_certificate_state(client):
    response = client.get("/api/certs", headers={"Authorization": "Bearer sekret-token"})
    data = response.get_json()
    assert data[0]["domain"] == "demo.local"
    assert len(data[0]["fingerprint"]) == 64
    assert data[0]["expiring"] is False


def test_metrics_endpoint_exports_prometheus_text(client):
    response = client.get("/api/metrics", headers={"Authorization": "Bearer sekret-token"})
    assert response.status_code == 200
    assert response.mimetype.startswith("text/plain")
    assert 'wwfi_published_domains{domain="demo.local"} 1.0' in response.get_data(as_text=True)


def test_index_serves_dashboard_html(client):
    response = client.get("/", headers={"Authorization": "Bearer sekret-token"})
    assert response.status_code == 200
    assert "WWFI Admin" in response.get_data(as_text=True)


def test_token_can_be_passed_as_query_param(state):
    app = create_app(token="query-token", state=state)
    response = app.test_client().get("/api/domains", query_string={"token": "query-token"})
    assert response.status_code == 200