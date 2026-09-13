from wwfi.dns_service import LocalDNSService


def test_dns_service_exports_hosts_and_dnsmasq_entries():
    service = LocalDNSService()
    service.add_record("demo.local", "127.0.0.1:8443")
    service.add_record("shop.local", "127.0.0.1:8080")

    hosts = service.export_hosts()
    dnsmasq = service.export_dnsmasq()

    assert "127.0.0.1 demo.local" in hosts
    assert "127.0.0.1 shop.local" in hosts
    assert "address=/demo.local/127.0.0.1" in dnsmasq
    assert "address=/shop.local/127.0.0.1" in dnsmasq


def test_dns_service_exports_stubby_dot_config():
    service = LocalDNSService()
    stubby = service.export_stubby()

    assert "GETDNS_TRANSPORT_TLS" in stubby
    assert "tls_auth_name: cloudflare-dns.com" in stubby
    assert "127.0.0.1@5353" in stubby


def test_dns_service_write_files_includes_stubby(tmp_path):
    service = LocalDNSService()
    service.add_record("demo.local", "127.0.0.1:8443")

    result = service.write_files(tmp_path)

    assert (tmp_path / "wwfi-stubby.yml").exists()
    assert "stubby" in result
    assert "GETDNS_TRANSPORT_TLS" in (tmp_path / "wwfi-stubby.yml").read_text(encoding="utf-8")
