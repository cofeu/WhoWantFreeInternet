from wwfi.dns import LocalDNS


def test_local_dns_exports_hosts_file_format():
    dns = LocalDNS()
    dns.add_record("demo.local", "127.0.0.1:8443", encrypted=True)

    hosts = dns.as_hosts_file()

    assert "127.0.0.1 demo.local" in hosts
