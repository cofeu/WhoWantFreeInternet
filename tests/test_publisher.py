from wwfi.publisher import DomainPublisher


def test_domain_publisher_creates_local_and_host_mappings():
    publisher = DomainPublisher()
    site = publisher.publish(
        domain="demo.local",
        local_backend="127.0.0.1:8000",
        host_backend="10.0.0.30:8000",
        tls_enabled=True,
        identity="alice",
        port=443,
    )

    assert site.domain == "demo.local"
    assert site.local_backend == "127.0.0.1:8000"
    assert site.host_backend == "10.0.0.30:8000"
    assert site.https_url == "https://demo.local"
    assert "curl --resolve demo.local:443:127.0.0.1" in site.curl_command
    assert "Host: demo.local" in site.wget_command


def test_domain_publisher_rejects_unencrypted_publish():
    publisher = DomainPublisher()

    try:
        publisher.publish(
            domain="unsafe.local",
            local_backend="127.0.0.1:8000",
            host_backend="10.0.0.30:8000",
            tls_enabled=False,
            identity="alice",
            port=443,
        )
        assert False, "Expected ValueError for unencrypted domain publish"
    except ValueError:
        pass
