import pytest

from wwfi.site import SiteManager


def test_domain_site_is_exposed_with_https_by_default():
    manager = SiteManager()
    site = manager.publish_site("app.local", "127.0.0.1:8000")

    assert site.domain == "app.local"
    assert site.url == "https://app.local"
    assert site.tls_enabled is True


def test_site_manager_rejects_non_tls_site_for_public_domain():
    manager = SiteManager()

    with pytest.raises(ValueError):
        manager.publish_site("unsafe.local", "127.0.0.1:8080", tls_enabled=False)


def test_domain_with_certificate_has_fingerprint():
    manager = SiteManager()
    site = manager.publish_site("secure.local", "127.0.0.1:9000")

    assert site.certificate.fingerprint
    assert site.certificate.domain == "secure.local"
