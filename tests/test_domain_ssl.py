import pytest

from wwfi.site import (
    SiteManager,
    TLS_MODE_ACME,
    TLS_MODE_CA,
    TLS_MODE_SELF_SIGNED,
    resolve_cert_paths,
)


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


def test_site_defaults_to_ca_tls_mode():
    manager = SiteManager()
    site = manager.publish_site("app.local", "127.0.0.1:8000")

    assert site.tls_mode == TLS_MODE_CA


def test_site_accepts_operator_chosen_tls_mode():
    manager = SiteManager()
    site = manager.publish_site("secure.local", "127.0.0.1:9000", tls_mode=TLS_MODE_ACME)

    assert site.tls_mode == TLS_MODE_ACME


def test_site_rejects_unknown_tls_mode():
    manager = SiteManager()

    with pytest.raises(ValueError):
        manager.publish_site("secure.local", "127.0.0.1:9000", tls_mode="http")


def test_resolve_cert_paths_maps_each_tls_mode(tmp_path):
    # ACME path is only returned when certs actually exist.
    acme_dir = tmp_path / "acme"
    acme_dir.mkdir()
    (acme_dir / "cofeu.org.crt").write_text("cert")
    (acme_dir / "cofeu.org.key").write_text("key")
    acme_cert, acme_key = resolve_cert_paths("cofeu.org", TLS_MODE_ACME, tmp_path)
    assert (acme_cert, acme_key) == (acme_dir / "cofeu.org.crt", acme_dir / "cofeu.org.key")

    ca_cert, ca_key = resolve_cert_paths("cofeu.org", TLS_MODE_CA, tmp_path)
    assert (ca_cert, ca_key) == (tmp_path / "cofeu.org.crt", tmp_path / "cofeu.org.key")

    ss_cert, ss_key = resolve_cert_paths("cofeu.org", TLS_MODE_SELF_SIGNED, tmp_path)
    assert (ss_cert, ss_key) == (tmp_path / "self-signed" / "cofeu.org.crt", tmp_path / "self-signed" / "cofeu.org.key")


def test_resolve_cert_paths_acme_requires_issued_certificate(tmp_path):
    with pytest.raises(OSError):
        resolve_cert_paths("cofeu.org", TLS_MODE_ACME, tmp_path)


def test_resolve_cert_paths_rejects_unknown_mode(tmp_path):
    with pytest.raises(ValueError):
        resolve_cert_paths("cofeu.org", "keystore", tmp_path)
