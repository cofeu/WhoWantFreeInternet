from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .certutil import cert_validity

_REQUIRED_DEFAULT_DAYS = 30


def _parse(cert_pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(cert_pem.encode("ascii"))


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


@dataclass(frozen=True)
class CertificateRecord:
    domain: str
    fingerprint: str
    serial: int
    not_before: datetime.datetime
    not_after: datetime.datetime
    path: str | None = None
    pem: str | None = None

    def expires_soon(self, days_before: int = _REQUIRED_DEFAULT_DAYS, now: datetime.datetime | None = None) -> bool:
        current = now or _now()
        renew_at = self.not_after - datetime.timedelta(days=days_before)
        return current >= renew_at

    def is_expired(self, now: datetime.datetime | None = None) -> bool:
        return (now or _now()) >= self.not_after


def certificate_fingerprint(cert_pem: str) -> str:
    return _parse(cert_pem).fingerprint(hashes.SHA256()).hex()


def parse_certificate_record(cert_pem: str, *, domain: str | None = None, path: str | None = None) -> CertificateRecord:
    cert = _parse(cert_pem)
    if domain is None:
        first_name = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        domain = first_name[0].value if first_name else "unknown"
    not_before, not_after = cert_validity(cert)
    return CertificateRecord(
        domain=domain,
        fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
        serial=cert.serial_number,
        not_before=not_before,
        not_after=not_after,
        path=path,
        pem=cert_pem,
    )


class CertificateManager:
    def __init__(self, cert_dir: str | Path | None = None):
        self.cert_dir = Path(cert_dir) if cert_dir else None
        if self.cert_dir is not None:
            self.cert_dir.mkdir(parents=True, exist_ok=True)
        self.records: Dict[str, CertificateRecord] = {}
        self.backups: Dict[str, List[str]] = {}

    def register(self, cert_pem: str, *, domain: str | None = None, path: str | None = None) -> CertificateRecord:
        record = parse_certificate_record(cert_pem, domain=domain, path=path)
        self.records[record.domain] = record
        self.backups.setdefault(record.domain, [])
        return record

    def needs_renewal(self, domain: str, days_before: int = _REQUIRED_DEFAULT_DAYS, now: datetime.datetime | None = None) -> bool:
        record = self.records.get(domain)
        if record is None:
            return True
        return record.expires_soon(days_before=days_before, now=now)

    def rotate(self, domain: str, new_cert_pem: str, *, new_path: str | None = None) -> CertificateRecord:
        old = self.records.get(domain)
        if old is not None:
            backup_path = self._backup(domain, old)
            self.backups.setdefault(domain, []).append(backup_path)
        record = parse_certificate_record(new_cert_pem, domain=domain, path=new_path)
        self.records[domain] = record
        if new_path and self.cert_dir is not None:
            Path(new_path).write_text(new_cert_pem.rstrip() + "\n", encoding="utf-8")
        return record

    def rollback(self, domain: str) -> CertificateRecord | None:
        backups = self.backups.get(domain) or []
        if not backups:
            return None
        backup_path = backups.pop()
        cert_pem = Path(backup_path).read_text(encoding="utf-8")
        record = parse_certificate_record(cert_pem, domain=domain, path=backup_path)
        self.records[domain] = record
        return record

    def list_certificates(self) -> Dict[str, CertificateRecord]:
        return dict(self.records)

    def _backup(self, domain: str, record: CertificateRecord) -> str:
        if self.cert_dir is None:
            return ""
        backup_dir = self.cert_dir / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        suffix = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        backup_path = backup_dir / f"{domain}-{suffix}.pem"
        if record.pem:
            backup_path.write_text(record.pem.rstrip() + "\n", encoding="utf-8")
        elif record.path and Path(record.path).exists():
            backup_path.write_bytes(Path(record.path).read_bytes())
        return str(backup_path)