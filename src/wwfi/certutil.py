"""Internal helpers for reading certificate validity across cryptography versions.

Newer cryptography releases removed the ``_utc`` validity accessors, while
older ones returned naïve datetimes from the plain accessors. These helpers
normalize to timezone-aware UTC datetimes regardless of the installed version.
"""

from __future__ import annotations

import datetime


def _to_utc_aware(value: datetime.datetime) -> datetime.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc)


def cert_validity(cert) -> tuple[datetime.datetime, datetime.datetime]:
    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_before is None:
        not_before = cert.not_valid_before
    if not_after is None:
        not_after = cert.not_valid_after
    return _to_utc_aware(not_before), _to_utc_aware(not_after)