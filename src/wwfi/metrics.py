from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, Tuple


def _sanitize_label(value) -> str:
    text = str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
    return text


@dataclass
class MetricFamily:
    name: str
    documentation: str
    metric_type: str  # counter | gauge


class MetricsRegistry:
    def __init__(self):
        self._counters: Dict[str, Dict[Tuple[str, str], float]] = {}
        self._gauges: Dict[str, Dict[Tuple[str, str], float]] = {}
        self._families: Dict[str, MetricFamily] = {}
        self._lock = threading.Lock()

    def _declare(self, name: str, documentation: str, metric_type: str, store: dict) -> None:
        with self._lock:
            store.setdefault(name, {})
            self._families.setdefault(
                name,
                MetricFamily(name=name, documentation=documentation, metric_type=metric_type),
            )

    def counter(self, name: str, documentation: str, labels: Dict[str, str] | None = None, value: float = 0.0) -> None:
        self._declare(name, documentation, "counter", self._counters)
        with self._lock:
            key = tuple(sorted((labels or {}).items()))
            self._counters[name][key] = self._counters[name].get(key, 0.0) + value

    def gauge(self, name: str, documentation: str, labels: Dict[str, str] | None = None, value: float = 0.0) -> None:
        self._declare(name, documentation, "gauge", self._gauges)
        with self._lock:
            key = tuple(sorted((labels or {}).items()))
            self._gauges[name][key] = value

    def inc(self, name: str, documentation: str, labels: Dict[str, str] | None = None) -> None:
        self.counter(name, documentation, labels, 1.0)

    def text(self) -> str:
        with self._lock:
            lines = []
            for name, family in sorted(self._families.items()):
                lines.append(f"# HELP {family.name} {family.documentation}")
                lines.append(f"# TYPE {family.name} {family.metric_type}")
                samples = getattr(self, f"_{family.metric_type}s")[name]
                for labels, value in sorted(samples.items()):
                    if labels:
                        parts = ", ".join(f'{k}="{_sanitize_label(v)}"' for k, v in labels)
                        lines.append(f"{name}{{{parts}}} {float(value)}")
                    else:
                        lines.append(f"{name} {float(value)}")
            return "\n".join(lines) + "\n"

    def health(self) -> str:
        return self.text()


def wwfi_session_metrics(registry: MetricsRegistry, *, active_sessions: int = 0, rejected_sessions: int = 0) -> MetricsRegistry:
    registry.gauge("wwfi_active_sessions", "Number of active encrypted sessions", value=active_sessions)
    registry.counter("wwfi_rejected_sessions_total", "Total rejected or blocked session attempts", value=rejected_sessions)
    return registry


def wwfi_domain_metrics(registry: MetricsRegistry, domains: dict, *, instances: int = 1) -> MetricsRegistry:
    for domain in domains:
        registry.gauge(
            "wwfi_published_domains",
            "Number of published WWFI domains",
            labels={"domain": domain},
            value=1,
        )
    registry.gauge(
        "wwfi_published_domains",
        "Number of published WWFI domains",
        labels={"instance": "total"},
        value=float(instances),
    )
    return registry


def wwfi_certificate_metrics(registry: MetricsRegistry, records: dict, *, now: float | None = None) -> MetricsRegistry:
    current = now or time.time()
    for domain, record in records.items():
        days_left = (record.not_after.timestamp() - current) / 86400.0
        registry.gauge(
            "wwfi_cert_days_remaining",
            "Days remaining until certificate expiration",
            labels={"domain": domain},
            value=days_left,
        )
        registry.gauge(
            "wwfi_cert_expiring",
            "Certificate expiring soon (1) or healthy (0)",
            labels={"domain": domain},
            value=1.0 if days_left < 30 else 0.0,
        )
    return registry