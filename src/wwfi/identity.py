from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class CIPNIPRoute:
    domain: str
    backend: str
    private_ip: str
    encrypted: bool = True


class CIPNIPRouter:
    def __init__(self):
        self.routes: Dict[str, CIPNIPRoute] = {}

    def register(self, domain: str, backend: str, *, private_ip: str, encrypted: bool = True) -> CIPNIPRoute:
        if not domain:
            raise ValueError("Domain is required.")
        if not private_ip:
            raise ValueError("Private IP is required.")
        if not encrypted:
            raise PermissionError("Private route requires encrypted transport.")

        route = CIPNIPRoute(domain=domain, backend=backend, private_ip=private_ip, encrypted=encrypted)
        self.routes[domain] = route
        return route

    def resolve(self, domain: str) -> dict:
        route = self.routes.get(domain)
        if route is None:
            raise KeyError(f"No route registered for {domain}")
        return {
            "domain": route.domain,
            "backend": route.backend,
            "private_ip": route.private_ip,
            "encrypted": route.encrypted,
        }
