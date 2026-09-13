from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RoutePolicy:
    allow_private_routes: bool = True
    enforce_encryption: bool = True
    require_identity: bool = True


@dataclass
class Route:
    source: str
    destination: str
    encrypted: bool = True
    identity: str | None = None


class RouteManager:
    def __init__(self, policy: RoutePolicy):
        self.policy = policy
        self.routes: dict[str, Route] = {}

    def add_route(self, source: str, destination: str, encrypted: bool = True, identity: str | None = None) -> Route:
        if self.policy.require_identity and not identity:
            raise PermissionError("Identity is required to register a route.")
        if self.policy.enforce_encryption and not encrypted:
            raise PermissionError("Encrypted route is required.")

        route = Route(source=source, destination=destination, encrypted=encrypted, identity=identity)
        self.routes[source] = route
        return route

    def resolve(self, source: str) -> Route | None:
        return self.routes.get(source)
