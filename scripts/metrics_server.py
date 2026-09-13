#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from wwfi.certs import CertificateManager
from wwfi.metrics import (
    MetricsRegistry,
    wwfi_certificate_metrics,
    wwfi_domain_metrics,
    wwfi_session_metrics,
)
from wwfi.registry import SiteRegistry


class MetricsHandler(BaseHTTPRequestHandler):
    state = {}

    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404)
            return
        body = self.state["registry"].text().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *args):
        return


def build_state(registry_file: str | None = None) -> MetricsRegistry:
    registry = MetricsRegistry()
    sites = SiteRegistry()
    certs = CertificateManager()
    default_sites = {
        "demo.local": "127.0.0.1:8443",
        "shop.local": "127.0.0.1:8080",
    }
    for domain, backend in default_sites.items():
        sites.register_site(domain, backend, backend, identity="demo")
    wwfi_domain_metrics(registry, sites.local, instances=len(sites.local))
    wwfi_session_metrics(registry, active_sessions=1, rejected_sessions=0)

    if registry_file:
        data = json.loads(Path(registry_file).read_text(encoding="utf-8"))
        for domain, path in (data.get("certificates") or {}).items():
            if Path(path).exists():
                certs.register(Path(path).read_text(encoding="utf-8"), domain=domain)
        if certs.records:
            wwfi_certificate_metrics(registry, certs.records)
    return registry


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve WWFI Prometheus metrics over HTTP.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9090)
    parser.add_argument("--registry-file", default=None, help="Optional JSON registry describing certificate paths.")
    args = parser.parse_args()

    MetricsHandler.state = {"registry": build_state(args.registry_file)}
    server = ThreadingHTTPServer((args.host, args.port), MetricsHandler)
    print(f"WWFI metrics listening on http://{args.host}:{args.port}/metrics")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    main()