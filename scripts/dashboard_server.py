#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os

from wwfi.dashboard import DashboardState, serve


def main() -> None:
    parser = argparse.ArgumentParser(description="WWFI admin dashboard server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8087)
    parser.add_argument("--token", default=None, help="API token (defaults to WWFI_TOKEN env).")
    args = parser.parse_args()

    token = args.token or os.environ.get("WWFI_TOKEN")
    state = DashboardState()
    for domain, backend in [("demo.local", "127.0.0.1:8000"), ("shop.local", "127.0.0.1:8080")]:
        state.registry.register_site(domain, backend, backend, identity="demo")
        state.dns.add_record(domain, backend)

    serve(host=args.host, port=args.port, token=token, state=state)


if __name__ == "__main__":
    main()