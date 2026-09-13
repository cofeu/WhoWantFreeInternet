#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from pathlib import Path

from wwfi.dns_service import LocalDNSService


CONFIG_PATH = Path('/tmp/wwfi-dns-config.json')
OUTPUT_DIR = Path('/tmp/wwfi-dns')


def main() -> None:
    service = LocalDNSService()
    service.add_record('demo.local', '127.0.0.1:8443')
    service.add_record('shop.local', '127.0.0.1:8080')
    CONFIG_PATH.write_text(json.dumps(service.export_config(), indent=2), encoding='utf-8')
    service.write_files(OUTPUT_DIR)
    print('WWFI DNS background service running')
    print(service.export_dnsmasq())

    while True:
        time.sleep(30)
        if CONFIG_PATH.exists():
            updated = json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
            service.records = updated.get('records', {})
            service.write_files(OUTPUT_DIR)


if __name__ == '__main__':
    main()
