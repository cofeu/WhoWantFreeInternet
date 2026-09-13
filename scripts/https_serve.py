#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ssl
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _run(cmd: list[str]) -> None:
    import subprocess

    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def ensure_certificate(domain: str, cert_dir: Path, *, reissue: bool = False) -> tuple[str, str]:
    cert_dir.mkdir(exist_ok=True)
    key_path = cert_dir / f"{domain}.key"
    csr_path = cert_dir / f"{domain}.csr"
    cert_path = cert_dir / f"{domain}.crt"
    ext_path = cert_dir / f"{domain}.san"

    if not reissue and key_path.exists() and cert_path.exists():
        return str(key_path), str(cert_path)

    if reissue:
        for p in (key_path, csr_path, cert_path):
            p.unlink(missing_ok=True)

    ca_key = cert_dir / "ca.key"
    ca_cert = cert_dir / "ca.crt"
    signed_by_ca = ca_key.exists() and ca_cert.exists()

    _run(
        [
            "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key_path), "-out", str(csr_path),
            "-subj", f"/CN={domain}",
        ]
    )
    ext_path.write_text(f"subjectAltName=DNS:{domain}\n")
    if signed_by_ca:
        _run(
            [
                "openssl", "x509", "-req", "-in", str(csr_path),
                "-CA", str(ca_cert), "-CAkey", str(ca_key),
                "-CAcreateserial", "-out", str(cert_path),
                "-days", "825", "-sha256", "-extfile", str(ext_path),
            ]
        )
        print(f"[wwfi-https] issued {domain} certificate signed by WWFI Local Root CA")
    else:
        _run(
            [
                "openssl", "x509", "-req", "-in", str(csr_path),
                "-signkey", str(key_path), "-out", str(cert_path),
                "-days", "365", "-extfile", str(ext_path),
            ]
        )
        print(f"[wwfi-https] issued self-signed {domain} certificate (CA keys not found)")
    return str(key_path), str(cert_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="WWFI HTTPS static file server for a local domain.")
    parser.add_argument("--domain", default="cofeu.org")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--dir", default=str(ROOT), help="Directory to serve files from.")
    parser.add_argument("--reissue", action="store_true", help="Re-issue the certificate (CA-signed if certs/ca.key exists).")
    args = parser.parse_args()

    key_path, cert_path = ensure_certificate(args.domain, ROOT / "certs", reissue=args.reissue)
    handler = lambda *a, **kw: SimpleHTTPRequestHandler(
        *a, directory=args.dir, **kw
    )
    server = ThreadingHTTPServer((args.host, args.port), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"[wwfi-https] {args.domain} -> {args.host}:{args.port} (dir: {args.dir})")
    print(f"[wwfi-https] curl --resolve {args.domain}:{args.port}:{args.host} -k https://{args.domain}:{args.port}/test.html")
    server.serve_forever()


if __name__ == "__main__":
    main()