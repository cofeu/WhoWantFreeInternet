#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ssl
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from wwfi.site import (  # noqa: E402
    TLS_MODE_ACME,
    TLS_MODE_CA,
    TLS_MODE_SELF_SIGNED,
    resolve_cert_paths,
)


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


def ensure_self_signed(domain: str, cert_dir: Path, *, reissue: bool = False) -> tuple[str, str]:
    out = cert_dir / "self-signed"
    out.mkdir(parents=True, exist_ok=True)
    cert_path = out / f"{domain}.crt"
    key_path = out / f"{domain}.key"
    if not reissue and cert_path.exists() and key_path.exists():
        return str(key_path), str(cert_path)
    for p in (cert_path, key_path):
        p.unlink(missing_ok=True)
    _run(
        [
            "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-days", "365", "-subj", f"/CN={domain}",
            "-addext", f"subjectAltName=DNS:{domain}",
        ]
    )
    return str(key_path), str(cert_path)


def choose_certificate(domain: str, cert_dir: Path, tls_mode: str, *, reissue: bool = False) -> tuple[str, str]:
    """Operator chooses the SSL source; 'auto' prefers acme > ca > self-signed."""
    if tls_mode == TLS_MODE_ACME:
        cert, key = resolve_cert_paths(domain, TLS_MODE_ACME, cert_dir)
        print(f"[wwfi-https] {domain} using ACME cert: {cert}")
        return str(key), str(cert)
    if tls_mode == TLS_MODE_SELF_SIGNED:
        ctx = ensure_self_signed(domain, cert_dir, reissue=reissue)
        print(f"[wwfi-https] {domain} using self-signed cert (tls_mode=self-signed)")
        return ctx
    if tls_mode == "auto":
        acme_cert, acme_key = cert_dir / "acme" / f"{domain}.crt", cert_dir / "acme" / f"{domain}.key"
        if acme_cert.exists() and acme_key.exists():
            print(f"[wwfi-https] {domain} using ACME cert (auto)")
            return str(acme_key), str(acme_cert)
    ca_cert, ca_key = cert_dir / f"{domain}.crt", cert_dir / f"{domain}.key"
    if tls_mode == "auto" and ca_cert.exists() and ca_key.exists():
        print(f"[wwfi-https] {domain} using WWFI CA cert (auto)")
        return str(ca_key), str(ca_cert)
    ctx = ensure_certificate(domain, cert_dir, reissue=reissue)
    label = "ca" if tls_mode == TLS_MODE_CA or (tls_mode == "auto" and (cert_dir / "ca.key").exists()) else "self-signed"
    print(f"[wwfi-https] {domain} using {label} cert (mode={tls_mode})")
    return ctx


def main() -> None:
    parser = argparse.ArgumentParser(description="WWFI HTTPS static file server for a local domain.")
    parser.add_argument("--domain", default="cofeu.org")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--dir", default=str(ROOT), help="Directory to serve files from.")
    parser.add_argument(
        "--tls-mode",
        choices=["auto", "acme", "ca", "self-signed"],
        default="auto",
        help="SSL source: acme (Let's Encrypt), ca (WWFI Local Root CA), self-signed, or auto-pick.",
    )
    parser.add_argument("--reissue", action="store_true", help="Re-issue the certificate.")
    parser.add_argument("--issue-only", action="store_true", help="Issue the certificate then exit (no server).")
    args = parser.parse_args()

    key_path, cert_path = choose_certificate(args.domain, ROOT / "certs", args.tls_mode, reissue=args.reissue)
    if args.issue_only:
        print(f"[wwfi-https] issued cert for {args.domain}: {cert_path}")
        return

    handler = lambda *a, **kw: SimpleHTTPRequestHandler(
        *a, directory=args.dir, **kw
    )
    server = ThreadingHTTPServer((args.host, args.port), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"[wwfi-https] {args.domain} -> {args.host}:{args.port} (tls-mode={args.tls_mode}, dir: {args.dir})")
    print(f"[wwfi-https] curl --resolve {args.domain}:{args.port}:{args.host} -k https://{args.domain}:{args.port}/test.html")
    server.serve_forever()


if __name__ == "__main__":
    main()