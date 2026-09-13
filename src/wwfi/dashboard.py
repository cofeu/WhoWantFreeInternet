from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Any, Dict

from flask import Flask, Response, jsonify, render_template_string, request

from .certs import CertificateManager
from .dns import LocalDNS
from .metrics import (
    MetricsRegistry,
    wwfi_certificate_metrics,
    wwfi_domain_metrics,
    wwfi_session_metrics,
)
from .registry import SiteRegistry

_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WWFI Admin</title>
<style>
 body{font-family:ui-monospace,monospace;background:#0f1115;color:#e6e6e6;margin:2rem}
 h1{color:#4db8ff} h2{color:#9ad0ff;border-bottom:1px solid #2a2f3a;padding-bottom:.3rem}
 table{border-collapse:collapse;width:100%;margin:1rem 0}
 th,td{text-align:left;padding:.4rem .7rem;border-bottom:1px solid #2a2f3a}
 .ok{color:#4ade80}.warn{color:#facc15}.bad{color:#f87171}
 form{display:inline}.btn{background:#1e2a38;color:#e6e6e6;border:1px solid #2a2f3a;padding:.3rem .8rem;cursor:pointer}
 input[type=text]{background:#161a22;border:1px solid #2a2f3a;color:#e6e6e6;padding:.3rem}
</style>
</head>
<body>
<h1>WWFI Admin</h1>
<section>
 <h2>Domainler</h2>
 <table id="domains"><thead><tr><th>Domain</th><th>Lokal backend</th><th>Host backend</th><th>TLS</th><th>Kimlik</th></tr></thead><tbody></tbody></table>
</section>
<section>
 <h2>DNS Kayıtları</h2>
 <table id="records"><thead><tr><th>Domain</th><th>Hedef</th><th>TTL</th><th>Encrypted</th></tr></thead><tbody></tbody></table>
</section>
<section>
 <h2>Sertifikalar</h2>
 <table id="certs"><thead><tr><th>Domain</th><th>Fingerprint</th><th>Bitiş</th></tr></thead><tbody></tbody></table>
</section>
<script>
const TOKEN = localStorage.getItem("wwfi_token") || "";
const headers = { "Authorization": "Bearer " + TOKEN, "Content-Type": "application/json" };
function row(tbl, cells){ const tr=document.createElement("tr"); cells.forEach(c=>{const td=document.createElement("td"); td.textContent=c; tr.appendChild(td);}); tbl.querySelector("tbody").appendChild(tr);}
function loadDomains(){ fetch("/api/domains",{headers}).then(r=>r.json()).then(d=>d.forEach(x=>row(document.getElementById("domains"),[x.domain,x.local_backend||"",x.host_backend||"",String(x.tls_enabled),x.identity||""]))).catch(showErr);}
function loadRecords(){ fetch("/api/records",{headers}).then(r=>r.json()).then(d=>d.forEach(x=>row(document.getElementById("records"),[x.domain,x.target,x.ttl,String(x.encrypted)]))).catch(showErr);}
function loadCerts(){ fetch("/api/certs",{headers}).then(r=>r.json()).then(d=>d.forEach(x=>row(document.getElementById("certs"),[x.domain,x.fingerprint,x.not_after]))).catch(showErr);}
function showErr(e){ console.error(e); }
function saveToken(){ localStorage.setItem("wwfi_token", document.getElementById("token").value.trim()); location.reload(); }
</script>
<footer>
 <h2>Kimlik Doğrulama</h2>
 <form onsubmit="event.preventDefault();saveToken();">
   <input type="text" id="token" placeholder="WWFI API token" autocomplete="off">
   <button class="btn" type="submit">Kaydet</button>
 </form>
</footer>
</body>
</html>
"""


@dataclass
class DashboardState:
    registry: SiteRegistry = field(default_factory=SiteRegistry)
    dns: LocalDNS = field(default_factory=LocalDNS)
    certificates: CertificateManager = field(default_factory=CertificateManager)
    metrics: MetricsRegistry = field(default_factory=MetricsRegistry)


def _require_auth(token: str | None):  # kept for programmatic use / tests
    def wrapper(request=None):
        if not token:
            return None
        auth = (request or {}).get("headers", {}).get("Authorization", "")
        provided = auth[7:] if auth.startswith("Bearer ") else None
        if provided and hmac.compare_digest(provided, token):
            return None
        return {"error": "unauthorized"}, 401

    return wrapper


def create_app(*, token: str | None = None, state: DashboardState | None = None) -> Flask:
    app = Flask(__name__)
    state = state or DashboardState()
    check_auth = _require_auth(token)

    @app.before_request
    def _auth() -> Response | None:
        if not token or request.path == "/api/health":
            return None
        auth = request.headers.get("Authorization", "")
        provided = auth[7:] if auth.startswith("Bearer ") else request.args.get("token", "")
        if provided and hmac.compare_digest(provided, token):
            return None
        return jsonify({"error": "unauthorized"}), 401

    @app.get("/")
    def index():
        return render_template_string(_INDEX_HTML)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/api/domains")
    def domains():
        rows = []
        for domain, cfg in state.registry.local.items():
            host = state.registry.host.get(domain)
            rows.append(
                {
                    "domain": domain,
                    "local_backend": cfg.backend,
                    "host_backend": host.backend if host else None,
                    "tls_enabled": cfg.tls_enabled,
                    "identity": cfg.identity,
                    "version": state.registry.versions.get(domain, 0),
                }
            )
        return jsonify(rows)

    @app.get("/api/records")
    def records():
        return jsonify(
            [
                {
                    "domain": domain,
                    "target": record.target,
                    "ttl": record.ttl,
                    "encrypted": record.encrypted,
                }
                for domain, record in sorted(state.dns.records.items())
            ]
        )

    @app.get("/api/certs")
    def certs():
        return jsonify(
            [
                {
                    "domain": domain,
                    "fingerprint": record.fingerprint,
                    "serial": record.serial,
                    "not_before": record.not_before.isoformat(),
                    "not_after": record.not_after.isoformat(),
                    "expiring": record.expires_soon(),
                }
                for domain, record in sorted(state.certificates.records.items())
            ]
        )

    @app.get("/api/metrics")
    def metrics():
        wwfi_domain_metrics(state.metrics, state.registry.local)
        wwfi_certificate_metrics(state.metrics, state.certificates.records)
        body = state.metrics.text()
        return Response(body, mimetype="text/plain; version=0.0.4")

    return app


def serve(host="127.0.0.1", port=8087, token=None, state=None) -> Flask:
    app = create_app(token=token, state=state)
    app.run(host=host, port=port, threaded=True)
    return app