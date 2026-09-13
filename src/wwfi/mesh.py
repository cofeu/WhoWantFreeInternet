from __future__ import annotations

import asyncio
import contextlib
import datetime
import hashlib
import hmac
import json
import os
import ssl
import struct
import threading
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .admin import AdminAuth, admin_panel_html
from .certs import certificate_fingerprint
from .certutil import cert_validity

DEFAULT_CONTROL_HOST = "127.0.0.1"
DEFAULT_CONTROL_PORT = 8123
DEFAULT_BIND_PORT = 9443

MESH_FRAME_MAX = 1 << 20  # 1 MiB header cap


class MeshError(Exception):
    pass


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


@dataclass
class MeshKey:
    node_id: str
    key: ed25519.Ed25519PrivateKey

    @property
    def public_bytes(self) -> bytes:
        return self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.public_bytes).hexdigest()

    @property
    def node_fingerprint(self) -> str:
        return self.fingerprint[:32]

    def sign(self, payload: bytes) -> bytes:
        return self.key.sign(payload)

    @staticmethod
    def load_or_create(path: str | Path, node_id: str) -> "MeshKey":
        path = Path(path)
        if path.exists():
            raw = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(raw, ed25519.Ed25519PrivateKey):
                raise MeshError(f"{path} is not an Ed25519 key")
            return MeshKey(node_id=node_id, key=raw)
        key = ed25519.Ed25519PrivateKey.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        os.chmod(path, 0o600)
        return MeshKey(node_id=node_id, key=key)


# ---------------------------------------------------------------------------
# Certificates (CA + per-node mTLS certs)
# ---------------------------------------------------------------------------


def _build_name(cn: str):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def generate_ca(out_dir: str | Path, *, cn: str = "WWFI Mesh Root CA") -> Tuple[str, str]:
    """Generate a local mesh CA (cryptography, RSA-2048 root). Returns (cert_path, key_path).

    RSA root keeps cert chain verification working across OpenSSL builds
    (Ed25519-signed chains are rejected by some openssl versions).
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    cert_path = out / "mesh-ca.crt"
    key_path = out / "mesh-ca.key"
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_build_name(cn))
        .issuer_name(_build_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=None, decipher_only=None,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    ).sign(key, hashes.SHA256())

    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    os.chmod(key_path, 0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(cert_path), str(key_path)


def issue_node_cert(
    ca_cert_path: str | Path,
    ca_key_path: str | Path,
    node_id: str,
    out_dir: str | Path,
    *,
    key: ed25519.Ed25519PrivateKey | None = None,
) -> Tuple[str, str]:
    """Issue a node mTLS certificate signed by the mesh CA.

    When `key` is given, the certificate belongs to that exact key — so the
    node's Ed25519 identity IS its TLS identity (one key for both planes).
    """
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
    )
    from cryptography.x509 import (
        load_pem_x509_certificate,
    )

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    cert_path = out / f"mesh-node-{node_id}.crt"
    key_path = out / f"mesh-node-{node_id}.key"
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)

    ca_cert = load_pem_x509_certificate(Path(ca_cert_path).read_bytes())
    ca_key = load_pem_private_key(Path(ca_key_path).read_bytes(), password=None)

    key = key or ed25519.Ed25519PrivateKey.generate()
    alg = None if isinstance(ca_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_build_name(f"wwfi-node/{node_id}"))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=None, decipher_only=None,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
        ), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    ).sign(ca_key, alg)

    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    os.chmod(key_path, 0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(cert_path), str(key_path)


# ---------------------------------------------------------------------------
# State store
# ---------------------------------------------------------------------------


@dataclass
class PeerSpec:
    node_id: str
    host: str
    port: int


@dataclass
class RouteSpec:
    domain: str
    owner: str  # node id that can reach the target directly
    target_host: str
    target_port: int
    encrypted: bool = True


@dataclass
class MeshStore:
    path: str = "~/.wwfi/mesh.json"
    node_id: str = ""
    key_path: str = "~/.wwfi/mesh-node.key"
    cert_path: str = ""
    ca_cert_path: str = ""
    bind_host: str = "127.0.0.1"
    bind_port: int = DEFAULT_BIND_PORT
    control_host: str = DEFAULT_CONTROL_HOST
    control_port: int = DEFAULT_CONTROL_PORT
    peers: Dict[str, PeerSpec] = field(default_factory=dict)  # by node_id
    routes: Dict[str, RouteSpec] = field(default_factory=dict)  # domains I serve
    announces: Dict[str, RouteSpec] = field(default_factory=dict)  # learned from mesh
    reach: Dict[str, List[str]] = field(default_factory=dict)  # node_id -> peer ids via which reachable

    def load(self) -> "MeshStore":
        p = Path(self.path).expanduser()
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            for k, v in data.items():
                if k == "peers":
                    self.peers = {n: PeerSpec(**sp) for n, sp in v.items()}
                elif k == "routes":
                    self.routes = {d: RouteSpec(**rp) for d, rp in v.items()}
                elif k == "announces":
                    self.announces = {d: RouteSpec(**rp) for d, rp in v.items()}
                elif k == "reach":
                    self.reach = v
                else:
                    setattr(self, k, v)
        return self

    def save(self) -> None:
        p = Path(self.path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        blob = {
            "node_id": self.node_id,
            "key_path": self.key_path,
            "cert_path": self.cert_path,
            "ca_cert_path": self.ca_cert_path,
            "bind_host": self.bind_host,
            "bind_port": self.bind_port,
            "control_host": self.control_host,
            "control_port": self.control_port,
            "peers": {n: asdict(sp) for n, sp in self.peers.items()},
            "routes": {d: asdict(rp) for d, rp in self.routes.items()},
            "announces": {d: asdict(rp) for d, rp in self.announces.items()},
            "reach": self.reach,
        }
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(blob, indent=2), encoding="utf-8")
        os.replace(tmp, p)

    def route_to(self, dst: str) -> List[PeerSpec]:
        """First-hop path toward dst using the reach table (BFS over known peers)."""
        if dst in self.peers:
            return [self.peers[dst]]
        visited = {dst}
        queue: List[List[str]] = [[dst]]
        while queue:
            path = queue.pop(0)
            head = path[-1]
            next_ids = self.reach.get(head, [])
            for nid in next_ids:
                if nid in visited:
                    continue
                visited.add(nid)
                new_path = path + [nid]
                if nid in self.peers:
                    return [self.peers[nid]]
                queue.append(new_path)
        return []

    def next_hop(self, dst: str) -> Tuple[Optional[PeerSpec], Optional[str]]:
        """Peer to contact and the node id to keep asking for toward dst."""
        if dst in self.peers:
            return self.peers[dst], dst
        # find a peer that can reach dst
        for nid, peer in self.peers.items():
            if nid == dst:
                return peer, dst
        for dst_node, ids in self.reach.items():
            if dst_node == dst:
                for via in ids:
                    if via in self.peers:
                        return self.peers[via], dst
        return None, None

    def advertised_domains(self) -> List[str]:
        return sorted(set(self.routes) | set(self.announces))


# ---------------------------------------------------------------------------
# Wire framing
# ---------------------------------------------------------------------------


def encode_frame(msg: dict) -> bytes:
    body = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    if len(body) > MESH_FRAME_MAX:
        raise MeshError("frame too large")
    return struct.pack("!I", len(body)) + body


async def read_frame(reader: asyncio.StreamReader) -> dict:
    head = await reader.readexactly(4)
    (size,) = struct.unpack("!I", head)
    if size > MESH_FRAME_MAX:
        raise MeshError("frame too large")
    body = await reader.readexactly(size)
    return json.loads(body.decode("utf-8"))


# ---------------------------------------------------------------------------
# Mesh node
# ---------------------------------------------------------------------------


class MeshNode:
    def __init__(self, state: MeshStore):
        self.state = state
        self.key = MeshKey.load_or_create(Path(state.key_path).expanduser(), state.node_id)
        self._server: Optional[asyncio.AbstractServer] = None
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._http_thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._running = False
        self._extra_servers: list[asyncio.AbstractServer] = []
        # control API auth (see wwfi.admin); empty = back-compat loopback trust
        self.admin = None
        self.control_token = ""

    @property
    def public_control(self) -> bool:
        """Control API reachable from the network (not loopback). When true,
        name-plane requests REQUIRED to authenticate (token or session)."""
        host = self.state.control_host.lower()
        return host not in ("127.0.0.1", "localhost", "::1")

    # -- TLS context -------------------------------------------------------

    def _server_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=self.state.cert_path, keyfile=self.state.key_path)
        if self.state.ca_cert_path:
            ctx.load_verify_locations(cafile=self.state.ca_cert_path)
            ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def _client_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(certfile=self.state.cert_path, keyfile=self.state.key_path)
        if self.state.ca_cert_path:
            ctx.load_verify_locations(cafile=self.state.ca_cert_path)
            ctx.verify_mode = ssl.CERT_REQUIRED
            # Trust anchor is the mesh CA + server-side CN validation; mesh
            # endpoints are plain IPs, so skip the extra hostname check.
            ctx.check_hostname = False
        return ctx

    @staticmethod
    def _peer_id_of(sslobj) -> str:
        cert = sslobj.getpeercert()
        if not cert:
            raise MeshError("peer presented no certificate")
        cn = None
        for field in cert.get("subject", ()):
            if field[0][0] == "commonName":
                cn = field[0][1]
        if not cn or not cn.startswith("wwfi-node/"):
            raise MeshError(f"untrusted peer CN: {cn!r}")
        return cn[len("wwfi-node/"):]

    # -- asyncio server ----------------------------------------------------

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._server = await asyncio.start_server(
            self._handle_stream,
            self.state.bind_host,
            self.state.bind_port,
            ssl=self._server_context(),
        )
        self._start_control_api()
        print(
            f"[wwfi-mesh] node={self.state.node_id} bind={self.state.bind_host}:{self.state.bind_port} "
            f"control={self.state.control_host}:{self.state.control_port} fingerprint={self.key.fingerprint[:16]}"
        )

    def _start_control_api(self) -> None:
        node = self
        loop = self._loop

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def __init__(self, *args, **kwargs):
                self._pending_cookie = None
                super().__init__(*args, **kwargs)

            def _emit_cookie(self):
                if self._pending_cookie is None:
                    return
                if self._pending_cookie:
                    self.send_header(
                        "Set-Cookie",
                        f"WWFI_SESSION={self._pending_cookie}; HttpOnly; SameSite=Strict; Path=/; Max-Age={7*24*3600}",
                    )
                else:
                    self.send_header("Set-Cookie", "WWFI_SESSION=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
                self._pending_cookie = None

            def _json(self, code, obj):
                self.send_response(code)
                self._emit_cookie()
                body = json.dumps(obj).encode()
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _html(self, code, html):
                self.send_response(code)
                self._emit_cookie()
                body = html.encode("utf-8")
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _set_cookie(self, value):
                self._pending_cookie = value

            def _clear_cookie(self):
                self._pending_cookie = ""

            def _bearer(self):
                auth = self.headers.get("Authorization", "")
                if auth.startswith("Bearer "):
                    return auth[len("Bearer "):].strip()
                return None

            def _session_user(self):
                if not node.admin:
                    return None
                raw = self.headers.get("Cookie", "")
                value = None
                for part in raw.split(";"):
                    part = part.strip()
                    if part.startswith("WWFI_SESSION="):
                        value = part[len("WWFI_SESSION="):]
                        break
                return node.admin.parse_session(value)

            def _api_authorized(self) -> bool:
                """Name plane / data plane endpoints. When a token is
                configured it is REQUIRED on every interface; otherwise a
                loopback binding keeps local trust, public binds are denied."""
                if self._session_user():
                    return True
                token = self._bearer()
                if node.control_token:
                    return bool(token) and hmac.compare_digest(node.control_token, token)
                if token:
                    return False
                return not node.public_control

            def _admin_required(self) -> Optional[str]:
                user = self._session_user()
                return user or None

            def do_GET(self):
                from urllib.parse import unquote

                if self.path == "/api/health":
                    self._json(200, {"status": "ok", "node": node.state.node_id})
                    return
                if self.path.startswith("/admin"):
                    self._html(200, admin_panel_html())
                    return
                if self.path.startswith("/api/admin/domains"):
                    if not self._admin_required():
                        self._json(401, {"error": "admin login required"})
                        return
                    rows = []
                    for domain, r in sorted(node.state.routes.items()):
                        rows.append(
                            {
                                "domain": domain,
                                "owner": r.owner,
                                "target_host": r.target_host,
                                "target_port": r.target_port,
                                "encrypted": bool(r.encrypted),
                            }
                        )
                    for domain, r in sorted(node.state.announces.items()):
                        if domain in node.state.routes:
                            continue
                        rows.append(
                            {
                                "domain": domain,
                                "owner": r.owner,
                                "target_host": r.target_host,
                                "target_port": r.target_port,
                                "encrypted": bool(r.encrypted),
                            }
                        )
                    self._json(200, rows)
                    return
                if self.path == "/api/domains":
                    if not self._api_authorized():
                        self._json(401, {"error": "token required"})
                        return
                    self._json(200, [{"name": d} for d in node.state.advertised_domains()])
                    return
                if self.path.startswith("/api/route/"):
                    if not self._api_authorized():
                        self._json(401, {"error": "token required"})
                        return
                    domain = unquote(self.path[len("/api/route/"):])
                    fut = asyncio.run_coroutine_threadsafe(node.resolve(domain), loop)
                    self._json(*fut.result(timeout=10))
                    return
                self._json(404, {"error": "not found"})

            def do_POST(self):
                from urllib.parse import unquote

                length = int(self.headers.get("Content-Length") or 0)
                try:
                    payload = json.loads(self.rfile.read(length) or b"{}")
                except json.JSONDecodeError:
                    self._json(400, {"error": "bad json"})
                    return

                if self.path == "/api/login":
                    if not node.admin or not node.admin.exists:
                        self._json(403, {"error": "no-admin"})
                        return
                    username = str(payload.get("username") or "")
                    password = str(payload.get("password") or "")
                    if not node.admin.verify_password(username, password):
                        self._json(401, {"error": "bad credentials"})
                        return
                    self._set_cookie(node.admin.issue_session(username))
                    self._json(200, {"ok": True, "user": username})
                    return
                if self.path == "/api/logout":
                    self._clear_cookie()
                    self._json(200, {"ok": True})
                    return
                if self.path == "/api/admin/domains":
                    if not self._admin_required():
                        self._json(401, {"error": "admin login required"})
                        return
                    domain = str(payload.get("domain") or "").strip()
                    target = str(payload.get("target") or "").strip()
                    if not domain or not target:
                        self._json(400, {"error": "domain and target required"})
                        return
                    try:
                        target_port = int(payload.get("target_port") or 80)
                    except (TypeError, ValueError):
                        self._json(400, {"error": "target_port must be an integer"})
                        return
                    owner = str(payload.get("owner") or node.state.node_id).strip()
                    node.state.routes[domain] = RouteSpec(
                        domain=domain,
                        owner=owner,
                        target_host=target,
                        target_port=target_port,
                    )
                    node.state.announces.pop(domain, None)
                    node.state.save()
                    self._json(200, {"ok": True, "domain": domain})
                    return
                if self.path == "/api/forward":
                    if not self._api_authorized():
                        self._json(401, {"error": "token required"})
                        return
                    domain = payload.get("domain")
                    local_port = int(payload.get("local_port") or 0)
                    if not domain:
                        self._json(400, {"error": "domain required"})
                        return
                    fut = asyncio.run_coroutine_threadsafe(
                        node.forward(domain, local_port=local_port), loop
                    )
                    try:
                        self._json(*fut.result(timeout=30))
                    except asyncio.TimeoutError:
                        self._json(504, {"error": "forward timed out"})
                    except Exception as exc:  # pragma: no cover
                        self._json(500, {"error": str(exc)})
                    return
                if self.path == "/api/peer" and payload.get("op") == "reach":
                    if not self._api_authorized():
                        self._json(401, {"error": "token required"})
                        return
                    node.state.reach = {
                        k: list(v) for k, v in (payload.get("reach") or {}).items()
                    }
                    node.state.save()
                    self._json(200, {"status": "ok"})
                    return
                self._json(404, {"error": "not found"})

            def do_DELETE(self):
                from urllib.parse import unquote

                if self.path.startswith("/api/admin/domains/"):
                    if not self._admin_required():
                        self._json(401, {"error": "admin login required"})
                        return
                    domain = unquote(self.path[len("/api/admin/domains/"):])
                    if domain in node.state.routes:
                        del node.state.routes[domain]
                        node.state.save()
                        self._json(200, {"ok": True, "removed": domain})
                        return
                    self._json(404, {"error": "no such domain"})
                    return
                self._json(404, {"error": "not found"})

        self._httpd = ThreadingHTTPServer(
            (self.state.control_host, self.state.control_port), Handler
        )
        self._http_thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._http_thread.start()

    # -- connection handling ------------------------------------------------

    async def _handle_stream(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer_id = None
        try:
            peer_id = self._peer_id_of(writer.get_extra_info("ssl_object"))
        except MeshError as exc:
            writer.close()
            return
        try:
            while True:
                msg = await read_frame(reader)
                mtype = msg.get("type")
                if mtype == "open":
                    await self._handle_open(reader, writer, peer_id, msg)
                    return  # stream is now fully consumed by the pipe
                elif mtype == "resolve":
                    domain = msg.get("domain")
                    if domain in self.state.routes:
                        r = self.state.routes[domain]
                        writer.write(encode_frame({
                            "type": "resolve_ok", "domain": domain, "owner": self.state.node_id,
                            "target_host": r.target_host, "target_port": r.target_port,
                            "path": r.owner,
                        }))
                        await writer.drain()
                        return
                    writer.write(encode_frame({"type": "resolve_none", "domain": domain}))
                    await writer.drain()
                    return
                elif mtype == "announce":
                    for entry in msg.get("routes") or []:
                        self.state.announces[entry["domain"]] = RouteSpec(
                            domain=entry["domain"],
                            owner=entry.get("owner") or peer_id,
                            target_host=entry.get("target_host") or "",
                            target_port=int(entry.get("target_port") or 0),
                        )
                    self.state.save()
                    writer.write(encode_frame({"type": "announce_ok"}))
                    await writer.drain()
                    continue
                elif mtype == "ping":
                    writer.write(encode_frame({"type": "pong"}))
                    await writer.drain()
                    continue
                else:
                    writer.write(encode_frame({"type": "error", "error": f"unknown type {mtype}"}))
                    await writer.drain()
                    return
        except asyncio.IncompleteReadError:
            pass
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def _handle_open(self, reader, writer, caller_id, msg):
        domain = msg.get("domain")
        dst = msg.get("dst")
        r = self.state.routes.get(domain)
        if dst and dst != self.state.node_id:
            hop, next_node = self.state.next_hop(dst)
            if not hop:
                writer.write(encode_frame({"type": "error", "error": f"no route to {dst}"}))
                await writer.drain()
                return
            try:
                remote_reader, remote_writer = await asyncio.open_connection(
                    hop.host, hop.port, ssl=self._client_context()
                )
            except Exception as exc:
                writer.write(encode_frame({"type": "error", "error": f"peer unreachable: {exc}"}))
                await writer.drain()
                return
            remote_writer.write(encode_frame({
                "type": "open", "dst": next_node, "domain": domain,
            }))
            await remote_writer.drain()
            resp = await read_frame(remote_reader)
            if resp.get("type") != "ok":
                writer.write(encode_frame({"type": "error", "error": resp.get("error", "peer refused")}))
                await writer.drain()
                remote_writer.close()
                return
            writer.write(encode_frame({"type": "ok", "domain": domain}))
            await writer.drain()
            await self._pipe(writer, remote_reader, remote_writer, reader)
            return

        if r is None:
            writer.write(encode_frame({"type": "error", "error": f"{domain} not served here"}))
            await writer.drain()
            return
        try:
            target_reader, target_writer = await asyncio.open_connection(
                r.target_host, r.target_port
            )
        except Exception as exc:
            writer.write(encode_frame({"type": "error", "error": f"target unreachable: {exc}"}))
            await writer.drain()
            return
        writer.write(encode_frame({"type": "ok", "domain": domain}))
        await writer.drain()
        await self._pipe(writer, target_reader, target_writer, reader)

    @staticmethod
    async def _pipe(client_writer, target_reader, target_writer, client_reader):
        async def pump(src_reader: asyncio.StreamReader, dst_writer: asyncio.StreamWriter):
            try:
                while True:
                    chunk = await src_reader.read(64 * 1024)
                    if not chunk:
                        break
                    dst_writer.write(chunk)
                    await dst_writer.drain()
            except Exception:
                pass
            with contextlib.suppress(Exception):
                dst_writer.close()

        await asyncio.gather(
            pump(client_reader, target_writer),
            pump(target_reader, client_writer),
        )

    # -- name plane (distributed resolve) ------------------------------------

    async def resolve(self, domain: str) -> Tuple[int, dict]:
        local = self.state.routes.get(domain)
        if local:
            return 200, {
                "domain": domain, "owner": self.state.node_id,
                "target_host": local.target_host, "target_port": local.target_port,
                "via": [],
            }
        ann = self.state.announces.get(domain)
        if ann:
            return 200, {
                "domain": domain, "owner": ann.owner,
                "target_host": ann.target_host, "target_port": ann.target_port,
                "via": [],
            }
        # ask direct peers (2-hop guard)
        for peer in self.state.peers.values():
            try:
                reader, writer = await asyncio.open_connection(
                    peer.host, peer.port, ssl=self._client_context()
                )
            except Exception:
                continue
            writer.write(encode_frame({"type": "resolve", "domain": domain}))
            await writer.drain()
            try:
                resp = await asyncio.wait_for(read_frame(reader), timeout=5)
            except Exception:
                writer.close()
                continue
            writer.close()
            if resp.get("type") == "resolve_ok" and resp.get("owner"):
                self.state.announces[domain] = RouteSpec(
                    domain=domain,
                    owner=resp["owner"],
                    target_host=resp.get("target_host") or "",
                    target_port=int(resp.get("target_port") or 0),
                )
                self.state.save()
                return 200, {
                    "domain": domain, "owner": resp["owner"],
                    "target_host": resp.get("target_host"), "target_port": resp.get("target_port"),
                    "via": [peer.node_id],
                }
        return 404, {"domain": domain, "error": "not found on the mesh"}

    # -- data plane (tunnel to a domain and hold it open) --------------------

    async def open_tunnel(self, domain: str) -> Tuple[int, dict]:
        code, info = await self.resolve(domain)
        if code != 200:
            return code, info
        owner = info["owner"]
        if owner == self.state.node_id:
            r = self.state.routes[domain]
            try:
                reader, writer = await asyncio.open_connection(r.target_host, r.target_port)
            except Exception as exc:
                return 502, {"domain": domain, "error": f"target unreachable: {exc}"}
            return 200, {"domain": domain, "host": r.target_host, "port": r.target_port, "path": [], "stream": (reader, writer)}
        hop, next_node = self.state.next_hop(owner)
        if not hop:
            return 502, {"domain": domain, "error": f"no path to owner node {owner}"}
        try:
            reader, writer = await asyncio.open_connection(
                hop.host, hop.port, ssl=self._client_context()
            )
        except Exception as exc:
            return 502, {"domain": domain, "error": f"peer unreachable: {exc}"}
        try:
            writer.write(encode_frame({"type": "open", "dst": owner, "domain": domain}))
            await writer.drain()
            resp = await asyncio.wait_for(read_frame(reader), timeout=10)
        except Exception as exc:
            writer.close()
            return 502, {"domain": domain, "error": f"open failed: {exc}"}
        if resp.get("type") != "ok":
            writer.close()
            return 502, {"domain": domain, "error": resp.get("error", "refused")}
        return 200, {"domain": domain, "stream": (reader, writer)}

    async def forward(self, domain: str, *, local_port: int = 0) -> Tuple[int, dict]:
        """Bind a loopback port; every connection opens a mesh tunnel to `domain`."""
        code, info = await self.resolve(domain)
        if code != 200:
            return code, info
        host, port = (info.get("target_host"), info.get("target_port"))
        owner = info.get("owner")

        async def handle(creader, cwriter):
            kick, info2 = await self.open_tunnel(domain)
            if kick != 200 or "stream" not in info2:
                with contextlib.suppress(Exception):
                    cwriter.close()
                return
            sreader, swriter = info2["stream"]
            await self._pipe(cwriter, sreader, swriter, creader)

        server = await asyncio.start_server(handle, "127.0.0.1", local_port)
        self._extra_servers.append(server)
        bound = server.sockets[0].getsockname()[1]
        asyncio.ensure_future(server.serve_forever())
        print(
            f"[wwfi-mesh] forwarding {domain} (owner={owner} target={host}:{port}) "
            f"=> http://127.0.0.1:{bound}"
        )
        return 200, {"domain": domain, "owner": owner, "local_port": bound, "http": f"http://127.0.0.1:{bound}"}

    # -- lifecycle -----------------------------------------------------------

    async def run_forever(self) -> None:
        self._running = True
        try:
            while self._running:
                await asyncio.sleep(3600)
        finally:
            await self.close()

    async def stop(self) -> None:
        self._running = False

    async def close(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
        for server in self._extra_servers:
            server.close()
            with contextlib.suppress(Exception):
                await server.wait_closed()
        if self._server:
            self._server.close()
            await self._server.wait_closed()