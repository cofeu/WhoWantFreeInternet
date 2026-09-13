from __future__ import annotations

import asyncio
import ssl
from pathlib import Path

import pytest

from wwfi.mesh import (
    MeshKey,
    MeshNode,
    MeshStore,
    PeerSpec,
    RouteSpec,
    generate_ca,
    issue_node_cert,
)


def _run(coro, timeout=30):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(asyncio.wait_for(coro, timeout))
    finally:
        loop.close()


class EchoServer:
    def __init__(self, host="127.0.0.2"):
        self.host = host
        self.server = None
        self.port = 0

    async def start(self):
        async def handle(reader, writer):
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        self.server = await asyncio.start_server(handle, self.host, 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self.port

    async def close(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()


def build_node(tmp_path, node_id, *, hosts, ca_dir=None, bind_port=0, control_port=0):
    """Hosts can be a dict of routes to serve and/or peers to trust."""
    routes = {d: s for d, s in hosts.items() if isinstance(s, RouteSpec)}
    peers = {n: s for n, s in hosts.items() if isinstance(s, PeerSpec)}
    ca_dir = ca_dir or (tmp_path / "ca")
    cert_dir = tmp_path / "certs"
    ca_cert, ca_key = generate_ca(ca_dir)
    state = MeshStore(
        path=str(tmp_path / f"{node_id}.json"),
        node_id=node_id,
        key_path=str(tmp_path / f"{node_id}.key"),
        cert_path="",
        ca_cert_path=ca_cert,
        bind_host="127.0.0.1",
        bind_port=bind_port,
        control_host="127.0.0.1",
        control_port=control_port,
    )
    key = MeshKey.load_or_create(Path(state.key_path).expanduser(), node_id)
    cert_path, key_path = issue_node_cert(ca_cert, ca_key, node_id, cert_dir, key=key.key)
    state.cert_path = cert_path
    state.key_path = key_path
    state.routes.update(routes)
    state.peers.update(peers)
    state.save()
    return state


def test_store_route_to_uses_reach_table(tmp_path):
    state = build_node(tmp_path, "alpha", hosts={})
    state.peers["zulu"] = PeerSpec("zulu", "10.0.0.5", 9443)
    state.reach = {"beta": ["gamma"], "gamma": ["zulu"]}
    path = state.route_to("beta")
    assert path and path[0].node_id == "zulu"
    direct = state.route_to("zulu")
    assert direct and direct[0].host == "10.0.0.5"


def test_two_plane_e2e_forward_over_encrypted_mesh(tmp_path):
    """Name plane resolves yi.cket -> owner 'beta'; data plane tunnels bytes to
    a private loopback target (simulating Yusuf's 10.x home server)."""

    async def scenario():
        echo = EchoServer()
        echo_port = await echo.start()

        beta_state = build_node(
            tmp_path,
            "beta",
            hosts={
                "yi.cket": RouteSpec(
                    domain="yi.cket",
                    owner="beta",
                    target_host="127.0.0.2",
                    target_port=echo_port,
                )
            },
            bind_port=0,
            control_port=0,
        )
        beta = MeshNode(beta_state)
        await beta.start()
        beta_port = beta._server.sockets[0].getsockname()[1]

        alpha_state = build_node(
            tmp_path,
            "alpha",
            hosts={"beta": PeerSpec("beta", "127.0.0.1", beta_port)},
            ca_dir=None,
            bind_port=0,
            control_port=0,
        )
        alpha = MeshNode(alpha_state)
        await alpha.start()

        try:
            code, info = await alpha.resolve("yi.cket")
            assert code == 200
            assert info["owner"] == "beta"
            assert info["target_host"] == "127.0.0.2"
            assert info["target_port"] == echo_port

            code, fwd = await alpha.forward("yi.cket", local_port=0)
            assert code == 200
            assert fwd["owner"] == "beta"

            reader, writer = await asyncio.open_connection("127.0.0.1", fwd["local_port"])
            writer.write(b"mesh-hello\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(64), 10)
            assert data == b"mesh-hello\n"
            writer.close()
        finally:
            await alpha.close()
            await beta.close()
            await echo.close()

    _run(scenario())


def test_local_forward_owner_serves_own_domain(tmp_path):
    async def scenario():
        echo = EchoServer()
        echo_port = await echo.start()

        beta_state = build_node(
            tmp_path,
            "beta",
            hosts={
                "yi.cket": RouteSpec(
                    domain="yi.cket",
                    owner="beta",
                    target_host="127.0.0.2",
                    target_port=echo_port,
                )
            },
            bind_port=0,
            control_port=0,
        )
        beta = MeshNode(beta_state)
        await beta.start()
        try:
            code, fwd = await beta.forward("yi.cket", local_port=0)
            assert code == 200
            assert fwd["owner"] == "beta"
            reader, writer = await asyncio.open_connection("127.0.0.1", fwd["local_port"])
            writer.write(b"local-ok")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(64), 10)
            assert data == b"local-ok"
            writer.close()
        finally:
            await beta.close()
            await echo.close()

    _run(scenario())


def test_distributed_resolve_when_announced(tmp_path):
    async def scenario():
        echo = EchoServer()
        echo_port = await echo.start()

        beta_state = build_node(
            tmp_path,
            "beta",
            hosts={
                "shop.local": RouteSpec(
                    domain="shop.local",
                    owner="beta",
                    target_host="127.0.0.2",
                    target_port=echo_port,
                )
            },
            bind_port=0,
            control_port=0,
        )
        beta = MeshNode(beta_state)
        await beta.start()
        beta_port = beta._server.sockets[0].getsockname()[1]

        alpha_state = build_node(
            tmp_path,
            "alpha",
            hosts={"beta": PeerSpec("beta", "127.0.0.1", beta_port)},
            ca_dir=None,
            bind_port=0,
            control_port=0,
        )
        alpha = MeshNode(alpha_state)
        await alpha.start()
        try:
            # direct-peer broadcast: alpha has no route for shop.local,
            # the name plane resolves it from the trusted peer beta
            code, info = await alpha.resolve("shop.local")
            assert code == 200, info
            assert info["owner"] == "beta"
            assert info["target_host"] == "127.0.0.2"
            # learned by the mesh and cached for later
            assert "shop.local" in alpha.state.announces
        finally:
            await alpha.close()
            await beta.close()
            await echo.close()

    _run(scenario())


def test_untrusted_ca_rejected(tmp_path):
    """A client signed by a different CA must not be able to join the mesh."""

    async def scenario():
        echo = EchoServer()
        echo_port = await echo.start()

        beta_state = build_node(
            tmp_path,
            "beta",
            hosts={
                "yi.cket": RouteSpec(
                    domain="yi.cket",
                    owner="beta",
                    target_host="127.0.0.2",
                    target_port=echo_port,
                )
            },
            bind_port=0,
            control_port=0,
        )
        beta = MeshNode(beta_state)
        await beta.start()
        beta_port = beta._server.sockets[0].getsockname()[1]

        other_ca = tmp_path / "evil-ca"
        attacker_state = build_node(
            tmp_path,
            "attacker",
            hosts={"beta": PeerSpec("beta", "127.0.0.1", beta_port)},
            ca_dir=other_ca,
            bind_port=0,
            control_port=0,
        )
        attacker = MeshNode(attacker_state)
        try:
            ctx = attacker._client_context()
            with pytest.raises((ssl.SSLCertVerificationError, ConnectionError, OSError)):
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", beta_port, ssl=ctx
                )
        finally:
            await beta.close()
            await echo.close()

    _run(scenario())


def test_control_api_lists_served_domains(tmp_path):
    import http.client

    async def scenario():
        echo = EchoServer()
        echo_port = await echo.start()

        beta_state = build_node(
            tmp_path,
            "beta",
            hosts={
                "yi.cket": RouteSpec(
                    domain="yi.cket",
                    owner="beta",
                    target_host="127.0.0.2",
                    target_port=echo_port,
                )
            },
            bind_port=0,
            control_port=0,
        )
        beta = MeshNode(beta_state)
        await beta.start()
        control_port = beta._httpd.server_port
        try:
            conn = http.client.HTTPConnection("127.0.0.1", control_port, timeout=10)
            conn.request("GET", "/api/domains")
            resp = conn.getresponse()
            assert resp.status == 200
            domains = resp.read().decode()
            assert "yi.cket" in domains
            conn.close()
        finally:
            await beta.close()
            await echo.close()

    _run(scenario())