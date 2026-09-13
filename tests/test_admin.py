"""Domain admin panel auth + control API integration tests."""

import asyncio
import http.client
import json
from pathlib import Path

from wwfi.admin import (
    AdminAuth,
    generate_token,
    hash_password,
    verify_password,
)
from wwfi.mesh import (
    MeshKey,
    MeshNode,
    MeshStore,
    RouteSpec,
    generate_ca,
    issue_node_cert,
)


def _run(coro):
    asyncio.run(coro)


def build_node(tmp_path, node_id, *, routes=None, control_port=0):
    routes = routes or {}
    ca_cert, ca_key = generate_ca(tmp_path / "ca")
    state = MeshStore(
        path=str(tmp_path / f"{node_id}.json"),
        node_id=node_id,
        key_path=str(tmp_path / f"{node_id}.key"),
        cert_path="",
        ca_cert_path=ca_cert,
        bind_host="127.0.0.1",
        bind_port=0,
        control_host="127.0.0.1",
        control_port=control_port,
    )
    key = MeshKey.load_or_create(Path(state.path).expanduser().parent / f"{node_id}.key", node_id)
    cert_path, key_path = issue_node_cert(
        ca_cert, ca_key, node_id, str(tmp_path / "certs"), key=key.key
    )
    state.cert_path = cert_path
    state.key_path = key_path
    state.routes.update(routes)
    state.save()
    return state


# --- pure auth -------------------------------------------------------------


def test_password_hash_roundtrip():
    record = hash_password("hunter2-secret")
    assert verify_password("hunter2-secret", record) is True
    assert verify_password("wrong", record) is False
    assert verify_password("", record) is False


def test_admin_auth_save_load_and_sessions(tmp_path):
    file = tmp_path / "admin.json"
    auth = AdminAuth.load(file).set_user("yusuf", "pw123").set_api_token()
    assert auth.exists
    assert file.exists()
    assert oct(file.stat().st_mode & 0o777) == "0o600"

    loaded = AdminAuth.load(file)
    assert loaded.verify_password("yusuf", "pw123") is True
    assert loaded.verify_password("yusuf", "nope") is False
    assert loaded.verify_password("mallory", "pw123") is False
    assert loaded.verify_api_token(auth.api_token) is True
    assert loaded.verify_api_token("wrong-token") is False

    cookie = loaded.issue_session("yusuf")
    assert loaded.parse_session(cookie) == "yusuf"
    assert loaded.parse_session(cookie[:-1] + ("0" if cookie[-1] != "0" else "1")) is None


def test_session_rejects_tampered_and_expired(tmp_path):
    auth = AdminAuth.load(tmp_path / "admin.json").set_user("yusuf", "pw")
    ok = auth.issue_session("yusuf")
    sig = ok.split(".")[1]
    payload = ok.split(".")[0]
    # tampered user inside the payload -> signature mismatch
    tampered_payload = json.dumps({"u": "mallory", "e": 2 * 10**12}).encode()
    import base64

    fb = base64.urlsafe_b64encode(tampered_payload).decode().rstrip("=")
    assert auth.parse_session(fb + "." + sig) is None
    # expired session
    import time

    past = auth.issue_session("yusuf")
    meta = json.loads(
        base64.urlsafe_b64decode(past.split(".")[0] + "==").decode()
    )
    meta["e"] = int(time.time()) - 10
    payload = base64.urlsafe_b64encode(json.dumps(meta).encode()).decode().rstrip("=")
    assert auth.parse_session(payload + "." + past.split(".")[1]) is None


# --- control API integration -----------------------------------------------


def test_control_api_requires_token_and_admin_login(tmp_path):
    admin = AdminAuth.load(tmp_path / "admin.json")
    admin.set_user("yusuf", "pw123").set_api_token()

    async def scenario():
        state = build_node(tmp_path, "oracle", control_port=0)
        node = MeshNode(state)
        node.admin = admin
        node.control_token = admin.api_token
        await node.start()
        port = node._httpd.server_port
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            # name plane: token required once configured
            conn.request("GET", "/api/domains")
            assert conn.getresponse().status == 401
            conn.request("GET", "/api/domains", headers={"Authorization": "Bearer " + admin.api_token})
            assert conn.getresponse().status == 200
            conn.request("GET", "/api/domains", headers={"Authorization": "Bearer wrong"})
            assert conn.getresponse().status == 401

            # admin panel page served
            conn.request("GET", "/admin")
            resp = conn.getresponse()
            assert resp.status == 200
            assert "WWFI Domain Admin" in resp.read().decode()

            # mutations need a session
            conn.request("POST", "/api/admin/domains",
                         body=json.dumps({"domain": "app.x", "target": "10.0.0.5", "target_port": 80}),
                         headers={"Content-Type": "application/json"})
            assert conn.getresponse().status == 401

            # bad login
            conn.request("POST", "/api/login",
                         body=json.dumps({"username": "yusuf", "password": "nope"}),
                         headers={"Content-Type": "application/json"})
            assert conn.getresponse().status == 401

            # good login -> session cookie
            conn.request("POST", "/api/login",
                         body=json.dumps({"username": "yusuf", "password": "pw123"}),
                         headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            assert resp.status == 200
            cookie = resp.getheader("Set-Cookie").split(";")[0]
            auth_headers = {"Cookie": cookie, "Content-Type": "application/json"}

            # add a published domain
            conn.request("POST", "/api/admin/domains",
                         body=json.dumps({"domain": "app.x", "target": "10.0.0.5", "target_port": 80}),
                         headers=auth_headers)
            assert conn.getresponse().status == 200

            # list it
            conn.request("GET", "/api/admin/domains", headers={"Cookie": cookie})
            resp = conn.getresponse()
            assert resp.status == 200
            rows = json.loads(resp.read().decode())
            assert any(r["domain"] == "app.x" for r in rows)

            # it now appears on the name plane
            conn.request("GET", "/api/domains", headers={"Authorization": "Bearer " + admin.api_token})
            assert "app.x" in conn.getresponse().read().decode()

            # delete it
            conn.request("DELETE", "/api/admin/domains/app.x", headers={"Cookie": cookie})
            assert conn.getresponse().status == 200
            conn.request("GET", "/api/domains", headers={"Authorization": "Bearer " + admin.api_token})
            assert "app.x" not in conn.getresponse().read().decode()

            # logout clears the client cookie (stateless HMAC session)
            conn.request("POST", "/api/logout", headers={"Cookie": cookie})
            resp = conn.getresponse()
            assert resp.status == 200
            assert "Max-Age=0" in resp.getheader("Set-Cookie", "")
            conn.close()
        finally:
            await node.close()

    _run(scenario())


def test_loopback_without_token_keeps_local_trust(tmp_path):
    async def scenario():
        state = build_node(tmp_path, "local1", control_port=0)
        node = MeshNode(state)  # no token, no admin
        await node.start()
        port = node._httpd.server_port
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            conn.request("GET", "/api/domains")
            assert conn.getresponse().status == 200
            conn.request("POST", "/api/admin/domains",
                         body=json.dumps({"domain": "x.y", "target": "127.0.0.1", "target_port": 1}),
                         headers={"Content-Type": "application/json"})
            assert conn.getresponse().status == 401  # admin still requires login
            conn.close()
        finally:
            await node.close()

    _run(scenario())