#!/usr/bin/env python3
"""WWFI Mesh node CLI daemon + tooling.

Both the name plane (distributed resolve across trusted peers) and the data
plane (encrypted mTLS tunnel between nodes) live here. Every client that joins
the mesh behaves as a resolver AND a network node.

Examples
--------
# 1. Bootstrap the mesh CA (once, on the control node):
python3 scripts/wwfi_mesh_node.py ca-init --dir certs

# 2. Init a node (creates Ed25519 identity + issues a CA-signed mTLS cert):
python3 scripts/wwfi_mesh_node.py init --state ~/.wwfi/yusuf.json \
    --node yusuf --cert-dir certs --ca-dir certs

# 3. Join two nodes:
python3 scripts/wwfi_mesh_node.py peer add --state ~/.wwfi/yusuf.json \
    --peer yicket --endpoint 192.168.1.50:9443
python3 scripts/wwfi_mesh_node.py peer add --state ~/.wwfi/yicket.json \
    --peer yusuf --endpoint <yusuf-public-ip>:9443

# 4. Publish a private target behind a node:
python3 scripts/wwfi_mesh_node.py route add --state ~/.wwfi/yicket.json \
    --domain yi.cket --owner yicket --target 10.37.4.21 --target-port 80

# 5. Run the node daemon (TLS listener + control API on 127.0.0.1:8123):
python3 scripts/wwfi_mesh_node.py node --state ~/.wwfi/yicket.json

# 6. From the remote client, reach Yusuf's private server by domain only:
python3 scripts/wwfi_mesh_node.py forward --state ~/.wwfi/yusuf.json \
    --domain yi.cket --local-port 8900
curl http://127.0.0.1:8900/
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from wwfi.admin import AdminAuth  # noqa: E402
from wwfi.mesh import (  # noqa: E402
    DEFAULT_BIND_PORT,
    DEFAULT_CONTROL_HOST,
    DEFAULT_CONTROL_PORT,
    MeshError,
    MeshKey,
    MeshNode,
    MeshStore,
    PeerSpec,
    RouteSpec,
    generate_ca,
    issue_node_cert,
)

DEFAULT_ADMIN_FILE = "configs/admin.json"


def _load_state(path: str) -> MeshStore:
    state = MeshStore(path=path).load()
    if not state.node_id:
        raise MeshError(f"{path} has not been initialized (run 'init' first)")
    return state


def cmd_admin(args) -> None:
    auth = AdminAuth.load(args.file)
    if args.cmd == "init":
        if not args.password:
            import getpass

            pw = getpass.getpass("Admin password: ")
        else:
            pw = args.password
        auth.set_user(args.user, pw)
        auth.set_api_token()
        print(f"[wwfi-mesh] admin user '{args.user}' saved to {args.file} (chmod 600)")
        print(f"[wwfi-mesh] API token (for the extension gateway): {auth.api_token}")
        print("[wwfi-mesh] the credentials file is gitignored — never commit it.")
    elif args.cmd == "token":
        auth.set_api_token(args.token)
        print(f"[wwfi-mesh] API token: {auth.api_token}")


def cmd_ca_init(args) -> None:
    cert, key = generate_ca(args.dir)
    print(f"[wwfi-mesh] CA ready: cert={cert} key={key}")
    print("[wwfi-mesh] every node must be issued a cert signed by this CA.")


def cmd_init(args) -> None:
    state = MeshStore(path=args.state)
    state.node_id = args.node
    state.ca_cert_path = str(Path(args.ca_dir).expanduser() / "mesh-ca.crt")
    cert_dir = Path(args.cert_dir).expanduser() if args.cert_dir != "auto" else Path("~/.wwfi").expanduser()
    cert_dir.mkdir(parents=True, exist_ok=True)
    state.cert_path = str(cert_dir / f"mesh-node-{args.node}.crt")
    state.key_path = str(cert_dir / f"mesh-node-{args.node}.key")
    if not Path(state.ca_cert_path).exists():
        raise MeshError(f"mesh CA not found at {state.ca_cert_path!r} — run 'ca-init' first")
    # the node identity key IS the TLS key (one key for both planes)
    key = MeshKey.load_or_create(Path(state.key_path), args.node)
    if not Path(state.cert_path).exists():
        cert, k = issue_node_cert(
            state.ca_cert_path,
            str(Path(args.ca_dir).expanduser() / "mesh-ca.key"),
            args.node,
            str(cert_dir),
            key=key.key,
        )
        state.cert_path = cert
        state.key_path = k
    state.save()
    print(
        f"[wwfi-mesh] node={args.node} cert={state.cert_path} "
        f"fingerprint={key.fingerprint[:32]}"
    )
    print(f"[wwfi-mesh] state saved to {state.path}")


def cmd_peer_add(args) -> None:
    state = _load_state(args.state)
    host, _, port = args.endpoint.rpartition(":")
    if not host:
        raise MeshError("--endpoint must be host:port")
    state.peers[args.peer] = PeerSpec(node_id=args.peer, host=host, port=int(port))
    state.save()
    print(f"[wwfi-mesh] peer {args.peer} -> {host}:{port}")


def cmd_peer_ls(args) -> None:
    state = _load_state(args.state)
    for nid, peer in sorted(state.peers.items()):
        print(f"{nid}\t{peer.host}:{peer.port}")


def cmd_route_add(args) -> None:
    state = _load_state(args.state)
    state.routes[args.domain] = RouteSpec(
        domain=args.domain,
        owner=args.owner or state.node_id,
        target_host=args.target,
        target_port=args.target_port,
    )
    state.save()
    print(
        f"[wwfi-mesh] {state.node_id} now serves {args.domain} "
        f"-> {args.target}:{args.target_port} (owner={args.owner or state.node_id})"
    )


def cmd_route_ls(args) -> None:
    state = _load_state(args.state)
    routes = state.routes if args.local else state.advertised_domains()
    for domain in sorted(state.routes):
        r = state.routes[domain]
        print(f"{domain}\towner={r.owner}\t{r.target_host}:{r.target_port}")
    if not args.local:
        for domain in sorted(set(state.announces) - set(state.routes)):
            r = state.announces[domain]
            print(f"{domain}\towner={r.owner}\t(routes: {state.reach.get(r.owner, [])})")


def cmd_node(args) -> None:
    state = _load_state(args.state)
    if not state.cert_path or not Path(state.cert_path).exists():
        raise MeshError(f"node cert missing for {state.node_id} — run 'init'")
    if args.bind_address:
        state.bind_host, _, state.bind_port = args.bind_address.rpartition(":")
        state.bind_port = int(state.bind_port or DEFAULT_BIND_PORT)
    if args.control_address:
        state.control_host, _, state.control_port = args.control_address.rpartition(":")
        state.control_port = int(state.control_port or DEFAULT_CONTROL_PORT)
    state.save()

    import asyncio

    node = MeshNode(state)
    node.admin = AdminAuth.load(args.admin_file)
    node.control_token = args.token or node.admin.api_token
    public = node.public_control
    if not node.control_token:
        if public:
            print("[!!] control API bound to a public address WITHOUT a token — requests will be DENIED")
            print("[!!]   pass --token $SECRET (or run 'admin init' to generate one)")
        else:
            print("[wwfi-mesh] control API on loopback with no token (local trust)")
    if node.admin and node.admin.exists:
        print(f"[wwfi-mesh] admin panel enabled: users={sorted(node.admin.data.get('users', {}))}")
    elif public:
        print("[!!] no admin credentials — admin panel disabled. Run: wwfi_mesh_node.py admin init")

    print(
        f"[wwfi-mesh] starting node {state.node_id} "
        f"(fingerprint={node.key.fingerprint[:16]}…)"
    )

    async def main():
        await node.start()
        await node.run_forever()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[wwfi-mesh] shutting down")


def cmd_forward(args) -> None:
    state = _load_state(args.state)

    import asyncio

    node = MeshNode(state)

    async def main():
        code, info = await node.resolve(args.domain)
        if code != 200:
            print(f"[wwfi-mesh] resolve failed ({code}): {info}")
            sys.exit(1)
        print(
            f"[wwfi-mesh] {args.domain} -> owner={info['owner']} "
            f"target={info.get('target_host')}:{info.get('target_port')}"
        )
        code, info2 = await node.forward(args.domain, local_port=args.local_port)
        if code != 200:
            print(f"[wwfi-mesh] forward failed ({code}): {info2}")
            sys.exit(1)
        await asyncio.sleep(36000)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[wwfi-mesh] forward closed")


def cmd_resolve(args) -> None:
    state = _load_state(args.state)

    import asyncio

    node = MeshNode(state)

    async def main():
        code, info = await node.resolve(args.domain)
        print(json.dumps({"code": code, **info}, indent=2, default=str))
        sys.exit(0 if code == 200 else 1)

    asyncio.run(main())


def main() -> None:
    p = argparse.ArgumentParser(description="WWFI Mesh node (resolver + network node)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("ca-init", help="bootstrap the mesh CA")
    sp.add_argument("--dir", default="certs")
    sp.set_defaults(func=cmd_ca_init)

    sp = sub.add_parser("init", help="create node identity + mTLS cert")
    sp.add_argument("--state", required=True, help="path to node state JSON")
    sp.add_argument("--node", required=True, help="node id (e.g. yusuf, yicket)")
    sp.add_argument("--ca-dir", default="certs")
    sp.add_argument("--cert-dir", default="auto")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("peer", help="peer management")
    sp_arg = sp.add_subparsers(dest="peer_cmd", required=True)
    sp_add = sp_arg.add_parser("add", help="add a trusted peer")
    sp_add.add_argument("--state", required=True)
    sp_add.add_argument("--peer", required=True, help="peer node id")
    sp_add.add_argument("--endpoint", required=True, help="host:port of the peer's node listener")
    sp_add.set_defaults(func=cmd_peer_add)
    sp_ls = sp_arg.add_parser("ls", help="list peers")
    sp_ls.add_argument("--state", required=True)
    sp_ls.set_defaults(func=cmd_peer_ls)

    sp = sub.add_parser("route", help="route management (domains I serve)")
    sp_arg = sp.add_subparsers(dest="route_cmd", required=True)
    sp_add = sp_arg.add_parser("add", help="publish a domain -> private target")
    sp_add.add_argument("--state", required=True)
    sp_add.add_argument("--domain", required=True)
    sp_add.add_argument("--owner", default="")
    sp_add.add_argument("--target", required=True)
    sp_add.add_argument("--target-port", type=int, required=True)
    sp_add.set_defaults(func=cmd_route_add)
    sp_ls = sp_arg.add_parser("ls", help="list routes")
    sp_ls.add_argument("--state", required=True)
    sp_ls.add_argument("--local", action="store_true", help="local routes only")
    sp_ls.set_defaults(func=cmd_route_ls)

    sp = sub.add_parser("node", help="run the mesh node daemon")
    sp.add_argument("--state", required=True)
    sp.add_argument("--bind-address", default="", help="public listener host:port")
    sp.add_argument("--control-address", default="", help="control API host:port (default {DEFAULT_CONTROL_HOST}:{DEFAULT_CONTROL_PORT})")
    sp.add_argument("--token", default="", help="static API token for the extension / API clients (or set via 'admin init')")
    sp.add_argument("--admin-file", default=DEFAULT_ADMIN_FILE, help="gitignored admin credentials JSON")
    sp.set_defaults(func=cmd_node)

    sp = sub.add_parser("admin", help="domain admin panel credentials (stored gitignored)")
    sp_arg = sp.add_subparsers(dest="admin_cmd", required=True)
    sp_init = sp_arg.add_parser("init", help="create/rotate the admin user + API token")
    sp_init.add_argument("--user", required=True)
    sp_init.add_argument("--password", default="", help="omit to be prompted (hidden)")
    sp_init.add_argument("--file", default=DEFAULT_ADMIN_FILE)
    sp_init.set_defaults(func=cmd_admin, cmd="init")
    sp_tok = sp_arg.add_parser("token", help="set/rotate the static API token")
    sp_tok.add_argument("--token", default="", help="explicit token, or random if omitted")
    sp_tok.add_argument("--file", default=DEFAULT_ADMIN_FILE)
    sp_tok.set_defaults(func=cmd_admin, cmd="token")

    sp = sub.add_parser("forward", help="publish a mesh tunnel as a loopback proxy")
    sp.add_argument("--state", required=True)
    sp.add_argument("--domain", required=True)
    sp.add_argument("--local-port", type=int, default=0)
    sp.set_defaults(func=cmd_forward)

    sp = sub.add_parser("resolve", help="resolve a domain over the mesh")
    sp.add_argument("--state", required=True)
    sp.add_argument("--domain", required=True)
    sp.set_defaults(func=cmd_resolve)

    args = p.parse_args()
    try:
        args.func(args)
    except MeshError as exc:
        sys.stderr.write(f"error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()