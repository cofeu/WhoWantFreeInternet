"""WWFI admin panel auth + credential store.

Credentials live in a gitignored JSON file (default ``configs/admin.json``) and
are **never** part of the repository. Passwords are stored as salted PBKDF2
SHA-256 hashes; a random session secret and the shared API token live in the
same file so the mesh node keeps its auth across restarts.

Two client kinds:
- API clients (the browser extension) authenticate with a static Bearer token.
- The domain admin panel authenticates with username + password, then uses a
  short-lived HMAC-signed session cookie.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

PBKDF2_ITERATIONS = 210_000
SESSION_TTL_SECONDS = 7 * 24 * 3600
_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


class AdminError(Exception):
    pass


def _normalize_password(pw: str) -> str:
    if not pw:
        raise AdminError("password must not be empty")
    return pw


def _fingerprint(pw: str, salt_bytes: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt_bytes, PBKDF2_ITERATIONS)


def hash_password(password: str, salt: Optional[bytes] = None) -> dict:
    salt = salt or secrets.token_bytes(16)
    return {
        "kdf": "pbkdf2-sha256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(_fingerprint(password, salt)).decode("ascii"),
    }


def verify_password(password: str, record: dict) -> bool:
    try:
        salt = base64.b64decode(record["salt"])
        want = base64.b64decode(record["hash"])
    except (KeyError, ValueError):
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(digest, want)


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def generate_token(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sign(secret: str, message: str) -> str:
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass
class AdminAuth:
    """Loads and verifies admin credentials + sessions from a gitignored file."""

    path: Path
    data: dict = field(default_factory=dict)

    def __post_init__(self):
        self.path = Path(self.path).expanduser()

    # -- IO ---------------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> "AdminAuth":
        obj = cls(path=Path(path))
        if obj.path.exists():
            obj.data = json.loads(obj.path.read_text(encoding="utf-8"))
        return obj

    @property
    def exists(self) -> bool:
        return bool(self.data.get("users"))

    @property
    def session_secret(self) -> str:
        return self.data.get("session_secret") or ""

    @property
    def api_token(self) -> str:
        return self.data.get("api_token") or ""

    def save(self) -> "AdminAuth":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)
        return self

    def set_user(self, username: str, password: str, *, rotate_secret: bool = True) -> "AdminAuth":
        if not username:
            raise AdminError("username must not be empty")
        users = self.data.setdefault("users", {})
        users[username] = hash_password(password)
        if rotate_secret or not self.session_secret:
            self.data["session_secret"] = generate_token(32)
        return self.save()

    def set_api_token(self, token: Optional[str] = None) -> "AdminAuth":
        self.data["api_token"] = token or generate_token()
        return self.save()

    # -- verification -----------------------------------------------------

    def verify_password(self, username: str, password: str) -> bool:
        record = self.data.get("users", {}).get(username)
        if not record:
            return False
        return verify_password(password, record)

    def verify_api_token(self, token: str) -> bool:
        return bool(token) and bool(self.api_token) and constant_time_equal(token, self.api_token)

    def issue_session(self, username: str) -> str:
        payload = _b64url(
            json.dumps({"u": username, "e": int(time.time()) + SESSION_TTL_SECONDS}).encode("utf-8")
        )
        return payload + "." + _sign(self.session_secret, payload)

    def parse_session(self, cookie: Optional[str]) -> Optional[str]:
        if not cookie:
            return None
        try:
            payload, sig = cookie.split(".", 1)
        except ValueError:
            return None
        if not constant_time_equal(sig, _sign(self.session_secret, payload)):
            return None
        try:
            meta = json.loads(_b64url_decode(payload).decode("utf-8"))
        except Exception:
            return None
        if meta.get("e", 0) < time.time():
            return None
        user = meta.get("u")
        if user not in self.data.get("users", {}):
            return None
        return user

    def random_username_hint(self) -> str:
        return "".join(secrets.choice(_ALPHABET) for _ in range(8))


def admin_panel_html() -> str:
    """Standalone admin panel page (login + domain board), plain JS/HTML."""
    return r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WWFI Domain Admin</title>
<style>
  :root{color-scheme:dark}
  body{font:14px/1.5 system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;background:#0e1116;color:#e6e6e6}
  h1{font-size:1.3rem}
  table{width:100%;border-collapse:collapse;margin:1rem 0}
  th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid #2a2f3a}
  th{color:#9aa4b2}
  code{background:#1b2028;padding:1px 5px;border-radius:3px}
  input{background:#141a22;color:#e6e6e6;border:1px solid #2a2f3a;border-radius:4px;padding:.4rem .5rem}
  button{background:#1f6feb;color:#fff;border:0;border-radius:4px;padding:.45rem .8rem;cursor:pointer}
  button.danger{background:#b42318}
  a{color:#8ab4f8;cursor:pointer}
  .card{border:1px solid #2a2f3a;border-radius:8px;padding:1rem;margin:1rem 0}
  .err{color:#f28b82;font-size:.9rem}
  #login{max-width:320px;margin:4rem auto}
  input[type=password],input[type=text],input[type=number]{width:100%;box-sizing:border-box;margin:.3rem 0}
</style>
</head>
<body>
  <!-- Login -->
  <section id="login" class="card" style="display:none">
    <h1>WWFI Domain Admin</h1>
    <p class="err" id="loginErr"></p>
    <input type="text" id="loginUser" placeholder="username" autocomplete="username">
    <input type="password" id="loginPass" placeholder="password" autocomplete="current-password">
    <button id="loginBtn">Sign in</button>
    <p class="err" id="noAdmin" style="display:none">No admin configured on this node.
      Run: <code>python3 scripts/wwfi_mesh_node.py admin init --user NAME --password ***</code></p>
  </section>

  <!-- Dashboard -->
  <section id="dash" style="display:none">
    <h1>WWFI Domain Admin</h1>
    <p><a id="logout">Sign out</a></p>
    <details class="card" open>
      <summary>Publish a domain</summary>
      <div>
        <input type="text" id="dom" placeholder="domain" style="width:16rem">
        <input type="text" id="owner" placeholder="owner (default = this node)">
        <input type="text" id="target" placeholder="target host" style="width:12rem">
        <input type="number" id="tport" placeholder="port" style="width:6rem">
        <button id="addBtn">Publish</button>
      </div>
      <p class="err" id="addErr"></p>
    </details>
    <table>
      <thead><tr><th>domain</th><th>owner</th><th>target</th><th>tls</th><th></th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </section>

<script>
"use strict";
const $ = (id) => document.getElementById(id);

async function api(path, opts) {
  const r = await fetch(path, opts || {});
  const body = r.headers.get("content-type") && r.headers.get("content-type").includes("json")
    ? await r.json() : null;
  if (r.status === 401) { showLogin(); return null; }
  return { r, body };
}

function showLogin() {
  $("login").style.display = "block";
  $("dash").style.display = "none";
}

function showDash() {
  $("login").style.display = "none";
  $("dash").style.display = "block";
}

async function loadDomains() {
  const res = await api("/api/admin/domains");
  if (!res) return;
  const rows = res.body || [];
  $("rows").innerHTML = "";
  rows.forEach((d) => {
    const tr = document.createElement("tr");
    tr.innerHTML = "<td><code>" + d.domain + "</code></td><td>" + d.owner +
      "</td><td>" + d.target_host + ":" + d.target_port + "</td><td>" +
      (d.encrypted ? "mTLS" : "plain") + '</td><td><a class="danger" data-del="' +
      d.domain + '">remove</a></td>';
    tr.querySelector("[data-del]").onclick = async () => {
      const rm = await api("/api/admin/domains/" + encodeURIComponent(d.domain), { method: "DELETE" });
      if (rm) loadDomains();
    };
    $("rows").appendChild(tr);
  });
  showDash();
}

$("loginBtn").onclick = async () => {
  const err = $("loginErr");
  const r = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: $("loginUser").value, password: $("loginPass").value }),
  });
  if (r.ok) { location.reload(); return; }
  const b = await r.json().catch(() => ({}));
  err.textContent = b.error === "no-admin" ? "" : "Invalid credentials";
  $("noAdmin").style.display = b.error === "no-admin" ? "block" : "none";
};

$("logout").onclick = async () => {
  await fetch("/api/logout", { method: "POST" });
  location.reload();
};

$("addBtn").onclick = async () => {
  $("addErr").textContent = "";
  const payload = {
    domain: $("dom").value.trim(),
    target: $("target").value.trim(),
  };
  if (!$("owner").value.trim()) payload.owner = "";
  else payload.owner = $("owner").value.trim();
  payload.target_port = parseInt($("tport").value, 10) || 0;
  const res = await api("/api/admin/domains", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res) return;
  if (!res.r.ok) { $("addErr").textContent = res.body && res.body.error || "add failed"; return; }
  $("dom").value = ""; $("target").value = ""; $("tport").value = "";
  loadDomains();
};

loadDomains();
</script>
</body>
</html>
"""