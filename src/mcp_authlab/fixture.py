"""A small MCP resource server that implements the authorization spec correctly, plus
profiles that break it in the ways real servers do. The test suite scans each profile.

Run:  mcp-authlab fixture --profile reference
Then: mcp-authlab scan http://127.0.0.1:8765/mcp --token "$(curl -s http://127.0.0.1:8765/dev/token)"

Everything is stdlib. The HS256 secret is random per process; /dev/token mints tokens for demos.
"""

from __future__ import annotations

import json
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field, fields
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import PROTOCOL_VERSION, discovery, jwtutil


@dataclass
class Profile:
    name: str = "reference"
    no_prm: bool = False             # no Protected Resource Metadata at all
    bare_401: bool = False           # 401 without a WWW-Authenticate header
    no_scope_challenge: bool = False
    skip_signature: bool = False     # accepts any JWT shape, including alg=none
    skip_audience: bool = False      # does not check aud
    query_tokens: bool = False       # accepts ?access_token=
    session_is_auth: bool = False    # a known Mcp-Session-Id is enough
    weak_session: bool = False       # short sequential session IDs
    ignore_origin: bool = False
    wildcard_scopes: bool = False
    http_as: bool = False            # AS endpoints published as http://
    no_pkce: bool = False
    no_registration: bool = False
    no_iss: bool = False
    no_error_param: bool = False     # 401 for a bad token without error="invalid_token"
    ignore_version: bool = False
    open: bool = False               # no authorization at all
    wrong_resource: bool = False     # PRM 'resource' points elsewhere
    forbid_instead: bool = False     # 403 instead of 401 when unauthenticated


PROFILES: dict[str, Profile] = {
    "reference": Profile("reference"),
    "legacy": Profile("legacy", no_prm=True, bare_401=True, no_error_param=True),
    "weak-as": Profile("weak-as", no_pkce=True, no_registration=True, no_iss=True, no_scope_challenge=True),
    "passthrough": Profile("passthrough", skip_signature=True, skip_audience=True, ignore_origin=True),
    "sloppy": Profile("sloppy", query_tokens=True, session_is_auth=True, weak_session=True, ignore_origin=True,
                      wildcard_scopes=True, no_registration=True, ignore_version=True, no_error_param=True, no_scope_challenge=True),
    "open": Profile("open", open=True),
    "mismatch": Profile("mismatch", wrong_resource=True, http_as=True, forbid_instead=True),
}

EXPECTED_FAILURES: dict[str, set[str]] = {
    # What the scanner must flag (fail or warn) for each profile. Tests assert exactly these.
    "reference": set(),
    "legacy": {"CHAL-02", "PRM-01", "TOK-04"},
    "weak-as": {"ASM-04", "ASM-05", "ASM-06", "CHAL-03"},
    "passthrough": {"TOK-02", "TOK-03", "ORIG-01"},
    "sloppy": {"TOK-05", "SESS-01", "SESS-02", "ORIG-01", "PRM-05", "ASM-05", "VER-01", "TOK-04", "CHAL-03"},
    "open": {"CHAL-01"},
    "mismatch": {"CHAL-01", "PRM-02", "ASM-03"},
}


class FixtureState:
    def __init__(self, profile: Profile, public_url: str, as_url: str):
        self.profile = profile
        self.public_url = public_url
        self.resource = discovery.canonical(public_url)
        self.as_url = as_url.rstrip("/")
        self.secret = secrets.token_bytes(32)
        self.sessions: dict[str, dict] = {}
        self.counter = 1000
        self.lock = threading.Lock()

    def mint(self, aud: str | None = None, ttl: int = 3600) -> str:
        now = int(time.time())
        return jwtutil.encode(
            {"iss": self.as_url, "sub": "demo-user", "aud": aud or self.resource, "iat": now, "exp": now + ttl, "scope": "mcp:tools"},
            self.secret,
        )

    def new_session(self) -> str:
        with self.lock:
            if self.profile.weak_session:
                self.counter += 1
                sid = str(self.counter)
            else:
                sid = secrets.token_urlsafe(32)
            self.sessions[sid] = {"created": time.time()}
            return sid


class Handler(BaseHTTPRequestHandler):
    state: FixtureState  # set by serve()
    server_version = "mcp-authlab-fixture/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet
        if getattr(self.server, "verbose", False):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # -- plumbing ---------------------------------------------------------------
    def _send(self, status: int, body: bytes | None = None, headers: dict[str, str] | None = None, ctype: str = "application/json"):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if body is not None:
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
        else:
            self.send_header("Content-Length", "0")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, status: int, obj, headers: dict[str, str] | None = None):
        self._send(status, json.dumps(obj).encode(), headers)

    @property
    def st(self) -> FixtureState:
        return self.state

    @property
    def mcp_path(self) -> str:
        return urlsplit(self.st.public_url).path or "/mcp"

    def _prm_doc(self) -> dict:
        p = self.st.profile
        scopes = ["mcp:tools", "*", "offline_access"] if p.wildcard_scopes else ["mcp:tools", "mcp:resources"]
        return {
            "resource": "https://somewhere-else.example/mcp" if p.wrong_resource else self.st.resource,
            "authorization_servers": [self.st.as_url],
            "scopes_supported": scopes,
            "bearer_methods_supported": ["header"],
            "resource_name": f"mcp-authlab fixture ({p.name})",
        }

    def _as_doc(self) -> dict:
        p = self.st.profile
        base = self.st.as_url
        if p.http_as:
            base = "http://as.example.com"
        doc = {
            "issuer": self.st.as_url,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["mcp:tools", "mcp:resources"],
        }
        if not p.no_pkce:
            doc["code_challenge_methods_supported"] = ["S256"]
        if not p.no_registration:
            doc["registration_endpoint"] = f"{base}/register"
            doc["client_id_metadata_document_supported"] = True
        if not p.no_iss:
            doc["authorization_response_iss_parameter_supported"] = True
        return doc

    def _challenge_headers(self, error: str | None = None, desc: str | None = None) -> dict[str, str]:
        p = self.st.profile
        if p.bare_401:
            return {}
        parts = []
        if error and not p.no_error_param:
            parts.append(f'error="{error}"')
            if desc:
                parts.append(f'error_description="{desc}"')
        if not p.no_prm:
            parts.append(f'resource_metadata="{self._prm_url()}"')
        if not p.no_scope_challenge:
            parts.append('scope="mcp:tools"')
        return {"WWW-Authenticate": "Bearer " + ", ".join(parts) if parts else "Bearer"}

    def _prm_url(self) -> str:
        o = urlsplit(self.st.public_url)
        path = o.path.rstrip("/")
        return f"{o.scheme}://{o.netloc}/.well-known/oauth-protected-resource{path}"

    # -- authorization ------------------------------------------------------------
    def _authorize(self) -> tuple[bool, int, dict[str, str]]:
        """Return (ok, status, headers) for the request's credentials."""
        p = self.st.profile
        if p.open:
            return True, 200, {}
        token = None
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        if token is None and p.query_tokens:
            qs = parse_qs(urlsplit(self.path).query)
            token = (qs.get("access_token") or [None])[0]
        if token is None and p.session_is_auth:
            sid = self.headers.get("Mcp-Session-Id")
            if sid and sid in self.st.sessions:
                return True, 200, {}
        if token is None:
            status = 403 if p.forbid_instead else 401
            return False, status, self._challenge_headers()
        try:
            if p.skip_signature:
                _, claims, _ = jwtutil.decode_unverified(token)
                if claims.get("exp") is not None and time.time() >= claims["exp"]:
                    raise ValueError("expired")
            else:
                claims = jwtutil.verify_hs256(token, self.st.secret)
            if not p.skip_audience and claims.get("aud") != self.st.resource:
                raise ValueError("wrong audience")
        except Exception as e:  # noqa: BLE001
            return False, 401, self._challenge_headers("invalid_token", str(e))
        return True, 200, {}

    # -- handlers ----------------------------------------------------------------
    def do_GET(self):
        path = urlsplit(self.path).path
        prm_path = urlsplit(self._prm_url()).path
        if path in (prm_path, "/.well-known/oauth-protected-resource"):
            if self.st.profile.no_prm:
                return self._send(404, b"not found", ctype="text/plain")
            return self._json(200, self._prm_doc())
        if path == "/.well-known/oauth-authorization-server":
            return self._json(200, self._as_doc())
        if path == "/dev/token":
            qs = parse_qs(urlsplit(self.path).query)
            aud = (qs.get("aud") or [None])[0]
            return self._send(200, self.st.mint(aud).encode(), ctype="text/plain")
        if path == self.mcp_path:
            ok, status, headers = self._authorize()
            if not ok:
                return self._send(status, headers=headers)
            return self._send(405, headers={"Allow": "POST, DELETE"})
        return self._send(404, b"not found", ctype="text/plain")

    def do_DELETE(self):
        path = urlsplit(self.path).path
        if path != self.mcp_path:
            return self._send(404)
        ok, status, headers = self._authorize()
        if not ok:
            return self._send(status, headers=headers)
        sid = self.headers.get("Mcp-Session-Id")
        with self.st.lock:
            self.st.sessions.pop(sid, None)
        return self._send(204)

    def do_POST(self):
        p = self.st.profile
        path = urlsplit(self.path).path
        if path != self.mcp_path:
            return self._send(404)
        origin = self.headers.get("Origin")
        if origin and not p.ignore_origin:
            host = urlsplit(origin).hostname or ""
            if host not in ("localhost", "127.0.0.1", urlsplit(self.st.public_url).hostname):
                return self._send(403, b"origin not allowed", ctype="text/plain")
        ok, status, headers = self._authorize()
        if not ok:
            return self._send(status, headers=headers)
        ver = self.headers.get("MCP-Protocol-Version")
        if ver and ver not in (PROTOCOL_VERSION, "2025-03-26", "2025-11-25") and not p.ignore_version:
            return self._send(400, b"unsupported protocol version", ctype="text/plain")
        length = int(self.headers.get("Content-Length") or 0)
        try:
            msg = json.loads(self.rfile.read(length) or b"null")
        except ValueError:
            return self._send(400, b"bad json", ctype="text/plain")
        if not isinstance(msg, dict):
            return self._send(400, b"expected a JSON-RPC message", ctype="text/plain")
        method = msg.get("method")
        if "id" not in msg:  # notification or response
            return self._send(202)
        if method == "initialize":
            sid = self.st.new_session()
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mcp-authlab-fixture", "version": "0.1", "profile": p.name},
            }
            return self._json(200, {"jsonrpc": "2.0", "id": msg["id"], "result": result}, {"Mcp-Session-Id": sid})
        sid = self.headers.get("Mcp-Session-Id")
        if not sid or sid not in self.st.sessions:
            return self._send(404 if sid else 400)
        if method == "ping":
            return self._json(200, {"jsonrpc": "2.0", "id": msg["id"], "result": {}})
        if method == "tools/list":
            return self._json(200, {"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": [
                {"name": "echo", "description": "Echo the input", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}
            ]}})
        if method == "tools/call":
            args = (msg.get("params") or {}).get("arguments") or {}
            return self._json(200, {"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": str(args.get("text", ""))}]}})
        return self._json(200, {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "method not found"}})


def serve(profile: Profile, host: str = "127.0.0.1", port: int = 0, public_url: str | None = None, verbose: bool = False) -> tuple[ThreadingHTTPServer, FixtureState]:
    """Bind and return (server, state) without blocking. Call server.serve_forever() or run it in a thread."""
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    srv.verbose = verbose  # type: ignore[attr-defined]
    real_port = srv.server_address[1]
    public = public_url or f"http://{host}:{real_port}/mcp"
    o = urlsplit(public)
    as_url = f"{o.scheme}://{o.netloc}"
    state = FixtureState(profile, public, as_url)
    Handler.state = state
    return srv, state


def profile_from_args(name: str, flags: list[str]) -> Profile:
    base = PROFILES.get(name)
    if base is None:
        raise SystemExit(f"unknown profile {name!r}; choose from {', '.join(PROFILES)}")
    p = Profile(**{f.name: getattr(base, f.name) for f in fields(Profile)})
    valid = {f.name for f in fields(Profile) if f.type == "bool"}
    for flag in flags:
        if flag not in valid:
            raise SystemExit(f"unknown flag {flag!r}; choose from {', '.join(sorted(valid))}")
        setattr(p, flag, True)
    if flags:
        p.name = f"{name}+{'+'.join(flags)}"
    return p
