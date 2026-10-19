"""A small MCP resource server plus a minimal authorization server, written against the
spec, with profiles that break them the ways real servers do. The test suite scans each profile.

Run:  mcp-authlab fixture --profile reference --auto-consent
Then: mcp-authlab login http://127.0.0.1:8765/mcp --no-browser
      mcp-authlab scan  http://127.0.0.1:8765/mcp

Everything is stdlib. The HS256 secret is random per process; /dev/token mints tokens for demos.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import secrets
import sys
import threading
import time
from dataclasses import dataclass, fields
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import parse_qs, urlencode, urlsplit

from . import PROTOCOL_VERSION, discovery, jwtutil

JsonDoc = dict[str, object]


@dataclass
class Profile:
    name: str = "reference"
    # resource server
    no_prm: bool = False  # no Protected Resource Metadata at all
    bare_401: bool = False  # 401 without a WWW-Authenticate header
    no_scope_challenge: bool = False
    skip_signature: bool = False  # accepts any JWT shape, including alg=none
    skip_audience: bool = False  # does not check aud
    query_tokens: bool = False  # accepts ?access_token=
    session_is_auth: bool = False  # a known Mcp-Session-Id is enough
    weak_session: bool = False  # short sequential session IDs
    ignore_origin: bool = False
    wildcard_scopes: bool = False
    no_error_param: bool = False  # 401 for a bad token without error="invalid_token"
    ignore_version: bool = False
    open: bool = False  # no authorization at all
    wrong_resource: bool = False  # PRM 'resource' points elsewhere
    forbid_instead: bool = False  # 403 instead of 401 when unauthenticated
    bare_403: bool = False  # scope step-up 403 without a challenge
    stateless: bool = False  # no Mcp-Session-Id at all
    # authorization server metadata
    http_as: bool = False  # AS endpoints published as http://
    no_pkce: bool = False  # metadata lacks S256
    no_registration: bool = False
    no_iss: bool = False  # metadata says iss is unsupported
    # authorization server behaviour
    pkce_optional: bool = False  # authorize accepts a request without code_challenge
    skip_verifier: bool = False  # token endpoint ignores code_verifier
    skip_redirect_check: bool = False  # token endpoint ignores redirect_uri
    ignore_resource: bool = False  # tokens are always minted for the default resource
    static_refresh: bool = False  # refresh tokens never rotate
    drop_iss: bool = False  # advertises iss but omits it from the callback


DEFECTS: tuple[str, ...] = tuple(f.name for f in fields(Profile) if f.name != "name")

PROFILES: dict[str, Profile] = {
    "reference": Profile("reference"),
    "legacy": Profile("legacy", no_prm=True, bare_401=True, no_error_param=True),
    "weak-as": Profile(
        "weak-as",
        no_pkce=True,
        no_registration=True,
        no_iss=True,
        no_scope_challenge=True,
        pkce_optional=True,
        skip_verifier=True,
        ignore_resource=True,
    ),
    "passthrough": Profile("passthrough", skip_signature=True, skip_audience=True, ignore_origin=True),
    "sloppy": Profile(
        "sloppy",
        query_tokens=True,
        session_is_auth=True,
        weak_session=True,
        ignore_origin=True,
        wildcard_scopes=True,
        no_registration=True,
        ignore_version=True,
        no_error_param=True,
        no_scope_challenge=True,
        bare_403=True,
        skip_redirect_check=True,
        static_refresh=True,
        drop_iss=True,
    ),
    "open": Profile("open", open=True),
    "mismatch": Profile("mismatch", wrong_resource=True, http_as=True, forbid_instead=True),
}

# What the scanner must flag (fail or warn) for each profile after a login and a scan.
# Tests assert exactly these. TLS-01 warns on loopback for every profile and is left out.
EXPECTED_FAILURES: dict[str, set[str]] = {
    "reference": set(),
    "legacy": {"CHAL-02", "PRM-01", "TOK-04", "SCOPE-01"},
    "weak-as": {"ASM-04", "ASM-05", "ASM-06", "CHAL-03", "ASF-01", "ASF-02", "ASF-04"},
    "passthrough": {"TOK-02", "TOK-03", "ORIG-01"},
    "sloppy": {
        "TOK-05",
        "SESS-01",
        "SESS-02",
        "ORIG-01",
        "PRM-05",
        "ASM-05",
        "VER-01",
        "TOK-04",
        "CHAL-03",
        "SCOPE-01",
        "ASF-03",
        "ASF-05",
        "ASF-06",
    },
    "open": {"CHAL-01"},
    "mismatch": {"CHAL-01", "PRM-02", "ASM-03"},
}
# Profiles `login` can run against: the rest hide the metadata or point at an unreachable authorization server.
LOGIN_PROFILES = ("reference", "weak-as", "passthrough", "sloppy", "open")

TOOL_SCOPES = {"list_secrets": "mcp:admin"}
SUPPORTED_SCOPES = ("mcp:tools", "mcp:resources", "mcp:admin")


class FixtureState:
    def __init__(self, profile: Profile, public_url: str, as_url: str, auto_consent: bool = False):
        self.profile = profile
        self.public_url = public_url
        self.resource = discovery.canonical(public_url)
        self.as_url = as_url.rstrip("/")
        self.auto_consent = auto_consent
        self.secret = secrets.token_bytes(32)
        self.sessions: dict[str, dict[str, float]] = {}
        self.clients: dict[str, dict[str, Any]] = {}
        self.codes: dict[str, dict[str, Any]] = {}
        self.refresh_tokens: dict[str, dict[str, Any]] = {}
        self.counter = 1000
        self.lock = threading.Lock()

    def mint(self, aud: str | None = None, ttl: int = 3600, scope: str = "mcp:tools") -> str:
        now = int(time.time())
        return jwtutil.encode(
            {
                "iss": self.as_url,
                "sub": "demo-user",
                "aud": aud or self.resource,
                "iat": now,
                "exp": now + ttl,
                "scope": scope,
                "jti": secrets.token_urlsafe(8),
            },
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


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], state: FixtureState | None = None, verbose: bool = False):
        super().__init__(address, Handler)
        self.state = state
        self.verbose = verbose


def _is_loopback_redirect(uri: str) -> bool:
    p = urlsplit(uri)
    return p.scheme in ("http", "https") and discovery.is_loopback(uri) and bool(p.hostname)


def _same_redirect(registered: str, given: str) -> bool:
    """RFC 8252 section 7.3: loopback redirect URIs match regardless of port."""
    a, b = urlsplit(registered), urlsplit(given)
    if a == b:
        return True
    return (
        _is_loopback_redirect(given)
        and a.scheme == b.scheme
        and (a.hostname or "").lower() == (b.hostname or "").lower()
        and a.path == b.path
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "mcp-authlab-fixture/0.2"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet unless verbose
        if cast(FixtureServer, self.server).verbose:
            sys.stderr.write(f"{self.address_string()} - {fmt % args}\n")

    # -- plumbing ---------------------------------------------------------------
    @property
    def st(self) -> FixtureState:
        state = cast(FixtureServer, self.server).state
        assert state is not None, "FixtureServer started without state"
        return state

    @property
    def p(self) -> Profile:
        return self.st.profile

    @property
    def mcp_path(self) -> str:
        return urlsplit(self.st.public_url).path or "/mcp"

    def _send(
        self,
        status: int,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        ctype: str = "application/json",
    ) -> None:
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

    def _json(self, status: int, obj: object, headers: dict[str, str] | None = None) -> None:
        self._send(status, json.dumps(obj).encode(), headers)

    def _text(self, status: int, text: str) -> None:
        self._send(status, text.encode(), ctype="text/plain")

    def _html(self, status: int, markup: str) -> None:
        self._send(status, markup.encode(), ctype="text/html; charset=utf-8")

    def _redirect(self, url: str) -> None:
        self._send(302, headers={"Location": url})

    def _form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    def _query(self) -> dict[str, str]:
        return {k: v[0] for k, v in parse_qs(urlsplit(self.path).query, keep_blank_values=True).items()}

    # -- metadata ---------------------------------------------------------------
    def _prm_url(self) -> str:
        o = urlsplit(self.st.public_url)
        path = o.path.rstrip("/")
        return f"{o.scheme}://{o.netloc}/.well-known/oauth-protected-resource{path}"

    def _prm_doc(self) -> JsonDoc:
        scopes = ["mcp:tools", "*", "offline_access"] if self.p.wildcard_scopes else ["mcp:tools", "mcp:resources"]
        return {
            "resource": "https://somewhere-else.example/mcp" if self.p.wrong_resource else self.st.resource,
            "authorization_servers": [self.st.as_url],
            "scopes_supported": scopes,
            "bearer_methods_supported": ["header"],
            "resource_name": f"mcp-authlab fixture ({self.p.name})",
        }

    def _as_doc(self) -> JsonDoc:
        base = "http://as.example.com" if self.p.http_as else self.st.as_url
        doc: JsonDoc = {
            "issuer": self.st.as_url,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": list(SUPPORTED_SCOPES),
        }
        if not self.p.no_pkce:
            doc["code_challenge_methods_supported"] = ["S256"]
        if not self.p.no_registration:
            doc["registration_endpoint"] = f"{base}/register"
            doc["client_id_metadata_document_supported"] = True
        if not self.p.no_iss:
            doc["authorization_response_iss_parameter_supported"] = True
        return doc

    def _challenge_headers(
        self, error: str | None = None, desc: str | None = None, scope: str | None = None
    ) -> dict[str, str]:
        if self.p.bare_401:
            return {}
        parts = []
        if error and not self.p.no_error_param:
            parts.append(f'error="{error}"')
            if desc:
                parts.append(f'error_description="{desc}"')
        if not self.p.no_prm:
            parts.append(f'resource_metadata="{self._prm_url()}"')
        if scope:
            parts.append(f'scope="{scope}"')
        elif not self.p.no_scope_challenge:
            parts.append('scope="mcp:tools"')
        return {"WWW-Authenticate": "Bearer " + ", ".join(parts) if parts else "Bearer"}

    # -- resource server authorization -------------------------------------------
    def _authorize(self) -> tuple[dict[str, Any] | None, int, dict[str, str]]:
        """Return (claims, status, headers). claims is None when the request is refused."""
        if self.p.open:
            return {"scope": " ".join(SUPPORTED_SCOPES)}, 200, {}
        token = None
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        if token is None and self.p.query_tokens:
            token = self._query().get("access_token")
        if token is None and self.p.session_is_auth:
            sid = self.headers.get("Mcp-Session-Id")
            if sid and sid in self.st.sessions:
                return {"scope": "mcp:tools"}, 200, {}
        if token is None:
            status = 403 if self.p.forbid_instead else 401
            return None, status, self._challenge_headers()
        try:
            if self.p.skip_signature:
                _, claims, _ = jwtutil.decode_unverified(token)
                exp = claims.get("exp")
                if isinstance(exp, (int, float)) and time.time() >= exp:
                    raise ValueError("expired")
            else:
                claims = jwtutil.verify_hs256(token, self.st.secret)
            if not self.p.skip_audience and claims.get("aud") != self.st.resource:
                raise ValueError("wrong audience")
        except Exception as e:  # noqa: BLE001
            return None, 401, self._challenge_headers("invalid_token", str(e))
        return claims, 200, {}

    # -- handlers ----------------------------------------------------------------
    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        prm_path = urlsplit(self._prm_url()).path
        if path in (prm_path, "/.well-known/oauth-protected-resource"):
            if self.p.no_prm:
                self._text(404, "not found")
            else:
                self._json(200, self._prm_doc())
            return
        if path == "/.well-known/oauth-authorization-server":
            self._json(200, self._as_doc())
            return
        if path == "/authorize":
            self._authorize_endpoint(self._query())
            return
        if path == "/dev/token":
            q = self._query()
            self._send(
                200, self.st.mint(q.get("aud"), scope=q.get("scope") or "mcp:tools").encode(), ctype="text/plain"
            )
            return
        if path == self.mcp_path:
            claims, status, headers = self._authorize()
            if claims is None:
                self._send(status, headers=headers)
            else:
                self._send(405, headers={"Allow": "POST, DELETE"})
            return
        self._text(404, "not found")

    def do_DELETE(self) -> None:
        path = urlsplit(self.path).path
        if path != self.mcp_path:
            self._send(404)
            return
        claims, status, headers = self._authorize()
        if claims is None:
            self._send(status, headers=headers)
            return
        sid = self.headers.get("Mcp-Session-Id")
        with self.st.lock:
            self.st.sessions.pop(sid or "", None)
        self._send(204)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path == "/register":
            self._register_endpoint()
            return
        if path == "/token":
            self._token_endpoint(self._form())
            return
        if path == "/authorize":
            self._authorize_endpoint(self._form(), consented=True)
            return
        if path != self.mcp_path:
            self._send(404)
            return
        origin = self.headers.get("Origin")
        if origin and not self.p.ignore_origin:
            host = urlsplit(origin).hostname or ""
            if host not in ("localhost", "127.0.0.1", urlsplit(self.st.public_url).hostname):
                self._text(403, "origin not allowed")
                return
        claims, status, headers = self._authorize()
        if claims is None:
            self._send(status, headers=headers)
            return
        ver = self.headers.get("MCP-Protocol-Version")
        if ver and ver not in (PROTOCOL_VERSION, "2025-03-26", "2025-11-25") and not self.p.ignore_version:
            self._text(400, "unsupported protocol version")
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            msg = json.loads(self.rfile.read(length) or b"null")
        except ValueError:
            self._text(400, "bad json")
            return
        if not isinstance(msg, dict):
            self._text(400, "expected a JSON-RPC message")
            return
        self._mcp(cast(dict[str, Any], msg), claims)

    # -- MCP -------------------------------------------------------------------------
    def _mcp(self, msg: dict[str, Any], claims: dict[str, Any]) -> None:
        method = msg.get("method")
        if "id" not in msg:  # notification or response
            self._send(202)
            return
        rid = msg["id"]
        if method == "initialize":
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mcp-authlab-fixture", "version": "0.2", "profile": self.p.name},
            }
            headers = {} if self.p.stateless else {"Mcp-Session-Id": self.st.new_session()}
            self._json(200, {"jsonrpc": "2.0", "id": rid, "result": result}, headers)
            return
        sid = self.headers.get("Mcp-Session-Id") or ""
        if not self.p.stateless and sid not in self.st.sessions:
            self._send(404 if sid else 400)
            return
        if method == "ping":
            self._json(200, {"jsonrpc": "2.0", "id": rid, "result": {}})
            return
        if method == "tools/list":
            tools = [
                {
                    "name": "echo",
                    "description": "Echo the input",
                    "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
                },
                {
                    "name": "list_secrets",
                    "description": "List the names of stored secrets (needs mcp:admin)",
                    "inputSchema": {"type": "object", "properties": {}},
                    "annotations": {"readOnlyHint": True},
                },
            ]
            self._json(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": tools}})
            return
        if method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name")
            needed = TOOL_SCOPES.get(str(name))
            granted = str(claims.get("scope") or "").split()
            if needed and needed not in granted:
                headers = (
                    {}
                    if self.p.bare_403
                    else self._challenge_headers("insufficient_scope", "needs " + needed, scope=needed)
                )
                self._send(403, headers=headers)
                return
            if name == "list_secrets":
                content = [{"type": "text", "text": "db-password, api-key"}]
            else:
                args = params.get("arguments") or {}
                content = [{"type": "text", "text": str(args.get("text", ""))}]
            self._json(200, {"jsonrpc": "2.0", "id": rid, "result": {"content": content}})
            return
        self._json(200, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}})

    # -- authorization server ----------------------------------------------------------
    def _register_endpoint(self) -> None:
        if self.p.no_registration:
            self._json(404, {"error": "registration is off"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._json(400, {"error": "invalid_client_metadata"})
            return
        uris = req.get("redirect_uris") if isinstance(req, dict) else None
        if not (isinstance(uris, list) and uris and all(isinstance(u, str) and _is_loopback_redirect(u) for u in uris)):
            self._json(400, {"error": "invalid_redirect_uri", "error_description": "loopback redirect URIs only"})
            return
        cid = "fx-" + secrets.token_urlsafe(12)
        client = {
            "client_id": cid,
            "client_id_issued_at": int(time.time()),
            "redirect_uris": uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_name": req.get("client_name") if isinstance(req, dict) else None,
        }
        with self.st.lock:
            self.st.clients[cid] = client
        self._json(201, client)

    def _client_ok(self, client_id: str | None, redirect_uri: str | None) -> bool:
        if not client_id or not redirect_uri or not _is_loopback_redirect(redirect_uri):
            return False
        client = self.st.clients.get(client_id)
        if client is None:
            return self.p.no_registration  # pre-registered clients are not modelled; accept any id
        return any(_same_redirect(r, redirect_uri) for r in client["redirect_uris"])

    def _authorize_endpoint(self, q: dict[str, str], consented: bool = False) -> None:
        client_id, redirect_uri = q.get("client_id"), q.get("redirect_uri")
        if not self._client_ok(client_id, redirect_uri):
            self._html(400, "<h1>invalid_request</h1><p>unknown client or redirect_uri</p>")
            return
        assert redirect_uri is not None and client_id is not None

        def err(code: str, desc: str) -> None:
            params = {"error": code, "error_description": desc}
            if q.get("state"):
                params["state"] = q["state"]
            self._redirect(redirect_uri + ("&" if "?" in redirect_uri else "?") + urlencode(params))

        if q.get("response_type") != "code":
            err("unsupported_response_type", "only code")
            return
        challenge = q.get("code_challenge")
        if not challenge and not self.p.pkce_optional:
            err("invalid_request", "code_challenge is required")
            return
        if challenge and q.get("code_challenge_method", "plain") != "S256":
            err("invalid_request", "only S256")
            return
        scope = " ".join(s for s in (q.get("scope") or "mcp:tools").split() if s in SUPPORTED_SCOPES) or "mcp:tools"
        if not consented and not self.st.auto_consent:
            hidden = "".join(
                f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">' for k, v in q.items()
            )
            self._html(
                200,
                "<!doctype html><title>mcp-authlab fixture: consent</title>"
                f"<h1>Allow {html.escape(client_id)} to use scope {html.escape(scope)}?</h1>"
                f'<form method="post" action="/authorize">{hidden}<button>Allow</button></form>',
            )
            return
        code = secrets.token_urlsafe(32)
        with self.st.lock:
            self.st.codes[code] = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": challenge,
                "scope": scope,
                "resource": q.get("resource"),
                "exp": time.time() + 120,
            }
        params = {"code": code}
        if q.get("state"):
            params["state"] = q["state"]
        if not self.p.no_iss and not self.p.drop_iss:
            params["iss"] = self.st.as_url
        self._redirect(redirect_uri + ("&" if "?" in redirect_uri else "?") + urlencode(params))

    def _token_error(self, code: str, desc: str) -> None:
        self._json(400, {"error": code, "error_description": desc}, {"Cache-Control": "no-store"})

    def _token_response(self, aud: str, scope: str, client_id: str, old_refresh: str | None = None) -> None:
        with self.st.lock:
            if old_refresh and self.p.static_refresh:
                refresh = old_refresh
            else:
                refresh = "rt-" + secrets.token_urlsafe(32)
                self.st.refresh_tokens.pop(old_refresh or "", None)
                self.st.refresh_tokens[refresh] = {"client_id": client_id, "aud": aud, "scope": scope}
        body = {
            "access_token": self.st.mint(aud, scope=scope),
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh,
            "scope": scope,
        }
        self._json(200, body, {"Cache-Control": "no-store"})

    def _token_endpoint(self, f: dict[str, str]) -> None:
        grant = f.get("grant_type")
        client_id = f.get("client_id") or ""
        if grant == "refresh_token":
            rec = self.st.refresh_tokens.get(f.get("refresh_token") or "")
            if rec is None or rec["client_id"] != client_id:
                self._token_error("invalid_grant", "unknown refresh token")
                return
            self._token_response(rec["aud"], rec["scope"], client_id, old_refresh=f.get("refresh_token"))
            return
        if grant != "authorization_code":
            self._token_error("unsupported_grant_type", "authorization_code or refresh_token")
            return
        with self.st.lock:
            rec = self.st.codes.pop(f.get("code") or "", None)  # single use, whatever happens next
        if rec is None or rec["exp"] < time.time():
            self._token_error("invalid_grant", "unknown, used or expired code")
            return
        if rec["client_id"] != client_id:
            self._token_error("invalid_grant", "code was issued to another client")
            return
        if not self.p.skip_redirect_check and f.get("redirect_uri") != rec["redirect_uri"]:
            self._token_error("invalid_grant", "redirect_uri does not match the authorization request")
            return
        if rec["code_challenge"] and not self.p.skip_verifier:
            verifier = f.get("code_verifier") or ""
            digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
            if not verifier or digest != rec["code_challenge"]:
                self._token_error("invalid_grant", "code_verifier does not match code_challenge")
                return
        resource = f.get("resource") or rec["resource"]
        aud = self.st.resource if self.p.ignore_resource or not resource else discovery.canonical(resource)
        self._token_response(aud, rec["scope"], client_id)


def serve(
    profile: Profile,
    host: str = "127.0.0.1",
    port: int = 0,
    public_url: str | None = None,
    verbose: bool = False,
    auto_consent: bool = False,
) -> tuple[FixtureServer, FixtureState]:
    """Bind and return (server, state) without blocking. Call start(server) or server.serve_forever()."""
    srv = FixtureServer((host, port), verbose=verbose)
    real_port = srv.server_address[1]
    public = public_url or f"http://{host}:{real_port}/mcp"
    o = urlsplit(public)
    state = FixtureState(profile, public, f"{o.scheme}://{o.netloc}", auto_consent=auto_consent)
    srv.state = state
    return srv, state


def start(srv: FixtureServer) -> threading.Thread:
    """Serve in a daemon thread. The short poll interval keeps shutdown() quick."""
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    return t


def profile_from_args(name: str, flags: list[str]) -> Profile:
    base = PROFILES.get(name)
    if base is None:
        raise SystemExit(f"unknown profile {name!r}; choose from {', '.join(PROFILES)}")
    p = Profile(**{f.name: getattr(base, f.name) for f in fields(Profile)})
    for flag in flags:
        if flag not in DEFECTS:
            raise SystemExit(f"unknown flag {flag!r}; choose from {', '.join(DEFECTS)}")
        setattr(p, flag, True)
    if flags:
        p.name = f"{name}+{'+'.join(flags)}"
    return p
