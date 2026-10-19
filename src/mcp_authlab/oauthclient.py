"""`mcp-authlab login`: the scanner as an OAuth 2.1 public client.

Discovers the authorization server the same way the scanner does, registers a
client (RFC 7591) or uses --client-id, runs the authorization code flow with
PKCE S256 and a loopback redirect, and stores the tokens. On the way it probes
the authorization server (the ASF-* checks) and mints a second token for a
different resource so the scan can test audience binding.

A strict authorization server burns a code after a failed exchange, so the
wrong-verifier and wrong-redirect probes can cost an extra authorization round.
With a browser that is one more consent page; with the fixture it is automatic.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sys
import threading
import time
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, cast
from urllib.parse import parse_qs, urlencode, urlsplit

from . import __version__, discovery, jwtutil
from .catalog import BY_ID, CATALOG, ERROR, FAIL, LOGIN, PASS, SKIP, WARN, Result
from .httpclient import Client, Response, TransportError

JsonDoc = dict[str, Any]


class LoginError(Exception):
    pass


@dataclass
class TokenSet:
    access_token: str
    refresh_token: str | None
    expires_at: float | None
    raw: JsonDoc
    resource: str


@dataclass
class LoginOutcome:
    canonical: str
    issuer: str
    metadata: JsonDoc
    client_id: str
    main: TokenSet
    foreign: TokenSet | None
    foreign_usable: bool
    foreign_note: str | None
    foreign_audience_known: bool
    results: list[Result] = field(default_factory=list)

    def to_store(self) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "resource": self.canonical,
            "issuer": self.issuer,
            "token_endpoint": self.metadata.get("token_endpoint"),
            "client_id": self.client_id,
            "access_token": self.main.access_token,
            "refresh_token": self.main.refresh_token,
            "expires_at": self.main.expires_at,
            "logged_in_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tool_version": __version__,
            "foreign": {
                "resource": self.foreign.resource if self.foreign else None,
                "access_token": self.foreign.access_token if self.foreign else None,
                "usable": self.foreign_usable,
                "audience_known": self.foreign_audience_known,
                "note": self.foreign_note,
            },
            "asf": [r.to_dict() for r in self.results],
        }
        return entry


# -- loopback callback --------------------------------------------------------------------


class _Callback(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        srv = cast(_CallbackServer, self.server)
        u = urlsplit(self.path)
        if u.path != srv.path:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        params = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        body = b"<!doctype html><title>mcp-authlab</title><p>Signed in. You can close this tab.</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        srv.deliver(params)


class _CallbackServer(HTTPServer):
    def __init__(self, port: int = 0):
        super().__init__(("127.0.0.1", port), _Callback)
        self.path = "/callback"
        self.lock = threading.Lock()
        self.inbox: dict[str, dict[str, str]] = {}  # state -> params
        self.event = threading.Condition(self.lock)

    @property
    def redirect_uri(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}{self.path}"

    def deliver(self, params: dict[str, str]) -> None:
        with self.event:
            self.inbox[params.get("state", "")] = params
            self.event.notify_all()

    def wait(self, state: str, timeout: float) -> dict[str, str] | None:
        deadline = time.monotonic() + timeout
        with self.event:
            while state not in self.inbox:
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                self.event.wait(left)
            return self.inbox.pop(state)


# -- the client ----------------------------------------------------------------------------


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _json_body(resp: Response) -> JsonDoc | None:
    try:
        doc = json.loads(resp.text)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def _is_https_or_loopback(url: str) -> bool:
    return urlsplit(url).scheme.lower() == "https" or discovery.is_loopback(url)


class Login:
    def __init__(
        self,
        target: str,
        client_id: str | None = None,
        foreign_resource: str | None = None,
        scope: str | None = None,
        no_browser: bool = False,
        timeout: float = 300.0,
        http_timeout: float = 10.0,
        insecure: bool = False,
        redirect_port: int = 0,
        client: Client | None = None,
        log: Callable[[str], None] | None = None,
    ):
        self.target = target.strip()
        self.canonical = discovery.canonical(self.target)
        self.client_id = client_id
        self.foreign_resource = foreign_resource
        self.scope = scope
        self.no_browser = no_browser
        self.timeout = timeout
        self.insecure = insecure
        self.redirect_port = redirect_port
        self.http = client or Client(timeout=http_timeout, insecure=insecure)
        self.log = log or (lambda s: print(s, file=sys.stderr))
        self.results: list[Result] = []
        self.metadata: JsonDoc = {}
        self.issuer = ""
        self.redirect_uri = ""
        self.callback_iss: list[str | None] = []  # what each callback carried

    def _add(self, cid: str, status: str, message: str, **evidence: Any) -> Result:
        r = Result(BY_ID[cid], status, message, evidence)
        self.results.append(r)
        return r

    # -- discovery ---------------------------------------------------------------------
    def _fetch_json(self, url: str, accept_statuses: tuple[int, ...] = (200,)) -> JsonDoc | None:
        try:
            resp = self.http.get(url, {"Accept": "application/json"})
        except TransportError:
            return None
        if resp.status not in accept_statuses:
            return None
        return _json_body(resp)

    def discover(self) -> None:
        self.log(f"discovering authorization server for {self.canonical}")
        prm: JsonDoc | None = None
        try:
            challenge = self.http.post_json(
                self.target,
                b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
                {"Accept": "application/json, text/event-stream"},
            )
        except TransportError as e:
            raise LoginError(f"{self.target} did not answer: {e}") from e
        from . import wwwauth

        ch = wwwauth.bearer(challenge.header_all("WWW-Authenticate"))
        candidates: list[str] = []
        if ch and ch.params.get("resource_metadata", "").startswith(("http://", "https://")):
            candidates.append(ch.params["resource_metadata"])
        candidates += [u for u in discovery.protected_resource_metadata_urls(self.canonical) if u not in candidates]
        for url in candidates:
            prm = self._fetch_json(url)
            if prm:
                break
        if not prm:
            raise LoginError(
                "no Protected Resource Metadata found; the server does not advertise an authorization server"
            )
        servers = prm.get("authorization_servers")
        if not (isinstance(servers, list) and servers and isinstance(servers[0], str)):
            raise LoginError("Protected Resource Metadata lists no authorization server")
        self.issuer = servers[0]
        for _kind, url in discovery.authorization_server_metadata_urls(self.issuer):
            doc = self._fetch_json(url)
            if doc:
                self.metadata = doc
                break
        if not self.metadata:
            raise LoginError(f"no authorization server metadata found for {self.issuer}")
        for key in ("authorization_endpoint", "token_endpoint"):
            if not isinstance(self.metadata.get(key), str):
                raise LoginError(f"authorization server metadata lacks {key}")

    def register(self) -> None:
        if self.client_id:
            self.log(f"using client_id {self.client_id}")
            return
        reg = self.metadata.get("registration_endpoint")
        if not isinstance(reg, str):
            raise LoginError(
                f"{self.issuer} offers no dynamic registration; pass --client-id with a client registered for "
                f"redirect URI {self.redirect_uri}"
            )
        body = json.dumps(
            {
                "client_name": "mcp-authlab",
                "client_uri": "https://github.com/tmtmiller1/mcp-authlab",
                "redirect_uris": [self.redirect_uri],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "application_type": "native",
            }
        ).encode()
        try:
            resp = self.http.post_json(reg, body, {"Accept": "application/json"})
        except TransportError as e:
            raise LoginError(f"registration failed: {e}") from e
        doc = _json_body(resp)
        if resp.status not in (200, 201) or not doc or not isinstance(doc.get("client_id"), str):
            raise LoginError(f"registration returned {resp.status}: {resp.text[:300]}")
        self.client_id = doc["client_id"]
        self.log(f"registered client {self.client_id}")

    # -- authorization rounds ------------------------------------------------------------
    def _authorize_url(self, params: dict[str, str]) -> str:
        ep = str(self.metadata["authorization_endpoint"])
        return ep + ("&" if "?" in ep else "?") + urlencode(params)

    def _drive_loopback(self, url: str) -> None:
        """Without a browser, fetch the authorization URL ourselves and follow redirects to the callback."""
        for _ in range(8):
            try:
                resp = self.http.get(url, {"Accept": "text/html,application/json"})
            except TransportError as e:
                raise LoginError(f"could not fetch {url}: {e}") from e
            if resp.status in (301, 302, 303, 307, 308):
                loc = resp.header("Location")
                if not loc:
                    raise LoginError("redirect without Location")
                if loc.startswith(self.redirect_uri):
                    self.http.get(loc)  # deliver it to our own callback server
                    return
                url = loc
                continue
            if resp.status == 200:
                raise LoginError(
                    "the authorization server showed a page instead of redirecting; --no-browser only works with "
                    "an authorization server that approves without a user (fixture: --auto-consent)"
                )
            raise LoginError(f"authorization endpoint answered {resp.status}: {resp.text[:300]}")
        raise LoginError("too many redirects")

    def _round(self, cb: _CallbackServer, resource: str, label: str) -> tuple[str, str]:
        """One authorization request. Returns (code, verifier)."""
        verifier, challenge = _pkce()
        state = secrets.token_urlsafe(16)
        params = {
            "response_type": "code",
            "client_id": self.client_id or "",
            "redirect_uri": self.redirect_uri,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": resource,
        }
        if self.scope:
            params["scope"] = self.scope
        url = self._authorize_url(params)
        loopback_as = discovery.is_loopback(url)
        if self.no_browser and loopback_as:
            self.log(f"[{label}] fetching {url}")
            self._drive_loopback(url)
        else:
            self.log(f"[{label}] open this URL to sign in:\n  {url}")
            if not self.no_browser:
                webbrowser.open(url)
        got = cb.wait(state, self.timeout)
        if got is None:
            raise LoginError("timed out waiting for the browser to come back")
        self.callback_iss.append(got.get("iss"))
        if "error" in got:
            raise LoginError(f"authorization server refused: {got.get('error')}: {got.get('error_description', '')}")
        advertised = self.metadata.get("authorization_response_iss_parameter_supported") is True
        if advertised and got.get("iss") and discovery.canonical(got["iss"]) != discovery.canonical(self.issuer):
            raise LoginError(
                f"callback iss {got['iss']!r} is not the expected issuer {self.issuer!r}; stopping (RFC 9207)"
            )
        code = got.get("code")
        if not code:
            raise LoginError("callback carried no code")
        return code, verifier

    def _exchange(self, code: str, verifier: str, resource: str, redirect_uri: str | None = None) -> Response:
        fields = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri or self.redirect_uri,
            "client_id": self.client_id or "",
            "code_verifier": verifier,
            "resource": resource,
        }
        try:
            return self.http.post_form(str(self.metadata["token_endpoint"]), fields)
        except TransportError as e:
            raise LoginError(f"token endpoint unreachable: {e}") from e

    def _tokens(self, resp: Response, resource: str) -> TokenSet:
        doc = _json_body(resp)
        if resp.status != 200 or not doc or not isinstance(doc.get("access_token"), str):
            raise LoginError(f"token endpoint answered {resp.status}: {resp.text[:300]}")
        exp = doc.get("expires_in")
        expires_at = time.time() + float(exp) if isinstance(exp, (int, float)) else None
        rt = doc.get("refresh_token")
        return TokenSet(doc["access_token"], rt if isinstance(rt, str) else None, expires_at, doc, resource)

    def _is_burned(self, resp: Response) -> bool:
        doc = _json_body(resp) or {}
        return resp.status in (400, 401) and doc.get("error") in ("invalid_grant", "invalid_request")

    # -- probes --------------------------------------------------------------------------
    def _probe_asf01(self) -> None:
        params = {
            "response_type": "code",
            "client_id": self.client_id or "",
            "redirect_uri": self.redirect_uri,
            "state": secrets.token_urlsafe(8),
            "resource": self.canonical,
        }
        url = self._authorize_url(params)
        try:
            resp = self.http.get(url, {"Accept": "text/html,application/json"})
        except TransportError as e:
            self._add("ASF-01", ERROR, str(e))
            return
        ev = {"http_status": resp.status, "location": resp.header("Location")}
        loc = resp.header("Location") or ""
        if resp.status in (400, 401, 403):
            self._add("ASF-01", PASS, f"{resp.status} without code_challenge", **ev)
        elif resp.status in (301, 302, 303, 307, 308) and loc.startswith(self.redirect_uri):
            q = parse_qs(urlsplit(loc).query)
            if "error" in q:
                self._add("ASF-01", PASS, f"redirected back with error={q['error'][0]}", **ev)
            else:
                self._add(
                    "ASF-01", FAIL, "issued an authorization code without code_challenge; PKCE is optional here", **ev
                )
        else:
            self._add(
                "ASF-01",
                WARN,
                f"answered {resp.status} without code_challenge (a login page or a redirect elsewhere); "
                "this tool cannot see whether the request would be refused after sign-in",
                **ev,
            )

    def _probe_asf02(self, code: str, resource: str) -> Response:
        """Wrong verifier. Returns the response so the caller can tell whether it got a token anyway."""
        resp = self._exchange(code, secrets.token_urlsafe(48), resource)
        if resp.status == 200 and (_json_body(resp) or {}).get("access_token"):
            self._add(
                "ASF-02",
                FAIL,
                "token endpoint issued a token for a wrong code_verifier; PKCE is not enforced",
                http_status=200,
            )
        elif resp.status in (400, 401):
            self._add(
                "ASF-02",
                PASS,
                f"{resp.status} {(_json_body(resp) or {}).get('error', '')}".strip(),
                http_status=resp.status,
            )
        else:
            self._add("ASF-02", WARN, f"unexpected {resp.status} for a wrong code_verifier", http_status=resp.status)
        return resp

    def _probe_asf03(self, code: str, verifier: str, resource: str) -> Response:
        wrong = self.redirect_uri.replace("/callback", "/elsewhere")
        resp = self._exchange(code, verifier, resource, redirect_uri=wrong)
        if resp.status == 200 and (_json_body(resp) or {}).get("access_token"):
            self._add(
                "ASF-03",
                FAIL,
                "token endpoint issued a token although redirect_uri differed from the authorization request",
                http_status=200,
            )
        elif resp.status in (400, 401):
            self._add(
                "ASF-03",
                PASS,
                f"{resp.status} {(_json_body(resp) or {}).get('error', '')}".strip(),
                http_status=resp.status,
            )
        else:
            self._add("ASF-03", WARN, f"unexpected {resp.status} for a wrong redirect_uri", http_status=resp.status)
        return resp

    def _aud(self, token: str) -> list[str] | None:
        try:
            _, claims, _ = jwtutil.decode_unverified(token)
        except (ValueError, UnicodeDecodeError):
            return None
        aud = claims.get("aud")
        if isinstance(aud, str):
            return [aud]
        if isinstance(aud, list):
            return [str(a) for a in aud]
        return []

    def _probe_asf04(self, main: TokenSet, foreign: TokenSet | None) -> tuple[bool, str | None, bool]:
        """Returns (foreign_usable, note, audience_known)."""
        main_aud = self._aud(main.access_token)
        if main_aud is None:
            r = self._add(
                "ASF-04", SKIP, "access tokens are opaque; the scan compares what the resource server does with each"
            )
            r.evidence["opaque"] = True
            return foreign is not None, None, False
        canon = {discovery.canonical(a) for a in main_aud}
        bound = self.canonical in canon
        if foreign is None:
            if bound:
                self._add("ASF-04", PASS, f"aud={main_aud}", aud=main_aud)
            else:
                self._add(
                    "ASF-04",
                    FAIL,
                    f"aud={main_aud} does not name the requested resource {self.canonical}",
                    aud=main_aud,
                )
            return False, "login minted no foreign-audience token", True
        f_aud = self._aud(foreign.access_token) or []
        f_canon = {discovery.canonical(a) for a in f_aud}
        if not bound:
            self._add(
                "ASF-04",
                FAIL,
                f"aud={main_aud} does not name the requested resource {self.canonical}",
                aud=main_aud,
                foreign_aud=f_aud,
            )
            return bool(f_canon) and f_canon != canon, None, True
        if f_canon == canon:
            self._add(
                "ASF-04",
                FAIL,
                f"the token requested for {foreign.resource} came back with the same aud {main_aud}; "
                "the authorization server ignores resource= (RFC 8707)",
                aud=main_aud,
                foreign_aud=f_aud,
            )
            return (
                False,
                "the authorization server ignored resource= and minted the second token for the same audience, so "
                "there is no foreign token to test with (see ASF-04)",
                True,
            )
        self._add(
            "ASF-04", PASS, f"aud={main_aud}; the second token carries aud={f_aud}", aud=main_aud, foreign_aud=f_aud
        )
        return True, None, True

    def _probe_asf05(self, main: TokenSet) -> TokenSet:
        if not main.refresh_token:
            r = self._add("ASF-05", SKIP, "no refresh token was issued, so there is nothing to rotate")
            r.applicable = False
            return main
        fields = {
            "grant_type": "refresh_token",
            "refresh_token": main.refresh_token,
            "client_id": self.client_id or "",
            "resource": main.resource,
        }
        try:
            resp = self.http.post_form(str(self.metadata["token_endpoint"]), fields)
        except TransportError as e:
            self._add("ASF-05", ERROR, str(e))
            return main
        doc = _json_body(resp) or {}
        if resp.status != 200 or not isinstance(doc.get("access_token"), str):
            self._add("ASF-05", WARN, f"refresh failed with {resp.status}: {resp.text[:200]}", http_status=resp.status)
            return main
        new_rt = doc.get("refresh_token")
        if not isinstance(new_rt, str):
            self._add("ASF-05", WARN, "refresh response carried no refresh_token; the old one stays valid indefinitely")
            new_rt = main.refresh_token
        elif new_rt == main.refresh_token:
            self._add(
                "ASF-05", WARN, "the same refresh token came back; a public client's refresh tokens should rotate"
            )
        else:
            self._add("ASF-05", PASS, "a new refresh token was issued on refresh")
        exp = doc.get("expires_in")
        expires_at = time.time() + float(exp) if isinstance(exp, (int, float)) else main.expires_at
        return TokenSet(doc["access_token"], new_rt, expires_at, doc, main.resource)

    def _probe_asf06(self) -> None:
        problems = []
        for key in ("issuer", "authorization_endpoint", "token_endpoint", "registration_endpoint"):
            v = self.metadata.get(key)
            if isinstance(v, str) and not _is_https_or_loopback(v):
                problems.append(f"{key}={v}")
        advertised = self.metadata.get("authorization_response_iss_parameter_supported") is True
        if advertised and any(i is None for i in self.callback_iss):
            problems.append("metadata advertises iss but a callback arrived without it")
        if problems:
            self._add("ASF-06", FAIL, "; ".join(problems), callbacks=len(self.callback_iss))
        else:
            note = "iss present on every callback" if advertised else "iss not advertised, so not required"
            self._add("ASF-06", PASS, f"all URLs HTTPS (or loopback); {note}", callbacks=len(self.callback_iss))

    # -- the whole flow -------------------------------------------------------------------
    def run(self) -> LoginOutcome:
        self.discover()
        cb = _CallbackServer(self.redirect_port)
        self.redirect_uri = cb.redirect_uri
        t = threading.Thread(target=cb.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        try:
            self.register()
            assert self.client_id
            self._probe_asf01()

            # Round 1: the token for the server itself; the wrong-verifier probe spends its code if the AS is strict.
            code, verifier = self._round(cb, self.canonical, "token")
            resp = self._probe_asf02(code, self.canonical)
            if resp.status == 200 and (_json_body(resp) or {}).get("access_token"):
                main = self._tokens(resp, self.canonical)
            else:
                resp = self._exchange(code, verifier, self.canonical)
                if self._is_burned(resp):
                    self.log("the authorization server burned the code after the failed probe; one more sign-in")
                    code, verifier = self._round(cb, self.canonical, "token again")
                    resp = self._exchange(code, verifier, self.canonical)
                main = self._tokens(resp, self.canonical)
            self.log("got an access token for " + self.canonical)

            # Round 2: a token for another resource; the wrong-redirect probe spends its code the same way.
            foreign_res = self.foreign_resource or self.issuer
            foreign: TokenSet | None = None
            try:
                code, verifier = self._round(cb, foreign_res, "foreign token")
                resp = self._probe_asf03(code, verifier, foreign_res)
                if resp.status == 200 and (_json_body(resp) or {}).get("access_token"):
                    foreign = self._tokens(resp, foreign_res)
                else:
                    resp = self._exchange(code, verifier, foreign_res)
                    if self._is_burned(resp):
                        self.log("code burned after the probe; one more sign-in for the foreign token")
                        code, verifier = self._round(cb, foreign_res, "foreign token again")
                        resp = self._exchange(code, verifier, foreign_res)
                    foreign = self._tokens(resp, foreign_res)
                self.log("got a token for " + foreign_res)
            except LoginError as e:
                self.log(f"could not mint a foreign-audience token: {e}")
                if not any(r.check.id == "ASF-03" for r in self.results):
                    self._add("ASF-03", SKIP, f"no second authorization code to test with: {e}")
            usable, note, known = self._probe_asf04(main, foreign)
            if foreign is None and note is None:
                note = "login minted no foreign-audience token"
            main = self._probe_asf05(main)
            self._probe_asf06()
        finally:
            cb.shutdown()
            cb.server_close()
        for c in CATALOG:
            if c.phase == LOGIN and not any(r.check.id == c.id for r in self.results):
                self._add(c.id, SKIP, "login did not reach this probe")
        return LoginOutcome(
            self.canonical,
            self.issuer,
            self.metadata,
            self.client_id or "",
            main,
            foreign,
            usable and foreign is not None,
            note if not (usable and foreign is not None) else None,
            known,
            self.results,
        )


def refresh(entry: dict[str, Any], http: Client | None = None) -> dict[str, Any] | None:
    """Refresh a stored token set in place. Returns the updated entry, or None when it could not."""
    rt, ep, cid = entry.get("refresh_token"), entry.get("token_endpoint"), entry.get("client_id")
    if not (isinstance(rt, str) and isinstance(ep, str) and isinstance(cid, str)):
        return None
    http = http or Client()
    try:
        resp = http.post_form(
            ep, {"grant_type": "refresh_token", "refresh_token": rt, "client_id": cid, "resource": entry["resource"]}
        )
    except TransportError:
        return None
    doc = _json_body(resp) or {}
    if resp.status != 200 or not isinstance(doc.get("access_token"), str):
        return None
    entry["access_token"] = doc["access_token"]
    if isinstance(doc.get("refresh_token"), str):
        entry["refresh_token"] = doc["refresh_token"]
    exp = doc.get("expires_in")
    entry["expires_at"] = time.time() + float(exp) if isinstance(exp, (int, float)) else None
    return entry
