"""The scanner: runs the catalog against a live MCP server and keeps the evidence."""

from __future__ import annotations

import contextlib
import json
import re
import secrets
import time
from typing import Any
from urllib.parse import quote, urlsplit

from . import PROTOCOL_VERSION, SPEC_VERSION, __version__, discovery, jwtutil, tokenstore, wwwauth
from .catalog import BY_ID, CATALOG, ERROR, FAIL, LOGIN, PASS, SKIP, WARN, Result
from .grading import coverage, coverage_line, grade
from .httpclient import Client, Response, TransportError
from .policy import Policy

_WILDCARD_SCOPES = {"*", "all", "full", "full-access", "full_access", "admin", "everything", "root", "superuser"}
_REQUIRED_AS_FIELDS = ("issuer", "authorization_endpoint", "token_endpoint", "response_types_supported")
_AS_ENDPOINT_KEYS = (
    "authorization_endpoint",
    "token_endpoint",
    "registration_endpoint",
    "jwks_uri",
    "introspection_endpoint",
    "revocation_endpoint",
)
_READ_ONLY_NAME = re.compile(r"^(list|get|search|read|find|describe|fetch|show|query|lookup|view|whoami|status)", re.I)
LOGIN_HINT = "run `mcp-authlab login <url>` to enable"

JsonDoc = dict[str, Any]


def initialize_payload() -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-authlab", "version": __version__},
            },
        }
    ).encode()


def _rpc(method: str, params: dict[str, Any] | None = None, rid: int | None = 2) -> bytes:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if rid is not None:
        msg["id"] = rid
    return json.dumps(msg).encode()


def _mcp_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    h = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": PROTOCOL_VERSION}
    if extra:
        h.update(extra)
    return h


def _jsonrpc_result(resp: Response) -> JsonDoc | None:
    """Pull the JSON-RPC message out of a JSON or SSE body, if there's one."""
    if resp.content_type == "text/event-stream":
        data_lines: list[str] = []
        for line in resp.text.splitlines() + [""]:
            if line.startswith("data:"):
                data_lines.append(line[5:].strip())
                continue
            if line == "" and data_lines:
                try:
                    msg = json.loads("\n".join(data_lines))
                except ValueError:
                    msg = None
                data_lines = []
                if isinstance(msg, dict) and ("result" in msg or "error" in msg):
                    return msg
        return None
    try:
        msg = json.loads(resp.text)
    except ValueError:
        return None
    return msg if isinstance(msg, dict) else None


def _summ(resp: Response) -> dict[str, Any]:
    return {
        "http_status": resp.status,
        "www_authenticate": resp.header_all("WWW-Authenticate"),
        "content_type": resp.content_type,
    }


class Scanner:
    def __init__(
        self,
        target: str,
        token: str | None = None,
        foreign_token: str | None = None,
        timeout: float = 10.0,
        insecure: bool = False,
        client: Client | None = None,
        foreign_note: str | None = None,
        foreign_audience_known: bool = True,
        login_results: list[dict[str, Any]] | None = None,
        tool: str | None = None,
    ):
        self.target = target.strip()
        self.canonical = discovery.canonical(self.target)
        self.token = token
        self.foreign_token = foreign_token
        self.foreign_note = foreign_note
        self.foreign_note_needs_login = False
        self.foreign_audience_known = foreign_audience_known
        self.login_results = login_results
        self.tool = tool
        self.client = client or Client(timeout=timeout, insecure=insecure)
        self.results: list[Result] = []
        self.prm: JsonDoc | None = None
        self.prm_url: str | None = None
        self.challenge: wwwauth.Challenge | None = None
        self.open = False
        self.started = time.time()

    # -- helpers -----------------------------------------------------------------
    def _add(self, cid: str, status: str, message: str, **evidence: Any) -> Result:
        r = Result(BY_ID[cid], status, message, evidence)
        self.results.append(r)
        return r

    def _skip(self, cid: str, why: str, applicable: bool = True, login: bool = False) -> None:
        r = self._add(cid, SKIP, why)
        r.applicable = applicable
        if login:
            r.evidence["needs_login"] = True

    def _get(self, cid: str) -> Result | None:
        return next((r for r in self.results if r.check.id == cid), None)

    def _post_initialize(self, headers: dict[str, str] | None = None, url: str | None = None) -> Response:
        return self.client.post_json(url or self.target, initialize_payload(), _mcp_headers(headers))

    # -- phases ------------------------------------------------------------------
    def run(self) -> list[Result]:
        self.results = []
        self._tls()
        unauth = self._challenge()
        self._protected_resource_metadata()
        self._authorization_servers()
        self._authorization_server_flow()
        self._token_probes(unauth)
        self._authenticated_probes()
        self._resolve_asf04()
        return self.results

    def _tls(self) -> None:
        scheme = urlsplit(self.target).scheme.lower()
        if scheme == "https":
            self._add("TLS-01", PASS, "https")
        elif discovery.is_loopback(self.target):
            self._add("TLS-01", WARN, "plain http on loopback (acceptable for local development only)")
        else:
            self._add("TLS-01", FAIL, f"scheme is {scheme!r}; bearer tokens would travel in the clear")

    def _challenge(self) -> Response | None:
        try:
            resp = self._post_initialize()
        except TransportError as e:
            self._add("CHAL-01", ERROR, f"the server didn't answer: {e}")
            for cid in ("CHAL-02", "CHAL-03"):
                self._skip(cid, "the server didn't respond")
            return None
        ev = _summ(resp)
        if resp.status == 401:
            self._add("CHAL-01", PASS, "401 Unauthorized", **ev)
        elif resp.status in (200, 202):
            self.open = True
            self._add(
                "CHAL-01",
                FAIL,
                "server answered an unauthenticated initialize; it's open or authorization is off",
                **ev,
            )
        elif resp.status == 403:
            self._add("CHAL-01", FAIL, "403 instead of 401: clients can't start the discovery flow from a 403", **ev)
        else:
            self._add("CHAL-01", FAIL, f"expected 401, got {resp.status}", **ev)

        values = resp.header_all("WWW-Authenticate")
        ch = wwwauth.bearer(values)
        self.challenge = ch
        if resp.status != 401:
            self._skip("CHAL-02", "the server didn't answer 401")
            self._skip("CHAL-03", "the server didn't answer 401")
            return resp
        if ch is None:
            self._add(
                "CHAL-02",
                FAIL,
                "the 401 doesn't carry a Bearer challenge, so clients can't find the authorization server",
                **ev,
            )
            self._skip("CHAL-03", "the 401 doesn't carry a Bearer challenge")
            return resp
        rm = ch.params.get("resource_metadata")
        if not rm:
            self._add("CHAL-02", FAIL, "Bearer challenge lacks resource_metadata", **ev)
        elif urlsplit(rm).scheme not in ("http", "https"):
            self._add("CHAL-02", FAIL, f"resource_metadata isn't an http(s) URL: {rm!r}", **ev)
        else:
            self._add("CHAL-02", PASS, f"resource_metadata={rm}", **ev)
        scope = ch.params.get("scope")
        if scope:
            self._add("CHAL-03", PASS, f"scope={scope!r}", **ev)
        else:
            self._add(
                "CHAL-03",
                WARN,
                "the 401 doesn't say which scopes to request, so clients fall back to scopes_supported "
                "or ask for a token without scopes",
                **ev,
            )
        return resp

    def _fetch_json(self, url: str, attempts: list[dict[str, Any]], **tag: Any) -> JsonDoc | None:
        try:
            resp = self.client.get(url, {"Accept": "application/json"})
        except TransportError as e:
            attempts.append({**tag, "url": url, "error": str(e)})
            return None
        attempts.append({**tag, "url": url, "status": resp.status, "content_type": resp.content_type})
        if resp.status != 200:
            return None
        try:
            doc = json.loads(resp.text)
        except ValueError:
            return None
        return doc if isinstance(doc, dict) else None

    def _protected_resource_metadata(self) -> None:
        candidates: list[str] = []
        advertised = self.challenge.params.get("resource_metadata") if self.challenge else None
        if advertised and urlsplit(advertised).scheme in ("http", "https"):
            candidates.append(advertised)
        for u in discovery.protected_resource_metadata_urls(self.canonical):
            if u not in candidates:
                candidates.append(u)
        fetched: dict[str, JsonDoc | None] = {}
        attempts: list[dict[str, Any]] = []
        for url in candidates:
            fetched[url] = self._fetch_json(url, attempts)

        wellknown = [u for u in discovery.protected_resource_metadata_urls(self.canonical) if fetched.get(u)]
        if wellknown:
            self.prm_url = wellknown[0]
            self.prm = fetched[self.prm_url]
            self._add("PRM-01", PASS, f"found at {self.prm_url}", attempts=attempts)
        elif advertised and fetched.get(advertised):
            self.prm_url = advertised
            self.prm = fetched[advertised]
            self._add(
                "PRM-01",
                FAIL,
                "metadata is only reachable through the challenge URL, not at the RFC 9728 well-known path; "
                "clients that start from the URL alone won't find it",
                attempts=attempts,
            )
        else:
            self._add(
                "PRM-01",
                FAIL,
                "couldn't find a Protected Resource Metadata document at the challenge URL or the well-known paths",
                attempts=attempts,
            )
            for cid in ("PRM-02", "PRM-03", "PRM-04", "PRM-05", "PRM-06"):
                self._skip(cid, "needs the Protected Resource Metadata document")
            return

        prm = self.prm or {}
        resource = prm.get("resource")
        sp = urlsplit(self.canonical)
        origin = discovery.canonical(f"{sp.scheme}://{sp.netloc}")
        served_at_root = (
            self.prm_url is not None and urlsplit(self.prm_url).path == "/.well-known/oauth-protected-resource"
        )
        if not isinstance(resource, str):
            self._add("PRM-02", FAIL, "'resource' missing from metadata", document=prm)
        elif discovery.canonical(resource) == self.canonical:
            self._add("PRM-02", PASS, f"resource={resource}", document=prm)
        elif served_at_root and discovery.canonical(resource) == origin:
            self._add(
                "PRM-02",
                PASS,
                f"resource={resource} (the origin; tokens are bound to the host rather than the endpoint path, "
                "which RFC 9728 section 3.3 permits for a root well-known document)",
                document=prm,
            )
        else:
            self._add(
                "PRM-02",
                FAIL,
                f"resource={resource!r} doesn't match the scanned URI {self.canonical!r}; "
                "clients MUST reject mismatched metadata (RFC 9728 section 3.3)",
                document=prm,
            )

        servers = prm.get("authorization_servers")
        if isinstance(servers, list) and servers and all(isinstance(s, str) and s for s in servers):
            self._add("PRM-03", PASS, ", ".join(servers))
        else:
            self._add("PRM-03", FAIL, "authorization_servers missing or empty", document=prm)

        if advertised:
            adv_doc = fetched.get(advertised)
            if adv_doc is None:
                self._add(
                    "PRM-04",
                    FAIL,
                    f"challenge pointed at {advertised} but it didn't return a JSON document",
                    attempts=attempts,
                )
            elif adv_doc == self.prm:
                self._add("PRM-04", PASS, "challenge URL and well-known document agree")
            else:
                self._add(
                    "PRM-04",
                    WARN,
                    "challenge URL returns a different document than the well-known path",
                    advertised=adv_doc,
                    wellknown=self.prm,
                )
        else:
            self._skip("PRM-04", "the challenge didn't advertise resource_metadata", applicable=False)

        scopes = prm.get("scopes_supported")
        if isinstance(scopes, list):
            bad = [
                s
                for s in scopes
                if isinstance(s, str)
                and (s.lower() in _WILDCARD_SCOPES or s == "offline_access" or s.endswith(":*") or s.endswith("/*"))
            ]
            if bad:
                self._add("PRM-05", WARN, f"over-broad or inappropriate scopes advertised: {bad}", scopes=scopes)
            else:
                self._add("PRM-05", PASS, f"{len(scopes)} scopes, all specific", scopes=scopes)
        else:
            self._add(
                "PRM-05",
                PASS,
                "scopes_supported isn't published, so clients wait for a challenge to learn what to request",
            )

        methods = prm.get("bearer_methods_supported")
        if isinstance(methods, list) and "query" in methods:
            self._add(
                "PRM-06",
                WARN,
                "bearer_methods_supported includes 'query'; MCP clients MUST NOT put tokens in the query string",
                methods=methods,
            )
        else:
            self._add("PRM-06", PASS, "bearer_methods_supported leaves out 'query'")

    def _authorization_servers(self) -> None:
        servers = (self.prm or {}).get("authorization_servers")
        if not (isinstance(servers, list) and servers):
            for cid in ("ASM-01", "ASM-02", "ASM-03", "ASM-04", "ASM-05", "ASM-06"):
                self._skip(cid, "the metadata doesn't list an authorization server")
            return
        # Grade on the worst server; report each.
        docs: list[tuple[str, str, JsonDoc]] = []
        failures: list[str] = []
        attempts_all: list[dict[str, Any]] = []
        for issuer in servers:
            if not isinstance(issuer, str):
                failures.append(f"{issuer!r} isn't a URL")
                continue
            found: tuple[str, str, JsonDoc] | None = None
            for kind, url in discovery.authorization_server_metadata_urls(issuer):
                doc = self._fetch_json(url, attempts_all, issuer=issuer)
                if doc is not None:
                    found = (kind, url, doc)
                    break
            if not found:
                failures.append(f"{issuer}: metadata isn't at any discovery location")
                continue
            _kind, url, doc = found
            missing = [f for f in _REQUIRED_AS_FIELDS if f not in doc]
            if missing:
                failures.append(f"{issuer}: metadata lacks {missing}")
            docs.append((issuer, url, doc))
        if failures:
            self._add("ASM-01", FAIL, "; ".join(failures), attempts=attempts_all)
        else:
            self._add("ASM-01", PASS, "; ".join(f"{i} via {u}" for i, u, _ in docs), attempts=attempts_all)
        if not docs:
            for cid in ("ASM-02", "ASM-03", "ASM-04", "ASM-05", "ASM-06"):
                self._skip(cid, "couldn't fetch authorization server metadata")
            return

        # RFC 8414 section 3.3: the issuer must be identical to the URL the metadata was discovered from.
        # Clients compare the strings exactly, so a trailing slash or a case difference fails here too.
        bad_iss = [f"{i}: issuer={d.get('issuer')!r}" for i, _, d in docs if d.get("issuer") != i]
        if bad_iss:
            self._add("ASM-02", FAIL, "issuer mismatch invites mix-up attacks: " + "; ".join(bad_iss))
        else:
            self._add("ASM-02", PASS, "issuer values match")

        insecure = []
        for _, _, d in docs:
            for key in _AS_ENDPOINT_KEYS:
                v = d.get(key)
                if isinstance(v, str) and not discovery.is_https_or_loopback(v):
                    insecure.append(f"{key}={v}")
        if insecure:
            self._add("ASM-03", FAIL, "non-HTTPS endpoints: " + ", ".join(insecure))
        else:
            self._add("ASM-03", PASS, "all endpoints HTTPS (or loopback)")

        no_pkce = [
            i
            for i, _, d in docs
            if not isinstance(d.get("code_challenge_methods_supported"), list)
            or "S256" not in d["code_challenge_methods_supported"]
        ]
        if no_pkce:
            self._add(
                "ASM-04",
                FAIL,
                "code_challenge_methods_supported lacks S256 for: "
                + ", ".join(no_pkce)
                + ". MCP clients refuse to proceed without it.",
            )
        else:
            self._add("ASM-04", PASS, "S256 advertised")

        reg: list[tuple[str, list[str]]] = []
        for i, _, d in docs:
            ways = []
            if d.get("registration_endpoint"):
                ways.append("dynamic registration")
            if d.get("client_id_metadata_document_supported") is True:
                ways.append("client ID metadata documents")
            reg.append((i, ways))
        none = [i for i, ways in reg if not ways]
        if none:
            self._add(
                "ASM-05",
                WARN,
                "clients have to be registered by hand for: "
                + ", ".join(none)
                + " (neither dynamic registration nor Client ID Metadata Documents is offered)",
            )
        else:
            self._add("ASM-05", PASS, "; ".join(f"{i}: {', '.join(w)}" for i, w in reg))

        no_iss = [i for i, _, d in docs if d.get("authorization_response_iss_parameter_supported") is not True]
        if no_iss:
            self._add(
                "ASM-06", WARN, "authorization_response_iss_parameter_supported isn't true for: " + ", ".join(no_iss)
            )
        else:
            self._add("ASM-06", PASS, "iss parameter supported")

    def _authorization_server_flow(self) -> None:
        """Report the ASF-* results recorded by `mcp-authlab login`, if there are any."""
        ids = [c.id for c in CATALOG if c.phase == LOGIN]
        if not self.login_results:
            for cid in ids:
                self._skip(cid, f"needs a login against this server's authorization server; {LOGIN_HINT}", login=True)
            return
        stored = {d["id"]: d for d in self.login_results if d.get("id") in BY_ID}
        for cid in ids:
            d = stored.get(cid)
            if d is None:
                self._skip(cid, "login didn't record a result for this check")
            else:
                self.results.append(Result.from_dict(d))

    def _token_probes(self, unauth: Response | None) -> None:
        if unauth is None or unauth.status in (200, 202):
            why = (
                "server is unreachable"
                if unauth is None
                else "server accepts unauthenticated requests, so a refused token can't be told apart"
            )
            for cid in ("TOK-01", "TOK-02", "TOK-03", "TOK-04"):
                self._skip(cid, why)
            return
        garbage = "authlab." + secrets.token_urlsafe(24)
        try:
            r: Response | None = self._post_initialize({"Authorization": f"Bearer {garbage}"})
        except TransportError as e:
            self._add("TOK-01", ERROR, str(e))
            r = None
        if r is not None:
            if r.status == 401:
                self._add("TOK-01", PASS, "401", **_summ(r))
            elif r.status in (200, 202):
                self._add("TOK-01", FAIL, "server accepted a random string as a bearer token", **_summ(r))
            else:
                self._add("TOK-01", FAIL, f"expected 401, got {r.status}", **_summ(r))
            ch = wwwauth.bearer(r.header_all("WWW-Authenticate"))
            if r.status != 401:
                self._skip("TOK-04", "no 401 to inspect")
            elif ch and ch.params.get("error") == "invalid_token":
                self._add("TOK-04", PASS, 'error="invalid_token" present', **_summ(r))
            else:
                self._add(
                    "TOK-04",
                    WARN,
                    '401 for a bad token doesn\'t say error="invalid_token", so '
                    "clients can't tell a missing token from a bad one",
                    **_summ(r),
                )

        unsigned = jwtutil.unsigned(self.canonical)
        try:
            r = self._post_initialize({"Authorization": f"Bearer {unsigned}"})
        except TransportError as e:
            self._add("TOK-02", ERROR, str(e))
        else:
            if r.status in (200, 202):
                self._add(
                    "TOK-02", FAIL, "server accepted an unsigned JWT, so it isn't validating tokens at all", **_summ(r)
                )
            elif r.status == 401:
                self._add("TOK-02", PASS, "401", **_summ(r))
            else:
                self._add("TOK-02", WARN, f"refused with {r.status} rather than 401", **_summ(r))

        if not self.foreign_token:
            if self.foreign_note:
                self._skip("TOK-03", self.foreign_note, login=self.foreign_note_needs_login)
            else:
                self._skip("TOK-03", f"needs a token minted for a different resource; {LOGIN_HINT}", login=True)
            return
        try:
            r = self._post_initialize({"Authorization": f"Bearer {self.foreign_token}"})
        except TransportError as e:
            self._add("TOK-03", ERROR, str(e))
            return
        if r.status in (200, 202) and self.foreign_audience_known:
            self._add(
                "TOK-03",
                FAIL,
                "server accepted a token issued for another resource, so it isn't checking the audience "
                "(token passthrough risk)",
                **_summ(r),
            )
        elif r.status in (200, 202):
            self._add(
                "TOK-03",
                WARN,
                "server accepted the second token. It's opaque, so this tool can't see whether the authorization "
                "server bound it to the other resource. Treat this as a likely audience failure and confirm with "
                "the authorization server's introspection endpoint or logs.",
                **_summ(r),
            )
        elif r.status == 401:
            self._add("TOK-03", PASS, "401", **_summ(r))
        else:
            self._add("TOK-03", WARN, f"refused with {r.status} rather than 401", **_summ(r))

    def _resolve_asf04(self) -> None:
        """ASF-04 for opaque tokens: login could not read aud, so use what the resource server did with each."""
        asf = self._get("ASF-04")
        tok3 = self._get("TOK-03")
        if asf is None or asf.status != SKIP or not asf.evidence.get("opaque") or tok3 is None:
            return
        if tok3.status in (SKIP, ERROR):
            return
        # Decide from what the resource server did, not from TOK-03's status: a 403 refusal is a WARN there.
        accepted = tok3.evidence.get("http_status") in (200, 202)
        if not accepted:
            asf.status = PASS
            asf.message = (
                "tokens are opaque, but the resource server told the two apart, so they were bound differently"
            )
        else:
            asf.status = WARN
            asf.message = (
                "tokens are opaque and the resource server accepted both; either the authorization server ignored "
                "resource= or the resource server skips audience checks"
            )

    def _authenticated_probes(self) -> None:
        needs = [c.id for c in CATALOG if c.needs_token]
        if not self.token:
            for cid in needs:
                self._skip(cid, f"needs a valid token; {LOGIN_HINT} or pass --token", login=True)
            return
        auth = {"Authorization": f"Bearer {self.token}"}
        try:
            r1 = self._post_initialize(auth)
        except TransportError as e:
            self._add("TOK-06", ERROR, str(e))
            for cid in needs:
                if cid != "TOK-06":
                    self._skip(cid, "initialize failed")
            return
        msg = _jsonrpc_result(r1)
        ok = r1.status == 200 and msg is not None and "result" in msg
        if ok:
            info = ((msg or {}).get("result") or {}).get("serverInfo")
            self._add("TOK-06", PASS, f"initialize succeeded; server={info}", **_summ(r1))
        else:
            self._add(
                "TOK-06",
                FAIL,
                f"initialize with the supplied token returned {r1.status}; check the token",
                **_summ(r1),
                body=r1.text[:500],
            )
            for cid in needs:
                if cid != "TOK-06":
                    self._skip(cid, "the token didn't work")
            return

        sid = r1.header("Mcp-Session-Id")
        self._scope_probe(auth, sid)

        # TOK-05: same token, query string only
        sep = "&" if "?" in self.target else "?"
        if self.open:
            self._skip("TOK-05", "server is open, so a 200 here wouldn't prove anything")
            rq = None
        else:
            try:
                rq = self._post_initialize(url=f"{self.target}{sep}access_token={quote(self.token, safe='')}")
            except TransportError as e:
                self._add("TOK-05", ERROR, str(e))
                rq = None
        if rq is not None:
            if rq.status in (200, 202):
                self._add(
                    "TOK-05",
                    FAIL,
                    "token accepted from the query string; it will leak into logs and referrers",
                    **_summ(rq),
                )
            else:
                self._add("TOK-05", PASS, f"{rq.status}", **_summ(rq))
            qsid = rq.header("Mcp-Session-Id")
            if qsid:
                self._end_session(qsid, auth)

        if not sid:
            self._skip("SESS-01", "server is stateless (it doesn't issue Mcp-Session-Id)", applicable=False)
            self._skip("SESS-02", "server is stateless (it doesn't issue Mcp-Session-Id)", applicable=False)
        else:
            self._session_probes(sid, auth)

        try:
            ro = self._post_initialize({**auth, "Origin": "https://attacker.example"})
        except TransportError as e:
            self._add("ORIG-01", ERROR, str(e))
        else:
            if ro.status in (200, 202):
                self._add(
                    "ORIG-01",
                    FAIL,
                    "request from an unknown Origin was served; a DNS-rebinding page could drive this server",
                    **_summ(ro),
                )
            else:
                self._add("ORIG-01", PASS, f"{ro.status}", **_summ(ro))
            osid = ro.header("Mcp-Session-Id")
            if osid:
                self._end_session(osid, auth)

        self._version_probe(auth)

    def _version_probe(self, auth: dict[str, str]) -> None:
        """VER-01. The spec requires the header on requests after initialize, so open a session the normal way
        and send a ping with an unsupported version. initialize itself negotiates the version in its body."""
        try:
            ri = self._post_initialize(auth)
            vsid = ri.header("Mcp-Session-Id")
            sess = {"Mcp-Session-Id": vsid} if vsid else {}
            self.client.post_json(
                self.target, _rpc("notifications/initialized", rid=None), _mcp_headers({**auth, **sess})
            )
            rv = self.client.post_json(
                self.target, _rpc("ping", rid=4), _mcp_headers({**auth, **sess, "MCP-Protocol-Version": "1999-01-01"})
            )
        except TransportError as e:
            self._add("VER-01", ERROR, str(e))
            return
        if rv.status == 400:
            self._add("VER-01", PASS, "400 for a ping after initialize", **_summ(rv))
        elif rv.status in (200, 202):
            self._add("VER-01", WARN, "server answered a ping with an unsupported MCP-Protocol-Version", **_summ(rv))
        else:
            self._add("VER-01", WARN, f"expected 400, got {rv.status}", **_summ(rv))
        if vsid:
            self._end_session(vsid, auth)

    def _session_probes(self, sid: str, auth: dict[str, str]) -> None:
        if self.open:
            self._skip("SESS-01", "server is open, so a 200 here wouldn't prove anything")
            rs = None
        else:
            # A live session, no token, and a request other than initialize: the common bug checks the token
            # on initialize and then trusts the session ID for everything after.
            try:
                rs = self.client.post_json(self.target, _rpc("tools/list"), _mcp_headers({"Mcp-Session-Id": sid}))
            except TransportError as e:
                self._add("SESS-01", ERROR, str(e))
                rs = None
        if rs is not None:
            if rs.status in (200, 202):
                self._add(
                    "SESS-01",
                    FAIL,
                    "a request carrying only the session ID, without a bearer token, was accepted; "
                    "anyone who learns the session ID is the user",
                    **_summ(rs),
                )
            elif rs.status in (401, 403):
                self._add("SESS-01", PASS, f"{rs.status} without a token even with a live session ID", **_summ(rs))
            else:
                self._add("SESS-01", WARN, f"refused with {rs.status} rather than 401", **_summ(rs))
        try:
            r2 = self._post_initialize(auth)
            sid2 = r2.header("Mcp-Session-Id")
        except TransportError:
            sid2 = None
        problems = []
        if len(sid) < 16:
            problems.append(f"only {len(sid)} characters")
        if not re.fullmatch(r"[\x21-\x7e]+", sid):
            problems.append("contains characters outside visible ASCII")
        if sid.isdigit():
            problems.append("purely numeric")
        if sid2 and sid2 == sid:
            problems.append("the same ID was issued to two separate initializations")
        if sid2 and sid.isdigit() and sid2.isdigit() and abs(int(sid2) - int(sid)) <= 2:
            problems.append("sequential")
        if problems:
            self._add("SESS-02", WARN, "; ".join(problems), length=len(sid))
        else:
            self._add("SESS-02", PASS, f"{len(sid)} visible-ASCII characters, distinct per session", length=len(sid))
        self._end_session(sid, auth)
        if sid2 and sid2 != sid:
            self._end_session(sid2, auth)

    def _pick_tool(self, tools: list[Any]) -> str | None:
        names: list[str] = [t["name"] for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)]
        if self.tool:
            return self.tool if self.tool in names else None
        for t in tools:
            if (
                isinstance(t, dict)
                and isinstance(t.get("annotations"), dict)
                and t["annotations"].get("readOnlyHint") is True
            ):
                name = t.get("name")
                if isinstance(name, str):
                    return name
        for name in names:
            if _READ_ONLY_NAME.match(name):
                return name
        return None

    def _scope_probe(self, auth: dict[str, str], sid: str | None) -> None:
        """SCOPE-01: list tools, call a read-only one, inspect any 403."""
        if self.open:
            self._skip("SCOPE-01", "server is open, so scopes don't apply", applicable=False)
            return
        sess = {"Mcp-Session-Id": sid} if sid else {}
        hdrs = _mcp_headers({**auth, **sess})
        try:
            self.client.post_json(self.target, _rpc("notifications/initialized", rid=None), hdrs)
            rl = self.client.post_json(self.target, _rpc("tools/list"), hdrs)
        except TransportError as e:
            self._add("SCOPE-01", ERROR, str(e))
            return
        listing = _jsonrpc_result(rl)
        tools = ((listing or {}).get("result") or {}).get("tools") if listing else None
        if rl.status != 200 or not isinstance(tools, list):
            self._skip("SCOPE-01", f"tools/list returned {rl.status}, so the probe can't pick a tool", applicable=False)
            return
        if not tools:
            self._skip("SCOPE-01", "the server's tools/list is empty", applicable=False)
            return
        name = self._pick_tool(tools)
        if name is None:
            self._skip(
                "SCOPE-01",
                "couldn't find a tool that's safe to call (one with readOnlyHint or a list/get/search name); "
                "pass --tool NAME to choose one",
            )
            return
        try:
            rc = self.client.post_json(self.target, _rpc("tools/call", {"name": name, "arguments": {}}, rid=3), hdrs)
        except TransportError as e:
            self._add("SCOPE-01", ERROR, str(e))
            return
        ev = {**_summ(rc), "tool": name}
        if rc.status in (200, 202):
            self._add(
                "SCOPE-01", PASS, f"calling {name!r} succeeded ({rc.status}); the token already had enough scope", **ev
            )
            return
        if rc.status != 403:
            self._add(
                "SCOPE-01",
                WARN,
                f"calling {name!r} with a valid token returned {rc.status}; expected 200 or a 403 step-up challenge",
                **ev,
            )
            return
        ch = wwwauth.bearer(rc.header_all("WWW-Authenticate"))
        missing = []
        if ch is None:
            missing.append("a Bearer challenge")
        else:
            if ch.params.get("error") != "insufficient_scope":
                missing.append('error="insufficient_scope"')
            if not ch.params.get("scope"):
                missing.append("a scope parameter")
            if not ch.params.get("resource_metadata"):
                missing.append("resource_metadata")
        if ch is None or missing:
            self._add(
                "SCOPE-01",
                WARN,
                f"403 for {name!r} lacks " + ", ".join(missing) + "; clients can't work out what to request",
                **ev,
            )
        else:
            self._add("SCOPE-01", PASS, f"403 for {name!r} asks for scope={ch.params.get('scope')!r}", **ev)

    def _end_session(self, sid: str, auth: dict[str, str]) -> None:
        with contextlib.suppress(TransportError):
            self.client.request(
                "DELETE", self.target, {**auth, "Mcp-Session-Id": sid, "MCP-Protocol-Version": PROTOCOL_VERSION}
            )


def build_report(
    scanner: Scanner, results: list[Result], policy: Policy | None = None, login: dict[str, Any] | None = None
) -> dict[str, Any]:
    if policy:
        policy.apply(results)
    g = grade(results)
    cov = coverage(results)
    cov["line"] = coverage_line(cov)
    report: dict[str, Any] = {
        "tool": "mcp-authlab",
        "version": __version__,
        "spec": SPEC_VERSION,
        "target": scanner.target,
        "canonical": scanner.canonical,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(scanner.started)),
        "coverage": cov,
        **g.to_dict(),
        "counts": {k: sum(1 for r in results if r.status == k) for k in (PASS, FAIL, WARN, SKIP, ERROR)},
        "policy": policy.to_dict() if policy else None,
        "login": login,
        "results": [r.to_dict() for r in results],
        "requests": [e.__dict__ for e in scanner.client.log],
    }
    return report


def run(
    target: str,
    token: str | None = None,
    foreign_token: str | None = None,
    timeout: float = 10.0,
    insecure: bool = False,
    policy: Policy | None = None,
    stored: dict[str, Any] | None = None,
    tool: str | None = None,
    client: Client | None = None,
) -> dict[str, Any]:
    """Scan `target`. `stored` is a token-store entry from `mcp-authlab login`; explicit tokens win over it."""
    login_meta: dict[str, Any] | None = None
    foreign_note = None
    foreign_expired = False
    foreign_known = True
    login_results = None
    if stored and not token:
        token = stored.get("access_token")
        login_results = stored.get("asf") or []
        foreign = stored.get("foreign") or {}
        login_meta = {
            "issuer": stored.get("issuer"),
            "client_id": stored.get("client_id"),
            "logged_in_at": stored.get("logged_in_at"),
            "foreign_resource": foreign.get("resource"),
        }
        if not foreign_token:
            if foreign.get("usable") is False:
                foreign_note = foreign.get("note") or "login didn't mint a usable foreign-audience token"
            elif tokenstore.is_expired(foreign, skew=0):
                # An expired token gets a 401 from any server, which would read as a pass on a critical check.
                foreign_note = "the foreign-audience token has expired and couldn't be refreshed"
                foreign_expired = True
            else:
                foreign_token = foreign.get("access_token")
                foreign_known = bool(foreign.get("audience_known", True))
    s = Scanner(
        target,
        token=token,
        foreign_token=foreign_token,
        timeout=timeout,
        insecure=insecure,
        client=client,
        foreign_note=foreign_note,
        foreign_audience_known=foreign_known,
        login_results=login_results,
        tool=tool,
    )
    s.foreign_note_needs_login = foreign_expired
    results = s.run()
    return build_report(s, results, policy, login_meta)
