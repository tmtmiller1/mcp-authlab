"""The check catalog and the scanner that runs it against a live MCP server.

Every check cites the normative text it enforces. Results carry the evidence
(status codes, headers, documents) so a finding can be verified by hand.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlsplit

from . import PROTOCOL_VERSION, SPEC_VERSION, __version__, discovery, jwtutil, wwwauth
from .httpclient import Client, Response, TransportError

AUTHZ = f"https://modelcontextprotocol.io/specification/{SPEC_VERSION}/basic/authorization"
BEST = f"https://modelcontextprotocol.io/specification/{SPEC_VERSION}/basic/security_best_practices"
TRANSPORT = f"https://modelcontextprotocol.io/specification/{SPEC_VERSION}/basic/transports"
DRAFT_AUTHZ = "https://modelcontextprotocol.io/specification/draft/basic/authorization"
RFC9728 = "https://www.rfc-editor.org/rfc/rfc9728"
RFC8414 = "https://www.rfc-editor.org/rfc/rfc8414"
RFC6750 = "https://www.rfc-editor.org/rfc/rfc6750"
RFC9207 = "https://www.rfc-editor.org/rfc/rfc9207"
OAUTH21 = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13"

PASS, FAIL, WARN, SKIP, ERROR = "pass", "fail", "warn", "skip", "error"


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    level: str  # MUST or SHOULD
    critical: bool  # a failure that makes the grade F on its own
    cite: str  # human-readable citation
    url: str
    needs_token: bool = False
    needs_foreign_token: bool = False

    @property
    def weight(self) -> int:
        return 20 if self.critical else (10 if self.level == "MUST" else 3)


@dataclass
class Result:
    check: Check
    status: str
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.check.id,
            "title": self.check.title,
            "level": self.check.level,
            "critical": self.check.critical,
            "status": self.status,
            "message": self.message,
            "cite": self.check.cite,
            "url": self.check.url,
            "evidence": self.evidence,
        }


CATALOG: list[Check] = [
    Check("TLS-01", "MCP endpoint is served over HTTPS", "MUST", False,
          "MCP Authorization, Communication Security; OAuth 2.1 section 1.5", f"{AUTHZ}#communication-security"),
    Check("CHAL-01", "Unauthenticated request is refused with 401", "MUST", False,
          "MCP Authorization, Error Handling; OAuth 2.1 section 5.3", f"{AUTHZ}#error-handling"),
    Check("CHAL-02", "401 carries WWW-Authenticate: Bearer with resource_metadata", "MUST", False,
          "MCP Authorization, Authorization Server Location; RFC 9728 section 5.1", f"{AUTHZ}#authorization-server-location"),
    Check("CHAL-03", "401 challenge names the scopes to request", "SHOULD", False,
          "MCP Authorization (draft), Scope Selection Strategy; RFC 6750 section 3", f"{DRAFT_AUTHZ}#scope-selection-strategy"),
    Check("PRM-01", "Protected Resource Metadata is published at the RFC 9728 well-known location", "MUST", False,
          "MCP Authorization, Overview item 3; RFC 9728 section 3", f"{AUTHZ}#overview"),
    Check("PRM-02", "Metadata 'resource' equals the server's canonical URI", "MUST", False,
          "RFC 9728 section 3.3; MCP Authorization, Canonical Server URI", f"{AUTHZ}#canonical-server-uri"),
    Check("PRM-03", "Metadata lists at least one authorization server", "MUST", False,
          "MCP Authorization, Authorization Server Location", f"{AUTHZ}#authorization-server-location"),
    Check("PRM-04", "resource_metadata URL in the challenge resolves to the same document", "SHOULD", False,
          "RFC 9728 section 5.1", f"{RFC9728}#section-5.1"),
    Check("PRM-05", "scopes_supported avoids wildcard, omnibus, and offline_access scopes", "SHOULD", False,
          "Security Best Practices, Scope Minimization; MCP Authorization (draft), Refresh Tokens", f"{BEST}#scope-minimization"),
    Check("PRM-06", "Metadata does not advertise bearer tokens in the query string", "SHOULD", False,
          "MCP Authorization, Token Requirements; RFC 6750 section 2.3", f"{AUTHZ}#token-requirements"),
    Check("ASM-01", "Each authorization server publishes discoverable metadata with the required fields", "MUST", False,
          "MCP Authorization, Overview item 4; RFC 8414 section 2 and 3", f"{AUTHZ}#server-metadata-discovery"),
    Check("ASM-02", "Authorization server 'issuer' matches the advertised URL", "MUST", False,
          "RFC 8414 section 3.3", f"{RFC8414}#section-3.3"),
    Check("ASM-03", "Authorization server endpoints use HTTPS", "MUST", False,
          "MCP Authorization, Communication Security; OAuth 2.1 section 1.5", f"{AUTHZ}#communication-security"),
    Check("ASM-04", "Authorization server advertises PKCE S256", "MUST", False,
          "MCP Authorization, Authorization Code Protection; OAuth 2.1 section 7.5.2", f"{AUTHZ}#authorization-code-protection"),
    Check("ASM-05", "A client registration path exists (dynamic registration or Client ID Metadata Documents)", "SHOULD", False,
          "MCP Authorization, Dynamic Client Registration; draft, Client Registration", f"{AUTHZ}#dynamic-client-registration"),
    Check("ASM-06", "Authorization server supports the RFC 9207 'iss' response parameter", "SHOULD", False,
          "MCP Authorization (draft), Authorization Response Validation", f"{DRAFT_AUTHZ}#authorization-response-validation"),
    Check("TOK-01", "Malformed bearer token is refused with 401", "MUST", False,
          "MCP Authorization, Token Handling; OAuth 2.1 section 5.2", f"{AUTHZ}#token-handling"),
    Check("TOK-02", "Unsigned (alg=none) token with the right audience is refused", "MUST", True,
          "MCP Authorization, Token Handling; Security Best Practices, Token Passthrough", f"{BEST}#token-passthrough"),
    Check("TOK-03", "Valid token issued for a different resource is refused (audience binding)", "MUST", True,
          "MCP Authorization, Access Token Privilege Restriction; RFC 8707 section 2", f"{AUTHZ}#access-token-privilege-restriction",
          needs_foreign_token=True),
    Check("TOK-04", "Invalid-token 401 carries error=\"invalid_token\"", "SHOULD", False,
          "RFC 6750 section 3.1", f"{RFC6750}#section-3.1"),
    Check("TOK-05", "Valid token in the query string is not accepted", "MUST", False,
          "MCP Authorization, Token Requirements", f"{AUTHZ}#token-requirements", needs_token=True),
    Check("TOK-06", "Valid token succeeds (initialize completes)", "MUST", False,
          "MCP Authorization, Access Token Usage", f"{AUTHZ}#access-token-usage", needs_token=True),
    Check("SESS-01", "Session ID does not substitute for authentication", "MUST", True,
          "Security Best Practices, Session Hijacking: servers MUST NOT use sessions for authentication", f"{BEST}#session-hijacking",
          needs_token=True),
    Check("SESS-02", "Session IDs are long, random, and non-sequential", "SHOULD", False,
          "Transports, Session Management; Security Best Practices, Session Hijacking", f"{TRANSPORT}#session-management",
          needs_token=True),
    Check("ORIG-01", "Request with a hostile Origin header is refused", "MUST", False,
          "Transports, Security Warning: servers MUST validate the Origin header", f"{TRANSPORT}#security-warning", needs_token=True),
    Check("VER-01", "Unsupported MCP-Protocol-Version is refused with 400", "MUST", False,
          "Transports, Protocol Version Header", f"{TRANSPORT}#protocol-version-header", needs_token=True),
]
BY_ID = {c.id: c for c in CATALOG}

_WILDCARD_SCOPES = {"*", "all", "full", "full-access", "full_access", "admin", "everything", "root", "superuser"}
_REQUIRED_AS_FIELDS = ("issuer", "authorization_endpoint", "token_endpoint", "response_types_supported")


def initialize_payload() -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-authlab", "version": __version__},
        },
    }).encode()


def _mcp_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    h = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": PROTOCOL_VERSION}
    if extra:
        h.update(extra)
    return h


def _jsonrpc_result(resp: Response) -> dict | None:
    """Pull the JSON-RPC message out of a JSON or SSE body, if there is one."""
    if resp.content_type == "text/event-stream":
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                try:
                    msg = json.loads(line[5:].strip())
                except ValueError:
                    continue
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
    ):
        self.target = target.strip()
        self.canonical = discovery.canonical(self.target)
        self.token = token
        self.foreign_token = foreign_token
        self.client = client or Client(timeout=timeout, insecure=insecure)
        self.results: list[Result] = []
        self.prm: dict | None = None
        self.prm_url: str | None = None
        self.challenge: wwwauth.Challenge | None = None
        self.open = False
        self.started = time.time()

    # -- helpers -----------------------------------------------------------------
    def _add(self, cid: str, status: str, message: str, **evidence: Any) -> Result:
        r = Result(BY_ID[cid], status, message, evidence)
        self.results.append(r)
        return r

    def _skip(self, cid: str, why: str) -> None:
        self._add(cid, SKIP, why)

    def _post_initialize(self, headers: dict[str, str] | None = None, url: str | None = None) -> Response:
        return self.client.post_json(url or self.target, initialize_payload(), _mcp_headers(headers))

    # -- phases ------------------------------------------------------------------
    def run(self) -> list[Result]:
        self.results = []
        self._tls()
        unauth = self._challenge()
        self._protected_resource_metadata()
        self._authorization_servers()
        self._token_probes(unauth)
        self._authenticated_probes()
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
            self._add("CHAL-01", ERROR, f"no HTTP response: {e}")
            for cid in ("CHAL-02", "CHAL-03"):
                self._skip(cid, "no response to inspect")
            return None
        ev = _summ(resp)
        if resp.status == 401:
            self._add("CHAL-01", PASS, "401 Unauthorized", **ev)
        elif resp.status in (200, 202):
            self.open = True
            self._add("CHAL-01", FAIL, "server answered an unauthenticated initialize; it is open or authorization is off", **ev)
        elif resp.status == 403:
            self._add("CHAL-01", FAIL, "403 instead of 401: clients cannot start the discovery flow from a 403", **ev)
        else:
            self._add("CHAL-01", FAIL, f"expected 401, got {resp.status}", **ev)

        values = resp.header_all("WWW-Authenticate")
        ch = wwwauth.bearer(values)
        self.challenge = ch
        if resp.status != 401:
            self._skip("CHAL-02", "no 401 to carry a challenge")
            self._skip("CHAL-03", "no 401 to carry a challenge")
            return resp
        if ch is None:
            self._add("CHAL-02", FAIL, "no Bearer challenge in WWW-Authenticate; clients cannot discover the authorization server", **ev)
            self._skip("CHAL-03", "no Bearer challenge")
            return resp
        rm = ch.params.get("resource_metadata")
        if not rm:
            self._add("CHAL-02", FAIL, "Bearer challenge lacks resource_metadata", **ev)
        elif urlsplit(rm).scheme not in ("http", "https"):
            self._add("CHAL-02", FAIL, f"resource_metadata is not an http(s) URL: {rm!r}", **ev)
        else:
            self._add("CHAL-02", PASS, f"resource_metadata={rm}", **ev)
        scope = ch.params.get("scope")
        if scope:
            self._add("CHAL-03", PASS, f"scope={scope!r}", **ev)
        else:
            self._add("CHAL-03", WARN, "no scope parameter; clients fall back to scopes_supported or request nothing", **ev)
        return resp

    def _protected_resource_metadata(self) -> None:
        candidates: list[str] = []
        advertised = self.challenge.params.get("resource_metadata") if self.challenge else None
        if advertised and urlsplit(advertised).scheme in ("http", "https"):
            candidates.append(advertised)
        for u in discovery.protected_resource_metadata_urls(self.canonical):
            if u not in candidates:
                candidates.append(u)
        fetched: dict[str, dict | None] = {}
        attempts: list[dict[str, Any]] = []
        for url in candidates:
            try:
                resp = self.client.get(url, {"Accept": "application/json"})
            except TransportError as e:
                attempts.append({"url": url, "error": str(e)})
                fetched[url] = None
                continue
            attempts.append({"url": url, "status": resp.status, "content_type": resp.content_type})
            doc = None
            if resp.status == 200:
                try:
                    doc = json.loads(resp.text)
                except ValueError:
                    doc = None
            fetched[url] = doc if isinstance(doc, dict) else None

        wellknown = [u for u in discovery.protected_resource_metadata_urls(self.canonical) if fetched.get(u)]
        if wellknown:
            self.prm_url = wellknown[0]
            self.prm = fetched[self.prm_url]
            self._add("PRM-01", PASS, f"found at {self.prm_url}", attempts=attempts)
        elif advertised and fetched.get(advertised):
            self.prm_url = advertised
            self.prm = fetched[advertised]
            self._add("PRM-01", FAIL, "metadata is only reachable through the challenge URL, not at the RFC 9728 well-known path; clients that start from the URL alone will not find it", attempts=attempts)
        else:
            self._add("PRM-01", FAIL, "no Protected Resource Metadata document found", attempts=attempts)
            for cid in ("PRM-02", "PRM-03", "PRM-04", "PRM-05", "PRM-06"):
                self._skip(cid, "no metadata document")
            return

        prm = self.prm or {}
        resource = prm.get("resource")
        sp = urlsplit(self.canonical)
        origin = discovery.canonical(f"{sp.scheme}://{sp.netloc}")
        served_at_root = self.prm_url is not None and urlsplit(self.prm_url).path == "/.well-known/oauth-protected-resource"
        if not isinstance(resource, str):
            self._add("PRM-02", FAIL, "'resource' missing from metadata", document=prm)
        elif discovery.canonical(resource) == self.canonical:
            self._add("PRM-02", PASS, f"resource={resource}", document=prm)
        elif served_at_root and discovery.canonical(resource) == origin:
            self._add("PRM-02", PASS, f"resource={resource} (the origin; tokens are bound to the host rather than the endpoint path, which RFC 9728 section 3.3 permits for a root well-known document)", document=prm)
        else:
            self._add("PRM-02", FAIL, f"resource={resource!r} does not match the scanned URI {self.canonical!r}; clients MUST reject mismatched metadata (RFC 9728 section 3.3)", document=prm)

        servers = prm.get("authorization_servers")
        if isinstance(servers, list) and servers and all(isinstance(s, str) and s for s in servers):
            self._add("PRM-03", PASS, ", ".join(servers))
        else:
            self._add("PRM-03", FAIL, "authorization_servers missing or empty", document=prm)

        if advertised:
            adv_doc = fetched.get(advertised)
            if adv_doc is None:
                self._add("PRM-04", FAIL, f"challenge pointed at {advertised} but it did not return a JSON document", attempts=attempts)
            elif adv_doc == self.prm:
                self._add("PRM-04", PASS, "challenge URL and well-known document agree")
            else:
                self._add("PRM-04", WARN, "challenge URL returns a different document than the well-known path", advertised=adv_doc, wellknown=self.prm)
        else:
            self._skip("PRM-04", "challenge did not advertise resource_metadata")

        scopes = prm.get("scopes_supported")
        if isinstance(scopes, list):
            bad = [s for s in scopes if isinstance(s, str) and (s.lower() in _WILDCARD_SCOPES or s == "offline_access" or s.endswith(":*") or s.endswith("/*"))]
            if bad:
                self._add("PRM-05", WARN, f"over-broad or inappropriate scopes advertised: {bad}", scopes=scopes)
            else:
                self._add("PRM-05", PASS, f"{len(scopes)} scopes, none over-broad", scopes=scopes)
        else:
            self._add("PRM-05", PASS, "scopes_supported not published (clients request nothing until challenged)")

        methods = prm.get("bearer_methods_supported")
        if isinstance(methods, list) and "query" in methods:
            self._add("PRM-06", WARN, "bearer_methods_supported includes 'query'; MCP clients MUST NOT put tokens in the query string", methods=methods)
        else:
            self._add("PRM-06", PASS, "no query-string bearer method advertised")

    def _authorization_servers(self) -> None:
        servers = (self.prm or {}).get("authorization_servers")
        if not (isinstance(servers, list) and servers):
            for cid in ("ASM-01", "ASM-02", "ASM-03", "ASM-04", "ASM-05", "ASM-06"):
                self._skip(cid, "no authorization servers to inspect")
            return
        # Grade on the worst server; report each.
        docs: list[tuple[str, str, dict]] = []
        failures: list[str] = []
        attempts_all: list[dict[str, Any]] = []
        for issuer in servers:
            if not isinstance(issuer, str):
                failures.append(f"{issuer!r} is not a URL")
                continue
            found = None
            for kind, url in discovery.authorization_server_metadata_urls(issuer):
                try:
                    resp = self.client.get(url, {"Accept": "application/json"})
                except TransportError as e:
                    attempts_all.append({"issuer": issuer, "url": url, "error": str(e)})
                    continue
                attempts_all.append({"issuer": issuer, "url": url, "status": resp.status})
                if resp.status == 200:
                    try:
                        doc = json.loads(resp.text)
                    except ValueError:
                        continue
                    if isinstance(doc, dict):
                        found = (kind, url, doc)
                        break
            if not found:
                failures.append(f"{issuer}: no metadata at any discovery location")
                continue
            kind, url, doc = found
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
                self._skip(cid, "no authorization server metadata to inspect")
            return

        bad_iss = [f"{i}: issuer={d.get('issuer')!r}" for i, _, d in docs if discovery.canonical(str(d.get("issuer", ""))) != discovery.canonical(i)]
        if bad_iss:
            self._add("ASM-02", FAIL, "issuer mismatch invites mix-up attacks: " + "; ".join(bad_iss))
        else:
            self._add("ASM-02", PASS, "issuer values match")

        insecure = []
        for i, _, d in docs:
            for key in ("authorization_endpoint", "token_endpoint", "registration_endpoint", "jwks_uri", "introspection_endpoint", "revocation_endpoint"):
                v = d.get(key)
                if isinstance(v, str) and urlsplit(v).scheme.lower() != "https" and not discovery.is_loopback(v):
                    insecure.append(f"{key}={v}")
        if insecure:
            self._add("ASM-03", FAIL, "non-HTTPS endpoints: " + ", ".join(insecure))
        else:
            self._add("ASM-03", PASS, "all endpoints HTTPS (or loopback)")

        no_pkce = [i for i, _, d in docs if "S256" not in (d.get("code_challenge_methods_supported") or [])]
        if no_pkce:
            self._add("ASM-04", FAIL, "code_challenge_methods_supported lacks S256 for: " + ", ".join(no_pkce) + ". MCP clients refuse to proceed without it.")
        else:
            self._add("ASM-04", PASS, "S256 advertised")

        reg = []
        for i, _, d in docs:
            ways = []
            if d.get("registration_endpoint"):
                ways.append("dynamic registration")
            if d.get("client_id_metadata_document_supported") is True:
                ways.append("client ID metadata documents")
            reg.append((i, ways))
        none = [i for i, ways in reg if not ways]
        if none:
            self._add("ASM-05", WARN, "no automatic client registration path for: " + ", ".join(none) + "; every client needs a pre-registered client_id")
        else:
            self._add("ASM-05", PASS, "; ".join(f"{i}: {', '.join(w)}" for i, w in reg))

        no_iss = [i for i, _, d in docs if d.get("authorization_response_iss_parameter_supported") is not True]
        if no_iss:
            self._add("ASM-06", WARN, "authorization_response_iss_parameter_supported is not true for: " + ", ".join(no_iss))
        else:
            self._add("ASM-06", PASS, "iss parameter supported")

    def _token_probes(self, unauth: Response | None) -> None:
        if unauth is None or unauth.status in (200, 202):
            why = "server is unreachable" if unauth is None else "server accepts unauthenticated requests, so token rejection cannot be observed"
            for cid in ("TOK-01", "TOK-02", "TOK-03", "TOK-04"):
                self._skip(cid, why)
            return
        garbage = "authlab." + secrets.token_urlsafe(24)
        try:
            r = self._post_initialize({"Authorization": f"Bearer {garbage}"})
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
                self._add("TOK-04", PASS, "error=\"invalid_token\" present", **_summ(r))
            else:
                self._add("TOK-04", WARN, "401 for a bad token does not say error=\"invalid_token\"; clients cannot tell 'no token' from 'bad token'", **_summ(r))

        unsigned = jwtutil.unsigned(self.canonical)
        try:
            r = self._post_initialize({"Authorization": f"Bearer {unsigned}"})
        except TransportError as e:
            self._add("TOK-02", ERROR, str(e))
        else:
            if r.status in (200, 202):
                self._add("TOK-02", FAIL, "server accepted an unsigned JWT: it is not validating tokens at all", **_summ(r))
            elif r.status == 401:
                self._add("TOK-02", PASS, "401", **_summ(r))
            else:
                self._add("TOK-02", WARN, f"refused with {r.status} rather than 401", **_summ(r))

        if not self.foreign_token:
            self._skip("TOK-03", "needs --foreign-token: a real token from the same authorization server minted for a different resource")
        else:
            try:
                r = self._post_initialize({"Authorization": f"Bearer {self.foreign_token}"})
            except TransportError as e:
                self._add("TOK-03", ERROR, str(e))
            else:
                if r.status in (200, 202):
                    self._add("TOK-03", FAIL, "server accepted a token issued for another resource: audience is not validated (token passthrough risk)", **_summ(r))
                elif r.status == 401:
                    self._add("TOK-03", PASS, "401", **_summ(r))
                else:
                    self._add("TOK-03", WARN, f"refused with {r.status} rather than 401", **_summ(r))

    def _authenticated_probes(self) -> None:
        needs = [c.id for c in CATALOG if c.needs_token]
        if not self.token:
            for cid in needs:
                self._skip(cid, "needs --token")
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
            self._add("TOK-06", PASS, f"initialize succeeded; server={((msg or {}).get('result') or {}).get('serverInfo')}", **_summ(r1))
        else:
            self._add("TOK-06", FAIL, f"initialize with the supplied token returned {r1.status}; check the token", **_summ(r1), body=r1.text[:500])
            for cid in needs:
                if cid != "TOK-06":
                    self._skip(cid, "token did not work")
            return

        # TOK-05: same token, query string only
        sep = "&" if "?" in self.target else "?"
        if self.open:
            self._skip("TOK-05", "server is open; acceptance proves nothing")
            rq = None
        else:
            try:
                rq = self._post_initialize(url=f"{self.target}{sep}access_token={self.token}")
            except TransportError as e:
                self._add("TOK-05", ERROR, str(e))
                rq = None
        if rq is not None:
            if rq.status in (200, 202):
                self._add("TOK-05", FAIL, "token accepted from the query string; it will leak into logs and referrers", **_summ(rq))
            else:
                self._add("TOK-05", PASS, f"{rq.status}", **_summ(rq))

        sid = r1.header("Mcp-Session-Id")
        if not sid:
            self._skip("SESS-01", "server is stateless (no Mcp-Session-Id)")
            self._skip("SESS-02", "server is stateless (no Mcp-Session-Id)")
        else:
            if self.open:
                self._skip("SESS-01", "server is open; acceptance proves nothing")
                rs = None
            else:
                try:
                    rs = self._post_initialize({"Mcp-Session-Id": sid})
                except TransportError as e:
                    self._add("SESS-01", ERROR, str(e))
                    rs = None
            if rs is not None:
                if rs.status in (200, 202):
                    self._add("SESS-01", FAIL, "a request carrying only the session ID (no bearer token) was accepted; anyone who learns the session ID is the user", **_summ(rs))
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

        try:
            ro = self._post_initialize({**auth, "Origin": "https://attacker.example"})
        except TransportError as e:
            self._add("ORIG-01", ERROR, str(e))
        else:
            if ro.status in (200, 202):
                self._add("ORIG-01", FAIL, "request from an unknown Origin was served; a DNS-rebinding page could drive this server", **_summ(ro))
            else:
                self._add("ORIG-01", PASS, f"{ro.status}", **_summ(ro))
            osid = ro.header("Mcp-Session-Id")
            if osid:
                self._end_session(osid, auth)

        try:
            rv = self._post_initialize({**auth, "MCP-Protocol-Version": "1999-01-01"})
        except TransportError as e:
            self._add("VER-01", ERROR, str(e))
        else:
            if rv.status == 400:
                self._add("VER-01", PASS, "400", **_summ(rv))
            elif rv.status in (200, 202):
                self._add("VER-01", WARN, "server ignored an unsupported MCP-Protocol-Version", **_summ(rv))
            else:
                self._add("VER-01", WARN, f"expected 400, got {rv.status}", **_summ(rv))
            vsid = rv.header("Mcp-Session-Id")
            if vsid:
                self._end_session(vsid, auth)

    def _end_session(self, sid: str, auth: dict[str, str]) -> None:
        try:
            self.client.request("DELETE", self.target, {**auth, "Mcp-Session-Id": sid, "MCP-Protocol-Version": PROTOCOL_VERSION})
        except TransportError:
            pass


# -- grading ---------------------------------------------------------------------

def grade(results: list[Result]) -> tuple[str, int, list[str]]:
    """Return (letter, score 0-100, reasons). Skips and errors are left out of the denominator."""
    applicable = [r for r in results if r.status in (PASS, FAIL, WARN)]
    total = sum(r.check.weight for r in applicable)
    earned = sum(r.check.weight for r in applicable if r.status == PASS)
    earned += sum(r.check.weight // 2 for r in applicable if r.status == WARN and r.check.level == "MUST")
    score = round(100 * earned / total) if total else 0
    reasons: list[str] = []
    critical = [r for r in applicable if r.status == FAIL and r.check.critical]
    must = [r for r in applicable if r.status == FAIL and r.check.level == "MUST"]
    if critical:
        reasons.append("critical failure: " + ", ".join(r.check.id for r in critical))
        return "F", score, reasons
    chal = next((r for r in results if r.check.id == "CHAL-01"), None)
    if chal and chal.status == FAIL:
        reasons.append("server does not challenge unauthenticated requests")
        return "F", score, reasons
    if must:
        reasons.append("MUST failures: " + ", ".join(r.check.id for r in must))
        letter = "C" if score >= 70 else ("D" if score >= 50 else "F")
        return letter, score, reasons
    if score >= 95:
        letter = "A"
    elif score >= 85:
        letter = "B"
    elif score >= 70:
        letter = "C"
    elif score >= 50:
        letter = "D"
    else:
        letter = "F"
    warns = [r.check.id for r in applicable if r.status == WARN]
    if warns:
        reasons.append("warnings: " + ", ".join(warns))
    return letter, score, reasons


GRADE_ORDER = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}


def run(target: str, **kw: Any) -> dict[str, Any]:
    s = Scanner(target, **kw)
    results = s.run()
    letter, score, reasons = grade(results)
    return {
        "tool": "mcp-authlab",
        "version": __version__,
        "spec": SPEC_VERSION,
        "target": s.target,
        "canonical": s.canonical,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(s.started)),
        "grade": letter,
        "score": score,
        "reasons": reasons,
        "counts": {k: sum(1 for r in results if r.status == k) for k in (PASS, FAIL, WARN, SKIP, ERROR)},
        "results": [r.to_dict() for r in results],
        "requests": [e.__dict__ for e in s.client.log],
    }
