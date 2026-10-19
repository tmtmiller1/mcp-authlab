"""The check catalog: every check with the normative text it enforces.

Weights and grade thresholds live in grading.py, so a check here only says
what level the spec gives it and whether a failure is critical.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import SPEC_VERSION

AUTHZ = f"https://modelcontextprotocol.io/specification/{SPEC_VERSION}/basic/authorization"
BEST = f"https://modelcontextprotocol.io/specification/{SPEC_VERSION}/basic/security_best_practices"
TRANSPORT = f"https://modelcontextprotocol.io/specification/{SPEC_VERSION}/basic/transports"
DRAFT_AUTHZ = "https://modelcontextprotocol.io/specification/draft/basic/authorization"
RFC9728 = "https://www.rfc-editor.org/rfc/rfc9728"
RFC8414 = "https://www.rfc-editor.org/rfc/rfc8414"
RFC6750 = "https://www.rfc-editor.org/rfc/rfc6750"
RFC9207 = "https://www.rfc-editor.org/rfc/rfc9207"
RFC8707 = "https://www.rfc-editor.org/rfc/rfc8707"
RFC7636 = "https://www.rfc-editor.org/rfc/rfc7636"
OAUTH21 = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13"

PASS, FAIL, WARN, SKIP, ERROR = "pass", "fail", "warn", "skip", "error"
STATUSES = (PASS, FAIL, WARN, SKIP, ERROR)

# How a check gets its evidence. "scan" checks run against the resource server;
# "login" checks run during `mcp-authlab login` against the authorization server
# and are stored with the tokens, so a later scan can report them.
SCAN, LOGIN = "scan", "login"

GROUPS: list[tuple[str, str]] = [
    ("TLS", "Transport"),
    ("CHAL", "Challenge"),
    ("PRM", "Protected Resource Metadata"),
    ("ASM", "Authorization Server Metadata"),
    ("ASF", "Authorization server flow"),
    ("TOK", "Token validation"),
    ("SCOPE", "Scope step-up"),
    ("SESS", "Sessions"),
    ("ORIG", "Origin"),
    ("VER", "Protocol version"),
]


@dataclass(frozen=True, kw_only=True)
class Check:
    id: str
    title: str
    level: str  # MUST or SHOULD
    critical: bool  # a failure that makes the grade F on its own
    cite: str  # human-readable citation
    url: str
    needs_token: bool = False
    needs_foreign_token: bool = False
    phase: str = SCAN
    disputed: str | None = None  # why operators push back, when the spec and the field disagree

    @property
    def group(self) -> str:
        return self.id.split("-")[0]


@dataclass
class Result:
    check: Check
    status: str
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)
    applicable: bool = (
        True  # False when the server lacks the feature the check tests (a stateless server has no sessions)
    )
    effective_level: str | None = None  # set by a policy downgrade
    counted: bool = True  # False when a policy ignores the check

    @property
    def level(self) -> str:
        return self.effective_level or self.check.level

    @property
    def critical(self) -> bool:
        return self.check.critical and self.effective_level is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.check.id,
            "title": self.check.title,
            "level": self.check.level,
            "critical": self.check.critical,
            "effective_level": self.level,
            "effective_critical": self.critical,
            "counted": self.counted,
            "applicable": self.applicable,
            "phase": self.check.phase,
            "status": self.status,
            "message": self.message,
            "cite": self.check.cite,
            "url": self.check.url,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Result:
        return cls(BY_ID[d["id"]], d["status"], d["message"], dict(d.get("evidence") or {}), d.get("applicable", True))


_ORIG_DISPUTE = (
    "The transports spec says servers MUST validate Origin to stop DNS rebinding. Operators point out that "
    "non-browser clients don't send Origin, so a server that only checks Origin when it's present is also "
    "defending the browser case. This check sends a hostile Origin, so a server that validates when present "
    "still passes; the pushback is from operators who skip the header entirely because their clients are CLIs."
)
_VER_DISPUTE = (
    "The transports spec says a server MUST respond 400 when a request after initialize carries an unsupported "
    "MCP-Protocol-Version. Operators "
    "prefer to answer with the newest version they support so older clients keep working. The spec text is "
    "clear, so this stays MUST; use a policy downgrade if your organisation accepts version tolerance."
)

CATALOG: list[Check] = [
    Check(
        id="TLS-01",
        title="MCP endpoint is served over HTTPS",
        level="MUST",
        critical=False,
        cite="MCP Authorization, Communication Security; OAuth 2.1 section 1.5",
        url=f"{AUTHZ}#communication-security",
    ),
    Check(
        id="CHAL-01",
        title="Unauthenticated request is refused with 401",
        level="MUST",
        critical=False,
        cite="MCP Authorization, Error Handling; OAuth 2.1 section 5.3",
        url=f"{AUTHZ}#error-handling",
    ),
    Check(
        id="CHAL-02",
        title="401 carries WWW-Authenticate: Bearer with resource_metadata",
        level="MUST",
        critical=False,
        cite="MCP Authorization, Authorization Server Location; RFC 9728 section 5.1",
        url=f"{AUTHZ}#authorization-server-location",
    ),
    Check(
        id="CHAL-03",
        title="401 challenge names the scopes to request",
        level="SHOULD",
        critical=False,
        cite="MCP Authorization (draft), Scope Selection Strategy; RFC 6750 section 3",
        url=f"{DRAFT_AUTHZ}#scope-selection-strategy",
    ),
    Check(
        id="PRM-01",
        title="Protected Resource Metadata is published at the RFC 9728 well-known location",
        level="MUST",
        critical=False,
        cite="MCP Authorization, Overview item 3; RFC 9728 section 3",
        url=f"{AUTHZ}#overview",
    ),
    Check(
        id="PRM-02",
        title="Metadata 'resource' equals the server's canonical URI",
        level="MUST",
        critical=False,
        cite="RFC 9728 section 3.3; MCP Authorization, Canonical Server URI",
        url=f"{AUTHZ}#canonical-server-uri",
    ),
    Check(
        id="PRM-03",
        title="Metadata lists at least one authorization server",
        level="MUST",
        critical=False,
        cite="MCP Authorization, Authorization Server Location",
        url=f"{AUTHZ}#authorization-server-location",
    ),
    Check(
        id="PRM-04",
        title="resource_metadata URL in the challenge resolves to the same document",
        level="SHOULD",
        critical=False,
        cite="RFC 9728 section 5.1",
        url=f"{RFC9728}#section-5.1",
    ),
    Check(
        id="PRM-05",
        title="scopes_supported avoids wildcard, omnibus, and offline_access scopes",
        level="SHOULD",
        critical=False,
        cite="Security Best Practices, Scope Minimization; MCP Authorization (draft), Refresh Tokens",
        url=f"{BEST}#scope-minimization",
    ),
    Check(
        id="PRM-06",
        title="Metadata keeps bearer tokens out of the query string",
        level="SHOULD",
        critical=False,
        cite="MCP Authorization, Token Requirements; RFC 6750 section 2.3",
        url=f"{AUTHZ}#token-requirements",
    ),
    Check(
        id="ASM-01",
        title="Each authorization server publishes discoverable metadata with the required fields",
        level="MUST",
        critical=False,
        cite="MCP Authorization, Overview item 4; RFC 8414 section 2 and 3",
        url=f"{AUTHZ}#server-metadata-discovery",
    ),
    Check(
        id="ASM-02",
        title="Authorization server 'issuer' matches the advertised URL",
        level="MUST",
        critical=False,
        cite="RFC 8414 section 3.3",
        url=f"{RFC8414}#section-3.3",
    ),
    Check(
        id="ASM-03",
        title="Authorization server endpoints use HTTPS",
        level="MUST",
        critical=False,
        cite="MCP Authorization, Communication Security; OAuth 2.1 section 1.5",
        url=f"{AUTHZ}#communication-security",
    ),
    Check(
        id="ASM-04",
        title="Authorization server advertises PKCE S256",
        level="MUST",
        critical=False,
        cite="MCP Authorization, Authorization Code Protection; OAuth 2.1 section 7.5.2",
        url=f"{AUTHZ}#authorization-code-protection",
    ),
    Check(
        id="ASM-05",
        title="A client registration path exists (dynamic registration or Client ID Metadata Documents)",
        level="SHOULD",
        critical=False,
        cite="MCP Authorization, Dynamic Client Registration; draft, Client Registration",
        url=f"{AUTHZ}#dynamic-client-registration",
    ),
    Check(
        id="ASM-06",
        title="Authorization server supports the RFC 9207 'iss' response parameter",
        level="SHOULD",
        critical=False,
        cite="MCP Authorization (draft), Authorization Response Validation",
        url=f"{DRAFT_AUTHZ}#authorization-response-validation",
    ),
    Check(
        id="ASF-01",
        title="Authorization endpoint refuses a request without code_challenge",
        level="MUST",
        critical=False,
        cite="MCP Authorization, Authorization Code Protection; OAuth 2.1 section 7.5.2; RFC 7636 section 4.4.1",
        url=f"{AUTHZ}#authorization-code-protection",
        phase=LOGIN,
    ),
    Check(
        id="ASF-02",
        title="Token endpoint refuses a wrong code_verifier",
        level="MUST",
        critical=False,
        cite="OAuth 2.1 section 4.1.3; RFC 7636 section 4.6",
        url=f"{RFC7636}#section-4.6",
        phase=LOGIN,
    ),
    Check(
        id="ASF-03",
        title="Token endpoint refuses a redirect_uri that differs from the authorization request",
        level="MUST",
        critical=False,
        cite="OAuth 2.1 section 4.1.3; RFC 6749 section 4.1.3",
        url=f"{OAUTH21}#section-4.1.3",
        phase=LOGIN,
    ),
    Check(
        id="ASF-04",
        title="Issued access token is bound to the requested resource",
        level="MUST",
        critical=False,
        cite="MCP Authorization, Resource Parameter Implementation; RFC 8707 section 2",
        url=f"{AUTHZ}#resource-parameter-implementation",
        phase=LOGIN,
    ),
    Check(
        id="ASF-05",
        title="Refresh tokens rotate for a public client",
        level="SHOULD",
        critical=False,
        cite="OAuth 2.1 section 4.3.1: refresh tokens for public clients are sender-constrained or rotate",
        url=f"{OAUTH21}#section-4.3.1",
        phase=LOGIN,
    ),
    Check(
        id="ASF-06",
        title="Authorization server URLs are HTTPS and the callback carried iss when advertised",
        level="MUST",
        critical=False,
        cite="MCP Authorization, Communication Security; RFC 9207 section 2",
        url=f"{RFC9207}#section-2",
        phase=LOGIN,
    ),
    Check(
        id="TOK-01",
        title="Malformed bearer token is refused with 401",
        level="MUST",
        critical=False,
        cite="MCP Authorization, Token Handling; OAuth 2.1 section 5.2",
        url=f"{AUTHZ}#token-handling",
    ),
    Check(
        id="TOK-02",
        title="Unsigned (alg=none) token with the right audience is refused",
        level="MUST",
        critical=True,
        cite="MCP Authorization, Token Handling; Security Best Practices, Token Passthrough",
        url=f"{BEST}#token-passthrough",
    ),
    Check(
        id="TOK-03",
        title="Valid token issued for a different resource is refused (audience binding)",
        level="MUST",
        critical=True,
        cite="MCP Authorization, Access Token Privilege Restriction; RFC 8707 section 2",
        url=f"{AUTHZ}#access-token-privilege-restriction",
        needs_foreign_token=True,
    ),
    Check(
        id="TOK-04",
        title='Invalid-token 401 carries error="invalid_token"',
        level="SHOULD",
        critical=False,
        cite="RFC 6750 section 3.1",
        url=f"{RFC6750}#section-3.1",
    ),
    Check(
        id="TOK-05",
        title="A valid token in the query string is refused",
        level="MUST",
        critical=False,
        cite="MCP Authorization, Token Requirements",
        url=f"{AUTHZ}#token-requirements",
        needs_token=True,
    ),
    Check(
        id="TOK-06",
        title="Valid token succeeds (initialize completes)",
        level="MUST",
        critical=False,
        cite="MCP Authorization, Access Token Usage",
        url=f"{AUTHZ}#access-token-usage",
        needs_token=True,
    ),
    Check(
        id="SCOPE-01",
        title='A tool call the token can\'t make gets 403 with error="insufficient_scope" and a scope hint',
        level="SHOULD",
        critical=False,
        cite="MCP Authorization (draft), Scope Selection Strategy; RFC 6750 section 3.1",
        url=f"{DRAFT_AUTHZ}#scope-selection-strategy",
        needs_token=True,
    ),
    Check(
        id="SESS-01",
        title="A session ID alone doesn't authenticate",
        level="MUST",
        critical=True,
        cite="Security Best Practices, Session Hijacking: servers MUST NOT use sessions for authentication",
        url=f"{BEST}#session-hijacking",
        needs_token=True,
    ),
    Check(
        id="SESS-02",
        title="Session IDs are long, random, and non-sequential",
        level="SHOULD",
        critical=False,
        cite="Transports, Session Management; Security Best Practices, Session Hijacking",
        url=f"{TRANSPORT}#session-management",
        needs_token=True,
    ),
    Check(
        id="ORIG-01",
        title="Request with a hostile Origin header is refused",
        level="MUST",
        critical=False,
        cite="Transports, Security Warning: servers MUST validate the Origin header",
        url=f"{TRANSPORT}#security-warning",
        needs_token=True,
        disputed=_ORIG_DISPUTE,
    ),
    Check(
        id="VER-01",
        title="Unsupported MCP-Protocol-Version after initialize is refused with 400",
        level="MUST",
        critical=False,
        cite="Transports, Protocol Version Header",
        url=f"{TRANSPORT}#protocol-version-header",
        needs_token=True,
        disputed=_VER_DISPUTE,
    ),
]
BY_ID: dict[str, Check] = {c.id: c for c in CATALOG}
CRITICAL_IDS: list[str] = [c.id for c in CATALOG if c.critical]


def needs_label(c: Check) -> str:
    if c.phase == LOGIN:
        return "`login`"
    if c.needs_token:
        return "`--token` or `login`"
    if c.needs_foreign_token:
        return "`--foreign-token` or `login`"
    return ""


def markdown_table() -> str:
    """The table in docs/checks.md. A test fails when that file is stale."""
    lines = ["| ID | Level | Check | Needs | Normative source |", "|---|---|---|---|---|"]
    for c in CATALOG:
        lvl = c.level + ("\\*" if c.critical else "")
        lines.append(f"| {c.id} | {lvl} | {c.title} | {needs_label(c)} | [{c.cite}]({c.url}) |")
    lines.append("")
    lines.append("MUST\\* is a critical check: one failure makes the conformance level Unsafe and the grade F.")
    disputed = [c for c in CATALOG if c.disputed]
    if disputed:
        lines.append("")
        lines.append("## Disputed checks")
        lines.append("")
        lines.append(
            "These stay MUST because the spec says MUST. A [policy file](grading.md#policy-files) can downgrade them."
        )
        for c in disputed:
            lines.append("")
            lines.append(f"**{c.id}** {c.title}. {c.disputed}")
    return "\n".join(lines)
