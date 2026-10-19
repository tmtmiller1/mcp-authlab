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
    applicable: bool = True  # False when a skip means "this server has nothing to test here"
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
    "non-browser clients never send Origin, so a server that only checks Origin when it is present is also "
    "defending the browser case. This check sends a hostile Origin, so a server that validates when present "
    "still passes; the pushback is from operators who skip the header entirely because their clients are CLIs."
)
_VER_DISPUTE = (
    "The transports spec says a server MUST respond 400 to an unsupported MCP-Protocol-Version. Operators "
    "prefer to answer with the newest version they support so older clients keep working. The spec text is "
    "clear, so this stays MUST; use a policy downgrade if your organisation accepts version tolerance."
)

CATALOG: list[Check] = [
    Check(
        "TLS-01",
        "MCP endpoint is served over HTTPS",
        "MUST",
        False,
        "MCP Authorization, Communication Security; OAuth 2.1 section 1.5",
        f"{AUTHZ}#communication-security",
    ),
    Check(
        "CHAL-01",
        "Unauthenticated request is refused with 401",
        "MUST",
        False,
        "MCP Authorization, Error Handling; OAuth 2.1 section 5.3",
        f"{AUTHZ}#error-handling",
    ),
    Check(
        "CHAL-02",
        "401 carries WWW-Authenticate: Bearer with resource_metadata",
        "MUST",
        False,
        "MCP Authorization, Authorization Server Location; RFC 9728 section 5.1",
        f"{AUTHZ}#authorization-server-location",
    ),
    Check(
        "CHAL-03",
        "401 challenge names the scopes to request",
        "SHOULD",
        False,
        "MCP Authorization (draft), Scope Selection Strategy; RFC 6750 section 3",
        f"{DRAFT_AUTHZ}#scope-selection-strategy",
    ),
    Check(
        "PRM-01",
        "Protected Resource Metadata is published at the RFC 9728 well-known location",
        "MUST",
        False,
        "MCP Authorization, Overview item 3; RFC 9728 section 3",
        f"{AUTHZ}#overview",
    ),
    Check(
        "PRM-02",
        "Metadata 'resource' equals the server's canonical URI",
        "MUST",
        False,
        "RFC 9728 section 3.3; MCP Authorization, Canonical Server URI",
        f"{AUTHZ}#canonical-server-uri",
    ),
    Check(
        "PRM-03",
        "Metadata lists at least one authorization server",
        "MUST",
        False,
        "MCP Authorization, Authorization Server Location",
        f"{AUTHZ}#authorization-server-location",
    ),
    Check(
        "PRM-04",
        "resource_metadata URL in the challenge resolves to the same document",
        "SHOULD",
        False,
        "RFC 9728 section 5.1",
        f"{RFC9728}#section-5.1",
    ),
    Check(
        "PRM-05",
        "scopes_supported avoids wildcard, omnibus, and offline_access scopes",
        "SHOULD",
        False,
        "Security Best Practices, Scope Minimization; MCP Authorization (draft), Refresh Tokens",
        f"{BEST}#scope-minimization",
    ),
    Check(
        "PRM-06",
        "Metadata does not advertise bearer tokens in the query string",
        "SHOULD",
        False,
        "MCP Authorization, Token Requirements; RFC 6750 section 2.3",
        f"{AUTHZ}#token-requirements",
    ),
    Check(
        "ASM-01",
        "Each authorization server publishes discoverable metadata with the required fields",
        "MUST",
        False,
        "MCP Authorization, Overview item 4; RFC 8414 section 2 and 3",
        f"{AUTHZ}#server-metadata-discovery",
    ),
    Check(
        "ASM-02",
        "Authorization server 'issuer' matches the advertised URL",
        "MUST",
        False,
        "RFC 8414 section 3.3",
        f"{RFC8414}#section-3.3",
    ),
    Check(
        "ASM-03",
        "Authorization server endpoints use HTTPS",
        "MUST",
        False,
        "MCP Authorization, Communication Security; OAuth 2.1 section 1.5",
        f"{AUTHZ}#communication-security",
    ),
    Check(
        "ASM-04",
        "Authorization server advertises PKCE S256",
        "MUST",
        False,
        "MCP Authorization, Authorization Code Protection; OAuth 2.1 section 7.5.2",
        f"{AUTHZ}#authorization-code-protection",
    ),
    Check(
        "ASM-05",
        "A client registration path exists (dynamic registration or Client ID Metadata Documents)",
        "SHOULD",
        False,
        "MCP Authorization, Dynamic Client Registration; draft, Client Registration",
        f"{AUTHZ}#dynamic-client-registration",
    ),
    Check(
        "ASM-06",
        "Authorization server supports the RFC 9207 'iss' response parameter",
        "SHOULD",
        False,
        "MCP Authorization (draft), Authorization Response Validation",
        f"{DRAFT_AUTHZ}#authorization-response-validation",
    ),
    Check(
        "ASF-01",
        "Authorization endpoint refuses a request without code_challenge",
        "MUST",
        False,
        "MCP Authorization, Authorization Code Protection; OAuth 2.1 section 7.5.2; RFC 7636 section 4.4.1",
        f"{AUTHZ}#authorization-code-protection",
        phase=LOGIN,
    ),
    Check(
        "ASF-02",
        "Token endpoint refuses a wrong code_verifier",
        "MUST",
        False,
        "OAuth 2.1 section 4.1.3; RFC 7636 section 4.6",
        f"{RFC7636}#section-4.6",
        phase=LOGIN,
    ),
    Check(
        "ASF-03",
        "Token endpoint refuses a redirect_uri that differs from the authorization request",
        "MUST",
        False,
        "OAuth 2.1 section 4.1.3; RFC 6749 section 4.1.3",
        f"{OAUTH21}#section-4.1.3",
        phase=LOGIN,
    ),
    Check(
        "ASF-04",
        "Issued access token is bound to the requested resource",
        "MUST",
        False,
        "MCP Authorization, Resource Parameter Implementation; RFC 8707 section 2",
        f"{AUTHZ}#resource-parameter-implementation",
        phase=LOGIN,
    ),
    Check(
        "ASF-05",
        "Refresh tokens rotate for a public client",
        "SHOULD",
        False,
        "OAuth 2.1 section 4.3.1: refresh tokens for public clients are sender-constrained or rotate",
        f"{OAUTH21}#section-4.3.1",
        phase=LOGIN,
    ),
    Check(
        "ASF-06",
        "Authorization server URLs are HTTPS and the callback carried iss when advertised",
        "MUST",
        False,
        "MCP Authorization, Communication Security; RFC 9207 section 2",
        f"{RFC9207}#section-2",
        phase=LOGIN,
    ),
    Check(
        "TOK-01",
        "Malformed bearer token is refused with 401",
        "MUST",
        False,
        "MCP Authorization, Token Handling; OAuth 2.1 section 5.2",
        f"{AUTHZ}#token-handling",
    ),
    Check(
        "TOK-02",
        "Unsigned (alg=none) token with the right audience is refused",
        "MUST",
        True,
        "MCP Authorization, Token Handling; Security Best Practices, Token Passthrough",
        f"{BEST}#token-passthrough",
    ),
    Check(
        "TOK-03",
        "Valid token issued for a different resource is refused (audience binding)",
        "MUST",
        True,
        "MCP Authorization, Access Token Privilege Restriction; RFC 8707 section 2",
        f"{AUTHZ}#access-token-privilege-restriction",
        needs_foreign_token=True,
    ),
    Check(
        "TOK-04",
        'Invalid-token 401 carries error="invalid_token"',
        "SHOULD",
        False,
        "RFC 6750 section 3.1",
        f"{RFC6750}#section-3.1",
    ),
    Check(
        "TOK-05",
        "Valid token in the query string is not accepted",
        "MUST",
        False,
        "MCP Authorization, Token Requirements",
        f"{AUTHZ}#token-requirements",
        needs_token=True,
    ),
    Check(
        "TOK-06",
        "Valid token succeeds (initialize completes)",
        "MUST",
        False,
        "MCP Authorization, Access Token Usage",
        f"{AUTHZ}#access-token-usage",
        needs_token=True,
    ),
    Check(
        "SCOPE-01",
        'A tool call the token cannot make gets 403 with error="insufficient_scope" and a scope hint',
        "SHOULD",
        False,
        "MCP Authorization (draft), Scope Selection Strategy; RFC 6750 section 3.1",
        f"{DRAFT_AUTHZ}#scope-selection-strategy",
        needs_token=True,
    ),
    Check(
        "SESS-01",
        "Session ID does not substitute for authentication",
        "MUST",
        True,
        "Security Best Practices, Session Hijacking: servers MUST NOT use sessions for authentication",
        f"{BEST}#session-hijacking",
        needs_token=True,
    ),
    Check(
        "SESS-02",
        "Session IDs are long, random, and non-sequential",
        "SHOULD",
        False,
        "Transports, Session Management; Security Best Practices, Session Hijacking",
        f"{TRANSPORT}#session-management",
        needs_token=True,
    ),
    Check(
        "ORIG-01",
        "Request with a hostile Origin header is refused",
        "MUST",
        False,
        "Transports, Security Warning: servers MUST validate the Origin header",
        f"{TRANSPORT}#security-warning",
        needs_token=True,
        disputed=_ORIG_DISPUTE,
    ),
    Check(
        "VER-01",
        "Unsupported MCP-Protocol-Version is refused with 400",
        "MUST",
        False,
        "Transports, Protocol Version Header",
        f"{TRANSPORT}#protocol-version-header",
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
