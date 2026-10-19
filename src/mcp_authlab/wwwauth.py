"""Parse WWW-Authenticate challenges (RFC 9110 section 11.6.1), tolerant of real-world formatting."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_TOKEN = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_QUOTED = r'"(?:[^"\\]|\\.)*"'
_PARAM = re.compile(rf"\s*({_TOKEN})\s*=\s*({_QUOTED}|{_TOKEN})\s*,?")
_SCHEME = re.compile(rf"\s*({_TOKEN})(?:\s+|$)")


@dataclass
class Challenge:
    scheme: str
    params: dict[str, str] = field(default_factory=dict)
    token68: str | None = None


def _unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return re.sub(r"\\(.)", r"\1", v[1:-1])
    return v


def parse(header_values: list[str]) -> list[Challenge]:
    """Parse one or more WWW-Authenticate header values into challenges."""
    challenges: list[Challenge] = []
    for raw in header_values:
        s = raw.strip()
        while s:
            m = _SCHEME.match(s)
            if not m:
                break
            scheme = m.group(1)
            s = s[m.end():]
            ch = Challenge(scheme=scheme)
            # auth-params until the next "<token> " that is not "<token>="
            while True:
                pm = _PARAM.match(s)
                if not pm:
                    break
                ch.params[pm.group(1).lower()] = _unquote(pm.group(2))
                s = s[pm.end():]
            if not ch.params:
                t68 = re.match(r"\s*([A-Za-z0-9\-._~+/]+=*)\s*,?", s)
                if t68 and not _SCHEME.match(s + " x"):
                    ch.token68 = t68.group(1)
                    s = s[t68.end():]
            challenges.append(ch)
            s = s.lstrip(", ")
    return challenges


def bearer(header_values: list[str]) -> Challenge | None:
    for ch in parse(header_values):
        if ch.scheme.lower() == "bearer":
            return ch
    return None
