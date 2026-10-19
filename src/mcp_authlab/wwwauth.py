"""Parse WWW-Authenticate challenges from the RFC 9110 section 11.6.1 grammar.

    WWW-Authenticate = #challenge
    challenge        = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
    auth-scheme      = token
    auth-param       = token BWS "=" BWS ( token / quoted-string )
    token68          = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="

A header may carry several challenges separated by commas, and a response may
carry several headers. The parser reads one challenge at a time: a scheme, then
either a single token68 or a comma-separated run of auth-params. A bare token
after a comma that has no "=" after it starts the next challenge.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_TCHAR = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]"
_TOKEN = re.compile(rf"{_TCHAR}+")
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
_TOKEN68 = re.compile(r"[A-Za-z0-9\-._~+/]+=*")
_OWS = re.compile(r"[ \t]*")
_AUTH_PARAM = re.compile(rf"({_TCHAR}+)[ \t]*=[ \t]*(?:\"((?:[^\"\\]|\\.)*)\"|({_TCHAR}+))")


@dataclass
class Challenge:
    scheme: str
    params: dict[str, str] = field(default_factory=dict)
    token68: str | None = None


class _Cursor:
    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0

    def done(self) -> bool:
        return self.i >= len(self.s)

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def ows(self) -> None:
        m = _OWS.match(self.s, self.i)
        if m:
            self.i = m.end()

    def skip_commas(self) -> None:
        """RFC 9110 list syntax allows empty elements: ', ,Bearer'."""
        while True:
            self.ows()
            if self.peek() == ",":
                self.i += 1
            else:
                return

    def match(self, rx: re.Pattern[str]) -> re.Match[str] | None:
        return rx.match(self.s, self.i)


def _unescape(quoted: str) -> str:
    return re.sub(r"\\(.)", r"\1", quoted)


def _parse_one(c: _Cursor, out: list[Challenge]) -> bool:
    """Parse one challenge at the cursor; return False at the end of parseable input."""
    c.skip_commas()
    m = c.match(_TOKEN)
    if not m:
        return False
    ch = Challenge(scheme=m.group(0))
    c.i = m.end()
    out.append(ch)
    if c.done() or c.peek() == ",":
        return True
    if c.peek() not in " \t":
        # Something other than SP or comma after the scheme: not a challenge we understand.
        # Skip to the next comma so one bad element doesn't hide the rest.
        nxt = c.s.find(",", c.i)
        c.i = len(c.s) if nxt < 0 else nxt
        return True
    c.ows()
    # Try auth-params first; token68 only when the first thing isn't name=value.
    pm = c.match(_AUTH_PARAM)
    if not pm:
        tm = c.match(_TOKEN68)
        if tm:
            ch.token68 = tm.group(0)
            c.i = tm.end()
        return True
    while True:
        pm = c.match(_AUTH_PARAM)
        if not pm:
            return True
        name = pm.group(1).lower()
        value = _unescape(pm.group(2)) if pm.group(2) is not None else pm.group(3)
        ch.params.setdefault(name, value)
        c.i = pm.end()
        save = c.i
        c.ows()
        if c.peek() != ",":
            # A missing comma between two auth-params is a common server bug. Read on as the same
            # challenge rather than mistaking the next param name for a new scheme.
            if c.match(_AUTH_PARAM):
                continue
            c.i = save
            return True
        c.skip_commas()
        # After a comma: another auth-param continues this challenge; a bare token starts the next one.
        if not c.match(_AUTH_PARAM):
            c.i = save
            return True


def parse(header_values: list[str]) -> list[Challenge]:
    """Parse one or more WWW-Authenticate header values into challenges, in order."""
    challenges: list[Challenge] = []
    for raw in header_values:
        c = _Cursor(raw)
        while not c.done():
            if not _parse_one(c, challenges):
                break
    return challenges


def bearer(header_values: list[str]) -> Challenge | None:
    """The first Bearer challenge, or None."""
    for ch in parse(header_values):
        if ch.scheme.lower() == "bearer":
            return ch
    return None
