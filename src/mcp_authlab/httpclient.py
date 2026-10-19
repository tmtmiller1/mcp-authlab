"""Minimal HTTP client on urllib: no redirects, no exceptions on 4xx/5xx, keeps evidence."""

from __future__ import annotations

import http.client
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from email.message import Message
from typing import Any


class TransportError(Exception):
    """The request never produced an HTTP response (DNS, TLS, refused, timeout)."""


@dataclass
class Response:
    status: int
    headers: Message
    body: bytes
    url: str
    elapsed_ms: int

    def header(self, name: str) -> str | None:
        return self.headers.get(name)

    def header_all(self, name: str) -> list[str]:
        return self.headers.get_all(name) or []

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()


@dataclass
class Exchange:
    method: str
    url: str
    request_headers: dict[str, str]
    status: int | None
    response_headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


class _KeepErrors(urllib.request.HTTPErrorProcessor):
    def http_response(self, request: urllib.request.Request, response: Any) -> Any:
        return response

    https_response = http_response


REDACT = {"authorization", "cookie", "mcp-session-id"}


class Client:
    def __init__(self, timeout: float = 10.0, insecure: bool = False, user_agent: str = "mcp-authlab"):
        self.timeout = timeout
        self.user_agent = user_agent
        self.log: list[Exchange] = []
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(
            _NoRedirect(), _KeepErrors(), urllib.request.HTTPSHandler(context=ctx)
        )

    def request(
        self, method: str, url: str, headers: dict[str, str] | None = None, body: bytes | None = None
    ) -> Response:
        hdrs = {"User-Agent": self.user_agent}
        hdrs.update(headers or {})
        req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
        logged = {k: ("<redacted>" if k.lower() in REDACT else v) for k, v in hdrs.items()}
        entry = Exchange(method=method, url=url, request_headers=logged, status=None)
        self.log.append(entry)
        start = time.monotonic()
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                data = resp.read()
                elapsed = int((time.monotonic() - start) * 1000)
                entry.status = resp.status
                entry.response_headers = dict(resp.headers.items())
                return Response(resp.status, resp.headers, data, url, elapsed)
        except urllib.error.HTTPError as e:  # only raised for codes urllib still treats as errors
            data = e.read()
            elapsed = int((time.monotonic() - start) * 1000)
            entry.status = e.code
            entry.response_headers = dict(e.headers.items())
            return Response(e.code, e.headers, data, url, elapsed)
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
            entry.error = f"{type(e).__name__}: {e}"
            raise TransportError(entry.error) from e

    def get(self, url: str, headers: dict[str, str] | None = None) -> Response:
        return self.request("GET", url, headers)

    def post_json(self, url: str, payload: bytes, headers: dict[str, str] | None = None) -> Response:
        hdrs = {"Content-Type": "application/json"}
        hdrs.update(headers or {})
        return self.request("POST", url, hdrs, payload)

    def post_form(self, url: str, fields: dict[str, str], headers: dict[str, str] | None = None) -> Response:
        hdrs = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        hdrs.update(headers or {})
        return self.request("POST", url, hdrs, urllib.parse.urlencode(fields).encode())
