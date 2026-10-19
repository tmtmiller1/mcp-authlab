"""Just enough JWT for probes and the fixture: HS256 sign/verify and an unsigned (alg none) minter."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


Claims = dict[str, Any]


def _segment(obj: object) -> str:
    return _b64(json.dumps(obj, separators=(",", ":")).encode())


def encode(claims: Claims, key: bytes | None, alg: str = "HS256") -> str:
    header = {"alg": alg, "typ": "JWT"}
    signing_input = f"{_segment(header)}.{_segment(claims)}"
    if alg == "none" or key is None:
        return signing_input + "."
    sig = hmac.new(key, signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64(sig)}"


def decode_unverified(token: str) -> tuple[Claims, Claims, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWS compact serialization")
    header = json.loads(_unb64(parts[0]))
    claims = json.loads(_unb64(parts[1]))
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError("header and claims must be JSON objects")
    return header, claims, parts[2]


def verify_hs256(token: str, key: bytes) -> Claims:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed")
    header = json.loads(_unb64(parts[0]))
    if header.get("alg") != "HS256":
        raise ValueError(f"alg {header.get('alg')!r} not allowed")
    expected = hmac.new(key, f"{parts[0]}.{parts[1]}".encode("ascii"), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _unb64(parts[2])):
        raise ValueError("bad signature")
    claims = json.loads(_unb64(parts[1]))
    if not isinstance(claims, dict):
        raise ValueError("claims must be a JSON object")
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and time.time() >= exp:
        raise ValueError("expired")
    return claims


def unsigned(aud: str, issuer: str = "https://authlab.invalid", ttl: int = 600) -> str:
    """An alg=none token. Any server that accepts this is not validating signatures."""
    now = int(time.time())
    return encode(
        {"iss": issuer, "sub": "mcp-authlab-probe", "aud": aud, "iat": now, "exp": now + ttl, "scope": "mcp"},
        None,
        alg="none",
    )
