"""Tokens and login results, kept in ~/.config/mcp-authlab/tokens.json (mode 0600), keyed by canonical resource."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any


class TokenStoreError(Exception):
    pass


def path() -> Path:
    env = os.environ.get("MCP_AUTHLAB_TOKENS")
    if env:
        return Path(env)
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "mcp-authlab" / "tokens.json"


def _ensure_dir(p: Path) -> None:
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)


@contextlib.contextmanager
def _locked() -> Iterator[None]:
    """Hold an exclusive lock so a login and a scan's refresh can't overwrite each other."""
    p = path()
    _ensure_dir(p)
    fd = os.open(p.with_name(p.name + ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read(strict: bool) -> dict[str, dict[str, Any]]:
    p = path()
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as e:
        if strict:
            raise TokenStoreError(f"couldn't read {p}: {e}") from e
        return {}
    try:
        data = json.loads(text)
    except ValueError as e:
        if strict:
            raise TokenStoreError(f"{p} isn't valid JSON; move it aside and log in again") from e
        return {}
    if not isinstance(data, dict):
        if strict:
            raise TokenStoreError(f"{p} should hold a JSON object; move it aside and log in again")
        return {}
    return data


def load_all() -> dict[str, dict[str, Any]]:
    """Everything stored. A missing or unreadable file reads as empty; writes refuse to overwrite a broken one."""
    return _read(strict=False)


def _write(data: dict[str, dict[str, Any]]) -> Path:
    p = path()
    _ensure_dir(p)
    fd, tmp = tempfile.mkstemp(prefix=".tokens-", suffix=".tmp", dir=p.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, p)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return p


def get(canonical: str) -> dict[str, Any] | None:
    return load_all().get(canonical)


def put(canonical: str, entry: dict[str, Any]) -> Path:
    with _locked():
        data = _read(strict=True)
        data[canonical] = entry
        return _write(data)


def remove(canonical: str) -> bool:
    with _locked():
        data = _read(strict=True)
        if canonical not in data:
            return False
        del data[canonical]
        _write(data)
        return True


def is_expired(entry: dict[str, Any], skew: int = 30) -> bool:
    exp = entry.get("expires_at")
    return isinstance(exp, (int, float)) and time.time() + skew >= exp
