"""Tokens and login results, kept in ~/.config/mcp-authlab/tokens.json (mode 0600), keyed by canonical resource."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any


def path() -> Path:
    env = os.environ.get("MCP_AUTHLAB_TOKENS")
    if env:
        return Path(env)
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "mcp-authlab" / "tokens.json"


def load_all() -> dict[str, dict[str, Any]]:
    p = path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_all(data: dict[str, dict[str, Any]]) -> Path:
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)
    os.chmod(p, 0o600)
    return p


def get(canonical: str) -> dict[str, Any] | None:
    return load_all().get(canonical)


def put(canonical: str, entry: dict[str, Any]) -> Path:
    data = load_all()
    data[canonical] = entry
    return save_all(data)


def remove(canonical: str) -> bool:
    data = load_all()
    if canonical in data:
        del data[canonical]
        save_all(data)
        return True
    return False


def is_expired(entry: dict[str, Any], skew: int = 30) -> bool:
    exp = entry.get("expires_at")
    return isinstance(exp, (int, float)) and time.time() + skew >= exp
