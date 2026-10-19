"""Policy files: an organisation's own bar, applied on top of the catalog.

    fail_under = "B"
    ignore = ["VER-01"]
    downgrade = { "ORIG-01" = "SHOULD" }

Ignored checks still run and still print; they stop counting toward the grade.
A downgraded check counts at the new level and is never critical.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .catalog import BY_ID, Result
from .grading import GRADE_ORDER


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    fail_under: str | None = None
    ignore: list[str] = field(default_factory=list)
    downgrade: dict[str, str] = field(default_factory=dict)
    source: str | None = None

    def apply(self, results: list[Result]) -> None:
        for r in results:
            if r.check.id in self.ignore:
                r.counted = False
            lvl = self.downgrade.get(r.check.id)
            if lvl and lvl != r.check.level:
                r.effective_level = lvl

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "fail_under": self.fail_under,
            "ignore": self.ignore,
            "downgrade": self.downgrade,
        }


def parse(text: str, source: str | None = None) -> Policy:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise PolicyError(f"policy is not valid TOML: {e}") from e
    pol = Policy(source=source)
    unknown = set(doc) - {"fail_under", "ignore", "downgrade"}
    if unknown:
        raise PolicyError(f"unknown policy keys: {', '.join(sorted(unknown))}")
    fu = doc.get("fail_under")
    if fu is not None:
        if not isinstance(fu, str) or fu.upper() not in GRADE_ORDER:
            raise PolicyError(f"fail_under must be one of {', '.join(GRADE_ORDER)}, got {fu!r}")
        pol.fail_under = fu.upper()
    ign = doc.get("ignore", [])
    if not isinstance(ign, list) or not all(isinstance(i, str) for i in ign):
        raise PolicyError("ignore must be a list of check IDs")
    for cid in ign:
        if cid not in BY_ID:
            raise PolicyError(f"ignore names an unknown check {cid!r}")
    pol.ignore = list(ign)
    dg = doc.get("downgrade", {})
    if not isinstance(dg, dict):
        raise PolicyError("downgrade must be a table of check ID = level")
    for cid, lvl in dg.items():
        if cid not in BY_ID:
            raise PolicyError(f"downgrade names an unknown check {cid!r}")
        if lvl not in ("MUST", "SHOULD"):
            raise PolicyError(f"downgrade level for {cid} must be MUST or SHOULD, got {lvl!r}")
        pol.downgrade[cid] = lvl
    return pol


def load(path: str | Path) -> Policy:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        raise PolicyError(f"cannot read policy {p}: {e}") from e
    return parse(text, source=str(p))
