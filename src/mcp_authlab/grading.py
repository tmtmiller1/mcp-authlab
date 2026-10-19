"""Conformance level and letter grade.

Every weight and threshold is in GRADING below and in docs/grading.md; keep the
two in step. A reader with the JSON report and that document can recompute
any grade by hand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .catalog import ERROR, FAIL, PASS, SKIP, WARN, Result

GRADING: dict[str, Any] = {
    # Weight a check contributes to the denominator when it ran (pass, fail or warn).
    "weights": {"critical": 20, "MUST": 10, "SHOULD": 3},
    # Share of a check's weight a WARN earns. A SHOULD check that warns earns nothing;
    # a MUST check that warns (loopback http, 400 answered as 200) earns half.
    "warn_credit": {"MUST": 0.5, "SHOULD": 0.0},
    # Score (percent of weight earned) needed for each letter, checked top down.
    "thresholds": [("A", 95), ("B", 85), ("C", 70), ("D", 50)],
    # A failed MUST check caps the letter here, whatever the score.
    "must_failure_cap": "C",
    # These failures are F on their own: any critical check, and a server that
    # answers unauthenticated requests with anything other than 401.
    "f_on_failure": ["CHAL-01"],
}

LEVELS = ("Unsafe", "Non-conformant", "Conformant with warnings", "Conformant")
GRADE_ORDER = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
_LETTERS = ["A", "B", "C", "D", "F"]


def weight(r: Result) -> int:
    w: dict[str, int] = GRADING["weights"]
    if r.critical:
        return w["critical"]
    return w[r.level]


@dataclass
class Grade:
    level: str
    letter: str
    score: int
    reasons: list[str] = field(default_factory=list)
    critical_failures: list[str] = field(default_factory=list)
    must_failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    ignored: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "conformance": self.level,
            "grade": self.letter,
            "score": self.score,
            "reasons": self.reasons,
            "critical_failures": self.critical_failures,
            "must_failures": self.must_failures,
            "warnings": self.warnings,
            "ignored": self.ignored,
        }


def _cap(letter: str, cap: str) -> str:
    return letter if _LETTERS.index(letter) >= _LETTERS.index(cap) else cap


def conformance_level(results: list[Result]) -> str:
    counted = [r for r in results if r.counted and r.status in (FAIL, WARN)]
    if any(r.status == FAIL and r.critical for r in counted):
        return "Unsafe"
    if any(r.status == FAIL and r.level == "MUST" for r in counted):
        return "Non-conformant"
    if counted:
        return "Conformant with warnings"
    return "Conformant"


def grade(results: list[Result]) -> Grade:
    """Compute the conformance level and the letter grade. Skips and errors stay out of the denominator."""
    counted = [r for r in results if r.counted]
    ran = [r for r in counted if r.status in (PASS, FAIL, WARN)]
    total = sum(weight(r) for r in ran)
    earned = 0.0
    credit: dict[str, float] = GRADING["warn_credit"]
    for r in ran:
        if r.status == PASS:
            earned += weight(r)
        elif r.status == WARN:
            earned += weight(r) * credit[r.level]
    score = round(100 * earned / total) if total else 0

    g = Grade(conformance_level(results), "F", score)
    g.critical_failures = [r.check.id for r in ran if r.status == FAIL and r.critical]
    g.must_failures = [r.check.id for r in ran if r.status == FAIL and r.level == "MUST"]
    g.warnings = [r.check.id for r in ran if r.status == WARN]
    g.ignored = [r.check.id for r in results if not r.counted and r.status in (FAIL, WARN)]

    letter = "F"
    for name, floor in GRADING["thresholds"]:
        if score >= floor:
            letter = name
            break
    if g.critical_failures:
        g.reasons.append("critical failure: " + ", ".join(g.critical_failures))
        letter = "F"
    f_on = [r.check.id for r in ran if r.status == FAIL and r.check.id in GRADING["f_on_failure"]]
    if f_on and not g.critical_failures:
        g.reasons.append("server does not challenge unauthenticated requests")
        letter = "F"
    if g.must_failures and letter != "F":
        g.reasons.append("MUST failures: " + ", ".join(g.must_failures))
        letter = _cap(letter, GRADING["must_failure_cap"])
    elif g.must_failures:
        g.reasons.append("MUST failures: " + ", ".join(g.must_failures))
    if g.warnings and not g.must_failures:
        g.reasons.append("warnings: " + ", ".join(g.warnings))
    if g.ignored:
        g.reasons.append("ignored by policy: " + ", ".join(g.ignored))
    g.letter = letter
    return g


def coverage(results: list[Result]) -> dict[str, Any]:
    """How many applicable checks ran, and which critical checks did not."""
    applicable = [r for r in results if r.applicable]
    ran = [r for r in applicable if r.status in (PASS, FAIL, WARN, ERROR)]
    not_run = [r.check.id for r in applicable if r.status == SKIP and r.critical]
    login_helps = any(r.status == SKIP and r.critical and r.evidence.get("needs_login") for r in applicable)
    return {"ran": len(ran), "applicable": len(applicable), "critical_not_run": not_run, "login_helps": login_helps}


def coverage_line(cov: dict[str, Any]) -> str:
    line = f"coverage {cov['ran']}/{cov['applicable']}"
    if cov["critical_not_run"]:
        line += " · critical checks not run: " + ", ".join(cov["critical_not_run"])
        if cov.get("login_helps"):
            line += " (run `mcp-authlab login` to enable)"
    return line
