"""Public entry point. `checks.run(url, ...)` scans a server and returns the report dict.

The catalog lives in catalog.py, the scanner in scanner.py and the grading in
grading.py; this module re-exports them so existing imports keep working.
"""

from __future__ import annotations

from .catalog import BY_ID, CATALOG, ERROR, FAIL, PASS, SKIP, WARN, Check, Result
from .grading import GRADE_ORDER, GRADING, LEVELS, Grade, conformance_level, coverage, grade
from .scanner import Scanner, build_report, initialize_payload, run

__all__ = [
    "BY_ID",
    "CATALOG",
    "ERROR",
    "FAIL",
    "GRADE_ORDER",
    "GRADING",
    "LEVELS",
    "PASS",
    "SKIP",
    "WARN",
    "Check",
    "Grade",
    "Result",
    "Scanner",
    "build_report",
    "conformance_level",
    "coverage",
    "grade",
    "initialize_payload",
    "run",
]
