"""Render a scan as terminal text, Markdown, JSON or SARIF."""

from __future__ import annotations

import json
import sys
from typing import Any

from . import __version__
from .catalog import BY_ID, GROUPS

_SYM = {"pass": "✓", "fail": "✗", "warn": "!", "skip": "–", "error": "?"}
_COLOR = {"pass": "32", "fail": "31", "warn": "33", "skip": "90", "error": "35"}
_GRADE_COLOR = {"A": "32", "B": "32", "C": "33", "D": "33", "F": "31"}
_LEVEL_COLOR = {"Conformant": "32", "Conformant with warnings": "33", "Non-conformant": "33", "Unsafe": "31"}
FOOTER = (
    "MUST* marks a critical check: one failure is Unsafe and an F on its own. "
    "Skipped checks say what they need; `mcp-authlab login <url>` runs the rest."
)


def status_symbol(status: str, color: bool) -> str:
    """The one-character mark for a result status, colored for a terminal when asked."""
    return _c(_COLOR[status], _SYM[status], color)


def _c(code: str, text: str, enabled: bool) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if enabled else text


def _sections(results: list[dict[str, Any]]) -> list[tuple[str, list[dict[str, Any]]]]:
    out = []
    for prefix, title in GROUPS:
        rows = sorted((r for r in results if r["id"].split("-")[0] == prefix), key=lambda r: r["id"])
        if rows:
            out.append((title, rows))
    return out


def _level_tag(r: dict[str, Any], star: str = "*") -> str:
    lvl = str(r.get("effective_level") or r["level"])
    crit = r.get("effective_critical", r["critical"])
    tag = lvl + (star if crit else "")
    if lvl != r["level"]:
        tag += "↓"
    return tag


def _policy_note(r: dict[str, Any]) -> str:
    notes = []
    if not r.get("counted", True):
        notes.append("ignored by policy")
    if (r.get("effective_level") or r["level"]) != r["level"]:
        notes.append(f"downgraded from {r['level']} by policy")
    return "; ".join(notes)


def terminal(report: dict[str, Any], color: bool | None = None, verbose: bool = False) -> str:
    if color is None:
        color = sys.stdout.isatty()
    lines = []
    g = report["grade"]
    lvl = report["conformance"]
    lines.append(_c("1", f"mcp-authlab {report['version']}  ·  spec {report['spec']}", color))
    lines.append(f"target   {report['target']}")
    lines.append(f"coverage {report['coverage']['line'][len('coverage ') :]}")
    lvl_c = _c("1;" + _LEVEL_COLOR[lvl], lvl, color)
    grade_c = _c("1;" + _GRADE_COLOR[g], g, color)
    lines.append(f"level    {lvl_c}   grade {grade_c}   score {report['score']}/100")
    for reason in report["reasons"]:
        lines.append(f"         {reason}")
    c = report["counts"]
    lines.append(
        f"checks   {c['pass']} pass · {c['fail']} fail · {c['warn']} warn · {c['skip']} skipped"
        + (f" · {c['error']} error" if c["error"] else "")
    )
    if report.get("policy"):
        lines.append(f"policy   {report['policy'].get('source') or 'inline'}")
    if report.get("login"):
        lg = report["login"]
        lines.append(f"login    {lg.get('issuer')} as client {lg.get('client_id')} ({lg.get('logged_in_at')})")
    for title, rows in _sections(report["results"]):
        lines.append("")
        lines.append(_c("1", title, color))
        for r in rows:
            sym = _c(_COLOR[r["status"]], _SYM[r["status"]], color)
            tag = _level_tag(r)
            lines.append(f"  {sym} {r['id']:<9}{tag:<8}{r['title']}")
            note = _policy_note(r)
            if r["status"] in ("fail", "warn", "error", "skip") or verbose:
                lines.append(f"              {_c('90', r['message'], color)}")
            if r["status"] in ("fail", "warn"):
                lines.append(f"              {_c('90', r['cite'], color)}")
            if note:
                lines.append(f"              {_c('90', note, color)}")
    lines.append("")
    lines.append(_c("90", FOOTER, color))
    return "\n".join(lines)


def markdown(report: dict[str, Any]) -> str:
    c = report["counts"]
    out = [
        f"# MCP authorization scan: `{report['target']}`",
        "",
        report["coverage"]["line"],
        "",
        f"**{report['conformance']}** · grade **{report['grade']}** (score {report['score']}/100) · "
        f"spec {report['spec']} · scanned {report['scanned_at']} · mcp-authlab {report['version']}",
        "",
    ]
    for reason in report["reasons"]:
        out.append(f"- {reason}")
    if report["reasons"]:
        out.append("")
    out.append(f"{c['pass']} pass · {c['fail']} fail · {c['warn']} warn · {c['skip']} skipped")
    out.append("")
    for title, rows in _sections(report["results"]):
        out.append(f"## {title}")
        out.append("")
        out.append("| | ID | Level | Check | Finding |")
        out.append("|---|---|---|---|---|")
        for r in rows:
            msg = r["message"].replace("|", "\\|")
            note = _policy_note(r)
            if note:
                msg += f" *({note})*"
            tag = _level_tag(r, "\\*")
            out.append(f"| {_SYM[r['status']]} | {r['id']} | {tag} | [{r['title']}]({r['url']}) | {msg} |")
        out.append("")
    out.append(FOOTER.replace("MUST*", "MUST\\*"))
    return "\n".join(out)


def as_json(report: dict[str, Any], requests: bool = False) -> str:
    data = dict(report)
    if not requests:
        data.pop("requests", None)
    return json.dumps(data, indent=2)


def _sarif_level(r: dict[str, Any]) -> str:
    if r["status"] in ("pass", "skip"):
        return "none"
    if r["status"] == "error":
        return "note"
    lvl = r.get("effective_level") or r["level"]
    if r["status"] == "fail" and (r.get("effective_critical", r["critical"]) or lvl == "MUST"):
        return "error"
    return "warning"


def _sarif_kind(status: str) -> str:
    return {"pass": "pass", "fail": "fail", "warn": "fail", "skip": "notApplicable", "error": "open"}[status]


def sarif(report: dict[str, Any]) -> str:
    """SARIF 2.1.0: one rule per catalog check, one result per scan result."""
    rules = []
    for cid, check in BY_ID.items():
        rules.append(
            {
                "id": cid,
                "name": cid.replace("-", ""),
                "shortDescription": {"text": check.title},
                "fullDescription": {"text": f"{check.title}. {check.cite}."},
                "helpUri": check.url,
                "help": {"text": check.cite},
                "defaultConfiguration": {"level": "error" if check.level == "MUST" else "warning"},
                "properties": {
                    "level": check.level,
                    "critical": check.critical,
                    "tags": ["security", "oauth", "mcp", check.group.lower()],
                },
            }
        )
    results = []
    for r in report["results"]:
        text = f"{r['id']} {r['status']}: {r['message']}"
        note = _policy_note(r)
        if note:
            text += f" ({note})"
        results.append(
            {
                "ruleId": r["id"],
                "kind": _sarif_kind(r["status"]),
                "level": _sarif_level(r),
                "message": {"text": text},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": report["target"]}}}],
                "properties": {
                    "status": r["status"],
                    "counted": r.get("counted", True),
                    "effective_level": r.get("effective_level") or r["level"],
                    "cite": r["cite"],
                },
            }
        )
    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-authlab",
                        "version": report.get("version", __version__),
                        "informationUri": "https://github.com/tmtmiller1/mcp-authlab",
                        "rules": rules,
                    }
                },
                "invocations": [{"executionSuccessful": True, "endTimeUtc": report["scanned_at"]}],
                "properties": {
                    "target": report["target"],
                    "conformance": report["conformance"],
                    "grade": report["grade"],
                    "score": report["score"],
                    "coverage": report["coverage"]["line"],
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


FORMATS = ("text", "json", "markdown", "sarif")


def render(
    report: dict[str, Any], fmt: str, color: bool | None = None, verbose: bool = False, requests: bool = False
) -> str:
    if fmt == "json":
        return as_json(report, requests=requests)
    if fmt == "markdown":
        return markdown(report)
    if fmt == "sarif":
        return sarif(report)
    if fmt == "text":
        return terminal(report, color=color, verbose=verbose)
    raise ValueError(f"unknown format {fmt!r}")
