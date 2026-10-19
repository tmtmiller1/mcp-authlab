"""Render a scan as terminal text, Markdown, or JSON."""

from __future__ import annotations

import json
import sys
from typing import Any

_SYM = {"pass": "✓", "fail": "✗", "warn": "!", "skip": "–", "error": "?"}
_COLOR = {"pass": "32", "fail": "31", "warn": "33", "skip": "90", "error": "35"}
_GRADE_COLOR = {"A": "32", "B": "32", "C": "33", "D": "33", "F": "31"}


def _c(code: str, text: str, enabled: bool) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if enabled else text


def _sections(results: list[dict[str, Any]]) -> list[tuple[str, list[dict[str, Any]]]]:
    order = [("TLS", "Transport"), ("CHAL", "Challenge"), ("PRM", "Protected Resource Metadata"),
             ("ASM", "Authorization Server Metadata"), ("TOK", "Token validation"),
             ("SESS", "Sessions"), ("ORIG", "Origin"), ("VER", "Protocol version")]
    out = []
    for prefix, title in order:
        rows = sorted((r for r in results if r["id"].split("-")[0] == prefix), key=lambda r: r["id"])
        if rows:
            out.append((title, rows))
    return out


def terminal(report: dict[str, Any], color: bool | None = None, verbose: bool = False) -> str:
    if color is None:
        color = sys.stdout.isatty()
    lines = []
    g = report["grade"]
    lines.append(_c("1", f"mcp-authlab {report['version']}  ·  spec {report['spec']}", color))
    lines.append(f"target   {report['target']}")
    lines.append(f"grade    {_c('1;' + _GRADE_COLOR[g], g, color)}   score {report['score']}/100")
    for reason in report["reasons"]:
        lines.append(f"         {reason}")
    c = report["counts"]
    lines.append(f"checks   {c['pass']} pass · {c['fail']} fail · {c['warn']} warn · {c['skip']} skipped" + (f" · {c['error']} error" if c["error"] else ""))
    for title, rows in _sections(report["results"]):
        lines.append("")
        lines.append(_c("1", title, color))
        for r in rows:
            sym = _c(_COLOR[r["status"]], _SYM[r["status"]], color)
            lvl = r["level"] + ("*" if r["critical"] else " ")
            lines.append(f"  {sym} {r['id']:<8}{lvl:<7}{r['title']}")
            if r["status"] in ("fail", "warn", "error") or verbose:
                lines.append(f"             {_c('90', r['message'], color)}")
                if r["status"] in ("fail", "warn"):
                    lines.append(f"             {_c('90', r['cite'], color)}")
    lines.append("")
    lines.append(_c("90", "MUST* marks a critical check: one failure is an F on its own. Skipped checks need --token or --foreign-token.", color))
    return "\n".join(lines)


def markdown(report: dict[str, Any]) -> str:
    c = report["counts"]
    out = [
        f"# MCP authorization scan: `{report['target']}`",
        "",
        f"**Grade {report['grade']}** (score {report['score']}/100) · spec {report['spec']} · scanned {report['scanned_at']} · mcp-authlab {report['version']}",
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
            lvl = r["level"] + ("\\*" if r["critical"] else "")
            msg = r["message"].replace("|", "\\|")
            out.append(f"| {_SYM[r['status']]} | {r['id']} | {lvl} | [{r['title']}]({r['url']}) | {msg} |")
        out.append("")
    out.append("MUST\\* marks a critical check: one failure is an F on its own.")
    return "\n".join(out)


def as_json(report: dict[str, Any], requests: bool = False) -> str:
    data = dict(report)
    if not requests:
        data.pop("requests", None)
    return json.dumps(data, indent=2)
