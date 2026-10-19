#!/usr/bin/env python3
"""Scan every endpoint in endpoints.toml unauthenticated, write results/<date>.json, regenerate README.md.

Run from anywhere: python3 registry/scan.py [--date YYYY-MM-DD]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import tomllib
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from mcp_authlab import __version__, checks  # noqa: E402

NOTE = (
    "Unauthenticated scans only: the tool sends a handful of requests (an unauthenticated initialize, the metadata "
    "documents, two invalid tokens) and never logs in. Runs every Monday from GitHub Actions. If your server is "
    "listed and you want it removed or a finding corrected, "
    "[open an issue](https://github.com/tmtmiller1/mcp-authlab/issues)."
)


def scan_all(date: str) -> dict[str, Any]:
    with open(HERE / "endpoints.toml", "rb") as fh:
        endpoints = tomllib.load(fh)["endpoint"]
    out: dict[str, Any] = {"date": date, "tool_version": __version__, "scans": []}
    for ep in endpoints:
        try:
            data = checks.run(ep["url"], timeout=15)
        except Exception as e:  # noqa: BLE001 - keep scanning the rest
            out["scans"].append({"name": ep["name"], "url": ep["url"], "error": f"{type(e).__name__}: {e}"})
            continue
        data.pop("requests", None)
        out["scans"].append({"name": ep["name"], "url": ep["url"], "report": data})
    return out


def _findings(report: dict[str, Any]) -> str:
    rows = [r for r in report["results"] if r["status"] in ("fail", "warn", "error")]
    if not rows:
        return "nothing to report"
    return "<br>".join(f"**{r['id']}** {r['message']}".replace("|", "\\|") for r in rows)


def render(results: dict[str, Any], history: list[str]) -> str:
    lines = [
        "# Public MCP endpoint registry",
        "",
        f"Scanned {results['date']} with mcp-authlab {results['tool_version']}. {NOTE}",
        "",
        "| Server | Level | Grade | Coverage | Findings |",
        "|---|---|---|---|---|",
    ]
    for s in results["scans"]:
        if "error" in s:
            lines.append(f"| [{s['name']}]({s['url']}) | scan failed | | | {s['error']} |")
            continue
        r = s["report"]
        lines.append(
            f"| [{s['name']}]({s['url']}) | {r['conformance']} | {r['grade']} ({r['score']}/100) | "
            f"{r['coverage']['line']} | {_findings(r)} |"
        )
    lines += [
        "",
        "Coverage counts the checks that ran out of those that apply. The critical checks named as not run need a "
        "login, which the registry never does; `mcp-authlab login <url>` runs them for your own server.",
        "",
        "Raw results: " + ", ".join(f"[{d}](results/{d}.json)" for d in history),
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--date", default=time.strftime("%Y-%m-%d", time.gmtime()))
    args = ap.parse_args()
    results = scan_all(args.date)
    out_dir = HERE / "results"
    out_dir.mkdir(exist_ok=True)
    (out_dir / f"{args.date}.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    history = sorted((p.stem for p in out_dir.glob("*.json")), reverse=True)
    (HERE / "README.md").write_text(render(results, history), encoding="utf-8")
    for s in results["scans"]:
        if "error" in s:
            print(f"{s['name']}: {s['error']}")
        else:
            r = s["report"]
            print(f"{s['name']}: {r['conformance']} {r['grade']} · {r['coverage']['line']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
