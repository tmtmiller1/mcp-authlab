"""Command line entry point."""

from __future__ import annotations

import argparse
import os
import sys

from . import SPEC_VERSION, __version__, checks, fixture, report


def _cmd_scan(args: argparse.Namespace) -> int:
    token = args.token or os.environ.get("MCP_AUTHLAB_TOKEN")
    foreign = args.foreign_token or os.environ.get("MCP_AUTHLAB_FOREIGN_TOKEN")
    data = checks.run(args.url, token=token, foreign_token=foreign, timeout=args.timeout, insecure=args.insecure)
    if args.format == "json":
        out = report.as_json(data, requests=args.requests)
    elif args.format == "markdown":
        out = report.markdown(data)
    else:
        out = report.terminal(data, color=(False if args.no_color else None), verbose=args.verbose)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"wrote {args.output}  (grade {data['grade']}, score {data['score']})", file=sys.stderr)
    else:
        print(out)
    if args.fail_under:
        if checks.GRADE_ORDER[data["grade"]] < checks.GRADE_ORDER[args.fail_under.upper()]:
            print(f"grade {data['grade']} is below --fail-under {args.fail_under.upper()}", file=sys.stderr)
            return 2
    return 0


def _cmd_fixture(args: argparse.Namespace) -> int:
    profile = fixture.profile_from_args(args.profile, args.flag or [])
    srv, state = fixture.serve(profile, args.host, args.port, args.public_url, verbose=args.verbose)
    print(f"mcp-authlab fixture  profile={profile.name}", file=sys.stderr)
    print(f"  MCP endpoint   {state.public_url}", file=sys.stderr)
    print(f"  demo token     curl -s {state.as_url}/dev/token", file=sys.stderr)
    print(f"  foreign token  curl -s '{state.as_url}/dev/token?aud=https://other.example/mcp'", file=sys.stderr)
    if args.print_token:
        print(state.mint())
        sys.stdout.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def _cmd_checks(args: argparse.Namespace) -> int:
    if args.markdown:
        print("| ID | Level | Check | Needs | Normative source |")
        print("|---|---|---|---|---|")
        for c in checks.CATALOG:
            lvl = c.level + ("\\*" if c.critical else "")
            needs = "`--token`" if c.needs_token else ("`--foreign-token`" if c.needs_foreign_token else "")
            print(f"| {c.id} | {lvl} | {c.title} | {needs} | [{c.cite}]({c.url}) |")
        print()
        print("MUST\\* is a critical check: one failure grades the server F on its own.")
    else:
        for c in checks.CATALOG:
            flag = "*" if c.critical else " "
            print(f"{c.id:<8} {c.level:<6}{flag} {c.title}")
            print(f"         {c.cite}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mcp-authlab", description=f"Black-box conformance scanner for MCP server authorization (spec {SPEC_VERSION}).")
    p.add_argument("--version", action="version", version=f"mcp-authlab {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a live MCP server endpoint and grade it")
    s.add_argument("url", help="MCP endpoint, e.g. https://mcp.example.com/mcp")
    s.add_argument("--token", help="a valid access token for this server (or MCP_AUTHLAB_TOKEN); unlocks session, origin, and query-string checks")
    s.add_argument("--foreign-token", help="a valid token from the same authorization server minted for a different resource (or MCP_AUTHLAB_FOREIGN_TOKEN); unlocks the audience check")
    s.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    s.add_argument("--output", "-o", help="write the report to a file instead of stdout")
    s.add_argument("--fail-under", metavar="GRADE", help="exit 2 if the grade is below this letter (for CI), e.g. B")
    s.add_argument("--timeout", type=float, default=10.0)
    s.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    s.add_argument("--requests", action="store_true", help="include every HTTP exchange in JSON output")
    s.add_argument("--verbose", "-v", action="store_true", help="show evidence for passing checks too")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(func=_cmd_scan)

    f = sub.add_parser("fixture", help="run the reference server (or a deliberately broken profile) locally")
    f.add_argument("--profile", default="reference", help=", ".join(fixture.PROFILES))
    f.add_argument("--flag", action="append", help="turn on one defect flag (repeatable), e.g. --flag skip_audience")
    f.add_argument("--host", default="127.0.0.1")
    f.add_argument("--port", type=int, default=8765)
    f.add_argument("--public-url", help="the URL clients use, if different from host:port (sets the canonical resource)")
    f.add_argument("--print-token", action="store_true", help="print a demo token on stdout at startup")
    f.add_argument("--verbose", "-v", action="store_true")
    f.set_defaults(func=_cmd_fixture)

    c = sub.add_parser("checks", help="list the check catalog with citations")
    c.add_argument("--markdown", action="store_true")
    c.set_defaults(func=_cmd_checks)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
