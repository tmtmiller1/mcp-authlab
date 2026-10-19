"""Command line entry point."""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from typing import Any

from . import SPEC_VERSION, __version__, catalog, checks, discovery, fixture, oauthclient, policy, report, tokenstore
from .grading import GRADE_ORDER
from .policy import PolicyError


def _render(args: argparse.Namespace, data: dict[str, Any]) -> str:
    color = False if args.no_color else None
    return report.render(data, args.format, color=color, verbose=args.verbose, requests=args.requests)


def _load_policy(path: str | None) -> policy.Policy | None:
    if not path:
        return None
    try:
        return policy.load(path)
    except PolicyError as e:
        raise SystemExit(f"mcp-authlab: {e}") from e


def _stored_tokens(url: str, use_store: bool) -> dict[str, Any] | None:
    if not use_store:
        return None
    canonical = discovery.canonical(url)
    entry = tokenstore.get(canonical)
    if not entry:
        return None
    changed = False
    if tokenstore.is_expired(entry):
        if oauthclient.refresh(entry):
            changed = True
        else:
            print("the stored access token has expired; run `mcp-authlab login` again", file=sys.stderr)
    foreign = entry.get("foreign")
    if isinstance(foreign, dict) and foreign.get("access_token") and tokenstore.is_expired(foreign):
        if oauthclient.refresh(entry, foreign=True):
            changed = True
        else:
            print("the foreign-audience token has expired, so TOK-03 will be skipped", file=sys.stderr)
    if changed:
        try:
            tokenstore.put(canonical, entry)
        except tokenstore.TokenStoreError as e:
            print(f"couldn't save the refreshed tokens: {e}", file=sys.stderr)
    return entry


def _cmd_scan(args: argparse.Namespace) -> int:
    token = args.token or os.environ.get("MCP_AUTHLAB_TOKEN")
    foreign = args.foreign_token or os.environ.get("MCP_AUTHLAB_FOREIGN_TOKEN")
    pol = _load_policy(args.policy)
    stored = _stored_tokens(args.url, use_store=not args.no_login and not token)
    data = checks.run(
        args.url,
        token=token,
        foreign_token=foreign,
        timeout=args.timeout,
        insecure=args.insecure,
        policy=pol,
        stored=stored,
        tool=args.tool,
    )
    out = _render(args, data)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(
            f"wrote {args.output}  ({data['conformance']}, grade {data['grade']}, {data['coverage']['line']})",
            file=sys.stderr,
        )
    else:
        print(out)
    fail_under = (args.fail_under or (pol.fail_under if pol else None) or "").upper()
    if fail_under:
        if fail_under not in GRADE_ORDER:
            raise SystemExit(f"mcp-authlab: --fail-under must be one of {', '.join(GRADE_ORDER)}")
        if GRADE_ORDER[data["grade"]] < GRADE_ORDER[fail_under]:
            print(f"grade {data['grade']} is below --fail-under {fail_under}", file=sys.stderr)
            return 2
    return 0


def _cmd_login(args: argparse.Namespace) -> int:
    login = oauthclient.Login(
        args.url,
        client_id=args.client_id,
        foreign_resource=args.foreign_resource,
        scope=args.scope,
        no_browser=args.no_browser,
        timeout=args.timeout,
        http_timeout=args.http_timeout,
        insecure=args.insecure,
        redirect_port=args.redirect_port,
        thorough=True if args.thorough else None,
    )
    try:
        outcome = login.run()
    except oauthclient.LoginError as e:
        print(f"login failed: {e}", file=sys.stderr)
        return 1
    try:
        path = tokenstore.put(outcome.canonical, outcome.to_store())
    except tokenstore.TokenStoreError as e:
        print(f"login worked, but the tokens couldn't be saved: {e}", file=sys.stderr)
        return 1
    color = False if args.no_color else sys.stdout.isatty()
    print(f"logged in to {outcome.canonical} via {outcome.issuer}")
    print("authorization server flow checks:")
    for r in outcome.results:
        sym = report.status_symbol(r.status, color)
        print(f"  {sym} {r.check.id:<9}{r.check.level:<7}{r.check.title}")
        if r.status != "pass":
            print(f"              {r.message}")
    if outcome.foreign_usable:
        print(
            f"foreign-audience token minted for {outcome.foreign.resource if outcome.foreign else ''}; TOK-03 will run"
        )
    else:
        print(f"TOK-03 won't run: {outcome.foreign_note}")
    print(f"tokens saved to {path} (mode 0600). Now run: mcp-authlab scan {args.url}")
    return 0


def _cmd_logout(args: argparse.Namespace) -> int:
    try:
        removed = tokenstore.remove(discovery.canonical(args.url))
    except tokenstore.TokenStoreError as e:
        print(f"mcp-authlab: {e}", file=sys.stderr)
        return 1
    if removed:
        print("removed stored tokens for " + discovery.canonical(args.url))
        return 0
    print("not logged in to " + discovery.canonical(args.url), file=sys.stderr)
    return 1


def _cmd_fixture(args: argparse.Namespace) -> int:
    profile = fixture.profile_from_args(args.profile, args.flag or [])
    srv, state = fixture.serve(
        profile, args.host, args.port, args.public_url, verbose=args.verbose, auto_consent=args.auto_consent
    )
    print(
        f"mcp-authlab fixture  profile={profile.name}" + ("  (auto-consent)" if args.auto_consent else ""),
        file=sys.stderr,
    )
    print(f"  MCP endpoint   {state.public_url}", file=sys.stderr)
    print(
        f"  login          mcp-authlab login {state.public_url}" + (" --no-browser" if args.auto_consent else ""),
        file=sys.stderr,
    )
    print(f"  demo token     curl -s {state.as_url}/dev/token", file=sys.stderr)
    print(f"  foreign token  curl -s '{state.as_url}/dev/token?aud=https://other.example/mcp'", file=sys.stderr)
    if args.print_token:
        print(state.mint())
        sys.stdout.flush()
    with contextlib.suppress(KeyboardInterrupt):
        srv.serve_forever(poll_interval=0.05)
    return 0


def _cmd_checks(args: argparse.Namespace) -> int:
    if args.markdown:
        print(catalog.markdown_table())
    else:
        for c in catalog.CATALOG:
            flag = "*" if c.critical else " "
            print(f"{c.id:<9}{c.level:<6}{flag} {c.title}")
            print(f"          {c.cite}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="mcp-authlab",
        description=f"Conformance scanner for MCP server authorization (spec {SPEC_VERSION}).",
    )
    p.add_argument("--version", action="version", version=f"mcp-authlab {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a live MCP server endpoint and grade it")
    s.add_argument("url", help="MCP endpoint, e.g. https://mcp.example.com/mcp")
    s.add_argument(
        "--token", help="a valid access token for this server (or MCP_AUTHLAB_TOKEN); `login` stores one for you"
    )
    s.add_argument(
        "--foreign-token",
        help="a valid token from the same authorization server minted for a different resource "
        "(or MCP_AUTHLAB_FOREIGN_TOKEN); `login` mints one for you",
    )
    s.add_argument("--no-login", action="store_true", help="ignore tokens stored by `login`")
    s.add_argument(
        "--policy", metavar="FILE", help="TOML policy: fail_under, ignore, downgrade (see examples/policy.toml)"
    )
    s.add_argument("--tool", help="the tool SCOPE-01 calls; by default a read-only one chosen from tools/list")
    s.add_argument("--format", choices=report.FORMATS, default="text")
    s.add_argument("--output", "-o", help="write the report to a file instead of stdout")
    s.add_argument("--fail-under", metavar="GRADE", help="exit 2 if the grade is below this letter (for CI), e.g. B")
    s.add_argument("--timeout", type=float, default=10.0)
    s.add_argument("--insecure", action="store_true", help="skip TLS certificate checks")
    s.add_argument("--requests", action="store_true", help="include every HTTP exchange in JSON output")
    s.add_argument("--verbose", "-v", action="store_true", help="show evidence for passing checks too")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(func=_cmd_scan)

    lg = sub.add_parser("login", help="sign in to a server's authorization server and store tokens for scan")
    lg.add_argument("url", help="MCP endpoint, e.g. https://mcp.example.com/mcp")
    lg.add_argument("--client-id", help="use this client_id instead of dynamic registration")
    lg.add_argument(
        "--foreign-resource", help="resource URI for the second token (default: the authorization server's issuer)"
    )
    lg.add_argument("--scope", help="scopes to request (default: let the server decide)")
    lg.add_argument(
        "--no-browser",
        action="store_true",
        help="print the URL instead of opening a browser; fetch it directly on loopback",
    )
    lg.add_argument("--timeout", type=float, default=300.0, help="seconds to wait for the browser to come back")
    lg.add_argument("--http-timeout", type=float, default=10.0)
    lg.add_argument(
        "--redirect-port", type=int, default=0, help="fixed loopback port for the redirect URI (default: any free port)"
    )
    lg.add_argument(
        "--thorough",
        action="store_true",
        help="run the redirect_uri probe even when the authorization server revokes codes after a failed "
        "exchange, which costs one more sign-in (default on loopback with --no-browser)",
    )
    lg.add_argument("--insecure", action="store_true", help="skip TLS certificate checks")
    lg.add_argument("--no-color", action="store_true")
    lg.set_defaults(func=_cmd_login)

    lo = sub.add_parser("logout", help="forget stored tokens for a server")
    lo.add_argument("url")
    lo.set_defaults(func=_cmd_logout)

    f = sub.add_parser("fixture", help="run the reference server, or one of its broken profiles, locally")
    f.add_argument("--profile", default="reference", help=", ".join(fixture.PROFILES))
    f.add_argument("--flag", action="append", help="turn on one defect flag (repeatable), e.g. --flag skip_audience")
    f.add_argument("--host", default="127.0.0.1")
    f.add_argument("--port", type=int, default=8765)
    f.add_argument(
        "--public-url", help="the URL clients use, if different from host:port (sets the canonical resource)"
    )
    f.add_argument(
        "--auto-consent", action="store_true", help="approve every authorization request without a consent page"
    )
    f.add_argument("--print-token", action="store_true", help="print a demo token on stdout at startup")
    f.add_argument("--verbose", "-v", action="store_true")
    f.set_defaults(func=_cmd_fixture)

    c = sub.add_parser("checks", help="list the check catalog with citations")
    c.add_argument("--markdown", action="store_true")
    c.set_defaults(func=_cmd_checks)

    args = p.parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
