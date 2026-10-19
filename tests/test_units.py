"""Discovery, JWT helpers, SSE parsing, output formats, the report schema, docs freshness and CLI exit codes."""

from __future__ import annotations

import contextlib
import io
import json
import os
import time
import unittest
from email.message import Message
from typing import Any

from support import FixtureCase

from mcp_authlab import catalog, checks, cli, discovery, jwtutil, report, scanner
from mcp_authlab.httpclient import Response

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class DiscoveryTests(unittest.TestCase):
    def test_canonical(self):
        self.assertEqual(discovery.canonical("HTTPS://MCP.Example.com:443/mcp/"), "https://mcp.example.com/mcp")
        self.assertEqual(discovery.canonical("https://h:8443/x#frag"), "https://h:8443/x")
        self.assertEqual(discovery.canonical("http://h:80/"), "http://h")
        self.assertEqual(discovery.canonical("https://h/a?b=1"), "https://h/a?b=1")
        self.assertEqual(discovery.canonical("http://[::1]:8080/mcp"), "http://[::1]:8080/mcp")

    def test_loopback(self):
        for url in ("http://localhost/x", "http://127.0.0.1:1/x", "http://127.9.9.9/", "http://[::1]/"):
            self.assertTrue(discovery.is_loopback(url), url)
        self.assertFalse(discovery.is_loopback("https://mcp.example.com"))

    def test_wellknown_paths(self):
        self.assertEqual(
            discovery.protected_resource_metadata_urls("https://h/a/mcp"),
            ["https://h/.well-known/oauth-protected-resource/a/mcp", "https://h/.well-known/oauth-protected-resource"],
        )
        self.assertEqual(
            discovery.protected_resource_metadata_urls("https://h"), ["https://h/.well-known/oauth-protected-resource"]
        )
        self.assertEqual(
            [u for _, u in discovery.authorization_server_metadata_urls("https://as.example/tenant")],
            [
                "https://as.example/.well-known/oauth-authorization-server/tenant",
                "https://as.example/.well-known/openid-configuration/tenant",
                "https://as.example/tenant/.well-known/openid-configuration",
            ],
        )
        self.assertEqual(
            discovery.authorization_server_metadata_urls("https://as.example/"),
            [
                ("rfc8414", "https://as.example/.well-known/oauth-authorization-server"),
                ("oidc", "https://as.example/.well-known/openid-configuration"),
            ],
        )


class JwtTests(unittest.TestCase):
    def test_round_trip(self):
        key = b"k" * 32
        tok = jwtutil.encode({"aud": "a", "exp": int(time.time()) + 60}, key)
        self.assertEqual(jwtutil.verify_hs256(tok, key)["aud"], "a")
        header, claims, sig = jwtutil.decode_unverified(tok)
        self.assertEqual(header["alg"], "HS256")
        self.assertEqual(claims["aud"], "a")
        self.assertTrue(sig)

    def test_rejects(self):
        key = b"k" * 32
        good = jwtutil.encode({"aud": "a"}, key)
        with self.assertRaises(ValueError):
            jwtutil.verify_hs256(good, b"other")
        with self.assertRaises(ValueError):
            jwtutil.verify_hs256(jwtutil.unsigned("a"), key)  # alg none
        with self.assertRaises(ValueError):
            jwtutil.verify_hs256("a.b", key)
        with self.assertRaises(ValueError):
            jwtutil.verify_hs256(jwtutil.encode({"exp": int(time.time()) - 1}, key), key)
        with self.assertRaises(ValueError):
            jwtutil.decode_unverified("nope")

    def test_unsigned(self):
        tok = jwtutil.unsigned("https://r")
        self.assertTrue(tok.endswith("."))
        header, claims, sig = jwtutil.decode_unverified(tok)
        self.assertEqual((header["alg"], claims["aud"], sig), ("none", "https://r", ""))


def _resp(body: str, ctype: str, status: int = 200) -> Response:
    h = Message()
    h["Content-Type"] = ctype
    return Response(status, h, body.encode(), "http://x", 1)


class JsonRpcParsing(unittest.TestCase):
    def test_json_body(self):
        msg = scanner._jsonrpc_result(_resp('{"jsonrpc":"2.0","id":1,"result":{}}', "application/json"))
        self.assertEqual(msg["result"], {})
        self.assertIsNone(scanner._jsonrpc_result(_resp("[]", "application/json")))
        self.assertIsNone(scanner._jsonrpc_result(_resp("not json", "application/json")))

    def test_sse_body(self):
        sse = (
            "event: message\n"
            'data: {"jsonrpc":"2.0","method":"notifications/progress"}\n\n'
            ": comment\n"
            "event: message\n"
            'data: {"jsonrpc":"2.0",\n'
            'data:  "id":1,"result":{"ok":true}}\n\n'
        )
        msg = scanner._jsonrpc_result(_resp(sse, "text/event-stream; charset=utf-8"))
        self.assertEqual(msg["result"], {"ok": True})
        self.assertIsNone(scanner._jsonrpc_result(_resp("data: nope\n\n", "text/event-stream")))
        self.assertIsNone(scanner._jsonrpc_result(_resp("", "text/event-stream")))
        self.assertIsNone(scanner._jsonrpc_result(_resp('data: {"a":1}', "text/event-stream")))


# -- a hand-written validator for docs/report.schema.json ---------------------------------------


_TYPES: dict[str, Any] = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def validate(instance: Any, schema: dict[str, Any], root: dict[str, Any], path: str = "$") -> list[str]:
    errors: list[str] = []
    if "$ref" in schema:
        ref = schema["$ref"]
        assert ref.startswith("#/"), ref
        node: Any = root
        for part in ref[2:].split("/"):
            node = node[part]
        return validate(instance, node, root, path)
    types = schema.get("type")
    if types is not None:
        allowed = types if isinstance(types, list) else [types]
        ok = False
        for t in allowed:
            py = _TYPES[t]
            if t == "integer" and isinstance(instance, bool):
                continue
            if t == "number" and isinstance(instance, bool):
                continue
            if isinstance(instance, py):
                ok = True
        if not ok:
            errors.append(f"{path}: expected {allowed}, got {type(instance).__name__}")
            return errors
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in {schema['enum']}")
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: {instance!r} != {schema['const']!r}")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: {instance} < minimum {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: {instance} > maximum {schema['maximum']}")
    if isinstance(instance, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required {key!r}")
        for key, value in instance.items():
            if key in props:
                errors += validate(value, props[key], root, f"{path}.{key}")
            elif "additionalProperties" in schema:
                ap = schema["additionalProperties"]
                if ap is False:
                    errors.append(f"{path}: unexpected property {key!r}")
                elif isinstance(ap, dict):
                    errors += validate(value, ap, root, f"{path}.{key}")
    if isinstance(instance, list) and "items" in schema:
        for i, item in enumerate(instance):
            errors += validate(item, schema["items"], root, f"{path}[{i}]")
    return errors


class OutputTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        state = self.start("sloppy")
        self.data = checks.run(state.public_url, stored=self.login(state).to_store(), timeout=5)

    def test_json_matches_the_published_schema(self):
        with open(os.path.join(HERE, "docs", "report.schema.json"), encoding="utf-8") as fh:
            schema = json.load(fh)
        for requests in (False, True):
            data = json.loads(report.as_json(self.data, requests=requests))
            self.assertEqual(validate(data, schema, schema), [])
            self.assertEqual("requests" in data, requests)
        # The validator itself catches mistakes.
        broken = json.loads(report.as_json(self.data))
        broken["grade"] = "Z"
        broken["results"][0]["status"] = "maybe"
        del broken["coverage"]
        self.assertEqual(len(validate(broken, schema, schema)), 3)

    def test_first_lines_carry_coverage(self):
        text = report.terminal(self.data, color=False)
        lines = text.splitlines()
        self.assertTrue(lines[2].startswith("coverage "), lines[:3])
        self.assertIn("level    Unsafe", lines[3])
        self.assertIn("MUST*", text)
        md = report.markdown(self.data)
        self.assertTrue(md.splitlines()[2].startswith("coverage "))
        self.assertIn("| ✗ | SESS-01 | MUST\\* |", md)
        color = report.terminal(self.data, color=True)
        self.assertIn("\x1b[", color)
        verbose = report.terminal(self.data, color=False, verbose=True)
        self.assertGreater(len(verbose.splitlines()), len(lines))

    def test_sarif(self):
        doc = json.loads(report.sarif(self.data))
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        self.assertEqual(set(rules), set(catalog.BY_ID))
        self.assertEqual(rules["TOK-03"]["helpUri"], catalog.BY_ID["TOK-03"].url)
        results = {r["ruleId"]: r for r in run["results"]}
        self.assertEqual(len(results), len(self.data["results"]))
        self.assertEqual((results["SESS-01"]["level"], results["SESS-01"]["kind"]), ("error", "fail"))
        self.assertEqual((results["TOK-05"]["level"], results["TOK-05"]["kind"]), ("error", "fail"))
        self.assertEqual((results["SESS-02"]["level"], results["SESS-02"]["kind"]), ("warning", "fail"))
        self.assertEqual((results["TOK-01"]["level"], results["TOK-01"]["kind"]), ("none", "pass"))
        self.assertEqual(run["properties"]["coverage"], self.data["coverage"]["line"])
        loc = results["SESS-01"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(loc, self.data["target"])

    def test_policy_notes_in_output(self):
        from mcp_authlab import policy

        pol = policy.parse('ignore = ["SESS-01"]\ndowngrade = { "ORIG-01" = "SHOULD" }')
        pol.apply([])
        data = dict(self.data)
        data["results"] = [dict(r) for r in self.data["results"]]
        for r in data["results"]:
            if r["id"] == "SESS-01":
                r["counted"] = False
            if r["id"] == "ORIG-01":
                r["effective_level"] = "SHOULD"
                r["effective_critical"] = False
        text = report.terminal(data, color=False)
        self.assertIn("ignored by policy", text)
        self.assertIn("SHOULD↓", text)
        self.assertIn("downgraded from MUST by policy", report.markdown(data))
        sarif = json.loads(report.sarif(data))
        orig = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "ORIG-01")
        self.assertEqual(orig["level"], "warning")


class DocsFreshness(unittest.TestCase):
    def test_checks_md_matches_the_catalog(self):
        with open(os.path.join(HERE, "docs", "checks.md"), encoding="utf-8") as fh:
            hint = "run: mcp-authlab checks --markdown > docs/checks.md"
            self.assertEqual(fh.read(), catalog.markdown_table() + "\n", hint)

    def test_grading_doc_carries_the_same_numbers(self):
        from mcp_authlab.grading import GRADING

        with open(os.path.join(HERE, "docs", "grading.md"), encoding="utf-8") as fh:
            doc = fh.read()
        for key, value in GRADING["weights"].items():
            self.assertIn(f"| {key} | {value} |", doc)
        for letter, floor in GRADING["thresholds"]:
            self.assertIn(f"| {letter} | {floor} |", doc)
        self.assertIn(f"capped at **{GRADING['must_failure_cap']}**", doc)

    def test_disputed_checks_are_still_must(self):
        for cid in ("ORIG-01", "VER-01"):
            c = catalog.BY_ID[cid]
            self.assertEqual(c.level, "MUST")
            self.assertTrue(c.disputed)
            self.assertIn(cid, catalog.markdown_table())


class CliTests(FixtureCase):
    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_scan_exit_codes(self):
        state = self.start("sloppy")
        code, out, _ = self.run_cli("scan", state.public_url, "--no-color", "--token", state.mint())
        self.assertEqual(code, 0)
        self.assertIn("level    Unsafe", out)
        code, _, err = self.run_cli(
            "scan", state.public_url, "--no-color", "--fail-under", "B", "--token", state.mint()
        )
        self.assertEqual(code, 2)
        self.assertIn("below --fail-under B", err)
        code, _, _ = self.run_cli("scan", state.public_url, "--no-color", "--fail-under", "F")
        self.assertEqual(code, 0)

    def test_login_then_scan_uses_the_store(self):
        state = self.start("reference")
        code, out, _ = self.run_cli("login", state.public_url, "--no-browser", "--no-color", "--timeout", "5")
        self.assertEqual(code, 0, out)
        self.assertIn("tokens saved to", out)
        self.assertIn("TOK-03 will run", out)
        self.assertEqual(oct(os.stat(os.environ["MCP_AUTHLAB_TOKENS"]).st_mode & 0o777), "0o600")
        code, out, _ = self.run_cli("scan", state.public_url, "--no-color")
        self.assertEqual(code, 0)
        self.assertIn(f"coverage {len(catalog.CATALOG)}/{len(catalog.CATALOG)}", out)
        self.assertIn("login    ", out)
        code, out, _ = self.run_cli("scan", state.public_url, "--no-color", "--no-login")
        self.assertIn("critical checks not run", out)
        code, out, _ = self.run_cli("logout", state.public_url)
        self.assertEqual(code, 0)
        code, _, _ = self.run_cli("logout", state.public_url)
        self.assertEqual(code, 1)

    def test_login_failure_exit_code(self):
        state = self.start("weak-as")
        code, _, err = self.run_cli("login", state.public_url, "--no-browser", "--timeout", "5")
        self.assertEqual(code, 1)
        self.assertIn("--client-id", err)

    def test_policy_fail_under_and_formats(self):
        state = self.start("reference", ["ignore_origin"])
        pol = os.path.join(self._tmp.name, "p.toml")
        with open(pol, "w", encoding="utf-8") as fh:
            fh.write('fail_under = "A"\n')
        code, _, _ = self.run_cli("scan", state.public_url, "--token", state.mint(), "--policy", pol, "--no-color")
        self.assertEqual(code, 2)
        with open(pol, "w", encoding="utf-8") as fh:
            fh.write('fail_under = "A"\nignore = ["ORIG-01"]\n')
        code, _, _ = self.run_cli("scan", state.public_url, "--token", state.mint(), "--policy", pol, "--no-color")
        self.assertEqual(code, 0)
        for fmt in ("json", "markdown", "sarif"):
            out_path = os.path.join(self._tmp.name, f"r.{fmt}")
            code, _, err = self.run_cli("scan", state.public_url, "--format", fmt, "-o", out_path)
            self.assertEqual(code, 0)
            self.assertIn("coverage ", err)
            with open(out_path, encoding="utf-8") as fh:
                body = fh.read()
            if fmt != "markdown":
                json.loads(body)
        with open(pol, "w", encoding="utf-8") as fh:
            fh.write("ignore = ['NOPE']\n")
        with self.assertRaises(SystemExit):
            self.run_cli("scan", state.public_url, "--policy", pol)

    def test_checks_listing(self):
        code, out, _ = self.run_cli("checks")
        self.assertEqual(code, 0)
        self.assertIn("TOK-02", out)
        code, out, _ = self.run_cli("checks", "--markdown")
        self.assertEqual(out.rstrip("\n"), catalog.markdown_table())


if __name__ == "__main__":
    unittest.main()
