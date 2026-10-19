"""Scan every fixture profile and assert the scanner flags exactly the defects that profile has."""

from __future__ import annotations

import threading
import unittest
import urllib.request

from mcp_authlab import checks, fixture, wwwauth, discovery


class FixtureCase(unittest.TestCase):
    def start(self, name: str):
        srv, state = fixture.serve(fixture.PROFILES[name])
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return state

    def scan(self, name: str, with_tokens: bool = True) -> dict:
        state = self.start(name)
        token = foreign = None
        if with_tokens:
            token = state.mint()
            foreign = state.mint(aud="https://other.example/mcp")
        return checks.run(state.public_url, token=token, foreign_token=foreign, timeout=5)

    def flagged(self, data: dict) -> set[str]:
        return {r["id"] for r in data["results"] if r["status"] in ("fail", "warn") and r["id"] != "TLS-01"}

    def errors(self, data: dict) -> set[str]:
        return {r["id"] for r in data["results"] if r["status"] == "error"}


class ProfileTests(FixtureCase):
    def test_every_profile_flags_exactly_its_defects(self):
        for name, expected in fixture.EXPECTED_FAILURES.items():
            with self.subTest(profile=name):
                data = self.scan(name)
                self.assertEqual(self.errors(data), set(), data["results"])
                self.assertEqual(self.flagged(data), expected)

    def test_reference_grades_a(self):
        data = self.scan("reference")
        self.assertEqual(data["grade"], "A")
        skipped = {r["id"] for r in data["results"] if r["status"] == "skip"}
        self.assertEqual(skipped, set(), "with both tokens no check should be skipped")

    def test_grades(self):
        self.assertEqual(self.scan("passthrough")["grade"], "F")
        self.assertEqual(self.scan("open")["grade"], "F")
        self.assertEqual(self.scan("sloppy")["grade"], "F")
        self.assertIn(self.scan("legacy")["grade"], ("C", "D"))
        self.assertIn(self.scan("weak-as")["grade"], ("B", "C"))
        self.assertIn(self.scan("mismatch")["grade"], ("F",))

    def test_without_tokens_skips_authenticated_checks(self):
        data = self.scan("reference", with_tokens=False)
        skipped = {r["id"] for r in data["results"] if r["status"] == "skip"}
        self.assertEqual(skipped, {c.id for c in checks.CATALOG if c.needs_token or c.needs_foreign_token})
        self.assertEqual(data["grade"], "A")

    def test_fixture_speaks_mcp(self):
        state = self.start("reference")
        req = urllib.request.Request(state.public_url, data=checks.initialize_payload(), method="POST",
                                     headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                                              "Authorization": f"Bearer {state.mint()}"})
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertTrue(resp.headers.get("Mcp-Session-Id"))


class UnitTests(unittest.TestCase):
    def test_wwwauth_parsing(self):
        ch = wwwauth.bearer(['Bearer realm="x", resource_metadata="https://h/.well-known/oauth-protected-resource", scope="a b"'])
        self.assertEqual(ch.params["resource_metadata"], "https://h/.well-known/oauth-protected-resource")
        self.assertEqual(ch.params["scope"], "a b")
        multi = wwwauth.parse(['Basic realm="r"', 'Bearer error="invalid_token", error_description="bad \\"sig\\""'])
        self.assertEqual([c.scheme for c in multi], ["Basic", "Bearer"])
        self.assertEqual(multi[1].params["error_description"], 'bad "sig"')
        self.assertIsNone(wwwauth.bearer(["Basic realm=x"]))

    def test_canonical(self):
        self.assertEqual(discovery.canonical("HTTPS://MCP.Example.com:443/mcp/"), "https://mcp.example.com/mcp")
        self.assertEqual(discovery.canonical("https://h:8443/x#frag"), "https://h:8443/x")

    def test_wellknown_paths(self):
        self.assertEqual(discovery.protected_resource_metadata_urls("https://h/a/mcp"),
                         ["https://h/.well-known/oauth-protected-resource/a/mcp", "https://h/.well-known/oauth-protected-resource"])
        self.assertEqual([u for _, u in discovery.authorization_server_metadata_urls("https://as.example/tenant")],
                         ["https://as.example/.well-known/oauth-authorization-server/tenant",
                          "https://as.example/.well-known/openid-configuration/tenant",
                          "https://as.example/tenant/.well-known/openid-configuration"])

    def test_grade_rules(self):
        def res(cid, status):
            return checks.Result(checks.BY_ID[cid], status, "")
        all_pass = [res(c.id, "pass") for c in checks.CATALOG]
        self.assertEqual(checks.grade(all_pass)[0], "A")
        one_critical = [res(c.id, "fail" if c.id == "TOK-02" else "pass") for c in checks.CATALOG]
        self.assertEqual(checks.grade(one_critical)[0], "F")
        one_should = [res(c.id, "warn" if c.id == "CHAL-03" else "pass") for c in checks.CATALOG]
        self.assertEqual(checks.grade(one_should)[0], "A")
        one_must = [res(c.id, "fail" if c.id == "PRM-01" else "pass") for c in checks.CATALOG]
        self.assertIn(checks.grade(one_must)[0], ("C", "D"))


if __name__ == "__main__":
    unittest.main()
