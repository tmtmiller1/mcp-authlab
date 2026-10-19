"""Log in to and scan every fixture profile; assert the scanner flags exactly the defects that profile has."""

from __future__ import annotations

import unittest
import urllib.request
from dataclasses import fields

from support import FixtureCase, by_id, flagged, statuses

from mcp_authlab import catalog, checks, fixture, oauthclient


class ProfileTests(FixtureCase):
    def test_every_login_profile_flags_exactly_its_defects(self):
        for name in fixture.LOGIN_PROFILES:
            with self.subTest(profile=name):
                data = self.scan(name, mode="login")
                self.assertEqual(statuses(data, "error"), set(), data["results"])
                self.assertEqual(flagged(data), fixture.EXPECTED_FAILURES[name])

    def test_profiles_with_an_unreachable_as_scan_with_minted_tokens(self):
        for name in fixture.PROFILES:
            if name in fixture.LOGIN_PROFILES:
                continue
            with self.subTest(profile=name):
                data = self.scan(name, mode="dev")
                self.assertEqual(statuses(data, "error"), set())
                self.assertEqual(flagged(data), fixture.EXPECTED_FAILURES[name])

    def test_reference_runs_every_check_and_grades_a(self):
        data = self.scan("reference")
        self.assertEqual(data["grade"], "A")
        self.assertEqual(data["conformance"], "Conformant with warnings")  # TLS-01 on loopback
        self.assertEqual(statuses(data, "skip"), set(), "after a login no check should be skipped")
        n = len(catalog.CATALOG)
        self.assertEqual(data["coverage"]["ran"], n)
        self.assertEqual(data["coverage"]["line"], f"coverage {n}/{n}")
        self.assertEqual(data["login"]["issuer"], data["canonical"].rsplit("/mcp", 1)[0])

    def test_levels_and_grades(self):
        self.assertEqual(self.scan("passthrough")["conformance"], "Unsafe")
        self.assertEqual(self.scan("passthrough")["grade"], "F")
        self.assertEqual(self.scan("sloppy")["conformance"], "Unsafe")
        self.assertEqual(self.scan("open")["grade"], "F")
        self.assertEqual(self.scan("open")["conformance"], "Non-conformant")
        legacy = self.scan("legacy", mode="dev")
        self.assertEqual(legacy["conformance"], "Non-conformant")
        self.assertIn(legacy["grade"], ("C", "D"))
        self.assertEqual(self.scan("weak-as")["conformance"], "Non-conformant")
        self.assertEqual(self.scan("mismatch", mode="dev")["grade"], "F")

    def test_without_login_skips_token_checks_and_says_what_unlocks_them(self):
        data = self.scan("reference", mode="none")
        needs = {c.id for c in catalog.CATALOG if c.needs_token or c.needs_foreign_token or c.phase == catalog.LOGIN}
        self.assertEqual(statuses(data, "skip"), needs)
        self.assertEqual(data["grade"], "A")
        self.assertEqual(data["conformance"], "Conformant with warnings")
        self.assertEqual(data["coverage"]["critical_not_run"], ["TOK-03", "SESS-01"])
        self.assertIn("(run `mcp-authlab login` to enable)", data["coverage"]["line"])
        n = len(catalog.CATALOG)
        self.assertTrue(data["coverage"]["line"].startswith(f"coverage {n - len(needs)}/{n}"))
        for r in data["results"]:
            if r["status"] == "skip":
                self.assertIn("login", r["message"], r)

    def test_as_that_ignores_resource_indicator_is_reported_not_faked(self):
        data = self.scan("weak-as")
        tok3 = by_id(data)["TOK-03"]
        self.assertEqual(tok3["status"], "skip")
        self.assertIn("ignored resource=", tok3["message"])
        self.assertEqual(by_id(data)["ASF-04"]["status"], "fail")
        self.assertNotIn("run `mcp-authlab login`", data["coverage"]["line"])

    def test_explicit_tokens_win_over_the_store(self):
        state = self.start("reference")
        stored = self.login(state).to_store()
        data = checks.run(state.public_url, token=state.mint(), stored=stored, timeout=5)
        self.assertIsNone(data["login"])
        self.assertEqual(by_id(data)["ASF-01"]["status"], "skip")
        self.assertEqual(by_id(data)["TOK-06"]["status"], "pass")

    def test_bad_token_skips_the_dependent_checks(self):
        state = self.start("reference")
        data = checks.run(state.public_url, token="not-a-token", timeout=5)
        self.assertEqual(by_id(data)["TOK-06"]["status"], "fail")
        self.assertEqual(by_id(data)["SESS-01"]["message"], "token did not work")

    def test_stateless_server_marks_session_checks_not_applicable(self):
        data = self.scan("reference", flags=["stateless"])
        sess = by_id(data)["SESS-01"]
        self.assertEqual(sess["status"], "skip")
        self.assertFalse(sess["applicable"])
        self.assertEqual(data["coverage"]["applicable"], len(catalog.CATALOG) - 2)
        self.assertEqual(data["coverage"]["ran"], len(catalog.CATALOG) - 2)

    def test_bare_401_makes_prm04_not_applicable(self):
        data = self.scan("reference", flags=["bare_401"], mode="none")
        self.assertEqual(by_id(data)["CHAL-02"]["status"], "fail")
        prm4 = by_id(data)["PRM-04"]
        self.assertEqual(prm4["status"], "skip")
        self.assertFalse(prm4["applicable"])

    def test_scope_probe_skips_when_no_safe_tool(self):
        data = self.scan("reference", tool="echo-does-not-exist")
        self.assertEqual(by_id(data)["SCOPE-01"]["status"], "skip")
        self.assertIn("--tool", by_id(data)["SCOPE-01"]["message"])

    def test_scope_probe_passes_when_the_token_already_has_the_scope(self):
        state = self.start("reference")
        data = checks.run(state.public_url, token=state.mint(scope="mcp:tools mcp:admin"), timeout=5)
        r = by_id(data)["SCOPE-01"]
        self.assertEqual(r["status"], "pass")
        self.assertIn("already had enough scope", r["message"])

    def test_unreachable_server(self):
        data = checks.run("http://127.0.0.1:9/mcp", timeout=1)
        self.assertEqual(by_id(data)["CHAL-01"]["status"], "error")
        self.assertEqual(by_id(data)["TOK-01"]["message"], "server is unreachable")
        self.assertEqual((data["conformance"], data["grade"]), ("Non-conformant", "F"))

    def test_two_fixtures_in_one_process(self):
        a = self.start("reference")
        b = self.start("open")
        self.assertNotEqual(a.public_url, b.public_url)
        da = checks.run(a.public_url, token=a.mint(), timeout=5)
        db = checks.run(b.public_url, timeout=5)
        self.assertEqual(da["grade"], "A")
        self.assertEqual(db["grade"], "F")
        self.assertIn("'profile': 'reference'", by_id(da)["TOK-06"]["message"])
        self.assertEqual(by_id(db)["CHAL-01"]["status"], "fail")

    def test_fixture_speaks_mcp(self):
        state = self.start("reference")
        req = urllib.request.Request(
            state.public_url,
            data=checks.initialize_payload(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {state.mint()}",
            },
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertTrue(resp.headers.get("Mcp-Session-Id"))


class LoginTests(FixtureCase):
    def test_login_stores_tokens_and_results(self):
        state = self.start("reference")
        out = self.login(state)
        entry = out.to_store()
        self.assertTrue(entry["access_token"])
        self.assertTrue(entry["refresh_token"])
        self.assertTrue(entry["client_id"].startswith("fx-"))
        self.assertTrue(entry["foreign"]["usable"])
        self.assertEqual(entry["foreign"]["resource"], state.as_url)
        self.assertEqual({r["id"] for r in entry["asf"]}, {c.id for c in catalog.CATALOG if c.phase == catalog.LOGIN})
        self.assertTrue(all(r["status"] == "pass" for r in entry["asf"]), entry["asf"])

    def test_login_needs_client_id_without_registration(self):
        state = self.start("weak-as")
        with self.assertRaises(oauthclient.LoginError) as cm:
            self.login(state, client_id=None)
        self.assertIn("--client-id", str(cm.exception))

    def test_login_refuses_consent_page_without_browser(self):
        state = self.start("reference", auto_consent=False)
        with self.assertRaises(oauthclient.LoginError) as cm:
            self.login(state)
        self.assertIn("--auto-consent", str(cm.exception))

    def test_foreign_resource_override(self):
        state = self.start("reference")
        out = self.login(state, foreign_resource="https://elsewhere.example/api")
        self.assertEqual(out.foreign.resource, "https://elsewhere.example/api")
        self.assertTrue(out.foreign_usable)

    def test_refresh(self):
        state = self.start("reference")
        entry = self.login(state).to_store()
        old = entry["access_token"]
        entry["expires_at"] = 0
        refreshed = oauthclient.refresh(entry)
        self.assertIsNotNone(refreshed)
        self.assertNotEqual(refreshed["access_token"], old)
        data = checks.run(state.public_url, stored=refreshed, timeout=5)
        self.assertEqual(by_id(data)["TOK-06"]["status"], "pass")

    def test_profile_defects_match_the_dataclass(self):
        names = {f.name for f in fields(fixture.Profile)} - {"name"}
        self.assertEqual(set(fixture.DEFECTS), names)
        for f in fields(fixture.Profile):
            if f.name != "name":
                self.assertIn(f.type, (bool, "bool"))
        with self.assertRaises(SystemExit):
            fixture.profile_from_args("reference", ["no_such_flag"])
        p = fixture.profile_from_args("reference", ["open"])
        self.assertTrue(p.open)
        self.assertEqual(p.name, "reference+open")


if __name__ == "__main__":
    unittest.main()
