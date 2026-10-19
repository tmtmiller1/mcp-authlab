"""Conformance level, letter grade and policy files on synthetic result sets."""

from __future__ import annotations

import os
import unittest

from support import FixtureCase, by_id

from mcp_authlab import catalog, checks, policy
from mcp_authlab.catalog import FAIL, PASS, SKIP, WARN, Result
from mcp_authlab.grading import GRADING, conformance_level, coverage, grade


def results(**overrides: str) -> list[Result]:
    return [Result(c, overrides.get(c.id, PASS), "") for c in catalog.CATALOG]


class GradeRules(unittest.TestCase):
    def test_all_pass_is_conformant_a(self):
        g = grade(results())
        self.assertEqual((g.level, g.letter, g.score), ("Conformant", "A", 100))
        self.assertEqual(g.reasons, [])

    def test_critical_failure_is_unsafe_f(self):
        g = grade(results(**{"TOK-02": FAIL}))
        self.assertEqual((g.level, g.letter), ("Unsafe", "F"))
        self.assertEqual(g.critical_failures, ["TOK-02"])
        self.assertIn("critical failure: TOK-02", g.reasons)

    def test_open_server_is_f_without_being_unsafe(self):
        g = grade(results(**{"CHAL-01": FAIL}))
        self.assertEqual((g.level, g.letter), ("Non-conformant", "F"))
        self.assertIn("server doesn't challenge unauthenticated requests", g.reasons)

    def test_must_failure_caps_at_c(self):
        g = grade(results(**{"PRM-01": FAIL}))
        self.assertEqual(g.level, "Non-conformant")
        self.assertEqual(g.letter, GRADING["must_failure_cap"])
        self.assertGreaterEqual(g.score, 95)  # the score alone would be an A

    def test_many_must_failures_fall_below_the_cap(self):
        ids = ["PRM-01", "PRM-02", "PRM-03", "ASM-01", "ASM-02", "ASM-03", "ASM-04", "TOK-01", "TOK-05", "TOK-06"]
        ids.append("ORIG-01")
        g = grade(results(**dict.fromkeys(ids, FAIL)))
        self.assertEqual(g.level, "Non-conformant")
        self.assertIn(g.letter, ("D", "F"))

    def test_should_warning_is_conformant_with_warnings(self):
        g = grade(results(**{"CHAL-03": WARN}))
        self.assertEqual((g.level, g.letter), ("Conformant with warnings", "A"))
        self.assertEqual(g.warnings, ["CHAL-03"])
        self.assertIn("warnings: CHAL-03", g.reasons)

    def test_must_warning_earns_half_credit(self):
        g = grade(results(**{"VER-01": WARN}))
        total = sum(GRADING["weights"]["critical" if c.critical else c.level] for c in catalog.CATALOG)
        expected = round(100 * (total - GRADING["weights"]["MUST"] * 0.5) / total)
        self.assertEqual(g.score, expected)
        self.assertEqual(g.level, "Conformant with warnings")

    def test_thresholds(self):
        # Fail enough SHOULD checks to walk the score down through each letter.
        shoulds = [c.id for c in catalog.CATALOG if c.level == "SHOULD"]
        g = grade(results(**dict.fromkeys(shoulds, WARN)))
        total = sum(GRADING["weights"]["critical" if c.critical else c.level] for c in catalog.CATALOG)
        self.assertEqual(g.score, round(100 * (total - 3 * len(shoulds)) / total))
        self.assertEqual(g.letter, next(name for name, floor in GRADING["thresholds"] if g.score >= floor))

    def test_skips_and_errors_stay_out_of_the_denominator(self):
        ids = [c.id for c in catalog.CATALOG if c.needs_token]
        g = grade(results(**dict.fromkeys(ids, SKIP)))
        self.assertEqual((g.letter, g.score), ("A", 100))
        g = grade(results(**{"CHAL-01": "error"}))
        self.assertEqual(g.score, 100)

    def test_empty_results(self):
        g = grade([])
        self.assertEqual((g.level, g.letter, g.score), ("Conformant", "F", 0))

    def test_level_order(self):
        self.assertEqual(conformance_level(results(**{"TOK-02": FAIL, "PRM-01": FAIL})), "Unsafe")
        self.assertEqual(conformance_level(results(**{"PRM-01": FAIL, "CHAL-03": WARN})), "Non-conformant")
        self.assertEqual(conformance_level(results(**{"CHAL-03": WARN})), "Conformant with warnings")
        self.assertEqual(conformance_level(results()), "Conformant")

    def test_coverage_counts_only_applicable_checks(self):
        rs = results(**{"SESS-01": SKIP, "SESS-02": SKIP, "TOK-03": SKIP})
        for r in rs:
            if r.check.id.startswith("SESS"):
                r.applicable = False
            if r.check.id == "TOK-03":
                r.evidence["needs_login"] = True
        cov = coverage(rs)
        self.assertEqual((cov["ran"], cov["applicable"]), (len(rs) - 3, len(rs) - 2))
        self.assertEqual(cov["critical_not_run"], ["TOK-03"])
        self.assertTrue(cov["login_helps"])


class PolicyRules(FixtureCase):
    def write(self, text: str) -> str:
        path = os.path.join(self._tmp.name, "policy.toml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_parse(self):
        pol = policy.parse('fail_under = "b"\nignore = ["VER-01"]\ndowngrade = { "ORIG-01" = "SHOULD" }\n')
        self.assertEqual((pol.fail_under, pol.ignore, pol.downgrade), ("B", ["VER-01"], {"ORIG-01": "SHOULD"}))
        self.assertEqual(policy.parse("").fail_under, None)

    def test_rejects_bad_policies(self):
        for text in (
            "fail_under = 'Z'",
            "ignore = ['NOPE-01']",
            "downgrade = { 'VER-01' = 'MAYBE' }",
            "downgrade = { 'NOPE-01' = 'SHOULD' }",
            "ignore = 'VER-01'",
            "surprise = 1",
            "this is not toml",
        ):
            with self.subTest(text=text), self.assertRaises(policy.PolicyError):
                policy.parse(text)
        with self.assertRaises(policy.PolicyError):
            policy.load(os.path.join(self._tmp.name, "missing.toml"))

    def test_ignored_check_still_runs_but_stops_counting(self):
        pol = policy.parse('ignore = ["ORIG-01"]')
        rs = results(**{"ORIG-01": FAIL})
        pol.apply(rs)
        g = grade(rs)
        self.assertEqual((g.level, g.letter, g.score), ("Conformant", "A", 100))
        self.assertEqual(g.ignored, ["ORIG-01"])
        self.assertIn("ignored by policy: ORIG-01", g.reasons)
        self.assertEqual(next(r for r in rs if r.check.id == "ORIG-01").status, FAIL)

    def test_downgrade_counts_at_the_new_level(self):
        pol = policy.parse('downgrade = { "ORIG-01" = "SHOULD" }')
        rs = results(**{"ORIG-01": FAIL})
        pol.apply(rs)
        g = grade(rs)
        self.assertEqual(g.level, "Conformant with warnings")
        self.assertEqual(g.letter, "A")
        self.assertEqual(g.must_failures, [])
        r = next(r for r in rs if r.check.id == "ORIG-01")
        self.assertEqual((r.level, r.critical, r.to_dict()["effective_level"]), ("SHOULD", False, "SHOULD"))

    def test_downgrading_a_critical_check_removes_critical(self):
        pol = policy.parse('downgrade = { "TOK-02" = "SHOULD" }')
        rs = results(**{"TOK-02": FAIL})
        pol.apply(rs)
        self.assertEqual(grade(rs).level, "Conformant with warnings")

    def test_policy_changes_a_real_scan(self):
        state = self.start("reference", ["ignore_origin"])
        plain = checks.run(state.public_url, token=state.mint(), timeout=5)
        self.assertEqual((plain["conformance"], plain["grade"]), ("Non-conformant", "C"))
        pol = policy.load(self.write('ignore = ["ORIG-01"]\n'))
        data = checks.run(state.public_url, token=state.mint(), timeout=5, policy=pol)
        self.assertEqual((data["conformance"], data["grade"]), ("Conformant with warnings", "A"))
        self.assertEqual(by_id(data)["ORIG-01"]["status"], "fail")
        self.assertFalse(by_id(data)["ORIG-01"]["counted"])
        self.assertEqual(data["policy"]["ignore"], ["ORIG-01"])

    def test_example_policy_parses(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        pol = policy.load(os.path.join(here, "examples", "policy.toml"))
        self.assertEqual(pol.fail_under, "B")
        self.assertIn("VER-01", pol.ignore)
        self.assertEqual(pol.downgrade.get("ORIG-01"), "SHOULD")


if __name__ == "__main__":
    unittest.main()
