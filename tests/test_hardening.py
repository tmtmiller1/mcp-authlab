"""Cases where the scanner could report a pass it hadn't earned, or leak a credential into its output."""

from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import threading
import time
import unittest
import urllib.request
from collections.abc import Callable
from email.message import Message

from support import FixtureCase, by_id

from mcp_authlab import catalog, checks, cli, httpclient, jwtutil, oauthclient, report, scanner, tokenstore
from mcp_authlab.catalog import ERROR, FAIL, PASS, SKIP, WARN, Result
from mcp_authlab.grading import coverage, grade


class ExpiredForeignToken(FixtureCase):
    def test_expired_foreign_token_skips_tok03_instead_of_passing(self):
        state = self.start("reference", ["skip_audience"])
        entry = self.login(state).to_store()
        live = checks.run(state.public_url, stored=entry, timeout=5)
        self.assertEqual(by_id(live)["TOK-03"]["status"], "fail")

        entry["foreign"]["expires_at"] = time.time() - 60
        data = checks.run(state.public_url, stored=entry, timeout=5)
        tok3 = by_id(data)["TOK-03"]
        self.assertEqual(tok3["status"], "skip")
        self.assertIn("expired", tok3["message"])
        self.assertIn("TOK-03", data["coverage"]["critical_not_run"])
        self.assertIn("run `mcp-authlab login`", data["coverage"]["line"])

    def test_scan_refreshes_an_expired_foreign_token(self):
        state = self.start("reference", ["skip_audience"])
        entry = self.login(state).to_store()
        entry["foreign"]["expires_at"] = time.time() - 60
        tokenstore.put(entry["resource"], entry)
        out = os_capture(lambda: cli.main(["scan", state.public_url, "--format", "json"]))
        data = json.loads(out)
        self.assertEqual(by_id(data)["TOK-03"]["status"], "fail")
        self.assertGreater(tokenstore.get(entry["resource"])["foreign"]["expires_at"], time.time())


def os_capture(fn: Callable[[], object]) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        fn()
    return buf.getvalue()


class Redaction(FixtureCase):
    def test_request_log_never_carries_the_token(self):
        state = self.start("reference")
        token = state.mint()
        data = checks.run(state.public_url, token=token, timeout=5)
        out = report.as_json(data, requests=True)
        self.assertNotIn(token, out)
        self.assertIn("access_token=%3Credacted%3E", out)

    def test_redact_url_and_headers(self):
        self.assertEqual(
            httpclient._redact_url("https://h/cb?code=abc&state=s&iss=x"),
            "https://h/cb?code=%3Credacted%3E&state=s&iss=x",
        )
        h = Message()
        h["WWW-Authenticate"] = 'Basic realm="a"'
        h["WWW-Authenticate"] = 'Bearer realm="b"'
        h["Set-Cookie"] = "sid=secret"
        logged = httpclient._log_headers(h)
        self.assertEqual(logged["WWW-Authenticate"], 'Basic realm="a", Bearer realm="b"')
        self.assertEqual(logged["Set-Cookie"], "<redacted>")

    def test_client_refuses_non_http_urls(self):
        with self.assertRaises(httpclient.TransportError):
            httpclient.Client().get("file:///etc/passwd")

    def test_asf01_evidence_keeps_no_authorization_code(self):
        state = self.start("weak-as")  # issues a code without code_challenge
        entry = self.login(state).to_store()
        asf1 = next(r for r in entry["asf"] if r["id"] == "ASF-01")
        self.assertEqual(asf1["status"], "fail")
        self.assertNotIn("location", asf1["evidence"])
        self.assertTrue(asf1["evidence"]["redirected_to_callback"])
        self.assertNotIn("code=", json.dumps(entry["asf"]))


class ErroredCriticalChecks(unittest.TestCase):
    def test_an_errored_critical_check_caps_the_grade_and_counts_as_not_run(self):
        rs = [Result(c, ERROR if c.id == "TOK-02" else PASS, "") for c in catalog.CATALOG]
        g = grade(rs)
        self.assertEqual(g.letter, "C")
        self.assertTrue(any("TOK-02" in reason and "errored" in reason for reason in g.reasons))
        cov = coverage(rs)
        self.assertEqual(cov["critical_not_run"], ["TOK-02"])
        self.assertEqual(cov["ran"], len(rs) - 1)

    def test_an_errored_ordinary_check_leaves_the_grade_alone(self):
        rs = [Result(c, ERROR if c.id == "PRM-04" else PASS, "") for c in catalog.CATALOG]
        self.assertEqual(grade(rs).letter, "A")


def _jwt(aud: object) -> str:
    claims: dict[str, object] = {"sub": "u", "exp": int(time.time()) + 600}
    if aud is not None:
        claims["aud"] = aud
    return jwtutil.encode(claims, b"k" * 32)


class AudienceBinding(unittest.TestCase):
    TARGET = "https://mcp.example.com/mcp"
    OTHER = "https://as.example.com"

    def probe(self, main_aud: object, foreign_aud: object) -> tuple[Result, bool, str | None]:
        lg = oauthclient.Login(self.TARGET, log=lambda _s: None)
        main = oauthclient.TokenSet(_jwt(main_aud), None, None, {}, self.TARGET)
        foreign = oauthclient.TokenSet(_jwt(foreign_aud), None, None, {}, self.OTHER)
        usable, note, _known = lg._probe_asf04(main, foreign)
        return lg.results[-1], usable, note

    def test_bound_correctly(self):
        r, usable, _ = self.probe(self.TARGET, self.OTHER)
        self.assertEqual((r.status, usable), (PASS, True))

    def test_same_audience_means_resource_ignored(self):
        r, usable, note = self.probe(self.TARGET, self.TARGET)
        self.assertEqual((r.status, usable), (FAIL, False))
        self.assertIn("ignored resource=", note or "")

    def test_foreign_token_that_also_names_this_server(self):
        r, usable, _ = self.probe(self.TARGET, [self.TARGET, self.OTHER])
        self.assertEqual((r.status, usable), (FAIL, False))

    def test_foreign_token_without_aud(self):
        r, usable, _ = self.probe(self.TARGET, None)
        self.assertEqual(r.status, FAIL)
        self.assertIn("no aud claim", r.message)
        self.assertTrue(usable)

    def test_foreign_token_bound_somewhere_unexpected(self):
        r, usable, _ = self.probe(self.TARGET, "https://third.example.com")
        self.assertEqual((r.status, usable), (WARN, True))

    def test_main_token_not_bound(self):
        r, usable, _ = self.probe("https://third.example.com", self.OTHER)
        self.assertEqual((r.status, usable), (FAIL, True))


class OpaqueTokens(FixtureCase):
    def test_opaque_tokens_bound_correctly(self):
        data = self.scan("reference", ["opaque_tokens"])
        self.assertEqual(by_id(data)["TOK-03"]["status"], "pass")
        self.assertEqual(by_id(data)["ASF-04"]["status"], "pass")
        self.assertIn("opaque", by_id(data)["ASF-04"]["message"])

    def test_opaque_tokens_accepted_by_a_server_without_audience_checks(self):
        data = self.scan("reference", ["opaque_tokens", "skip_audience"])
        self.assertEqual(by_id(data)["TOK-03"]["status"], "warn")
        self.assertEqual(by_id(data)["ASF-04"]["status"], "warn")

    def test_resolver_reads_a_403_refusal_as_a_refusal(self):
        s = scanner.Scanner("https://mcp.example.com/mcp")
        asf = Result(catalog.BY_ID["ASF-04"], SKIP, "opaque", {"opaque": True})
        tok3 = Result(catalog.BY_ID["TOK-03"], WARN, "refused with 403 rather than 401", {"http_status": 403})
        s.results = [asf, tok3]
        s._resolve_asf04()
        self.assertEqual(asf.status, PASS)
        tok3.evidence["http_status"] = 200
        asf.status = SKIP
        s._resolve_asf04()
        self.assertEqual(asf.status, WARN)


class IssuerExactMatch(FixtureCase):
    def test_trailing_slash_issuer_fails_asm02(self):
        data = self.scan("reference", ["issuer_trailing_slash"], mode="dev")
        self.assertEqual(by_id(data)["ASM-02"]["status"], "fail")

    def test_login_stops_on_an_iss_that_differs_from_the_metadata(self):
        state = self.start("reference", ["issuer_trailing_slash"])
        with self.assertRaises(oauthclient.LoginError) as cm:
            self.login(state)
        self.assertIn("RFC 9207", str(cm.exception))


class CallbackServer(unittest.TestCase):
    def test_an_idle_connection_does_not_hold_up_the_callback(self):
        cb = oauthclient._CallbackServer(0)
        t = threading.Thread(target=cb.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        self.addCleanup(cb.server_close)
        self.addCleanup(cb.shutdown)
        idle = socket.create_connection(("127.0.0.1", cb.server_address[1]))
        self.addCleanup(idle.close)
        with urllib.request.urlopen(cb.redirect_uri + "?state=s1&code=c1", timeout=2) as resp:
            self.assertEqual(resp.status, 200)
        self.assertEqual(cb.wait("s1", 2), {"state": "s1", "code": "c1"})


class TokenStoreFile(FixtureCase):
    def test_permissions(self):
        p = tokenstore.put("https://x.example/mcp", {"access_token": "t"})
        self.assertEqual(oct(os.stat(p).st_mode & 0o777), "0o600")
        self.assertEqual(oct(os.stat(p.parent).st_mode & 0o777), "0o700")

    def test_a_corrupt_store_is_left_alone(self):
        p = tokenstore.path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{not json", encoding="utf-8")
        self.assertEqual(tokenstore.load_all(), {})
        with self.assertRaises(tokenstore.TokenStoreError):
            tokenstore.put("https://x.example/mcp", {"access_token": "t"})
        self.assertEqual(p.read_text(encoding="utf-8"), "{not json")


class JwtHeaders(unittest.TestCase):
    def test_non_object_header_is_a_value_error(self):
        bad = jwtutil._b64(b"[1]") + "." + jwtutil._b64(b"{}") + ".sig"
        with self.assertRaises(ValueError):
            jwtutil.verify_hs256(bad, b"k")
        with self.assertRaises(ValueError):
            jwtutil.decode_unverified(bad)


if __name__ == "__main__":
    unittest.main()
