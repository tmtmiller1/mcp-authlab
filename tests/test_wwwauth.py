"""WWW-Authenticate parsing against the RFC 9110 grammar and the challenges real servers send."""

from __future__ import annotations

import unittest

from mcp_authlab import wwwauth

CASES: list[tuple[str, list[str], list[tuple[str, dict[str, str], str | None]]]] = [
    (
        "keycloak invalid token",
        ['Bearer realm="myrealm", error="invalid_token", error_description="Token verification failed"'],
        [
            (
                "Bearer",
                {"realm": "myrealm", "error": "invalid_token", "error_description": "Token verification failed"},
                None,
            )
        ],
    ),
    (
        "auth0 missing token",
        [
            'Bearer realm="https://tenant.auth0.com/", error="invalid_token", '
            'error_description="The access token is missing"'
        ],
        [
            (
                "Bearer",
                {
                    "realm": "https://tenant.auth0.com/",
                    "error": "invalid_token",
                    "error_description": "The access token is missing",
                },
                None,
            )
        ],
    ),
    (
        "entra with empty realm and authorization_uri",
        [
            'Bearer realm="", authorization_uri="https://login.microsoftonline.com/common/oauth2/authorize", '
            'client_id="00000002-0000-0000-c000-000000000000"'
        ],
        [
            (
                "Bearer",
                {
                    "realm": "",
                    "authorization_uri": "https://login.microsoftonline.com/common/oauth2/authorize",
                    "client_id": "00000002-0000-0000-c000-000000000000",
                },
                None,
            )
        ],
    ),
    (
        "github copilot mcp challenge",
        ['Bearer resource_metadata="https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/"'],
        [
            (
                "Bearer",
                {"resource_metadata": "https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/"},
                None,
            )
        ],
    ),
    (
        "github api basic",
        ['Basic realm="GitHub"'],
        [("Basic", {"realm": "GitHub"}, None)],
    ),
    (
        "mcp step-up with scope",
        [
            'Bearer error="insufficient_scope", scope="mcp:admin mcp:tools", resource_metadata="https://h/.well-known/oauth-protected-resource"'
        ],
        [
            (
                "Bearer",
                {
                    "error": "insufficient_scope",
                    "scope": "mcp:admin mcp:tools",
                    "resource_metadata": "https://h/.well-known/oauth-protected-resource",
                },
                None,
            )
        ],
    ),
    (
        "two challenges in one header",
        ['Basic realm="r", Bearer realm="b", scope="x"'],
        [("Basic", {"realm": "r"}, None), ("Bearer", {"realm": "b", "scope": "x"}, None)],
    ),
    (
        "two headers",
        ["Negotiate", 'Bearer error="invalid_token"'],
        [("Negotiate", {}, None), ("Bearer", {"error": "invalid_token"}, None)],
    ),
    (
        "token68 (NTLM type 2)",
        ["NTLM TlRMTVNTUAACAAAADAAMADgAAAAFgoqiAAAAAAAAAAAAAAAAAAAAAA=="],
        [("NTLM", {}, "TlRMTVNTUAACAAAADAAMADgAAAAFgoqiAAAAAAAAAAAAAAAAAAAAAA==")],
    ),
    (
        "token68 followed by another challenge",
        ['Negotiate oRQwEqADCgEBoQsGCSqGSIb3EgECAg==, Basic realm="x"'],
        [("Negotiate", {}, "oRQwEqADCgEBoQsGCSqGSIb3EgECAg=="), ("Basic", {"realm": "x"}, None)],
    ),
    (
        "comma inside a quoted string",
        ['Bearer error_description="expired, please sign in again", error="invalid_token"'],
        [("Bearer", {"error_description": "expired, please sign in again", "error": "invalid_token"}, None)],
    ),
    (
        "escaped quotes",
        ['Bearer error_description="bad \\"sig\\" here"'],
        [("Bearer", {"error_description": 'bad "sig" here'}, None)],
    ),
    (
        "unquoted token values and odd spacing",
        ["Bearer realm=api ,  scope=read , Digest realm=d"],
        [("Bearer", {"realm": "api", "scope": "read"}, None), ("Digest", {"realm": "d"}, None)],
    ),
    (
        "bare scheme then another",
        ["Bearer, Basic realm=x"],
        [("Bearer", {}, None), ("Basic", {"realm": "x"}, None)],
    ),
    (
        "empty list elements",
        [", , Bearer realm=x,"],
        [("Bearer", {"realm": "x"}, None)],
    ),
    (
        "param names are case-insensitive and first wins",
        ['Bearer Realm="a", realm="b"'],
        [("Bearer", {"realm": "a"}, None)],
    ),
    (
        "bws around the equals",
        ['Bearer realm = "x", error= invalid_token'],
        [("Bearer", {"realm": "x", "error": "invalid_token"}, None)],
    ),
    (
        "missing comma between params stays one challenge",
        ['Bearer realm="x" error="invalid_token"'],
        [("Bearer", {"realm": "x", "error": "invalid_token"}, None)],
    ),
    (
        "empty header",
        [""],
        [],
    ),
]


class WwwAuthTests(unittest.TestCase):
    def test_table(self):
        for name, headers, expected in CASES:
            with self.subTest(case=name):
                got = [(c.scheme, c.params, c.token68) for c in wwwauth.parse(headers)]
                self.assertEqual(got, expected)

    def test_bearer_picks_the_first_bearer(self):
        ch = wwwauth.bearer(['Basic realm="x"', 'Bearer scope="a", realm="r"', 'Bearer realm="second"'])
        assert ch is not None
        self.assertEqual(ch.params["realm"], "r")
        self.assertIsNone(wwwauth.bearer(["Basic realm=x"]))
        self.assertIsNone(wwwauth.bearer([]))


if __name__ == "__main__":
    unittest.main()
