# mcp-authlab

[![ci](https://github.com/tmtmiller1/mcp-authlab/actions/workflows/ci.yml/badge.svg)](https://github.com/tmtmiller1/mcp-authlab/actions/workflows/ci.yml)
[![pypi](https://img.shields.io/pypi/v/mcp-authlab)](https://pypi.org/project/mcp-authlab/)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)
[![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](pyproject.toml)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Tests whether an [MCP](https://modelcontextprotocol.io) server refuses the tokens it should refuse. Most MCP auth scanners read the discovery documents and stop there. mcp-authlab logs in to the server's authorization server, mints real tokens, and then attacks the resource server with them: an unsigned token, a token issued for a different service, a session ID with no token at all. Every finding cites the line of the spec it enforces.

```
$ scripts/demo.sh passthrough

mcp-authlab 0.2.1  ·  spec 2025-06-18
target   http://127.0.0.1:8765/mcp
coverage 33/33
level    Unsafe   grade F   score 81/100
         critical failure: TOK-02, TOK-03
         MUST failures: TOK-02, TOK-03, ORIG-01
checks   29 pass · 3 fail · 1 warn · 0 skipped

Token validation
  ✓ TOK-01   MUST    Malformed bearer token is refused with 401
  ✗ TOK-02   MUST*   Unsigned (alg=none) token with the right audience is refused
              server accepted an unsigned JWT, so it isn't validating tokens at all
              MCP Authorization, Token Handling; Security Best Practices, Token Passthrough
  ✗ TOK-03   MUST*   Valid token issued for a different resource is refused (audience binding)
              server accepted a token issued for another resource, so it isn't checking the audience (token passthrough risk)
              MCP Authorization, Access Token Privilege Restriction; RFC 8707 section 2
  ✓ TOK-05   MUST    A valid token in the query string is refused

Sessions
  ✓ SESS-01  MUST*   A session ID alone doesn't authenticate

Origin
  ✗ ORIG-01  MUST    Request with a hostile Origin header is refused
              request from an unknown Origin was served; a DNS-rebinding page could drive this server
```

That's a real run against the `passthrough` profile of the bundled reference server, trimmed to three sections.

## What's different

Several tools already check MCP discovery: the 401 challenge, the RFC 9728 and RFC 8414 metadata, PKCE support in the metadata. mcp-authlab does that too, and it's the least interesting part. These are the parts that, as of 2026-10-19, no other public MCP scanner does (see [How it compares](#how-it-compares)):

- **Forged-token probe.** It sends an `alg=none` JWT with the right audience. A server that accepts it isn't checking signatures.
- **Foreign-audience probe.** `login` asks the authorization server for a second token bound to a different resource, then hands it to your server. A server that accepts it is open to token passthrough, the confused-deputy problem the MCP security guidance calls out by name. If the authorization server ignores `resource=` and can't mint such a token, the report says that instead of guessing.
- **Session replay.** It replays a live `Mcp-Session-Id` with the bearer token removed. A server that answers has made the session ID a password.
- **Authorization server enforcement, not just advertisement.** During `login` it checks that the authorization server actually refuses a request without `code_challenge`, a wrong `code_verifier` and a mismatched `redirect_uri`, that tokens are bound to the requested resource, and that refresh tokens rotate.
- **A reference server that proves the scanner.** The bundled fixture is a working MCP resource server and authorization server with switches that break it the ways real servers break. The test suite logs in to each broken profile and asserts the scanner flags exactly its defects.

It's pure Python standard library, so the only code you're trusting is in this repo.

## Why these checks

The MCP authorization spec is a thin profile over OAuth 2.1, RFC 9728 (protected resource metadata), RFC 8414 (authorization server metadata) and RFC 8707 (resource indicators). You can read most of it off a 401. The failures that lead to account takeover only show up when you probe with real tokens:

- **Token passthrough.** A server that accepts any well-formed token and forwards it downstream looks identical to a correct one until you hand it a token minted for a different audience, or one without a signature.
- **Sessions as authentication.** A server that trusts `Mcp-Session-Id` after the first authenticated request turns every leaked session ID into a stolen account.

Those three checks (TOK-02, TOK-03 and SESS-01, marked `MUST*`) are critical. One failure makes the server **Unsafe** on its own, even if everything else passes. Getting the tokens to run them used to be the hard part; `login` does it for you.

## Install

```
pipx install mcp-authlab
```

or `pip install mcp-authlab`, or `pip install -e .` from a checkout. Python 3.11 or newer is the whole requirement.

## Use

```
mcp-authlab scan https://mcp.example.com/mcp
```

Without a login the scanner runs the 19 checks that need no credentials: the challenge, both metadata documents and the invalid-token probes. The first lines of the report say how much that covered and which critical checks it couldn't reach:

```
coverage 19/33 · critical checks not run: TOK-03, SESS-01 (run `mcp-authlab login` to enable)
```

### Logging in

```
mcp-authlab login https://mcp.example.com/mcp
```

`login` finds the authorization server the same way a client does, registers itself by dynamic registration (RFC 7591) or uses `--client-id`, opens your browser for the authorization code flow with PKCE, and stores the tokens in `~/.config/mcp-authlab/tokens.json` (mode 0600, keyed by canonical resource). From then on `scan` uses them and refreshes them when they expire. `logout` forgets them.

While it has the authorization server's attention it does three more things:

- **Probes the authorization server** (the `ASF-*` checks): does it refuse a request without `code_challenge`, a wrong `code_verifier`, a mismatched `redirect_uri`? Are tokens bound to the resource you asked for? Do refresh tokens rotate? Were all URLs HTTPS and did the callback carry `iss`? You sign in twice, once per token. A strict server revokes an authorization code after the failed `code_verifier` probe, which costs one more sign-in. When that happens the `redirect_uri` probe is skipped and the report says so; `--thorough` runs it at the price of a fourth sign-in.
- **Mints a second token for a different resource** (the authorization server's own issuer URL by default, `--foreign-resource` to choose) so the scan can test audience binding. If the authorization server ignores `resource=` and hands back the same audience, the report says so.
- **Records the results** next to the tokens so the scan report carries them.

`--no-browser` prints the URL for you to open by hand. When the authorization server is on loopback, as the fixture's is, it fetches the URL itself. That's how the test suite and `scripts/demo.sh` run the whole flow hands-free.

You can also hand the scanner tokens directly with `--token` and `--foreign-token` (or `MCP_AUTHLAB_TOKEN` and `MCP_AUTHLAB_FOREIGN_TOKEN`). Explicit tokens win over stored ones, and `--no-login` ignores the store. Tokens only go to the server you name, and the scanner closes every session it opens with a `DELETE`.

### Output and CI

`--format text` (default), `json` (schema in [docs/report.schema.json](docs/report.schema.json); add `--requests` for every HTTP exchange), `markdown`, or `sarif` for GitHub code scanning. `-o file` writes to a file. `--fail-under B` exits 2 when the grade is lower, and `--policy authlab.toml` lets a team write its bar down once (below). [examples/github-action.yml](examples/github-action.yml) shows a scheduled scan that gates on grade and uploads SARIF.

## What it checks

33 checks in ten groups. The full table with citations is in [docs/checks.md](docs/checks.md) and from `mcp-authlab checks`.

| Group | Covers |
|---|---|
| Transport | HTTPS on the MCP endpoint |
| Challenge | 401 on unauthenticated requests, `WWW-Authenticate: Bearer` with `resource_metadata`, `scope` hint |
| Protected Resource Metadata | published at the RFC 9728 well-known path, `resource` matches the canonical URI, authorization servers listed, challenge URL agrees, scopes are specific (wildcards and `offline_access` flagged), bearer tokens kept out of the query string |
| Authorization Server Metadata | discoverable via RFC 8414 or OpenID Connect at the right path for the issuer, required fields, issuer matches, HTTPS endpoints, PKCE S256, a client registration path, RFC 9207 `iss` |
| Authorization server flow (`login`) | PKCE required at the authorization endpoint and enforced at the token endpoint, `redirect_uri` checked, tokens bound to the requested resource, refresh token rotation, HTTPS and `iss` on the callback |
| Token validation | random string refused, `alg=none` refused, foreign-audience token refused, `error="invalid_token"` on 401, query-string token refused, valid token works |
| Scope step-up | a tool call the token can't make gets a 403 with `error="insufficient_scope"`, a `scope` hint and `resource_metadata` |
| Sessions | a session ID alone doesn't authenticate; IDs are long, random, distinct |
| Origin | hostile `Origin` refused |
| Protocol version | unsupported `MCP-Protocol-Version` gets 400 |

Checks cite the [2025-06-18 authorization spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization), the [security best practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices) and [transports](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports) pages, and the underlying RFCs. Items that only exist in the [draft spec](https://modelcontextprotocol.io/specification/draft/basic/authorization) (scope challenges, Client ID Metadata Documents, `iss`) are graded as SHOULD.

### Grading

The headline is a conformance level read straight from the spec's language: **Unsafe** (a critical check failed), **Non-conformant** (a MUST failed), **Conformant with warnings** (only SHOULD items or soft MUST answers), or **Conformant**. A letter grade from a weighted score sits next to it for CI gates, and a MUST failure caps it at C. [docs/grading.md](docs/grading.md) has every weight and threshold and a worked example you can check by hand against the JSON report.

### Policy files

Two MUST checks draw pushback from operators. ORIG-01 does because non-browser clients don't send `Origin`, and VER-01 because answering an old client with the newest version you support is friendlier than a 400. They stay MUST because the spec says MUST, and the catalog carries a `disputed` note explaining both sides. A policy file is where your organisation records its own call:

```toml
fail_under = "B"
ignore = ["VER-01"]                    # still runs and prints, stops counting
downgrade = { "ORIG-01" = "SHOULD" }   # counts as SHOULD and stops being critical
```

Run it with `mcp-authlab scan --policy authlab.toml`. [examples/policy.toml](examples/policy.toml) explains each key.

## The reference server

`mcp-authlab fixture` runs a small streamable HTTP MCP server plus a minimal authorization server, written against the spec, that grades A. The resource server serves protected resource metadata, HS256 tokens, sessions, Origin checks, a scope-gated tool and a plain one. The authorization server does dynamic registration, a consent page (`--auto-consent` approves on its own for tests), PKCE S256, resource indicators and rotating refresh tokens. Together they're about 600 lines, and they're a fair example of what a conformant pair has to do.

Profiles turn on defects:

| Profile | What's wrong | Level | Grade |
|---|---|---|---|
| `reference` | passes every check | Conformant with warnings (plain http on loopback) | A |
| `legacy` | resource metadata missing, bare 401, `invalid_token` error missing | Non-conformant | C |
| `weak-as` | authorization server metadata leaves out PKCE, registration, `iss` and scope hints; PKCE optional in practice; `resource=` ignored | Non-conformant | C |
| `passthrough` | accepts unsigned tokens and foreign audiences, ignores Origin | Unsafe | F |
| `sloppy` | sessions as auth, sequential session IDs, query-string tokens, wildcard scopes, redirect_uri unchecked, static refresh tokens, bare 403s | Unsafe | F |
| `open` | serves every request, token or not | Non-conformant | F |
| `mismatch` | metadata `resource` points elsewhere, 403 instead of 401, http:// authorization server | Non-conformant | F |

`--flag <defect>` turns on a single defect on top of any profile (`stateless` and `ignore_resource` are two useful ones). `scripts/demo.sh <profile>` starts one, logs in without a browser, scans with the tokens it minted, and stops it:

```
scripts/demo.sh passthrough
```

## Field notes

Unauthenticated scans of public endpoints on 2026-10-19, so each line covers 19 of 33 checks and the critical checks `TOK-03` and `SESS-01` were skipped. `python3 registry/scan.py` reruns them and rewrites the [registry](registry/README.md) table.

- **Linear** `coverage 19/33 · critical checks not run: TOK-03, SESS-01`: Conformant, A. Every check that ran passed.
- **Notion** `coverage 19/33 · critical checks not run: TOK-03, SESS-01`: Conformant, A. Every check that ran passed.
- **Sentry** `coverage 19/33 · critical checks not run: TOK-03, SESS-01`: Conformant with warnings, A. The 401 doesn't say which scopes to request.
- **Asana** `coverage 19/33 · critical checks not run: TOK-03, SESS-01`: Conformant with warnings, A. The 401 doesn't say which scopes to request, and the authorization server doesn't advertise `iss`. Metadata binds tokens to the host rather than the `/sse` path, which RFC 9728 allows.
- **GitHub** `coverage 18/33 · critical checks not run: TOK-03, SESS-01`: Non-conformant, C. A malformed token gets 400 rather than the 401 the spec requires, so the `invalid_token` check couldn't run either. The challenge's `resource_metadata` URL returns a different document than the well-known path, and clients have to be registered by hand.

All five look clean from outside. The critical findings need a login to show up.

## How it compares

Checked on 2026-10-19 against each project's README, and against the source for the official suite and mcp-authcheck.

| | scans a live server | runs the OAuth flow | probes token validation | CI gate | zero dependencies |
|---|---|---|---|---|---|
| **mcp-authlab** | yes | yes (`login`) | random, unsigned, foreign-audience and query-string tokens; session replay; scope step-up | `--fail-under`, `--policy`, SARIF | yes (stdlib) |
| [MCP conformance suite](https://github.com/modelcontextprotocol/conformance) (official) | yes (`server --url`) | for authorization servers: the happy-path code grant and DPoP | its merged server scenarios don't send a bearer token yet; audience checks are proposed in [issue #78](https://github.com/modelcontextprotocol/conformance/issues/78) and DPoP server checks are in review (as of 2026-10-22); it does test DNS rebinding | yes, GitHub Action with expected-failure baselines | no (Node) |
| [mcp-authcheck](https://github.com/tstanmay13/mcp-authcheck) | yes | no; it only sends credentials you give it | one bogus token; wrong-audience and scope checks are listed but not built yet | `--min-grade`, GitHub Action | yes (Node, no runtime packages) |
| [mcp-auth-doctor](https://github.com/Jah-yee/mcp-auth-doctor) | yes | opt-in `--login` with PKCE, `state` and `iss` checks | uses its own real token once on `tools/list` | exit codes 0 to 3 | one package (httpx) |
| [MCPJam OAuth conformance](https://docs.mcpjam.com/cli/oauth-conformance) | yes | interactive, headless or client credentials, with `redirect_uri` rejection checks | one invalid bearer token; an audience problem only shows up as a 401 on the real token | JUnit and JSON reporters | not stated (part of the MCPJam Inspector CLI) |
| [AuthPlane/conformance](https://github.com/AuthPlane/conformance) | a catalog of cases that SDKs run in-process against their own verifier | no | its example rejects a bad JWT header, against the SDK's verifier | through each SDK's report | n/a (catalog, no runner) |
| [mcp-auth-audit](https://github.com/sudo-ai-git/mcp-auth-audit) | reads a server's declared auth schema from supplied metadata ("No LLM, no network") | no | no | PASS/FAIL; exit codes undocumented | not stated (Python) |
| [Snyk Agent Scan](https://github.com/invariantlabs-ai/mcp-scan) (was invariantlabs mcp-scan) | connects to configured servers to read tool descriptions for prompt injection | uses OAuth tokens you already have | no | `--ci` | no (needs a Snyk API token) |
| [mcp-guardian](https://github.com/eqtylab/mcp-guardian) (policy proxy) | sits between client and server to log and approve tool calls | no | no | no | no (Rust) |

If you only need the discovery checks, mcp-authcheck and mcp-auth-doctor do them with less setup. MCPJam and the official suite are the better fit for testing a client or an SDK across the whole protocol. mcp-authlab is for the question they leave open: does this server refuse the tokens it should?

## Limits

A scan sees what a client sees: the challenge, the metadata documents, and how the resource server answers tokens it should refuse. `login` adds the authorization server's behaviour for one public client. So the report covers both halves of the spec, but it can't tell you how a token was validated internally or what a confidential client would see. When tokens are opaque, the audience verdict rests on how the resource server treated the two tokens, and the report says so.

## Roadmap

- Client ID Metadata Document checks: fetch the document, validate `redirect_uris`.
- Enterprise-managed authorization (ID-JAG) metadata checks from [ext-auth](https://github.com/modelcontextprotocol/ext-auth).
- Legacy HTTP+SSE transport.
- Token introspection (RFC 7662) for opaque-token audience checks when the authorization server offers it.

## Development

```
python3 -m unittest discover -s tests -v
ruff check src tests && ruff format --check src tests && mypy src
```

The tests start each fixture profile on a random port, log in to it with `--no-browser`, scan it in-process, and assert the flagged set equals the profile's declared defects. The suite runs in about six seconds. Adding a check means adding it to `catalog.CATALOG`, implementing it in `scanner.Scanner` (or `oauthclient.Login` for the authorization server), breaking it in a fixture profile, declaring that in `EXPECTED_FAILURES`, and regenerating `docs/checks.md` with `mcp-authlab checks --markdown`. A test fails when that file is stale. [CHANGELOG.md](CHANGELOG.md) lists what changed in each release.

## Contributing and security

[CONTRIBUTING.md](CONTRIBUTING.md) covers running the tests and adding a check. To report a vulnerability in mcp-authlab itself, see [SECURITY.md](SECURITY.md). To have a server taken off the registry or a finding corrected, [open a registry issue](https://github.com/tmtmiller1/mcp-authlab/issues/new?template=registry.yml).

## License

MIT.
