# mcp-authlab

Conformance scanner for [MCP](https://modelcontextprotocol.io) server authorization. Point it at a live server and it tells you, with a spec citation for every finding, whether the server does OAuth the way the Model Context Protocol says it must. Log in once and it tests the parts you can only see with a token: forged tokens, foreign audiences, session hijacking, and the authorization server's own PKCE and redirect handling.

```
$ mcp-authlab login https://mcp.example.com/mcp
$ mcp-authlab scan  https://mcp.example.com/mcp

mcp-authlab 0.2.0  ·  spec 2025-06-18
target   https://mcp.example.com/mcp
coverage 33/33
level    Unsafe   grade F   score 76/100
         critical failure: TOK-02, TOK-03
checks   29 pass · 3 fail · 1 warn · 0 skipped

Token validation
  ✓ TOK-01   MUST    Malformed bearer token is refused with 401
  ✗ TOK-02   MUST*   Unsigned (alg=none) token with the right audience is refused
              server accepted an unsigned JWT: it is not validating tokens at all
              MCP Authorization, Token Handling; Security Best Practices, Token Passthrough
  ✗ TOK-03   MUST*   Valid token issued for a different resource is refused (audience binding)
              server accepted a token issued for another resource: audience is not validated
              MCP Authorization, Access Token Privilege Restriction; RFC 8707 section 2
  ✓ TOK-05   MUST    Valid token in the query string is not accepted

Sessions
  ✓ SESS-01  MUST*   Session ID does not substitute for authentication
  ✓ SESS-02  SHOULD  Session IDs are long, random, and non-sequential

Origin
  ✗ ORIG-01  MUST    Request with a hostile Origin header is refused
              request from an unknown Origin was served; a DNS-rebinding page could drive this server
```

It's pure Python standard library, so the only code you're trusting is in this repo. It ships with a reference resource server and authorization server that pass every check, plus profiles that break them the ways real servers do, and the test suite logs in to and scans each profile and asserts the scanner flags exactly those defects.

## Why

The MCP authorization spec is a thin profile over OAuth 2.1, RFC 9728 (protected resource metadata), RFC 8414 (authorization server metadata) and RFC 8707 (resource indicators). Most of it is discovery plumbing you can read off a 401. The parts that matter for security only show up when you probe with real tokens:

- **Token passthrough.** A server that accepts any well-formed token and forwards it downstream looks identical to a correct one until you hand it a token minted for a different audience, or one with no signature at all.
- **Sessions as authentication.** A server that trusts `Mcp-Session-Id` after the first authenticated request turns every session ID leak into account takeover.
- **Origin.** A streamable HTTP server that skips the `Origin` check can be driven by any web page through DNS rebinding.

Those are the critical checks (marked `MUST*`). One failure makes the server **Unsafe** on its own, whatever else it gets right. Getting the tokens to run them used to be the hard part; `login` does it for you.

## Install

```
pipx install git+https://github.com/tmtmiller1/mcp-authlab
```

or `pip install -e .` from a checkout. Python 3.11 or newer is the whole requirement.

## Use

```
mcp-authlab scan https://mcp.example.com/mcp
```

Without a login the scanner runs the 19 checks that need no credentials: the challenge, both metadata documents and the negative token probes. The first lines of the report say how much that covered and which critical checks it couldn't reach:

```
coverage 19/33 · critical checks not run: TOK-03, SESS-01 (run `mcp-authlab login` to enable)
```

### Logging in

```
mcp-authlab login https://mcp.example.com/mcp
```

`login` finds the authorization server the same way a client does, registers itself by dynamic registration (RFC 7591) or uses `--client-id`, opens your browser for the authorization code flow with PKCE, and stores the tokens in `~/.config/mcp-authlab/tokens.json` (mode 0600, keyed by canonical resource). From then on `scan` uses them on its own and refreshes them when they expire; `logout` forgets them.

While it has the authorization server's attention it does three more things:

- **Probes the authorization server** (the `ASF-*` checks): does it refuse a request without `code_challenge`, a wrong `code_verifier`, a mismatched `redirect_uri`? Are tokens bound to the resource you asked for? Do refresh tokens rotate? Were all URLs HTTPS and did the callback carry `iss`? You sign in twice, once per token. A strict server revokes an authorization code after the failed `code_verifier` probe, which costs one more sign-in; when that happens the `redirect_uri` probe is skipped and the report says so, and `--thorough` runs it at the price of a fourth sign-in.
- **Mints a second token for a different resource** (the authorization server's own issuer URL by default, `--foreign-resource` to choose) so the scan can test audience binding. If the authorization server ignores `resource=` and hands back the same audience, the report says exactly that rather than guessing.
- **Records the results** next to the tokens so the scan report carries them.

`--no-browser` prints the URL for you to open by hand. When the authorization server is on loopback (the fixture), it fetches the URL itself, which is how the test suite and `scripts/demo.sh` run the whole flow with nothing to click.

You can still hand the scanner tokens directly with `--token` and `--foreign-token` (or `MCP_AUTHLAB_TOKEN` and `MCP_AUTHLAB_FOREIGN_TOKEN`); explicit tokens win over stored ones, and `--no-login` ignores the store. Tokens only ever go to the server you name, and every session the scanner opens it closes with a `DELETE`.

### Output and CI

`--format text` (default), `json` (schema in [docs/report.schema.json](docs/report.schema.json); add `--requests` for every HTTP exchange), `markdown`, or `sarif` for GitHub code scanning. `-o file` writes to a file. `--fail-under B` exits 2 when the grade is lower; `--policy authlab.toml` lets a team write its bar down once (below). [examples/github-action.yml](examples/github-action.yml) shows a scheduled scan that gates on grade and uploads SARIF.

## What it checks

33 checks in ten groups. The full table with citations is in [docs/checks.md](docs/checks.md) and from `mcp-authlab checks`.

| Group | Covers |
|---|---|
| Transport | HTTPS on the MCP endpoint |
| Challenge | 401 on unauthenticated requests, `WWW-Authenticate: Bearer` with `resource_metadata`, `scope` hint |
| Protected Resource Metadata | published at the RFC 9728 well-known path, `resource` matches the canonical URI, authorization servers listed, challenge URL agrees, no wildcard or `offline_access` scopes, no query-string bearer method |
| Authorization Server Metadata | discoverable via RFC 8414 or OpenID Connect at the right path for the issuer, required fields, issuer matches, HTTPS endpoints, PKCE S256, a client registration path, RFC 9207 `iss` |
| Authorization server flow (`login`) | PKCE required at the authorization endpoint and enforced at the token endpoint, `redirect_uri` checked, tokens bound to the requested resource, refresh token rotation, HTTPS and `iss` on the callback |
| Token validation | random string refused, `alg=none` refused, foreign-audience token refused, `error="invalid_token"` on 401, query-string token refused, valid token works |
| Scope step-up | a tool call the token can't make gets a 403 with `error="insufficient_scope"`, a `scope` hint and `resource_metadata` |
| Sessions | session ID alone doesn't authenticate; IDs are long, random, distinct |
| Origin | hostile `Origin` refused |
| Protocol version | unsupported `MCP-Protocol-Version` gets 400 |

Checks cite the [2025-06-18 authorization spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization), the [security best practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices) and [transports](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports) pages, and the underlying RFCs. Items that only exist in the [draft spec](https://modelcontextprotocol.io/specification/draft/basic/authorization) (scope challenges, Client ID Metadata Documents, `iss`) are graded as SHOULD.

### Grading

The headline is a conformance level read straight from the spec's language: **Unsafe** (a critical check failed), **Non-conformant** (a MUST failed), **Conformant with warnings** (only SHOULD items or soft MUST answers), or **Conformant**. A letter grade from a weighted score sits next to it for CI gates, and a MUST failure caps it at C. [docs/grading.md](docs/grading.md) has every weight and threshold and a worked example you can check by hand against the JSON report.

### Policy files

Two MUST checks draw pushback from operators: ORIG-01, because non-browser clients never send `Origin`, and VER-01, because answering an old client with the newest version you support is friendlier than a 400. They stay MUST because the spec says MUST, and the catalog carries a `disputed` note explaining both sides. A policy file is where your organisation records its own call:

```toml
fail_under = "B"
ignore = ["VER-01"]                    # still runs and prints, stops counting
downgrade = { "ORIG-01" = "SHOULD" }   # counts as SHOULD, never critical
```

`mcp-authlab scan --policy authlab.toml`. [examples/policy.toml](examples/policy.toml) explains each key.

## The reference server

`mcp-authlab fixture` runs a small streamable HTTP MCP server plus a minimal authorization server, written against the spec, that grades A. The resource server serves protected resource metadata, HS256 tokens, sessions, Origin checks, a scope-gated tool and a couple of plain ones. The authorization server does dynamic registration, a consent page (`--auto-consent` approves on its own for tests), PKCE S256, resource indicators and rotating refresh tokens. Together they're about 600 lines and read as a worked example of what a conformant pair has to do.

Profiles turn on defects:

| Profile | What's wrong | Level | Grade |
|---|---|---|---|
| `reference` | nothing | Conformant with warnings (plain http on loopback) | A |
| `legacy` | no resource metadata, bare 401, no `invalid_token` error | Non-conformant | C |
| `weak-as` | authorization server without PKCE, registration, `iss`, scope hints; PKCE optional in practice; `resource=` ignored | Non-conformant | C |
| `passthrough` | accepts unsigned tokens and foreign audiences, ignores Origin | Unsafe | F |
| `sloppy` | sessions as auth, sequential session IDs, query-string tokens, wildcard scopes, redirect_uri unchecked, static refresh tokens, bare 403s | Unsafe | F |
| `open` | no authorization at all | Non-conformant | F |
| `mismatch` | metadata `resource` points elsewhere, 403 instead of 401, http:// authorization server | Non-conformant | F |

`--flag <defect>` turns on a single defect on top of any profile (`stateless` and `ignore_resource` are two useful ones). `scripts/demo.sh <profile>` starts one, logs in without a browser, scans with the tokens it minted, and stops it:

```
scripts/demo.sh passthrough
```

## Field notes

Unauthenticated scans of public endpoints on 2026-10-19, so each line covers 19 of 33 checks and the critical checks `TOK-03` and `SESS-01` did not run. The [registry](registry/README.md) rescans these every Monday.

- **Linear** `coverage 19/33 · critical checks not run: TOK-03, SESS-01`: Conformant, A, nothing to report.
- **Notion** `coverage 19/33 · critical checks not run: TOK-03, SESS-01`: Conformant, A, nothing to report.
- **Sentry** `coverage 19/33 · critical checks not run: TOK-03, SESS-01`: Conformant with warnings, A; the 401 doesn't hint scopes.
- **Asana** `coverage 19/33 · critical checks not run: TOK-03, SESS-01`: Conformant with warnings, A; the 401 doesn't hint scopes and the authorization server doesn't advertise `iss`. Metadata binds tokens to the host rather than the `/sse` path, which RFC 9728 allows.
- **GitHub** `coverage 18/33 · critical checks not run: TOK-03, SESS-01`: Non-conformant, C. A malformed token gets 400 rather than the 401 the spec requires (so the `invalid_token` check couldn't run either), the challenge's `resource_metadata` URL returns a different document than the well-known path, and there's no automatic client registration.

All five looked clean from outside; the critical findings need a login to show up.

## How it compares

Checked against each project's README on 2026-10-19.

| | scans a live server | runs the OAuth flow | probes token validation | CI gate | zero dependencies |
|---|---|---|---|---|---|
| **mcp-authlab** | yes | yes (`login`) | yes: unsigned, foreign-audience, query-string, session replay | yes (`--fail-under`, `--policy`, SARIF) | yes (stdlib only) |
| [AuthPlane/conformance](https://github.com/AuthPlane/conformance) | no: a language-neutral catalog of test cases that SDKs run in-process against their own verifier | no | partly: the example case rejects a bad JWT header, run against the SDK's verifier rather than a remote server | indirectly: SDK reports carry a non-zero exit status on failure | n/a (no runner of its own; Python dev tooling) |
| [sudo-ai-git/mcp-auth-audit](https://github.com/sudo-ai-git/mcp-auth-audit) | no: "No LLM, no network"; audits a server's declared auth schema from supplied metadata | no | no | PASS/FAIL with findings; exit codes not documented | not stated (Python, pyproject) |
| [invariantlabs mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) (now Snyk Agent Scan) | partly: connects to configured MCP servers to pull tool descriptions and look for prompt injection; takes existing OAuth tokens via `--mcp-oauth-tokens-path` | no | no | yes (`--ci`) | no (Python via `uvx`, needs a Snyk API token and service) |
| [eqtylab/mcp-guardian](https://github.com/eqtylab/mcp-guardian) (policy proxy) | no: sits between the client and the server to log and approve tool calls | no | no | no | no (Rust, built with `just`) |

The policy-proxy space is crowded and useful; it controls what a client may do. mcp-authlab is the only one in the table that checks whether the server's own OAuth implementation is sound, and that is the gap it fills.

## Limits

A scan is black-box and sees what a client sees: the challenge, the metadata documents, and how the resource server answers tokens it shouldn't accept. `login` adds the authorization server's behaviour for one public client, so the report covers both halves of the spec but still can't tell you how a token was validated internally or what a confidential client would see. When tokens are opaque the audience-binding verdict rests on how the resource server treated the two tokens, and the report says so. The roadmap below has what comes next.

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

The tests start each fixture profile on a random port, log in to it with `--no-browser`, scan it in-process, and assert the flagged set equals the profile's declared defects; the suite runs in about four seconds. Adding a check means adding it to `catalog.CATALOG`, implementing it in `scanner.Scanner` (or `oauthclient.Login` for the authorization server), breaking it in a fixture profile, declaring that in `EXPECTED_FAILURES`, and regenerating `docs/checks.md` with `mcp-authlab checks --markdown` (a test fails when it's stale). [CHANGELOG.md](CHANGELOG.md) lists what changed in each release.

## License

MIT.
