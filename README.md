# mcp-authlab

Black-box conformance scanner for [MCP](https://modelcontextprotocol.io) server authorization. Point it at a live server and it tells you, with a grade and a spec citation for every finding, whether the server does OAuth the way the Model Context Protocol says it must.

```
$ mcp-authlab scan https://mcp.example.com/mcp --token "$TOKEN"

grade    F   score 76/100
         critical failure: TOK-02, TOK-03
checks   22 pass · 3 fail · 1 warn · 0 skipped

Token validation
  ✓ TOK-01  MUST   Malformed bearer token is refused with 401
  ✗ TOK-02  MUST*  Unsigned (alg=none) token with the right audience is refused
             server accepted an unsigned JWT: it is not validating tokens at all
             MCP Authorization, Token Handling; Security Best Practices, Token Passthrough
  ✗ TOK-03  MUST*  Valid token issued for a different resource is refused (audience binding)
             server accepted a token issued for another resource: audience is not validated
             MCP Authorization, Access Token Privilege Restriction; RFC 8707 section 2
  ✓ TOK-05  MUST   Valid token in the query string is not accepted

Sessions
  ✓ SESS-01 MUST*  Session ID does not substitute for authentication
  ✓ SESS-02 SHOULD Session IDs are long, random, and non-sequential

Origin
  ✗ ORIG-01 MUST   Request with a hostile Origin header is refused
             request from an unknown Origin was served; a DNS-rebinding page could drive this server
```

It's pure Python standard library: no dependencies, nothing to trust but this repo. It ships with a reference resource server that passes every check, plus profiles that break it the ways real servers do, and the test suite scans each profile and asserts the scanner flags exactly those defects.

## Why

The MCP authorization spec is a thin profile over OAuth 2.1, RFC 9728 (protected resource metadata), RFC 8414 (authorization server metadata) and RFC 8707 (resource indicators). Most of it is discovery plumbing you can read off a 401. The parts that matter for security you can't see from the outside unless you probe for them:

- **Token passthrough.** A server that accepts any well-formed token and forwards it downstream looks identical to a correct one until you hand it a token minted for a different audience, or one with no signature at all.
- **Sessions as authentication.** A server that trusts `Mcp-Session-Id` after the first authenticated request turns every session ID leak into account takeover.
- **Origin.** A streamable HTTP server that doesn't check `Origin` can be driven by any web page through DNS rebinding.

Those three are the critical checks (marked `MUST*`). One failure grades the server F on its own, whatever else it gets right.

## Install

```
pipx install git+https://github.com/tmtmiller1/mcp-authlab
```

or `pip install -e .` from a checkout. Python 3.11 or newer, nothing else.

## Use

```
mcp-authlab scan https://mcp.example.com/mcp
```

Without a token the scanner runs the 19 checks that need no credentials: the challenge, both metadata documents, and the negative token probes. Two more inputs unlock the rest:

| Option | Unlocks | Where to get it |
|---|---|---|
| `--token` (or `MCP_AUTHLAB_TOKEN`) | session replay, hostile Origin, query-string token, protocol version | any valid access token for this server, for example from your client's token cache |
| `--foreign-token` (or `MCP_AUTHLAB_FOREIGN_TOKEN`) | audience binding (TOK-03) | a valid token from the same authorization server minted for a *different* resource |

The token checks only ever send the token to the server you name. Each session the scanner opens, it closes with a `DELETE`.

Output formats: `--format text` (default), `json` (stable schema, add `--requests` for every HTTP exchange), `markdown`. `-o file` writes to a file. `--fail-under B` exits 2 when the grade is lower, which is what you want in CI; see [examples/github-action.yml](examples/github-action.yml).

## What it checks

26 checks in eight groups. The full table with citations is in [docs/checks.md](docs/checks.md) and from `mcp-authlab checks`.

| Group | Covers |
|---|---|
| Transport | HTTPS on the MCP endpoint |
| Challenge | 401 on unauthenticated requests, `WWW-Authenticate: Bearer` with `resource_metadata`, `scope` hint |
| Protected Resource Metadata | published at the RFC 9728 well-known path, `resource` matches the canonical URI, authorization servers listed, challenge URL agrees, no wildcard or `offline_access` scopes, no query-string bearer method |
| Authorization Server Metadata | discoverable via RFC 8414 or OpenID Connect at the right path for the issuer, required fields, issuer matches, HTTPS endpoints, PKCE S256, a client registration path (dynamic registration or Client ID Metadata Documents), RFC 9207 `iss` |
| Token validation | random string refused, `alg=none` refused, foreign-audience token refused, `error="invalid_token"` on 401, query-string token refused, valid token works |
| Sessions | session ID alone doesn't authenticate; IDs are long, random, distinct |
| Origin | hostile `Origin` refused |
| Protocol version | unsupported `MCP-Protocol-Version` gets 400 |

Checks cite the [2025-06-18 authorization spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization), the [security best practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices) and [transports](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports) pages, and the underlying RFCs. Items that only exist in the [draft spec](https://modelcontextprotocol.io/specification/draft/basic/authorization) (scope challenges, Client ID Metadata Documents, `iss`) are graded as SHOULD.

### Grading

Each check has a weight: critical 20, MUST 10, SHOULD 3. Skipped checks are left out of the denominator, so an unauthenticated scan isn't penalised for what it couldn't test. Score is the share of weight earned. Then:

- any critical failure, or no 401 challenge at all: **F**
- any other MUST failure: at best **C**
- otherwise A ≥ 95, B ≥ 85, C ≥ 70, D ≥ 50

## The reference server

`mcp-authlab fixture` runs a small streamable HTTP MCP server, written against the spec, that grades A. It serves protected resource metadata, authorization server metadata, HS256 tokens, sessions, Origin checks and a couple of tools. It's about 300 lines and reads as a worked example of what a conformant resource server has to do.

Profiles turn on defects:

| Profile | What's wrong | Grade |
|---|---|---|
| `reference` | nothing | A |
| `legacy` | no resource metadata, bare 401, no `invalid_token` error | C |
| `weak-as` | authorization server without PKCE, registration, `iss`, scope hints | C |
| `passthrough` | accepts unsigned tokens and foreign audiences, ignores Origin | F |
| `sloppy` | sessions as auth, sequential session IDs, query-string tokens, wildcard scopes | F |
| `open` | no authorization at all | F |
| `mismatch` | metadata `resource` points elsewhere, 403 instead of 401, http:// authorization server | F |

`--flag <defect>` turns on a single defect on top of any profile. `scripts/demo.sh <profile>` starts one, mints both tokens, scans, and stops it:

```
scripts/demo.sh passthrough
```

## Field notes

Scanned unauthenticated on 2026-10-19 against public endpoints, so seven checks were skipped on each:

- Linear and Notion: A, nothing to report.
- Sentry: A; the 401 doesn't hint scopes.
- Asana: A; metadata binds tokens to the host rather than the `/sse` path (allowed), no `iss` support advertised.
- GitHub: C; a malformed token gets 400 rather than the 401 the spec requires, and the challenge's `resource_metadata` URL (with a trailing slash) returns a different document than the well-known path without one.

None of the five has a critical finding visible from outside. The checks that would show one need a token.

## Limits

This is a black-box scan of the resource server. It reads authorization server metadata but doesn't run an authorization code flow, so it can't tell you whether the authorization server actually enforces PKCE or validates redirect URIs. It can't prove audience binding without a foreign-audience token. Scope step-up (`403 insufficient_scope`) isn't probed yet. The authorization extensions in [ext-auth](https://github.com/modelcontextprotocol/ext-auth) (enterprise-managed authorization, cross-app access) aren't covered yet.

## Roadmap

- Scope step-up probe: call a tool with a down-scoped token and check the 403 challenge.
- Client ID Metadata Document checks: fetch the document, validate `redirect_uris`.
- Enterprise-managed authorization (ID-JAG) metadata checks from ext-auth.
- SARIF output for code-scanning dashboards.
- Legacy HTTP+SSE transport.

## Development

```
python3 -m unittest discover -s tests -v
```

The tests start each fixture profile on a random port, scan it in-process, and assert the flagged set equals the profile's declared defects. Adding a check means adding it to `CATALOG`, implementing it in `Scanner`, breaking it in a fixture profile, and declaring that in `EXPECTED_FAILURES`.

## License

MIT.
