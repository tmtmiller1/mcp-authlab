# Changelog

## 0.2.2 (2026-10-23)

- The README's comparison table now notes the official conformance suite's open server-auth work: audience checks proposed in issue #78, and DPoP server checks in review. There are no code changes.

## 0.2.1 (2026-10-19)

- VER-01 sends its unsupported `MCP-Protocol-Version` on a ping after `initialize`, where the spec requires the header. 0.2.0 sent it on `initialize` itself and flagged servers that were right to accept it there, including the official TypeScript SDK's example server.
- ASF-03 is marked inconclusive when the authorization server refuses the second resource outright. A refusal there could be about the resource rather than the redirect, so 0.2.0 could report a pass it hadn't earned. A token issued despite the wrong `redirect_uri` still fails. The fixture's new `strict_resource` flag covers this.
- `scripts/demo.sh` runs straight from a fresh clone, without installing the package first, and says so plainly when `python3` is older than 3.11.
- The example GitHub Actions workflow creates its token directory with mode 0700 and notes that it reads `authlab.toml` from your repo.

## 0.2.0 (2026-10-19)

- `mcp-authlab login <url>` signs you in to a server's authorization server with the real authorization code flow (PKCE S256, dynamic registration or `--client-id`, loopback redirect, RFC 8707 `resource`, RFC 9207 `iss` checked) and stores the tokens in `~/.config/mcp-authlab/tokens.json` with mode 0600. `scan` picks them up on its own, so the critical token and session checks run for anyone who can log in.
- `login` also mints a second token for a different resource (the authorization server's issuer by default, `--foreign-resource` to choose) so the audience-binding check runs. When the authorization server ignores `resource=`, the report says so.
- Six new checks on the authorization server itself, ASF-01 to ASF-06: PKCE required, wrong verifier refused, wrong redirect_uri refused, tokens bound to the requested resource, refresh tokens rotate, HTTPS and `iss` everywhere. They run during `login` and show up in the scan report. A login is two sign-ins; a server that revokes codes after a failed exchange costs a third, and `login --thorough` spends a fourth on the redirect_uri probe.
- A scope step-up check, SCOPE-01: a tool call the token can't make should get a 403 with `error="insufficient_scope"`, a `scope` hint and `resource_metadata`. `--tool` chooses which tool to call; by default the scanner picks a read-only one.
- Every report opens with a coverage line: how many checks ran out of how many apply, and which critical checks didn't run.
- The headline is now a conformance level (Unsafe, Non-conformant, Conformant with warnings, Conformant) read straight from the spec's MUST and SHOULD language. The letter grade stays as the CI knob; `docs/grading.md` shows how to recompute both by hand.
- `--policy file.toml` lets a team set its own bar: `fail_under`, `ignore` and `downgrade`. Ignored checks still run and print. ORIG-01 and VER-01 now carry a note on why operators dispute them; they stay MUST.
- `--format sarif` for GitHub code scanning, and a JSON schema for the report at `docs/report.schema.json`.
- `registry/`: a list of public MCP endpoints and a script that scans them unauthenticated and writes the results and a summary table.
- The fixture grew a small authorization server with consent, PKCE, resource indicators and refresh tokens, plus eight new defect flags and a `stateless` flag. Several fixtures can run in one process.
- `WWW-Authenticate` parsing follows the RFC 9110 grammar: several challenges per header, token68, commas inside quoted strings, escaped quotes.
- `mcp-authlab logout <url>` forgets stored tokens.
- A critical check whose request times out or drops caps the grade at C and shows up in the coverage line, so a server that hangs up on a forged token can't grade A.
- `scan` refreshes an expired foreign-audience token and skips TOK-03 when it can't. An expired token gets a 401 from any server, which would otherwise read as a pass.
- SESS-01 replays the session ID on `tools/list` rather than `initialize`, which catches servers that check the token once and trust the session after that.
- ASM-02 and the callback `iss` check compare issuers as exact strings, as RFC 8414 and RFC 9207 require.
- `--requests` output hides tokens and authorization codes in URLs, along with `Set-Cookie` headers.
- The tokens file sits in a 0700 directory, writes are locked, and a damaged file is left in place for you to look at.
- The fixture's `opaque_tokens` and `issuer_trailing_slash` flags cover opaque access tokens and issuer mismatches.
- The test suite polls for shutdown every 50 ms instead of every 500, and ruff and mypy run in CI.

## 0.1.0 (2026-10-19)

- First release: 26 black-box checks, the reference fixture with seven defect profiles, text, Markdown and JSON reports, `--fail-under` for CI.
