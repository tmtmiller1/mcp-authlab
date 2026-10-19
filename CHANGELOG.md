# Changelog

## 0.2.0 (2026-10-19)

- `mcp-authlab login <url>` signs you in to a server's authorization server with the real authorization code flow (PKCE S256, dynamic registration or `--client-id`, loopback redirect, RFC 8707 `resource`, RFC 9207 `iss` checked) and stores the tokens in `~/.config/mcp-authlab/tokens.json` with mode 0600. `scan` picks them up on its own, so the critical token and session checks run for anyone who can log in.
- `login` also mints a second token for a different resource (the authorization server's issuer by default, `--foreign-resource` to choose) so the audience-binding check runs. When the authorization server ignores `resource=`, the report says so instead of skipping quietly.
- Six new checks on the authorization server itself, ASF-01 to ASF-06: PKCE required, wrong verifier refused, wrong redirect_uri refused, tokens bound to the requested resource, refresh tokens rotate, HTTPS and `iss` everywhere. They run during `login` and show up in the scan report. A login is two sign-ins; a server that revokes codes after a failed exchange costs a third, and `login --thorough` spends a fourth on the redirect_uri probe.
- A scope step-up check, SCOPE-01: a tool call the token can't make should get a 403 with `error="insufficient_scope"`, a `scope` hint and `resource_metadata`. `--tool` chooses which tool to call; by default the scanner picks a read-only one.
- Every report opens with a coverage line: how many checks ran out of how many apply, and which critical checks didn't run.
- The headline is now a conformance level (Unsafe, Non-conformant, Conformant with warnings, Conformant) read straight from the spec's MUST and SHOULD language. The letter grade stays as the CI knob; `docs/grading.md` shows how to recompute both by hand.
- `--policy file.toml` lets a team set its own bar: `fail_under`, `ignore` and `downgrade`. Ignored checks still run and print. ORIG-01 and VER-01 now carry a note on why operators dispute them; they stay MUST.
- `--format sarif` for GitHub code scanning, and a JSON schema for the report at `docs/report.schema.json`.
- `registry/`: a list of public MCP endpoints scanned unauthenticated every Monday by GitHub Actions, with results committed to the repo.
- The fixture grew a small authorization server with consent, PKCE, resource indicators and refresh tokens, plus eight new defect flags and a `stateless` flag. Several fixtures can run in one process.
- `WWW-Authenticate` parsing follows the RFC 9110 grammar: several challenges per header, token68, commas inside quoted strings, escaped quotes.
- `mcp-authlab logout <url>` forgets stored tokens.
- The test suite runs in about four seconds instead of eight; ruff and mypy run in CI.

## 0.1.0 (2026-10-19)

- First release: 26 black-box checks, the reference fixture with seven defect profiles, text, Markdown and JSON reports, `--fail-under` for CI.
