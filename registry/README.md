# Public MCP endpoint registry

Scanned 2026-10-19 with mcp-authlab 0.2.0. Unauthenticated scans only: the tool sends a handful of requests (an unauthenticated initialize, the metadata documents, two invalid tokens) and never logs in. Runs every Monday from GitHub Actions. If your server is listed and you want it removed or a finding corrected, [open an issue](https://github.com/tmtmiller1/mcp-authlab/issues).

| Server | Level | Grade | Coverage | Findings |
|---|---|---|---|---|
| [Linear](https://mcp.linear.app/mcp) | Conformant | A (100/100) | coverage 19/33 · critical checks not run: TOK-03, SESS-01 (run `mcp-authlab login` to enable) | nothing to report |
| [Notion](https://mcp.notion.com/mcp) | Conformant | A (100/100) | coverage 19/33 · critical checks not run: TOK-03, SESS-01 (run `mcp-authlab login` to enable) | nothing to report |
| [Sentry](https://mcp.sentry.dev/mcp) | Conformant with warnings | A (98/100) | coverage 19/33 · critical checks not run: TOK-03, SESS-01 (run `mcp-authlab login` to enable) | **CHAL-03** no scope parameter; clients fall back to scopes_supported or request nothing |
| [Asana](https://mcp.asana.com/sse) | Conformant with warnings | A (96/100) | coverage 19/33 · critical checks not run: TOK-03, SESS-01 (run `mcp-authlab login` to enable) | **CHAL-03** no scope parameter; clients fall back to scopes_supported or request nothing<br>**ASM-06** authorization_response_iss_parameter_supported is not true for: https://mcp.asana.com |
| [GitHub](https://api.githubcopilot.com/mcp/) | Non-conformant | C (80/100) | coverage 18/33 · critical checks not run: TOK-03, SESS-01 (run `mcp-authlab login` to enable) | **CHAL-03** no scope parameter; clients fall back to scopes_supported or request nothing<br>**PRM-04** challenge URL returns a different document than the well-known path<br>**ASM-05** no automatic client registration path for: https://github.com/login/oauth; every client needs a pre-registered client_id<br>**TOK-01** expected 401, got 400<br>**TOK-02** refused with 400 rather than 401 |

Coverage counts the checks that ran out of those that apply. The critical checks named as not run need a login, which the registry never does; `mcp-authlab login <url>` runs them for your own server.

Raw results: [2026-10-19](results/2026-10-19.json)
