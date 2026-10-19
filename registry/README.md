# Public MCP endpoint registry

Scanned 2026-10-19 with mcp-authlab 0.2.0. Unauthenticated scans only: the tool sends a handful of requests (an unauthenticated initialize, the metadata documents, two invalid tokens) and doesn't log in. The scan is run by hand from time to time. If your server is listed and you want it removed or a finding corrected, [open an issue](https://github.com/tmtmiller1/mcp-authlab/issues/new?template=registry.yml).

| Server | Level | Grade | Coverage | Findings |
|---|---|---|---|---|
| [Linear](https://mcp.linear.app/mcp) | Conformant | A (100/100) | coverage 19/33 · critical checks not run: TOK-03, SESS-01 (run `mcp-authlab login` to enable) | every check that ran passed |
| [Notion](https://mcp.notion.com/mcp) | Conformant | A (100/100) | coverage 19/33 · critical checks not run: TOK-03, SESS-01 (run `mcp-authlab login` to enable) | every check that ran passed |
| [Sentry](https://mcp.sentry.dev/mcp) | Conformant with warnings | A (98/100) | coverage 19/33 · critical checks not run: TOK-03, SESS-01 (run `mcp-authlab login` to enable) | **CHAL-03** the 401 doesn't say which scopes to request, so clients fall back to scopes_supported or ask for a token without scopes |
| [Asana](https://mcp.asana.com/sse) | Conformant with warnings | A (96/100) | coverage 19/33 · critical checks not run: TOK-03, SESS-01 (run `mcp-authlab login` to enable) | **CHAL-03** the 401 doesn't say which scopes to request, so clients fall back to scopes_supported or ask for a token without scopes<br>**ASM-06** authorization_response_iss_parameter_supported isn't true for: https://mcp.asana.com |
| [GitHub](https://api.githubcopilot.com/mcp/) | Non-conformant | C (80/100) | coverage 18/33 · critical checks not run: TOK-03, SESS-01 (run `mcp-authlab login` to enable) | **CHAL-03** the 401 doesn't say which scopes to request, so clients fall back to scopes_supported or ask for a token without scopes<br>**PRM-04** challenge URL returns a different document than the well-known path<br>**ASM-05** clients have to be registered by hand for: https://github.com/login/oauth (neither dynamic registration nor Client ID Metadata Documents is offered)<br>**TOK-01** expected 401, got 400<br>**TOK-02** refused with 400 rather than 401 |

Coverage counts the checks that ran out of those that apply. The critical checks named as not run need a login, and the registry only scans unauthenticated; `mcp-authlab login <url>` runs them for your own server.

Raw results: [2026-10-19](results/2026-10-19.json)
