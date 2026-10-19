# Security

## Reporting a vulnerability in mcp-authlab

Use GitHub's private vulnerability reporting: the **Report a vulnerability** button under this repository's [Security tab](https://github.com/tmtmiller1/mcp-authlab/security/advisories/new). Please report it there rather than in a public issue.

Things that count as a vulnerability here:

- a token, authorization code or session ID ending up somewhere it shouldn't: a report, the request log, an error message, or a host other than the one you scanned
- the token store at `~/.config/mcp-authlab/tokens.json` readable by other users
- a check that reports a pass for a server that breaks the rule it tests, in a way an attacker could arrange

A wrong grade that isn't exploitable is an ordinary bug; open an issue for it.

## What the tool sends

- `scan` sends a few dozen requests to the server you name and to the metadata and authorization server URLs that server advertises. It only fetches `http` and `https` URLs, and it never follows redirects.
- Bearer tokens only go to the MCP endpoint you name. The deliberately bad tokens it sends are random strings and an unsigned JWT that it makes up on the spot.
- Every session the scan opens, it closes with a `DELETE`. The only tool it calls is a read-only one (or the one you pick with `--tool`).
- `login` registers one client with the authorization server and signs in as you. Two of its probes deliberately send a wrong `code_verifier` and a wrong `redirect_uri` to the token endpoint.

Logging in and probing with tokens is a security test, so only do that against servers you run or have permission to test. The public [registry](registry/README.md) sticks to the unauthenticated checks, which send what any client sends while connecting, plus two invalid tokens.

## Reporting a problem with a server in the registry

If a registry entry is about your server and you want it removed or a finding corrected, [open a registry issue](https://github.com/tmtmiller1/mcp-authlab/issues/new?template=registry.yml). If you've found a vulnerability in someone else's MCP server, report it to that vendor, not here.
