# Contributing

Bug reports, false positives and new checks are all welcome. For anything bigger than a small fix, open an issue first so we can agree on the shape.

## Setup

Python 3.11 or newer. The tool itself has no dependencies; the linters are only for development.

```
pip install -e . ruff==0.15.22 mypy==2.1.0
python3 -m unittest discover -s tests
ruff check src tests && ruff format --check src tests && mypy src
```

CI runs all three on Python 3.11, 3.12 and 3.13, plus `scripts/demo.sh` against every fixture profile.

## Adding a check

1. Add it to `CATALOG` in `src/mcp_authlab/catalog.py` with the spec text it enforces in `cite` and a link in `url`. Use MUST or SHOULD exactly as the spec does.
2. Implement it in `scanner.Scanner`, or in `oauthclient.Login` if it probes the authorization server.
3. Add a defect flag to `fixture.Profile` that breaks the rule, and put the check in `EXPECTED_FAILURES` for a profile that sets that flag. The profile tests fail until the scanner catches it.
4. Regenerate the docs with `mcp-authlab checks --markdown > docs/checks.md`. A test fails while that file is stale.
5. Add a line to `CHANGELOG.md` describing what a user sees.

A check has to be provable from outside the server. If the only way to know is to read the server's code, it belongs in the Limits section of the README, not the catalog.

## Reporting a false positive

Run the scan with `--format json --requests` and attach the result. Tokens, codes and session IDs are already redacted, but read it over before posting. Say which check is wrong and which spec text you think applies.

## Writing

Docs, messages and the changelog are written plainly, the way you'd explain the thing out loud: contractions, active voice, and what the user sees rather than what the code avoids.
