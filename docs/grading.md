# How a scan is graded

A report has two headline results. The **conformance level** comes straight from the RFC 2119 language in the spec: it says whether anything the spec calls MUST is broken. The **letter grade** is a weighted score for people who want a single knob to gate CI on. You can recompute both from the `results` array of a JSON report with nothing but this page.

Every number on this page is also in one place in the code: the `GRADING` dict in `src/mcp_authlab/grading.py`. A test fails if the two drift apart.

## Which results count

Each result has a `status`:

| status | meaning |
|---|---|
| `pass` | the check ran and the server did what the spec says |
| `fail` | the check ran and the server broke a MUST or SHOULD |
| `warn` | the check ran and found something short of a failure: a SHOULD the server skipped, or a MUST answered the wrong way without an outright break (loopback http, a 200 where a 400 was due) |
| `skip` | the check could not run. `message` says why; `applicable` is false when the server lacks the feature the check tests (a stateless server doesn't issue session IDs) |
| `error` | the request itself failed (timeout, connection refused) |

Only `pass`, `fail` and `warn` results take part in grading. A result with `counted: false` was ignored by a policy file: it still prints, but the rules below skip it.

Each result also has `effective_level` (MUST or SHOULD) and `effective_critical`. They equal the catalog's `level` and `critical` unless a policy downgraded the check. Use the effective values below.

## Conformance level

Walk these rules top down and stop at the first match:

1. Any counted `fail` where `effective_critical` is true: **Unsafe**.
2. Any counted `fail` where `effective_level` is MUST: **Non-conformant**.
3. Any counted `fail` or `warn` at all: **Conformant with warnings**.
4. Otherwise: **Conformant**.

So a server that only misses SHOULD items, or that runs on plain http on localhost, is "Conformant with warnings". One critical failure is "Unsafe" even if everything else passes.

## Score

Each counted result that ran gets a weight:

| effective level | weight |
|---|---|
| critical | 20 |
| MUST | 10 |
| SHOULD | 3 |

A `pass` earns the full weight. A `warn` on a MUST check earns half (5); a `warn` on a SHOULD check earns 0. A `fail` earns 0.

```
score = round(100 × earned / total)
```

`total` is the sum of weights of results that ran, so skipped and errored checks are left out of the denominator and an unauthenticated scan isn't penalised for what it couldn't test. That's why the coverage line is the first thing in every report. With no results at all the score is 0.

## Letter grade

Start from the score:

| letter | score at least |
|---|---|
| A | 95 |
| B | 85 |
| C | 70 |
| D | 50 |

Below 50 is F. Then apply, in order:

1. Any counted critical `fail`: **F**.
2. CHAL-01 counted and `fail` (the server answered an unauthenticated request with something other than 401): **F**.
3. Any counted MUST `fail`: the letter is capped at **C**. A score of 98 with one MUST failure is a C.
4. Any counted critical check with status `error`: the letter is capped at **C** too. The request for a forged token or a session replay timed out or dropped, so the scan couldn't confirm the server is safe. The coverage line lists these checks as not run.

## Worked example

A JSON report with these counted results (everything else skipped):

| id | level | critical | status | weight | earned |
|---|---|---|---|---|---|
| TLS-01 | MUST | no | pass | 10 | 10 |
| CHAL-01 | MUST | no | pass | 10 | 10 |
| CHAL-03 | SHOULD | no | warn | 3 | 0 |
| PRM-01 | MUST | no | fail | 10 | 0 |
| TOK-02 | MUST | yes | pass | 20 | 20 |

total 53, earned 40, score = round(100 × 40 / 53) = 75. Score says C. PRM-01 is a MUST failure, so the cap applies and the letter stays C. Level: PRM-01 is a MUST failure and isn't critical, so **Non-conformant**.

Now ignore PRM-01 with a policy: total 43, earned 40, score 93, letter B, level **Conformant with warnings** (CHAL-03 still warns).

## Policy files

`--policy authlab.toml` lets an organisation write its own bar down once:

```toml
fail_under = "B"                       # exit 2 below this letter; --fail-under on the command line wins
ignore = ["VER-01"]                    # still runs and prints, stops counting
downgrade = { "ORIG-01" = "SHOULD" }   # counts as SHOULD and stops being critical
```

[examples/policy.toml](../examples/policy.toml) explains each key. Two catalog entries carry a `disputed` note for this reason: ORIG-01 (Origin validation) and VER-01 (protocol version refusal) are MUST in the spec and often argued about by operators. They stay MUST here because the spec says so; the policy file is where your organisation records its own decision.

## Reading the report's own summary

The JSON report already carries the outcome of these rules so you can check your arithmetic: `conformance`, `grade`, `score`, `reasons`, `critical_failures`, `must_failures`, `warnings` and `ignored`. The schema is at [report.schema.json](report.schema.json).
