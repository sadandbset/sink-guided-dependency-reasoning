# Augur IRIS Report

Generated at: `2026-10-16T01:53:19.851898+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 2 | Command/Argument Injection | 4 | 14 | 0 | 0 | 405 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 2 | Command/Argument Injection | 2 | 0 | 2 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass2` `tasks.py:107` `py/augur/pydash/pass2-command-injection`: Command injection: untrusted data (CLI task parameter or environment-derived value) flows into the shell command string passed to invoke.run().
Command injection: untrusted data (CLI task parameter or environment-derived value) flows into the shell command string passed to invoke.run().
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `tasks.py:134` `py/augur/pydash/pass2-command-injection`: Command injection: untrusted data (CLI task parameter or environment-derived value) flows into the shell command string passed to invoke.run().
Command injection: untrusted data (CLI task parameter or environment-derived value) flows into the shell command string passed to invoke.run().
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
