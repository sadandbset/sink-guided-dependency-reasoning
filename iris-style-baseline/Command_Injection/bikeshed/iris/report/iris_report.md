# Augur IRIS Report

Generated at: `2026-10-14T01:32:01.278768+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 2 | Command/Argument Injection | 14 | 20 | 0 | 3 | 12 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 2 | Command/Argument Injection | 3 | 0 | 3 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass2` `bikeshed/cli.py:665` `py/bikeshed/iris/pass2-command-injection`: Tainted data from a labeled input boundary reaches a command-execution sink (CWE-78).
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `release.py:84` `py/bikeshed/iris/pass2-command-injection`: Tainted data from a labeled input boundary reaches a command-execution sink (CWE-78).
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `release.py:98` `py/bikeshed/iris/pass2-command-injection`: Tainted data from a labeled input boundary reaches a command-execution sink (CWE-78).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
