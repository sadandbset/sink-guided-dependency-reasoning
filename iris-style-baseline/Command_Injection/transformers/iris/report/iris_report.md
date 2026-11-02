# Augur IRIS Report

Generated at: `2026-10-19T06:52:29.012836+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 2 | Command/Argument Injection | 30 | 5 | 0 | 3 | 0 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 2 | Command/Argument Injection | 1 | 0 | 1 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass2` `src/transformers/onnx/__main__.py:59` `py/augur/transformers/pass2-command-injection`: Command injection: CLI-provided value reaches a shell command string executed with shell=True (CWE-78).
Command injection: CLI-provided value reaches a shell command string executed with shell=True (CWE-78).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
