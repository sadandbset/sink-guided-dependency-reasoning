# Augur IRIS Report

Generated at: `2026-10-16T00:05:18.458956+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 2 | Command/Argument Injection | 1092 | 17 | 0 | 20 | 576 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 2 | Command/Argument Injection | 2 | 0 | 2 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass2` `web/pgadmin/misc/__init__.py:274` `py/augur/pgadmin4/pass2-command-injection`: Command injection: attacker-controlled value (HTTP request body/field, URL path parameter, /pty socket payload, imported file content, or the batch-job command transported through process_executor sys.argv) flows into a command-execution site (shell command string via getoutput, or the BatchProcess command list executed with shell=True on Windows).
Command injection: attacker-controlled value (HTTP request body/field, URL path parameter, /pty socket payload, imported file content, or the batch-job command transported through process_executor sys.argv) flows into a command-execution site (shell command string via getoutput, or the BatchProcess command list executed with shell=True on Windows).
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `web/pgadmin/misc/bgprocess/process_executor.py:331` `py/augur/pgadmin4/pass2-command-injection`: Command injection: attacker-controlled value (HTTP request body/field, URL path parameter, /pty socket payload, imported file content, or the batch-job command transported through process_executor sys.argv) flows into a command-execution site (shell command string via getoutput, or the BatchProcess command list executed with shell=True on Windows).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
