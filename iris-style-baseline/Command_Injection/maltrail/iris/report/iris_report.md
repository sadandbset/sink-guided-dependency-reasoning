# Augur IRIS Report

Generated at: `2026-10-15T09:26:29.497439+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 2 | Command/Argument Injection | 158 | 30 | 0 | 46 | 317 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 2 | Command/Argument Injection | 1 | 0 | 1 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass2` `core/httpd.py:399` `py/augur/maltrail/pass2-command-injection`: Command injection: attacker-controlled HTTP request value (request parameter, header, POST body or client address) flows unquoted into a shell command string executed with shell=True.
Command injection: attacker-controlled HTTP request value (request parameter, header, POST body or client address) flows unquoted into a shell command string executed with shell=True.
Command injection: attacker-controlled HTTP request value (request parameter, header, POST body or client address) flows unquoted into a shell command string executed with shell=True.
Command injection: attacker-controlled HTTP request value (request parameter, header, POST body or client address) flows unquoted into a shell command string executed with shell=True.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
