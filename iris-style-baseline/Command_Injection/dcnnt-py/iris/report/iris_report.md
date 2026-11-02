# Augur IRIS Report

Generated at: `2026-10-15T05:33:59.035811+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 2 | Command/Argument Injection | 71 | 7 | 1 | 12 | 90 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 2 | Command/Argument Injection | 5 | 0 | 5 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass2` `dcnnt/plugins/file_transfer.py:110` `py/augur/dcnnt-py/pass2-command-injection`: Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `dcnnt/plugins/notifications.py:58` `py/augur/dcnnt-py/pass2-command-injection`: Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `dcnnt/plugins/opener.py:34` `py/augur/dcnnt-py/pass2-command-injection`: Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `dcnnt/plugins/opener.py:44` `py/augur/dcnnt-py/pass2-command-injection`: Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `dcnnt/plugins/sync.py:318` `py/augur/dcnnt-py/pass2-command-injection`: Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
Command injection: attacker-controlled value from the phone-side protocol flows unquoted into a shell command executed with shell=True.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
