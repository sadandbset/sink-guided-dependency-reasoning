# Augur IRIS Report

Generated at: `2026-10-14T12:12:53.627496+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 2 | Command/Argument Injection | 29 | 5 | 0 | 25 | 25 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 2 | Command/Argument Injection | 3 | 0 | 3 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass2` `binderhub/build.py:325` `py/augur/binderhub/pass2-command-injection`: User-controlled request data flows into a command execution sink (CWE-78: command/argument injection). The tainted value is passed as a command or argument element, not necessarily through a shell.
User-controlled request data flows into a command execution sink (CWE-78: command/argument injection). The tainted value is passed as a command or argument element, not necessarily through a shell.
User-controlled request data flows into a command execution sink (CWE-78: command/argument injection). The tainted value is passed as a command or argument element, not necessarily through a shell.
User-controlled request data flows into a command execution sink (CWE-78: command/argument injection). The tainted value is passed as a command or argument element, not necessarily through a shell.
User-controlled request data flows into a command execution sink (CWE-78: command/argument injection). The tainted value is passed as a command or argument element, not necessarily through a shell.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `binderhub/build.py:343` `py/augur/binderhub/pass2-command-injection`: User-controlled request data flows into a command execution sink (CWE-78: command/argument injection). The tainted value is passed as a command or argument element, not necessarily through a shell.
User-controlled request data flows into a command execution sink (CWE-78: command/argument injection). The tainted value is passed as a command or argument element, not necessarily through a shell.
User-controlled request data flows into a command execution sink (CWE-78: command/argument injection). The tainted value is passed as a command or argument element, not necessarily through a shell.
User-controlled request data flows into a command execution sink (CWE-78: command/argument injection). The tainted value is passed as a command or argument element, not necessarily through a shell.
User-controlled request data flows into a command execution sink (CWE-78: command/argument injection). The tainted value is passed as a command or argument element, not necessarily through a shell.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `binderhub/build.py:378` `py/augur/binderhub/pass2-command-injection`: User-controlled request data flows into a command execution sink (CWE-78: command/argument injection). The tainted value is passed as a command or argument element, not necessarily through a shell.
User-controlled request data flows into a command execution sink (CWE-78: command/argument injection). The tainted value is passed as a command or argument element, not necessarily through a shell.
User-controlled request data flows into a command execution sink (CWE-78: command/argument injection). The tainted value is passed as a command or argument element, not necessarily through a shell.
User-controlled request data flows into a command execution sink (CWE-78: command/argument injection). The tainted value is passed as a command or argument element, not necessarily through a shell.
User-controlled request data flows into a command execution sink (CWE-78: command/argument injection). The tainted value is passed as a command or argument element, not necessarily through a shell.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
