# Augur IRIS Report

Generated at: `2026-10-14T05:01:19.131674+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 2 | Command/Argument Injection | 1 | 2 | 0 | 0 | 0 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 2 | Command/Argument Injection | 2 | 2 | 0 | 0 |

## Top Likely True Positives

- `pass2` `src/abilian/devtools/main.py:14` `py/augur/abilian-devtools/pass2-command-injection`: CLI-provided file or directory name reaches a shell command executed by os.system (CWE-78).
  - Reason: command injection dangerous shell pattern: `os\.system|popen\(|exec\(`
- `pass2` `src/abilian/devtools/main.py:16` `py/augur/abilian-devtools/pass2-command-injection`: CLI-provided file or directory name reaches a shell command executed by os.system (CWE-78).
  - Reason: command injection dangerous shell pattern: `os\.system|popen\(|exec\(`

## Candidate Findings (Need Analyst Review)

No unresolved candidates.

## Filtered as Likely False Positives

No findings matched FP heuristics.
