# Augur IRIS Report

Generated at: `2026-10-24T02:45:54.066135+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 39 | 23 | 0 | 3 | 466 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 13 | 0 | 13 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `thefuck/rules/dirty_untar.py:42` `py/augur/thefuck/pass1-path-traversal`: Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `thefuck/rules/dirty_untar.py:45` `py/augur/thefuck/pass1-path-traversal`: Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `thefuck/rules/dirty_unzip.py:9` `py/augur/thefuck/pass1-path-traversal`: Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `thefuck/rules/dirty_unzip.py:46` `py/augur/thefuck/pass1-path-traversal`: Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `thefuck/rules/dirty_unzip.py:49` `py/augur/thefuck/pass1-path-traversal`: Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `thefuck/shells/generic.py:60` `py/augur/thefuck/pass1-path-traversal`: Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `thefuck/output_readers/read_log.py:93` `py/augur/thefuck/pass1-path-traversal`: Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `thefuck/entrypoints/shell_logger.py:74` `py/augur/thefuck/pass1-path-traversal`: Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `thefuck/rules/ssh_known_hosts.py:33` `py/augur/thefuck/pass1-path-traversal`: Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `thefuck/rules/ssh_known_hosts.py:36` `py/augur/thefuck/pass1-path-traversal`: Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `thefuck/utils.py:217` `py/augur/thefuck/pass1-path-traversal`: Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `thefuck/utils.py:222` `py/augur/thefuck/pass1-path-traversal`: Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `thefuck/utils.py:233` `py/augur/thefuck/pass1-path-traversal`: Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
