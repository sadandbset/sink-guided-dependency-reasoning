# Augur IRIS Report

Generated at: `2026-10-16T07:56:48.774562+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 2 | Command/Argument Injection | 434 | 24 | 1 | 3 | 615 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 2 | Command/Argument Injection | 3 | 0 | 3 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass2` `configure.py:150` `py/augur/tensorflow/pass2-command-injection`: Untrusted input flows from [untrusted source](1) into a command/argument execution sink ([execution sink](2)). Augur pass 2 (CWE-78): the source is a reviewed tp label (tfdbg gRPC receive boundary, CLI argument, interactive input or urlopen response) and the sink is a labeled subprocess command-execution site (shell=True string command or argv-list command with external/parameter-influenced operands). The reviewed sites have static, internally derived or list-form operands - review before treating this as a vulnerability.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `configure.py:154` `py/augur/tensorflow/pass2-command-injection`: Untrusted input flows from [untrusted source](1) into a command/argument execution sink ([execution sink](2)). Augur pass 2 (CWE-78): the source is a reviewed tp label (tfdbg gRPC receive boundary, CLI argument, interactive input or urlopen response) and the sink is a labeled subprocess command-execution site (shell=True string command or argv-list command with external/parameter-influenced operands). The reviewed sites have static, internally derived or list-form operands - review before treating this as a vulnerability.
  - Reason: no explicit FP/TP heuristic matched
- `pass2` `configure.py:1247` `py/augur/tensorflow/pass2-command-injection`: Untrusted input flows from [untrusted source](1) into a command/argument execution sink ([execution sink](2)). Augur pass 2 (CWE-78): the source is a reviewed tp label (tfdbg gRPC receive boundary, CLI argument, interactive input or urlopen response) and the sink is a labeled subprocess command-execution site (shell=True string command or argv-list command with external/parameter-influenced operands). The reviewed sites have static, internally derived or list-form operands - review before treating this as a vulnerability.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
