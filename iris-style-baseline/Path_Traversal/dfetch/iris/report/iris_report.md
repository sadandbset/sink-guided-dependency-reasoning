# Augur IRIS Report

Generated at: `2026-10-22T02:43:27.746907+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 11 | 16 | 0 | 33 | 100 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 15 | 0 | 15 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `dfetch/commands/diff.py:171` `py/augur/dfetch/pass1-path-traversal`: Untrusted dfetch input ([this input boundary](1)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](2)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](3)) flows to a filesystem operation at an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `dfetch/project/git.py:70` `py/augur/dfetch/pass1-path-traversal`: Untrusted dfetch input ([this input boundary](1)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](2)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](3)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](4)) flows to a filesystem operation at an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `dfetch/project/metadata.py:70` `py/augur/dfetch/pass1-path-traversal`: Untrusted dfetch input ([this input boundary](1)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](2)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](3)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](4)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](5)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](6)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](7)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](8)) flows to a filesystem operation at an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `dfetch/project/metadata.py:165` `py/augur/dfetch/pass1-path-traversal`: Untrusted dfetch input ([this input boundary](1)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](2)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](3)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](4)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](5)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](6)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](7)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](8)) flows to a filesystem operation at an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `dfetch/project/svn.py:196` `py/augur/dfetch/pass1-path-traversal`: Untrusted dfetch input ([this input boundary](1)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](2)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](3)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](4)) flows to a filesystem operation at an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `dfetch/project/svn.py:206` `py/augur/dfetch/pass1-path-traversal`: Untrusted dfetch input ([this input boundary](1)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](2)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](3)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](4)) flows to a filesystem operation at an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `dfetch/project/svn.py:242` `py/augur/dfetch/pass1-path-traversal`: Untrusted dfetch input ([this input boundary](1)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](2)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](3)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](4)) flows to a filesystem operation at an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `dfetch/project/svn.py:245` `py/augur/dfetch/pass1-path-traversal`: Untrusted dfetch input ([this input boundary](1)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](2)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](3)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](4)) flows to a filesystem operation at an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `dfetch/util/util.py:14` `py/augur/dfetch/pass1-path-traversal`: Untrusted dfetch input ([this input boundary](1)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](2)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](3)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](4)) flows to a filesystem operation at an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `dfetch/util/util.py:33` `py/augur/dfetch/pass1-path-traversal`: Untrusted dfetch input ([this input boundary](1)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](2)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](3)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](4)) flows to a filesystem operation at an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `dfetch/util/util.py:39` `py/augur/dfetch/pass1-path-traversal`: Untrusted dfetch input ([this input boundary](1)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](2)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](3)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](4)) flows to a filesystem operation at an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `dfetch/util/util.py:52` `py/augur/dfetch/pass1-path-traversal`: Untrusted dfetch input ([this input boundary](1)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](2)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](3)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](4)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](5)) flows to a filesystem operation at an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `dfetch/util/util.py:107` `py/augur/dfetch/pass1-path-traversal`: Untrusted dfetch input ([this input boundary](1)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](2)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](3)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](4)) flows to a filesystem operation at an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `dfetch/project/vcs.py:134` `py/augur/dfetch/pass1-path-traversal`: Untrusted dfetch input ([this input boundary](1)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](2)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](3)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](4)) flows to a filesystem operation at an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `dfetch/project/vcs.py:138` `py/augur/dfetch/pass1-path-traversal`: Untrusted dfetch input ([this input boundary](1)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](2)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](3)) flows to a filesystem operation at an attacker-influenced path.
Untrusted dfetch input ([this input boundary](4)) flows to a filesystem operation at an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
