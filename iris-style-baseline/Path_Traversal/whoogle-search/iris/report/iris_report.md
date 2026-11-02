# Augur IRIS Report

Generated at: `2026-10-24T02:46:58.265057+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 81 | 7 | 0 | 22 | 139 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 2 | 0 | 2 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `app/routes.py:430` `py/augur/whoogle-search/pass1-path-traversal`: Untrusted request input reaches the path argument of a filesystem access API with no containment check, allowing traversal outside the intended base directory (CWE-22/23/36/73).
Untrusted request input reaches the path argument of a filesystem access API with no containment check, allowing traversal outside the intended base directory (CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `app/routes.py:445` `py/augur/whoogle-search/pass1-path-traversal`: Untrusted request input reaches the path argument of a filesystem access API with no containment check, allowing traversal outside the intended base directory (CWE-22/23/36/73).
Untrusted request input reaches the path argument of a filesystem access API with no containment check, allowing traversal outside the intended base directory (CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
