# Augur IRIS Report

Generated at: `2026-10-22T02:41:45.694503+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 194 | 98 | 19 | 27 | 400 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 4 | 0 | 4 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `django/contrib/sessions/backends/file.py:78` `py/augur/django/pass1-path-traversal`: Request-controlled data reaches the path operand of a filesystem access; unescaped traversal can escape the intended root directory (CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `django/contrib/sessions/backends/file.py:126` `py/augur/django/pass1-path-traversal`: Request-controlled data reaches the path operand of a filesystem access; unescaped traversal can escape the intended root directory (CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `django/contrib/sessions/backends/file.py:164` `py/augur/django/pass1-path-traversal`: Request-controlled data reaches the path operand of a filesystem access; unescaped traversal can escape the intended root directory (CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `django/contrib/sessions/backends/file.py:181` `py/augur/django/pass1-path-traversal`: Request-controlled data reaches the path operand of a filesystem access; unescaped traversal can escape the intended root directory (CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
