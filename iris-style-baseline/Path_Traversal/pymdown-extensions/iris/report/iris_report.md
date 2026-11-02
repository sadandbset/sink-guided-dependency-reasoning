# Augur IRIS Report

Generated at: `2026-10-23T02:41:39.269955+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 7 | 4 | 1 | 13 | 48 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 2 | 0 | 2 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `pymdownx/b64.py:86` `py/augur/pymdown-extensions/pass1-path-traversal`: This filesystem path argument is controlled by untrusted input (Markdown source or rendered output) and is used for file access without a base-directory containment check (path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `pymdownx/snippets.py:311` `py/augur/pymdown-extensions/pass1-path-traversal`: This filesystem path argument is controlled by untrusted input (Markdown source or rendered output) and is used for file access without a base-directory containment check (path traversal, CWE-22/23/36/73).
This filesystem path argument is controlled by untrusted input (Markdown source or rendered output) and is used for file access without a base-directory containment check (path traversal, CWE-22/23/36/73).
This filesystem path argument is controlled by untrusted input (Markdown source or rendered output) and is used for file access without a base-directory containment check (path traversal, CWE-22/23/36/73).
This filesystem path argument is controlled by untrusted input (Markdown source or rendered output) and is used for file access without a base-directory containment check (path traversal, CWE-22/23/36/73).
This filesystem path argument is controlled by untrusted input (Markdown source or rendered output) and is used for file access without a base-directory containment check (path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
