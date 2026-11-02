# Augur IRIS Report

Generated at: `2026-10-22T07:11:36.005919+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 3 | 2 | 2 | 1 | 196 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 2 | 0 | 0 | 2 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

No unresolved candidates.

## Filtered as Likely False Positives

- `pass1` `src/fides/api/main.py:170` `py/augur/fides/pass1-path-traversal`: Tainted request-derived path data ([this request path parameter](1)) reaches a filesystem access on the catch-all static-file route. The requested path is joined into the packaged admin-UI directory without canonicalization and the lexical path_is_in_ui_directory guard does not reject '..' segments, so the served file may escape the UI root (CWE-022/023/036/073).
  - Reason: path traversal guard heuristic: `reject|deny|block.*\.\.`
- `pass1` `src/fides/api/main.py:180` `py/augur/fides/pass1-path-traversal`: Tainted request-derived path data ([this request path parameter](1)) reaches a filesystem access on the catch-all static-file route. The requested path is joined into the packaged admin-UI directory without canonicalization and the lexical path_is_in_ui_directory guard does not reject '..' segments, so the served file may escape the UI root (CWE-022/023/036/073).
  - Reason: path traversal guard heuristic: `reject|deny|block.*\.\.`
