# Augur IRIS Report

Generated at: `2026-10-23T13:08:18.662468+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 138 | 19 | 1 | 10 | 21 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 6 | 0 | 6 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `starlette/responses.py:288` `py/augur/starlette/pass1-path-traversal`: Untrusted request path flows to a file access API; possible path traversal outside the declared static root (CWE-022/023/036/073).
Untrusted request path flows to a file access API; possible path traversal outside the declared static root (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `starlette/responses.py:335` `py/augur/starlette/pass1-path-traversal`: Untrusted request path flows to a file access API; possible path traversal outside the declared static root (CWE-022/023/036/073).
Untrusted request path flows to a file access API; possible path traversal outside the declared static root (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `starlette/responses.py:353` `py/augur/starlette/pass1-path-traversal`: Untrusted request path flows to a file access API; possible path traversal outside the declared static root (CWE-022/023/036/073).
Untrusted request path flows to a file access API; possible path traversal outside the declared static root (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `starlette/staticfiles.py:155` `py/augur/starlette/pass1-path-traversal`: Untrusted request path flows to a file access API; possible path traversal outside the declared static root (CWE-022/023/036/073).
Untrusted request path flows to a file access API; possible path traversal outside the declared static root (CWE-022/023/036/073).
Untrusted request path flows to a file access API; possible path traversal outside the declared static root (CWE-022/023/036/073).
Untrusted request path flows to a file access API; possible path traversal outside the declared static root (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `starlette/staticfiles.py:177` `py/augur/starlette/pass1-path-traversal`: Untrusted request path flows to a file access API; possible path traversal outside the declared static root (CWE-022/023/036/073).
Untrusted request path flows to a file access API; possible path traversal outside the declared static root (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `starlette/staticfiles.py:193` `py/augur/starlette/pass1-path-traversal`: Untrusted request path flows to a file access API; possible path traversal outside the declared static root (CWE-022/023/036/073).
Untrusted request path flows to a file access API; possible path traversal outside the declared static root (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
