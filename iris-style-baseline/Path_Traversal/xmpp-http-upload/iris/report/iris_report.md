# Augur IRIS Report

Generated at: `2026-10-24T03:42:39.972539+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 4 | 7 | 0 | 8 | 13 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 7 | 0 | 7 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `xhu.py:57` `py/augur/xmpp-http-upload/pass1-path-traversal`: Tainted route-parameter path data flows into a filesystem access. The sanitized_join guard at xhu.py:42-46 compares the un-normalized (root / path).absolute() string lexically, so '..' segments in the request path escape the declared DATA_ROOT when the OS resolves them at the file access (CWE-022/023/036/073).
Tainted route-parameter path data flows into a filesystem access. The sanitized_join guard at xhu.py:42-46 compares the un-normalized (root / path).absolute() string lexically, so '..' segments in the request path escape the declared DATA_ROOT when the OS resolves them at the file access (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `xhu.py:76` `py/augur/xmpp-http-upload/pass1-path-traversal`: Tainted route-parameter path data flows into a filesystem access. The sanitized_join guard at xhu.py:42-46 compares the un-normalized (root / path).absolute() string lexically, so '..' segments in the request path escape the declared DATA_ROOT when the OS resolves them at the file access (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `xhu.py:80` `py/augur/xmpp-http-upload/pass1-path-traversal`: Tainted route-parameter path data flows into a filesystem access. The sanitized_join guard at xhu.py:42-46 compares the un-normalized (root / path).absolute() string lexically, so '..' segments in the request path escape the declared DATA_ROOT when the OS resolves them at the file access (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `xhu.py:137` `py/augur/xmpp-http-upload/pass1-path-traversal`: Tainted route-parameter path data flows into a filesystem access. The sanitized_join guard at xhu.py:42-46 compares the un-normalized (root / path).absolute() string lexically, so '..' segments in the request path escape the declared DATA_ROOT when the OS resolves them at the file access (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `xhu.py:144` `py/augur/xmpp-http-upload/pass1-path-traversal`: Tainted route-parameter path data flows into a filesystem access. The sanitized_join guard at xhu.py:42-46 compares the un-normalized (root / path).absolute() string lexically, so '..' segments in the request path escape the declared DATA_ROOT when the OS resolves them at the file access (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `xhu.py:197` `py/augur/xmpp-http-upload/pass1-path-traversal`: Tainted route-parameter path data flows into a filesystem access. The sanitized_join guard at xhu.py:42-46 compares the un-normalized (root / path).absolute() string lexically, so '..' segments in the request path escape the declared DATA_ROOT when the OS resolves them at the file access (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `xhu.py:229` `py/augur/xmpp-http-upload/pass1-path-traversal`: Tainted route-parameter path data flows into a filesystem access. The sanitized_join guard at xhu.py:42-46 compares the un-normalized (root / path).absolute() string lexically, so '..' segments in the request path escape the declared DATA_ROOT when the OS resolves them at the file access (CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
