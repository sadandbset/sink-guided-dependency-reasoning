# Augur IRIS Report

Generated at: `2026-10-24T03:44:08.163772+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 270 | 61 | 0 | 0 | 45 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 14 | 0 | 14 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `src/App/Extensions.py:61` `py/augur/zope/pass1-path-traversal`: Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/App/Extensions.py:178` `py/augur/zope/pass1-path-traversal`: Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/OFS/ObjectManager.py:622` `py/augur/zope/pass1-path-traversal`: Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/OFS/ObjectManager.py:645` `py/augur/zope/pass1-path-traversal`: Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/OFS/ObjectManager.py:679` `py/augur/zope/pass1-path-traversal`: Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/OFS/ObjectManager.py:707` `py/augur/zope/pass1-path-traversal`: Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/OFS/ObjectManager.py:709` `py/augur/zope/pass1-path-traversal`: Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/Products/Five/browser/resource.py:156` `py/augur/zope/pass1-path-traversal`: Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/Products/Five/browser/resource.py:157` `py/augur/zope/pass1-path-traversal`: Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/Products/Five/browser/resource.py:170` `py/augur/zope/pass1-path-traversal`: Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/Zope2/App/startup.py:51` `py/augur/zope/pass1-path-traversal`: Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/Zope2/App/startup.py:52` `py/augur/zope/pass1-path-traversal`: Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/OFS/userfolder.py:309` `py/augur/zope/pass1-path-traversal`: Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `src/Zope2/App/zcml.py:38` `py/augur/zope/pass1-path-traversal`: Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
