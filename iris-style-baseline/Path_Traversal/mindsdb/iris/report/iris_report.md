# Augur IRIS Report

Generated at: `2026-10-22T09:06:51.395803+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 29 | 28 | 0 | 33 | 110 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 10 | 0 | 10 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `mindsdb/api/http/namespaces/config.py:137` `py/augur/mindsdb/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `mindsdb/api/http/namespaces/file.py:123` `py/augur/mindsdb/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `mindsdb/api/http/namespaces/file.py:133` `py/augur/mindsdb/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `mindsdb/api/http/namespaces/file.py:136` `py/augur/mindsdb/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `mindsdb/api/http/namespaces/file.py:138` `py/augur/mindsdb/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `mindsdb/interfaces/file/file_controller.py:100` `py/augur/mindsdb/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `mindsdb/interfaces/file/file_controller.py:100` `py/augur/mindsdb/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `mindsdb/integrations/handlers/file_handler/file_handler.py:158` `py/augur/mindsdb/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `mindsdb/api/http/namespaces/handlers.py:136` `py/augur/mindsdb/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `mindsdb/interfaces/database/integrations.py:68` `py/augur/mindsdb/pass1-path-traversal`: Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
