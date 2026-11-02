# Augur IRIS Report

Generated at: `2026-10-22T12:42:52.022065+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 20 | 23 | 0 | 31 | 14 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 21 | 0 | 21 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass1` `openapi_python_client/__init__.py:109` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:125` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:146` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:151` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:154` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:160` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:172` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:181` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:186` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:192` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:197` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:204` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:208` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:214` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:218` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:220` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:223` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:225` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:229` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:235` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched
- `pass1` `openapi_python_client/__init__.py:237` `py/augur/openapi-python-client/pass1-path-traversal`: Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
