# Augur IRIS Report

Generated at: `2026-10-20T08:12:38.408481+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 3 | SSRF | 185 | 47 | 0 | 0 | 71 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 3 | SSRF | 10 | 0 | 10 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass3` `mlflow/server/handlers.py:1143` `py/augur/mlflow/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `mlflow/store/artifact/http_artifact_repo.py:64` `py/augur/mlflow/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `mlflow/store/artifact/http_artifact_repo.py:88` `py/augur/mlflow/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `mlflow/store/artifact/http_artifact_repo.py:104` `py/augur/mlflow/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `mlflow/store/artifact/http_artifact_repo.py:113` `py/augur/mlflow/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `mlflow/store/artifact/http_artifact_repo.py:125` `py/augur/mlflow/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `mlflow/store/artifact/http_artifact_repo.py:139` `py/augur/mlflow/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `mlflow/store/artifact/http_artifact_repo.py:151` `py/augur/mlflow/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `mlflow/utils/request_utils.py:190` `py/augur/mlflow/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `mlflow/utils/rest_utils.py:109` `py/augur/mlflow/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
