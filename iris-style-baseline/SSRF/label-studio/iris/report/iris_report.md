# Augur IRIS Report

Generated at: `2026-10-20T05:15:38.958521+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 3 | SSRF | 143 | 9 | 2 | 0 | 140 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 3 | SSRF | 5 | 0 | 5 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass3` `label_studio/ml/api_connector.py:81` `py/augur/label-studio/pass3-ssrf`: SSRF (CWE-918): untrusted input reaches the request parameters of the ML-backend HTTP transport (requests.Session.request, URL keyword forwarded via **kwargs). Attacker control: full URL = MLBackend.url (API-writable TextField) joined with a fixed path suffix, supplied by any authenticated projects_change user via /api/ml; validate_upload_url enforces http/https but local-IP blocking is disabled by default (ML_BLOCK_LOCAL_IP=False).
SSRF (CWE-918): untrusted input reaches the request parameters of the ML-backend HTTP transport (requests.Session.request, URL keyword forwarded via **kwargs). Attacker control: full URL = MLBackend.url (API-writable TextField) joined with a fixed path suffix, supplied by any authenticated projects_change user via /api/ml; validate_upload_url enforces http/https but local-IP blocking is disabled by default (ML_BLOCK_LOCAL_IP=False).
SSRF (CWE-918): untrusted input reaches the request parameters of the ML-backend HTTP transport (requests.Session.request, URL keyword forwarded via **kwargs). Attacker control: full URL = MLBackend.url (API-writable TextField) joined with a fixed path suffix, supplied by any authenticated projects_change user via /api/ml; validate_upload_url enforces http/https but local-IP blocking is disabled by default (ML_BLOCK_LOCAL_IP=False).
SSRF (CWE-918): untrusted input reaches the request parameters of the ML-backend HTTP transport (requests.Session.request, URL keyword forwarded via **kwargs). Attacker control: full URL = MLBackend.url (API-writable TextField) joined with a fixed path suffix, supplied by any authenticated projects_change user via /api/ml; validate_upload_url enforces http/https but local-IP blocking is disabled by default (ML_BLOCK_LOCAL_IP=False).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `label_studio/core/utils/io.py:224` `py/augur/label-studio/pass3-ssrf`: SSRF (CWE-918): untrusted input reaches the URL argument of a server-side HTTP request (requests.get inside ssrf_safe_get). Attacker control: full URL (host, port, path; scheme restricted to http/https by validate_upload_url) supplied by any authenticated projects_change user via POST /api/projects/{{pk}}/import; private-IP blocking and the post-connection peer check are disabled by default (SSRF_PROTECTION_ENABLED=False).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `label_studio/webhooks/utils.py:53` `py/augur/label-studio/pass3-ssrf`: SSRF (CWE-918): untrusted input reaches the URL argument of a server-side HTTP request (webhook delivery requests.post). Attacker control: full URL (Webhook.url URLField syntax check only, no scheme allow-list / host / private-IP validation on delivery) supplied by any authenticated organization member via /api/webhooks; Webhook.headers additionally gives control over the outbound request headers.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `label_studio/io_storages/s3/utils.py:38` `py/augur/label-studio/pass3-ssrf`: SSRF (CWE-918): untrusted input reaches the endpoint configuration of a boto3 S3 client (session.client('s3', **settings) with endpoint_url; server-side HTTP performed by botocore). Attacker control: full endpoint URL (host, port, base path) from the API-writable S3ImportStorage/S3ExportStorage.s3_endpoint TextField (projects_change) or the operator S3_ENDPOINT environment fallback.
SSRF (CWE-918): untrusted input reaches the endpoint configuration of a boto3 S3 client (session.client('s3', **settings) with endpoint_url; server-side HTTP performed by botocore). Attacker control: full endpoint URL (host, port, base path) from the API-writable S3ImportStorage/S3ExportStorage.s3_endpoint TextField (projects_change) or the operator S3_ENDPOINT environment fallback.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `label_studio/io_storages/s3/utils.py:39` `py/augur/label-studio/pass3-ssrf`: SSRF (CWE-918): untrusted input reaches the endpoint configuration of a boto3 S3 resource (session.resource('s3', **settings) with endpoint_url; server-side HTTP performed by botocore). Attacker control: full endpoint URL (host, port, base path) from the API-writable S3ImportStorage/S3ExportStorage.s3_endpoint TextField (projects_change) or the operator S3_ENDPOINT environment fallback.
SSRF (CWE-918): untrusted input reaches the endpoint configuration of a boto3 S3 resource (session.resource('s3', **settings) with endpoint_url; server-side HTTP performed by botocore). Attacker control: full endpoint URL (host, port, base path) from the API-writable S3ImportStorage/S3ExportStorage.s3_endpoint TextField (projects_change) or the operator S3_ENDPOINT environment fallback.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
