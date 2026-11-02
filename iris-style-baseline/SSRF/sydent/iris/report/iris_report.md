# Augur IRIS Report

Generated at: `2026-10-20T10:52:56.817459+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 3 | SSRF | 112 | 16 | 0 | 2 | 9 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 3 | SSRF | 1 | 0 | 1 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass3` `sydent/http/servlets/registerservlet.py:60` `py/augur/sydent/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted request data reaches the URL/host of a server-side outbound matrix:// federation or HTTPS request.
Server-side request forgery (CWE-918): untrusted request data reaches the URL/host of a server-side outbound matrix:// federation or HTTPS request.
Server-side request forgery (CWE-918): untrusted request data reaches the URL/host of a server-side outbound matrix:// federation or HTTPS request.
Server-side request forgery (CWE-918): untrusted request data reaches the URL/host of a server-side outbound matrix:// federation or HTTPS request.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
