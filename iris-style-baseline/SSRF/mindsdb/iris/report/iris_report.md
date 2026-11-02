# Augur IRIS Report

Generated at: `2026-10-20T05:18:09.643144+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 3 | SSRF | 134 | 93 | 0 | 0 | 2 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 3 | SSRF | 2 | 0 | 2 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass3` `mindsdb/api/http/namespaces/file.py:99` `py/augur/mindsdb/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted input from [this request/SQL boundary](1) reaches the URL of a server-side network request at [this network request URL argument](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `mindsdb/api/http/namespaces/file.py:116` `py/augur/mindsdb/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted input from [this request/SQL boundary](1) reaches the URL of a server-side network request at [this network request URL argument](2).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
