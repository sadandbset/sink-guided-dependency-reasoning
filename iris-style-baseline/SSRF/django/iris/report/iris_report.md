# Augur IRIS Report

Generated at: `2026-10-20T02:02:53.248048+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 3 | SSRF | 4 | 3 | 0 | 3 | 228 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 3 | SSRF | 1 | 0 | 1 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass3` `django/contrib/sitemaps/__init__.py:27` `py/augur/django/pass3-ssrf`: Untrusted URL input reaches a server-side request URL argument (CWE-918, Augur pass 3).
Untrusted URL input reaches a server-side request URL argument (CWE-918, Augur pass 3).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
