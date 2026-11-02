# Augur IRIS Report

Generated at: `2026-10-20T01:20:31.581187+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 3 | SSRF | 6 | 2 | 0 | 8 | 217 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 3 | SSRF | 1 | 0 | 1 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass3` `dtale/cli/clickutils.py:244` `py/augur/dtale/pass3-ssrf`: SSRF (CWE-918): untrusted input reaches the URL argument (arg 0) of requests.get inside the shared remote-fetch funnel handle_path. Attacker control: full URL - the /web-upload 'url' query parameter on the unauthenticated route (dtale/views.py:3921) controls scheme (limited to http/https by the is_url prefix check), host, port and path; no host allow-list, no private-IP blocking, no redirect control. The same request's proxy routing is attacker-controlled through the /web-upload 'proxy' parameter (requests proxies mapping, dtale/cli/clickutils.py:240-243).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
