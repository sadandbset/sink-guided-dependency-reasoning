# Augur IRIS Report

Generated at: `2026-10-19T14:57:55.646258+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 3 | SSRF | 1468 | 20 | 9 | 155 | 2346 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 3 | SSRF | 3 | 0 | 3 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass3` `homeassistant/components/rest_command/__init__.py:122` `py/augur/core/pass3-ssrf`: SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: template-rendered URL; admin YAML template with authenticated service data variables; host control only if template references a variable in scheme or host.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `homeassistant/components/downloader/__init__.py:81` `py/augur/core/pass3-ssrf`: SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: full URL controlled by any authenticated user (downloader service data, cv.url format check only).
SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: full URL controlled by any authenticated user (downloader service data, cv.url format check only).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `homeassistant/components/hassio/ingress.py:135` `py/augur/core/pass3-ssrf`: SSRF (CWE-918): untrusted input reaches a server-side request URL argument. Attacker control: fixed supervisor host; attacker controls only path/query (ingress-authenticated session).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
