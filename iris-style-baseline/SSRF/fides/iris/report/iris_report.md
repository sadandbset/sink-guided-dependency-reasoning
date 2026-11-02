# Augur IRIS Report

Generated at: `2026-10-20T02:00:44.170345+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 3 | SSRF | 26 | 30 | 0 | 1 | 133 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 3 | SSRF | 3 | 0 | 3 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass3` `src/fides/api/service/messaging/message_dispatch_service.py:472` `py/augur/fides/pass3-ssrf`: SSRF (path-only, host pinned): config-boundary data reaches only path segments of a request to a fixed host (api.yotpo.com, or api.mailgun.net / api.eu.mailgun.net selected by a boolean). The destination host cannot be relocated by the submitting client; lower severity than host-controllable flows, kept for recall per the reviewed candidate labels.
SSRF (path-only, host pinned): config-boundary data reaches only path segments of a request to a fixed host (api.yotpo.com, or api.mailgun.net / api.eu.mailgun.net selected by a boolean). The destination host cannot be relocated by the submitting client; lower severity than host-controllable flows, kept for recall per the reviewed candidate labels.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `src/fides/api/service/messaging/message_dispatch_service.py:493` `py/augur/fides/pass3-ssrf`: SSRF (path-only, host pinned): config-boundary data reaches only path segments of a request to a fixed host (api.yotpo.com, or api.mailgun.net / api.eu.mailgun.net selected by a boolean). The destination host cannot be relocated by the submitting client; lower severity than host-controllable flows, kept for recall per the reviewed candidate labels.
SSRF (path-only, host pinned): config-boundary data reaches only path segments of a request to a fixed host (api.yotpo.com, or api.mailgun.net / api.eu.mailgun.net selected by a boolean). The destination host cannot be relocated by the submitting client; lower severity than host-controllable flows, kept for recall per the reviewed candidate labels.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `src/fides/api/service/messaging/message_dispatch_service.py:513` `py/augur/fides/pass3-ssrf`: SSRF (path-only, host pinned): config-boundary data reaches only path segments of a request to a fixed host (api.yotpo.com, or api.mailgun.net / api.eu.mailgun.net selected by a boolean). The destination host cannot be relocated by the submitting client; lower severity than host-controllable flows, kept for recall per the reviewed candidate labels.
SSRF (path-only, host pinned): config-boundary data reaches only path segments of a request to a fixed host (api.yotpo.com, or api.mailgun.net / api.eu.mailgun.net selected by a boolean). The destination host cannot be relocated by the submitting client; lower severity than host-controllable flows, kept for recall per the reviewed candidate labels.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
