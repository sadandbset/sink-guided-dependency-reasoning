# Augur IRIS Report

Generated at: `2026-10-20T08:11:18.441679+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 3 | SSRF | 3 | 21 | 0 | 0 | 49 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 3 | SSRF | 4 | 0 | 4 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass3` `scout/server/blueprints/cases/controllers.py:95` `py/augur/scout/pass3-ssrf`: SSRF (host control via Host header): request.url_root (Host-header-derived, scout/server/blueprints/cases/views.py:225) is concatenated with 'reports/report' and POSTed server-side (cases/controllers.py:94). An authenticated user with case access steers the outbound host (and port via the Host header) when the chanjo coverage integration is enabled; the path is fixed. Requires SQLALCHEMY_DATABASE_URI to be configured.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `scout/server/blueprints/cases/controllers.py:548` `py/augur/scout/pass3-ssrf`: SSRF (host control via Host header / SERVER_NAME): url_for('report.json_chrom_coverage', _external=True) (cases/controllers.py:544) builds the POST target host from the request Host header unless SERVER_NAME is configured (scout/server/config.py defines none). The path is fixed to the app's own chanjo MT coverage endpoint; host-only control by an authenticated user.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `scout/server/blueprints/cases/controllers.py:554` `py/augur/scout/pass3-ssrf`: SSRF (host control via Host header / SERVER_NAME): url_for('report.json_chrom_coverage', _external=True) (cases/controllers.py:544) builds the POST target host from the request Host header unless SERVER_NAME is configured (scout/server/config.py defines none). The path is fixed to the app's own chanjo MT coverage endpoint; host-only control by an authenticated user.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `scout/server/blueprints/alignviewers/views.py:44` `py/augur/scout/pass3-ssrf`: SSRF (full target control): the client-supplied /remote/cors/<path:remote_url> route variable is forwarded verbatim as the url of requests.request with allow_redirects=True (scout/server/blueprints/alignviewers/views.py:42). Any authenticated user controls scheme, host, port and path of the outbound request; inbound headers (minus Host), body and cookies are also forwarded. No scheme/host validation or allowlist exists anywhere on this path.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
