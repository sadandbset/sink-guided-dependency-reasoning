# Augur IRIS Report

Generated at: `2026-10-20T04:19:57.783793+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 3 | SSRF | 306 | 79 | 0 | 13 | 94 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 3 | SSRF | 10 | 0 | 10 | 0 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass3` `geonode/harvesting/harvesters/arcgis.py:410` `py/augur/geonode/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](1) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](3) reaches the URL of a server-side network request at [this network request URL argument](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `geonode/services/serviceprocessors/base.py:81` `py/augur/geonode/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](1) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](3) reaches the URL of a server-side network request at [this network request URL argument](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `geonode/storage/data_retriever.py:116` `py/augur/geonode/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](1) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](1) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](3) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](4) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](5) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](6) reaches the URL of a server-side network request at [this network request URL argument](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `geonode/harvesting/harvesters/geonodeharvester.py:702` `py/augur/geonode/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](1) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](3) reaches the URL of a server-side network request at [this network request URL argument](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `geonode/thumbs/utils.py:421` `py/augur/geonode/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](1) reaches the URL of a server-side network request at [this network request URL argument](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `geonode/utils.py:1236` `py/augur/geonode/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](1) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](3) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](3) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](4) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](5) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](6) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](7) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](8) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](9) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](10) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](11) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](12) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](13) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](1) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](3) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](4) reaches the URL of a server-side network request at [this network request URL argument](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `geonode/utils.py:1248` `py/augur/geonode/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](1) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](3) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](3) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](4) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](5) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](6) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](7) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](8) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](9) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](10) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](11) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](12) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](13) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](1) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](3) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](4) reaches the URL of a server-side network request at [this network request URL argument](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `geonode/utils.py:1883` `py/augur/geonode/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](1) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](1) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](3) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](4) reaches the URL of a server-side network request at [this network request URL argument](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `geonode/proxy/views.py:195` `py/augur/geonode/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](1) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](3) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](4) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](5) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](6) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](7) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](8) reaches the URL of a server-side network request at [this network request URL argument](2).
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `geonode/services/serviceprocessors/wms.py:284` `py/augur/geonode/pass3-ssrf`: Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](1) reaches the URL of a server-side network request at [this network request URL argument](2).
Server-side request forgery (CWE-918): untrusted input from [this request/form/URL boundary](3) reaches the URL of a server-side network request at [this network request URL argument](2).
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

No findings matched FP heuristics.
