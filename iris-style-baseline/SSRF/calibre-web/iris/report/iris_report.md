# Augur IRIS Report

Generated at: `2026-10-19T11:59:35.550849+00:00`

## Label Summary

| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Path Traversal | 0 | 0 | 0 | 0 | 0 |
| 3 | SSRF | 11 | 13 | 0 | 4 | 171 |

## Finding Counts

| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |
| --- | --- | ---: | ---: | ---: | ---: |
| 3 | SSRF | 11 | 0 | 5 | 6 |

## Top Likely True Positives

No findings matched TP-promoting heuristics.

## Candidate Findings (Need Analyst Review)

- `pass3` `cps/metadata_provider/amazon.py:111` `py/augur/calibre-web/pass3-ssrf`: SSRF (fixed-host metadata provider): user metadata-search text is embedded into the URL argument of a provider search fetch with a pinned host (quote-encoded except Amazon, which embeds the raw query after a fixed prefix); scheme and host are not attacker-controlled, only the query/path component is.
SSRF (fixed-host metadata provider): user metadata-search text is embedded into the URL argument of a provider search fetch with a pinned host (quote-encoded except Amazon, which embeds the raw query after a fixed prefix); scheme and host are not attacker-controlled, only the query/path component is.
SSRF (fixed-host metadata provider): user metadata-search text is embedded into the URL argument of a provider search fetch with a pinned host (quote-encoded except Amazon, which embeds the raw query after a fixed prefix); scheme and host are not attacker-controlled, only the query/path component is.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `cps/metadata_provider/comicvine.py:50` `py/augur/calibre-web/pass3-ssrf`: SSRF (fixed-host metadata provider): user metadata-search text is embedded into the URL argument of a provider search fetch with a pinned host (quote-encoded except Amazon, which embeds the raw query after a fixed prefix); scheme and host are not attacker-controlled, only the query/path component is.
SSRF (fixed-host metadata provider): user metadata-search text is embedded into the URL argument of a provider search fetch with a pinned host (quote-encoded except Amazon, which embeds the raw query after a fixed prefix); scheme and host are not attacker-controlled, only the query/path component is.
SSRF (fixed-host metadata provider): user metadata-search text is embedded into the URL argument of a provider search fetch with a pinned host (quote-encoded except Amazon, which embeds the raw query after a fixed prefix); scheme and host are not attacker-controlled, only the query/path component is.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `cps/editbooks.py:808` `py/augur/calibre-web/pass3-ssrf`: SSRF (full target control): the attacker-supplied cover_url form field of the book edit route flows into the URL argument of a server-side requests.get via helper.save_cover_from_url (cps/helper.py:740). Scheme, host, port and path are chosen by the submitting (authenticated edit+upload) user; the localhost check is conditional on the operator allow_localhost flag and redirects are followed.
SSRF (full target control): the attacker-supplied cover_url form field of the book edit route flows into the URL argument of a server-side requests.get via helper.save_cover_from_url (cps/helper.py:740). Scheme, host, port and path are chosen by the submitting (authenticated edit+upload) user; the localhost check is conditional on the operator allow_localhost flag and redirects are followed.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `cps/helper.py:740` `py/augur/calibre-web/pass3-ssrf`: SSRF (full target control): the attacker-supplied cover_url form field of the book edit route flows into the URL argument of a server-side requests.get via helper.save_cover_from_url (cps/helper.py:740). Scheme, host, port and path are chosen by the submitting (authenticated edit+upload) user; the localhost check is conditional on the operator allow_localhost flag and redirects are followed.
SSRF (full target control): the attacker-supplied cover_url form field of the book edit route flows into the URL argument of a server-side requests.get via helper.save_cover_from_url (cps/helper.py:740). Scheme, host, port and path are chosen by the submitting (authenticated edit+upload) user; the localhost check is conditional on the operator allow_localhost flag and redirects are followed.
  - Reason: no explicit FP/TP heuristic matched
- `pass3` `cps/metadata_provider/lubimyczytac.py:115` `py/augur/calibre-web/pass3-ssrf`: SSRF (fixed-host metadata provider): user metadata-search text is embedded into the URL argument of a provider search fetch with a pinned host (quote-encoded except Amazon, which embeds the raw query after a fixed prefix); scheme and host are not attacker-controlled, only the query/path component is.
SSRF (fixed-host metadata provider): user metadata-search text is embedded into the URL argument of a provider search fetch with a pinned host (quote-encoded except Amazon, which embeds the raw query after a fixed prefix); scheme and host are not attacker-controlled, only the query/path component is.
SSRF (fixed-host metadata provider): user metadata-search text is embedded into the URL argument of a provider search fetch with a pinned host (quote-encoded except Amazon, which embeds the raw query after a fixed prefix); scheme and host are not attacker-controlled, only the query/path component is.
  - Reason: no explicit FP/TP heuristic matched

## Filtered as Likely False Positives

- `pass3` `cps/metadata_provider/google.py:48` `py/augur/calibre-web/pass3-ssrf`: SSRF (fixed-host metadata provider): user metadata-search text is embedded into the URL argument of a provider search fetch with a pinned host (quote-encoded except Amazon, which embeds the raw query after a fixed prefix); scheme and host are not attacker-controlled, only the query/path component is.
SSRF (fixed-host metadata provider): user metadata-search text is embedded into the URL argument of a provider search fetch with a pinned host (quote-encoded except Amazon, which embeds the raw query after a fixed prefix); scheme and host are not attacker-controlled, only the query/path component is.
SSRF (fixed-host metadata provider): user metadata-search text is embedded into the URL argument of a provider search fetch with a pinned host (quote-encoded except Amazon, which embeds the raw query after a fixed prefix); scheme and host are not attacker-controlled, only the query/path component is.
  - Reason: SSRF trusted endpoint heuristic: `google|bing|duckduckgo|search endpoint`
- `pass3` `cps/kobo.py:96` `py/augur/calibre-web/pass3-ssrf`: SSRF (partial: host pinned): the request.full_path-derived path suffix (plus verbatim header/body forwarding) reaches the URL argument of requests.request to the fixed Kobo store host storeapi.kobo.com (cps/kobo.py:96). The attacker controls the path/query and the forwarded headers, not the host; the proxy is only active when the admin enables config_kobo_proxy.
  - Reason: SSRF trusted endpoint heuristic: `admin.*config|trusted endpoint|configured url`
- `pass3` `cps/kobo.py:114` `py/augur/calibre-web/pass3-ssrf`: SSRF (partial: host pinned): the request.full_path-derived path suffix (plus verbatim header/body forwarding) reaches the URL argument of requests.request to the fixed Kobo store host storeapi.kobo.com (cps/kobo.py:96). The attacker controls the path/query and the forwarded headers, not the host; the proxy is only active when the admin enables config_kobo_proxy.
  - Reason: SSRF trusted endpoint heuristic: `admin.*config|trusted endpoint|configured url`
- `pass3` `cps/kobo.py:330` `py/augur/calibre-web/pass3-ssrf`: SSRF (partial: host pinned): the request.full_path-derived path suffix (plus verbatim header/body forwarding) reaches the URL argument of requests.request to the fixed Kobo store host storeapi.kobo.com (cps/kobo.py:96). The attacker controls the path/query and the forwarded headers, not the host; the proxy is only active when the admin enables config_kobo_proxy.
  - Reason: SSRF trusted endpoint heuristic: `admin.*config|trusted endpoint|configured url`
- `pass3` `cps/kobo.py:1059` `py/augur/calibre-web/pass3-ssrf`: SSRF (partial: host pinned): the request.full_path-derived path suffix (plus verbatim header/body forwarding) reaches the URL argument of requests.request to the fixed Kobo store host storeapi.kobo.com (cps/kobo.py:96). The attacker controls the path/query and the forwarded headers, not the host; the proxy is only active when the admin enables config_kobo_proxy.
  - Reason: SSRF trusted endpoint heuristic: `admin.*config|trusted endpoint|configured url`
- `pass3` `cps/metadata_provider/lubimyczytac.py:203` `py/augur/calibre-web/pass3-ssrf`: SSRF (second-order): a URL derived from an earlier remote response (provider search-result HTML href or Google Drive file metadata) is re-fetched server-side; not directly web-input-controlled - the request target can only be steered by a malicious or compromised upstream service.
  - Reason: SSRF trusted endpoint heuristic: `google|bing|duckduckgo|search endpoint`
