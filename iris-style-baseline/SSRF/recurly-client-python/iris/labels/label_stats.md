# Pass 3 (CWE-918 SSRF) Label Statistics — recurly-client-python

- Target: recurly-client-python 2.6.1 (official Recurly REST API client SDK — a library, not a service; no routes/handlers/framework)
- Labeling model: **glm-5.3**
- Generated at: 2026-10-20 (run `recurly-client-python-ssrf-pass3-20261020`)
- Batches: **8** (5 source batches + 3 sink batches)
- Candidate total: **156** (sources.csv 77 + sinks.csv 79), all labeled, 0 excluded, 0 merged

## Role distribution (all candidates)

| role | count |
| --- | --- |
| source | 21 |
| sink | 13 |
| sanitizer | 0 |
| summary | 73 |
| none | 49 |

## Role x classification distribution

| role | classification | count |
| --- | --- | --- |
| source | candidate | 21 |
| sink | tp | 5 |
| sink | candidate | 8 |
| summary | candidate | 73 |
| none | fp | 49 |

No `tp` sources and no `fp` sources: within this codebase (a client SDK) no source is *provably* attacker-controlled — the untrusted boundaries are the embedding application (public-API parameters) and second-order server-controlled carriers, so every source is `candidate` pending host-app context. No `unknown` classifications: every candidate could be decided from source.

## Sources (77 candidates)

| role | classification | count |
| --- | --- | --- |
| source | candidate | 21 |
| summary | candidate | 13 |
| none | fp | 43 |

Source family summary (by labeling batch, see `labels_raw_pass3.json`):

- b1 configuration reads (SUBDOMAIN / BASE_URI / CA_CERTS_FILE): 6 -> none/fp (operator/admin config; CA_CERTS_FILE never reaches a URL)
- b2 server XML attribute reads (elem.attrib family): 23 -> 5 source/candidate (the href-bearing reads: `__init__.py:223/:1122`, `resource.py:508/:566/:589`), 18 none/fp (type/nil/name/method/field/symbol dispatch reads and serialization-side writes)
- b3 response headers + bodies (getheader / read): 19 -> 6 source/candidate (Location `__init__.py:260/:313/:585/:1084`, `resource.py:662`; Link `resource.py:153`), 13 none/fp (12 `read()` bodies — only feed XML parse + DEBUG logging; 1 Content-Type check)
- b4 XML parse entries (ElementTree.fromstring): 12 -> summary/candidate (taint step body string -> Element tree)
- b5 public-API parameter boundaries + link-header parse: 17 -> 10 source/candidate (`http_request`, `element_for_url`, `headers_for_url`, `page_for_url`, `count_for_url`, `paginated`, `put`, `post` full-URL params; `GiftCard.redeem` redemption_code attribute; `objects_for_push_notification` webhook body), 1 summary/candidate (`parse_link_value` @ resource.py:153), 6 none/fp (path-only/query-only: `Resource.get`, `Plan.get_add_on`, `js.fetch`, `Resource.all`, `Resource.count`; plus the `link_header.py:95` `__main__` demo call)

## Sinks (79 candidates)

| role | classification | count |
| --- | --- | --- |
| sink | tp | 5 |
| sink | candidate | 8 |
| summary | candidate | 66 |
| none | fp | 6 |

Sink family summary:

- final network I/O (tp, 4): `http_client.HTTPConnection(urlparts.netloc)` (resource.py:245), `HTTPSConnection(urlparts.netloc)` (resource.py:247/:250), `connection.request(method, url, body, headers)` (resource.py:279, URL at arg 1)
- request funnel (tp, 1): `Resource.http_request(url, ...)` (resource.py:214) — the only funnel every library request passes through
- funnel-argument fetch wrappers (candidate, 8): `element_for_url` / `headers_for_url` / `page_for_url` / `count_for_url` / `paginated` / `put` / `post` (full-URL arg 0)
- defense-in-depth sink (candidate, 1): `connection.getresponse()` (resource.py:280) — http.client transmits the buffered request here; receiver-based, no URL argument
- summary steps (66): 27 `urljoin` call sites (arg 1 per CSV; base arg 0 propagates as well and must be modeled in Step 4), 12 `ElementTree.fromstring` (arg 0 -> Element), 28 internal fetch wrappers (`Account.charge/subscribe/...`, `Coupon.generate/restore`, `GiftCard.preview/redeem`, `Page.next_page/first_page`, `actionator`/`relatitator` follow-the-href closures, `Resource.delete/_update`, ...), 4 `urlencode` (query-only), 1 `urlsplit` (url -> netloc)
- none/fp (6): path-constrained or config-only fetchers — `Resource.get` (fixed member_path prefix), `Plan.get_add_on` (fixed prefix), `js.fetch` (fixed 'recurly_js/result/' prefix), `Invoice.pdf` (config host, path-only uuid), `Resource._create` (config + static path only), and the dead `urljoin` at `__init__.py:842` (computed value never used)

## Sanitizers

**0 entries.** Verified against source: no scheme/host allowlist, no private-IP or DNS-rebinding protection, and no redirect validation exists anywhere in the tree (`recurly/resource.py:240-250` is the only control point — a scheme *branch*, not a restriction; any non-https scheme falls to cleartext `HTTPConnection`). `recurly.CA_CERTS_FILE` (TLS server authentication) and `recurly.API_KEY` (request authentication) restrict nothing about the request *target* and were deliberately not treated as SSRF sanitizers.

## Quality checks

- schema conformance: validated with `jsonschema` 4.26.0 via `labels/validate_labels.py` — all constraints pass except the unsatisfiable `passes.contains {pass_id=1}` template artifact (single-pass run; see `phase1_review.md` §7)
- coverage: 156/156 candidates labeled, 0 unclassified, 0 dropped, 0 duplicates (every `(file, line, callable)` row is distinct; cross-CSV same-callable rows — e.g. `http_request` as source param and as sink funnel — are intentional and role-distinct)
- argument-index bounds: all `flow_kind=argument` entries carry integer `arg_index >= 0` (CSV values kept; two corrections from CSV `-1` recorded in `labels_raw_pass3.json` `arg_index_final`: `Invoice.pdf` and `Purchase.__invoice` uuid/url params -> 0; `getresponse` uses `receiver`/null, closure wrappers use `field`/`unknown`/null)
- pass 3 has >= 1 sink (5 tp + 8 candidate) and >= 1 source (21 candidate) — no "empty pass" documentation needed
- low-confidence entries (<0.55, re-examined and kept): 6 rows at 0.50 — the 4 `urlencode` sites and `Resource.all`/`Resource.count` kwargs summaries (query-string-only influence on a config-fixed host; out of CWE-918 host-forgery scope, retained as propagation steps)
