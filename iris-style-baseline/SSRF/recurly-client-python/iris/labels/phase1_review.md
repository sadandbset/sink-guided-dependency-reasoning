# Phase 1 Step 3 Review — recurly-client-python, Pass 3 (CWE-918 SSRF)

- Run: `recurly-client-python-ssrf-pass3-20261020` · generated 2026-10-20
- Labeling model: **glm-5.3** (the LLM performing this labeling run)
- Batches: 8 (b1–b5 source batches, b6–b8 sink batches) · candidates: **156** (sources.csv 77 + sinks.csv 79) — every CSV row labeled, 0 excluded, 0 merged
- Artifacts: `labels/labels.json` (schema-validated), `labels/labels_raw_pass3.json` (raw per-batch decisions with original CSV rows), `labels/label_stats.md`, regenerators `labels/build_labels.py` + `labels/validate_labels.py`
- Verification basis: real source under `dataset/codeql_databases/ssrf_dbs/recurly-client-python_vuln/recurly/` only (no ground truth, no fix commits, no external CVE descriptions; the pre-existing root-level SSRF audit artifacts were not opened)

## 1. Label distribution

| role | tp | candidate | fp | unknown | total |
| --- | --- | --- | --- | --- | --- |
| source | 0 | 21 | 0 | 0 | 21 |
| sink | 5 | 8 | 0 | 0 | 13 |
| sanitizer | 0 | 0 | 0 | 0 | 0 |
| summary | 0 | 73 | 0 | 0 | 73 |
| none | 0 | 0 | 49 | 0 | 49 |

## 2. Principal verified chains (drives the labels)

The target is a **client SDK with a single outbound funnel** — all chains converge on `Resource.http_request` (resource.py:214) -> `urlsplit(url)` (resource.py:240) -> `HTTP(S)Connection(urlparts.netloc)` (resource.py:245/247/250) -> `connection.request(method, url, ...)` (resource.py:279). Verified: **no scheme/host allowlist, no private-IP blocking, no redirect validation** exists on this funnel; any non-https scheme degrades to cleartext `HTTPConnection`.

1. **Public-API URL boundary (full host control, requires host-app context)** — `Resource.http_request(url, ...)` (resource.py:214, arg 0), `element_for_url` (:355), `headers_for_url` (:346), `Page.page_for_url` (:127), `Page.count_for_url` (:137), `Resource.paginated` (:487), `Resource.post` (:655), `Resource.put` (:644): the embedding application supplies the complete URL, which fully determines scheme/host/port. Labeled source/candidate (0.6) — within the library alone there is no attacker entry; flows realize only when a host app passes attacker-derived URLs. This is the SDK's entire untrusted surface: no routes, no handlers, no login boundaries exist (verified — zero framework imports).
2. **Second-order server-href chain (host control, second order)** — response XML `href` values read at `resource.py:508` (`self._url = document_url`), `resource.py:566/:589` (anchor/link href -> `actionator`/`relatitator` closures) and `__init__.py:223` (billing_info href) / `__init__.py:1122` (refund anchor href) are re-requested through the funnel. Location headers: `resource.py:662` (`self._url = response.getheader('Location')`), `__init__.py:260/:313/:1084`; Link pagination: `resource.py:153` -> `Page.start_url/next_url` -> `next_page/first_page` (resource.py:98/:112). `Coupon.generate` follows the Location header *directly* (`Page.page_for_url(response.getheader('Location'))`, `__init__.py:585`). All labeled source/candidate (0.6–0.65): attacker control presupposes a compromised or MITM'd Recurly endpoint (the channel is protected by API key + TLS) — recall-positive, manual-review required, no vulnerability claimed.
3. **Webhook XML chain (external input boundary)** — `objects_for_push_notification(notification)` (`__init__.py:1292`, arg 0) parses the raw push-notification POST body with `ElementTree.fromstring` **without any signature verification**; the decoded Resource elements carry href attributes that are re-requested on later attribute access (the b2 href sources). Attacker controllability depends on the host's webhook endpoint exposure.
4. **First-path-position interpolation (absolute-URL replacement capability)** — `urljoin(base, path)` returns an absolute URL whenever the *path* argument is itself absolute. Several wrappers place a caller- or server-set code attribute in the path's FIRST position: `GiftCard.redeem` (`'%s/redeem' % self.redemption_code`, `__init__.py:456` — labeled source, 0.6), `Account.charge/subscribe/...` (`'%s/adjustments' % self.account_code`), `Coupon.generate/restore` (coupon_code), `Plan.create_add_on` (plan_code). A scheme-prefixed value at these sites replaces scheme+host. These code attributes were not themselves extracted as CSV candidates (extraction coverage gap, recorded in detection.json); they are carried by the wrapper summary entries and the urljoin summaries.

## 3. Key negative decisions (what was *not* labeled source/sink and why)

- **All 6 configuration reads (SUBDOMAIN / BASE_URI / CA_CERTS_FILE) -> none/fp**: module-level operator config naming the fixed `*.recurly.com` host (admin-configured URL -> FP per the SSRF FP heuristic); CA_CERTS_FILE is a local CA-bundle path that never reaches a URL.
- **Path-only parameters -> none/fp**: `Resource.get(uuid)` (fixed `'accounts/'`-style member_path prefixes, host = base_uri), `Plan.get_add_on(add_on_code)` (interpolated behind the fixed `'%s/add_ons/%s'` prefix — first slot is `self.plan_code`, not the parameter), `js.fetch(token)` (fixed `'recurly_js/result/'` prefix), `Invoice.pdf(uuid)` (config host, path-only). Path manipulation on a host-fixed base is not CWE-918 host forgery.
- **Query-only parameters -> none/fp as sources**: `Resource.all/count(**kwargs)` — kwargs are urlencoded into the query string of a config-host collection URL; scheme/host/port fixed.
- **All 12 response `read()` bodies -> none/fp**: the bytes flow only into `ElementTree.fromstring` (labeled as a summary step) and DEBUG logging; no direct path from the body value to a request URL exists — the URL-relevant content is read at the separately labeled href/Location/Link sites.
- **18 non-href `elem.attrib` reads -> none/fp**: type/nil dispatch reads, anchor `name`/`method` reads, error `field`/`symbol` reads, and serialization-side attribute *writes* (resource.py:46/:463/:465/:468/:471/:701, `__init__.py:533`).
- **`getheader('Content-Type')` (resource.py:363) -> none/fp**: an `application/xml` format assertion, not URL material.
- **`parse_link_value` at link_header.py:95 -> none/fp**: the call is inside the module's `if __name__ == '__main__'` demo block (`sys.argv[1]`), not the library runtime; the live call is resource.py:153 (labeled summary).
- **`urljoin` dead site at `__init__.py:842` -> none/fp**: the computed URL is never used — line 843 calls `self.__invoice(self.collection_path)`; the live join is at :872.
- **`urljoin` (27 live sites) / `urlsplit` / `urlencode` -> summary, not sink**: pure URL construction/parsing APIs are not automatically sinks (per the pass rules); they are taint-propagation steps. `urljoin` arg_index 1 (path) per the CSV, with the base-argument propagation (arg 0) explicitly noted for Step 4 modeling.
- **`Resource._create` -> none/fp**: URL assembled solely from `recurly.base_uri()` config and a static class `collection_path`; no tainted input can reach the network target through it.
- **file:/data: and other non-HTTP schemes**: not applicable — no `file:`/`data:` loading exists anywhere in the tree (http.client only issues http(s)); nothing was diverted to other CWEs because no such code path exists. No `urllib.request.urlopen` / `requests` / `httpx` / `socket` call sites exist (verified, see detection.json `absentApis`).

## 4. Sanitizer and summary analysis

- **Sanitizers: 0 entries.** The only structural controls near the funnel are the scheme branch (resource.py:244-250: non-https -> cleartext `HTTPConnection`; https -> `HTTPSConnection`, optionally with `ssl.create_default_context(cafile=recurly.CA_CERTS_FILE)`) and `SOCKET_TIMEOUT_SECONDS` (resource.py:242-243). None restricts the request target's scheme, host or port; the CA gate is configuration-dependent and authenticates the server rather than restricting the destination. TLS validation, API-key authentication and general input checks were deliberately *not* treated as SSRF sanitizers. `isBarrier` in the pass-3 query must resolve to `none()`.
- **Summaries: 73 entries** — the propagation backbone: 27 live `urljoin` sites (both-argument propagation), 12 `ElementTree.fromstring` (body -> Element tree), 28 fetch wrappers (receiver fields `self._url` / `next_url` / `start_url` / `_refund_transaction_url` and first-position code attributes -> funnel arguments), 4 `urlencode` (query-only), 1 `urlsplit` (url -> netloc), 1 `parse_link_value` (Link header -> pagination URLs). **Phase 2 note**: `MySummaries.qll` additionally needs steps that are *not* representable from the CSV candidate set: (a) `self._url` writes (resource.py:510/:662) -> reads in other methods (inter-procedural field flow), (b) the closure captures in `_make_actionator`/`make_relatitator` (url -> `http_request`/`element_for_url` argument), (c) `parse_link_value` output dict keys -> `Page.start_url/next_url` fields. Without (a)–(c) the second-order chains in §2.2 will not connect in the taint query.

## 5. arg_index corrections and format notes

- `HTTPConnection.request` (resource.py:279): arg 1 = URL — verified against the call `connection.request(method, url, body, headers)` (method=0, url=1, body=2, headers=3); CSV argIndex 1 kept.
- `http_client.HTTPConnection/HTTPSConnection` ctor (resource.py:245/247/250): arg 0 = `urlparts.netloc` (host/port) — CSV argIndex 0 kept.
- `HTTPConnection.getresponse` (resource.py:280): no URL argument — `flow_kind: receiver`, `arg_index: null` (the schema forbids `argument` without a positional index).
- Two corrections from CSV `-1` (recorded per-entry in `labels_raw_pass3.json` as `arg_index_final` 0 with `arg_index_csv` -1): `Invoice.pdf` (uuid is the first positional parameter) and `Purchase.__invoice` (url is the first positional parameter).
- `urljoin` rows keep CSV arg 1 (path position); the base-argument (arg 0) propagation is documented in every rationale and must be modeled in Step 4.
- Wrapper rows with no URL parameter use `field`/`unknown`/`param(kwargs)` with `arg_index: null`, per the schema's `argument ⇒ arg_index ≥ 0` implication.

## 6. Items needing human review (low confidence / unverified propagation)

1. **All 21 source/candidate rows (0.6–0.65)**: for a client SDK the "untrusted boundary" is the embedding application; the library alone contains no attacker entry. Reviewers should decide whether host-app-parameter sources meet the project's reporting bar, or whether only the second-order carriers (§2.2) should feed Phase 2.
2. **Second-order carriers (attrib/Location/Link sources, 0.6–0.65)**: require a compromised/MITM'd endpoint assumption; the channel is protected by API key + TLS (and cleartext HTTP only occurs when the request URL itself is non-https).
3. **First-path-position code attributes (§2.4)**: `account_code` / `coupon_code` / `redemption_code` / `plan_code` were not extracted as CSV candidates; they are reachable as taint only via the wrapper summary entries. Consider adding them as explicit source candidates if the host-app boundary is accepted.
4. **Six 0.50-confidence summary rows** (4 × `urlencode`, `Resource.all`/`Resource.count` kwargs): query-string-only influence on a config-fixed host — out of CWE-918 host-forgery scope; retained purely as propagation steps, safe to prune.
5. **`connection.getresponse()` sink/candidate (0.6)**: defense-in-depth sink; `connection.request` arg 1 is the primary emission point and may make it redundant in Phase 2.
6. **`Plan.get_add_on` residual risk**: the *parameter* is path-constrained (none/fp), but `self.plan_code` occupies the first path slot at `__init__.py:1176` — a scheme-prefixed plan_code (caller- or server-set attribute, not a CSV candidate) would make the joined URL absolute. Recorded on the `create_add_on` summary entry.

## 7. Schema conformance note

`labels.json` was validated with `jsonschema` 4.26.0 (via `labels/validate_labels.py`, plus a self-contained constraint checker). One keyword is intentionally unsatisfied: `passes.contains {pass_id: 1}` requires a pass-1 element in the `passes` array, which contradicts this user-narrowed single-pass (Pass 3) run — treated as a schema template artifact (same convention as the prior manual pass-3 runs, e.g. mlflow/calibre-web). All other constraints (enums, patterns, required fields, `additionalProperties: false`, the `flow_kind: argument ⇒ arg_index ≥ 0` implication, id uniqueness) pass.

## 8. Coverage and provenance

- 156/156 CSV candidates labeled; no row dropped, merged, or re-asked. All `(file, line, callable)` candidates are distinct; cross-CSV same-callable rows (e.g. `http_request`, `post`, `put`, `page_for_url`, `paginated`, `redeem`, `fetch`, `get`, `get_add_on`, `parse_link_value` appear on both the source side and the sink side) are retained intentionally — the source-side row labels the parameter boundary, the sink-side row labels the fetch behavior. Signature-level deduplication (28 urljoin rows -> one predicate, etc.) is deferred to Step 4 library generation, where it is deterministic.
- Every CSV line number was re-checked against the source tree; each entry's first evidence string is the verbatim source line at its location, read from the tree at generation time.
- Deterministic re-rendering: `labels/build_labels.py` (reads the extraction CSVs, applies the decision table documented above, fails on any unlabeled row). `labels/validate_labels.py` re-checks schema conformance.
- Batch structure, per-candidate CSV rows, and per-decision rationales (with `arg_index_csv` / `arg_index_final` and `flow_kind_final`) are preserved in `labels/labels_raw_pass3.json` for audit.

**Status: Phase 1 Step 3 complete. Stopping here per instruction — not proceeding to Phase 2 (no .qll libraries, no queries, no taint analysis, no report).**
