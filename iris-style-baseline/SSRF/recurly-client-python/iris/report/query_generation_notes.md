# Query Generation Notes — recurly-client-python, Pass 3 (CWE-918 SSRF)

**Augur 0.3.0 · Phase 2 Step 4–5 (file generation only)** · Run `recurly-client-python-ssrf-pass3-20261020` · Generated 2026-10-20

**Inputs:** `iris/labels/labels.json` (156 entries: 21 source / 13 sink / 0 sanitizer / 73 summary / 49 none) and the source tree at `dataset/codeql_databases/ssrf_dbs/recurly-client-python_vuln` (recurly-client-python 2.6.1, sha 9db2d1a — identical to the CodeQL database snapshot; tree, DB and label line numbers agree 1:1, re-verified line-by-line during generation).

**Outputs:** `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass3_SSRF.ql` (formal, pass key `"ssrf"`).

**Review-gate note:** `labels/review_decision.json` does **not exist** in this workspace (Phase 1 wrote the advisory checkpoint `labels/phase1_review.md`; no `review_decision.json` audit artifact was created). The operator's instruction to build from "经过人工审核的 labels/labels.json" is taken as the review-gate approval (WORKFLOW.md 4.5 automated-mode convention: log and continue). No label was modified in this step.

**Toolchain:** CodeQL CLI 2.25.1, `codeql/python-all` 7.1.x resolved from the local pack cache via `iris/qlpack.yml` (name `iris/recurly-client-python-cwe918`). Every QL idiom used was verified directly against the installed pack sources rather than assumed: `DataFlow::exprNode` / `DataFlow::parameterNode` (`semmle/python/dataflow/new/internal/DataFlowPublic.qll:303/:350`), `DataFlow::ConfigSig` / `TaintTracking::Global<Config>` / `flowPath` / `PathGraph` (`codeql/dataflow` 2.1.7 shared framework, re-exported through `semmle.python.dataflow.new.{DataFlow,TaintTracking}`), `Call.getFunc/getPositionalArg`, `Attribute.getName/getObject`, `Subscript.getObject`, `Name.getId`, `Function.getArg(int)→Parameter` (`semmle/python/AstGenerated.qll` / `Exprs.qll`).

**Compile verification (post-generation):** the operator ran `codeql query compile queries/Pass3_SSRF.ql --check-only`, which surfaced one generation defect: the five private step predicates in `MySummaries.qll` had been emitted with the parameter names `from`/`to`, and `from` is a QL keyword (parse error at MySummaries.qll:115, all other diagnostics were cascades). Fixed by renaming to `nodeFrom`/`nodeTo` (no semantic change; label mapping untouched). A re-run of `codeql query compile --check-only` now compiles **clean: Done [1/1], zero errors, zero warnings** — all four `.qll` files and the query are type-checked by this pass (they are imported by the query). No database analysis has been executed.

**Threat model (from the reviewed labels):** the target is a client SDK with **no inbound network surface of its own** (no routes, handlers, framework — verified). Its untrusted boundaries are exactly the reviewed label set: (1) the embedding application calling the public API with full request URLs, (2) values controlled by the remote Recurly endpoint (XML `href` attributes, `Location`/`Link` response headers — second-order carriers re-requested by the library), (3) the externally delivered push-notification webhook body parsed without signature verification, and (4) caller/server-set code attributes in the first URL path position. All 156 outbound requests funnel through `Resource.http_request` (resource.py:214) → `urlsplit(url)` → `http_client.HTTP(S)Connection(urlparts.netloc)` → `connection.request(method, url, ...)`, with **no scheme/host allowlist, no private-IP blocking and no redirect validation anywhere in the package** (resource.py:240-250 only selects the transport).

---

## 1. Label ID → CodeQL predicate mapping

All library predicates take `(DataFlow::Node, string passKey)`; summaries take `(DataFlow::Node, DataFlow::Node, string passKey)`. Pass-key dispatch (WORKFLOW.md 5.1.5): the formal pass-3 query uses the single key `"ssrf"` — no other pass key exists in the generated files (no `command_injection` residue; grep-verified).

| Label role | Count | Rendered into | Notes |
| --- | --- | --- | --- |
| source | 21 | `MySources::isSource/5` | 5 families below; classification `candidate` (all 21) — see §1.6 |
| sink | 13 | `MySinks::isSink/4` | 4 families below (5 tp + 8 candidate) |
| sanitizer | 0 | `MySanitizers::isBarrier/4` → `none()` | §4 |
| summary | 73 | `MySummaries::isAdditionalTaintStep/6` | 5 custom step families (45 rows) + 28 wrapper rows realized natively (§5) |
| none | 49 | — | fp-classified rows; deliberately not rendered (enumerated in §6) |

### 1.1 MySources::isSource (21 rows)

| Family (private predicate) | Label IDs | Matching shape |
| --- | --- | --- |
| `serverHrefSource` — XML href reads | src-57 (resource.py:508), src-64 (:566), src-67 (:589), src-5 (__init__.py:223), src-25 (:1122) | `<x>.attrib['href']` Subscript / `<x>.attrib.get('href')` Call value node, file+line pinned to the 5 labeled lines |
| `responseHeaderSource` — Location/Link headers | src-8 (__init__.py:260), src-13 (:313), src-19 (:585), src-23 (:1084), src-74 (resource.py:662), src-39 (resource.py:153) | `<resp>.getheader(...)` Call value node, file+line pinned to the 6 labeled lines |
| `publicUrlParamSource` — embedding-app URL params | src-40 http_request (resource.py:214), src-46 element_for_url (:355), src-45 headers_for_url (:346), src-36 page_for_url (:127), src-37 count_for_url (:137), src-56 paginated (:487), src-70 put (:644), src-73 post (:655) | `DataFlow::parameterNode` of parameter position 1 (self/cls counted at 0 — equivalent to the labels' call-site arg_index 0 with receiver not counted), pinned by function name + file (names unique in the package, Phase-1 verified) |
| `redeemCodeSource` — first path segment | src-16 (GiftCard.redeem, `self.redemption_code` read at __init__.py:456) | `self.redemption_code` Attribute node, file+line pinned |
| `webhookBodySource` — external message body | src-28 (objects_for_push_notification, __init__.py:1292, param 0) | `parameterNode` of position 0 |

### 1.2 MySinks::isSink (13 rows)

| Family (private predicate) | Label IDs | Matching shape / dangerous argument |
| --- | --- | --- |
| `networkCtorSink` (tp) | snk-55 (resource.py:245), snk-56 (:247), snk-57 (:250) | arg 0 (`urlparts.netloc`) of `http_client.HTTP(S)Connection(...)`, file+line pinned — socket-level connection target |
| `requestLineSink` (tp) | snk-58 (resource.py:279) | arg 1 of `connection.request(method, url, body, headers)` (method=0, url=1, body=2, headers=3 — verified), file+line pinned — request-line URL |
| `getresponseSink` (tp) | snk-59 (resource.py:280) | receiver expression of `connection.getresponse()` — label flow_kind `receiver`, arg_index null (no URL argument exists); see §7 caveat |
| `funnelSink` (candidate) | snk-53 http_request (:214), snk-63 element_for_url (:355), snk-62 headers_for_url (:346), snk-51 page_for_url (:127), snk-52 count_for_url (:137), snk-64 paginated (:487), snk-78 put (:644), snk-79 post (:655) | arg 0 of every in-package call to these callables (call sites enumerated in the QLL header and §3); restricted to the 5 `recurly/` modules so the tests/ tree in the DB cannot match |

### 1.3 MySanitizers::isBarrier (0 rows) — see §4.

### 1.4 MySummaries::isAdditionalTaintStep (45 custom rows + 28 native rows)

| Family (private predicate) | Label IDs | Step |
| --- | --- | --- |
| `urljoinStep` | snk-4/6/8/10/12/14/16/18/20/22/23/25/27/29/31/33/35/37/39/41/44/46/48/61/70/73/77 (27 rows) | arg 0 OR arg 1 → joined result, for every in-package bare-name `urljoin(...)` call except the dead site __init__.py:842 (label snk-32, none/fp — result never used) |
| `urlencodeStep` | snk-66/68/71/74 (resource.py:517/:577/:611/:621) | arg 0 (kwargs) → query-string result, line-pinned |
| `urlsplitStep` | snk-54 (resource.py:240) | arg 0 → SplitResult, AND arg 0 → the `urlparts.netloc` Attribute reads at resource.py:245/:247/:250 (label snk-54's stated intent, feeding snk-55/56/57) |
| `fromstringStep` | src-7/10/12/15/22/29/30/49/59/61/72/76 (12 rows) | arg 0 (body string) → parsed Element result, for in-package `ElementTree.fromstring(...)` calls (exactly the 12 labeled sites) |
| `parseLinkValueStep` | src-38 (resource.py:153) | arg 0 (Link header) → parsed link dict result, file+line pinned (excludes the link_header.py:95 `__main__` demo) |
| native (no custom edge) | snk-2/3/5/7/9/11/13/15/17/19/21/24/26/30/34/36/38/40/42/45/49/50/65/67/69/72/75/80 (28 wrapper rows) | realized by local data flow + the urljoin step + CodeQL's built-in interprocedural attribute taint; see §5 |

### 1.5 Formal query wiring (queries/Pass3_SSRF.ql)

`module Pass3Config implements DataFlow::ConfigSig` delegates `isSource`/`isSink`/`isBarrier`/`isAdditionalFlowStep` to `MySources::isSource(node, "ssrf")`, `MySinks::isSink(node, "ssrf")`, `MySanitizers::isBarrier(node, "ssrf")`, `MySummaries::isAdditionalTaintStep(from, to, "ssrf")`; `module Pass3Flow = TaintTracking::Global<Pass3Config>`; `import Pass3Flow::PathGraph`; select `sink.getNode(), source, sink, message` with `flowPath`. Metadata: `@kind path-problem`, `@problem.severity error`, `@tags security`, `external/cwe/cwe-918`, `@id py/augur/recurly-client-python/pass3-ssrf`, `@precision low` (template `{{PRECISION}}`).

### 1.6 Classification note (label adequacy — recorded, not patched)

All 21 source entries carry classification `candidate` (there are **no `tp` source rows**): within the library no input is *provably* attacker-controlled, because the boundary is the embedding application (public-API parameters) or presupposes a compromised/MITM'd endpoint (second-order carriers). A `tp`-only formal query — the convention of the maltrail CWE-78 run — would therefore have an **empty** source set and produce zero findings by construction. Per the directive not to modify reviewed labels, the formal pass-3 query admits the full reviewed source set and the `candidate` classification is surfaced in the query description and here. **If the project's reporting bar requires `tp`-only formal findings, this is a labeling-adequacy gap: re-review of the 21 source classifications is requested rather than silently re-scoping the model.** No diagnostics variant was generated: nothing reviewed was excluded from the formal query, so there is no candidate-only remainder to diagnose (the optional diagnostics mechanism from the CWE-78 experiment is unused, not omitted by oversight).

## 2. Source trust boundaries and propagation basis

- **Public-API URL parameters (8, full-URL control).** `Resource.http_request(url, ...)` (resource.py:214), `element_for_url` (:355), `headers_for_url` (:346), `Page.page_for_url` (:127), `Page.count_for_url` (:137), `paginated` (:487), `put` (:644), `post` (:655) — the caller supplies the complete URL. `http_request` is the documented low-level entry ("Make an HTTP request with the given method to the given URL"); the others are documented public methods. Propagation basis: the parameter flows unmodified into `urlsplit(url)` / `HTTP(S)Connection(urlparts.netloc)` / `connection.request(method, url, ...)` (resource.py:240–280) — plain local data flow, no validation between parameter and network. Trust boundary: the **embedding application** — the SDK itself has no route, handler or login surface (verified: zero framework imports). An alert on these paths means "a host app passing attacker-derived URLs to the SDK's public API forges the request target", not an in-library attacker.
- **Server-controlled response URLs (11, second-order full-URL carriers).** XML `href` reads at resource.py:508 (`self._url = document_url`, re-requested by `delete`/`put`/`_update`/wrappers), :566/:589 (`__getattr__` anchor/link hrefs → `actionator`/`relatitator` closures → `http_request`/`element_for_url`), __init__.py:223 (billing_info href → `BillingInfo.element_for_url`), :1122 (refund anchor href → `_make_actionator`); `Location` headers at resource.py:662 (`self._url`), __init__.py:260/:313/:1084 (stored fields), :585 (`Coupon.generate` follows Location directly: `Page.page_for_url(response.getheader('Location'))`); `Link` header at resource.py:153 (→ `parse_link_value` → `Page.start_url/next_url`). Attacker model: a compromised or MITM'd Recurly endpoint (channel otherwise protected by API key + TLS; cleartext HTTP occurs only when the request URL itself is non-https). Propagation basis: verbatim source lines at each pinned site (each entry's first evidence string in labels.json).
- **Webhook body (1, external message parameter).** `objects_for_push_notification(notification)` (__init__.py:1292) receives the raw push-notification POST body from the host application and parses it with `ElementTree.fromstring` **without any signature verification** (grep-verified: no hmac/verification call in the package). Parsed Resource elements carry href attributes re-requested on attribute access; in this model the body taint reaches the `fromstring` result (family 4 step) and the href reads are independently sources.
- **First-path-segment attribute (1, host-capable path control).** `self.redemption_code` (__init__.py:456) is interpolated into `'%s/redeem' % ...` — the **first** position of the urljoin path argument, so a scheme-prefixed value makes `urljoin` return an absolute URL and replaces scheme+host. Same structural pattern (not separately labeled — recorded in Phase-1 review §6.3) exists for `self.account_code` (Account.charge/invoice/...), `self.coupon_code` (Coupon.generate/restore) and `self.plan_code` (Plan.create_add_on); their taint reaches the network via the same urljoin step without needing to be sources.

**Deliberately not sources** (labels none/fp): module config reads (`SUBDOMAIN`/`BASE_URI`/`CA_CERTS_FILE` — operator/admin config), response body `read()` values (feed only XML parsing and DEBUG logging — the URL-relevant content is read at the labeled href/header sites), path-only parameters (`Resource.get(uuid)`, `Plan.get_add_on`, `js.fetch` — fixed prefixes keep the join relative; host stays `base_uri()`), query-only kwargs (`Resource.all/count`), non-href attribute reads, and the 28 internal fetch wrappers (labeled `summary` — internal plumbing, **not** auto-promoted to external sources).

## 3. Sinks — real network APIs, dangerous argument indices, call locations

| Sink | Real API | Dangerous arg | Location | Call sites matched |
| --- | --- | --- | --- | --- |
| snk-55/56/57 | `http_client.HTTPConnection` / `HTTPSConnection` (six.moves → http.client) — socket-level connection construction | arg 0 = `urlparts.netloc` (host/port from `urlsplit(url)`) | resource.py:245 (cleartext branch: any non-https scheme), :247 (default TLS), :250 (TLS with `CA_CERTS_FILE`) | pinned lines |
| snk-58 | `HTTPConnection.request(method, url, body, headers)` — request-line emission | arg 1 = full request URL (selector) | resource.py:279 | pinned line |
| snk-59 | `HTTPConnection.getresponse()` — round-trip transmission | receiver (no URL arg) | resource.py:280 | pinned line |
| snk-53 | `http_request(url, ...)` — the funnel into the above | arg 0 | def resource.py:214 | resource.py:348/:359/:522/:647/:658/:672; __init__.py:247/:250/:267/:292/:308/:579/:760/:873 |
| snk-63 | `element_for_url(url)` → `http_request(url)` | arg 0 | def :355 | resource.py:130/:581; __init__.py:226/:1100/:1177; js.py:43 |
| snk-62 | `headers_for_url(url)` → `http_request(url, method='HEAD')` | arg 0 | def :346 | resource.py:139 |
| snk-51 | `Page.page_for_url(url)` → `element_for_url(url)` | arg 0 | def :127 | resource.py:110/:124/:612/:622; __init__.py:585 |
| snk-52 | `Page.count_for_url(url)` → `headers_for_url(url)` | arg 0 | def :137 | resource.py:622 |
| snk-64 | `paginated(url)` → `Page.page_for_url(url)` | arg 0 | def :487 | __init__.py:281 |
| snk-78 | `put(url)` → `http_request(url, 'PUT', self, ...)` | arg 0 | def :644 | resource.py:638; __init__.py:589/:952 |
| snk-79 | `post(url, ...)` → `http_request(url, 'POST', ...)` | arg 0 | def :655 | resource.py:642; __init__.py:240/:303/:326/:448/:451/:464/:801/:942/:945/:970 |

Every funnel call site was enumerated and verified against the tree during generation (each passes its argument verbatim into `http_request` or one more wrapper call — real code evidence, per the directive that resource-handler functions are not auto-sinks). Matching is restricted to the five `recurly/` modules; the `tests/` tree present in the CodeQL database cannot produce sink matches. Argument indices are the labels' CSV convention (call-site positional index, receiver not counted).

## 4. Scheme / fixed target / redirects / private addresses / sanitizers

- **Scheme:** no allowlist. `resource.py:244` *selects* the transport (`scheme != 'https'` → cleartext `HTTPConnection`); it never rejects a scheme. No `file:`/`data:` loading exists anywhere (http.client only issues http(s); detection.json `absentApis`) — nothing was diverted to another CWE because no such code path exists.
- **Fixed target:** the only fixed-host requests are those assembled solely from `recurly.base_uri()` config + static class paths (`Resource.get`/`all`/`count`/`_create`, `Invoice.pdf`, `js.fetch`, `Plan.get_add_on` — all labeled none/fp and not rendered). Everything else takes its host from the request URL or a server-supplied href/Location/Link.
- **Redirects:** no automatic redirect following (http.client does not follow; Location values are stored as `_url`/`_refund_transaction_url` and re-requested by explicit calls — resource.py:662→`delete`/`put`, __init__.py:585→`page_for_url`, :1084→`element_for_url`). These follows are modeled as the second-order sources; **no same-origin check or redirect allowlist exists**, so no barrier is modeled.
- **Private addresses / DNS rebinding:** no `ipaddress`, `socket.gethostbyname` or netloc comparison exists in the package (grep-verified) — nothing to model.
- **Sanitizers: none.** `MySanitizers::isBarrier` resolves to `none()` (never an unconditional block). Verified non-sanitizers, deliberately not modeled as barriers: `CA_CERTS_FILE`/`ssl.create_default_context` (TLS server authentication — irrelevant to target choice, and only applied on the https branch), `API_KEY` basic auth (request authentication), `SOCKET_TIMEOUT_SECONDS` (timeout), the non-ascii config sanity check (encoding guard). Login/permission checks do not exist (no inbound surface), so none could gate these paths.

## 5. Summary / custom propagation edges — source-code basis

Each edge is strictly conditional (name + shape + file/line pinning); there is **no unconditional taint propagation** and no edge without label or source evidence:

- **urljoin (27 sites):** pure URL construction — not a sink (directive). Basis: `urljoin(base, path)` returns an absolute URL whenever the path argument is absolute (the GiftCard.redeem/Coupon.generate/Plan.create_add_on/Account-wrapper pattern places caller- or server-set code attributes in the path's first position) and preserves the base host otherwise; every wrapper passes the joined result to the funnel. Both arguments propagate (arg_index 1 recorded per the CSV; arg 0 propagation is explicitly included).
- **urlencode (4 sites):** `'%s?%s' % (url, urlencode(kwargs))` (resource.py:517/:577/:611/:621) — query-component-only influence; retained per the reviewed labels (0.50 confidence), safe to prune in review.
- **urlsplit (resource.py:240):** `urlparts = urlsplit(url)`; `urlparts.netloc` (lines 245/247/250) is the connection target. The arg→result edge plus the arg→netloc projection (label snk-54's stated modeling intent) connect the funnel's URL to the constructor sinks.
- **ElementTree.fromstring (12 sites):** the parsed Element tree derives from the body string (arg 0 → result) — the propagation basis for the webhook-body source reaching parsed content.
- **parse_link_value (resource.py:153):** Link header string → parsed link dictionary (arg 0 → result).
- **28 wrapper summary rows — no custom edges.** `Account.charge` & co. assemble `urljoin(self._url, '%s/x' % self.code)` and pass it to `post`/`put`/`http_request`/`paginated`: this is local data flow (attribute read → urljoin argument → joined result via the urljoin step → funnel argument), and the `self._url`/`next_url`/`start_url`/`_refund_transaction_url` field writes→reads across methods are handled by CodeQL's built-in interprocedural attribute taint (python-all 7.x unification dataflow). The `actionator`/`relatitator` closures capture `url` from the enclosing `_make_actionator`/`make_relatitator` scope and use it in `full_url = '%s?%s' % (url, urlencode(kwargs))` → `http_request(full_url, ...)` — local flow through the closure capture. Adding redundant wrapper edges would duplicate every path, so the only non-native propagations (the five families above) carry the custom edges.

## 6. Not covered (rejected labels) and reasoning

Rendered nowhere, per the reviewed `none`/`fp` labels: 6 config reads, 12 response-body reads, 18 non-href/serialization-side `attrib` rows, 1 `Content-Type` getheader, 5 path-only parameters (`Resource.get`, `Plan.get_add_on`, `js.fetch`, `Resource.all`, `Resource.count` — as sources; `all`/`count` kwargs appear only as query-only summary rows), 1 `__main__` demo call (`parse_link_value` at link_header.py:95), 5 path-constrained/config-only fetch wrappers (`Invoice.pdf`, `Resource._create`, plus the `get`/`get_add_on`/`fetch` sink rows), and the dead `urljoin` at __init__.py:842. `API_KEY`/`SOCKET_TIMEOUT_SECONDS` reads never reach a URL (detection.json coverageGaps).

## 7. Uncovered APIs, dynamic calls and CodeQL analysis limitations

- **six.moves aliasing:** all network calls go through `six.moves.http_client` / `six.moves.urllib.parse` aliases. API-graph resolution of six.moves re-exports is less reliable than the uniform local spelling at every call site (Phase-1 finding), so the model uses **syntax-level matching** (bare `urljoin`/`urlsplit`/`urlencode` names; `http_client.HTTPConnection`/`HTTPSConnection`, `connection.request`/`getresponse`, `ElementTree.fromstring` receiver-qualified names) — exactly the idiom the compile-verified Phase-1 extraction used. Consequence: a hypothetical future call site importing these under different local names would not match (acceptable: the tree is frozen at sha 9db2d1a).
- **Closure capture & interprocedural attribute flow are relied upon, not modeled:** if the unification dataflow's closure/attribute handling changes, the second-order paths through `self._url` (resource.py:508/:662 writes → wrapper reads) and the `actionator`/`relatitator` closures would not connect. The direct paths (`__init__.py:585` Location→`page_for_url`; `:223` href→`element_for_url`; `resource.py:566` href→`_make_actionator`→closure) are local and robust.
- **`parse_link_value` result → `Page.start_url`/`next_url`:** requires dict-key iteration modeling (`for url, data in six.iteritems(links)`, resource.py:154) — not representable as a simple additional step and not labeled; the Link-header chain therefore stops at the parsed dict. Recorded as a propagation gap (Phase-1 review §4 note (c)).
- **`HTTPConnection(...)` argument → the connection instance:** not tracked by default; the defense-in-depth sink snk-59 (getresponse receiver) is therefore likely inert — the constructor sinks (snk-55/56/57) and the request-line sink (snk-58) are the effective emission points. Label-mandated, retained, documented.
- **Webhook chain depth:** `notification` → `fromstring` result connects (family 4); onward propagation through `Resource.value_for_element`/`from_element`/`update_from_element` into the `_elem` field is not labeled and not modeled — but the href reads at the end of that chain are themselves sources, so the webhook→re-request chain is covered at the href boundary, not through it.
- **Dynamic dispatch:** `Resource.__getattr__` synthesizes the follow-the-href closures at attribute-access time; `Adjustment.original_adjustment` returns `lambda: Adjustment.get(uuid)` (path-only — not a sink). The closures' *call sites* are dynamic (attribute access on Resource instances); the model anchors on their *definitions* (resource.py:515/:575) and the local flow inside them, which is static. `getattr`-style dispatch does not occur elsewhere.
- **tests/ tree:** present in the CodeQL database; excluded from all sink/source/step matching by the `recurly/`-module file pinning.
- **`urllib.request.urlopen` / `requests` / `httpx` / `socket`:** zero call sites (grep-verified, detection.json `absentApis`) — nothing to model; the funnel analysis is complete for this snapshot.

## 8. Reproducibility and independent-evaluation principles (same as the CWE-78 experiments)

- **Provenance:** built only from `iris/labels/labels.json` and the source tree at sha 9db2d1a. No PyVul ground truth, no fix commits, no CVE descriptions, no pre-existing SSRF audit artifacts were read; the project source, the CodeQL database, the extraction CSVs, the Augur tool files and the Phase-1 labels were not modified.
- **Determinism:** every predicate is a mechanical function of the reviewed labels — label id → family → (shape, file, line) pinning, with the mapping table in §1. A reviewer can re-derive each QL clause from `labels.json` alone; any disagreement is a generation bug to report, not a modeling judgment.
- **Separation of concerns:** sources are only reviewed boundary entries (no internal-wrapper parameter was promoted to a source to force connectivity — the 28 internal wrappers are summary-labeled and get no custom source); sinks are only network-request URL argument positions (pure URL utilities are propagation steps, not sinks); no sanitizer or additional step exists without source evidence; no unconditional taint propagation.
- **Severity honesty:** the alert message carries the attacker-control scope of both endpoints (full-URL vs host-level vs second-order vs host-capable path segment) via `MySources::scopeOf` / `MySinks::scopeOf`, so full-URL control is not conflated with path-only influence; path-only parameters are excluded entirely (labels none/fp).
- **Deferred execution:** compile is verified (`codeql query compile --check-only` → Done [1/1], zero errors/warnings, after the `from`-keyword fix recorded above); database analysis remains deferred. The run step (WORKFLOW.md 5.2.4, sequential) is: `codeql database analyze <DB> iris/queries/Pass3_SSRF.ql --format=sarifv2.1.0 --output=iris/results/pass3.sarif`. Expected-path sanity (derived, not executed): at minimum the local flows `src-19`→`page_for_url` arg (snk-51), `src-5`→`element_for_url` arg (snk-63), `src-25`→`actionator`→`http_request` arg (snk-53)→`connection.request` arg 1 (snk-58), and each `publicUrlParamSource`→`snk-58`/`snk-55..57` (via the urlsplit/netloc step) should produce paths; the attribute-flow-dependent second-order paths and the Link-header chain depend on the limitations in §7.

**Status: Phase 2 Step 4–5 file generation complete and compile-verified (`codeql query compile --check-only` passes with zero errors/warnings). Stopping here — no database analysis executed, no results produced, no report filtering (Step 6).**
