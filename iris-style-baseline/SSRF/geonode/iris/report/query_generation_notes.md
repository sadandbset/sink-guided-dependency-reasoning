# Query Generation Notes — GeoNode Pass 3 (CWE-918 SSRF), Augur Phase 2 Steps 4–5

- **Scope:** `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`,
  `libraries/MySummaries.qll`, `queries/Pass3_SSRF.ql`.
- **Inputs:** `labels/labels.json` (pass_id 3, 492 entries; Phase 1 reviewed labeling),
  `extraction/sources.csv` / `sinks.csv`, and the GeoNode sources at commit
  `abd1baf3d709265604010b7b15c8bfcc2a72a252` (read-only).
- **Review artifact:** `labels/review_decision.json` was **not present** in the workspace at the
  time of generation. The labeling artifacts (`labels/labels.json`, `labels/phase1_review.md`,
  `labels/label_stats.md`) were used as the reviewed input, per the run instructions. This is
  recorded as a process gap: the advisory checkpoint decision was never written; a human review
  sign-off (`review_decision.json`) should be added before Phase 2 Step 5 execution. No label was
  modified during model construction.
- **Toolchain:** CodeQL CLI 2.25.1 (E:\codeql), codeql/python-all 7.1.2 (shared dataflow
  framework codeql/dataflow 2.1.3). All five files pass `codeql query compile --check-only`
  against the installed toolchain. **No query execution / database analysis was performed**
  (per instruction, generation only).
- **API style:** modular data flow — `DataFlow::ConfigSig`, `TaintTracking::Global<Pass3Config>`,
  `Pass3Flow::PathGraph`, `flowPath`. Pass key: **"ssrf"** everywhere (no other pass key occurs
  in any generated file). `import libraries.MySources` dot-syntax imports from the iris qlpack
  root (`qlpack.yml`, name `iris/geonode-cwe918`).

## 1. Label ID → QLL predicate mapping

Only entries with `classification` in (`tp`, `candidate`) were instantiated (the Phase 1
`label_stats.md` library-input rule); all `fp` entries were excluded. 43 source-side labels and
33 sink-side labels plus 13 summary labels map as follows.

### MySources::isSource(node, "ssrf")

| Predicate (private helper) | Label IDs | Runtime node | Trust boundary |
| --- | --- | --- | --- |
| `proxyUrlParameter` | P3-S-0302, P3-S-0303 | `Subscript request.GET["url"]` (proxy/views.py:97) | anonymous web request (CSRF-only view) |
| `serviceRegistrationFormUrlSubscript` | P3-S-0063 | `Subscript self.cleaned_data["url"]` (services/forms.py:55) | form field of an authenticated user |
| `serviceRegistrationFormUrlGet` | P3-S-0064 | `Call self.cleaned_data.get("url")` (services/forms.py:64) | form field of an authenticated user |
| `registerServicePost` | P3-S-0356 | `Attribute request.POST` in `register_service` (services/views.py:60) | authenticated POST body |
| `setThumbnailFileUrlGet` | P3-S-0266 | `Call request.data.get("file")` (base/api/views.py:1343) | authenticated DRF payload |
| `setThumbnailFileUrlSubscript` | P3-S-0267, P3-S-0268 | `Subscript request.data["file"]` (base/api/views.py:1346) | authenticated DRF payload |
| `datasetApiRequestData` | P3-S-0351, P3-S-0352 | `Attribute request.data` (layers/api/views.py:128,257) | authenticated DRF payload |
| `documentFormDocUrl` | P3-S-0061 | `Call self.cleaned_data.get("doc_url")` (documents/forms.py:211) | form field (low-confidence candidate) |
| `proxyAuthorizationHeader` | P3-S-0304, P3-S-0305, P3-S-0306 | `Call request.META.get("HTTP_AUTHORIZATION"...)` (proxy/views.py:160-161) | anonymous request header |
| `proxyRequestBody` | P3-S-0308 | `Attribute request.body` in `proxy` (proxy/views.py:185) | anonymous request body |
| `getHeadersRequestFields` | P3-S-0139…P3-S-0153 (14 ids) | `request.headers/COOKIES/META/method` reads inside `get_headers` (utils.py:381-452) | anonymous request fields (low confidence) |
| `cswDispatchRequestMeta` | P3-S-0353, P3-S-0354 | `Attribute request.META` in `csw_global_dispatch` (catalogue/views.py:58-59) | anonymous CSW request env |
| `managementCommandJobData` | P3-S-0094 | `Attribute request.data` (management_commands_http/mixins.py:29) | admin-authenticated DRF payload |
| `geoserverProxyPathParams` | P3-S-0383, P3-S-0384 | `Parameter proxy_path`/`downstream_path` of `geoserver_proxy` (geoserver/views.py:417) | anonymous route segments (path-only control) |
| `thumbnailUrlSecondOrder` | P3-S-0098 | `Attribute instance.thumbnail_url` loads (geoserver/signals.py:143, helpers.py:2160) | second-order DB field |
| `serviceBaseUrlSecondOrder` | P3-S-0103 | `Attribute self.base_url` load in `Service._get_service_url` (services/models.py) | second-order DB field |
| `harvesterRemoteUrlSecondOrder` | P3-S-0101 | `Attribute record.remote_url` loads in `from_django_record` (harvesting/harvesters/*.py) | second-order DB field |
| `datasetOwsUrlSecondOrder` | P3-S-0102, P3-S-0104 | `Attribute *.ows_url` loads (thumbs/thumbnails.py:260,275) | second-order DB fields |

**Label ids NOT instantiated as source nodes (recorded, not silently dropped):**

- P3-S-0062 (`CreateServiceForm.url` CharField definition): a class-scope field definition has no
  runtime data flow node carrying user input; the boundary is realized at runtime by P3-S-0063 /
  P3-S-0064 / P3-S-0356, which are instantiated.
- P3-S-0099 (`Link.url` field definition) and P3-S-0100 (`Document.doc_url` field definition):
  the labels themselves record that no server-side fetch consumer was identified for these
  fields (display/redirect only); the document boundary is instantiated via P3-S-0061. No
  `Link.url`/`doc_url` load node is modeled — instantiating generic `.url` attribute loads would
  be unjustifiably broad. **Gap requiring re-review:** if a fetch consumer for `Link.url` /
  `Document.doc_url` is later identified, a new label (not a model edit) is needed.
- P3-S-0394…P3-S-0400 (`request.POST` rows in documents/views.py:326-338): the URL-bearing value
  of these POSTs is the DocumentForm `doc_url` field, whose read is instantiated (P3-S-0061); the
  raw `request.POST` nodes are not separately instantiated because Django form binding
  (`DocumentForm(request.POST)`) is framework code outside the database and would add dead
  boundary markers only. (For `register_service` the analogous `request.POST` row WAS
  instantiated, P3-S-0356, because its label is `tp`.)

### MySinks::isSink(node, "ssrf")

Sinks are matched at **API-signature level** (see §3); every matcher places the sink node on the
URL argument. Mapping of label IDs to the signature families:

| Predicate (private helper) | Dangerous position | tp/candidate label IDs backing the signature | fp-labeled sites sharing the signature (matched, but untainted) |
| --- | --- | --- | --- |
| `requestsModuleVerbUrl` | `requests.<get/post/put/delete>(url, …)` positional arg 0 | P3-K-0075 (tp), P3-K-0015 (cand) | P3-K-0001, P3-K-0007-0014, P3-K-0017-0018, P3-K-0022-0026, P3-K-0053-0061 |
| `httpClientWrapperUrl` | `http_client.<request/get/post>(url, …)` positional arg 0 | P3-K-0016, P3-K-0065, P3-K-0070 (tp), P3-K-0037-0040 (cand) | P3-K-0048, P3-K-0071-0072, helpers.py:127/1617-1680, ows.py:182 |
| `harvesterSessionUrl` | `self.http_session/http_session.<get/post>(url, …)` positional arg 0 | P3-K-0002, P3-K-0003, P3-K-0027-0035, P3-K-0079 (cand) | — |
| `httpClientActionKeywordUrl` | `action(url=…)` keyword `url` value (utils.py:1236) | P3-K-0063 (tp) | — |
| `httpClientSessionGetUrl` | `session.get(url, …)` positional arg 0 (utils.py:1248) | P3-K-0064 (tp) | — |
| `owslibWrapperUrl` | `WebMapService/WebFeatureService/WebCoverageService/openURL/http_post(url, …)` and `wms111/wms130.WebMapService_*(url, …)` positional arg 0 | P3-K-0062, P3-K-0073, P3-K-0074 (tp), P3-K-0076-0078 (cand) | P3-K-0021, P3-K-0042, P3-K-0069 |
| `arcrestWrapperUrl` | `arcrest.<MapService/ImageService/Catalog>(url, …)` positional arg 0 | P3-K-0004, P3-K-0005, P3-K-0006 (cand) | — |
| `smartOpenUri` | `smart_open.open(uri=…)` keyword `uri` value | P3-K-0019 (tp) | — |

**Sink label IDs deliberately not modeled:**

- P3-K-0020 (`CatalogueServiceWeb(url=…)`, catalogue/backends/generic.py:56): the only instance
  is fp (settings.CATALOGUE URL, `skip_caps` defaults to true); the signature has no tp/candidate
  instance. The library's actual CSW fetch `http_post(self.url, …)` (P3-K-0022) is covered by
  `owslibWrapperUrl`.
- P3-K-0046 / P3-K-0047 (`client.post(urljoin(self.host, …))`, geoserver/management/commands/
  importlayers.py:152): CLI/`--host`-derived URL (fp); the receiver name `client` is too generic
  to model safely without false positives.

Test files (`%/tests/%`, `%tests.py`, `%/test_%.py`) are excluded from sink matching
(`notInTestFile`), mirroring the label scope and the WORKFLOW "test files → FP" heuristic.

### MySanitizers::isBarrier(node, "ssrf")

**None.** Zero sanitizer labels exist for pass 3 and no additional barrier could be validated
from the source (see §4). The predicate resolves to `none()` and the `isBarrier` hook remains in
the query so a validated barrier can be added after re-review.

### MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "ssrf")

| Edge | Backing summary labels | Source-code basis |
| --- | --- | --- |
| M0 `proxyUrlToOutboundRequest` | P3-S-0300 (proxy `url` param); realizes the chain described by P3-S-0302/0303 | proxy/views.py:97 `raw_url = url or request.GET["url"]` → :98-192 normalization (urllib.parse + hyperlink) → :194 `http_client.request(_url, …)` |
| M1 `serviceHandlerFactoryDispatch` | P3-S-0001 | serviceprocessors/__init__.py:64-68 `handler = handlers.get(service_type, {}).get("handler"); service = handler(base_url, service_id)` |
| M2 `handlerInitUrlToSelfUrl` | P3-S-0031, P3-S-0016, P3-S-0017, P3-S-0412, P3-S-0413 | serviceprocessors/base.py:69-70 `self.url = url`; loads at base.py:81, wms.py:63/95/271/282 |
| M3 `thumbnailUrlPersistence` | write side P3-S-0266/0267/0268, load side P3-S-0098 | base/api/views.py:1367 `resource.thumbnail_url = file_data`; loads at geoserver/signals.py:143, helpers.py:2160 |
| M4a `requestDataToStorageManager` | P3-S-0351/P3-S-0352 → P3-K-0019 | layers/api/views.py:128→132→135/276 serializer round-trip → `StorageManager(remote_files=data)` |
| M4b `retrieverFileParamToOriginalUri` | P3-K-0019 chain | storage/data_retriever.py:55 `self._original_file_uri = _file`; load at :115-117 `smart_open.open(uri=self._original_file_uri, …)` |
| M4c `storageManagerParamToItemRetriever` | P3-K-0019 chain | storage/manager.py:129 `DataRetriever(remote_files)`; data_retriever.py:150 `{name: DataItemRetriever(file) for …}` |
| M5 `harvesterRecordRemoteUrlToSelf` | P3-S-0029, P3-S-0015 | harvesters/wms.py:129-133 `cls(record.remote_url, record.id, …)`; base.py:79-80 `self.remote_url = remote_url` |
| M6 `serviceUrlPropertyEvaluation` | P3-S-0103 consumers | services/models.py:81-96 `_get_service_url` (`urlparse(self.base_url)`); property loads at services/views.py:94/97/190/288, serviceprocessors/wms.py:106/149, arcgis.py:~126, thumbs/thumbnails.py:308 |
| M7 `geoserverProxyPathToProxyUrlArgument` | P3-S-0383/P3-S-0384 → P3-S-0300 | geoserver/views.py:374-376 `raw_url = "".join([LOCATION, downstream_path, path])` → :466-468 `proxy(request, url=raw_url, …)` |

**Summary labels that need NO additional edge** (standard interprocedural data flow covers them,
verified against the call graphs): P3-S-0159 (`is_monochromatic_image` `image_url` →
`http_client.get(url)` at utils.py:1883), P3-S-0137/P3-S-0138 (`get_map` → `getmap` → `openURL`
at thumbs/utils.py:421), P3-S-0030 (`download_resource_file` `url` → `requests.get(url,
stream=True)` at harvesters/base.py:334).

## 2. Source trust boundaries and propagation basis

All instantiated sources correspond to reviewed external request/URL boundaries; no internal
network wrapper parameter was promoted to a source (the 15 extracted param candidates are either
summary edges (M0/M1/M2/M4b/M5), sinks of native flow, or route-exposed parameters
(geoserver_proxy, instantiated as `candidate` with path-only controllability)):

- **Anonymous (no authentication):** `/proxy/?url=` (proxy/views.py:97) — only
  `@requires_csrf_token`; proxy Authorization header/body (P3-S-0304..0308); `csw_global_dispatch`
  META (public CSW endpoint). These carry the strongest trust-boundary claim.
- **Any authenticated user:** `register_service` POST + `CreateServiceForm.url`
  (@login_required, no admin gate — the fetch happens during form validation);
  `set_thumbnail` (IsAuthenticated + UserHasPerms); DRF dataset metadata/replace/append
  payloads (dataset permissions).
- **Admin-only boundary (kept as candidate per labels):** management_commands_http job payloads
  (IsAdminUser). Note: its reachability to the `updategeoip --url` fetch is NOT modeled (job
  execution goes through celery/management-command machinery outside the database) — this source
  is instantiated but has no modeled path to any sink.
- **Second-order DB fields** (attacker-influenced content with a verified write path):
  `ResourceBase.thumbnail_url` (written by set_thumbnail), `Service.base_url` (written by service
  registration), `Harvester.remote_url` (admin API **and** auto-created from the
  user-registered `Service.service_url` at serviceprocessors/wms.py:145 / arcgis.py:129),
  `Dataset/MapLayer.ows_url` (harvested from user-registered services).

## 3. Sinks: real network APIs, dangerous argument positions, call sites

| API | URL position | tp/candidate call sites |
| --- | --- | --- |
| `requests.get/post/put/delete` (python-requests) | positional arg 0 | services/serviceprocessors/wms.py:284; harvesting/harvesters/base.py:334 |
| `geonode.utils.HttpClient.request/get/post` (internal wrapper; per-request `requests.Session`, `verify=False`) | positional arg 0 | proxy/views.py:194; serviceprocessors/base.py:81; utils.py:1883; geoserver/helpers.py:1012-1082 |
| `action(url=url, …)` / `session.get(url, …)` — final dispatch inside `HttpClient.request` | keyword `url` value / positional arg 0 | utils.py:1236, 1248 |
| `requests.Session.get/post` on harvester `http_session` | positional arg 0 | harvesters/geonodeharvester.py:145…1274; harvesters/wms.py:203; harvesters/arcgis.py:156, 277 |
| OWSLib `WebMapService`, `wms111/wms130.WebMapService_*`, `WebFeatureService`, `WebCoverageService`, `openURL`, `http_post` | positional arg 0 | serviceprocessors/wms.py:96, 272; harvesters/wms.py:78, 92, 157, 203; thumbs/utils.py:421 |
| arcrest `MapService` / `ImageService` / `Catalog` | positional arg 0 | harvesters/arcgis.py:347, 350, 410 |
| `smart_open.open` | keyword `uri` value | storage/data_retriever.py:115 |

The two keyword-position sinks (`action(url=…)`, `smart_open.open(uri=…)`) are recorded with
`arg_index 0` in the labels; the QL matchers place the sink node on the keyword **value**
expression, which is the node the taint analysis must reach. `urljoin`/`urlparse`/`urlsplit`/
`URL.from_text` were never treated as sinks (pure URL processing).

## 4. Scheme, fixed targets, redirects, private addresses, sanitizers

- **URL scheme:** no scheme allow-list exists on any modeled path. The `URLValidator` in
  `set_thumbnail` (base/api/views.py:1359-1362) rejects `file:`/`data:` (default schemes
  http/https/ftp/ftps) and enforces a png/jpeg/jpg path suffix — it constrains scheme/format but
  **not the host**, so it is not a barrier. `smart_open` accepts non-http schemes (`s3://`, `gs://`,
  plain local paths); that cross-protocol/local-file-read aspect is recorded in the labels and
  deliberately NOT merged into the CWE-918 verdicts (it is path-traversal-pass material).
- **Fixed targets:** the 46 fp-labeled call sites (OGC_SERVER LOCATION, SITEURL,
  SOCIALACCOUNT_PROVIDERS, CATALOGUE, monitoring config, br/geofence/security CLI flows) share
  sink signatures with the tp/candidate sites; they are matched by the model but only
  actually-tainted arguments alert. Step 6 filtering applies the operator-config FP heuristics.
- **Redirects:** the `requests` session inside `HttpClient.request` follows redirects by default,
  so only the initial URL's host is ever validated; no redirect control exists anywhere in the
  modeled code (the proxy's "does not support redirects" branch at proxy/views.py:239-249 handles
  the response, not the redirect following).
- **Private addresses / DNS:** `extract_ip_or_domain` + `validate_host`
  (proxy/views.py:140) compare the host as a string; there is no DNS resolution, private-IP
  range check, or rebinding protection anywhere in the modeled code.
- **Sanitizer verdict:** none modeled (`isBarrier` = `none()`). The partial PROXY_ALLOWED_HOSTS
  allow-list is documented in `MySanitizers.qll` as deliberately NOT a barrier (DEBUG bypass,
  user-extendable membership via service registration, string-only host match, redirect
  following). Auth/permission gates are reachability facts in rationales, never barriers.

## 5. Controllability scopes (kept distinct, not merged into one severity)

The formal alert message is uniform (path-problem format); the scopes below are the basis for
Step 6 triage and are encoded in the label rationales:

| Scope | Sources | Sinks |
| --- | --- | --- |
| **Full URL** (scheme+host+port+path) | P3-S-0302/0303 (proxy `?url=`), P3-S-0063/0064/0356 (service registration URL), P3-S-0266-0268 (thumbnail URL; scheme constrained to http/https/ftp(s) + image extension) | proxy fetch, handler probe/OWS fetches, `is_monochromatic_image` fetch |
| **Full URI, multi-scheme** (incl. s3:// and local paths) | P3-S-0351/0352 (dataset file paths) | `smart_open.open(uri=…)` (cross-protocol concern recorded separately) |
| **Host part, second-order** (URL fixed at registration/harvest time by a user, fetched later) | P3-S-0101/0103/0102/0104, P3-S-0098 | harvester session/OWSLib/arcrest fetches, thumbs `openURL`, geoserver helpers describe calls |
| **Path/query only** (host fixed to the configured geoserver backend) | P3-S-0383/0384 (geoserver_proxy route segments) | via proxy delegation M0/M7 |
| **Query only** (token appended to outbound query) | P3-S-0304..0306 | — |

## 6. Uncovered APIs, dynamic dispatch, and CodeQL analysis limits

- **Dynamic dispatch:** the service-handler registry (`handlers.get(service_type, …)`,
  serviceprocessors/__init__.py:64-68), the harvester classmethods (`cls(record.remote_url, …)`),
  and the DRF serializer round-trip are not resolvable by the standard library — covered by the
  scoped additional edges M1, M5, M4a. `handler(...)`-style resolution failures are the reason
  those edges exist; no unconditional edges were added.
- **Property getters** (`Service.service_url`) are not inlined — covered by M6.
- **`getattr` dispatch:** `action = getattr(session, method.lower(), None)` (utils.py:1232) —
  the keyword sink matcher covers `action(url=…)` by name; the fallback `session.get` is matched
  separately. Other `getattr`-based URL method selection elsewhere (none known in geonode) is
  not modeled.
- **Unmodeled third-party URL processing:** `hyperlink.URL.from_text(...).normalize().to_text()`
  and parts of `urllib.parse` processing inside `proxy()` and `_get_cleaned_url_params` — M0/M7
  bridge the former; the WMS harvester GetCapabilities chain (harvesters/wms.py:194-205) depends
  on stdlib flow modeling of `urlparse`/`urlsplit` inside `_get_cleaned_url_params` /
  `get_ogc_wms_url` and **may under-report** (documented, not bridged — no code evidence
  justifying a direct edge was found at labeling time).
- **Framework code outside the database:** Django forms, Django REST Framework serializers,
  Django ORM managers (`Harvester.objects.create(...)`, `Service.objects...`), celery task
  machinery, pycsw, requests/OWSLib/arcrest/smart_open internals. Consequences: request.POST →
  form binding is not tracked (dead boundary markers); harvester creation through
  `Harvester.objects.create` is covered via the second-order M5 source instead; the
  management_commands_http chain to `updategeoip --url` has no modeled path; the pycsw CSW
  fetch behavior is unverifiable from this database.
- **`session.verify = False`** on every `HttpClient` request — recorded, not modeled (TLS
  validation is orthogonal to CWE-918).
- **Control-flow splitting:** `DataFlow::exprNode(e)` may bind several nodes for one expression;
  all edge endpoints are matched via the same node constructors the query uses, and the expected
  call sites are in straight-line code, but exact alert counts can only be confirmed by execution.
- **Diagnostics:** no separate diagnostics query was created — the only internal-reachability
  questions (handler registry, classmethod construction) are answered by the scoped summary
  edges above, and no diagnostic path is counted as a formal CWE-918 alert. The empty
  `iris/diagnostics/` directory remains available if Step 5 execution reveals a need.

## 7. Label gaps recorded for re-review (no silent model fixes)

1. `labels/review_decision.json` absent — the checkpoint decision was never recorded (see header).
2. P3-S-0099 (`Link.url`) / P3-S-0100 (`Document.doc_url`): fetch consumers unverified; if one
   exists outside the extracted sink set, a new label and source predicate are required.
3. P3-S-0094 (management_commands_http `request.data`): admin-gated candidate with a concrete
   second-order chain to `updategeoip --url` → `requests.get`, but the job-execution machinery is
   outside the database; currently produces no modeled path.
4. P3-S-0353/0354 (pycsw env forwarding): fetch reachability inside pycsw unverifiable from this
   database; if pycsw is added to the analysis scope, this needs a summary edge and possibly new
   sink labels.
5. The WMS-harvester GetCapabilities chain may under-report due to unmodeled `urlparse`-based URL
   reassembly (see §6) — if execution confirms this, a re-reviewed summary label would be needed
   before adding an edge.

## 8. Reproducibility and independent evaluation

Same principles as the earlier CWE-78 experiment: everything generated here is derived only from
the reviewed `labels/labels.json` plus the current source snapshot; no PyVul ground truth, fix
commits, or CVE locations were consulted; the project sources, CodeQL database, extraction CSVs,
Augur tool files, and the Phase 1 labels were not modified. The pipeline remains deterministic:
Step 4 output is a pure function of (labels.json, source tree, toolchain) — the compile check is
`cd iris && codeql query compile --check-only queries/Pass3_SSRF.ql` (CLI 2.25.1,
python-all 7.1.2). Step 5 (execution against `geonode-db`) was intentionally NOT run and is the
next action, pending the missing review sign-off.
