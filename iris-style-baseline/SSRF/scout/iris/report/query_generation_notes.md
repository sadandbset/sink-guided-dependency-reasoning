# Scout — Augur Phase 2 Steps 4–5: Query Generation Notes (Pass 3, CWE-918 SSRF)

- **Run**: `scout-iris-pass3-step3-20261020` (continuation of the Phase 1 labeling run)
- **Generated**: 2026-10-20 · **Project**: scout (DB sha `51a838dd1df58dbb965cd39f6f146a5243ba207a`, `scout-db`, CodeQL CLI 2.25.1, `codeql/python-all`)
- **Inputs**: human-reviewed `iris/labels/labels.json` (73 Pass 3 entries: 3 source, 21 sink, 0 sanitizer, 0 summary, 49 none) + scout source tree. Ground truth, fix commits and CVE descriptions were not consulted.
- **Generated files**: `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass3_SSRF.ql` (query id `py/augur/scout/pass3-ssrf`).
- **Status**: files generated only — **no CodeQL query execution was performed** (per instruction). `codeql pack install` and sequential `codeql database analyze` are pending for the Step 5 execution phase.
- **Process note on the review gate**: `labels/review_decision.json` does not exist in the workspace (Phase 1 stopped at the advisory checkpoint without writing it). The operator's explicit instruction to execute Phase 2 Steps 4–5 is recorded here as the human approval event; no approval artifact was fabricated, and the reviewed `labels.json` was **not modified in any way** during model generation.

## 1. Label → QLL predicate mapping

### MySources.qll (3 of 3 source labels rendered)

| label id | classification (conf.) | rendered predicate / class | node anchored |
| --- | --- | --- | --- |
| src-025 | source/tp (0.95) | `RemoteCorsUrlParamSource` ← `remoteCorsHandlerParam` | parameter 0 of `def remote_cors(remote_url)` (alignviewers/views.py:34), via `DataFlow::parameterNode` |
| src-020 | source/tp (0.80) | `RequestUrlRootSource` ← `requestUrlRootRead` | the `request.url_root` attribute read (cases/views.py:225) |
| src-004 | source/candidate (0.60) | `UrlForExternalSource` ← `urlForExternalCall` | the `url_for(..., _external=True)` call expression (cases/controllers.py:544) |

Not rendered: all 26 `role=none` source rows (admin-config provenance ×16, DB-only/body-only `request.form` ×5, constrained `matchmaker_match.target`, remote_cors header/body/cookie forwarding ×4). No internal wrapper parameter was promoted to a source.

### MySinks.qll (20 of 21 sink labels rendered)

| label id | classification (conf.) | rendered class | network API · URL arg position · call site |
| --- | --- | --- | --- |
| snk-044 | sink/tp (0.95) | `RemoteCorsProxyUrlSink` | `requests.request` · url= keyword (positional 1) · alignviewers/views.py:42 |
| snk-004 | sink/tp (0.85) | `CoverageStatsPostUrlSink` | `requests.post` · arg 0 · cases/controllers.py:94 |
| snk-005, snk-006 | sink/candidate (0.60) | `CoverageStatsPostUrlSink` | `requests.post` · arg 0 · cases/controllers.py:548/554 |
| snk-025–snk-032 | sink/candidate (0.55) | `ScoutRequestsIoUrlSink` | `requests.post/get/delete` · arg 0 · scout_requests.py:34/36/59/61/85/87/89/110 |
| snk-033 | sink/candidate (0.45) | `FtpUrlopenUrlSink` | `urllib.request.urlopen` · arg 0 · scout_requests.py:141 |
| snk-042 | sink/candidate (0.50) | `RefseqGetRequestUrlSink` | `get_request` (in-DB wrapper → `requests.get`) · arg 0 · scout_requests.py:438 |
| snk-014 | sink/candidate (0.55) | `EnsemblRestGetUrlSink` | `requests.get` · arg 0 · ensembl_rest_clients.py:81 |
| snk-018 | sink/candidate (0.50) | `LoqusApiGetUrlSink` | `api_get` (= `get_request_json` alias, in-DB → `requests.get`) · arg 0 · loqus_extension.py:242 |
| snk-024 | sink/candidate (0.50) | `RankModelGetUrlSink` | `requests.get` · arg 0 · rank_model.py:23 |
| snk-010, snk-011, snk-013 | sink/candidate (0.45–0.50) | `MatchMakerWrapperUrlSink` | `matchmaker.patient_delete/patient_matches/match_external` (in-DB wrappers → `scout_requests.*` → `requests.*`) · arg 0 · cases/controllers.py:1163/1206/1257 |

**Not rendered: snk-007** (`query_phenomizer.query`, sink/unknown 0.50, cases/controllers.py:837). The reviewed label carries `flow_kind: unknown` and no argument index because the HTTP request is issued inside the external query-phenomizer package, which is not part of this CodeQL database — there is no provable URL argument position to anchor a sink on. This is a **labeling coverage gap requiring re-review** (see §7), not something to patch silently with a guessed model.

Not rendered: all 23 `role=none` sink rows (Beacon/matchmaker-internal dispatches, panel/CLI constant fetches, body-only wrapper invocations incl. `Beacon.add_variants`, `MatchMaker.patient_submit/match_internal`, and the Rerunner admin-entrypoint `requests.post`).

### MySanitizers.qll

`isBarrier` → `none()` for all pass keys. Matches the reviewed label set (0 sanitizer entries). See §4.

### MySummaries.qll

`isAdditionalTaintStep` → `none()` for all pass keys. Matches the reviewed label set (0 summary entries). See §5.

### Query wiring (queries/Pass3_SSRF.ql)

`Pass3Config implements DataFlow::ConfigSig` delegates to `MySources::isSource(source, "ssrf")`, `MySinks::isSink(sink, "ssrf")`, `MySanitizers::isBarrier(node, "ssrf")`, `MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "ssrf")`; `module Pass3Flow = TaintTracking::Global<Pass3Config>` with `import Pass3Flow::PathGraph` and `flowPath(source, sink)`. The pass key is uniformly `"ssrf"` in all four libraries and the query — verified, no `command_injection` or other pass-key remnants exist in any generated file. Metadata: `@kind path-problem`, `@problem.severity error`, `@precision medium`, `@tags security` + `external/cwe/cwe-918`, `@id py/augur/scout/pass3-ssrf`.

## 2. Source trust boundaries and propagation basis

All three rendered sources sit on the web-request boundary of the Flask app (entry: `create_app` → 13 blueprints, 134 route handlers):

1. **src-025 — full-URL boundary (highest trust in the model).** `@alignviewers_bp.route("/remote/cors/<path:remote_url>")` (alignviewers/views.py:33). Flask's `<path:>` converter hands an arbitrary client-supplied URL string to the handler parameter. Reachability: the global `before_request check_user` hook (app.py:83-98) requires an authenticated session (bypassable only by operator `LOGIN_DISABLED`); there is **no** institute/case binding and **no** role requirement on this endpoint — any logged-in user. Propagation basis: the parameter is passed verbatim as the `url=` keyword at views.py:42 (direct local flow; no summary edge needed).
2. **src-020 — Host-header boundary.** `request.url_root` (cases/views.py:225, pdf_case_report): Werkzeug derives `url_root` from the incoming `Host` header. Reachability: authenticated user + `institute_and_case` case access + chanjo integration enabled (`SQLALCHEMY_DATABASE_URI`). Propagation basis: argument 0 of `controllers.coverage_report_contents(...)` → `base_url` parameter → `base_url + "reports/report"` → `requests.post` arg 0 (controllers.py:94) — standard interprocedural + string-concatenation flow; the callee is defined in the database.
3. **src-004 — Host/SERVER_NAME-derived external URL (candidate).** `url_for("report.json_chrom_coverage", _external=True)` (controllers.py:544, mt_coverage_stats): with `SERVER_NAME` unset (scout/server/config.py defines none) Flask binds the request's URL adapter to the Host header, so the external URL host is request-derived; a deployment setting `SERVER_NAME` pins it (this is why the label stays candidate). Propagation basis: assignment to `cov_calc_url` → `requests.post(cov_calc_url, json=...)` at :548/:554 — plain local flow.

Deliberately excluded trust boundaries: admin deployment configuration (BEACON_URL, MME_URL, LOQUSDB_SETTINGS, RERUNNER_API_ENTRYPOINT, RANK_MODEL_LINK_PREFIX) — operator-trusted, not request-derived; `request.form` values that only select body content or write to MongoDB; the `matchmaker_match` `<target>` path variable (validated against server-listed node ids); and the remote_cors header/body/cookie forwarding (enters non-URL argument positions of the outbound request — impact amplifiers, not URL sources, per the reviewed labels).

## 3. Sink network APIs, dangerous argument positions, call sites

Every rendered sink is anchored at the **URL argument position** of a concrete network-request call, or at a wrapper invocation whose callee (defined in this database) verifiably embeds the argument into the URL it requests:

| network API | URL position | wrapper evidence |
| --- | --- | --- |
| `requests.request(method, url, ...)` | positional 1, passed as `url=` keyword at views.py:42 | direct — value is the route parameter |
| `requests.post(url, ...)` | positional 0 (controllers.py:94/548/554) | direct |
| `requests.post/get/delete(url, ...)` | positional 0 (scout_requests.py:34/36/59/61/85/87/89/110) | wrappers `post_request_json`/`get_request_json`/`delete_request_json`/`get_request` defined in-DB, pass `url` param unchanged |
| `urllib.request.urlopen(url, timeout=...)` | positional 0 (scout_requests.py:141) | `fetch_resource` ftp branch, defined in-DB |
| `get_request(url)` (scout_requests.py:438) | positional 0 | `get_request` defined in-DB → `requests.get(url)` at :110 |
| `api_get(url)` (loqus_extension.py:242) | positional 0 | alias import of `get_request_json` → `requests.get` at :59/:61 |
| `requests.get(url, headers=...)` (ensembl_rest_clients.py:81, rank_model.py:23) | positional 0 | direct |
| `matchmaker.patient_delete/patient_matches/match_external(arg0)` (controllers.py:1163/1206/1257) | positional 0 | MatchMaker methods defined in-DB build `url = "".join([self.host, path, patient_id, ...])` (matchmaker_extension.py:90/122/150) → `request(url=...)` → `scout_requests.*(url=...)` → `requests.*` |

CSV `argIndex -1` normalizations from Phase 1 (recorded in `labels_raw_pass3.json` deviations) are honored: `requests.request` url keyword → 1; wrapper `url=` keywords → 0. Multi-line call sites are matched on the **call** location (e.g. the requests.post at controllers.py:94 whose URL argument expression sits on line 95); the alert-message predicate in the query keys on the **sink expression** location and therefore includes both lines (94/95; 42/44 for the proxy call) — branches remain mutually exclusive by (file, line).

## 4. Scheme, fixed targets, redirects, private addresses, sanitizers

- **Scheme allowlists**: none exist anywhere in scout on the audited paths. The remote_cors proxy forwards `http(s)://<anything>` (and requests would also accept other schemes it supports); `fetch_resource` dispatches `ftp*` to urlopen by `url.startswith("ftp")` — a transport choice, not a rejection.
- **Fixed targets**: admin-config hosts (BEACON_URL, MME_URL, LOQUSDB api_url, RERUNNER entrypoint, rank-model prefix) and hard-constant hosts (Ensembl, PanelApp, OMIM, HGNC, ExAC, eutils.ncbi) are distinguished in the model: their fetch sites are either excluded (role=none labels) or rendered as candidate sinks whose alert messages explicitly state "host pinned, path/query only".
- **Redirects**: `requests.request(..., allow_redirects=True)` at the proxy (views.py:48) — redirect following is *enabled*, so even a scheme/host-checked value could be redirected internally; no redirect policy exists on any other outbound call either (requests defaults). No barrier modeled.
- **Private addresses / DNS resolution**: no `getaddrinfo`/private-IP/loopback check exists anywhere in scout (contrast: calibre-web had a partial one). Nothing to model.
- **Effective sanitizers**: none — `MySanitizers.isBarrier` is `none()` (satisfying the mandatory empty `isBarrier` hook of the workflow). Authentication gates (login, `institute_and_case`, `beacon_submitter`, MME node-membership filter) constrain reachability/ids, not outbound URLs, and are documented as non-sanitizers in `MySanitizers.qll`.

## 5. Summary / custom propagation edges — source-code basis

**None rendered** (0 summary labels). Each reviewed hop is standard data flow, verified in the source:

1. route param → `url=` keyword (same function, direct reference);
2. `request.url_root` → wrapper parameter → string concat → `requests.post` arg (callee `coverage_report_contents` in-DB);
3. `url_for(...)` result → variable → `requests.post` arg;
4. `scout_requests` wrapper parameters → their `requests.*` URL args (all wrappers in-DB, unchanged pass-through);
5. MatchMaker wrapper args → `"".join([self.host, ...])` URL → `request(url=...)` → `scout_requests.*(url=...)` (all in-DB).

No edge was created for: header/body/cookie forwarding in remote_cors (non-URL positions), Beacon/Rerunner form payloads (body positions on fixed admin URLs), or anything not supported by the source. There is no unconditional taint propagation in the model.

No diagnostics query was created: the only internal-reachability question (urlopen reachable only via `fetch_resource`'s ftp branch with constant URLs) was settled by direct source reading in Phase 1, and no formal CWE-918 alert depends on an unverified internal hop. If Step 5 execution surfaces unexpected wrapper-egress alerts (snk-025–032), a separate `diagnostics/` query can be added then — its paths would not count as formal CWE-918 alerts.

## 6. Attacker control-scope tiers (encoded in the alert messages)

The single `isSink` predicate intentionally does not conflate control scopes; `ssrfMessage` in the query differentiates:

| tier | sinks | scope |
| --- | --- | --- |
| full target control | snk-044 | scheme+host+port+path all attacker-chosen (route variable) |
| host-only control (Host header) | snk-004, snk-005/006 | host/port steerable via Host header; path fixed (`url_root`/`url_for _external`) |
| fixed-host path/query embedding | snk-014, snk-018, snk-024, snk-042 | host pinned by constant/config; only path/query segments data-derived (DB/second-order) |
| host-pinned server-issued path ids | snk-010/011/013 | host = admin MME_URL; path parts issued by the MME server itself |
| generic wrapper egress (triage) | snk-025–032, snk-033 | URL position of the shared wrappers' `requests.*`/urlopen calls; no audited caller passes web-derived URLs — alert = unmodeled flow |

## 7. Coverage gaps, dynamic calls, and CodeQL analysis limitations

- **snk-007 / query_phenomizer (gap requiring label re-review)**: network I/O inside the external `query-phenomizer` package, absent from the DB; no argument position is provable. Not modeled. Requested action: re-review with the installed package source; if its endpoint is fixed and hpo_ids go to the body, downgrade to none/fp and keep it out of the model; only add a sink if a URL argument position is proven.
- **External libraries not in the DB**: `requests`/`urllib`/`flask`/`flask_login` internals are outside the database; sinks are anchored at application call sites, and the flask route-parameter source is anchored at the handler parameter (route registration is verified by decorator text, not by framework modeling).
- **chanjo_report blueprint**: mounted from the external `chanjo_report` package (app.py:282-291) — its auth-exempt endpoints are the *target* of the snk-004/005 flows but its code is not analyzable here.
- **Jinja templates**: `igv_viewer.html` feeds admin-configured cloud track URLs through `url_for('alignviewers.remote_cors', remote_url=...)` — template-side flows are invisible to the Python DB; the route-parameter source is independent of this path (any authenticated client can call the route directly).
- **Dynamic dispatch**: `matchmaker.patient_*` and `beacon.add_variants` are attribute calls on module-level extension objects; the sink anchors match by name + site and do not resolve the callee — the wrapper bodies were verified manually (they are in-DB). `EnsemblRestApiClient.send_request` is a `@staticmethod` reached through instances; again site-anchored.
- **String modeling**: URL construction relies on `"".join([...])`, f-strings, and `str.format(...)` (loqus_extension.py:229-240, rank_model.py:75-77, scout_requests.py:432-438); CodeQL Python taint tracking covers these locally, but exact host/path splitting is not modeled — the control-scope tiers come from the reviewed labels, not from the analyzer.
- **Host-header reasoning is configuration-dependent**: the src-004/snk-005/006 tier assumes `SERVER_NAME` unset (scout default); a deployment that sets `SERVER_NAME` pins those targets (documented in the label and the alert message).
- **Expected alert surface at Step 5** (prediction for triage): src-025 → snk-044 (full control) and src-020 → snk-004 (host control) should produce path alerts; src-004 → snk-005/006 depends on the `url_for` result being tracked into `requests.post` (standard local flow, expected to fire); the candidate sinks should produce **no** alerts with the current source set — any alert there indicates an unmodeled flow and must be triaged, not auto-accepted.
- **Not executed**: per instruction, no `codeql pack install` / query run was performed; `iris/qlpack.yml` (name `iris/scout-cwe918`, dependency `codeql/python-all: "*"`) is already in place for the execution phase.

## 8. Reproducibility and independent-evaluation principles

Same principles as the earlier CWE-78 experiments, applied here:

1. **Deterministic rendering**: every predicate/class in the four QLLs is derived 1:1 from a reviewed label entry (mapping in §1); no signature exists that is not backed by a label id, and no label was altered. Rendering is reproducible from `labels.json` alone.
2. **Site pinning**: all AST matches are pinned to (database-relative file, line) or unique function/module identities, so future code changes fail closed (no match) rather than silently widening the model.
3. **No silent model patches**: the single identified labeling insufficiency (snk-07 unverifiable argument position) is recorded in §7 as a re-review request rather than being worked around in the QLLs.
4. **Honest scope statements**: alert messages carry the attacker control tier and the config preconditions (chanjo integration, SERVER_NAME) so that independent evaluators can assess each finding without access to the labeling session.
5. **No ground-truth contamination**: PyVul truth data, fix commits and CVE descriptions were not read; the model is derived only from the scout source tree and the Phase 1 labels.
6. **Audit trail**: `labels/labels_raw_pass3.json` preserves the per-candidate decisions, deviations and unresolved items; this file records the label→predicate mapping and known analyzer limits.
