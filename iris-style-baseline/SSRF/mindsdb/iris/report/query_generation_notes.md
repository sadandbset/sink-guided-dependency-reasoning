# Pass 3 Query Generation Notes — mindsdb (CWE-918 SSRF)

Augur Phase 2, Step 4–5. Generated 2026-10-20 by glm-5.3 (Z.ai GLM) via Claude Code CLI, from the
reviewed Pass 3 labels in `iris/labels/labels.json` (run `mindsdb-ssrf-pass3-labeling-20261020`,
229 entries: 136 sources + 93 sinks) and direct reading of the mindsdb sources at
`dataset/codeql_databases/ssrf_dbs/mindsdb_vuln` (DB `mindsdb-db`, CodeQL CLI 2.25.1).

**Generated files**

| File | Content |
| --- | --- |
| `libraries/MySources.qll` | 12 source predicates (module `MySources::isSource(node, passKey)`) |
| `libraries/MySinks.qll` | 4 sink predicates (module `MySinks::isSink(node, passKey)`) |
| `libraries/MySanitizers.qll` | `isBarrier` resolving to `none()` (no validated sanitizer) |
| `libraries/MySummaries.qll` | 5 evidence-conditioned additional taint-step families |
| `queries/Pass3_SSRF.ql` | `@kind path-problem`, `@problem.severity error`, id `py/augur/mindsdb/pass3-ssrf`, `TaintTracking::Global<Pass3Config>` + `PathGraph`/`flowPath` |

Pass key is `"ssrf"` everywhere (no other pass key appears in any generated file). Per instructions,
**no CodeQL analysis was executed** — files only. API surface was verified against the locally cached
`codeql/python-all 7.1.2` library before writing: `DataFlow::Node.asExpr()`, `DataFlow::exprNode(Expr)`,
`DataFlow::parameterNode(Parameter)` (`semmle/python/dataflow/new/internal/DataFlowPublic.qll`),
`DataFlow::ConfigSig` / `TaintTracking::Global` / `PathGraph` / `flowPath` (`codeql/dataflow 2.1.x`),
`Call.getPositionalArg/getANamedArg/getKwargs`, `DictUnpacking`, `Keyword.getArg/getValue`,
`Subscript.getObject/getIndex`, `Attribute.getName/getObject`, `Name.getId`, `Function.getName/getArg/
getEnclosingScope/getScope`, `Parameter.getName`, `StringLiteral.getText`, `AstNode.getLocation().getFile().getRelativePath()`.
No QL classes are defined; no `module`-named variables; `API::Node` was not needed (all matching is
AST-literal, mirroring the extraction strategy), so no API::Node↔DataFlow::Node conversion arises —
the only node conversions used are the verified `asExpr()`/`exprNode()`/`parameterNode()` functions.

## 0. Review status and label input policy

- The human review gate payload is `labels/phase1_review.md` (advisory checkpoint, WORKFLOW.md §4.5).
  **`labels/review_decision.json` does not exist** in this workspace — no approval record was written
  during Step 3. This is recorded as a process gap; the libraries were built from `labels.json` exactly
  as reviewed, using the documented Phase 2 input set (label_stats.md §"Phase 2 library input"):
  entries with `classification` in (`tp`, `candidate`) — 27 source entries (14 tp + 13 candidate) and
  42 sink entries (37 tp + 5 candidate).
- **No label was modified.** All 160 `fp` entries are excluded from library generation (operator-config
  request boundaries and fixed-host/config/literal/env URL call sites) and remain in `labels.json` for
  Step 6 audit/filtering. The two `role=none` env boundaries (REGISTRY_URL, MINDSDB_EXECUTOR_URL) are
  not sources, per the reviewed labels.
- The 5 additional taint-step families in `MySummaries.qll` (§5) implement propagation glue that the
  reviewed label rationales and `phase1_review.md` §6 already document; they add no new source or sink
  claims. Labeling gaps found during generation are recorded in §6 for re-review, not silently modeled.

## 1. Label ID → QLL predicate mapping

### MySources (27 entries → 12 predicates)

| Predicate | Label IDs (classification) | Boundary |
| --- | --- | --- |
| `sqlApiQueryBody` | P3-S-0117 (tp 0.9), P3-S-0118 (cand 0.5) | `request.json` in `api/http/namespaces/sql.py` (Query.post, POST /api/sql/query → `FakeMysqlProxy().process_query`) |
| `analysisQueryBody` | P3-S-0013 (tp 0.8) | `request.json` in `analysis.py`, constrained to Resource class `QueryAnalysis` (excludes the fp-labeled `DataAnalysis` read at :103) |
| `databasesBody` | P3-S-0046/0047/0050/0051/0055/0056 (tp 0.7–0.85) | `request.json` in `databases.py` (DatabasesResource.post / DatabaseResource.put / TablesList.post — connection-args and re-executed select bodies) |
| `fileUploadJsonBody` | P3-S-0067 (tp 0.95) | `request.json` in `file.py`, class `File` (PUT /api/files/<name>, `data["source"]` url branch) |
| `fileUploadStreamBody` | P3-S-0066 (tp 0.85) | `request.stream` in `file.py`, class `File` (multipart twin of the same body) |
| `configIntegrationJsonBody` | P3-S-0038 (tp 0.8), P3-S-0043 (cand 0.65) | `request.json` in `config.py`, class `Integration` (test-connection / modify params; excludes fp-labeled `GetConfig` read at :56) |
| `configIntegrationFormBody` | P3-S-0039 (tp 0.8), P3-S-0044 (cand 0.65) | `request.form` in `config.py`, class `Integration` |
| `chatbotsBody` | P3-S-0019/0020/0025/0026 (cand 0.6) | `request.json['chatbot']` in `chatbots.py` (`db_params` → integration_controller.add) |
| `modelsBody` | P3-S-0083/0084 (cand 0.6) | `request.json` in `models.py`, class `ModelsList` (CreatePredictor 'using' args; excludes the fp-labeled ModelResource/ModelPredict/ModelDescribe reads) |
| `viewsBody` | P3-S-0127/0128/0133/0134 (cand 0.5–0.55) | `request.json['view']` in `views.py` (stored view query text) |
| `mysqlWireSqlParam` | P3-S-0101 (tp 0.9) | `sql` parameter (arg 1) of `MysqlProxy.process_query` (`api/mysql/mysql_proxy/mysql_proxy.py:522`) |
| `postgresWireSqlParam` | P3-S-0102 (tp 0.9) | `sql` parameter (arg 1) of `PostgresProxyHandler.process_query` (`api/postgres/postgres_proxy/postgres_proxy.py:253`) |

### MySinks (42 entries → 4 predicates)

| Predicate | Label IDs | Dangerous argument position |
| --- | --- | --- |
| `requestsModuleVerbUrl` | 35 entries: P3-K-0003-family verb sites — P3-K-0020, 0025, 0026, 0030–0037, 0038, 0039–0043, 0044, 0046, 0047, 0048, 0062, 0063, 0071–0074, 0076–0078, 0080, 0084, 0085, 0087, 0090 | URL at positional argument 0 of `requests.<get/post/put/delete/head/patch>` |
| `requestsModuleRequestUrl` | P3-K-0027, 0028, 0029 (dremio), P3-K-0086 (strapi) | URL at positional argument 1 of `requests.request(method, url, ...)` |
| `requestsRequestKwargsWrapperUrl` | P3-K-0003 (sap_erp api.py:55), P3-K-0004 (lightdash api.py:21) | `requests.request(**kwargs)` — URL inside the kwargs dict; sink node is the `urljoin(self.base_url, relative_endpoint)` call that produces the dict's `"url"` entry (see §6.1) |
| `crawlSessionGetUrl` | P3-K-0091 | URL at positional argument 0 of `session.get(url, ...)` in `web_handler/urlcrawl_helpers.py` (requests.Session transport) |

### MySanitizers (0 entries)

`isBarrier` resolves to `none()` — no sanitizer entries exist in the reviewed labels and none could be
validated from the source (§4).

### MySummaries (0 label entries of role=summary; 5 edge families)

The mindsdb extraction deliberately contained no `summary`-role candidates (internal wrapper url params
were excluded at extraction, per detection.json coverage_gaps). The five edge families (S1–S4 in
`MySummaries.qll`) realize propagation chains that the reviewed tp/candidate rationales document;
mapping and evidence in §5.

## 2. Source boundary trustworthiness and propagation basis

Every source predicate is an external, request-reachable boundary — no internal network wrapper
parameter was promoted to a source (directive 9 of the label review):

- **Flask request bodies** (`request.json`/`request.form`/`request.stream`) inside `@ns_conf.route`
  flask_restx Resource methods. Reachability verified: `before_request` (initialize.py:251–266) protects
  the `/api/...` namespaces only when `config['auth']['http_auth_enabled']` is True; with the common
  self-hosted default (disabled) these endpoints are unauthenticated, and with auth enabled any
  authenticated user reaches them. The `requests.head` size pre-check in file.py is cloud-only; the
  `requests.get` at :116 runs for any caller.
- **Wire-protocol SQL text**: `MysqlProxy.process_query(sql)` receives the raw COM_QUERY text
  (mysql_proxy.py:712–720) and `PostgresProxyHandler.process_query(sql)` the raw Postgres query
  (postgres_proxy.py:369); both dispatch to `Executor.query_execute`. These parameters are the
  protocol-level boundary; protocol authentication applies before them (recorded as reachability, not
  as sanitizer).
- Propagation basis per family: sql/analysis bodies → `FakeMysqlProxy().process_query(query)` (direct
  call, sql.py:31–33, analysis.py:66); databases bodies → `parameters = database['parameters']` →
  `session.integration_controller.add(name, engine, parameters)` (databases.py:31–49) — then the S1
  persistence relay (§5); file bodies → `data["source"]` → `requests.get` (file.py:92–116, direct local
  flow, no summary needed); config integrations params → `create_tmp_handler(handler_type,
  connection_data=params).check_connection()` (config.py:143–146, standard interprocedural flow into
  S2); chatbots `db_params` → `integration_controller.add` (chatbots.py:44, S1); models/views bodies →
  CreatePredictor/stored view query (parser/storage boundary — see §6.2 gap).

## 3. Sinks: real network request APIs, dangerous argument positions, call sites

`requests` is the only outbound HTTP client in the entire `mindsdb/` tree (verified during extraction:
no `urllib.request.urlopen`/`urlretrieve`, no `httpx`/`aiohttp`/`http.client`; `urllib` usage is
parse-only). All 42 tp/candidate sink entries are `requests` call sites; the four predicates match them
at API-signature level (module object `requests`, verb attribute, URL argument node) plus one
file-constrained session transport:

- **URL at arg 0** (`requestsModuleVerbUrl`): files API `requests.head`/`requests.get`
  (file.py:99/116); `download_file` (mysql_proxy/utilities/functions.py:33); web-crawl `session.get`
  (urlcrawl_helpers.py:102 — separate predicate, arg 0); rag `url_to_documents`
  (rag_handler/settings.py:400); gmail `_download_secret_file` (gmail_handler.py:319) and the youtube
  `GoogleOAuth2Manager._download_secret_file` (google_oauth_utilities.py:67) `credentials_url`
  fetches; dremio :71/:127; frappe_client :34/:59/:70/:91/:108; pinot :185/:188/:211/:214;
  eventstoredb :90/:104/:118/:151/:165/:186; strapi :61/:98; scylla :54; mlflow :43/:79;
  ray_serve :34/:46; clipdrop :33; stabilityai :111; twitter :162; candidates file_handler :386
  and lightwood :155.
- **URL at arg 1** (`requestsModuleRequestUrl`): dremio :138/:143/:146
  (`requests.request("GET", self.base_url + ...)`), strapi :96 (`requests.request(method, url, ...)`).
- **kwargs wrapper** (`requestsRequestKwargsWrapperUrl`): sap_erp/lightdash api.py
  `requests.request(**kwargs)` — the URL is the `"url"` dict entry produced by
  `urljoin(self.base_url, relative_endpoint)`; the label's `arg_index: 1` denotes requests.request's
  URL position and the sink node is the urljoin call expression (rationale in §6.1).
- fp-labeled call sites of the same signatures (fixed provider hosts: airtable, pypi, hackernews,
  discord, coinbase, ollama (hardcoded localhost), etc.; config/OAuth hosts; literal S3/IMDS URLs;
  env-derived URLs) also match the signature-level predicates, but only tainted arguments produce
  alerts; the operator-config and fixed-host FP heuristics run at Step 6. Test files are excluded in
  `MySinks` (mirroring the label scope).

**Attacker-controllability scope is recorded separately, not merged** (per the generation directives;
the single path-problem query reports one severity — the scope differentiation lives in the labels and
this mapping, and is consumed by Step 6 filtering):

| Scope | Sinks (label IDs) |
| --- | --- |
| **Full URL** (scheme+host+port+path) | files API P3-K-0036/0037; download_file P3-K-0044; rag P3-K-0080; gmail/youtube credentials_url P3-K-0047/0048; mlflow P3-K-0062/0063; ray_serve P3-K-0076/0077; clipdrop P3-K-0020; stabilityai P3-K-0084; twitter P3-K-0090; web crawl P3-K-0091; frappe domain P3-K-0039..0043; sap_erp/lightdash base_url P3-K-0003/0004 (base path fixed, authority chosen) |
| **Host/port** (scheme fixed or scheme-arg) | dremio P3-K-0025..0029 (http), strapi P3-K-0085..0087 (http), pinot P3-K-0071..0074 (scheme = connection arg, default http), eventstoredb P3-K-0030..0035 (https only if tls arg), scylla P3-K-0078 (http/https prefix check) |
| **Path/query only** (fp-labeled; not in libraries) | airtable, npm, pypi, aqicn, coinbase, discord, hackernews, instatus, intercom, monkeylearn, oilpriceapi, ollama, pirateweather, shopify, tripadvisor, sharepoint, zipcodebase call sites |
| **Second-order** (response-derived URLs) | eventstoredb `link['uri']` P3-K-0032/0034, frappe redirect Location P3-K-0041, urlcrawl hrefs (P3-K-0091 loop) — all candidate |

## 4. Scheme, fixed targets, redirects, private addresses, sanitizers

- **No valid sanitizer exists** and none is modeled: `MySanitizers::isBarrier` returns `none()`. The
  only URL checks in the tree are scheme-shaped and host-blind — download_file's non-empty-scheme
  check (functions.py:23–31), file_handler's `scheme in ('http','https')` (:347–354), scylla's
  `startswith(('http://','https://'))` (:89), clipdrop's image-extension suffix check, urlcrawl's
  same-domain filter (applies only to discovered hrefs, with the domain derived from the attacker's
  URL), eventstoredb's isinstance checks on tls/port. There is **no host allow-list, no private-IP or
  DNS-resolution check anywhere** (zero `ipaddress`/`is_private` uses), and **no sink sets
  `allow_redirects`** (requests follows redirects by default; only frappe_client.py:63/70 sets
  `allow_redirects=False`), so even a host-shaped check would cover only the initial URL.
- **Fixed targets**: 51 fp-labeled sink sites (literal provider hosts, config auth servers, S3/IMDS
  literals, env URLs) are excluded from the library input set; signature-level predicates still match
  them but cannot fire without taint.
- **file:/data:** schemes are not treated as HTTP requests; no such fetching exists in the tree (the
  scheme-permissiveness of download_file is recorded in its label rationale as a separate
  cross-protocol concern, outside CWE-918).
- The `isBarrier` hook is kept in `Pass3Config` (WORKFLOW.md §5.2.3) so a re-reviewed barrier can be
  added without touching the query.

## 5. Summary / custom propagation edges — source-code evidence

All five families are conditioned on concrete functions, parameters, and attribute loads verified in
the source this run; **no unconditional taint propagation**:

| Edge | From → To | Source-code evidence |
| --- | --- | --- |
| S1 `integrationConnectionArgsPersistence` | `IntegrationController.add` connection_args param (arg 3) / `modify` data param (arg 2) → `_make_handler_args` connection_data param (arg 3) | write: integrations.py:194 `add` → `_add_integration_record` → :160–168 `db.Integration(data=connection_args or {})`; :217 `integration_record.data = data`; read: get_handler :447 `connection_data = integration_data.get('connection_data', {})` → :495–500 `_make_handler_args(..., connection_data=connection_data, ...)`; check_connections → create_tmp_handler :355–358. This is the sqlalchemy persistence relay the labels' rationales describe (second-order stored connection args). |
| S2 `handlerConstructionDispatch` | `_make_handler_args` connection_data param (arg 3) → handler `__init__` connection_data/kwargs param (arg 2), restricted to the nine connection-arg handler files | integrations.py:363–373 `handler_ars = dict(..., connection_data=connection_data, ...)`; :515 `handler = HandlerClass(**handler_ars)`; :410 `DBClient(handler_type, self.handler_modules[handler_type].Handler, **handler_ars)` — dynamic class + kwargs-splat dispatch not resolvable by data flow. Handler `__init__` signatures verified (dremio/pinot `(self, name, connection_data, **kwargs)`; strapi/eventstoredb/frappe/scylla/sap_erp/lightdash/gmail `(self, name, **kwargs)` reading connection_data from kwargs). |
| S3 `handlerInitParamToSelfAttr` | handler `__init__` connection_data/kwargs param (arg 2) → `self.<url-attr>` loads in the same handler file | stores verified: dremio_handler.py:46–49 (`self.connection_data = connection_data`; `self.base_url = f"http://{self.connection_data['host']}:{...}"`), strapi_handler.py:25–27, eventstoredb_handler.py:53–71 (`self.basic_url = build_basic_url(...)`), frappe_handler.py:44 (`self.domain = args['domain']`), scylla_handler.py:37, sap_erp_handler.py:69, lightdash_handler.py:42, gmail_handler.py:287–289; loads are the labeled sink sites. Cross-method field flow is unreachable to standard data flow because the instance comes from the S2 dispatch. |
| S3' `clientConstructorUrlToSelfAttr` | `FrappeClient.__init__` domain (arg 1) / `SAPERP.__init__` url (arg 1) / `Lightdash.__init__` url (arg 1) → `self.base_url`/`self.domain` loads in the client files | frappe_client.py:14–19 (`self.domain = domain`; `self.base_url = f'{self.domain}/api'`), sap_erp_handler/api.py:39–40 (`self.base_url = url`), lightdash_handler/api.py:7–8 (`self.base_url = urljoin(url, "/api/v1/")`); constructors called directly (frappe_handler.py:138, sap_erp_handler.py:134, lightdash_handler.py:73), so taint reaches the parameter through standard flow. |
| S4 `urljoinUrlReassembly` | either argument of `urljoin(...)` → the call result, at the three fetch-feeding sites | URL 拼接 evidence: sap_erp_handler/api.py:46 `urljoin(self.base_url, relative_endpoint)` (the kwargs "url" entry); lightdash_handler/api.py:14; urlcrawl_helpers.py:122 `urljoin(url, href)` (crawl link reassembly — an absolute href replaces the whole URL). urljoin is not modeled as a taint step by the standard library. |

**Expected connectivity of the reviewed chains** (what the query can surface, given the model):
request.json (databases/config/chatbots) → `integration_controller.add/modify`/`create_tmp_handler`
→ S1/S2 → handler `__init__` → S3 → `self.<url-attr>` loads → labeled sinks (dremio/pinot/strapi/
eventstoredb/frappe/scylla/gmail hosts; sap_erp/lightdash via S3' + S4 into the kwargs-wrapper sink);
request.json/stream (file.py) → `data["source"]` → file.py:99/116 directly (no summary needed).

## 6. Gaps, dynamic calls, and CodeQL analysis limitations

1. **kwargs-wrapper sink representation.** For P3-K-0003/P3-K-0004 the label records
   `arg_index: 1` (requests.request's URL position), but the call is `requests.request(**kwargs)` —
   there is no positional argument node, and taint of a dict *value* does not taint the dict *node*.
   The sink is therefore instantiated at the `urljoin(...)` expression that produces the `"url"` entry
   (the concrete URL value handed to requests.request). This is a faithful but non-literal realization
   of the label's argument position; flagged here for reviewer awareness.
2. **SQL-text parser boundary (largest recall gap).** The two tp SQL sources
   (`process_query(sql)`, and the request.json['query'] bodies that flow into them) do not connect to
   sinks through data flow: the sql text is consumed by `parse_sql` from the external `mindsdb_sql`
   package (not in this database), and connection args re-materialize as AST/dict values on the other
   side. The `CREATE DATABASE ... WITH PARAMETERS {'url': ...}` → `download_file` chain
   (P3-K-0044) and the `SELECT ... FROM web WHERE url=...` chain (P3-K-0091) are therefore verified in
   code but **not reachable by this query's data flow**; bridging them would require a
   parser-semantics summary edge, which has no per-site code evidence and was deliberately not added.
   Recommend recording this as a labeling/model insufficiency for re-review (options: accept as
   analysis limitation, or add reviewed semantic edges from the parsed-AST parameter maps).
3. **model_storage replay** (mlflow/ray_serve P3-K-0062/0063/0076/0077): CREATE MODEL `using` args are
   persisted via `model_storage` and replayed at predict time; the create-side taint crosses the same
   parser/storage boundary, so no edge was added (gap for re-review).
4. **Dynamic dispatch residuals.** `HandlerClass(**handler_ars)` and `DBClient(...)` construction
   (S2) is bridged only for the nine connection-arg handler files with tp-labeled sinks; other
   handlers rely on standard resolution. `check_connection()` dispatch on dynamically constructed
   handlers (config.py test path) is covered by S1/S2/S3 up to the handler entry, but any
   handler-internal indirection beyond the modeled attributes is not.
5. **Uncovered APIs / invisible I/O**: third-party SDKs perform network I/O outside this database
   (jira `jira_url`, shopify `shop_url` via the Shopify SDK, MlflowClient) — boundary captured by the
   source entries, fetch sites invisible. gRPC handler-wrapper traffic and the Mongo wire server's
   BSON→SQL translation are out of CWE-918 HTTP scope (documented in detection.json). The web-crawl
   response-derived href loop and eventstoredb `link['uri']` fetches are second-order (response
   content is not in the source set).
6. **fp signature co-matching.** Signature-level sink predicates match fp-labeled call sites too
   (same `requests` signatures); only tainted arguments produce alerts, and the Step 6 heuristics
   (admin-config URLs, fixed provider hosts) must be applied to the results.
7. **`labels/review_decision.json` is absent** (see §0) — recommend writing the approval record before
   the Step 5 execution run.

## 7. Reproducibility and independent-evaluation principles

Same principles as the prior CWE-78 experiments in this series:

- **Determinism**: every generated file is rendered from the reviewed `labels.json` plus code evidence
  recorded in this note; the label→predicate mapping (§1) is total (27/27 source entries and 42/42
  sink tp/candidate entries mapped; 0 fp entries used). Regeneration re-reads labels and source, never
  vulnerability databases.
- **Independence**: no PyVul ground truth, fix commits, CVE descriptions, or pre-existing SSRF analysis
  artifacts in the repo root were consulted at any point (Phase 1 or Phase 2); the DB root's nested
  `mindsdb-db/` directory and root-level report/CSV artifacts were not read.
- **Immutability**: project sources, the CodeQL database, the extraction CSVs, the Augur tool tree and
  the Phase 1 labels were not modified; all outputs live under `iris/` only.
- **Auditability**: each predicate carries its label IDs and evidence locations; each summary edge
  carries the exact store/load/call lines it bridges; gaps are recorded (§6) rather than bridged by
  unconditional propagation.
- **No analysis executed**: per instructions, `codeql database analyze` was not run; Step 5 execution
  (sequential, one query at a time, SARIF output) remains to be performed after the human review gate.
