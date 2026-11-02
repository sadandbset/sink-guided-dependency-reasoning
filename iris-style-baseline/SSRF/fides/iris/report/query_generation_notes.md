# Query Generation Notes — fides, Pass 3 (CWE-918 SSRF)

Augur Phase 2, Step 4–5. Generated: 2026-10-20.
Run context: `iris/labels/labels.json` (run_id `fides-iris-pass3-step3-20261020`, model
glm-5.3, 190 entries: 26 source / 30 sink / 1 summary / 133 none), rendered into:

| file | content |
| --- | --- |
| `libraries/MySources.qll` | 26 source predicates (site-pinned) |
| `libraries/MySinks.qll` | 30 sink predicates + `controlScope` scope taxonomy |
| `libraries/MySanitizers.qll` | `isBarrier` → `none()` (no labeled sanitizers) |
| `libraries/MySummaries.qll` | `isAdditionalTaintStep` → `none()` (see §5) |
| `queries/Pass3_SSRF.ql` | `@kind path-problem` global taint query, id `py/augur/fides/pass3-ssrf` |

Pass key is uniformly `"ssrf"` across all four libraries and the query (no
`command_injection` or other pass-key residue). Labels were used **verbatim**;
no signature was added, broadened or narrowed beyond the reviewed entries.

## 0. Review-gate status

`iris/labels/review_decision.json` does **not exist** — the Phase 1 checkpoint was
advisory and no machine/human decision file was written. The operator's explicit
instruction to execute Phase 2 Step 4–5 is recorded here as the interactive
approval to proceed. No label was modified during rendering; the one discrepancy
found between a label rationale and the code (src-026, §5) is reported for
re-review instead of being silently absorbed into the model.

## 1. Label-ID ↔ QLL predicate mapping

### MySources (`isSource(node, passKey)`), 26 entries

| label IDs | rendered predicate | node binding |
| --- | --- | --- |
| src-005/009/010/017/018/024/025/033/037/039/079–087 (19 × `ConnectionConfig.secrets`, flow_kind `field`) | `ConnectionSecretsReadSource` | `Attribute` named `secrets`, site-pinned by module base name + line, node = attribute read value (`asExpr() = a`) |
| src-016, src-078 (2 × `ConnectionConfig.get_saas_config`, flow_kind `return`) | `GetSaasConfigCallSource` | `Call` with `getFunc()` = Attribute `get_saas_config` at saas_connector.py:55 / oauth2_base.py:65, node = call value |
| src-048/049/050/052/054 (5 × `MessagingConfig.details`, flow_kind `field`) | `MessagingDetailsReadSource` | `Attribute` named `details` at message_dispatch_service.py:463/467/472/493/513, node = attribute read value |

Excluded by review (role `none`, 113 rows): CLI/env/toml operator configuration
(`config.cli.server_url`, `--org-url` options, 40 rows), request-header reads used
for logging/audit/locale/content-type (12 rows), credential reads into
headers/payloads/auth tuples (OAuth strategies, messaging secrets, 17 + 18 rows),
DB-protocol connector secrets (26 rows), and the remaining internal reads.

### MySinks (`isSink(node, passKey)` ≡ `controlScope(node, passKey, _)`), 30 entries

| labels | rendered predicate(s) | argument position |
| --- | --- | --- |
| snk-026 `requests.post` http_connector.py:48 | `httpsWebhookPostUrlSink` | `url=` keyword value (labeled arg index 0) |
| snk-011, snk-021/022/023, snk-034 `requests.Session.send` / `httpx.Client.send` | `sessionSendRequestSink` | positional arg 0 |
| snk-016, snk-018/019/025/027/028/042/043, snk-037/039/040/041 `AuthenticatedClient.send` | `clientSendRequestSink` | positional arg 0 |
| snk-020 `httpx.post` fides_client.py:59 | `httpxPostUrlSink` | positional arg 0 |
| snk-035/036 `httpx.AsyncClient.get` request_service.py:108/113 | `asyncClientGetUrlSink` | positional arg 0 |
| snk-013/014/017 bare `post(...)` (requests import) | `barePostUrlKeywordSink` | `url=` keyword value |
| snk-015/038 `AuthenticatedClient(...)` | `authenticatedClientCtorUriSink` | positional arg 0 (base URI) |
| snk-024 `FidesClient(...)` fides_connector.py:58 | `fidesClientCtorUriSink` | `uri=` keyword value (parameter index 0; Phase 1 deviation: CSV arg_index −1 → 0) |
| snk-030/031/032 `requests.get/post` mailgun | `mailgunUrlSink` | positional arg 0 |

Control-scope taxonomy (exposed via `MySinks::controlScope`, used by the query's
`ssrfMessage` so the four scopes are never conflated):

| scope | labels | meaning |
| --- | --- | --- |
| `full-url` | snk-026 | entire request URL (scheme/host/port/path) boundary-controlled |
| `scheme+host` | snk-013/014/015/020/021/022/023/024/034/035/036/038 (12) | base URI / host boundary-controlled, path fixed or separately derived |
| `host+path` | snk-011/016/018/019/025/027/028/037/039/040/041/042/043 (13) | host (saas config + secrets) and path (config/secrets placeholders) both boundary-controlled |
| `path` | snk-017/030/031/032 (4) | host pinned to a fixed literal; only path segments boundary-controlled |

Excluded by review (role `none`, 20 rows): core/api.py:28-130, core/user.py:34-112,
cli/utils.py:106/115 (operator CLI-config URLs), message_dispatch_service.py:418
and adobe_campaign.py:74 (fixed-literal URLs), okta.py:58 (SDK-internal I/O on an
operator `--org-url` value).

### MySanitizers / MySummaries

`isBarrier` → `none()`; `isAdditionalTaintStep` → `none()` (rationale in §4/§5 and
in the file headers). The query's `Pass3Config` still defines both hooks, as the
Augur workflow requires an (empty) barrier hook in every config.

## 2. Source trust boundaries and propagation basis

All 26 sources sit on the same two web boundaries, both **privilege-gated**
(classification `candidate`, not `tp`, in the reviewed labels):

1. **Connection secrets / SaaS config boundary** — the `unvalidated_secrets`
   request body of `PUT /api/v1/connection/{key}/secrets`
   (connection_endpoints.py:199-231, OAuth client scope
   `CONNECTION_CREATE_OR_UPDATE`; `verify=True` by default immediately calls
   `connection_status → test_connection`, which performs the outbound request),
   and `PUT /api/v1/connection/{key}/saas_config` (client_config protocol/host).
   The values persist into `ConnectionConfig.secrets` / `saas_config` DB columns
   and resurface in the connector service layer as the labeled reads. Propagation
   basis (verified in source): http_connector.py:26/43 → `HttpsSchema(**secrets)`
   → `config.url` → requests.post at :48; fides_connector.py:51 →
   `FidesConnectorSchema(**secrets)` → `FidesClient(uri=config.uri)`;
   saas_connector.py:55/145 → `build_uri()` → `AuthenticatedClient(uri, ...)`;
   oauth2_base.py:65/77/89 → token-request URI/path; the strategy/override reads
   feed URL hosts (friendbuy/heap `domain`), URL paths (yotpo `store_id`) and
   query-param values (api_key/query_param strategies).
2. **Messaging config boundary** — `POST/PUT /api/v1/messaging/*` and
   `POST MESSAGING_TEST` (messaging_endpoints.py:88/260/296/317/463, scope
   `MESSAGING_CREATE_OR_UPDATE`) → `MessagingConfig.details` → mailgun URL path
   segments (`details[IS_EU_DOMAIN]` host choice, `details[DOMAIN]`,
   `details[API_VERSION]`).

No internal network-wrapper parameter was promoted to a source: the 40
CLI/env/config boundary rows (S1) and 12 request-header rows (S2) were reviewed
as `none` and are not rendered. Data-subject identity values that shape SaaS
request *paths* (saas_query_config.py:393-396) and second-order pagination URLs
(pagination_strategy_link.py) were noted in Phase 1 coverage notes but never
labeled as sources, so they are not sources here either — a documented recall
gap, not a silent model change.

## 3. Sinks: real network APIs, argument positions, call sites

Every rendered sink is either a real network-egress call or a wrapper with
verified code evidence of passing the URL to actual network I/O:

- `requests.post` (http_connector.py:48) — url keyword; the webhook egress.
- `requests.Session.send` (authenticated_client.py:207) — arg 0, the
  PreparedRequest whose URL is built at :63-69 as `f"{self.uri}{path}"`; the
  transport of every SaaS request.
- `httpx.Client.send` (fides_client.py:125/227/271, request_runner_service.py:679)
  and `httpx.post` (fides_client.py:59) — arg 0 / arg 0; Fides-to-Fides transport
  on `FidesConnectorSchema.uri`.
- `httpx.AsyncClient.get` (request_service.py:108/113) — arg 0; polling URL built
  from the FidesClient `server_url` base.
- `AuthenticatedClient.send` wrapper invocations (saas_connector.py:137/287/436/539,
  oauth2_base.py:92, seven override functions) — arg 0 (SaaSRequestParams); each
  wrapper call verifiably reaches `AuthenticatedClient.send` →
  `self.session.send(prepared_request)` with the config-derived URL.
- Bare `post(...)` (from `requests`) in the override auth strategies — url
  keyword; direct network egress with the secrets-derived host.
- Constructor surrogates (`AuthenticatedClient(...)` arg 0 ×2, `FidesClient(...)`
  `uri=` keyword) — no I/O themselves, but the labeled rationale and code
  (authenticated_client.py:44-46/63-69; fides_client.py:44-46/59/91-98) show the
  URI argument becomes `self.uri` and is interpolated into every outbound URL;
  kept as sinks per the reviewed candidate labels to catch field-mediated flow.
- Mailgun `requests.get/post` (message_dispatch_service.py:471/492/512) — arg 0;
  real egress with a pinned host and config-derived path (scope `path`).

Line/argument coordinates come from the CodeQL extraction recorded in labels.json,
so site pinning (module base name + line) matches this database by construction.

## 4. Sanitizer handling (scheme / fixed targets / redirects / private IP)

No effective sanitizer exists in this codebase for the rendered flows, and none
is modeled:

- `HttpsSchema.url` / `FidesConnectorSchema.uri` are plain `str` fields with no
  URL validation (connections_secrets_https.py:14).
- No scheme allow-list, host whitelist, private-IP/`ipaddress` check or redirect
  control exists on any outbound path (grep over `src/fides`; the only
  allow-list hits are CORS-origin and config-key settings). The SaaS
  `requests.Session` follows redirects with default settings.
- OAuth client scopes on the config endpoints are authentication gates, not URL
  sanitizers — deliberately not modeled as barriers (also unsound: a barrier
  would suppress flows whose input did pass the gate).
- Fixed-target fetches were reviewed as `none` and excluded rather than
  "sanitized": CLI-config URLs (core/api, core/user, cli/utils), fixed literals
  (mandrillapp, adobelogin), the okta SDK, and the pinned-host mailgun/yotpo
  fetches (the latter two kept as `path`-scope sinks, clearly downgraded in the
  alert message).

## 5. Summary / custom propagation edges: source-code basis

`MySummaries::isAdditionalTaintStep` resolves to `none()`. The only
summary-shaped label, **src-026** (connector_registry_service.py:439,
`secrets=connection_config.secrets` in `SaasConnectionTemplateValues(...)`), was
re-verified against the current source during rendering and does **not** support
an edge:

- In `update_saas_instance` (connector_registry_service.py:424-449) the
  constructed `template_vals` is only consumed by
  `upsert_dataset_config_from_template`, which reads `template_values.instance_key`
  only (connector_registry_service.py:351-374); the new SaaSConfig is built from
  the registry template, not from the old secrets.
- The `template_values.secrets` that is consumed belongs to a different object in
  `instantiate_connection` (saas_config_endpoints.py:336-338) and originates from
  the template-instantiation request body, not from the line-439 read.
- The direct keyword passing at line 439 is already ordinary data flow.

**Action requested (re-review, not silently modeled):** label src-026's rationale
("propagates secrets into the new SaaSConfig") does not match the code; it should
be re-reviewed and likely re-classified. Separately, the following
field-mediated gaps were observed while rendering and are candidates for
*explicitly reviewed* summary labels if the reviewer wants those flows connected
— none were added here:

1. pydantic BaseModel mediation: `HttpsSchema(**secrets)` → `config.url`
   (http_connector.py:43→48) and `FidesConnectorSchema(**secrets)` →
   `config.uri` (fides_connector.py:51→58) — taint through the constructor into
   attribute reads is not tracked, so the full-url webhook flow may produce no
   alert even though both endpoints are labeled.
2. `assign_placeholders` / `map_param_values` (fides.api.util.saas_util): the
   regex-substitution `re.sub` internals are unlikely to propagate dict taint to
   the returned string, weakening saas_connector.py:145 → build_uri →
   AuthenticatedClient connectivity.
3. `PreparedRequest.url` writes in the api_key/query_param strategies
   (`request.url = set_query_parameter(...)`) — attribute write on a library
   object, not tracked into the `send` argument.

A diagnostics query (allowed by the workflow, not part of the formal CWE-918
alerts) may be added at execution time under `iris/diagnostics/` to measure local
reachability across these gaps; it was not created in this step.

## 6. Uncovered APIs, dynamic calls, CodeQL limitations

- **Not extracted / not in the DB**: sendgrid and twilio SDK network I/O
  (message_dispatch_service.py:552-575/592-629) happens inside the installed
  packages, which are not part of this CodeQL database (DB covers `src/fides`
  only); only template/mail payload data is config-derived there, not URLs.
- **okta SDK**: orgUrl network I/O inside the okta package; the call site was
  reviewed as `none` (operator `--org-url` origin) anyway.
- **Async hand-off**: privacy requests are created via the API and executed in a
  worker process with data passed through a Redis cache
  (`privacy_request.cache_identity`, `get_cached_identity_data`). Source (config
  bodies) and sinks (connector execution) live in different processes/stacks;
  realistic end-to-end paths for identity-shaped request paths would need
  cache/queue summary modeling, which no reviewed label provides.
- **Dynamic dispatch**: `SaaSRequestOverrideFactory.get_override(name, ...)` maps
  registered override names to functions dynamically; the seven override
  `client.send` sinks are anchored at their concrete definitions/call sites, so
  the factory dispatch itself is invisible (acceptable — the sinks are inside the
  override bodies).
- **fideslog analytics** (`fides/cli/utils.py` `client.send(event)`) — telemetry
  HTTP inside the fideslog SDK, out of DB; reviewed as none regardless.
- **Container reads**: `d[k]` subscript propagation from a tainted dict is
  modeled by the standard taint library (`subscriptStep`), so the
  `MessagingConfig.details[...]` reads stay connected.
- **urllib**: `urllib.request.urlopen`/`urlretrieve` are not used anywhere in
  `src/fides` (parse-only urllib); urljoin/urlparse were never treated as sinks.

## 7. Reproducibility and independent-evaluation principles

Same principles as the prior CWE-78 experiment:

- **Deterministic rendering**: every predicate is generated 1:1 from
  `labels.json` entries (label IDs cited in each QLL header); site pinning uses
  the CodeQL-extracted coordinates; no hand-tuned heuristics beyond the labels.
- **No ground truth**: PyVul truth, fix commits and CVE descriptions were not
  consulted; pre-existing root-level analysis artifacts in the source tree were
  not read; only the fides sources, the extraction CSVs, labels.json and the
  Augur references/templates were used.
- **No source/DB modification**: project sources, the CodeQL database, the
  extraction CSVs and the Augur tool files are untouched; all outputs live under
  `iris/libraries`, `iris/queries`, `iris/report`.
- **Verifiable toolchain**: CodeQL CLI 2.25.1 (`E:\codeql`); `iris/qlpack.yml`
  pins `codeql/python-all: 7.2.7` (not yet in the local pack cache — `codeql
  pack install` from `iris/` will resolve it before the first run). The QL APIs
  used (`DataFlow::ConfigSig`, `TaintTracking::Global`, `PathGraph`/`flowPath`,
  `DataFlow::Node.asExpr()`, `Call.getFunc/getArg/getPositionalArg/getAKeyword`,
  `Attribute.getName`, `Keyword.getArg/getValue`,
  `Scope.getEnclosingModule().getFile().getBaseName()`) were verified against the
  locally cached `codeql/python-all 7.1.2` + `codeql/dataflow 2.1.7` libraries,
  and the layout/idiom mirrors the previously executed calibre-web pass-3 query.
- **Execution contract (Step 5, not yet run)**: one sequential
  `codeql database analyze <db> queries/Pass3_SSRF.ql --format=sarifv2.1.0
  --output=results/pass3.sarif` run per the workflow's no-parallel rule, results
  logged to `iris/results/run_log.md`, then the Phase 2 Step 6 filter report.

Query metadata as required: `@kind path-problem`, `@problem.severity error`,
`@tags security` + `external/cwe/cwe-918` (plus cwe-099/cwe-610 from the pass
definition), id `py/augur/fides/pass3-ssrf`; the query imports
`libraries.MySources/MySinks/MySanitizers/MySummaries` (dot syntax from the
`iris` qlpack root) and delegates to `MySources::isSource`, `MySinks::isSink`,
`MySanitizers::isBarrier`, `MySummaries::isAdditionalTaintStep` — matching the
generated interfaces exactly.
