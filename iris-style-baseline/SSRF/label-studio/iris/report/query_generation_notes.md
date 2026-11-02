# Pass 3 (CWE-918 SSRF) Query Generation Notes — label-studio

- **Run**: `label-studio-pass3-ssrf-20261020`, Augur Phase 2, Step 4–5.
- **Inputs**: `iris/labels/labels.json` (pass 3, 294 entries: 143 source, 9 sink, 2 sanitizer, 140 none; reviewed 2026-10-20) + the DB source snapshot behind the Phase 1 labels.
- **Outputs**: `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass3_SSRF.ql`.
- **Toolchain**: CodeQL CLI 2.25.1 (E:\codeql), `codeql/python-all` 7.1.2 (cached pack), qlpack `iris/label-studio-cwe918` at the iris root. Pass key: `"ssrf"` everywhere. Query id: `py/augur/label-studio/pass3-ssrf`.
- **Review gate**: `labels/review_decision.json` does not exist in this experiment tree. Per WORKFLOW §4.5 (automated mode), the Phase 1 review summary `labels/phase1_review.md` is treated as the review record and the run self-approves; no label was modified during generation. All deviations from the labels recorded below are *query-generation decisions* documented here, not label changes.

## 1. Label ID → QLL predicate mapping

### MySources.qll (`isSource(node, "ssrf")`)

| Label family (ids) | Count | Predicate | Matching shape |
| --- | --- | --- | --- |
| request_field — `request.data/GET/POST/FILES/META/body/query_params` incl. `self.request.<field>` (p3-src-001…283 subset; tp: p3-src-251 uploader.py:239, p3-src-031/032 data_import/api.py:280/282, p3-src-064/065 io_storages/api.py:142/150) | 128 | `requestFieldRead` | `Attribute` whose object is `request` (Name) or `self.request` (Attribute) and whose name is one of the 7 reviewed fields, within the Phase 1 extraction scope (`label_studio/%` minus tests/`tests.py`/migrations/examples) |
| webhook_field (p3-src-258 `webhook.url`, p3-src-259 `webhook.headers`) | 2 | `webhookFieldRead` | `webhook.url`/`webhook.headers` reads pinned to webhooks/utils.py:53/54 |
| ml_self_url (p3-src-218/219/220/221) | 4 | `mlBackendUrlRead` | `self.url` pinned to ml/models.py:115/118/122/325 (the :97 `__str__` read stays excluded — reviewed role=none) |
| s3_endpoint (p3-src-214/215) | 2 | `s3EndpointRead` | `self.s3_endpoint` pinned to io_storages/s3/models.py:66/186 (the :57 cache-key read stays excluded) |
| redis_field (p3-src-222…227) | 6 | `redisFieldRead` | `self.host/.port/.password` pinned to io_storages/redis/models.py:64–69 (candidate labels; kept because the fields are reviewed sources — see §5 for the deferred sink) |
| ml_validate_url_param (p3-src-235) | 1 | `mlValidateUrlParam` | `value` parameter of `MLBackendSerializer.validate_url` (ml/serializers.py:10) via `DataFlow::parameterNode` |

Coverage: all 143 source-role entries. The 140 `none`/fp entries (137 `get_env`/`os.environ`/`os.getenv` + 4 `sys.argv` + internal-wrapper reads p3-src-246/213/217) are not modeled, exactly as reviewed.

### MySinks.qll (`isSink(node, "ssrf")` + `getSinkAlertMessage(node, "ssrf")`)

| Label id | Site | Modeled sink node | Controllability scope (embedded in the alert message) |
| --- | --- | --- | --- |
| p3-snk-005 | core/utils/io.py:224 `requests.get` | `exprNode(call.getArg(0))` — positional URL argument | full URL (scheme limited to http/https), authenticated `projects_change` user |
| p3-snk-007 | webhooks/utils.py:52 `requests.post` | `exprNode(call.getArg(0))` — positional URL argument | full URL, any authenticated organization member; headers also attacker-set |
| p3-snk-002 | ml/api_connector.py:81 `self.http.request` | `exprNode(call.getKwargs())` — the `**kwargs` forwarding argument of the pinned transport call | full URL = `MLBackend.url` + fixed suffix, `projects_change` |
| p3-snk-008 | io_storages/s3/utils.py:38 `session.client('s3', …, **settings)` | `exprNode(call.getKwargs())` — the `**settings` argument | full endpoint URL (botocore HTTP), `projects_change` or operator env |
| p3-snk-009 | io_storages/s3/utils.py:39 `session.resource('s3', …, **settings)` | `exprNode(call.getKwargs())` — the `**settings` argument | same as p3-snk-008 |

Not modeled, with reasons (no label modified):
- **p3-snk-006** redis.StrictRedis (io_storages/redis/models.py:56) — reviewed `candidate`: non-HTTP Redis protocol connection; the formal CWE-918 query models HTTP request URL arguments / endpoint URLs only, and phase1_review.md §5.1 explicitly left the non-HTTP scope decision to human review. Gap recorded in §5; `redisFieldRead` sources remain modeled so the flow activates if the sink is approved.
- **p3-snk-001 / 003 / 004** (windows_sqlite_fix:28, common.py:376, contextlog.py:312) — reviewed `fp`: operator env-configured sqlite.org download, hardcoded pypi.org endpoint, fixed tele.labelstud.io telemetry. Fixed destinations; excluded from the model rather than relying on Phase 6 filtering.

### MySanitizers.qll (`isBarrier(node, "ssrf")`)

| Label id | Guard | Barrier nodes |
| --- | --- | --- |
| p3-supp-001 | `validate_upload_url` (core/utils/io.py:172) | argument 0 of its two call sites: io.py:221 (inside `ssrf_safe_get`, `block_local_urls=settings.SSRF_PROTECTION_ENABLED`) and ml/serializers.py:11 (`MLBackendSerializer.validate_url`, `block_local_urls=settings.ML_BLOCK_LOCAL_IP`) |
| p3-supp-002 | `validate_ip` (io.py:199) | **no barrier node** — its argument is the DNS-resolved IP string, which never lies on a URL data-flow path; modeling it would be an unevidenced barrier |

### MySummaries.qll (`isAdditionalTaintStep(from, to, "ssrf")`)

| Edge | From → To | Source-code basis |
| --- | --- | --- |
| `requestPayloadAccessStep` | `request.<field>` node → result of `.get(k)`/`.getlist(k)` on that exact attribute, and → `request.<field>['k']` subscript | uploader.py:239 `request.data.get('url')`; data_import/api.py:282; ml/api.py:77 `self.request.query_params.get('project')`; data_import/api.py:639 `request.GET['filepath']` |
| `mlBackendUrlStep` | `url` parameter of `BaseHTTPAPI.__init__` (api_connector.py:41) → argument 0 of the `urllib.parse.urljoin` call (api_connector.py:129) | api_connector.py:42 `self._url = url` store; :126 `url = self._url` load; :127–128 `url += '/'`; :129 join (cross-method attribute store/load is not a default flow step) |
| `urlJoinStep` | argument 0 of any `urljoin(...)` call → call result | api_connector.py:129 (stdlib `urllib.parse` is not in this DB, so the join would otherwise drop taint); only arg 0 (base URL) is modeled — the reviewed suffixes are fixed strings |
| `s3EndpointKwargsStep` | `s3_endpoint` parameter of `get_client_and_resource` (s3/utils.py:17) → the `**settings` argument of the pinned client/resource calls (s3/utils.py:38/39) | s3/utils.py:35–37 (`s3_endpoint or get_env(...)`, `settings['endpoint_url'] = s3_endpoint`) and :38–39 (`session.client/resource('s3', …, **settings)`); container-element store + `**` unpacking is not a default flow step |
| `ssrfSafeGetBridge` | argument 0 of any `ssrf_safe_get(...)` call (callee by Name) → the `url` parameter of `ssrf_safe_get` (io.py:220) | uploader.py:15 `from core.utils.io import ssrf_safe_get` + :131–133 call; the bare-prefix import does not resolve in this DB (§5.9) |
| `mlApiConstructorBridge` | the `url` keyword value of any `MLApi(...)` constructor call → the `url` parameter of `BaseHTTPAPI.__init__` (api_connector.py:41) | ml/models.py:12 bare import of MLApi + :101/109/122 constructor calls; MLApi.__init__(**kwargs) → `super().__init__(**kwargs)` (api_connector.py:121–122); keyword binding through that chain is not tracked (probe-verified) |
| `mlKwargsForwardBridge` | the `url` keyword value of `self.post`/`self.get` calls (api_connector.py:141/143) → the `**kwargs` argument of the pinned transport call (api_connector.py:81) | api_connector.py:83–87 (post/get forward `*args, **kwargs` to `self.request`), :79–81 (`self.http.request(method, *args, **kwargs)`); keyword→`**kwargs`→`**kwargs` forwarding is not tracked (probe-verified) |
| `s3ClientBridge` | argument 4 of any `get_client_and_resource(...)` call (callee by Name) → the `s3_endpoint` parameter (s3/utils.py:17) | io_storages/s3/models.py:22 bare import + :61–67 positional call; the bare-prefix import does not resolve in this DB (§5.9) |

The query config delegates with the literal pass key `"ssrf"` to all four modules, per the Augur template; the select message is `MySinks::getSinkAlertMessage`.

## 1a. Empirical flow verification (diagnostics, not formal alerts)

Per the instructions, diagnostics queries under `iris/diagnostics/` were run (via `codeql query run`, not `database analyze`) to verify that the reviewed flows actually connect through the generated model before the Step 5 analysis run. Final result (`diagnostics/pass3_diag.csv`, 10 flows, all four reviewed flow families):

| Source (file:line) | Sink (file:line) | Flow |
| --- | --- | --- |
| data_import/uploader.py:239 `request.data` | core/utils/io.py:224 `requests.get` arg 0 | import-by-URL (sync) |
| webhooks/utils.py:53 `webhook.url` | webhooks/utils.py:52 `requests.post` arg 0 | webhook delivery (trivial source=sink path, admitted by `flowPath`) |
| ml/models.py:115 / :118 / :122 / :325 `self.url` | ml/api_connector.py:81 `**kwargs` of the transport | ML backend (healthcheck / setup / `api` property / get_versions) |
| io_storages/s3/models.py:66 and :186 `self.s3_endpoint` | io_storages/s3/utils.py:38 and :39 `**settings` | S3 endpoint (client and resource construction) |

Diagnostics files retained for reproducibility: `Pass3_FlowDiagnostics.ql` (the summary above), `Pass3_FlowCheckpoints.ql` (per-hop checkpoints), `Pass3_DispatchProbes*.ql` (isolated one-hop probes that localized each dispatch gap), `Pass3_ModuleTable.ql` (module-table inspection). These results are diagnostics only and are **not** counted as CWE-918 findings; formal alerts come from the Step 5 analysis run (not executed in this step).

## 2. Source trust boundaries

Every modeled source requires authentication; there is **no unauthenticated source** in this application:

- `request_field`: any DRF-authenticated user who can reach the view. The three URL-carrying endpoints (`POST /api/projects/{pk}/import` sync+async, `/api/storages/*validate`) additionally require **`projects_change`** (project collaborator, not admin). Per the reviewed labels, authentication limits attacker *identity*, not URL *value* control — it is not treated as a sanitizer.
- `webhook.url`/`webhook.headers`: writable by **any authenticated organization member** (`WebhookListAPI` permission `IsAuthenticated`) via `/api/webhooks`; DB-mediated (written by one request, delivered by a later event).
- `MLBackendSerializer.validate_url.value` / `MLBackend.self.url`: the ML backend URL, `projects_change` via `/api/ml`.
- `S3Storage.self.s3_endpoint`: the storage endpoint, `projects_change` via `/api/storages/s3` (serializers use `fields='__all__'`).
- Propagation basis for each family is the flow evidence recorded in the labels (e.g. p3-src-251 evidence chain `request.data['url'] → tasks_from_url → ssrf_safe_get → requests.get`), which the summary edges in §1 translate into data-flow steps.

Internal wrapper parameters (`tasks_from_url.url` at uploader.py:125, the `__str__`/cache-key-only field reads) were reviewed `none` and are **not** sources; no source was invented to connect a path.

## 3. Sink verification (API, argument position, call location)

| Sink | Real network I/O | Dangerous position | Call site |
| --- | --- | --- | --- |
| `requests.get` | requests (external lib; anchored at app call site) | positional arg 0 = URL | core/utils/io.py:224, inside `ssrf_safe_get` — the import-by-URL fetch (`request.data['url']` → `tasks_from_url` → `ssrf_safe_get`) |
| `requests.post` | requests | positional arg 0 = URL | webhooks/utils.py:52 `run_webhook_sync` — `requests.post(webhook.url, headers=webhook.headers, …)` |
| `requests.Session.request` | requests | URL is keyword `url=` forwarded via `**kwargs` (labels already recorded this as the modeling gap; `Call.getArg` cannot see keyword/double-star positions) | ml/api_connector.py:81 `self.http.request(method, *args, **kwargs)` — the single transport for all ML backend traffic |
| `boto3.Session.client` / `.resource` | botocore HTTP stack (external lib) | `endpoint_url` arrives via `**settings` | io_storages/s3/utils.py:38/39 |

Sink nodes for the kwargs-shaped sites are the `**kwargs`/`**settings` forwarding arguments (`Call.getKwargs()`), i.e. the exact expression through which the reviewed URL value reaches the transport. All five sites are pinned by relative path + line + callee shape, so no other `requests.get`/`post`/boto3 call in the tree can match (the fixed-destination calls at common.py:376 / contextlog.py:312 / windows_sqlite_fix:28 are not matched).

## 4. Scheme, fixed destinations, redirects, private addresses, sanitizers

- **URL scheme**: `validate_upload_url` (io.py:182–185) rejects non-`http`/`https` schemes *unconditionally* on both reviewed flows (import URL and ML backend URL). Consequence for CWE-918: `file:`/`data:` cross-protocol targets are blocked — the modeled sinks therefore carry "scheme restricted to http/https" in their scope strings, and no cross-protocol (CWE-099-style) flow is expected to fire. Webhook delivery has **no** scheme check beyond the URLField syntax validation at input; `requests` itself only speaks http/https, so effective scheme control there is also http/https, but host/port/path are fully attacker-chosen.
- **Fixed destinations**: the three reviewed fp sinks (sqlite.org dll download from `WINDOWS_SQLITE_BINARY_HOST_PREFIX` env, hardcoded pypi.org version check, fixed tele.labelstud.io telemetry) are excluded from the model per the SSRF admin/env-config FP heuristic. Telemetry *payload* content is attacker-influenced but the destination is a literal — recorded, not modeled.
- **Redirects**: no custom redirect control exists in the application code. `ssrf_safe_get` performs a post-connection peer-IP re-check (io.py:227–229) that would catch redirect/DNS-rebinding targets, but only when `SSRF_PROTECTION_ENABLED` is true (default false); requests' default `allow_redirects=True` for GET means a redirect to an internal host is otherwise followed unchecked. No sanitizer is modeled for redirects.
- **Private addresses**: `validate_ip` covers `0.0.0.0`, `127/8`, `10/8`, `172.16/12`, `192.168/16` only, and is gated by `SSRF_PROTECTION_ENABLED` (default **False**, core/settings/base.py:405) / `ML_BLOCK_LOCAL_IP` (default **False**, base.py:601). Gaps even when enabled: IPv6 loopback/ULA, IPv6-mapped IPv4, link-local 169.254.169.254 (cloud metadata), CGNAT 100.64/10; separate DNS resolution creates a TOCTOU window.
- **Effective sanitizer handling**: the barrier is modeled only as the checked URL argument node at the two `validate_upload_url` call sites (label p3-supp-001). Placement note (same convention as the prior SSRF runs): the downstream fetch uses a different AST node for the same variable, so the barrier *marks* the guard without pruning the fetch path — intentional, because with both gating settings default-off the private-IP component is not an effective neutralization and must not suppress the reviewed default-configuration flows. The scheme component is genuinely always-on but raises rather than rewrites, so it is a rejection guard, not a rewrite barrier. Authentication, URLField syntax checks and permission decorators are deliberately **not** barriers (reviewed as identity/format controls, not URL neutralization).

## 5. Uncovered APIs, dynamic calls, and CodeQL limitations

1. **Redis (p3-snk-006, p3-src-222…227)**: non-HTTP Redis protocol connection to API-supplied host/port — sink deliberately deferred to human review (§MySinks); sources are modeled. If approved, the sink needs `Call.getKwargs()` matching at io_storages/redis/models.py:56 plus an edge from the `redis_config` dict construction (models.py:63–70).
2. **DRF serializer mediation** (StorageValidateAPI `request.data` → serializer → model instance → `validate_connection()`): DRF internals are outside this database, so the `request.data` → `s3_endpoint`/`redis_config` link across `serializer.validated_data` is invisible to taint tracking. The reviewed field-read sources (`self.s3_endpoint` etc.) keep the flow observable from the field onward. A summary edge through the serializer was considered and rejected — no in-database code evidence to pin it to.
3. **Keyword/`**kwargs` argument positions**: `Call.getArg(int)` cannot see keyword or double-star arguments; `Function.getArgByName` casts parameters to `Name` and therefore cannot bind `*args`/`**kwargs` parameters at all (probe-verified). The ML and boto3 sinks anchor on `Call.getKwargs()` forwarding nodes, and the keyword-argument forwarding into/through `**kwargs` is bridged by the pinned evidence-based edges `mlApiConstructorBridge` / `mlKwargsForwardBridge` / `s3EndpointKwargsStep` (§1) — the default `codeql/python-all` dispatch does **not** carry keyword values through the element/container transitions in these shapes (probe-verified, see `diagnostics/Pass3_DispatchProbes2/5/6.ql`). `session.request`'s label arg index 1 is recorded in the sink message, not used for matching.
4. **Cross-method attribute store/load** (`self._url = url` → `url = self._url`) and **container-element store + `**` unpacking** (`settings['endpoint_url'] = …` → `**settings`) are not default flow steps; both are bridged by the pinned evidence-based edges `mlBackendUrlStep` / `s3EndpointKwargsStep` (§1). No equivalent bridging was added anywhere else — in particular **no** edge was added from the `ProjectImport.url` model attribute (async import writes `project_import.url = url`, a DB write) — the async-import path is DB-mediated and its source side (p3-src-031/032) will only connect if Phase 2 triage accepts DB-mediation modeling.
5. **Dynamic dispatch**: `getattr`-style indirection is not used on any reviewed sink path; `MLApi._request`'s `self.post/self.get` and `BaseHTTPAPI.request` resolve in-database. `rest_framework`, `requests`, `boto3`, `redis`, `urllib.parse` are external — their internals are unreachable, which is why sources/sinks anchor on application-level call sites and the accessor/urljoin edges exist.
6. **Trivial source=sink path**: `webhook.url` (source, webhooks/utils.py:53) is itself argument 0 of the `requests.post` (sink, :52). The shared dataflow library explicitly admits `flowsource = flowsink` in `flowPath`, so the webhook flow is reported as a zero-step path; if a future CodeQL version changed that, the webhook alert would need a `webhook`-parameter-level source (currently forbidden by the no-internal-wrapper-source rule).
7. **Barrier semantics**: the installed new-dataflow `ConfigSig` has no `isBarrierGuard` concept, so guard-effectiveness cannot be modeled branch-sensitively (see §4).
8. **Deleted Phase 1 scratch**: line numbers refer to the DB source snapshot (`label-studio-db/src.zip`, sha f8b2fb8); the on-disk `label_studio/` tree in the source root is a different variant (see labels metadata notes and phase1_review.md §6). Location pinning uses `File.getRelativePath()`, which the Phase 1 extraction already validated against this database.
9. **Bare-prefix app-internal imports do not resolve** (empirically decisive for this DB): the module table only contains `label_studio.*`-prefixed module names (verified by `diagnostics/Pass3_ModuleTable.ql`: `label_studio.core.utils.io` and `label_studio.ml.api_connector` exist; `core.utils.io`, `ml.api_connector`, `io_storages.s3.utils` do not), because the DB source root is the repository root and `label_studio/` is the top-level package. The application's runtime import style mixes bare prefixes (`from core.utils.io import ssrf_safe_get`, `from ml.api_connector import MLApi`, `from io_storages.s3.utils import get_client_and_resource`) with `label_studio.`-prefixed forms (e.g. `from label_studio.io_storages.s3.utils import AWS`, which is why the `AWS.get_blob_metadata` path dispatches natively). Calls made through the bare-prefix imports are therefore unresolved and their arguments do not flow into the callee parameters; the four wrapper bridges `ssrfSafeGetBridge`, `mlApiConstructorBridge`, `s3ClientBridge` (import resolution) and `mlKwargsForwardBridge` (keyword/`**kwargs` forwarding) restore exactly the reviewed, source-evidenced dispatches. Every bridge is pinned to a callee defined at a specific reviewed location plus a concrete argument/keyword position — no generic "any unresolved call" propagation.

## 6. Reproducibility and independent evaluation principles

Same principles as the earlier CWE-78 / SSRF experiment runs:

- **Deterministic generation**: every predicate is rendered from the reviewed labels (grouped by family, signature-pinned by relative path + line + callee shape); no free-form API matching beyond the reviewed families; `matches()` patterns are string literals only.
- **No ground truth consulted**: PyVul truth data, fix commits, CVE descriptions and the pre-existing `ssrf_*.md` / `ssrf_sinks.csv` artifacts in the source root were never read; the model is derived exclusively from `labels.json` + the DB source snapshot.
- **No source/DB/label modification**: the project source, CodeQL database, extraction CSVs and Phase 1 labels are untouched; all deviations are recorded here (§1, §5) rather than silently applied.
- **Audit trail**: `labels/labels_raw_pass3.json` preserves the raw candidates and verified source lines the labels were derived from; each QLL header documents its label-id mapping; `label_stats.md` / `phase1_review.md` document the review state.
- **Compile-before-analyze**: the generated query compiles against the local toolchain (CLI 2.25.1, python-all 7.1.2, `--search-path` on the cached packs), verified twice — before and after the bridge additions — per WORKFLOW §3.1.1.
- **Probe-verified model, not just compiled**: all four reviewed flow families were verified to connect end-to-end via the diagnostics queries (§1a) before the formal analysis run; every custom propagation edge in `MySummaries.qll` exists only because an isolated probe demonstrated that the default library does not carry that hop in this database (and real source code does).
- **Formal analysis intentionally not run**: the `codeql database analyze` pass (Step 5 execution, SARIF results, filtering and the iris report) is **not** executed in this step per instruction and remains the next action, to be run sequentially per WORKFLOW §5.2.4 (`codeql pack install` should be run first, or `--search-path C:/Users/lzh/.codeql/packages` passed as done for the compile/diagnostics runs).
