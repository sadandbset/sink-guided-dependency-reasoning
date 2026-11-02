# Query Generation Notes — mlflow Pass 3 (CWE-918 SSRF)

- Run: `mlflow-ssrf-pass3-20261020` · generated 2026-10-20 (Augur Phase 2 Step 4)
- Inputs: `labels/labels.json` (303 entries, reviewed in Phase 1; used **unmodified**), `extraction/sources.csv` / `extraction/sinks.csv`, mlflow source at `dataset/codeql_databases/ssrf_dbs/mlflow_vuln/mlflow/` (version 2.9.2.dev0)
- Outputs: `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass3_SSRF.ql`
- No CodeQL execution was performed in this step (generation only), per instruction. `codeql pack install` was already run in Phase 1 Step 0 (qlpack `iris/mlflow-cwe918`, `codeql/python-all: *`).
- Ground truth, fix commits and CVE descriptions were not consulted at any point; all signatures below are provable from the current source tree only.

## 0. Checkpoint status

`labels/review_decision.json` does **not exist** (Phase 1 Step 3 only produced `labels.json`, `labels_raw_pass3.json`, `label_stats.md`, `phase1_review.md`). Per WORKFLOW.md §4.5 the human review gate is advisory; in its absence this generation proceeds in automated mode against the Phase-1 label set as reviewed in `labels/phase1_review.md`, **without modifying any label**. Items flagged for human review in that document (section 6) remain unresolved and are reflected below as candidate/excluded material. If a formal re-review changes any label, the four `.qll` files must be regenerated — not hand-edited.

## 1. Label → predicate mapping

Selection policy: label entries with role `source`/`sink` and classification `tp` or `candidate` are modeled; `fp` and `none` entries are excluded (rationale per family below). Totals: **113 of 251** source candidates modeled, **30 of 52** sink candidates modeled (17 tp + 13 candidate), **0** sanitizer/summary label entries (barrier/steps built from source-code evidence, see §5).

### MySources (113 labels mapped)

| predicate | labels | count |
| --- | --- | --- |
| `flaskRequestFieldSource` | src-82, 83, 88, 137, 138, 139, 141, 144, 145, 147, 149, 150, 186 | 13 (tp) |
| `fastapiRequestJsonSource` | src-38 | 1 (tp) |
| `parserParseSource` | src-84, 89, 187 | 3 (tp) |
| `requestMaterializerSource` | src-85, 93–221 (odd rows: `_get_request_message()`/`_get_request_json()` returns) | 51 (tp) |
| `runArtifactUriSource` | src-90, 91, 130, 131, 132, 151, 152, 156, 180 | 9 (tp) |
| `modelVersionSourceFieldSource` | src-183, 184 | 2 (tp) |
| `repoArtifactUriSource` | src-39, 40, 43–48, 55, 60, 62, 63, 69–76, 223–227, 239, 241–248 | 34 (5 tp http_artifact_repo + 29 candidate cloud/DBFS repos) |

Excluded source labels (138) and why:
- 55 environment reads (`os.getenv`/`os.environ.get`/`MLFLOW_*` getters, none/fp): operator/server-admin configuration, not attacker-controlled at any server boundary.
- 65 route/handler `param` labels (11 tp + 54 candidate, e.g. src-19–29, src-87…220): the labeled Flask view functions and REST handlers in `mlflow/server/handlers.py` / `mlflow/server/__init__.py` take **no parameters** (verified — request content is materialized inside the handler body by `_get_request_message()`, which is modeled as `requestMaterializerSource`); the only parameterized candidates (`_download_artifact`/`_upload_artifact(artifact_path)`) are path-only parameters into the server's own proxied artifact repository root (admin `--artifacts-destination`, guarded by `validate_path_is_safe`) and cannot control an outbound URL host — excluded as URL-irrelevant rather than modeled as sources.
- 5 optional-auth layer request reads (src-30–34, source/fp): consumed only for credential lookup/comparison; no URL propagation.
- 5 CLI labels (src-50–54, source/fp + none/fp): `mlflow run <uri>` etc. are operator-local inputs driving client-side fetches.
- 5 `none` rows: 4 no-input routes (health/version/serve/static-file), 2 internal helper params (src-133, src-155), 1 `HTTPDatasetSource._resolve.raw_source` (unknown).
- 1 local-artifact-repo row (src-237, none/fp): local filesystem only, explicitly excluded from `repoArtifactUriSource`.

### MySinks (30 labels mapped)

| predicate | labels | count |
| --- | --- | --- |
| `gatewayProxyRequestSink` | sink-26 | 1 (tp) |
| `httpArtifactRepoRequestSink` | sink-27–33 | 7 (tp) |
| `multipartPutSink` | sink-34 | 1 (tp) |
| `sessionRequestSink` | sink-38 | 1 (tp) |
| `retriesSink` | sink-39, 42 | 2 (tp) |
| `restUtilsRelaySink` | sink-43–46 | 4 (tp) |
| `cloudStorageHttpSink` | sink-14–17, 22, 35, 36, 37 | 8 (1 tp + 7 candidate) |
| `databricksCallEndpointSink` | sink-13 | 1 (candidate) |
| `databricksModelsEndpointSink` | sink-18 | 1 (candidate) |
| `downloadChunkSink` | sink-21, 23, 24 | 3 (candidate) |
| `unityCatalogCallEndpointSink` | sink-48 | 1 (candidate) |

Excluded sink labels (22): 17 fp (client-side/operator-configured: deployments/gateway/auth clients, `base_rest_store`/`rest_store` client stores, pyfunc scoring-server client, openai parallel processor, aiohttp gateway provider with admin-configured provider base URLs, `mlflow run` zip fetch, dbfs fixed-host calls) and 5 none (ftp/sftp/git — non-HTTP protocols recorded separately in Phase 1, not mixed into the CWE-918 HTTP sink set).

## 2. Source trust boundaries and propagation basis

| boundary | why untrusted | evidence |
| --- | --- | --- |
| Flask request fields (`request.args/json/data/query_string`) | tracking server has **no authentication by default**; routes registered unconditionally | handlers.py:14 (import), 1132–1141 (gateway-proxy args), server/__init__.py:44–106 |
| `parser.parse` / `_get_request_message()` / `_get_request_json()` returns | these functions materialize the raw query string / JSON body into the protobuf request messages consumed by every REST handler | handlers.py:405–470 |
| FastAPI `request.json()` (deployments server) | separate deployments/gateway server request boundary | deployments/server/app.py:104–105 |
| `run.info.artifact_uri` (9 reads) | second-order DB content: the experiment `artifact_location` is client-settable via unauthenticated CreateExperiment (only the query component is validated, handlers.py:592–596) and is inherited by run artifact roots | handlers.py:554–570, 947–963, 1225–1270, 1319 |
| `request_message.source` (2 reads) | attacker-supplied CreateModelVersion source URI; `_validate_source` only rejects local/file sources | handlers.py:1626–1648, 1590–1621 |
| `self.artifact_uri` (34 reads) | second-order DB content on the artifact repository that performs the fetch; for `HttpArtifactRepository` it directly determines the outbound host via `_get_default_host_creds(self.artifact_uri)` | http_artifact_repo.py:39–40, 84, 117, 130, 143; artifact_repository_registry.py:107–117; artifact_repo.py:44–47 |

No internal network-wrapper parameter was turned into a source: the internal helpers (`_list_artifacts_for_proxied_run_artifact_root`, `_get_artifact_repo`, `HTTPDatasetSource._resolve`) carry `none` labels and stay unmodeled; wrapper-to-transport propagation is handled by summary steps (§5), not by sources.

## 3. Sinks: network API, dangerous argument index, call sites

| network API / wrapper | dangerous arg | call sites | control tier |
| --- | --- | --- | --- |
| `requests.request(method, url, …)` | arg 1 (URL; method=0) | handlers.py:1143 | **path-only** — host fixed by admin env `MLFLOW_DEPLOYMENTS_TARGET` (handlers.py:1127); attacker controls the `gateway_path` appended to the base (f-string `f"{target_uri}/{gateway_path}"`) |
| `requests.put(credential.url, …)` | arg 0 (URL) | http_artifact_repo.py:157 | **full URL (response-driven)** — credential parsed from the artifact server's mpu/create JSON response; see §6 (response taint not modeled) |
| `requests.Session.request(method, url, …)` | arg 1 (URL) | request_utils.py:190 | **host control** when the constructed URL's host derives from DB-content URI |
| `http_request(host_creds, endpoint, …)` (mlflow wrapper; URL = `f"{host_creds.host}{endpoint}"`, rest_utils.py:104–105) | arg 0 / `host_creds=` keyword (host-controlling; the label's arg index was corrected from CSV 1→0 in Phase 1) | http_artifact_repo.py:63, 88, 104, 113, 125, 139, 151; rest_utils.py:143 | **host control** via tainted artifact URI |
| `http_request(…, endpoint=…)` | arg 1 / `endpoint=` keyword (path-only position) | databricks_models_artifact_repo.py:79 | **path-only** on fixed Databricks host |
| `_get_http_response_with_retries(method, url, …)` | arg 1 (URL) | request_utils.py:222, rest_utils.py:107 | **host control** (transport relay) |
| `cloud_storage_http_request(method, url, …)` | arg 1 / `url=` keyword | request_utils.py:65 (tp); databricks 366/372/462/530, http_dataset_source.py:70, optimized_s3:159, file_utils.py:668 (candidates) | tp: URL from `download_chunk`'s `http_uri`; candidates: **cross-SDK signed URIs** (response-driven, propagation not provable in this DB) |
| `call_endpoint(host_creds, endpoint, …)` | arg 0 / `host_creds=` keyword | rest_utils.py:230; databricks_artifact_repo.py:144; unity_catalog_models_artifact_repo.py:98 | rest_utils: **host control** (relay); databricks/UC: host fixed to operator profile, DB-content path only |
| `download_chunk(*, http_uri=…)` | keyword `http_uri` (keyword-only; no positional index) | download_cloud_file_chunk.py:32, file_utils.py:760, 799 | candidate — remote/cloud signed URIs |

Control tiers are kept distinct: full-URL (multipart put, response-driven), host-control (artifact-URI chains through the rest-utils stack), path-only-on-fixed-host (gateway proxy, databricks endpoint), and cross-SDK signed-URI candidates. They are **not** treated as equal severity; Step 6 triage should use this table (the `@precision low` rating reflects the mixed tiers and second-order sources).

## 4. Sanitizers / scheme / fixed-target / redirect / private-IP handling

No sanitizer is modeled — the reviewed labels contain zero sanitizer entries and source inspection confirms none of the existing guards neutralizes URL host/scheme control on the modeled chains:

- `validate_path_is_safe` (handlers.py:551, 1239, 1663) — path-traversal guard only.
- `_validate_source` (handlers.py:1590–1621) — rejects local/file model-version sources; http/https remain allowed.
- `validate_query_string` (handlers.py:592) — query component of artifact locations only.
- No scheme allow-list, fixed-host whitelist, redirect following control, or private-IP/DNS-resolved-address blocking exists on the gateway-proxy path or the HttpArtifactRepository fetch chains (confirmed during Phase 1; detection.json `sanitizers_and_guards_observed`).

`MySanitizers::isBarrier` therefore resolves to `none()`; the mandatory `isBarrier` hook in `Pass3Config` stays wired to the library (WORKFLOW.md 5.2.3). Adding a barrier requires a label re-review, not a model edit. The admin-fixed target of the gateway proxy is handled by *not* modeling `MLFLOW_DEPLOYMENTS_TARGET` as a source (admin configuration) — the resulting alerts on sink-26 are path-tier by construction.

## 5. Summary / additional taint steps and their source-code basis

All steps are conditional (structural receiver/argument match, or explicit file scope); none is unconditional:

| step | edge | source-code basis |
| --- | --- | --- |
| `requestAccessorGetStep` | tainted receiver of `.get(...)` → call result | request-parameter parsing: handlers.py:1132–1134 (`args = request.args ... ; gateway_path = args.get("gateway_path")`), 550 (`request_dict.get("run_id")`); scoped to handlers.py |
| `parserParseStep` | tainted arg of `parser.parse(...)` → call result | query-string materialization: handlers.py:420, 547–548, 1657–1659; scoped to handlers.py |
| `artifactUriSplitStep` | tainted receiver of `.split(...)` → call result | URL splitting: http_artifact_repo.py:84 `url, tail = self.artifact_uri.split(endpoint, maxsplit=1)`; scoped to http_artifact_repo.py |
| `hostCredsWrapperStep` | tainted arg of `_get_default_host_creds(...)` → result | `_get_default_host_creds(store_uri)` returns `MlflowHostCreds(host=store_uri, …)` (tracking/_tracking_service/utils.py:141–153); called with artifact URIs at http_artifact_repo.py:40, 85; scoped to http_artifact_repo.py |
| `hostCredsPropertyStep` | `_get_default_host_creds` call node → `self._host_creds` attribute reads | property `_host_creds` returns `_get_default_host_creds(self.artifact_uri)` (http_artifact_repo.py:38–40); consumed as `http_request` arg 0 at :63/:104/:113; scoped to http_artifact_repo.py |
| `artifactRepositoryWrapperStep` | (a) tainted arg of `get_artifact_repository(...)` → result; (b) call result → `self.artifact_uri` reads in `mlflow/store/artifact/*` | resource-loading wrapper: registry `get_artifact_repository(artifact_uri)` constructs the repo with the URI (artifact_repository_registry.py:107–117); `ArtifactRepository.__init__` stores `self.artifact_uri = artifact_uri` (artifact_repo.py:44–47); handlers.py:1269/1319/1672 call sites; step (b) is a structural approximation of object-field flow and never creates taint from untainted call nodes |
| `hostCredsHostFieldStep` | `host_creds` name node → `host_creds.host` attribute read | URL construction inside the wrapper: rest_utils.py:74 `hostname = host_creds.host`, :104–105 `url = f"{cleaned_hostname}{endpoint}"`; scoped to rest_utils.py, field `host`, receiver `host_creds` (the `http_request`/`http_request_safe` parameter) |

Expected end-to-end path shapes (verifiable once Step 5 runs):
1. `request.args`/`request.json` (src-144/src-145) → local flow → `args` → `requestAccessorGetStep` → `gateway_path` → f-string → `requests.request` arg 1 (sink-26).
2. `run.info.artifact_uri` (e.g. src-156 @ handlers.py:1319) → `get_artifact_repository` arg → `artifactRepositoryWrapperStep` → `self.artifact_uri` (http_artifact_repo.py:40) → `hostCredsWrapperStep` → `hostCredsPropertyStep` → `http_request` arg 0 (sink-27…33); continuing via `hostCredsHostFieldStep` through rest_utils into `_get_http_response_with_retries` (sink-39/42) and `session.request` arg 1 (sink-38).
3. `self.artifact_uri` (src-223–227) direct short paths through the same edges.
4. `list_artifacts` variant: `self.artifact_uri` → `artifactUriSplitStep` → `url` → `_get_default_host_creds` → sink (sink-28 @ :88).

## 6. Uncovered APIs, dynamics, and CodeQL analysis limitations

- **`http_request(**call_kwargs)` (rest_utils.py:215, 218)** — dict-unpacking call sites cannot be matched positionally or by keyword name; sink-44/sink-45 predicates exist but will not fire at these two sites. Equivalent taint is caught earlier at the http_artifact_repo `http_request` sinks.
- **Response-driven URL (sink-34 `requests.put(credential.url)`)** — reaching it requires taint from the mpu/create *response* (`resp.json()` → `CreateMultipartUploadResponse` → `credential.url`); response-object taint is deliberately **not** modeled (it would be unconditional). The SSRF at mpu/create itself is covered by sink-31 (:125). Gap: full-URL-control PUT alerts will not fire.
- **Protobuf field propagation** — taint on a `_get_request_message()` result does not flow to `request_message.artifact_location` field reads (no object→field step for proto messages; adding a generic one would be unconditional). The write side of the DB chain is therefore not connected; coverage is preserved by the second-order read-side sources (`run.info.artifact_uri`, `self.artifact_uri`).
- **Databricks / optimized-S3 signed URIs (sink-13–18, 35–37, 48) and cloud SDK repos** — propagation crosses the Databricks/boto3 SDK boundary (not in this CodeQL database; detection.json coverage_gaps). These predicates match structurally but may yield no paths.
- **`request.json()` on the FastAPI deployments server (src-38)** has no modeled sink on that server surface (provider egress was labeled fp: admin-configured base URLs); it may only connect via cross-file flows.
- **Dynamic dispatch ambiguity** — sink/source matching is name+file scoped (Python dynamic dispatch limitation); unrelated same-named locals in the same files could in principle match (e.g. any `session.request` in request_utils.py — none other exists).
- **`download_chunk` keyword-only `http_uri`** — matched via `Call.getANamedArg()`/`Keyword.getArg()`/`getValue()`; a positional-only refactor would silently stop matching.
- **Not extracted at all (Phase 1 scope)**: `urllib.request.urlopen` (absent from the tree), httpx, flask/fastapi/requests/aiohttp internals, cloud SDK network I/O.
- **Diagnostics**: if local reachability of internal helpers to the transport needs confirmation, a separate diagnostics query (e.g. `@kind problem` on `MySummaries` steps only) may be added under `iris/diagnostics/`; it must not be counted as formal CWE-918 alerts. None was needed for this generation.

## 7. Label-model gaps requiring re-review (not silently modeled)

Per the no-label-modification rule, the following label insufficiencies are recorded for a Phase 1 re-review instead of being fixed in the model:
1. The 65 handler/route `param` labels have no matchable AST (functions are parameterless); if reviewers want handler-boundary seeds regardless, the labels should be re-issued against `_get_request_message` result variables.
2. sink-26 (gateway proxy) is labeled tp although the attacker controls only the path on an admin-fixed host — the reporting bar for path-only proxy access should be confirmed (phase1_review.md §6 item 4).
3. The 54 generic handler `source/candidate` labels were pruned from the model as URL-irrelevant; if alert volume is acceptable they can be reinstated as additional request-message seeds.
4. The cross-SDK candidate sinks (§6) will likely never produce paths in this database; consider downgrading or recording them as diagnostics-only material.

## 8. Reproducibility and independent evaluation

Same principles as the earlier CWE-78 experiment: (1) all generated code derives deterministically from the reviewed `labels.json` plus signatures verifiable in the current source tree — the mapping in §1 is exhaustive and checkable against `labels/labels_raw_pass3.json`; (2) no PyVul ground truth, fix commits, or CVE text was used at any stage; (3) the four `.qll` files and the query carry the run id `mlflow-ssrf-pass3-20261020` and are regenerable from the labels (hand edits are forbidden); (4) pass key is uniformly `"ssrf"` (no residual `"command_injection"` strings — verified); (5) formal analysis (Step 5) is deferred: when run, execute sequentially via `codeql database analyze <mlflow-db> iris/queries/Pass3_SSRF.ql --format=sarifv2.1.0 --output=iris/results/pass3.sarif` after `codeql pack install` in the `iris/` directory, and append runtime/alert counts to `iris/results/run_log.md`.

## 9. Post-generation compile fix (2026-10-20)

A `codeql query compile --check-only` pass (run after generation) surfaced one defect and one environment issue, both fixed:

1. **Reserved-word parameter name (parse failure)**: `MySummaries.qll` had used `from`/`to` as predicate parameter names; `from` is a QL keyword (query-clause syntax), which made the parser treat the predicate declarations as query clauses and cascaded ~150 syntax errors. All parameters were renamed to `nodeFrom`/`nodeTo`, matching the `taint_query.ql.tmpl` placeholder naming. This is a generator naming fix only — no predicate semantics, label mapping, source/sink/barrier/step logic, or pass key changed.
2. **Pack resolution ambiguity**: the local pack cache (`C:\Users\lzh\.codeql\packages`) holds multiple versions of every `codeql/*` pack, and `codeql pack install` cannot resolve them (it attempts to fetch `codeql/python-all@7.2.7` from the registry and fails with a CLI/registry manifest incompatibility). A `codeql-pack.lock.yml` pinning the same version set as the previous mlflow experiment (python-all 7.1.2 and its transitive packs, all present in the local cache) was added to the `iris/` root. With the lock file, compilation must run from the `iris/` directory with the default search path — passing `--additional-packs` that points at the multi-version cache root re-introduces the ambiguity.

Verified command and result:

```text
$ cd iris
$ codeql query compile --check-only -- queries/Pass3_SSRF.ql
Compiling query plan for ...\queries\Pass3_SSRF.ql.
Done [1/1]
```

No errors, no warnings — all AST/dataflow APIs used by the generated model (`DataFlow::Node.asExpr`, `Call.getFunc/getPositionalArg/getANamedArg`, `Keyword.getArg/getValue`, `Attribute.getName/getObject`, `Location.getFile`, `File.getRelativePath`, `DataFlow::ConfigSig`, `TaintTracking::Global`, `flowPath`/`PathGraph`) type-check against `codeql/python-all 7.1.2`. Step 5 execution (database analyze → `results/pass3.sarif`) remains deferred.

**Status: Phase 2 Step 4 complete — libraries + query generated and compile-verified (check-only); Step 5 execution deferred.**
