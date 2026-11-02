# Phase 1 Step 3 Review — mlflow, Pass 3 (CWE-918 SSRF)

- Run: `mlflow-ssrf-pass3-20261020` · generated 2026-10-20
- Labeling model: **glm-5.3** (the LLM performing this labeling run)
- Batches: 7 (b1–b5 source batches, b6–b7 sink batches) · candidates: **303** (251 sources + 52 sinks) — every CSV row labeled, 0 excluded, 0 deduplicated
- Artifacts: `labels/labels.json` (schema-valid), `labels/labels_raw_pass3.json` (raw per-batch decisions with original CSV rows), `labels/label_stats.md`
- Verification basis: real source under `dataset/codeql_databases/ssrf_dbs/mlflow_vuln/mlflow/` only (no ground truth, no fix commits, no external CVE descriptions)

## 1. Label distribution

| role | tp | candidate | fp | unknown | total |
| --- | --- | --- | --- | --- | --- |
| source | 95 | 83 | 7 | 0 | 185 |
| sink | 17 | 13 | 17 | 0 | 47 |
| sanitizer | 0 | 0 | 0 | 0 | 0 |
| summary | 0 | 0 | 0 | 0 | 0 |
| none | 0 | 7 | 63 | 1 | 71 |

## 2. Principal verified chains (drives the tp labels)

1. **Gateway proxy (path-level control, fixed host)** — `serve_gateway_proxy` (server/__init__.py:100) → `gateway_proxy_handler` (handlers.py:1126) reads `gateway_path` from `request.args`/`request.json` (handlers.py:1132-1141) → `requests.request(request_type, f"{target_uri}/{gateway_path}", json=json_data)` (handlers.py:1143). `target_uri` comes from the admin env `MLFLOW_DEPLOYMENTS_TARGET` (handlers.py:1127) — the attacker controls the path appended to the operator-fixed base, not the host. Labeled sink/tp at arg 1 with confidence 0.75 and this caveat recorded.
2. **Artifact-URI fetch chain (host control, second order)** — CreateExperiment persists the client-supplied `artifact_location` (handlers.py:585-596; only the query component is validated by `validate_query_string` — no scheme/host restriction) → run `artifact_uri` derives from it → `get_artifact_handler` (handlers.py:544-570) / `_list_artifacts` (handlers.py:932-963) / `upload_artifact_handler` (handlers.py:1225-1270) read `run.info.artifact_uri` → `get_artifact_repository(artifact_uri)` → `HttpArtifactRepository` with `_get_default_host_creds(self.artifact_uri)` (http_artifact_repo.py:39-40) → `http_request` (URL = `f"{host_creds.host}{endpoint}"`, rest_utils.py:104-105) → `session.request` (request_utils.py:190). Sources: flask request reads + `_get_request_message()` returns + `run.info.artifact_uri` field reads + http_artifact_repo `self.artifact_uri` reads. Sinks: the 7 `http_request` call sites + final transport.
3. **Model-version source chain (host control, second order)** — `_create_model_version` persists `request_message.source` after `_validate_source` (handlers.py:1590-1621, rejects only local/file relative-path sources; http/https remain allowed) → `get_model_version_artifact_handler` (handlers.py:1655-1675) resolves `get_model_version_download_uri` → `get_artifact_repository(artifact_uri)` → same HttpArtifactRepository fetch chain.
4. **Multipart response-driven URL** — `requests.put(credential.url, ...)` (http_artifact_repo.py:157) where `credential.url` is parsed from the JSON response of `mpu/create`, itself sent to the (potentially attacker-controlled) artifact host. Labeled sink/tp at arg 0, confidence 0.70.

Reachability caveat for chains 2–4: the tracking server runs **without authentication by default** (optional basic-auth layer, disabled by default), so "internal" handler parameters on /api/2.0/mlflow/* are genuinely network-attacker-reachable — this was verified, not assumed.

## 3. Key negative decisions (what was *not* labeled source/sink and why)

- **All 55 environment reads (os.getenv / os.environ.get / MLFLOW_* getters) → none/fp**: process-environment values are operator/server-admin configuration; not attacker-controlled at any server boundary. `MLFLOW_DEPLOYMENTS_TARGET` (handlers.py:1127) is admin config — the attacker controls only the appended `gateway_path`.
- **`mlflow run <uri>` and other CLI params → source/fp or none/fp**: operator-local CLI input driving a client-side `requests.get` (projects/utils.py:245); not a server-side attacker boundary. Kept as labeled rows with fp classification.
- **Auth-layer request reads (auth/__init__.py:139,141,746,748,749) → source/fp**: genuine untrusted Flask reads, but consumed only for credential lookup/comparison; no propagation into any outbound URL found.
- **Non-HTTP protocol access (ftp_artifact_repo.py:41 FTP.connect, sftp_artifact_repo.py:81 pysftp.Connection, projects/utils.py:208/211/230 git remote/fetch) → none/candidate**: recorded separately as CWE-918-adjacent cross-protocol remote access; excluded from the Pass-3 HTTP(S) sink set per the pass policy (also excludes file:/data: style concerns — those belong to other CWEs).
- **Gateway provider aiohttp POST (providers/utils.py:27) → sink/fp**: base URL from operator-managed gateway route config (fixed provider defaults) — admin-configured URL per the SSRF FP heuristic.
- **Client-side wrappers (17 rows: deployments/gateway/auth clients, base_rest_store/rest_store, pyfunc scoring-server client, openai parallel processor) → sink/fp**: hosts come from operator-configured tracking/gateway/Databricks URIs; fixed API endpoints.
- **Cloud-SDK artifact repos (s3/gs/azure) `self.artifact_uri` reads → source/candidate**: DB-stored URI content, but the network I/O happens inside external SDKs not present in this CodeQL database (possible endpoint-override family unproven; see detection.json coverage_gaps).
- **Internal helper params (handlers.py:966 `_list_artifacts_for_proxied_run_artifact_root`, handlers.py:1318 `_get_artifact_repo`; http_dataset_source.py:109 `raw_source`) → none**: internal wrapper parameters, not external boundaries; taint enters via the separately labeled field reads (`run.info.artifact_uri`). The `_get_request_message()`/`_get_request_json()` returns, by contrast, were kept as sources because they directly materialize external request content.

## 4. Sanitizer and summary analysis

- **Sanitizers: 0 entries.** No candidate in the CSVs is a proven CWE-918 sanitizer. The guards observed in source do not neutralize URL host/scheme control for the relevant chains: `validate_path_is_safe` (path-traversal guard on artifact paths), `_validate_source` (rejects local/file URIs but permits http/https — see handlers.py:1590-1621), `validate_query_string` (query component only), `_is_valid_uri`/`parse_target_uri` (deployment target shape). None of these was extracted as a CSV candidate, and none restricts scheme/host/private-IP on the gateway-proxy or HttpArtifactRepository paths (confirmed: no allow-list, private-IP blocking, or scheme restriction exists on either path). Auth, HTML escaping, and general format validation were deliberately not treated as SSRF sanitizers.
- **Summaries: 0 entries.** Wrapper relays in the egress stack (call_endpoint → http_request → _get_http_response_with_retries → session.request) are labeled as sinks instead, which directly preserves the taint endpoints needed by Phase 2. **Phase 2 note**: `MySummaries.qll` will nonetheless need additional taint steps that are *not* representable from the CSV candidate set: (a) `MlflowHostCreds(host=...)` constructor → `host_creds.host` field, (b) `get_artifact_repository(uri)` / `get_artifact_repository` → `repo.artifact_uri` field, (c) `_get_default_host_creds(uri)` → `MlflowHostCreds`, (d) protobuf `parse_dict(request_dict, request_message)` → `request_message` fields. Without (a)–(d) the second-order chains in section 2 will not connect in the taint query.

## 5. arg_index corrections and format notes

- The 7 `http_request()` call sites in http_artifact_repo.py (CSV argIndex 1 = `endpoint`) were relabeled **arg_index 0** (`host_creds`): the URL is `f"{host_creds.host}{endpoint}"` (rest_utils.py:104-105) — the host-controlling position is arg 0; `endpoint` is path-only and cannot relocate the host. Same correction for 4 rest_utils.py relay rows (:143, :215, :218, :230). Corrections are recorded per-entry in `labels_raw_pass3.json` (`arg_index_final`) with the original CSV value preserved (`arg_index_csv`).
- `download_chunk(*, ..., http_uri)` is keyword-only: its 3 call rows carry `arg_index: null` with `flow_kind: "unknown"` (the schema forbids `argument` without a positional index); the URL-carrying keyword is documented in the rationale.
- `cloud_storage_http_request(method, url, ...)` rows keep arg_index 1 (full URL, verified against the signature at request_utils.py:193-203). `requests.request/get/post/put` rows keep arg 0 (URL); `requests.request` at handlers.py:1143 keeps arg 1 (method=0, URL=1); `requests.Session.request` at request_utils.py:190 keeps arg 1.

## 6. Items needing human review (low confidence / unverified propagation)

1. `sink-13/14/15/16/17` (Databricks `call_endpoint`/`cloud_storage_http_request` signed-URI flows, 0.55): URLs are signed URIs from Databricks API responses; the underlying storage path derives from DB-content `artifact_uri`, but propagation crosses the external Databricks/ADLS SDK boundary and is not provable inside this database.
2. `sink-36` (optimized_s3_artifact_repo.py:159, 0.55) and `sink-35` (http_dataset_source.py:70, 0.55): same response-driven / DB-spec-driven URL pattern.
3. `src-228` (HTTPDatasetSource._resolve.raw_source, none/unknown, 0.50): internal resolution wrapper for dataset sources; second-order dataset-spec flows need manual confirmation.
4. `sink-26` (gateway proxy, tp but 0.75): confirm whether path-level control on an admin-fixed host meets the project's CWE-918 reporting bar (it is a proxy-endpoint-access issue rather than full host control).
5. `src-104` (_create_run, candidate 0.55): CreateRun carries no artifact_uri field (verified handlers.py:686-712); influence on fetch targets is indirect via the experiment's artifact location.
6. The 54 generic handler `source/candidate` rows (0.45): externally reachable REST boundaries whose message fields (IDs/names/tags/metrics) showed no flow into outbound URLs — kept only for conservative recall; reviewers may prune them before Phase 2 if alert volume is a concern.

## 7. Schema conformance note

`labels.json` was validated against `assets/labels_schema.json` (via `labels/validate_labels.py`, self-contained validator implementing every schema constraint; the `jsonschema` package is not installed in this environment and its installation was blocked by permission policy). One keyword is intentionally unsatisfied: `passes.contains { pass_id: 1 }` requires a pass-1 block to be present, which contradicts a user-narrowed single-pass run — it is treated as a template artifact. All other constraints (enums, patterns, required fields, `additionalProperties: false`, the `flow_kind: argument ⇒ arg_index ≥ 0` implication) pass.

## 8. Coverage and provenance

- 303/303 CSV candidates labeled; no row dropped, merged, or re-asked. Duplicate code sites (e.g. handlers.py:1132 `request.args` and `request.json`) are retained as distinct boundary reads; no true duplicates existed.
- Deterministic re-rendering: `labels/build_labels.py` (reads the extraction CSVs, applies the decision table documented above, fails on any unlabeled row). `labels/validate_labels.py` re-checks schema conformance.
- Batch structure, per-candidate CSV rows, and per-decision rationales are preserved in `labels/labels_raw_pass3.json` for audit.

**Status: Phase 1 Step 3 complete. Stopping here per instruction — not proceeding to Phase 2 (no .qll libraries, no queries, no taint analysis, no report).**
