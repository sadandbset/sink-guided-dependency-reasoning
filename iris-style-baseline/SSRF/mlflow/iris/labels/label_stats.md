# Pass 3 (CWE-918 SSRF) Label Statistics - mlflow

- Target: mlflow 2.9.2.dev0 (Flask tracking server primary surface)
- Labeling model: **glm-5.3**
- Generated at: 2026-10-20T00:00:00Z (run `mlflow-ssrf-pass3-20261020`)
- Batches: **7** (5 source batches + 2 sink batches)
- Candidate total: **303** (251 sources + 52 sinks), all labeled, 0 excluded

## Role distribution (all candidates)

| role | count |
| --- | --- |
| source | 185 |
| sink | 47 |
| sanitizer | 0 |
| summary | 0 |
| none | 71 |

## Role x classification distribution

| role | classification | count |
| --- | --- | --- |
| none | candidate | 7 |
| none | fp | 63 |
| none | unknown | 1 |
| sink | candidate | 13 |
| sink | fp | 17 |
| sink | tp | 17 |
| source | candidate | 83 |
| source | fp | 7 |
| source | tp | 95 |

## Sources (251 candidates)

| role | classification | count |
| --- | --- | --- |
| none | candidate | 2 |
| none | fp | 63 |
| none | unknown | 1 |
| source | candidate | 83 |
| source | fp | 7 |
| source | tp | 95 |

Source family summary (by labeling batch, see labels_raw_pass3.json):

- b1 environment/configuration reads (os.getenv, os.environ.get, MLFLOW_* getters): 55 -> none/fp (operator/server-admin config, not attacker-controlled)
- b2 Flask/FastAPI request boundary + materializers (request.args/json/data/query_string reads, parser.parse, _get_request_json/_get_request_message returns, deployments app request.json, auth-layer reads): 73 -> source/tp 68, source/fp 5 (auth-layer reads used only for credential handling)
- b3 handler/route parameter boundaries (server/__init__.py views + handlers.py REST handlers): 71 -> source/tp 11 (artifact/gateway-proxy-relevant handlers), source/candidate 54, none/fp 4 (health/version/serve/static-file), none/candidate 2 (internal helpers)
- b4 DB-content fields (run.info.artifact_uri 8, request_message.source 2, self.artifact_uri 36): 46 -> source/tp 16 (http_artifact_repo + run.info.artifact_uri + request_message.source), source/candidate 29 (non-HTTP cloud/DBFS repos), none/fp 1 (local repo)
- b5 CLI inputs + internal wrapper param: 6 -> source/fp 2 (`mlflow run` + uri arg), none/fp 3 (mlflow server/gc/doctor), none/unknown 1 (HTTPDatasetSource._resolve.raw_source)

## Sinks (52 candidates)

| role | classification | count |
| --- | --- | --- |
| none | candidate | 5 |
| sink | candidate | 13 |
| sink | fp | 17 |
| sink | tp | 17 |

Sink family summary:

- server-reachable egress (tp): gateway proxy requests.request (handlers.py:1143), 7x http_request in http_artifact_repo.py (arg corrected to 0), requests.put multipart part, session.request final transport + 5 rest-utils relays
- candidate sinks (13): Databricks/optimized-S3 signed-URI flows, unity-catalog models fetch, file_utils/download_chunk chunk downloads, HTTPDatasetSource load, dbfs/databricks fixed-host API calls with DB-content paths
- client-side/operator-configured (fp, 17): deployments/gateway/auth clients, base_rest_store/rest_store client stores, pyfunc scoring-server client, openai parallel processor, aiohttp gateway provider (admin-config), `mlflow run` zip fetch
- non-HTTP protocol (none/candidate, 5): ftp, sftp, 3x git operations - recorded separately

## Quality checks

- schema conformance: validated against assets/labels_schema.json (all constraints except the unsatisfiable passes.contains{pass_id=1} template artifact - see phase1_review.md)
- coverage: 303/303 candidates labeled, 0 unclassified, 0 dropped, 0 duplicates
- argument-index bounds: all flow_kind=argument entries carry integer arg_index >= 0; download_chunk keyword-only http_uri rows use arg_index null + flow_kind 'unknown'
- pass 3 has >= 1 sink (17 tp sinks + 13 candidates) and >= 1 source (95 tp sources)
- low-confidence entries (<0.55) flagged for human review: see phase1_review.md section 5
