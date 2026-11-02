# Augur Phase 1 Step 3 - Label Statistics (Pass 1: Path Traversal)

- Target: airflow (Apache Airflow 2.7.0.dev0, sha 2811ba7), Python, Flask/FAB + connexion + argparse
- Pass: 1 (CWE-22/23/36/73 Path Traversal)
- LLM model: glm-5.3 (Claude Code agent harness; source candidates labeled by direct in-context review, sink candidates by fork subagents of the same model)
- Generated: 2026-10-21

## 1. Candidate volume and dedup

| input | raw CSV rows | unique candidates | duplicate rows merged |
|---|---|---|---|
| sources.csv | 1996 | 1820 | 176 |
| sinks.csv | 1781 | 1471 | 310 |
| **total** | **3777** | **3291** | **486** |

Dedup key: `(role, file, line, callable, flow_kind, arg_index)`; the decoded `node` column only carries the AST node type string and is not location-unique. Every raw CSV row maps to exactly one label entry in `labels_raw_pass1.json`.

## 2. Batches

26 labeling batches total: 11 direct in-context review batches for source candidates (R-SRC-01..11) and 15 fork-subagent batches for sink candidates (B-SNK-A01..05 arg family, B-SNK-M01..05 method family, B-SNK-I01..05 internal-file-wrapper family).

| batch | family | rows | mode |
|---|---|---|---|
| R-SRC-01 | config | 260 | in-context LLM review |
| R-SRC-02 | config | 244 | in-context LLM review |
| R-SRC-03 | env | 180 | in-context LLM review |
| R-SRC-04 | env | 152 | in-context LLM review |
| R-SRC-05 | cli (sys.argv) | 36 | in-context LLM review |
| R-SRC-06 | http | 371 | in-context LLM review |
| R-SRC-07 | return (json.loads / itsdangerous loads) | 107 | in-context LLM review |
| R-SRC-08 | internal_transfer | 19 | in-context LLM review |
| R-SRC-09 | param | 160 | in-context LLM review |
| R-SRC-10 | param | 160 | in-context LLM review |
| R-SRC-11 | param | 131 | in-context LLM review |
| B-SNK-A01 | arg | 104 | fork subagent (glm-5.3) |
| B-SNK-A02 | arg | 104 | fork subagent (glm-5.3) |
| B-SNK-A03 | arg | 104 | fork subagent (glm-5.3) |
| B-SNK-A04 | arg | 104 | fork subagent (glm-5.3) |
| B-SNK-A05 | arg | 104 | fork subagent (glm-5.3) |
| B-SNK-I01 | internal_file_wrapper | 93 | fork subagent (glm-5.3) |
| B-SNK-I02 | internal_file_wrapper | 93 | fork subagent (glm-5.3) |
| B-SNK-I03 | internal_file_wrapper | 93 | fork subagent (glm-5.3) |
| B-SNK-I04 | internal_file_wrapper | 93 | fork subagent (glm-5.3) |
| B-SNK-I05 | internal_file_wrapper | 89 | fork subagent (glm-5.3) |
| B-SNK-M01 | method | 98 | fork subagent (glm-5.3) |
| B-SNK-M02 | method | 98 | fork subagent (glm-5.3) |
| B-SNK-M03 | method | 98 | fork subagent (glm-5.3) |
| B-SNK-M04 | method | 98 | fork subagent (glm-5.3) |
| B-SNK-M05 | method | 98 | fork subagent (glm-5.3) |

## 3. Source-candidate labels (unique candidates)

| role\classification | tp | fp | candidate | unknown | total |
|---|---|---|---|---|---|
| source | 628 | 0 | 3 | 0 | 631 |
| none | 0 | 1189 | 0 | 0 | 1189 |

Extraction family breakdown:

| extraction family | source/tp | source/candidate | none/fp | total |
|---|---|---|---|---|
| http | 368 | 0 | 3 | 371 |
| param | 231 | 0 | 220 | 451 |
| return | 10 | 3 | 94 | 107 |
| internal_transfer | 19 | 0 | 0 | 19 |
| env | 0 | 0 | 332 | 332 |
| config | 0 | 0 | 504 | 504 |
| cli | 0 | 0 | 36 | 36 |

## 4. Sink-candidate labels (unique candidates)

| role\classification | tp | fp | candidate | unknown | total |
|---|---|---|---|---|---|
| sink | 269 | 0 | 0 | 0 | 269 |
| summary | 54 | 0 | 0 | 0 | 54 |
| none | 0 | 1147 | 1 | 0 | 1148 |

Deployed production code (`airflow/` package, excluding dev/scripts/docs/example_dags/migrations/tests) only:

| role\classification | tp | fp | candidate | unknown | total |
|---|---|---|---|---|---|
| sink | 269 | 0 | 0 | 0 | 269 |
| summary | 54 | 0 | 0 | 0 | 54 |
| none | 0 | 324 | 1 | 0 | 325 |

Extraction family breakdown:

| family | sink | summary | none | total |
|---|---|---|---|---|
| arg | 150 | 48 | 322 | 520 |
| method | 40 | 0 | 450 | 490 |
| internal_file_wrapper | 79 | 6 | 376 | 461 |

## 5. Path origin of labeled production sinks

| path_origin | count | share |
|---|---|---|
| param | 183 | 68.0% |
| config | 39 | 14.5% |
| literal | 25 | 9.3% |
| db_field | 13 | 4.8% |
| env | 4 | 1.5% |
| remote | 2 | 0.7% |
| request | 2 | 0.7% |
| n/a | 1 | 0.4% |
| **total** | **269** | 100% |

`param` paths are operator/DAG-author or hook parameters (templateable fields, DB connection extras); `config` paths come from conf.get (BASE_LOG_FOLDER, DAGS_FOLDER, PLUGINS_FOLDER...); `db_field` paths are DB-stored TaskInstance/LogTemplate/Connection values; `request` = the serve-logs endpoint (serve_logs.py:108 wrapper + :109 send_from_directory, the /log/<path:filename> route variable); `remote` = paths derived from external/remote content (GCS blob names in gcs.py:790, IMAP attachment filenames in imap.py:265) written to local files - see phase1_review.md.

## 6. Top production sink/summary callables

| callable | family | count |
|---|---|---|
| open | arg | 107 |
| Path | arg | 48 |
| mkdir | method | 14 |
| remove | arg | 8 |
| rmtree | arg | 8 |
| open | method | 8 |
| walk | arg | 5 |
| chmod | method | 5 |
| chmod | arg | 4 |
| ZipFile | arg | 4 |
| read_bytes | method | 4 |
| read_text | method | 4 |
| stat | arg | 2 |
| relative_fileloc | internal_file_wrapper | 2 |
| SourceFileLoader | arg | 2 |

## 7. Top production source files

| file | source rows |
|---|---|
| airflow/www/views.py | 360 |
| airflow/api_connexion/endpoints/task_instance_endpoint.py | 54 |
| airflow/api_connexion/endpoints/dag_run_endpoint.py | 25 |
| airflow/www/api/experimental/endpoints.py | 22 |
| airflow/api_connexion/endpoints/dag_endpoint.py | 19 |
| airflow/api_connexion/endpoints/dataset_endpoint.py | 13 |
| airflow/www/decorators.py | 12 |
| airflow/api_connexion/endpoints/pool_endpoint.py | 11 |
| airflow/api_connexion/endpoints/connection_endpoint.py | 10 |
| airflow/api_connexion/endpoints/log_endpoint.py | 10 |

## 8. Low-confidence and human-review entries

- entries with confidence < 0.55: 4
- entries classified candidate/unknown: 4

- `P1-S-0120` source/candidate conf=0.45: Request-supplied file_token decoded by URLSafeSerializer(SECRET_KEY); decoded value is passed to DagCode.code(path). Arbitrary path injection requires SECRET_KEY compromise or leakage of a server-minted token (tokens are
- `P1-S-0169` source/candidate conf=0.45: Request-supplied token decoded by URLSafeSerializer(SECRET_KEY); decoded metadata drives download_logs/full_content flags, not a direct file path. Human review: signed-token boundary.
- `P1-S-1213` source/candidate conf=0.45: Azure AD OIDC id_token payload (base64 JWT payload segment) parsed with json.loads; external identity-provider-signed input, low path-traversal relevance. Human review.
- `P1-K-0370` none/candidate conf=0.45: GCSTimeSpanFileTransformOperator.execute performs real local ops (destination_file.parent.mkdir, temp_output_dir_path.glob) but the paths derive from TemporaryDirectory roots joined with GCS blob names (Path(temp_input_d

## 9. Exclusion rationale summary

- env (332) / config (504) / cli sys.argv (36) source rows: deployment/admin or local-operator trust level - not attacker-controlled boundaries (none/fp).
- dbt.py http rows (3): `request` is a requests.PreparedRequest, not the flask proxy (extraction collision).
- api_connexion helper/comprehension parameter rows and CLI `args` handler rows: internal/CLI boundaries, not request boundaries (none/fp).
- handler `session` parameters: injected DB session, not request data (none/fp).
- sink rows in dev/, scripts/, docs/, example_dags/, migrations/, docker_tests/, kubernetes_tests/, setup.py: non-deployed tooling/test/build code (none/fp) per WORKFLOW extraction-note expectation and FP heuristics.
- str/datetime `.replace`, `glob.glob`, remote (paramiko/SMB/FTP/Azure) method collisions on non-pathlib receivers: extraction name-collisions (none/fp).
- json.loads of internal/DB/CLI/config data: not attacker-controlled decode boundaries (none/fp).
