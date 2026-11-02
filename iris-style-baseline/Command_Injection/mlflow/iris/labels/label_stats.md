# Label Stats — MLflow Pass 2 (CWE-077/078/088), Step 3 LLM labeling

## 1. Run identity

- run_id: `mlflow-iris-pass2-labeling-20261015`
- generated_at: 2026-10-15
- model: glm-5.3 (Claude Code CLI harness; deterministic tool-assisted labeling, batched review)
- language: python; framework: flask (primary web surface; click CLI and fastapi gateway secondary)
- project: mlflow (vulnerable snapshot 2.5.1.dev0, sha 330bf0b38b07d4adf3fae99af1b44c8e857f514a)
- inputs: `extraction/sources.csv` (1148 rows), `extraction/sinks.csv` (145 rows),
  `exploration/detection.json`; all 1293 candidate rows were reviewed against the
  mlflow_vuln source tree (sink sites and key source boundaries read in full;
  the per-site decisions are encoded in `labels/work/build_labels.py`, which only
  formats them)
- output: `labels/labels.json` (schema-valid per
  `iris_tools/augur-0.3.0/assets/labels_schema.json`; pass 1 is a zero-entry
  stub required by the schema's `contains` constraint on pass_id=1),
  `labels/labels_raw_pass2.json` (per-site raw decisions + reconciliation log)

Threat model: external input enters via (1) the Flask tracking/model-registry
REST API and pyfunc scoring server, (2) the click CLI (`mlflow run` with -P
parameters / --docker-args), (3) untrusted project/model artifacts (MLproject
entry-point commands, MLmodel / conda.yaml / python_env.yaml / requirements
metadata), and (4) MLFLOW_* environment variables in shared or
deployment-controlled environments. `classification=tp` marks a genuine
source/sink/sanitizer API for CWE-78 — it is NOT a final vulnerability
ground-truth TP.

## 2. Batch policy

5 batches (WORKFLOW §4.4.4: stable scopes, conservative recall, re-ask
threshold 0.55; entries at/below 0.55 were re-checked against source before
confirming):

| batch | focus | candidates |
| --- | --- | --- |
| sink-01 | all 93 unique sink sites (exec APIs, shell wrappers, shell_arg_list / shell_true / cmd_format rows) — hand-reviewed line by line | 93 |
| src-01 | HTTP boundaries: request field/call reads, request-decoding wrappers, handler params, click CLI params/decorators, sys.argv | ~340 |
| src-02 | environment boundaries: MLFLOW_* registry, os.environ / os.getenv (incl. the flowKind=return getenv rows) | ~190 |
| src-03 | decode/open boundaries: json/yaml loads, open() with read vs write mode distinguished per source line | ~300 |
| reconciliation | dedup by (file, line); api/ast merges; dev/examples/setup/docs → fp; write-mode open → fp; sanitizer review | — |

## 3. Candidate coverage (all 1293 rows processed)

| | count |
| --- | --- |
| source CSV rows | 1148 |
| sink CSV rows | 145 |
| api/ast duplicate-row merges (same site) | 154 |
| **unique source sites** | **949** |
| **unique sink sites** | **93** |
| additional sanitizer entries (APIs verified in code) | 2 |
| **entries emitted (pass 2)** | **1044** |

Reconciliation detail (per-site row merges, match kinds) is in
`labels_raw_pass2.json` (`reconciliation`, `sites`). Nothing was invented:
every entry traces to a CSV site, except the two sanitizer entries which trace
to reviewed in-repo APIs (`mlflow/utils/string_utils.py:131 quote`,
`mlflow/projects/_project_spec.py:241 _sanitize_param_dict`).

## 4. Role / classification counts

| role | count | tp | candidate | fp |
| --- | --- | --- | --- | --- |
| source | 552 | 248 | 304 | 0 |
| sink | 31 | 16 | 3 | 12 |
| summary | 18 | 16 | 2 | 0 |
| sanitizer | 2 | 2 | 0 | 0 |
| none | 441 | 0 | 0 | 441 |
| **total** | **1044** | **282** | **309** | **453** |

Confidence distribution: {'<0.6': 242, '0.6-0.7': 68, '0.7-0.8': 257, '0.8-0.9': 356, '0.9-1.0': 121}.

Family breakdown: http 28 + request-decoding wrappers 53 + Model.load 26 +
load_project 2 + CLI params 103 + CLI decorators 154 + sys.argv 4 + decode 82 +
file open 86 + special env 16 (all `source`); rejected: non-product code 167
(dev/, examples/, setup.py, docs/), env-config/write-open 238, internal/routing
36 (all `none`/fp).

## 5. Boundary-level decisions

| extraction family | unique sites | decision |
| --- | --- | --- |
| flask_request_http (request.*) | 28 | source/tp 0.9 (data fields: json, data, args, form, query_string, stream, headers, content_type); request.method/url_rule → candidate 0.55 (routing metadata) |
| internal_transfer (_get_request_message/_get_request_json, parse_csv_input) | 53 | source/tp 0.85 — central HTTP request decoding for every REST endpoint and the scoring server |
| config (Model.load) | 31 | 26 source/tp 0.9 (MLmodel from untrusted model artifacts) · 5 fp (examples/sktime, non-product) |
| load_project | 2 | source/tp 0.95 — MLproject entry-point commands are the primary CWE-78 carrier |
| json_yaml_decode | 82 | tp 0.8–0.95 (MLproject/MLmodel/env/job-template YAML, request bodies, CLI config JSON) · candidate 0.55–0.65 (store round-trips, remote responses, flavor configs) |
| file open() | 86 | tp 0.7–0.85 (project/model/env/requirements artifact reads, scoring-server input) · candidate 0.55 (store/recipe/internal) · write-mode opens → fp 0.85 |
| cli param | 103 | tp 0.9 (`mlflow run` uri/entry_point/param_list/docker_args) · 0.8 (models/gateway CLI) · 0.75 (sagemaker/deployments CLI) · 0.7 (other CLI) |
| cli decorator | 154 | candidate 0.55 — binding declaration; the value enters via the function param rows |
| sys.argv | 4 | container entrypoint tp 0.7; others candidate 0.6 |
| env | 190 | tp 0.75–0.9: MLFLOW_WHEELED_MODEL_PIP_DOWNLOAD_OPTIONS, MLFLOW_CONDA_HOME, MLFLOW_CONDA_CREATE_ENV_CMD, CONDA_EXE, SHELL, MLFLOW_* registry reads; candidate 0.55–0.6 (container flavor/behavior flags, PYENV_ROOT); rest fp 0.75 (config/credentials/child-env maps) |
| param (handlers/gateway/auth) | (in http/cli rows) | tp 0.75–0.8 for request-derived handler params · fp for response objects / internal Run objects |
| dev/, examples/, setup.py, docs/ | 167 | none/fp 0.85 — non-product code |

## 6. Sinks (31) — the CWE-78 execution surface

Confirmed (16 tp):

| API | site | arg | confidence | note |
| --- | --- | --- | --- | --- |
| `subprocess.Popen` (bash -c) | projects/backend/local.py:277 | 2 | 0.95 | MLproject entry-point command (format-substituted; declared params quote()d, extra params unquoted) |
| `subprocess.Popen` (cmd /c) | projects/backend/local.py:280 | 2 | 0.90 | Windows variant, mutually exclusive at runtime |
| `os.system` | sagemaker/__init__.py:158 | 0 | 0.95 | ';'/&&-joined docker login/tag/push string, image interpolated unescaped |
| `subprocess.Popen` | utils/process.py:95 | 0 | 0.95 | central _exec_cmd sink; cmd string or argv, shell forwarded via **kwargs (virtualenv.py:137) |
| `subprocess.run` (shell=True) | models/wheeled_model.py:222 | 0 | 0.95 | single-string pip wheel command incl. MLFLOW_WHEELED_MODEL_PIP_DOWNLOAD_OPTIONS |
| `Popen` (bash -c) | models/container/__init__.py:203 | 2 | 0.95 | container serving: get_cmd gunicorn/waitress command + activate commands |
| `Popen` (bash -c) | models/container/__init__.py:114 | 2 | 0.90 | `conda env create` with model conda.yaml-derived env path |
| `Popen` (bash -c) | pyfunc/backend.py:241 | 2 | 0.90 | local pyfunc serve: scoring server command via bash -c |
| `Popen` (list → bash -c) | pyfunc/backend.py:243 | 0 | 0.90 | same call site, argv form (dangerous element index 2) |
| `Popen` (bash -c) | utils/environment.py:611 | 2 | 0.90 | Environment.execute: activate + command joined, bash -c |
| `Popen` (cmd /c) | utils/environment.py:613 | 2 | 0.85 | Windows variant of Environment.execute |
| `Popen` (bash -c) | projects/databricks.py:379 | 2 | 0.85 | Databricks run script (tar/rsync/mlflow run; mlflow argv quote()d) |
| `Popen` (bash -c) | models/container/__init__.py:130 | 2 | 0.85 | activate + pip install server deps (model-derived activate path) |
| `Popen` (Rscript -e) | rfunc/backend.py:106 | 2 | 0.85 | R code evaluation; model_path quote()d, host/port raw |
| `Popen` (bash -c) | models/container/__init__.py:139 | 2 | 0.80 | activate + pip install mlflow (fixed pip fragment) |
| `Popen` | utils/requirements_utils.py:197 | 0 | 0.80 | pip subprocess built from model requirements data |

Candidate (3): docker argv-list Popens — sagemaker/__init__.py:1132
(docker run, image/config values), models/docker_utils.py:245 (docker build,
CLI image name), gateway/runner.py:59 (gunicorn argv, CLI host/port) — no
shell, argument-level injection only.

Rejected (12 fp, kept labeled with rationale): fixed-argv probes
(utils/__init__.py:206/211 `nc`, pyfunc/backend.py:282 `[conda_path,
--version]`, rfunc/backend.py:86 `Rscript --version`,
databricks_utils.py:178 `mountpoint`, container:175 `nginx -c` packaged conf,
container:180/181 `ln -sf`, recipes step.py:110 open-tool) and
models/container/__init__.py:224 (shell=True but all fixed literals).
23 cmd_format f-string rows → none/fp: command construction or
log/error-message strings, not execution (each rationale names the exec sink
it feeds, when it does).

## 7. Summaries (18) — data-propagation wrappers

| API | site | hop modeled |
| --- | --- | --- |
| `_exec_cmd` | utils/process.py:31 | cmd param (+**kwargs incl. shell) → subprocess.Popen:95 |
| `Environment.execute` | utils/environment.py:587 | command → activate+command joined → bash -c/cmd /c (611/613) → _exec_cmd |
| `_run_entry_point` | projects/backend/local.py:262 | MLproject command → bash -c (277) / cmd /c (280) |
| `_run_mlflow_run_cmd` | projects/backend/local.py:242 | mlflow run argv (with -P params) → Popen 252/259 |
| `_join_commands` | utils/process.py:121/122 | commands → ['bash','-c', joined] |
| `PyFuncBackend.serve` | pyfunc/backend.py:163 | model_uri → get_cmd command string → bash -c 241/243 or Environment.execute |
| `_serve_pyfunc` | models/container/__init__.py:144 | model → get_cmd → /bin/bash -c 203 |
| `_install_pyfunc_deps` | models/container/__init__.py:87 | model_path/MLmodel env → conda env create 114 / activate 130/139 |
| `_serve_mleap` | models/container/__init__.py:212 | fixed java command string → Popen(shell=True) 224 |
| `WheeledModel._download_wheels` | models/wheeled_model.py:201 | env-var options + paths → shell=True run 222 |
| `push_image_to_ecr` | sagemaker/__init__.py:110 | image → docker login/tag/push string → os.system 158 |
| `_get_databricks_run_cmd` | projects/databricks.py:343 | tar URI + quoted mlflow argv → ['bash','-c', script] 379 |
| `_run_command` | utils/requirements_utils.py:193 | pip cmd → Popen 197 |
| `RFuncBackend._execute` | rfunc/backend.py:103 | R command string → Popen(['Rscript','-e',cmd]) 106 |
| `Runner.start` | gateway/runner.py:58 | CLI host/port/workers → gunicorn argv Popen 59 |
| `run_local` | sagemaker/__init__.py:1048 | model_uri/config → docker run argv Popen 1132 (candidate) |
| `_build_image_from_context` | models/docker_utils.py:227 | image_name → docker build argv Popen 245 (candidate) |

Uncovered (not a CSV row, noted in metadata): virtualenv.py:133-137
`_exec_cmd(..., shell=not _IS_UNIX)` is reached through the `_exec_cmd`
summary + Popen:95 sink entries.

## 8. Sanitizers (2 confirmed)

| API | site | verdict |
| --- | --- | --- |
| `quote` | utils/string_utils.py:131 | sanitizer/tp 0.85 — shlex.quote (POSIX) / mslex_quote (Windows); applied to MLproject declared params, entry-point script names, R model path, Databricks mlflow argv |
| `EntryPoint._sanitize_param_dict` | projects/_project_spec.py:241 | sanitizer/tp 0.8 — applies quote() to every declared/extra param value before command.format |

Caveats recorded in both rationales: the MLproject command template itself and
the unquoted extra-parameter fragments `--{key} {value}`
(_project_spec.py:236) still flow into bash -c unescaped; host/port values in
the R backend are interpolated raw. `validate_path_is_safe` /
schema-validation helpers in server/handlers.py are path-traversal guards,
not shell sanitizers (not emitted as candidates).

## 9. Quality checks (WORKFLOW §4.4.6)

1. Schema validated (inline validator implementing every constraint in
   `labels_schema.json`: required fields, enums, patterns, confidence range,
   argument-flow arg_index rule, passes-contains-pass_id=1, unique ids) — 0
   errors.
2. Pass 2 has 16 confirmed sinks — check satisfied.
3. Duplicates removed: 1293 CSV rows → 1042 unique sites (154 api/ast and
   Attribute/Attribute() same-line merges), recorded per site in
   `labels_raw_pass2.json`.
4. Argument indexes preserved from the extraction CSV convention (0-based
   positional index, this run's columnContract) and validated (int ≥ 0 for
   flow_kind=argument; null elsewhere).
