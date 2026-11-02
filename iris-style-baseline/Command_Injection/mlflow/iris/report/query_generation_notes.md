# Query Generation Notes — MLflow Pass 2 (CWE-077/078/088)

Phase 2 Step 4/5 output of the Augur 0.3.0 workflow (`iris_tools/augur-0.3.0/WORKFLOW.md`
§5.1–§5.2): rendering the reviewed Phase 1 labels into CodeQL libraries and the
formal pass-2 taint query. **No CodeQL command was executed in this step** (compile /
run / analyze / decode are deferred to the user's manual verification, per instruction).

## 1. Run identity

- run_id: `mlflow-iris-pass2-labeling-20261015` (labels), Phase 2 rendered 2026-10-15
- target: MLflow vulnerable snapshot `2.5.1.dev0`, sha
  `330bf0b38b07d4adf3fae99af1b44c8e857f514a`
  (`dataset/codeql_databases/mlflow_vuln`), CodeQL DB `mlflow-db`
- labels input: `labels/labels.json` (1044 pass-2 entries: 248 source tp / 304 source
  candidate / 16 sink tp / 3 sink candidate / 12 sink fp / 2 sanitizer tp / 16 summary
  tp / 2 summary candidate / 441 none-fp), `labels/label_stats.md`,
  `labels/labels_raw_pass2.json`
- threat model (from the label run): external input enters via (1) the Flask
  tracking/model-registry REST API and pyfunc scoring server, (2) the click CLI
  (`mlflow run` -P parameters / --docker-args), (3) untrusted project/model artifacts
  (MLproject entry-point commands, MLmodel / conda.yaml / requirements metadata) and
  (4) MLFLOW_* environment variables
- renderer: `scripts/render_libraries.py` (deterministic; every predicate pins the
  labeled (file, line) pair, or (file, function, position) for parameters). Regenerate
  with `python -I scripts/render_libraries.py`
- **Missing input reported**: `labels/review_decision.json` (listed as an input in the
  phase instructions) does not exist in the workspace — no `review_decision.json`
  exists in any prior project either (the prior runs' review record is
  `labels/phase1_review.md`, and mlflow has no such file). The labels.json
  classifications (tp / candidate / fp, with per-entry rationale and evidence) were
  therefore used as the authoritative reviewed input; no review decisions were
  invented or assumed beyond what the labels record.
- Pass 1 block in labels.json is a schema-required zero-entry stub and is deliberately
  not rendered (this run is scoped to pass 2).

## 2. Generated artifacts

| file | lines | role |
| --- | ---: | --- |
| `libraries/MySources.qll` | 2362 | source model (248 tp strict tier + 150 candidate diagnostic tier) |
| `libraries/MySinks.qll` | 204 | sink model (16 tp sites + 3 candidate diagnostic tier) |
| `libraries/MySanitizers.qll` | 93 | 2 reviewed barriers (quote, _sanitize_param_dict) |
| `libraries/MySummaries.qll` | 316 | 14 tp summary labels rendered as 13 taint-step predicates |
| `queries/Pass2_CommandInjection.ql` | 75 | formal pass-2 query (`@kind path-problem`) |

## 3. Source model — 248 tp entries (formal tier)

`MySources::isSource(node, "command_injection")` dispatches to
`isSourceStrict` = classification=tp labels only. Eight buckets:

| bucket | n | modeling basis |
| --- | ---: | --- |
| `isCliParamSource` | 98 | click CLI command/group parameters (`mlflow run` uri/entry_point/param_list/docker-args, models/gateway/sagemaker/deployments/store/recipes/auth CLI, gateway/app.py routes, click groups in experiments.py/runs.py/db.py) — pinned by (file, line, 0-based arg index, self-shifted) |
| `isHandlerParamSource` | 5 | Flask view/handler parameters (server/__init__.py, server/handlers.py) |
| `isRequestFieldSource` | 13 | `request.json/.data/.args/.form/.query_string/.content_type/.stream` attribute reads in the tracking-server / scoring-server / auth handlers — pinned by (file, line, attribute name) |
| `isRequestDecodeSource` | 54 | return values of the central request-decoding wrappers `_get_request_message` / `_get_request_json` / `parse_csv_input` / `get_json` |
| `isModelMetadataSource` | 28 | return values of `Model.load` / `load_project` / `to_dict` — MLmodel/MLproject metadata of untrusted artifacts |
| `isDecodeReturnSource` | 10 | `json.loads` / `json.load` / `yaml.safe_load` over request bodies and project/job-template YAML |
| `isFileOpenSource` | 27 | `open()` over project/model/env/requirements artifact files and scoring-server input |
| `isEnvReadSource` | 13 | MLFLOW_* env reads (`os.environ.get`/`os.getenv`, mlflow env-var registry `.get()`) + `sys.argv`/`os.environ` field reads at labeled container-entrypoint sites |

Every rule pins the labeled **(file, line)** pair (parameters additionally pin the
label's 0-based argument index; the declared position is shifted by one when the
enclosing function's first parameter is self/cls, matching the label convention that
excludes self). Generic name/derivation rules were rejected: the repository contains
far more `open()`/`loads()`/click definitions than the reviewed label set, so a
name-based rule would bind unreviewed sites.

### Candidate tier — 150 of 304 entries (NOT used by the formal query)

`isSourceDiagnostic` additionally includes `isDecodeCandidate` (72: json/yaml decode
of mixed-provenance data), `isFileOpenCandidate` (59: store/recipe/internal file
opens), `isRequestFieldCandidate` (9: `request.method`/`url_rule` routing metadata)
and `isEnvReadCandidate` (10: getenv/environ/argv reads not promoted to tp).

**Not rendered: 154 flow_kind=receiver labels** (click.option/group/command/argument
decorator calls). They are binding declarations with no data-flow node of their own;
the bound values enter through the function parameters, which are the tp
`isCliParamSource` bucket. Rendering a decorator call as a source would fabricate a
node with no taint semantics.

## 4. Sink model — 16 tp sites

`MySinks::isSink(node, "command_injection")` = `isSinkStrict`, four buckets that
separate the shell/argv execution modes exactly as the labels recorded them:

| bucket | n | sites |
| --- | ---: | --- |
| `isBashDashCElementSink` | 11 | the element at the labeled index of a `['bash'/'cmd'/'/bin/bash'/'Rscript', '-c'/'-e', command]` argv list: projects/backend/local.py:277/:280 (Popen, MLproject entry-point command), models/container/__init__.py:114/:130/:139/:203 (Popen, conda/activate/serving), pyfunc/backend.py:241 and utils/environment.py:611/:613 and projects/databricks.py:379 (list literals assigned/returned before execution), rfunc/backend.py:106 (Popen Rscript -e) |
| `isOsSystemStringSink` | 1 | sagemaker/__init__.py:158 `os.system(cmd)` — ';'/&&'-joined docker login/tag/push string |
| `isShellTrueRunSink` | 1 | models/wheeled_model.py:222 `subprocess.run([download_command], check=True, shell=True)` — the pip wheel download command including MLFLOW_WHEELED_MODEL_PIP_DOWNLOAD_OPTIONS |
| `isPopenCommandArgSink` | 3 | utils/process.py:95 (central `_exec_cmd` Popen: string or argv, shell forwarded via **kwargs, e.g. virtualenv.py:137 `shell=not _IS_UNIX`), utils/requirements_utils.py:197 (pip argv from model requirements), pyfunc/backend.py:243 (Popen of the bash -c payload list) |

Dangerous argument index per label: 0 for the single-string/forwarded-argument sinks,
2 for the bash/cmd -c list elements (the payload element), 0 for the wheeled
`run([command], shell=True)` (the list whose single element is the shell command).

Diagnostic tier (NOT used by the formal query): `isSinkDiagnostic` with the 3
candidate labels — sagemaker/__init__.py:1132 (docker run argv),
models/docker_utils.py:245 (docker build argv), gateway/runner.py:59 (gunicorn argv):
no shell, argument-level injection only.

Excluded by label review (NOT modeled): 12 fp fixed-argv/literal probes
(utils/__init__.py:206/:211, pyfunc/backend.py:282, rfunc/backend.py:86,
databricks_utils.py:178, container:175/:180/:181, recipes step.py:110, container:224)
and 23 cmd_format message rows (rationales in labels.json).

## 5. Sanitizer model — 2 barriers

- `isQuoteCallBarrier` (san-001): value of a `quote(...)` call at the reviewed
  application sites — mlflow/projects/_project_spec.py:167/:172/:241 (MLproject
  declared params, entry-point script names), mlflow/rfunc/backend.py:41/:80/:119
  (R model path), mlflow/projects/databricks.py:361 (mlflow run argv). These files
  import quote via `from mlflow.utils.string_utils import quote` (= shlex.quote on
  POSIX, mslex_quote on Windows), so a bare callee named `quote` in them is the
  barrier function; the pin is deliberately narrow so it can never hide a path
  elsewhere.
- `isSanitizeParamDictBarrier` (san-002): value of an
  `EntryPoint._sanitize_param_dict(...)` call in _project_spec.py — the
  quote()-wrapped parameter dict returned to compute_command.

Label caveats kept in the model (paths intentionally NOT blocked): the MLproject
command template itself, the unquoted extra-parameter fragments `--{key} {value}`
(_project_spec.py:236), and raw host/port interpolation in the R backend.
Scope limitation documented in the QLL: quote() also runs at
mlflow/projects/kubernetes.py:57, which the label set does not cover — that site is
not a barrier, which can only add findings, never hide a path.

## 6. Summary model — 14 of 16 tp labels rendered (13 predicates)

Each hop is pinned by (file, function name, parameter position) → (file, line) as
verified in the source tree; no edge was invented without a label:

| predicate | labels | hop |
| --- | --- | --- |
| `execCmdStep` | snk-063 | `_exec_cmd` cmd param → `subprocess.Popen(cmd)` (process.py:95) |
| `environmentExecuteStep` | snk-054 | `Environment.execute` command param (self-shifted) → bash/cmd list elements (environment.py:611/:613) |
| `runEntryPointStep` | snk-060 | `_run_entry_point` command param → bash/cmd elements (local.py:277/:280) |
| `runMlflowRunCmdStep` | snk-057 | `_run_mlflow_run_cmd` argv param → the two Popen sites (local.py:252/:259, non-shell) |
| `joinCommandsStep` | snk-066+067 | `_join_commands` *commands param → the returned `[*entry_point, sep.join(...)]` list value (process.py:124) — arg→return hop |
| `pyfuncServeStep` | snk-028 | `PyFuncBackend.serve` model_uri param → Popen(command) (pyfunc/backend.py:243) — the get_cmd() cross-function return is not natively tracked, this edge carries it |
| `servePyfuncContainerStep` | snk-021 | `_serve_pyfunc` model param → '/bin/bash -c' element (container/__init__.py:203) |
| `installPyfuncDepsStep` | snk-014 | `_install_pyfunc_deps` model_path param → conda/activate elements (container:114/:130/:139) |
| `rfuncExecuteStep` | snk-036 | `_execute` command param → 'Rscript -e' element (rfunc/backend.py:106) |
| `databricksRunCmdStep` | snk-047 | `_get_databricks_run_cmd` param → ['bash','-c',shell_command] element (databricks.py:379) |
| `pushImageToEcrStep` | snk-004 | `push_image_to_ecr` image param → `os.system(cmd)` (sagemaker/__init__.py:158) |
| `requirementsRunCommandStep` | snk-068 | `_run_command` cmd param → Popen(cmd) (requirements_utils.py:197) |
| `downloadWheelsStep` | snk-090 | `_download_wheels` pip_requirements_path param (cls-shifted) → run([download_command], shell=True) (wheeled_model.py:222) |

Within-function hops are also covered by native local dataflow; they are rendered
anyway because the labels model them explicitly. Recorded but NOT rendered (no edge
invented, documented in the QLL): snk-026 `_serve_mleap` (no taint-carrying
parameter; its exec site :224 is a reviewed fp of fixed literals) and snk-074
`Runner.start` (takes only self; carriers are CLI-set fields already covered by
`isCliParamSource`; terminal is a diagnostic-only sink). The 2 candidate summary
labels (snk-010 run_local, snk-052 _build_image_from_context) are also documented,
not rendered.

## 7. Formal query

`queries/Pass2_CommandInjection.ql` follows `assets/taint_query.ql.tmpl` rendered
with concrete values (no placeholders remain):

- `@kind path-problem` + `@problem.severity error` + `@precision low` + CWE-077/078/088
  tags, id `py/augur/mlflow/pass2-command-injection`
- imports `python`, `semmle.python.dataflow.new.DataFlow`,
  `semmle.python.dataflow.new.TaintTracking` and the four libraries
  (`libraries.MySources` … resolve against the existing `iris/mlflow-cwe78` qlpack
  root; qlpack.yml untouched)
- `module Pass2Config implements DataFlow::ConfigSig` wires
  `isSource/isSink/isBarrier/isAdditionalFlowStep` to the four library modules with
  passKey `"command_injection"`; `module Pass2Flow = TaintTracking::Global<Pass2Config>`
  + `import Pass2Flow::PathGraph`
- `from Pass2Flow::PathNode source, Pass2Flow::PathNode sink where
  Pass2Flow::flowPath(source, sink) select sink.getNode(), source, sink, message,
  source, "untrusted source", sink, "execution sink"` — the standard path-problem
  select shape; `@kind path-problem` + PathGraph is what makes SARIF path export
  (`codeql database analyze --format=sarif-latest`) produce full path messages
- no `API::Node` value is ever assigned to a `DataFlow::Node` variable (all library
  predicates are built from AST constructs via `DataFlow::exprNode` /
  `DataFlow::parameterNode`)

## 8. Verification performed (no CodeQL)

- `scripts/check_ql_balance.py`: brace/paren balance after comment/string stripping —
  all 5 files balanced
- `scripts/check_ql_pins.py`: every pinned rule resolved against the
  mlflow_vuln tree — 448 pins (call/attribute/list-literal/parameter/function
  signatures) verified: the pinned file exists, the pinned line exists, the pinned
  callable/attribute name occurs at that line (calls may span lines), list pins land
  on list literals, parameter pins land inside the def signature; 98 distinct files
  pinned, all under `mlflow/` (no dev/, examples/, tests/ or setup.py — those were
  fp-rejected in the labels)
- API idioms reused verbatim from the langchain run that compiled clean on the same
  pack (`codeql/python-all` 7.1.2): `DataFlow::exprNode/parameterNode`,
  `DataFlow::ConfigSig` + `TaintTracking::Global<...>` + `PathGraph` +
  `flowPath(source, sink)`, `Call.getPositionalArg(0)`, `List.getElt(i)`,
  `Parameter.getPosition()/isSelf()`, `Function.getArg(i)`,
  `Location.getFile().getRelativePath()`, `getStartLine()`. Two python-all 7.1.2
  pitfalls from the maltrail run were designed around: `Mod` is an operator class
  (not used here - the mlflow labels have no %-format sink family) and top-level
  scripts have no module name (all mlflow pins use file paths, not module names)
- each QLL module carries its own private `calledNameOf`/`labeledParam` helpers
  (private members are module-scoped; sharing them across modules would not compile)

## 9. Constraints honored

- no CodeQL compile/run/analyze/decode was executed
- no PyVul ground truth (cmd_sinks CSVs, confirmed_vulns.json, CVE/patch material)
  was consulted; every rule traces to a labels.json entry and every pin to the
  reviewed source location
- no rule was added or adjusted toward any known vulnerability location — the model
  is a direct rendering of the reviewed label set
- source tree, database, Augur installation and `qlpack.yml` were not modified;
  written files: `libraries/My{Sources,Sinks,Sanitizers,Summaries}.qll`,
  `queries/Pass2_CommandInjection.ql`, `report/query_generation_notes.md`,
  `scripts/render_libraries.py`, `scripts/check_ql_balance.py`,
  `scripts/check_ql_pins.py`

## 10. Regeneration

```
cd C:\Users\lzh\Desktop\github\PyVul-main\iris_manual\mlflow\iris
python -I scripts/render_libraries.py     # rebuilds the 4 QLLs (query is rendered too)
python -I scripts/check_ql_balance.py     # brace/paren sanity
python -I scripts/check_ql_pins.py        # pin verification against the tree
```

Expected manual next step (user-run, out of scope here):
`codeql query compile queries/Pass2_CommandInjection.ql`.
