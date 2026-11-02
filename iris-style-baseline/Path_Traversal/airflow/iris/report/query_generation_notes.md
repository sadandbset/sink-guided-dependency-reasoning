# Augur Phase 2 Step 4 — Query Generation Notes (Pass 1: Path Traversal)

**Target:** Apache Airflow 2.7.0.dev0 (sha 2811ba7), Python, flask/flask_appbuilder + connexion + argparse.
**Generated:** 2026-10-21. **Artifacts:** `libraries/MySources.qll`, `libraries/MySinks.qll`,
`libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass1_PathTraversal.ql`.

Inputs: the reviewed Pass 1 label set `iris/labels/labels.json` (3291 entries; 631 role=source,
269 role=sink, 54 role=summary, 0 role=sanitizer) and its audit trail
(`labels_raw_pass1.json`, `label_stats.md`, `phase1_review.md`).
`labels/review_decision.json` was **not present** on disk; the operator's explicit instruction
to execute Step 4–5 is recorded here as the checkpoint approval (WORKFLOW §4.5, automated-mode
behavior). Labels were treated as read-only: no entry was added, removed or reclassified; the
two rendering-level corrections below only affect how an unchanged label is expressed in QL
and are fully documented.

The four libraries were deterministically rendered from `labels.json` (group by role,
deduplicate signatures, stable ordering, machine-generated headers — WORKFLOW §5.1.4) by
`.step4_work/gen_qll.py`. All predicates use the unified pass key `"path_traversal"` and the
local CodeQL Python modular API (`DataFlow::ConfigSig`, `TaintTracking::Global`,
`Flow::PathGraph`, `flowPath`), verified against the locally resolved pack
`codeql/python-all 7.1.2` (+ `codeql/dataflow 2.1.7`): `DataFlow::exprNode(Expr)`,
`DataFlow::parameterNode(Parameter)`, `Call.getPositionalArg(int)`, `Function.getArg/getAnArg/
getAKeywordOnlyArg/getADecorator`, `Parameter.getName/isSelf`, `Location.getFile/getStartLine`,
`File.getAbsolutePath`. Per the task instructions, no query was compiled or executed in this step.

---

## 1. Label-ID → QLL predicate mapping

| labels | role | count | rendered as (file : predicate) | evidence anchor |
|---|---|---|---|---|
| P1-S-0013..P1-S-1648 | source | 204 | MySources: `flaskRequestAttrSource` | request-proxy attribute reads (`request.args` etc.) in the 18 boundary files listed in §2 |
| P1-S-0012..P1-S-1649 | source | 164 | MySources: `flaskRequestCallSource` | `request.<field>.get/getlist/items`, `request.get_json`, `accept_mimetypes.best_match` |
| P1-S-1115..P1-S-1639 | source | 62 | MySources: `handlerParamSource` (FAB @expose/@action + flask @route branch) | decorated views in `airflow/www/**` and `airflow/utils/serve_logs.py` |
| P1-S-0026..P1-S-0311 | source | 169 | MySources: `handlerParamSource` (connexion branch) | 63 OpenAPI operationIds (names cross-checked against `api_connexion/openapi/v1.yaml`) |
| P1-S-0110..P1-S-1618 | source | 19 | MySources: `requestWrapperCallSource` | `get_json_request_dict` (→`request.get_json()`, request_dict.py:22-26) + FAB urltools |
| P1-S-0016..P1-S-1622 | source | 11 | MySources: `requestDerivedLoadsSource` | 11 audited (file,line) sites — see §2 |
| P1-S-0120, P1-S-0169 | source/candidate | 2 | MySources: `signedTokenLoadsSource` | dag_source_endpoint.py:37, log_endpoint.py:64 — see §2 |
| P1-K-0006..P1-K-0658 | sink | 107 | MySinks: `builtinOpenSink` (arg 0) | every `open(...)` builtin call in the deployed tree |
| P1-K-0084..P1-K-0622, P1-K-0085..P1-K-0623 | sink | 30 | MySinks: `moduleQualifiedFsSink` — `os.chmod/listdir/makedirs/readlink/remove/stat/symlink/unlink/walk` (arg 0) | module-qualified `os.*` calls |
| P1-K-0081, P1-K-0296, P1-K-0179..P1-K-0497 | sink | 10 | MySinks: `moduleQualifiedFsSink` — `shutil.copy/move/rmtree` (arg 0) | module-qualified `shutil.*` calls |
| P1-K-0091..P1-K-0579 | sink | 4 | MySinks: `moduleQualifiedFsSink` — `zipfile.ZipFile` (arg 0) | DAG-archive opens |
| P1-K-0631, P1-K-0656 | sink | 2 | MySinks: `sendFromDirectorySink` (arg 1) | serve_logs.py:109, views.py:4088 |
| P1-K-0138, P1-K-0173 | sink | 2 | MySinks: `sourceFileLoaderSink` (arg 1) | dagbag.py:341, plugins_manager.py:254 |
| P1-K-0193, P1-K-0325 | sink | 2 | MySinks: `gzipOpenSink` (arg 0) | s3.py:1068, gcs.py:535 (`import gzip as gz`) |
| P1-K-0059..P1-K-0627 | sink | 32 | MySinks: `receiverPathMethodSink` (receiver node) | audited pathlib receiver sites — appendix B |
| P1-K-0005..P1-K-0630 | sink | 79 | MySinks: `wrapperParamSink` (parameter node) | audited wrapper functions — appendix A |
| 48 Path-constructor labels | summary | 48 | MySummaries: `pathConstructorStep` | `Path(x)` arg 0 → Path object, deployed tree |
| P1-K-0128, P1-K-0135 | summary | 2 | MySummaries: `pathRelativizationStep` | dag.py:1287/3520 `Path(self.fileloc).relative_to(...)` receiver→result |
| P1-K-0141, P1-K-0557, P1-K-0612 | summary | 3 | MySummaries: `pathTransformerStep` | correct_maybe_zipped (via P1-K-0141 rationale), process_subdir (P1-K-0557), add_triggerer_suffix (P1-K-0612): param→return |
| P1-K-0169 | summary | 1 | covered by `pathConstructorStep` + default flow | python.py:673 `python_path = Path(self.python)`; forwarding to the subprocess argument is default interprocedural flow — no extra edge |
| (none) | sanitizer | 0 | MySanitizers: `isBarrier = none()` | see §5 |

Coverage accounting: 269 sink labels = 107 open + 30 os + 10 shutil + 4 zipfile + 2
send_from_directory + 2 SourceFileLoader + 2 gz.open + 32 receiver + 79 wrapper + 1 documented
skip (P1-K-0201, sagemaker.py:173 `tarfile.open(mode="w:gz", fileobj=temp_file)`: a real
archive write whose path position does not exist — the only argument is the `fileobj` keyword
holding a `tempfile.TemporaryFile` object, so there is no dangerous path argument to model;
the label's classification and rationale already record "no path argument at this call site").

## 2. Source boundaries and access conditions

All 631 source entries are request-reachable external boundaries; none is an internal helper
parameter, env/config read, or CLI operator input (those 1189 rows were labeled none/fp in
Pass 1 and are intentionally absent from `MySources` — in particular no
`file_handler(path)`-style wrapper parameter was promoted to a source).

| boundary | access conditions (verified in code / labels) |
|---|---|
| flask request attrs & field calls (368 entries) | FAB web UI + connexion REST + experimental API + serve-logs + auth backends. Permission gates exist per-view (`@auth.has_access`, `security.requires_access`) but the *data* is attacker-supplied post-auth. The 3 collision rows (dbt `PreparedRequest`, labeled none/fp) are excluded by the `inRequestBoundaryCode` file constraint. |
| FAB/flask route params (62) | route variables of `@expose/@action/@route` views; `self` and `@provide_session`-injected `session` excluded by name/predicate. serve_logs_view's `filename` is the `/log/<path:filename>` converter value (slashes allowed) — guarded by JWT-filename equality (see §5). |
| connexion handler params (169) | injected from OpenAPI path/query per `v1.yaml`; `session` excluded. |
| `get_json_request_dict`/urltools (19) | REST v1 JSON body + FAB pagination/order query args. |
| request-derived `json.loads` (11 sites) | trigger_dag.py:82 (conf from API trigger bodies), common_schema.py:182 + dag_run_schema.py:48 (marshmallow `_deserialize` of request payloads), decorators.py:68 (request.values/view_args items), forms.py:153 + validators.py:77 (WTForms fields), views.py:1598/2110/4769/5170 (query args, trigger form, connection form, varimport multipart body), fab_security/manager.py:731 (Azure OIDC id_token payload — external IdP-signed, candidate-classified). |
| signed-token loads (2, candidate) | dag_source_endpoint.py:37 `auth_s.loads(file_token)` (SECRET_KEY-signed; minted from DagModel.fileloc), log_endpoint.py:64 (SECRET_KEY-signed metadata). Included because the audited role is `source`; Phase 2 triage must weigh the SECRET_KEY boundary (phase1_review.md HR-2/HR-6). |

## 3. Dangerous sinks (real file operations, positions, access types)

- **open (arg 0, 107):** read/write/append opens across the deployed tree — CLI import/export
  (`variable_command.py:84/106`...), `FileTaskHandler._init_file` log creation
  (file_task_handler.py:480), `DagCode._get_code_from_file` via `open_maybe_zipped`
  (utils/file.py:195), config/secrets readers, provider hook local files
  (samba.py:247, gcs.py:534, cloud_sql.py:535...). Access types: read, write, append-create.
- **os.* / shutil.* (arg 0, 40):** remove/unlink (deletes: task_command.py:388,
  base_task_runner.py:186), rmtree (8, log-dir cleanup in remote task handlers + cloud_sql),
  walk/makedirs/listdir/stat/chmod/symlink/readlink/move/copy. Notably
  `os.symlink` (file_processor_handler.py:124/130) creates the `latest` log symlink guarded by
  an `os.readlink` comparison.
- **zipfile.ZipFile (arg 0, 4):** DAG archive opens (dagbag.py:381, dag_processing/manager.py:779,
  processor.py:200, utils/file.py:192) — archive reads of deployment-trust paths.
- **send_from_directory (arg 1, 2):** serve_logs.py:109 (request-derived filename — the main
  file-response sink) and views.py:4088 (fixed `"robots.txt"` literal, static folder).
- **SourceFileLoader (arg 1, 2):** dagbag.py:341 and plugins_manager.py:254 — file *execution*
  of DAG/plugin files (scheduler-side, config-trust input).
- **gz.open (arg 0, 2):** s3.py:1068 / gcs.py:535 gzip sidecar writes during upload/download.
- **receiver-path methods (32, receiver node):** `Path(...).read_text/read_bytes/write_text/
  write_bytes/mkdir/glob/chmod/open` — the actual task-log read chain
  (file_task_handler.py:492 `parent.glob`, :496 `read_text`, :447/:451 mkdir/chmod),
  `Path(...).open()` member reads (utils/file.py:192/360, providers_manager.py:137/148,
  dbt.py:264), operator temp-dir mkdirs. The *path object* is the sink position; the file
  object produced by `.open()` is never treated as the sink.
- **wrapper params (79, parameter node):** the audited functions whose parameter provably
  flows into a file-operation path (appendix A): `serve_logs_view(filename)`,
  `open_maybe_zipped(fileloc)`, `FileTaskHandler._read(ti)/_init_file(ti)/set_context(ti)`,
  `_find_path_from_directory(base_dir_path)`, CLI import/export/daemon handlers (`args`),
  provider hooks (`retrieve_file/store_file/upload/get_file/push_from_local/...`),
  `ImapHook._create_file(name, payload, local_output_directory)`, etc. Rendering anchors each
  Function by (file, def-line) and the parameter **by name**, resolved from the real def
  signature (see §7 for the index conventions and the three static-method cases).

## 4. Path construction/decoding/normalization, roots and symlinks — evidence

- werkzeug decodes the URL path before the `<path:filename>` converter delivers it;
  `send_from_directory` then applies `werkzeug.utils.safe_join` (root containment) —
  framework behavior, recorded as site-level containment in the sink rationale of P1-K-0631
  (not modeled as a barrier; see §5).
- Path joins in the audited flows: `os.path.join(local_base, rendered_rel_path)`
  (file_task_handler.py:472), `Path(self.local_base, worker_log_rel_path)` (:322),
  `local_output_directory + "/" + name` (imap.py:261), `Path(temp_dir) / blob`
  (gcs.py:790), `os.path.join(base, subdir)` (s3.py:1393). None of these normalize `..`,
  so the sink labels keep the join results fully taint-relevant.
- No `os.path.normpath` exists anywhere in the snapshot; `abspath/realpath/resolve/
  relative_to` occur only as scheduler-side canonicalization (dag.py:1287/3520,
  utils/file.py) — modeled as propagation/summary steps, never as barriers.
- Allowed-root checks: the only root checks that actually execute before file access are
  werkzeug `safe_join` (serve-logs) and the JWT token-filename equality; the imap
  `"../" in name` blacklist and `os.path.islink(name)` check (imap.py:242-252) run before
  `_create_file` but are incomplete (Windows separators, absolute names, islink checks the
  CWD-relative name, not the output path) — neither is modeled as a barrier.
- Symlinks: `_find_path_from_directory` walks with `followlinks=True` but detects revisits
  (raises RuntimeError); the only `os.symlink` writes are scheduler-internal and readlink-
  compared (file_processor_handler.py:122-130). No user-controlled symlink race on the
  request surface — recorded as not applicable.

## 5. Barrier analysis (why `isBarrier = none()`)

No audited label carries the sanitizer role, and none of the observed guards was proven to
neutralize traversal in this concrete implementation:

- serve-logs JWT equality + `safe_join`: not extracted as candidate rows (framework code,
  `before_request` hook); their effect is documented at the sink (P1-K-0631) and flagged as
  human-review point HR-1 — modeling them as barriers would require inventing nodes outside
  the audited label set, which the task forbids.
- imap `"../"` blacklist: demonstrably incomplete (backslash separator variant, absolute
  names) — a blacklist is not a proven barrier (review rule #6).
- file_processor_handler startswith remap: operates on non-normalized strings and remaps
  scheduler-internal paths rather than validating a user-supplied path.
Per the "no unevidenced sanitizer" rule, `MySanitizers::isBarrier` resolves to `none()`; the
Pass1Config still delegates to it so the required hook exists (WORKFLOW §5.2.3).

## 6. Additional propagation edges (MySummaries) — necessity

- `Path(x)` arg0 → Path object (48 labels): **necessary** — receiver-method sinks take the
  Path *object*; without this step tainted path text would stop at the constructor.
- dag.py:1287/3520 `relative_to` receiver→result: **necessary** — method-call
  receiver→result is not default flow; keeps DB-stored fileloc taint flowing into the
  returned relative path.
- `correct_maybe_zipped` param→return: **necessary** — the redirect through
  `ZIP_REGEX.search(str(fileloc)).groups()` is not default-modeled. Rendered from the audited
  P1-K-0141 rationale (collect_dags: "dag_folder ... transformed by correct_maybe_zipped").
  `correct_maybe_zipped` itself has no label row because `zipfile.is_zipfile` is a probe, not
  a file access, so the Step-2 extractor never emitted it as a wrapper — this is a rendering
  of reviewed evidence, not a new label.
- `process_subdir` (P1-K-0557) and `add_triggerer_suffix` (P1-K-0612) param→return:
  **necessary** — both return derived paths through transformations
  (abspath/expanduser/substitution; as_posix + suffix) that default flow may miss.
- P1-K-0169 (`ExternalPythonOperator.execute_callable`): covered by the Path-constructor step
  (`Path(self.python)`) + default flow to the subprocess argument; no extra edge emitted.
- collect_dags forwarding to `list_py_file_paths`/`process_file`: default interprocedural
  flow already covers argument→parameter; no arbitrary edges were introduced anywhere.

## 7. Rendering decisions and label-fidelity notes

1. **Package mislabels (5 rows):** P1-K-0085/0224/0298/0623 (`os.chmod`) and P1-K-0605
   (`os.unlink`) were emitted by the Step-3 forks with signature package `pathlib`, but their
   rationales and the real code show module-qualified `os.chmod`/`os.unlink` calls
   (configuration.py:1560, beam.py:764, cloud_sql.py:545, file_processor_handler.py:123,
   file_task_handler.py:482). They are rendered in the `os` member branch. The labels
   themselves were not modified.
2. **Static-method parameter indexing (3 rows):** label arg_index counts positions
   *excluding self*; for `webserver_command._get_file_hash(fname)`,
   `pod_generator.deserialize_model_file(path)`, `file_task_handler._read_from_local
   (worker_log_path)` the recorded type hint is the enclosing class but these are
   `@staticmethod`s with no `self` — the renderer verifies the real def signature and indexes
   without the self-adjustment. All 79 wrapper labels resolved successfully against the real
   signatures (0 unresolved).
3. **P1-K-0201 (tarfile.open with fileobj only):** rendered nowhere — no positional path
   argument exists at that call site (see §1 accounting).
4. **Template adaptation:** `assets/taint_query.ql.tmpl` uses one `{{SOURCE_MODULE}}`
   placeholder for both the import and the qualified reference; the import needs
   `libraries.MySources` (file path) while the reference needs `MySources::isSource` (module
   name). The query follows the task's structure requirements: `import libraries.MySources`
   + `MySources::isSource(...)`. All other template placeholders are substituted verbatim
   (query id `py/augur/airflow/pass1-path-traversal`, `@kind path-problem`,
   `@problem.severity error`, `@precision medium`, CWE 022/023/036/073 tags).
5. **No label omissions found:** every role=source/sink/summary entry maps to a predicate
   case or a documented skip; nothing was sent back for re-review.
6. **Check-only compilation fixes (2026-10-21):** a `codeql query compile --check-only` pass
   surfaced two QL-level defects in the generated libraries, both fixed in the generator
   (`.step4_work/gen_qll.py`) and re-rendered: (a) the `isSource`/`isSink`/
   `isAdditionalTaintStep` or-blocks ended with `);` — QL formulas take no statement
   semicolons (only `module X = ...;` aliases do) — the stray `;` was removed; (b) the
   `atSite` location-anchor predicates used their `string` parameter inside a string
   concatenation (`"%/" + file`), and QL binding analysis does not treat predicate
   parameters as bound in the body — the predicates now declare `bindingset[site, line]`
   (all call sites pass literal site paths and line numbers, verified) and the parameter
   was renamed `site`. After the fix, `codeql query compile --check-only
   queries/Pass1_PathTraversal.ql` completes with no errors or warnings. No label was
   touched by either fix; both are pure QL-syntax/rendering corrections.

## 8. Known limitations, dynamic/alias gaps, diagnostics (not part of formal results)

- **`Path.parent` flow:** receiver sinks like `worker_log_path.parent.glob(...)`
  (file_task_handler.py:492) take the `.parent` attribute as receiver; taint through
  `Path.parent` is not default-modeled and no summary label exists for it — flows that need
  the parent hop may be under-reported (Phase 2 triage note, matches phase1_review HR-3's
  DB-hop indirection anyway).
- **Dynamic/aliased wrappers:** `str`-level joins (`local_output_directory + "/" + name`,
  imap.py:261) are default-flow; string concatenation into paths is covered, but dict-key
  indirection (e.g. `metadata` dict fields) relies on CodeQL's container modeling.
- **`gz` alias:** modeled by location anchoring (s3.py:1068, gcs.py:535) rather than import
  resolution, per the audited sites.
- **Diagnostics (advisory, not formal Pass 1 alerts):** a diagnostics query selecting
  `MySinks::isSink(n, "path_traversal")` / `MySources::isSource(n, "path_traversal")` match
  counts per file (and each wrapper predicate's resolved sites) can be written separately to
  sanity-check rendering coverage (269/631 expected) before the Step-5 run; per the task,
  only the six listed files were produced, so this remains a recommendation.
- **CodeQL API pinning:** verified against the locally resolved `codeql/python-all 7.1.2`
  and `codeql/dataflow 2.1.7` (the WORKFLOW's validated baseline was 6.1.x; the newer pack
  keeps `DataFlow::ConfigSig` / `TaintTracking::Global<Config>` / `PathGraph` /
  `flowPath` compatible). `codeql pack install` and the sequential Step-5 executions were
  intentionally NOT run in this step.

## 9. Experiment independence

No PyVul ground truth, CVE advisories, or patch diffs were consulted; the model derives
exclusively from the audited Pass 1 labels and the airflow_vuln source tree. The source tree,
the CodeQL database (`airflow-db`), the Augur installation, and the Phase 1 artifacts
(labels.json, CSVs) were not modified; intermediate generation scripts live under
`../.step4_work/` outside the `iris/` tree.

---

## Appendix A — wrapper-parameter sinks (79 labels; function anchored by file:def-line, parameter by resolved name)

| label | site | function | param | audited rationale (abridged) |
|---|---|---|---|---|
| P1-K-0005 | airflow/cli/commands/celery_command.py:46 | `flower` | `args` | CLI daemon handler opens log files whose paths come from setup_locations(process="flower", pid=args. |
| P1-K-0007 | airflow/cli/commands/celery_command.py:133 | `worker` | `args` | CLI daemon handler: setup_locations(WORKER_PROCESS_NAME, pid=args.pid, stdout=args.stdout, stderr=ar |
| P1-K-0011 | airflow/cli/commands/dag_processor_command.py:56 | `dag_processor` | `args` | CLI daemon handler: setup_locations("dag-processor", args.pid, args.stdout, args.stderr, args.log_fi |
| P1-K-0019 | airflow/cli/commands/internal_api_command.py:61 | `internal_api` | `args` | CLI daemon handler: setup_locations("internal-api", args.pid, args.stdout, args.stderr, args.log_fil |
| P1-K-0021 | airflow/cli/commands/kerberos_command.py:30 | `kerberos` | `args` | CLI daemon handler: setup_locations("kerberos", args.pid, args.stdout, args.stderr, args.log_file) t |
| P1-K-0023 | airflow/cli/commands/kubernetes_command.py:38 | `generate_pod_yaml` | `args` | CLI --output-path flows directly into file operations: yaml_output_path = args.output_path is used i |
| P1-K-0026 | airflow/cli/commands/pool_command.py:102 | `pool_import_helper` | `filepath` | open(filepath) reads the pool import file; the filepath parameter (CLI import path) is the file path |
| P1-K-0028 | airflow/cli/commands/pool_command.py:122 | `pool_export_helper` | `filepath` | open(filepath, "w") writes the pool export file; the filepath parameter (CLI export path) is the fil |
| P1-K-0030 | airflow/cli/commands/role_command.py:154 | `roles_export` | `args` | open(os.path.expanduser(args.file), "w") writes the roles export file; the args parameter (CLI --fil |
| P1-K-0032 | airflow/cli/commands/role_command.py:175 | `roles_import` | `args` | open(json_file) reads the roles import file; json_file = args.file (CLI --file import path) is the f |
| P1-K-0034 | airflow/cli/commands/scheduler_command.py:46 | `scheduler` | `args` | CLI daemon handler: setup_locations("scheduler", args.pid, args.stdout, args.stderr, args.log_file)  |
| P1-K-0039 | airflow/cli/commands/task_command.py:351 | `task_run` | `args` | open(args.cfg_path) reads and os.remove(args.cfg_path) deletes the task runtime config file; the arg |
| P1-K-0042 | airflow/cli/commands/triggerer_command.py:54 | `triggerer` | `args` | CLI daemon handler: setup_locations("triggerer", args.pid, args.stdout, args.stderr, args.log_file)  |
| P1-K-0044 | airflow/cli/commands/user_command.py:156 | `users_export` | `args` | open(args.export, "w") writes the users export file; the args parameter (CLI --export path) controls |
| P1-K-0046 | airflow/cli/commands/user_command.py:185 | `users_import` | `args` | open(json_file) reads the users import file; json_file = args.import (CLI --import path, accessed vi |
| P1-K-0048 | airflow/cli/commands/variable_command.py:82 | `_import_helper` | `filepath` | open(filepath) reads the variables import file; the filepath parameter (CLI import path) is the file |
| P1-K-0050 | airflow/cli/commands/variable_command.py:106 | `_variable_export_helper` | `filepath` | open(filepath, "w") writes the variables export file; the filepath parameter (CLI export path) is th |
| P1-K-0054 | airflow/cli/commands/webserver_command.py:125 | `_get_file_hash` | `fname` | open(fname, "rb") hashes a file by path; the fname parameter is the file path (static method, no sel |
| P1-K-0056 | airflow/cli/commands/webserver_command.py:323 | `webserver` | `args` | CLI daemon handler: setup_locations("webserver", args.pid, args.stdout, args.stderr, args.log_file)  |
| P1-K-0072 | airflow/configuration.py:1441 | `_parameterized_config_from_template` | `filename` | open(path) reads a config template whose path is derived from the filename parameter via _default_co |
| P1-K-0082 | airflow/configuration.py:1557 | `make_group_other_inaccessible` | `file_path` | os.stat(file_path) and os.chmod(file_path, ...) operate on the file_path parameter; the parameter is |
| P1-K-0090 | airflow/dag_processing/manager.py:770 | `_iter_dag_filelocs` | `fileloc` | zipfile.ZipFile(fileloc) opens the DAG archive by the fileloc parameter (nested helper iterating sel |
| P1-K-0118 | airflow/kubernetes/pod_generator.py:517 | `deserialize_model_file` | `path` | open(path) reads a pod template YAML by the path parameter (os.path.exists(path) guards it); callers |
| P1-K-0137 | airflow/models/dagbag.py:339 | `parse` | `filepath` | importlib.machinery.SourceFileLoader(mod_name, filepath) followed by loader.exec_module(new_module)  |
| P1-K-0139 | airflow/models/dagbag.py:377 | `_load_modules_from_zip` | `filepath` | zipfile.ZipFile(filepath) opens the DAG zip archive by the filepath parameter (position 0 after self |
| P1-K-0158 | airflow/operators/python.py:375 | `_write_args` | `file` | file.write_bytes(...) writes the pickled operator arguments; the file parameter (a pathlib.Path, pos |
| P1-K-0160 | airflow/operators/python.py:379 | `_write_string_args` | `file` | file.write_text(...) writes the string args file; the file parameter (a pathlib.Path, position 0 aft |
| P1-K-0162 | airflow/operators/python.py:382 | `_read_result` | `path` | path.stat() and path.read_bytes() read the subprocess result file; the path parameter (a pathlib.Pat |
| P1-K-0164 | airflow/operators/python.py:395 | `_execute_python_callable_in_subprocess` | `tmp_dir` | open(termination_log_path) reads the subprocess error log; the path is built as tmp_dir / "terminati |
| P1-K-0174 | airflow/providers/alibaba/cloud/log/oss_task_handler.py:80 | `set_context` | `ti` | open(self.handler.baseFilename, "w") truncates the task log file whose path was rendered from the ti |
| P1-K-0191 | airflow/providers/amazon/aws/hooks/s3.py:1030 | `load_file` | `filename` | open(filename, "rb") (gzip branch) reads the local file to upload, and client.upload_file(filename,  |
| P1-K-0194 | airflow/providers/amazon/aws/hooks/s3.py:1337 | `download_file` | `local_path` | open(file_path, "wb") and file_path.parent.mkdir() write the downloaded file; file_path = Path(local |
| P1-K-0198 | airflow/providers/amazon/aws/hooks/sagemaker.py:161 | `tar_and_s3_upload` | `path` | os.path.isdir(path)/os.listdir(path)/os.path.join(path, name) enumerate the local directory and tar_ |
| P1-K-0204 | airflow/providers/amazon/aws/log/s3_task_handler.py:74 | `set_context` | `ti` | open(self.handler.baseFilename, "w") truncates the task log file whose path was rendered from the ti |
| P1-K-0221 | airflow/providers/apache/beam/operators/beam.py:762 | `_make_executable` | `path` | _make_executable(path) performs os.stat(path) and os.chmod(path, ...) with the path directly taken f |
| P1-K-0232 | airflow/providers/apache/hive/hooks/hive.py:964 | `to_csv` | `csv_filepath` | HiveServer2Hook.to_csv(sql, csv_filepath, ...) writes results via open(csv_filepath, 'w') and cleans |
| P1-K-0235 | airflow/providers/apache/hive/transfers/s3_to_hive.py:236 | `_get_top_row_as_list` | `file_name` | S3ToHiveOperator._get_top_row_as_list(self, file_name) opens file_name directly: open(file_name) - p |
| P1-K-0237 | airflow/providers/apache/hive/transfers/s3_to_hive.py:262 | `_delete_top_row_and_compress` | `input_file_name` | static _delete_top_row_and_compress(input_file_name, output_file_ext, dest_dir) opens input_file_nam |
| P1-K-0243 | airflow/providers/cncf/kubernetes/decorators/kubernetes.py:54 | `_read_file_contents` | `filename` | module-level _read_file_contents(filename) reads the file with open(filename, 'rb') - parameter-cont |
| P1-K-0266 | airflow/providers/docker/decorators/docker.py:55 | `_b64_encode_file` | `filename` | module-level _b64_encode_file(filename) reads the file with open(filename, 'rb') - parameter-control |
| P1-K-0275 | airflow/providers/ftp/hooks/ftp.py:114 | `retrieve_file` | `local_full_path_or_buffer` | FTPHook.retrieve_file(remote_full_path, local_full_path_or_buffer, ...) writes the downloaded file w |
| P1-K-0277 | airflow/providers/ftp/hooks/ftp.py:192 | `store_file` | `local_full_path_or_buffer` | FTPHook.store_file(remote_full_path, local_full_path_or_buffer, ...) reads the local source with ope |
| P1-K-0321 | airflow/providers/google/cloud/hooks/functions.py:133 | `upload_function_zip` | `zip_path` | CloudFunctionsHook.upload_function_zip(location, zip_path, project_id) opens the local archive with  |
| P1-K-0323 | airflow/providers/google/cloud/hooks/gcs.py:453 | `upload` | `filename` | GCSHook.upload(bucket_name, object_name, filename, ...) when gzip is set performs open(filename, 'rb |
| P1-K-0404 | airflow/providers/google/common/utils/id_token_credentials.py:77 | `_load_credentials_from_file` | `filename` | module-level _load_credentials_from_file(filename, target_audience) checks os.path.exists(filename)  |
| P1-K-0406 | airflow/providers/google/marketing_platform/operators/analytics.py:438 | `_modify_column_headers` | `tmp_file_location` | GoogleAnalyticsModifyFileHeadersDataImportOperator._modify_column_headers(self, tmp_file_location, c |
| P1-K-0427 | airflow/providers/imap/hooks/imap.py:262 | `_create_file` | `name` | ImapHook._create_file(self, name, payload, local_output_directory) builds file_path = local_output_d |
| P1-K-0433 | airflow/providers/microsoft/azure/hooks/data_lake.py:416 | `upload_file` | `file_path` | AzureDataLakeStorageV2Hook.upload_file(file_system_name, file_name, file_path, ...) reads the local  |
| P1-K-0435 | airflow/providers/microsoft/azure/hooks/data_lake.py:435 | `upload_file_to_directory` | `file_path` | AzureDataLakeStorageV2Hook.upload_file_to_directory(file_system_name, directory_name, file_name, fil |
| P1-K-0437 | airflow/providers/microsoft/azure/hooks/wasb.py:295 | `load_file` | `file_path` | WasbHook.load_file(file_path, container_name, blob_name, ...) reads the local source with open(file_ |
| P1-K-0439 | airflow/providers/microsoft/azure/hooks/wasb.py:349 | `get_file` | `file_path` | WasbHook.get_file(file_path, container_name, blob_name, ...) downloads a blob and writes it with ope |
| P1-K-0448 | airflow/providers/microsoft/azure/transfers/oracle_to_azure_data_lake.py:84 | `_write_temp_file` | `path_to_save` | Operator wrapper: path_to_save parameter flows directly into builtin open(path_to_save, 'w') which w |
| P1-K-0452 | airflow/providers/openlineage/plugins/adapter.py:99 | `_read_yaml_config` | `path` | openlineage config reader: path parameter flows into open(path); the only caller passes conf.get('op |
| P1-K-0458 | airflow/providers/postgres/hooks/postgres.py:147 | `copy_expert` | `filename` | PostgresHook.copy_expert: filename parameter flows into open(filename,'w') (creates the file if miss |
| P1-K-0483 | airflow/providers/samba/hooks/samba.py:245 | `push_from_local` | `local_filepath` | Samba transfer helper: local_filepath parameter flows into open(local_filepath,'rb') (local read sin |
| P1-K-0485 | airflow/providers/sendgrid/utils/emailer.py:50 | `send_email` | `files` | Sendgrid emailer: attachment paths from the files parameter are opened directly with open(fname,'rb' |
| P1-K-0498 | airflow/providers/slack/hooks/slack.py:244 | `send_file` | `file` | Slack send_file: file parameter (keyword-only, position 1) is wrapped in Path(file) and opened with  |
| P1-K-0501 | airflow/providers/smtp/hooks/smtp.py:218 | `_build_mime_message` | `files` | SMTP hook MIME builder: attachment paths from the files parameter (position 4) are opened with open( |
| P1-K-0530 | airflow/providers_manager.py:524 | `_add_provider_info_from_local_source_files_on_path` | `path` | ProvidersManager path walker: the path parameter is passed to os.walk(path, topdown=True) and each f |
| P1-K-0533 | airflow/providers_manager.py:537 | `_add_provider_info_from_local_source_file` | `path` | ProvidersManager yaml loader: the path parameter is opened directly with open(path) and parsed; call |
| P1-K-0535 | airflow/secrets/local_filesystem.py:55 | `_parse_env_file` | `file_path` | Secrets .env parser: file_path parameter is opened directly (open(file_path)); callers pass the secr |
| P1-K-0537 | airflow/secrets/local_filesystem.py:101 | `_parse_yaml_file` | `file_path` | Secrets YAML parser: file_path parameter is opened directly (open(file_path)) and parsed with yaml.s |
| P1-K-0539 | airflow/secrets/local_filesystem.py:124 | `_parse_json_file` | `file_path` | Secrets JSON parser: file_path parameter is opened directly (open(file_path)) and parsed with json.l |
| P1-K-0549 | airflow/task/task_runner/cgroup_task_runner.py:191 | `_log_memory_usage` | `mem_cgroup_node` | cgroup memory logger: the mem_cgroup_node parameter's full_path attribute is concatenated into open( |
| P1-K-0562 | airflow/utils/code_utils.py:55 | `prepare_code_snippet` | `file_path` | Code-snippet formatter: file_path parameter is opened directly (open(file_path)) to render error sni |
| P1-K-0571 | airflow/utils/db_cleanup.py:132 | `_dump_table_to_file` | `file_path` | DB cleanup exporter: keyword-only file_path parameter (position 1) is opened with open(file_path,'w' |
| P1-K-0573 | airflow/utils/email.py:155 | `build_mime_message` | `files` | Core email builder: attachment paths from the files parameter (position 4) are opened with open(fnam |
| P1-K-0575 | airflow/utils/file.py:135 | `mkdirs` | `path` | Deprecated mkdirs helper: the path parameter is constructed into Path(path) and the directory is cre |
| P1-K-0578 | airflow/utils/file.py:183 | `open_maybe_zipped` | `fileloc` | open_maybe_zipped: the fileloc parameter drives both branches of file access - zipfile.ZipFile(archi |
| P1-K-0582 | airflow/utils/file.py:198 | `_find_path_from_directory` | `base_dir_path` | DAG directory walker: base_dir_path parameter is walked with os.walk(base_dir_path, followlinks=True |
| P1-K-0593 | airflow/utils/file.py:351 | `might_contain_dag_via_default_heuristic` | `file_path` | DAG heuristic: file_path parameter is either read as a zip member via zip_file.open(file_path) or op |
| P1-K-0596 | airflow/utils/file.py:380 | `iter_airflow_imports` | `file_path` | Import scanner: file_path parameter is read via Path(file_path).read_bytes() and parsed with ast; th |
| P1-K-0599 | airflow/utils/log/file_processor_handler.py:41 | `__init__` | `base_log_folder` | FileProcessorHandler constructor: the base_log_folder parameter (position 0) flows into _get_log_dir |
| P1-K-0608 | airflow/utils/log/file_processor_handler.py:134 | `_init_file` | `filename` | FileProcessorHandler log file creator: the filename parameter is rendered (jinja filename_template)  |
| P1-K-0614 | airflow/utils/log/file_task_handler.py:274 | `_read` | `ti` | FileTaskHandler._read: the ti (TaskInstance) parameter drives the rendered relative log path (self._ |
| P1-K-0616 | airflow/utils/log/file_task_handler.py:420 | `_prepare_log_folder` | `directory` | Log folder preparation: the directory parameter (a Path) is created with directory.mkdir(mode=..., p |
| P1-K-0619 | airflow/utils/log/file_task_handler.py:460 | `_init_file` | `ti` | FileTaskHandler log file creator: the ti parameter drives self._render_filename(ti, ti.try_number) w |
| P1-K-0624 | airflow/utils/log/file_task_handler.py:489 | `_read_from_local` | `worker_log_path` | Task-log local reader (static): the worker_log_path parameter (a Path) drives worker_log_path.parent |
| P1-K-0630 | airflow/utils/serve_logs.py:108 | `serve_logs_view` | `filename` | serve-logs endpoint: the filename parameter is the flask route variable of @flask_app.route('/log/<p |

## Appendix B — receiver-path method sinks (32 labels; sink node = the receiver expression)

| label | site | method | audited rationale (abridged) |
|---|---|---|---|
| P1-K-0059 | airflow/config_templates/airflow_local_settings.py:187 | `mkdir` | Path(directory).mkdir is a real directory-creation filesystem operation on a pathlib.Path receiver;  |
| P1-K-0076 | airflow/configuration.py:1495 | `mkdir` | pathlib.Path(AIRFLOW_HOME).mkdir is a real directory-creation operation; AIRFLOW_HOME is an environm |
| P1-K-0079 | airflow/configuration.py:1511 | `mkdir` | pathlib.Path(AIRFLOW_HOME).mkdir is a real directory-creation operation; AIRFLOW_HOME is an environm |
| P1-K-0159 | airflow/operators/python.py:377 | `write_bytes` | file.write_bytes(...) is a real pathlib file write; the receiver is the file: Path parameter of _wri |
| P1-K-0161 | airflow/operators/python.py:380 | `write_text` | file.write_text(...) is a real pathlib file write; the receiver is the file: Path parameter of _writ |
| P1-K-0163 | airflow/operators/python.py:386 | `read_bytes` | path.read_bytes() is a real pathlib file read; the receiver is the path: Path parameter of _read_res |
| P1-K-0178 | airflow/providers/alibaba/cloud/log/oss_task_handler.py:112 | `read_text` | pathlib.Path(local_loc).read_text() is a real file read of the local task-log copy; local_loc = os.p |
| P1-K-0196 | airflow/providers/amazon/aws/hooks/s3.py:1393 | `mkdir` | file_path.parent.mkdir is a real pathlib directory-creation; file_path = Path(local_dir, subdir, fil |
| P1-K-0209 | airflow/providers/amazon/aws/log/s3_task_handler.py:106 | `read_text` | pathlib.Path(local_loc).read_text() is a real file read of the local task-log copy; local_loc = os.p |
| P1-K-0249 | airflow/providers/cncf/kubernetes/operators/pod.py:414 | `read_text` | path.read_text() is a real pathlib file read, but the path is the fixed in-cluster serviceaccount li |
| P1-K-0264 | airflow/providers/dbt/cloud/operators/dbt.py:263 | `mkdir` | output_file_path.parent.mkdir is a real pathlib directory-creation; output_file_path = Path(self.out |
| P1-K-0265 | airflow/providers/dbt/cloud/operators/dbt.py:264 | `open` | output_file_path.open(mode='w') is a real pathlib file write of the downloaded dbt artifact; the pat |
| P1-K-0283 | airflow/providers/ftp/operators/ftp.py:124 | `mkdir` | Path(local_folder).mkdir is a real pathlib directory-creation; local_folder = os.path.dirname(_local |
| P1-K-0303 | airflow/providers/google/cloud/hooks/cloud_sql.py:614 | `mkdir` | Path(self.cloud_sql_proxy_socket_directory).mkdir is a real pathlib directory-creation for the Cloud |
| P1-K-0373 | airflow/providers/google/cloud/operators/gcs.py:790 | `mkdir` | destination_file.parent.mkdir is a genuine local pathlib directory creation. destination_file = temp |
| P1-K-0376 | airflow/providers/google/cloud/operators/gcs.py:829 | `glob` | temp_output_dir_path.glob("**/*") is a genuine local pathlib directory enumeration over the operator |
| P1-K-0469 | airflow/providers/qubole/hooks/qubole.py:236 | `mkdir` | pathlib.Path(resultpath).mkdir is a genuine local directory creation for qubole command results: res |
| P1-K-0493 | airflow/providers/sftp/operators/sftp.py:175 | `mkdir` | Path(local_folder).mkdir(parents=True, exist_ok=True) is a genuine local directory creation. local_f |
| P1-K-0505 | airflow/providers/snowflake/hooks/snowflake.py:251 | `read_bytes` | Path(private_key_file).read_bytes() is a genuine local file read. private_key_file comes from the Sn |
| P1-K-0508 | airflow/providers/snowflake/hooks/snowflake_sql_api.py:106 | `read_bytes` | Path(private_key_file).read_bytes() is a genuine local file read; private_key_file comes from the Sn |
| P1-K-0525 | airflow/providers_manager.py:137 | `open` | resource_files("airflow").joinpath("provider_info.schema.json").open("rb") is a genuine local file r |
| P1-K-0527 | airflow/providers_manager.py:148 | `open` | resource_files("airflow").joinpath("customized_form_field_behaviours.schema.json").open("rb") is a g |
| P1-K-0577 | airflow/utils/file.py:150 | `mkdir` | Path(path).mkdir(mode=mode, parents=True, exist_ok=True) in the deprecated directory-creation helper |
| P1-K-0580 | airflow/utils/file.py:192 | `open` | zipfile.ZipFile(archive, mode=mode).open(filename) inside open_maybe_zipped is a genuine local archi |
| P1-K-0594 | airflow/utils/file.py:360 | `open` | zip_file.open(file_path) is a genuine zipfile archive-member read; zip_file is a zipfile.ZipFile par |
| P1-K-0598 | airflow/utils/file.py:383 | `read_bytes` | Path(file_path).read_bytes() in iter_airflow_imports is a genuine local file read; file_path is the  |
| P1-K-0601 | airflow/utils/log/file_processor_handler.py:49 | `mkdir` | Path(self._get_log_directory()).mkdir(parents=True, exist_ok=True) is a genuine local directory crea |
| P1-K-0610 | airflow/utils/log/file_processor_handler.py:145 | `mkdir` | Path(directory).mkdir in FileProcessorHandler._init_file is a genuine local directory creation; dire |
| P1-K-0617 | airflow/utils/log/file_task_handler.py:447 | `mkdir` | directory.mkdir(mode=new_folder_permissions, parents=True, exist_ok=True) is a genuine local directo |
| P1-K-0618 | airflow/utils/log/file_task_handler.py:451 | `chmod` | directory.chmod(new_folder_permissions) is a genuine local permission change on the same log directo |
| P1-K-0625 | airflow/utils/log/file_task_handler.py:492 | `glob` | worker_log_path.parent.glob(worker_log_path.name + "*") is a genuine local directory enumeration (pa |
| P1-K-0627 | airflow/utils/log/file_task_handler.py:496 | `read_text` | Path(file).read_text() is a genuine local file read — the actual task-log content read in FileTaskHa |
