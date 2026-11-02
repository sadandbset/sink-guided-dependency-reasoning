# Augur Phase 1 Step 3 — LLM Candidate Labeling Review (Pass 1: Path Traversal)

**Checkpoint artifact (advisory human-review gate). Target: Apache Airflow 2.7.0.dev0 (sha 2811ba7).**
Model: `glm-5.3` (Claude Code agent harness). Generated: 2026-10-21.

This document summarizes the Step 3 labeling run, records the site-level flow analysis behind the
labels, and lists the items flagged for human review before Phase 2 (library generation + taint
queries). No PyVul ground truth, patch diffs, or CVE advisories were consulted; labeling was done
independently from the real source code only.

---

## 1. Scope, method, and reproducibility

- Candidates: all 3777 raw rows of `extraction/sources.csv` + `extraction/sinks.csv`, deduplicated
  to **3291 unique candidates** (486 duplicate rows merged; key: role+file+line+callable+flow_kind+
  arg_index — the decoded `node` column carries only the AST node type and is not location-unique).
  Every raw CSV row maps to exactly one label entry in `labels_raw_pass1.json`.
- Batches: **26 batches** — 11 in-context review batches for the 1820 source candidates
  (R-SRC-01…11, per-family code-line review sheets; the http family additionally required per-file
  flask-import and `request`-shadowing verification, the param family a cross-check against the 74
  `operationId`s of `api_connexion/openapi/v1.yaml`) and 15 fork-subagent batches for the 1471 sink
  candidates (B-SNK-A/M/I 01–05, ~90–104 rows each, each verdict grounded in the real source file).
- Output: `labels.json` (3291 entries, validated locally against
  `augur-0.3.0/assets/labels_schema.json` with `jsonschema` 4.26.0 — validation passed),
  `labels_raw_pass1.json` (raw-row → label-entry mapping + batch registry), `label_stats.md`.
- Intermediate review sheets and verdict files live under `../.step3_work/` (outside `iris/`).
  Nothing under the source tree, the CodeQL DB, the Augur installation, or the Phase 1 CSVs was
  modified.

## 2. Labeling rules (trust model used)

| rule | effect |
|---|---|
| External HTTP boundary (flask `request.*` reads, FAB `@expose/@action` route params, flask routes, connexion handler params = OpenAPI operationIds, `get_json_request_dict`/FAB urltools wrappers) | `source` / tp |
| CLI (argparse `args`, `sys.argv`), `conf.get*`, `os.environ`/`getenv` | `none` / fp — deployment/admin or local-operator trust, not attacker boundaries |
| `json.loads` sites | tp only where the decoded argument is verifiably request-derived (10 sites); `candidate` for signed-token/JWT decodes (3 sites); fp otherwise (94 sites: internal/DB/CLI/config data) |
| Real local file API on deployed code (`open`, `os.*`, `shutil.*`, `ZipFile`, `tarfile.open`, `send_from_directory`, `SourceFileLoader`, pathlib receiver-methods, wrappers with param→path flow) | `sink` / tp (arg index recorded) |
| `pathlib.Path(...)` constructor and pure path transformers | `summary` / tp — pure path construction performs no file access; recorded as taint-propagation steps |
| Non-deployed locations (`dev/`, `scripts/`, `docs/`, `example_dags/`, `airflow/migrations/`, `docker_tests/`, `kubernetes_tests/`, `setup.py`) | `none` / fp (build/CI/docs/test code, per WORKFLOW §5.3.2 and the extraction notes) |
| Name collisions (`str.replace`/`datetime.replace` matched as pathlib methods, `glob.glob` module function, non-flask `request` in dbt hook, remote paramiko/SMB/FTP/ADLS clients) | `none` / fp — with the verified receiver type in the rationale |
| Sanitizers | **no candidate row earned the `sanitizer` role**: no extracted call site was verified to neutralize traversal in this concrete implementation (see §4.6) — the observed guards are recorded in sink rationales/evidence instead |

## 3. Label counts (see label_stats.md for full tables)

- Sources (1820): 628 source/tp, 3 source/candidate, 1189 none/fp.
- Sinks (1471): 269 sink/tp, 54 summary/tp, 1147 none/fp, 1 none/candidate.
- Production-sink path origins: param 183 (operator/DAG-author/hook parameters), config 39,
  literal 25, db_field 13, env 4, request 2, remote-content 2.

## 4. Site-level flow analysis behind the labels

### 4.1 serve-logs app — `/log/<path:filename>` (the one request→file-response flow)

`airflow/utils/serve_logs.py:107-109`: `serve_logs_view(filename)` passes the URL path variable
(flask `<path:` converter — accepts `/` and `..` segments, no decoding needed beyond werkzeug's
built-in URL decoding) directly as argument 1 of `send_from_directory(log_directory, filename)`,
where `log_directory = expanduser(conf.get("logging","BASE_LOG_FOLDER"))` (serve_logs.py:46,
config trust). Labeled `P1-K-0630` (wrapper, param 0) and `P1-K-0631` (sink, argument 1) as
sink/tp; the handler parameter row `P1-S-…` (serve_logs_view `filename`) is source/tp.

Guards actually executed before file access (serve_logs.py:55-105, `before_request`): a JWT signed
with `webserver.secret_key` (audience `task-instance-logs`, 30 s grace) whose payload `filename`
must **equal** `request.view_args["filename"]`, else abort(403). Tokens are minted server-side by
`FileTaskHandler._get_log_retrieval_url` for the exact rendered log relative path. In addition,
flask's `send_from_directory` applies `werkzeug.utils.safe_join`, which rejects `..`-escapes and
absolute paths out of the directory root. **Net assessment**: the filename is request-derived and
the app performs no containment check of its own, but an attacker cannot obtain a signed token for
an arbitrary path (tokens exist only for server-rendered log paths), and werkzeug enforces root
containment regardless. Escape requires SECRET_KEY compromise (which also breaks token minting
trust broadly). Human review point HR-1.

### 4.2 REST `/dagSources/{file_token}` (signed-token path)

`airflow/api_connexion/endpoints/dag_source_endpoint.py:32-44`: `file_token` query/path param
(source/tp, `P1-S-…`) → `path = auth_s.loads(file_token)` with `URLSafeSerializer(SECRET_KEY)`
(labeled source/**candidate**, `P1-S-0120`) → `DagCode.code(path)`. In this snapshot
`DagCode.code()` resolves via `_get_code_from_db` (fileloc-hash DB lookup, dagcode.py:172-179);
the direct file-read variant `_get_code_from_file` (`open_maybe_zipped(fileloc)`, dagcode.py:176)
exists in the same class. Tokens are minted server-side from `DagModel.fileloc`
(api_connexion/schemas/dag_schema.py:62), so arbitrary-path injection again requires the SECRET_KEY.
Human review point HR-2.

### 4.3 Task-log reading chain (www + REST)

`www/views.py:1586-1657 get_logs_with_metadata` and `api_connexion/.../log_endpoint.py:47-… get_log`:
all request-derived identifiers (dag_id/task_id/execution_date/map_index/try_number/token) are used
as **DB lookup keys** for `TaskInstance` (and signed-token metadata flags), never as path
components. The actual path is built downstream in `FileTaskHandler`:
`worker_log_rel_path = _render_filename(ti, try_number)` (LogTemplate `filename` from the DB +
ti.dag_id/task_id/run_id fields, file_task_handler.py:321) → `Path(self.local_base,
worker_log_rel_path)` (:322) → `parent.glob(name+"*")` + `Path(file).read_text()` (:489-496,
labeled sink/tp, `db_field` origin); `_init_file` mirrors this for writes (`os.path.join` →
`open(full_path, "a")`, :472/:480). Traversal here would require DB-stored values (DAG/task ids or
a customized LogTemplate) containing separators — DAG-author/API-created-run trust level, not a
direct request→path flow. The download response's `Content-Disposition: filename=` header
(views.py:1654) is a header concern, not a file access. Human review point HR-3 (indirect flow via
API-created `run_id` reaching a customized LogTemplate — requires two DB writes, low likelihood).

### 4.4 DAG-folder processing (scheduler/CLI side)

`DagBag.process_file/_load_modules_from_file` (dagbag.py:278/341: `SourceFileLoader(mod_name,
filepath).exec_module()` — labeled sink/tp), `_load_modules_from_zip` (dagbag.py:381:
`zipfile.ZipFile(filepath)` — sink/tp), `open_maybe_zipped` (utils/file.py:183-195, sink/tp param
0), `_find_path_from_directory` (utils/file.py:198-…, `os.walk(base_dir, followlinks=True)` with an
explicit revisit/loop guard raising RuntimeError — sink/tp). Input roots are
`settings.DAGS_FOLDER`/`PLUGINS_FOLDER` (config) or CLI `--subdir` (operator); `correct_maybe_zipped`
(utils/file.py:166) is labeled `summary` (path-transformer). Intended Airflow functionality
(execute the DAGs folder), not attacker-reachable in the standard deployment. The
`file_processor_handler.py:93-96` startswith-remap
(`if filename.startswith(airflow_directory): os.path.join("native_dags", os.path.relpath(...))`)
is a **non-normalized string prefix check** — classic prefix weakness, but both the checked value
and the base are scheduler-internal paths; it remaps rather than validates a user-supplied path,
so it was NOT labeled a sanitizer.

### 4.5 CLI import/export and daemon handlers

`variables_import/_import_helper` (variable_command.py:69-95, `open(filepath)`), pool/role/user
import-export, `task_command.py:384-388` (`open(args.cfg_path)` / `os.remove`), kubernetes
`-o/--output-path` (os.makedirs + write), and the daemon log-file opens via `setup_locations`
(`--log-file/--stdout/--stderr/--pid`, defaults under AIRFLOW_HOME): all labeled sink/tp with
`path_origin=param`, **but their inputs come from the local CLI operator**, and the corresponding
CLI `args` source rows were labeled none/fp (operator trust). These are complete
wrapper→file-API flows with no untrusted source attached in production.

### 4.6 Guards observed and why none became a `sanitizer` label

- `serve_logs.py` JWT-filename equality + werkzeug safe_join: framework-level, not an extracted
  candidate call; recorded in the sink rationale (HR-1).
- `imap.py:242-252` (provider): `_is_escaping_current_directory(name)` = substring blacklist
  `"../" in name`, `_is_symlink(name)` = `os.path.islink(name)` — then `_create_file` concatenates
  `local_output_directory + "/" + name` and `open(file_path, "wb")` (imap.py:262-267, sink/tp,
  `P1-K-0428`, external-content origin). The blacklist misses absolute-path-style names,
  backslash separators (Windows), and `..` without a following slash; `islink` checks the CWD
  relative name, not the output path (check/use mismatch). **Not a reliable sanitizer** — this is
  the strongest candidate-weakness site found in the provider code (HR-4).
- `gcs.py:790` (GCSTimeSpanFileTransformOperator.execute): `destination_file =
  temp_input_dir_path / blob_to_transform` — GCS blob names (external object-store content) joined
  into local temp paths; `Path` joining does not normalize `..` segments, so a crafted blob name
  could escape the TemporaryDirectory. Labeled the local ops sink/tp and the wrapper row
  none/**candidate** (`P1-K-0370`) because the blob name is not an execute() parameter (HR-5).
- No `os.path.normpath` occurs anywhere in the snapshot; `abspath`/`realpath`/`Path.resolve`/
  `relative_to` appear as validation/canonicalization nodes but not as extracted candidates
  (documented in detection.json); `str.replace` sites strip characters, never traversal sequences.

### 4.7 Symlinks and TOCTOU

`os.symlink` occurs only in `file_processor_handler.py:124/:130` creating the `latest` log-dir
symlink, guarded by an `os.readlink` comparison (:122) — scheduler-internal, not
attacker-influenced. `_find_path_from_directory` walks with `followlinks=True` but detects
revisits and raises. `os.path.isfile/getmtime` probes before opens (dagbag.py:289/295) are
existence probes on deployment-trust paths. No user-controlled symlink race was identified;
recorded as **not applicable** for the request-reachable flows.

## 5. Answers to the review checklist

1. **True untrusted sources?** Yes for flask/FAB/connexion request reads, route params and the
   varimport multipart body (the uploaded filename is never used in a path — only
   `request.files["file"].read()` content). No for env/config/CLI/internal params — labeled
   none/fp with reasons; internal helper parameters (e.g. `_fetch_dag_runs`, comprehensions) are
   not boundaries.
2. **Path transformations tracked?** Yes per site: URL path variable → `send_from_directory`
   (safe_join); signed-token decode → DB hash lookup; DB fields → LogTemplate render →
   `Path`/`join` → `glob`/`read_text`; CLI/env → `expanduser`/`join` → `open`. Each hop is
   documented in the entry evidence.
3. **Real file sinks only?** Yes — `Path(...)` constructors and string ops are `summary`/`none`,
   never sinks; only actual open/read/write/remove/enumerate/archive-open/file-response calls and
   wrappers whose params reach such calls are sinks.
4. **Escape variants?** Analyzed per site: serve-logs (werkzeug blocks `..`/absolute), imap
   (blacklist misses separators/absolute forms — weakness recorded), gcs blob join (no
   normalization — weakness recorded), log-path chain (requires DB-stored separators).
5. **Root checks executed before access?** Only werkzeug safe_join (framework, serve-logs) and the
   signed-token equality; no application-level canonicalized-containment check exists on any
   request-reachable path in this snapshot.
6. **Function-name sanitizers?** None confirmed: the startswith remap operates on non-normalized
   strings and remaps rather than validates; the imap `"../"` blacklist is incomplete; no
   normpath/basename containment on user paths. No `sanitizer` labels emitted.
7. **Symlinks** — see §4.7: not applicable for request-reachable flows.
8. **Authorized file serving ≠ vulnerability**: DAG-source viewing, task-log reading, DAG-folder
   execution and log writing are intended, permission-gated Airflow features; their sink labels
   serve recall, and the trust analysis above is what separates intended use from attack.
9. **Tests/constants/unreachable code**: dev/, scripts/, docs/, example_dags/, migrations/,
   docker_tests/, kubernetes_tests/, setup.py rows are all none/fp (1147 of 1471 sink rows;
   fixed-constant paths inside prod code remain sink/tp at the API level with `literal` origin
   noted).
10. **Complete vs partial flows**: the only complete untrusted-source→file-API flows on the
    request surface are serve-logs (contained by signed token + safe_join) and the two signed-token
    decode candidates; everything else on the request surface stops at DB lookups, while the
    wrapper→file-API flows (CLI, providers, log handlers) carry operator/DAG-author/DB/remote-content
    trust inputs.

## 6. Human review points (checkpoint payload)

| id | item | entries | why |
|---|---|---|---|
| HR-1 | serve-logs `/log/<path:filename>` → `send_from_directory` | P1-K-0630/0631 + serve_logs_view param source | request-derived filename; app-level guard is only signed-token equality; containment relies on werkzeug safe_join and SECRET_KEY secrecy |
| HR-2 | `/dagSources/{file_token}` signed-token path decode | P1-S-0120 (candidate) + get_dag_source params | SECRET_KEY compromise or token leakage would reach DagCode path resolution; current default path is a DB hash lookup |
| HR-3 | task-log path chain via DB-stored ids/LogTemplate | FileTaskHandler sink rows (db_field origin) | indirect request influence possible only via API-created run_id + customized LogTemplate (two DB writes) |
| HR-4 | IMAP attachment filename → local write (imap.py:262-267) | P1-K-0428 | `"../"` substring blacklist + islink-on-wrong-path; Windows separator variant escapes; external mail content |
| HR-5 | GCS blob name joined into temp path (gcs.py:790) | P1-K-0370 (candidate) + mkdir/glob sink rows | Path join without normalization; blob names are external object-store content |
| HR-6 | log_endpoint token metadata decode | P1-S-0169 (candidate) | signed token drives flags, not paths; verify no future path use |

Top high-risk sink APIs for Phase 2 (production, param/config/db-controlled paths):
`open` (107 prod rows), `Path` constructor summary steps (48), `mkdir`/`remove`/`rmtree`/`walk`/
`chmod`/`ZipFile`/`SourceFileLoader`/`send_from_directory`, FileTaskHandler log read/write chain,
DagBag/DagCode file loading.

Unresolved/low-confidence entries: 4 (the 3 source candidates and P1-K-0370 above); everything
else was decided at confidence ≥ 0.85 with code-line evidence.

## 7. Statement of limits

- Labels are API-level (used for MySources/MySinks/MySummaries generation); site-level
  exploitability judgments in §4 are advisory for the Phase 2 triage, not part of labels.json.
- `classification` semantics: tp = genuinely carries the role on the deployed attack surface;
  fp = extraction collision or excluded trust level/location; candidate = human review required.
- One fork batch (B-SNK-I01) had to be re-run after a transient API rate-limit; its final output
  covers all 93 rows. All 15 sink batches and all 11 source review sheets were completed and are
  represented in the outputs — nothing was extrapolated or fabricated.

**Per the task instructions, this run stops here and does not enter Phase 2.**
