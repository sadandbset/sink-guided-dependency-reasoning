# Query Generation Notes — Augur Phase 2 Step 4–5, Pass 1 (Path Traversal)

- **Run:** `gradio-pathtraversal-pass1-20261022` · **Date:** 2026-10-22
- **Scope:** `gradio/` package of gradio 2.5.0 (`path_traversal_dbs/gradio_vuln`); DB `gradio_vuln/gradio-db`
- **Label input:** `iris/labels/labels.json` (114 entries; pass 1 roles: source 39 / sink 17 / none 58 / sanitizer 0 / summary 0)
- **Generated:** `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass1_PathTraversal.ql`
- **CodeQL baseline:** CLI 2.25.1, local pack `codeql/python-all 7.1.2`; all AST/data-flow API names in the generated files were verified against the local pack sources (not from memory). Per instructions, **no compilation or analysis was run** — compile in Step 5.

## 0. Review-gate state

`labels/review_decision.json` does not exist in the workspace. Per the operator instruction that the Step 5 (checkpoint) review is complete, `labels.json` is treated as the reviewed label set. The six open decisions from `labels/phase1_review.md` §6 were resolved as follows during generation:

| Review decision | Resolution in this generation |
| --- | --- |
| 1. `secure_filename` NameError (S64/K35/K44) | Not modeled as a barrier (verified unimported); see §4 |
| 2. `safe_join` as Step 4 barrier | Modeled as the only barrier (see §5) |
| 3. Keep tempfile suffix sinks (K03/K04); K25 stays candidate | K03/K04 modeled; K25 unmodeled (candidate) |
| 4. Scalar `preprocess` sources kept or pruned | Kept (conservative recall, per labels) |
| 5. Summaries fallback list | None needed (see §6); detection.json list retained as fallback |
| 6. S51 / K45 confirm or drop | Unmodeled (classification "candidate"), flagged for review |

Modeling rule applied throughout: only label entries with `classification = "tp"` drive the formal Pass 1 model. The three `candidate` entries (S51 `flag_data` flag_index, K25 `shutil.move` arg 1, K45 `os.path.getsize`) are **not** rendered into predicates; if the reviewer confirms them, they can be added without touching labels.json (they are listed in §7 with ready-to-add rule sketches). No label was found to be missing or wrong, so nothing was sent back for re-review.

## 1. Label ID → QL predicate mapping (with source evidence)

### MySources.qll — `isSource(node, "path_traversal")`

| Predicate (private, in module `MySources`) | Label IDs | Matching rule | Source evidence |
| --- | --- | --- | --- |
| `flaskRequestJsonSource` | S54–S58 (tp) | Subscript node whose base is the attribute `request.json`, inside functions `predict`/`flag`/`interpret`/`queue_push` of `gradio/networking.py` | networking.py:192 (`request.json["data"]`, /api/predict), :358 (/api/flag), :368 (/api/interpret), :394/:395 (/api/queue/push). S59 (`request.json['hash']`, queue_status) is none/fp and excluded |
| `flaskRoutePathParameter` | S62, S64 (tp) | Parameter `path` (index 0) of module-level functions `static_resource`/`file` in `networking.py` | networking.py:139 (`/static/<path:path>`), :379 (`/file/<path:path>`). S63 `enable_sharing` is none/fp (config storage only) and excluded |
| `interfaceDispatchParameter` | S46, S47 (tp) | Parameter `raw_input` (index 1) of methods `process`/`interpret` of class `Interface` in `interface.py` | interface.py:363/:377; dispatched from networking.py:192→196/201 and :368–370 |
| `componentPreprocessParameter` | S31–S44 (tp ×14) | Parameter `x` (index 1) of any function `preprocess` in `inputs.py` | All 14 overrides (InputComponent:29 through Timeseries:1331) are reviewed tp; File/Video/Audio carry the path-relevant `name`/`is_example` fields |
| `processSingleFileParameter` | S45 (tp) | Parameter `f` (index 0) of function `process_single_file` in `inputs.py` | inputs.py:1171 (nested in File.preprocess); `f["name"]` is the client filename, `f.get("is_example")` client-settable |
| `flagDataParameter` | S48, S49, S50 (tp) | Parameters `input_data`(0)/`output_data`(1)/`flag_option`(2) of module function `flag_data` in `networking.py` | networking.py:276; called from /api/flag (:358–360) and /api/predict auto-flag (:212–214). S51 `flag_index`(3) is candidate — excluded |
| `queuePushParameter` | S52, S53 (tp) | Parameters `input_data`(0)/`action`(1) of module function `push` in `queue.py` | queue.py:68; fed from networking.py:394–396; re-posted locally by queue_thread (networking.py:408–416) |
| `saveFlaggedDataParameter` | S03–S06, S10–S13 (tp ×8) | Parameter `data` (index 3) of method `save_flagged` whose enclosing class is Image/Video/Audio/File, in `inputs.py` or `outputs.py` | inputs.py:863/941/1115/1194; outputs.py:242/297/440/549 — all delegate to `save_flagged_file`. The json.dumps-only overrides are none/fp and not matched |
| `saveFlaggedFileDataParameter` | S30 (tp) | Parameter `data` (index 3) of method `save_flagged_file` of class `Component` in `component.py` | component.py:48–66 (decode → tempfile → shutil.move) |

Parameter indexes follow the label convention (0-based positional including `self`), matching `Function.getArg(index)`.

### MySinks.qll — `isSink(node, "path_traversal")`

| Predicate | Label IDs | Matching rule (sink node) | Operation / arg / access type |
| --- | --- | --- | --- |
| `ffmpegPathSink` | K01, K02 (tp) | Call `FFmpeg(...)` (Name callee, `from ffmpy import FFmpeg`) in `preprocess` (inputs.py) / `postprocess` (outputs.py); sink = the `inputs`/`outputs` keyword dict argument and the key expressions inside it | Subprocess file READ (inputs keys) and WRITE (outputs keys) via `ff.run()`; label flow kind keyword-controlled (arg index n/a). Callers: inputs.py:930, outputs.py:287 |
| `namedTemporaryFileNameSink` | K03–K06 (tp) | Call `tempfile.NamedTemporaryFile(...)` in `decode_base64_to_file` / `create_tmp_copy_of_file` (processing_utils.py); sink = value of the `prefix`/`suffix` keyword arguments | File CREATE with client-influenced name components (processing_utils.py:149/151/165/167). Called from component.py:51, inputs.py:919/1003/1177 (decode) and inputs.py:917/1001/1175 (copy) |
| `audioExportFilenameSink` | K19 (tp) | Method call `.export(...)` in `audio_to_file`; sink = positional arg 0 | Audio file WRITE (pydub `AudioSegment.export(filename)`, processing_utils.py:118) |
| `openPathSink` | K26, K27, K35, K41 (tp) | Call `open(...)` (Name callee) in `get_url_or_file_as_bytes` / `encode_file_to_base64` / `file` / `process_single_file`; sink = positional arg 0 | File READ (`"rb"` at :28/:41/:382/:1180; mode arg distinguishes read/write — all four sites are reads) |
| `sendFilePathSink` | K42, K44 (tp) | Call `send_file(...)` (Name callee, `from flask import send_file`) in `static_resource` / `file` (networking.py); sink = positional arg 0 | File READ served as HTTP response (networking.py:143/:388) |
| `audioFromFileSink` | K46 (tp) | Call `AudioSegment.from_file(...)` in `audio_from_file`; sink = positional arg 0 | Audio file READ (processing_utils.py:101) |
| `shutilCopySourceSink` | K47 (tp) | Call `shutil.copy2(...)` in `create_tmp_copy_of_file`; sink = positional arg 0 | File READ+COPY (processing_utils.py:168); destination (arg 1) is none/fp and not matched |

Unmodeled sink labels: K25 (candidate, `shutil.move` arg 1 at component.py:65), K45 (candidate, `os.path.getsize` at outputs.py:545). All 34 `none`/fp sink labels (fixed constants, BytesIO targets, literal-suffix tempfiles, developer-config paths, `os.remove(DB_FILE)` etc.) are not matched — see `labels/label_stats.md` for the full rejection rationale.

### MySanitizers.qll / MySummaries.qll

No label entries with role sanitizer/summary exist; `isBarrier` renders the single review-approved call-site barrier (§5), `isAdditionalTaintStep` resolves to `none()` (§6). Both keep the interface `(..., passKey)` required by the template.

## 2. Source boundaries and access conditions

| Source group | External boundary | Attacker control | Access conditions |
| --- | --- | --- | --- |
| S62/S64 route params | Flask URL `<path:path>` converter variable | full path string incl. `..`, absolute paths, separator and encoding variants | GET, network-reachable; `@login_check` is a no-op unless the operator set `app.auth` (networking.py:84–95); Flask normalizes the URL before routing (werkzeug path converter decodes `%2F`-free segments; `..` in the path converter value is passed through) |
| S54–S58 `request.json[...]` | HTTP POST JSON body | full JSON payload per route | POST; same login condition |
| S31–S45 preprocess/x, f | request JSON dispatched to input components | full component payload incl. `name`, `data`, `is_example` (is_example is client-settable — verified inputs.py:915/998/1172) | via /api/predict, /api/interpret, and the queue round-trip |
| S46/S47 process/interpret | internal dispatch boundary of the same payloads | same | — |
| S48–S50 flag_data | request JSON of /api/flag and prediction results | flagged content incl. data-URI header | POST /api/flag; auto-flagging on /api/predict |
| S52/S53 queue.push | request JSON entering the sqlite queue, re-entering /api/<task_type> over local HTTP | full payload (second-order) | queue enabled (`enable_queue`); note queue is mutually exclusive with auth/encrypt (networking.py:448–450) |
| S03–S13, S30 save_flagged(_file) | flagged request base64 persisted under the flagging dir | content + data-URI header (tempfile prefix/suffix surface) | flagging enabled (default) |

## 3. Sink operations and call relationships

All sinks are actual file accesses at dangerous PATH positions; the file objects returned by `open`/`send_file`/tempfile are never sinks, and `os.path.join`/slicing/format are propagation only:

- **K41** `open(file_name, "rb")` (inputs.py:1180) — arbitrary-file READ; the bytes are returned into the prediction/response pipeline (File.preprocess type `"bytes"`, inputs.py:1178–1182).
- **K47** `shutil.copy2(file_path, temp_name)` (processing_utils.py:168) — file READ/copy of the client `name` (is_example branches inputs.py:917/1001/1175).
- **K35/K44** `open(...)`/`send_file(...)` on `os.path.join(app.cwd, path)` (networking.py:382/388) — read/serve under the process working directory; intended root `app.cwd`, no working containment check (see §4).
- **K42** `send_file(safe_join(STATIC_PATH_LIB, path))` (networking.py:143) — read/serve from the packaged static dir, intended root `STATIC_PATH_LIB`; contained by the barrier.
- **K03–K06** `tempfile.NamedTemporaryFile(prefix=…, suffix=…)` (processing_utils.py:149/151/165/167) — file CREATE; intended root = system temp dir; suffix not separator-filtered in the flagging flow (file_path=None; decode_base64_to_binary processing_utils.py:124–135), while the preprocess/copy flows pass through `os.path.basename` (processing_utils.py:141–145/159–163).
- **K26/K27** `open(path,"rb")` read wrappers (processing_utils.py:28/41).
- **K46/K19** pydub read/write (processing_utils.py:101/118). **K01/K02** ffmpy subprocess file I/O on dict keys (inputs.py:926–930, outputs.py:283–287).

## 4. Path joining, decoding, normalization, allowed roots, symlinks — evidence

- **Joining:** `os.path.join(app.cwd, path)` (networking.py:382/388), `os.path.join(STATIC_PATH_LIB …)` via safe_join (networking.py:143), `os.path.join(dir, label, new_file_name)` (component.py:54/65, label charset-filtered), `"{}/log.csv".format(flag_path)` (networking.py:279). CodeQL propagates taint through all of these (`OsPathJoinCallAdditionalTaintStep`, `stringManipulation` — verified in the local pack), so no summary edges were added.
- **Decoding:** no URL decoding of route paths inside gradio (Flask decodes once before routing); base64 data-URI decoding (processing_utils.py:124–135) only extracts the header, and its `extension` component is not separator-filtered — the basis for keeping K03/K04.
- **Normalization:** `os.path.basename` at processing_utils.py:141–145/159–163 and outputs.py:290/544; no `normpath`/`realpath`/`resolve` anywhere in the package; `pathlib.Path` is a dead import (inputs.py:17). Taint propagates through basename (stdlib model), so it is not a barrier.
- **Allowed roots:** `app.cwd` (/file route, no check as written), `STATIC_PATH_LIB` (safe_join containment), the flagging dir (`app.interface.flagging_dir`, developer config; label charset filter on the subdirectory name), and the system temp dir (random name body + O_EXCL — constrains, does not canonicalize).
- **Symlinks:** no `os.path.islink`, no `realpath`, no symlink creation in the package; `shutil.move`/`copy2` follow symlinks at access time (post-check), but no check/use ordering issue exists for the modeled sinks except the TOCTOU-adjacent `os.path.exists` calls noted in detection.json (not barriers). Recorded as not applicable.
- **Timing:** all checks (safe_join, exists, charset filter) execute before the corresponding file access in the same expression/statement; no normalize-check-use reordering issues beyond those noted.

## 5. Barrier verification

| Candidate | Verdict | Why |
| --- | --- | --- |
| `safe_join(STATIC_PATH_LIB, path)` (networking.py:143) | **Barrier (modeled)** — genuinely blocks `..`, absolute-path and separator escape from the static root by rejecting non-contained joins with NotFound, before `send_file` opens anything. Barrier node = the safe_join call, which is also the send_file path argument, so the removed node cuts argument→sink flow |
| `secure_filename(path)` (networking.py:380) | **Not a barrier** — not imported in networking.py (only `safe_join` from `werkzeug.security`, line 30); unresolved name. Also not a propagator: see §7 limitation L1 |
| `os.path.basename`, slicing, `normpath` | Not barriers — component extractors; taint propagates through them |
| `path.startswith(app.interface.examples)` (networking.py:381) | Not a barrier — string prefix on an unnormalized path, and it gates only the encrypted branch; the `else` branch (:388) is unchecked |
| component.py:52 charset filter | Not needed for modeled sinks (guards the developer-config label dir name; the related move destination is unmodeled candidate K25) |

## 6. Additional propagation edges

None added (`isAdditionalTaintStep = none()`). Built-in coverage verified in the local pack: subscript reads (`subscriptStep`), string concat/format/`%`/f-strings, container literals (`containerStep`), `os.path.join`/`os.path.*` computations (Stdlib `AdditionalTaintStep` models auto-loaded with `TaintTracking`), and statically-resolvable call edges for the direct wrapper calls (`flag_data`, `decode_base64_to_file`, `create_tmp_copy_of_file`, `process_single_file`, `queue.push`). Dynamic-dispatch entries (`app.interface.process`, `input_component.preprocess`, `interface.save_flagged`) need no edges because the callee parameters are themselves labeled sources. The queue HTTP round-trip is intentionally not an edge (process boundary; modeled by S52/S53).

## 7. Known limitations, dynamic-dispatch/alias gaps, diagnostic paths

Not counted as formal Pass 1 findings; any query built from these notes is a diagnostic, per the ground rules:

- **L1 — `/file` route suppression (S64→K35/K44):** `path = secure_filename(path)` rebinds `path` to the result of an *unresolved* call. Python taint tracking has no argument→result step for unresolved calls (verified: no unknown-call step in `TaintTrackingPrivate`), so the tainted parameter does not reach the later uses of the rebound variable — the flow is expected to be suppressed *by the dead reassignment*, not by sanitization. Diagnostic (not formal): a query whose source is the `os.path.join(app.cwd, path)` argument or the post-assignment `path` variable at networking.py:381–388, to expose the route's unchecked join under an import-fixed `secure_filename`. The labels (S64/K35/K44 tp) stand; this is a CodeQL reachability note only.
- **L2 — `/static` route (S62→K42):** `safe_join` is imported from werkzeug, which is not part of the extracted DB, so the call is unresolved and would not propagate argument→result even without the barrier; the flow is doubly dead. The barrier is still modeled (documentation + robustness if the DB later includes werkzeug).
- **L3 — attribute reads do not propagate taint:** `file_obj.name` (e.g. inputs.py:921, 1006/1015) is an attribute read on a call result, and Python taint tracking has no object→attribute-value step, so paths derived from temp-file objects (`file.name`, `file_obj.name`) are not tainted. Affects reachability of K01/K02 (dict keys come from `file.name`) and K19 (call sites pass `file_obj.name`). The is_example flows into K47/K41 do not depend on this (they use `f["name"]` directly).
- **L4 — dict-key taint:** `containerStep`'s `dictStoreStep` propagates element *values* into the dict node, not keys; that is why the FFmpeg sink is modeled at both the dict node and the key expressions (the actual file paths).
- **L5 — dynamic dispatch:** `app.interface.process` (networking.py:196/201), `interface.save_flagged` (networking.py:286/289), `input_component.preprocess` (interface.py:369/385) may not resolve; recall does not depend on them (callee params are sources), but *path explanations* will start at those params rather than at the HTTP entry.
- **L6 — unmodeled candidates:** S51, K25, K45 (see §0). Ready-to-add sketches if the reviewer confirms them: S51 → `parameterSource(source, f, 3, "flag_index")` in `flagDataParameter`; K25 → `moduleCall(call, "shutil", "move")` in `save_flagged_file` (component.py), sink = arg 1; K45 → `moduleCall(call, "os.path", "getsize")` in `File.postprocess` (outputs.py), sink = arg 0.
- **L7 — API verification and check-only compile:** predicate/class/member names (`Call.getPositionalArg`, `Keyword.getArg/getValue`, `Dict.getAnItem`, `KeyValuePair.getKey`, `Subscript.getValue`, `Function.getArg/getScope`, `DataFlow::ParameterNode.getParameter`, `DataFlow::ConfigSig` members incl. `isAdditionalFlowStep`, `TaintTracking::Global`/`PathGraph`/`flowPath`) were verified against the local `codeql/python-all 7.1.2` sources. A first `codeql query compile --check-only` pass (run by the operator) surfaced four errors, which were fixed in the library files (no labels or sources touched):
  1. `'baseName' is not bound to a value` (MySources/MySinks/MySanitizers, `inGradioFile`): `regexpMatch` is a built-in check that never binds its argument, so the `baseName` parameter was used but never bound in the body. Fixed with a `bindingset[baseName]` annotation on the predicate declaration (every call site passes a string literal, so the binding assumption holds).
  2. `getId() cannot be resolved for type Function::Parameter` (MySources, `parameterSource`): the AST `Parameter` class extends the dbscheme union `@py_parameter = @py_Name | @py_Tuple` and is therefore not a static subtype of `Name`, whose `getId()` it does not inherit. Fixed as `p.asName().getId()` — `Parameter.asName()` (semmle/python/Function.qll) is the supported accessor.
  After the fix, `codeql query compile --check-only queries/Pass1_PathTraversal.ql` (CLI 2.25.x, pack cache resolution, no `--additional-packs`) completes with **no errors or warnings**. This is a compile check only — no database analysis was executed. Template note: `assets/taint_query.ql.tmpl`'s single `{{SOURCE_MODULE}}` placeholder cannot express both the dotted file import (`import libraries.MySources`) and the short module reference (`MySources::isSource`); the rendered query uses the dotted import lines with short module references — the only deviation from the template text.

## 8. Experiment independence

Labels were produced in Phase 1 from the real sources only; this generation step used WORKFLOW.md (Phase 2), `references/python.md`, `references/patterns.md`, `references/flask.md`, `assets/taint_query.ql.tmpl`, `assets/labels_schema.json`, the reviewed `labels/labels.json`, and the gradio sources in `gradio_vuln` (plus the local CodeQL pack sources for API verification). No PyVul ground truth, CVE advisories, or fix patches were consulted; the repo-local audit reports (`VULNERABILITY_AUDIT_REPORT.md`, `优先级策略漏洞审查报告.md`) remained unread. No source, database, or Phase 1 label file was modified; the only files written are the six listed above.
