# Query Generation Notes — Pass 1 Path Traversal (streamlit)

**Augur Phase 2 Step 4–5.** Generated: 2026-10-23. Run: `streamlit-pathtraversal-pass1-20261023`.

## 1. Scope, inputs, and constraint compliance

- Generated files: `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass1_PathTraversal.ql`, and this report. Nothing else was created; no source code, CodeQL database, Augur files, or Phase 1 labels were modified.
- Inputs: `labels/labels.json` (the reviewed pass 1 label set), `extraction/*.csv` (for candidate provenance), `exploration/detection.json`, WORKFLOW.md Phase 2, `references/python.md`, `references/patterns.md`, `assets/taint_query.ql.tmpl`, and the real source under `streamlit_vuln/lib/streamlit/` (read-only).
- **`labels/review_decision.json` was read as instructed and does not exist**: Phase 1 was stopped after writing the four contract files (`labels.json`, `labels_raw_pass1.json`, `label_stats.md`, `phase1_review.md`); the WORKFLOW 4.5 checkpoint is advisory and no decision file was requested in that step. `labels/labels.json` is therefore used as the reviewed label set exactly as written. This is a missing audit artifact, not a label omission — no label change is needed for it. It should be written (reviewer `auto` or human) before Step 5 execution for audit completeness.
- **No compilation or query execution was performed** (per experiment instructions). To compensate, every QL API used was verified read-only against the local packs: `codeql/python-all 7.1.2` and `codeql/dataflow 2.1.6` (see §7). `qlpack.yml` already exists at the iris root (`iris/streamlit-cwe22`, dependency `codeql/python-all: "*"`), matching the required layout; it was not modified.
- Query metadata: `@kind path-problem`, `@problem.severity error`, `@precision medium`, `@tags security` + `external/cwe/cwe-022`/`cwe-023`/`cwe-036`/`cwe-073`, id `py/augur/streamlit/pass1-path-traversal`. `medium` precision is chosen because the source set is conservative and evidence-restricted, but no barrier modeling exists and the st.image/st.audio/st.video sinks can only be judged with app-script context (Step 6 triage).
- Query structure follows `assets/taint_query.ql.tmpl` exactly: `Pass1PathTraversalConfig implements DataFlow::ConfigSig` delegating to `MySources/MySinks/MySanitizers/MySummaries` with the unified pass key `"path_traversal"`, `module Pass1PathTraversalFlow = TaintTracking::Global<Pass1PathTraversalConfig>`, `import Pass1PathTraversalFlow::PathGraph`, `flowPath(source, sink)`, select `sink.getNode(), source, sink, message`.

## 2. Label → QLL predicate mapping (sources)

All 11 `role=source` entries of pass 1 are modeled. Site selection is by reviewed AST shape + `lib/streamlit/` scope; `role=none` entries are not modeled (by construction, `none` entries cannot produce flows).

| Label | Role/class (conf) | QLL predicate | Node kind | External input boundary and access conditions |
| --- | --- | --- | --- | --- |
| src-012 | source/tp (0.97) | `MySources::componentRoutePath` | `parameterNode` of `ComponentRequestHandler.get` arg 1 (`path`) | Decoded tornado route capture of `/component/(.*)` (server.py:391-395). Unauthenticated GET (no XSRF); cross-origin reads possible when CORS disabled/development mode (components.py:351-353). Precondition: one registered path-based component (`declare_component(path=...)`), else 404 (components.py:313-317). Attacker controls everything after the component name. |
| src-016 | source/tp (0.80) | `staticRoutePath` | `parameterNode` of `StaticFileHandler.parse_url_path` arg 1 (`url_path`) | Decoded catch-all static route `/(.*)` (server.py:417-432). Unauthenticated GET. In-repo the value only feeds the page-name lookup and `super().parse_url_path` — the actual disk read is tornado library code outside the DB. |
| src-018 | source/candidate (0.60) | `websocketMessage` | `parameterNode` of `_BrowserWebSocketHandler.on_message` arg 1 (`payload`) | Raw WebSocket bytes on `/stream`, parsed as BackMsg protobuf (server.py:789). Protobuf field reads are not modeled as attribute flows, so this source is expected to yield **no** in-repo flow (documented gap, see §6). |
| src-007 | source/tp (0.90) | `requestFieldRead` (`body`) | `exprNode` of `self.request.body` | Raw multipart POST body on unauthenticated `/upload_file` (upload_file_request_handler.py:113-118). |
| src-009 | source/tp (0.85) | `requestFieldRead` (`headers`) | `exprNode` of `self.request.headers` | Content-Type header driving `parse_body_arguments` (upload:114) and Accept header at stats.py:116 (src-008). |
| src-008 | source/candidate (0.60) | (same predicate, `headers`) | — | Accept header, comparison-only use; included for recall per label. |
| src-010 | source/candidate (0.65) | `requestArgumentCall` | `exprNode` of `self.get_argument(...)` call | Query/form argument `title` (routes.py:129) — percent-decoded via `unquote_plus` then `clean_filename` into a response header only. |
| src-011 | source/candidate (0.60) | (same predicate) | — | Query argument `hash` (routes.py:298) — in-memory cache key only. |
| src-019 | source/candidate (0.70) | `requireArgCall` | `exprNode` of `self._require_arg(...)` call | Decoded request-body values `sessionId`/`widgetId` on `/upload_file` (upload:121-122); sessionId is validated against active sessions. |
| src-020 | source/candidate (0.70) | (same predicate) | — | `widgetId` as above. |
| src-022 | source/tp (0.80) | `multipartFilenameRead` | `exprNode` of `file["filename"]` subscript | Client-supplied multipart filename (upload:144) stored into `UploadedFileRec.name`; in-memory (`UploadedFile(io.BytesIO)`). Only the `filename` key — `content_type`/`body` are `role=none` (src-023/024) and are not matched. |

**Source restriction to `self.request.*` spelling is deliberate:** `ws.request.headers["X-Streamlit-User"]` at server.py:677 is a genuine request-header read that Phase 1 extraction did not capture (the extraction pattern matched `self.request.*` only). It is **not** modeled in the query (unreviewed) and is recorded here per the Step 4 protocol as a candidate label omission to be re-reviewed in Phase 1 before any Phase 2 rerun — labels.json was not modified.

## 3. Label → QLL predicate mapping (sinks)

All 30 `role=sink` entries deduplicate to 10 signatures (per the labels.json dedup note: Step 4 must deduplicate by `(module, callable, arg_index, flow_kind)`). Matching is signature-based within `lib/streamlit/` (the Phase 1 extraction scope); label classification (tp/candidate/fp) is retained for Step 6 filtering and does not change the predicates.

| Signature | Labels | Predicate | Dangerous position | Operation / access type |
| --- | --- | --- | --- | --- |
| `open`, argument 0 | sink-009 (tp) + 15 fp/candidate | `builtinOpenPathSink` | arg 0 (path text) | File read/write per mode. Key site: components.py:325 `open(abspath, "rb")` (the confirmed traversal read). Other labeled sites: cli.py:75 (write), image.py:339/415, media.py:184, config.py:1054, credentials.py:128/191, file_util.py:81/106, metrics_util.py:38/42, secrets.py:141, source_util.py:43, util.py:95, watcher/util.py:92. Matching is plain-`open`-name only, so `Image.open` (in-memory bytes) and `webbrowser.open` (not filesystem) do not match; the only other `open(`-shaped texts in the package are docstring examples and the `def open` method definition (server.py:752), neither of which is a Call node. |
| `tokenize.open`, argument 0 | sink-022 (fp) | `tokenizeOpenSink` | arg 0 | PEP263-aware source read (source_util.py:41). |
| `os.remove`, argument 0 | sink-002/003/004/005 | `osRemoveSink` | arg 0 | File delete (caching cleanup, credentials reset). |
| `os.makedirs`, argument 0 | sink-026/027 | `osMakedirsSink` | arg 0 | Directory create. |
| `os.stat`, argument 0 | sink-028/029 | `osStatSink` | arg 0 | Metadata read. |
| `shutil.rmtree`, argument 0 | sink-006/007/008 | `shutilRmtreeSink` | arg 0 | Directory tree delete. |
| `tornado.netutil.bind_unix_socket`, argument 0 | sink-030 (fp) | `bindUnixSocketSink` | arg 0 | Unix socket file creation at config-derived `server.address` (server.py:191). |
| `RequestHandler.render`, argument 0 | sink-031 (fp) | `renderSink` | arg 0 | Tornado template file load; sole in-scope site routes.py:90 (fixed index.html). Receiver module inferred (dynamic dispatch). |
| `pathlib.Path.glob`, receiver | sink-032/033 (fp) | `globReceiverSink` | receiver | Directory enumeration; the enumerated directory is the receiver expression (source_util.py:161, watcher/util.py:105). |
| `tempfile.mkdtemp`, any argument | sink-001 (fp) | `mkdtempArgSink` | any positional arg | Temp directory creation. The label's path-influencing positions are keyword `dir`/`prefix`/`suffix` (arg_index −1, keyword-controlled) which cannot be expressed as a reviewed positional index; the sole site (temporary_directory.py:49) passes only starred/keyword arguments, so this predicate is **vacuous** — retained for signature completeness. |

Path *construction* APIs (`os.path.join`, `Path(...)`, string concatenation, `os.path.basename/normpath/realpath`) are never sinks: they are propagation or validation nodes, consistent with the Phase 1 extraction policy (detection.json `noise_controls`). The opened file *object* (e.g. the `file` variable from `with open(...)`) is not a sink either — only the path text argument position is.

## 4. Path propagation, decoding, normalization, roots, and symlinks (evidence)

Propagation chain for the confirmed flow `src-012 → sink-009`, checked link by link against the default `codeql/python-all 7.1.2` taint library:

| Step (real code) | Modeled by | Evidence |
| --- | --- | --- |
| `path` param → `path.split("/")` (components.py:311) | default library | `TaintTrackingPrivate.qll:126-129` `stringManipulation`: split/rsplit receiver → call result |
| `parts` → `parts[1:]` (components.py:319) | default library | `TaintTrackingPrivate.qll:86-88` `subscriptStep`: subscripted object → subscript expression |
| `"/".join(parts[1:])` → `filename` (components.py:319) | default library | `TaintTrackingPrivate.qll:133-134` `stringManipulation`: `join` argument 0 → call result |
| `os.path.join(component_root, filename)` → `abspath` (components.py:320) | **custom edge** `MySummaries::osPathJoinStep` | The default join rule propagates only argument 0; here the tainted operand is argument 1. No `os.path.join` taint model exists in python-all 7.1.2 (grep of `semmle/python/dataflow/new/internal` and `semmle/python/modeling`). The edge is arg→result on the exact `os.path` spelling, restricted to `lib/streamlit/` — all 11 in-scope call sites are genuine path-text propagation sites (detection.json: os.path.join sites are propagation nodes, not barriers). No unconditional cross-function taint was added. |
| `abspath` → `open(abspath, "rb")` (components.py:325) | default library | ordinary argument passing |

- **Decoding:** tornado unquotes regex route captures before the handler sees them, so raw `../` and percent-encoded `%2e%2e%2f` both reach `path`; the route regex `(.*)` imposes no segment constraints (server.py:391-395). `unquote_plus` (routes.py:130) applies only to the `title` query argument, which flows to a response header — not modeled as a path step.
- **Allowed root:** `component_root` comes from `ComponentRegistry.get_component_path(parts[0])` (components.py:436-443); only `parts[0]` is validated. There is **no** containment check (no `startswith`/`relative_to`/commonpath), no fixed-name mapping, and no whitelist on `filename` before `open` — verified by reading components.py:306-349.
- **Normalization order / absolute paths:** nothing normalizes `abspath`; `os.path.join(component_root, filename)` with a `filename` beginning with `/` (or a drive letter on Windows) returns an absolute path that discards `component_root` — the join is a propagator, not a guard.
- **Symlinks:** no symlink handling exists on this path (no `os.path.realpath`, no `follow_symlinks` logic in the component flow); the traversal does not depend on symlinks, and none is created. TOCTOU-adjacent `os.path.exists/isdir` guards elsewhere (cli.py:203, file_util.py:75, memo_decorator.py:126) guard fixed internal paths and are not barriers on any labeled flow. Recorded as **not applicable**.
- **Tornado library side:** for the static route (src-016), the disk read and `validate_absolute_path` containment are framework code outside the database; in-repo the value only reaches `super().parse_url_path(url_path)` (routes.py:85), which resolves to no in-DB callee — hence no alert is expected from src-016, matching the label's framework-side note.

## 5. Barrier modeling

`MySanitizers::isBarrier(node, "path_traversal")` resolves to `none()` (empty barrier, WORKFLOW 5.2.3). No sanitizer role exists in the reviewed labels, and none was invented. Candidate barriers were each evaluated against the actual traversal mechanism:

- `string_util.clean_filename` (string_util.py:64-78): genuinely strips to `[-\w.]` and rejects `..`, but it is applied to the Content-Disposition filename (routes.py:131), never a filesystem path — it blocks no path-traversal mechanism in this query.
- `_is_valid_session_id` (upload_file_request_handler.py:50-52): session-membership check; blocks nothing path-related.
- Page-name allowlist (routes.py:67-81): rewrites known page names to `index.html`; unknown paths pass through unmodified — not a barrier.
- tornado `StaticFileHandler.validate_absolute_path`: out-of-DB library code; nothing in-repo to bind, and it does not affect the `/component/` route at all (ComponentRequestHandler extends RequestHandler, not StaticFileHandler).
- `normpath`/`resolve`/`basename`/`startswith`: absent between route capture and `open` on the confirmed flow; per instructions none is mechanically treated as a filter anywhere else either.

## 6. Additional propagation needs, gaps, and CodeQL limitations

- **Expected formal alert set (prediction, to be confirmed in Step 5):** exactly one path-problem — `src-012` (`ComponentRequestHandler.get` `path` parameter, components.py:310) → `sink-009` (`open` arg 0, components.py:325). No other labeled source reaches a labeled sink in-repo: upload-boundary values terminate in memory; `on_message` payload taint stops at `msg.ParseFromString(payload)` (no arg→receiver-object step exists and none was invented); `parse_url_path` defers out of the DB; `get_argument("title")` terminates in a response header. This prediction is recorded for verification against Step 5 output, not as a result.
- **Wrapper summary steps NOT added (no unconditional cross-function taint):** `open_python_file` (source_util.py:28-43) — callers pass operator-local paths; `streamlit_read`/`streamlit_write` (file_util.py:61-115) — callers pass framework-computed hashed cache paths; `parse_body_arguments` → `args`/`files` dicts — superseded by modeling `_require_arg` returns and `file["filename"]` as source nodes (per labels); `UploadedFile` deserialization → app-script widget values — app scripts are outside this DB; BackMsg `rerun_script` → widget states — needs protobuf field modeling. If Step 5 shows recall gaps, these are the first candidates for reviewed summary edges.
- **Dynamic dispatch / alias limitations:** `self.render(...)` and `<expr>.glob(...)` receiver modules are inferred (label metadata says so); sink matching is by call-site spelling (`os.remove`, `shutil.rmtree`, `tornado.netutil.bind_unix_socket`, `tokenize.open`), so alternate import spellings (`from os import remove`) would not match — none occur in `lib/streamlit` (verified by grep). `mkdtemp` keyword positions are unmodelable with the reviewed positional index (predicate is vacuous; see §3).
- **Windows path quirk carried from Phase 1:** the database was created on Windows; the scope predicate normalizes backslashes in `File.getAbsolutePath()` before matching `…/lib/streamlit/…`, mirroring the extraction fallback (detection.json `database_content_and_path_format`). `cli.py:196`'s `rsplit("/")`-based basename does not split Windows backslashes (sink-014 caveat) — that flow has no labeled source (src-021 is `role=none`), so it cannot alert.
- **Diagnostics (not written as files, not formal Pass 1 alerts):** if wrapper behavior needs debugging before Step 5, a non-alert query selecting `MySources::isSource`/`MySinks::isSink`/`MySummaries::isAdditionalTaintStep` hits (e.g. `select n, "src-012 node"` for each source predicate, or `Pass1PathTraversalFlow::flow` instead of `flowPath`) would enumerate matched nodes without producing path-problem results. Per the instruction to generate only the six files, no diagnostics file was created.
- **Label omission found (for Phase 1 re-review, not fixed here):** `ws.request.headers["X-Streamlit-User"]` (server.py:677) is an unreviewed request-header read missed by extraction (`self.request.*` pattern only). Reason recorded; labels.json unchanged; not modeled in the query.
- **Audit gap found:** `labels/review_decision.json` does not exist (see §1). Recommend writing it (even with `reviewer: "auto"`) before Step 5 execution.

## 7. API verification record (no compilation performed)

Every construct used was verified read-only in `C:/Users/lzh/.codeql/packages`:

- `semmle.python.dataflow.new.DataFlow` exposes `DataFlow::Node`, `DataFlow::exprNode(Expr)`, `DataFlow::parameterNode(Parameter)` (`…/new/internal/DataFlowPublic.qll:303,350`).
- `DataFlow::ConfigSig` (isSource/isSink/isBarrier/isAdditionalFlowStep with `none()` defaults) — `codeql/dataflow/2.1.6/…/DataFlow.qll:401-427`; `TaintTracking::Global<DataFlow::ConfigSig>` with `PathNode`/`flowPath`/`PathGraph` members — `…/TaintTracking.qll:167-192` and `DataFlow.qll:710-739,792`. This matches `assets/taint_query.ql.tmpl` lines 20-44 verbatim.
- Python AST: `Call.getFunc()/getArg(int)/getAnArg()` (Exprs.qll:156-171,183), `Attribute.getName()/getValue()` (Exprs.qll:61-93), `Name.getId()` (Exprs.qll:427-429), `Subscript.getObject()/getIndex()` (Exprs.qll:77-93), `StringLiteral.getS()` (verified in Phase 1), `Function.getArg(int)` (AstGenerated.qll:536), `Parameter.getFunction()/getName()`, `Function.getScope()`/`Class extends …, Scope` (Class.qll:89; methods' scope is the Class — Class.qll:94), `AstNode.getLocation().getFile()`, `File.getAbsolutePath()/replaceAll` (Files.qll + codeql.util.FileSystem; the `replaceAll("\\\\", "/")` backslash-normalization idiom is the one proven by the Phase 1 extraction on this same database). All are exposed via `import python` (python.qll imports Files/AstExtended/Exprs/Function/Class/…).
- Default taint steps cited in §4: `…/new/internal/TaintTrackingPrivate.qll:86-88` (subscript), `:114-134` (string methods incl. split/join), and the absence of any `os.path.join` model (grep of `…/new/internal` and `semmle/python/modeling`).
- No `API::Node`/`DataFlow::Node` mixing (pure AST matching); `module` is never used as a variable name; no nonexistent AST API is called.

## 8. Experiment independence

This generation used only: the reviewed Phase 1 label artifacts, the Augur workflow/reference/template files, the local CodeQL pack sources read as documentation, and the real streamlit source in the experiment directory. No PyVul ground truth, known CVE line numbers, or fix patches were consulted; the source tree, CodeQL database, Augur installation, and Phase 1 outputs were not modified. No query compilation or analysis was executed, per instructions.
