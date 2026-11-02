# Phase 2 Step 4-5 - Query Generation Notes (Pass 1: Path Traversal, pymodbus)

- **Run**: iris-pymodbus-pathtraversal-pass1-20261023, Phase 2 Step 4 (libraries) + Step 5 (pass query generation)
- **Inputs**: `labels/labels.json` (pass_id=1, 34 entries: 3 source / 8 sink / 0 sanitizer / 1 summary / 22 none), `exploration/detection.json`, Augur `WORKFLOW.md` Phase 2, `references/python.md`, `references/patterns.md`, `assets/taint_query.ql.tmpl`, and the real pymodbus_vuln source at each label's file:line anchor.
- **Outputs (this step, generation only - no compilation, no query execution, no alerts)**:
  1. `libraries/MySources.qll`
  2. `libraries/MySinks.qll`
  3. `libraries/MySanitizers.qll`
  4. `libraries/MySummaries.qll`
  5. `queries/Pass1_PathTraversal.ql`
- **Review-gate note**: `labels/review_decision.json` does **not** exist - Phase 1 Step 3 was contracted to stop after its four output artifacts, and no separate review-decision file was produced. The operator instruction to proceed to Phase 2 Step 4-5 is taken as the (automated-mode, WORKFLOW 4.5) approval; the Pass 1 label set was used exactly as written and was **not** modified.
- **Toolchain versions**: CodeQL CLI 2.25.1 (E:\codeql); local pack `codeql/python-all` 7.1.2 (also 7.1.1 cached; qlpack `iris/pymodbus-cwe22` depends on `codeql/python-all: "*"`). All QL APIs used were verified by reading the 7.1.2 library sources (see §7) - notably `Call.getANamedArg()`/`Keyword.getArg()`/`Keyword.getValue()` are used instead of `getArgByName`, which does not exist in this pack version.

## 1. Label ID ↔ QLL predicate mapping

All library predicates dispatch on the unified pass key `"path_traversal"`. Anchoring is structural (file pattern + enclosing function/method + callee shape + argument position/keyword), not line-based, so each rule matches exactly the labeled call site while tolerating line drift; the label's file:line is quoted in each rule's doc comment and in the tables below.

### MySources::isSource (3 rules from role=source, classification=tp)

| Label | QL rule | Node matched | Source-code evidence |
| --- | --- | --- | --- |
| S05 | `isReviewedRequestPathRead` via handler `handle_html_static` | `Attribute` `request.path` | http_server.py:260 `if not (page := request.path[1:]): page = "index.html"`; routes `GET /{tail:[a-z0-9.]*}` (:172) and `GET /` (:173); aiohttp `request.path` is the client-controlled percent-decoded URL path |
| S06 | same, handler `handle_html` | `Attribute` `request.path` | http_server.py:271 `page_type = request.path.split("/")[-1]`; route `GET /api/{tail:[a-z]*}` (:170) |
| S07 | same, handler `handle_json` | `Attribute` `request.path` | http_server.py:287 `page_type = request.path.split("/")[-1]`; route `POST /api/{tail:[a-z]*}` (:171) |

External input boundary and access conditions per source:

- **S05**: network client of the simulator web console (any party that can reach `http_host:http_port`, default `0.0.0.0:8080`, http_server.py:118-119). The value read is the request URL path after aiohttp percent-decoding; the handler strips the leading `/`. Receiver constrained to the handler parameter name `request`, file constrained to `pymodbus/server/simulator/http_server.py`, function constrained to the three labeled handler methods - no other `request.path` read in the codebase is treated as a source.
- **S06/S07**: same network boundary, but the reviewed downstream use is a `generator_html`/`generator_json` **dict key** (:276-282, :289-290) - no file access; expected to yield no path-problem alert, kept because the boundary is genuinely untrusted.

Rejected source candidates (role=none, not modeled): S01 (`annotate_pymodbus_logs` local contrib param), S02 (`log_file` dead config), S03 (`json_file` operator config), S04 (`custom_actions_module` -> importlib, Pass 4 semantics), S08/S09 (`log_file_name` operator logging config; no in-repo caller passes it), S10/S11/S12 (argparse CLI boundary, no privilege differential). **No source was invented to manufacture a flow - in particular no `file_handler(path)`-style parameter was promoted to a source.**

### MySinks::isSink (8 rules from role=sink, classification=tp)

| Label | QL rule | Dangerous argument | Real file operation / access type | Call relationship |
| --- | --- | --- | --- | --- |
| K11 | `simulatorStaticOpenSink` | `open(file, ...)` positional arg **0** | builtin open - file **read** (existence probe; `with` scope) | handle_html_static; `file` = K10 join result; same try block as K12; except maps FileNotFound/IsADirectoryError -> 404 (:266-267) |
| K12 | `simulatorFileResponseSink` | `web.FileResponse(file)` positional arg **0** | file **response**: aiohttp opens + streams file content as HTTP body (internal open outside the DB; call-site anchored) | handle_html_static; same `file` as K11, inside the same `with open(...)` try block (:263-265) |
| K06 | `simulatorSetupOpenSink` | `open(json_file, ...)` positional arg **0** | file **read** (json.load of setup config) | ModbusSimulatorServer.__init__ :130-131; fed by CLI/embedding-app constructor arg (no labeled untrusted source) |
| K03 | `explainOpenSink` | `open(file, ...)` positional arg **0** | file **read** (log annotation input) | annotate_pymodbus_logs :141; caller-supplied local path |
| K04 | `explainCopyfileSink` | `shutil.copyfile(out_file.name, file)` positional arg **1** (destination) | file **write/overwrite** (temp result copied back over the given path) | annotate_pymodbus_logs :168; arg 0 is the internal NamedTemporaryFile name (rejected as K05) |
| K13 | `loggingFileHandlerSink` | `logging.FileHandler(log_file_name)` positional arg **0** | file **write** (open/create for append) | Log.apply_logging_config :56-59; reachable only if an embedding app passes a filename (none in-repo) |
| K16 | `replConfigOpenSink` | `open(modbus_config_path, ...)` positional arg **0** | file **read** (json.load of server config) | typer command `run` :172-174; CLI operator option |
| K21 | `certChainLoadSink` | `load_cert_chain(certfile=...)` keyword **"certfile"** value (label arg_index 0; sibling `keyfile` keyword is the same label family) | file **read** (ssl loads cert + key files) | CommParams.generate_ssl :131-134; provenance ModbusTlsServer.__init__/client TLS params - operator config, no labeled untrusted source |

Rejected sink candidates (role=none, not modeled): K01/K02/K19/K20 (TLS definition-side params - parameters, not file accesses), K05 (os.remove of NamedTemporaryFile's own generated name), K07/K08/K14/K17 (constant path joins), K09 (open of constant generator template), K15 (FileHistory of constant home path), K18/K22 (serial_for_url device/socket open of operator comm config).

Path-text vs. file-object distinction: every sink node is the **path string/Path expression passed as the dangerous argument**, never the file object returned by open(); no post-open file-object API (read/write on the handle) is treated as a sink.

### MySanitizers::isBarrier (0 rules)

Resolves to `none()` for the pass key. No barrier is provable from the real source: the static-file handler performs **no** canonicalization, no root-containment check, no basename extraction, no `..` rejection (full audit of http_server.py:258-267 in Phase 1). The `try/except (FileNotFoundError, IsADirectoryError)` at :266-267 is 404 error handling, not validation, and is therefore not a barrier.

### MySummaries::isAdditionalTaintStep (1 rule from role=summary, classification=tp)

| Label | QL rule | Edge | Source-code evidence |
| --- | --- | --- | --- |
| K10 | `isReviewedStaticPathJoinCall` + arg->result | any positional argument of `os.path.join(...)` -> call result, anchored to handle_html_static | http_server.py:262 `file = os.path.join(self.web_path, page)`; result assigned to `file`, passed unchanged to open (:264) / FileResponse (:265); reviewed tainted position is arg 1 (`page`); arg 0 is the fixed base `self.web_path` (:166) |

## 2. Path construction, decoding, normalization, allowed-root and symlink evidence

- **Decoding**: aiohttp percent-decodes the URL once upstream of `request.path` (external library; single documented decoding, no double-decode step exists in DB code). No `unquote`/`quote` call exists anywhere in the tree.
- **Construction**: the only request-derived construction is `os.path.join(self.web_path, page)` (:262) - modeled as summary K10 (arg->result on that exact call site only). The constant constructions (`os.path.join(dirname(__file__), "web")` :166; `os.path.join(self.web_path, "generator", entry)` :200; argparse default :88; `Path.home().joinpath(".pymodhis")` repl/client:157) get **no** propagation edge - they have no tainted operand.
- **Normalization / allowed root**: none anywhere on the flow - no `normpath`, `abspath`, `resolve`, `relative_to`, `startswith`, `basename`, no allowlist mapping in DB code. The declared base is `self.web_path` = package `web/` directory (:166), but nothing enforces containment of the joined result.
- **Absolute paths / `..` / separators**: the join semantics mean a `page` containing `/`, `\`, or an anchored/absolute form would escape the base - nothing in the handler prevents it (review question set of Phase 1, points 4-5).
- **Symlinks / TOCTOU**: no symlink-handling code exists on the flow; `web/` holds fixed package assets. The handler is a single-shot `open()` inside `try` - no exists()-then-open window. Not applicable; nothing found (recorded, not assumed).

## 3. Barrier validity discussion

No barrier entries exist, and none were invented. Specifically **not** asserted as barriers (per the "cannot mechanically treat as filters" rule):

- the aiohttp route regex `/{tail:[a-z0-9.]*}` (:172) - external-library router semantics, not DB code; whether its anchored whole-path matching constrains `request.path[1:]` to `[a-z0-9.]` (no separators, no `%..` sequences) in the deployed aiohttp version is manual-review point **R1** (detection.json uncoveredCases; phase1_review.md §5). If it does constrain, the S05 finding is a false positive at triage time; if not, it is a real traversal channel. Either way it is not a CodeQL-provable barrier node on the taint path.
- `try/except FileNotFoundError/IsADirectoryError -> HTTPNotFound` (:266-267) - error handling after the open, not path validation before it.

## 4. Propagation completeness, gaps and known limitations

- **Expected primary finding** (informal, from labels + code reading; NOT a query run): S05 → (slice/walrus/assignment standard steps) → K10 summary → K11 and K12, i.e. `request.path[1:]` → `open(:264)` / `web.FileResponse(:265)`. All other labeled sources have no sink-reachable flow; all other labeled sinks have no untrusted source.
- **Modeled-but-inert rules (by design)**: S06/S07 sources, and sinks K03/K04/K06/K13/K16/K21 - kept because their API identification was reviewed as correct; no alert is expected from the current source set.
- **Potential duplicate alerts**: K11 and K12 share the same tainted `file` expression; the path query may emit one alert per sink call site. This is intended (each is a distinct dangerous file access) and is to be deduplicated only at report/triage time (Step 6), not by weakening the sink model.
- **Dynamic dispatch / alias gaps**: callee matching is name/shape-based (`open`, `os.path.join`, `web.FileResponse`, `shutil.copyfile`, `logging.FileHandler`, `load_cert_chain`, receiver attribute chains). Rebinding (e.g. `from os.path import join`, `from aiohttp import web as w`) would not match; a grep of the tree confirms none of the labeled sites uses such aliases, and the file+function anchoring keeps the rules from matching unrelated look-alikes.
- **`**kwargs` forwarding**: `ModbusSimulatorServer(**cmd_args)` (simulator/main.py:118) forwards CLI args as keywords; not modeled as a summary because the CLI boundary was reviewed as non-untrusted (S10-S12 = none). If a future pass re-labels that boundary, a summary edge would be needed there - flagged as a gap, not silently added.
- **aiohttp externals**: `web.FileResponse`'s internal file open and aiohttp's router semantics are outside the CodeQL database (AST-level only); the sink is anchored at the call site, and R1 governs exploitability.
- **Stdlib taint overlap**: the installed pack may already model `os.path.join` arg→result; the K10 summary is then redundant but harmless (same edge re-asserted on one call site).
- **Diagnostics (not part of the formal Pass 1 output)**: before the formal analysis run, a temporary diagnostics query (e.g. selecting the matched source Attribute/sink Call sites and the K10 call directly, without PathGraph) can verify that each library rule binds exactly one AST node per label. Per the task contract, no such file was created in this step - only the six contracted artifacts exist.

## 5. Query metadata (queries/Pass1_PathTraversal.ql)

- `@kind path-problem`, `@problem.severity error`, `@precision medium` (source/sink rules are structurally anchored, but exploitability rests on unresolved external-library semantics R1 - medium rather than high is the honest precision claim), `@tags security` + `external/cwe/cwe-022`, `external/cwe/cwe-023`, `external/cwe/cwe-036`, `external/cwe/cwe-073`, `@id py/augur/pymodbus/pass1-path-traversal`.
- Rendered from `assets/taint_query.ql.tmpl` with: LANGUAGE_IMPORTS = `python` + `semmle.python.dataflow.new.DataFlow` + `semmle.python.dataflow.new.TaintTracking`; SOURCE_MODULE `libraries.MySources`; SINK_MODULE `libraries.MySinks`; SANITIZER_MODULE `libraries.MySanitizers`; SUMMARY_MODULE `libraries.MySummaries`; CONFIG_NAME `Pass1Config`; FLOW_MODULE `Pass1Flow`; PASS_KEY `"path_traversal"`.
- Flow shape: `module Pass1Config implements DataFlow::ConfigSig` (all four predicates delegated with the pass key), `module Pass1Flow = TaintTracking::Global<Pass1Config>`, `import Pass1Flow::PathGraph`, `from Pass1Flow::PathNode source, Pass1Flow::PathNode sink where Pass1Flow::flowPath(source, sink) select sink.getNode(), source, sink, "<message>"`.
- `qlpack.yml` (unchanged, at iris root): `iris/pymodbus-cwe22` depending on `codeql/python-all: "*"`; library imports use the `libraries.My*` dotted pack-relative syntax; all four library module interfaces (`MySources::isSource`, `MySinks::isSink`, `MySanitizers::isBarrier`, `MySummaries::isAdditionalTaintStep`) exist with the exact `(DataFlow::Node, string)` / `(DataFlow::Node, DataFlow::Node, string)` signatures the query calls.

## 6. QL API verification against the local pack (python-all 7.1.2)

Every API used was confirmed present in `~/.codeql/packages/codeql/python-all/7.1.2/semmle/python/`:

- `AstNode.getLocation()` / `Location.getFile()` / `File.getAbsolutePath()` (Files.qll:249, AstExtended.qll) - file anchoring.
- `AstNode.getScope()`, `Function` extends `Scope`, `Function.getName()`, `Scope.getEnclosingScope()`, `Class.getName()` (Function.qll:10/19, Scope.qll, Class.qll:122) - enclosing function/method/class anchoring.
- `Call.getFunc()`, `Call.getArg(int)`, `Call.getANamedArg()` -> `DictItem`, `Keyword.getArg()` (name) / `Keyword.getValue()` (Exprs.qll:103-176, AstGenerated.qll:198-218). `getArgByName` does **not** exist in 7.1.2 - not used.
- `Attribute.getName()` / `Attribute.getObject()` (Exprs.qll:67-77), `Name.getId()` (Exprs.qll:427-429).
- `DataFlow::Node.asExpr()` (dataflow/new/internal/DataFlowPublic.qll:200+); `DataFlow::ConfigSig` signature module with `isSource/isSink/isBarrier/isAdditionalFlowStep` (codeql/dataflow 2.1.7 DataFlow.qll:401-433); `TaintTracking::Global<Config>` (TaintTracking.qll:313); `GlobalFlowSig` with `PathNode`, `flowPath`, `PathGraph` (DataFlow.qll:710-755).
- `module` is never used as a QL variable name; no `API::Node` is mixed with `DataFlow::Node`; no deprecated `StrConst`/`Decorator` classes are referenced.

## 7. Experiment independence

- No PyVul ground truth, known CVE line numbers, or fix patches were consulted; no `VULNERABILITY_AUDIT_REPORT.md` / `path_traversal_sinks.csv` / audit reports in the source tree were read.
- `labels/labels.json` was consumed read-only and unmodified; no label omissions were discovered during generation (all 12 tp/summary entries map to rules; all 22 none entries map to documented non-rules), so no Phase 1 re-review was triggered.
- Source code, the CodeQL database (pymodbus-db), Augur files and Phase 1 artifacts were not modified.
- Per the task contract, no compilation and no analysis run was executed; the artifacts are generation-only. WORKFLOW global rules 1-7 (pack install, sequential execution, path-problem severity, mandatory barrier hook) are addressed at execution time in the next step.

## 8. Label omissions found during generation

None. Every role=source/sink/summary entry was modeled; every role=none entry corresponds to a documented non-rule; no candidate required re-labeling.
