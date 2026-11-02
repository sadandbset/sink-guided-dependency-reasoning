# Augur Phase 2 Step 4-5 - Query Generation Notes (Pass 1 Path Traversal, flask-cors)

- **Project**: Flask-Cors (flask-cors_vuln snapshot, `flask_cors/version.py` = 3.0.8; CodeQL DB `flask-cors-db`, creation sha 5c6e05e)
- **Label contract**: `iris/labels/labels.json`, run `flask-cors-path-traversal-pass1-20261022` (67 entries: 8 source/tp, 3 sink/fp, 4 summary/candidate, 0 sanitizer, 52 none/fp), pass 1, CWE-022/023/036/073
- **Generated files**: `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass1_PathTraversal.ql` (rendered from `augur-0.3.0/assets/taint_query.ql.tmpl`)
- **Pack layout**: `qlpack.yml` (name `iris/flask-cors-cwe22`, dependency `codeql/python-all: "*"`) at the iris root; the four libraries under `iris/libraries`, imported as `import libraries.MySources` etc.; the query under `iris/queries`. All predicate interfaces referenced by the query exist in the libraries: `MySources::isSource(node, passKey)`, `MySinks::isSink(node, passKey)`, `MySanitizers::isBarrier(node, passKey)`, `MySummaries::isAdditionalTaintStep(from, to, passKey)`, all dispatched on the unified pass key `"path_traversal"`.
- **Status per task contract**: generation only - no `codeql pack install`, no compile validation and no query execution were performed in this round (execution is deferred to the next round, consistent with the Step 1-2 generation-only round).
- **Dataflow API style**: `DataFlow::ConfigSig` + `TaintTracking::Global<Pass1Config>` + `Pass1Flow::PathGraph` + `flowPath(source, sink)` (WORKFLOW.md 3.1 compatibility policy, preferred style). No `module` variable name, no `Decorator`/`StrConst` classes, no `AstNode.getFile()`, no mixing of `API::Node` with `DataFlow::Node` (all matching is AST-level, mirroring the extraction queries' `match_kind=ast` philosophy).
- **Audit-trail note**: `labels/review_decision.json` is **absent** from the workspace (WORKFLOW.md 4.5 defines it as an optional audit artifact; it was not written in the Step 3 round). It was not fabricated here. Per the operator's instruction that the Step 3 labels are reviewed, `labels.json` (with `labels/phase1_review.md` as the checkpoint payload) is treated as the reviewed contract. If a formal gate record is required, it should be added in a Phase 1 follow-up - not by Phase 2.

## 1. Label ID -> role -> QLL predicate mapping

### 1.1 Sources -> `MySources::isSource(node, "path_traversal")`

Two name-anchored AST branches cover all 8 source labels (signatures deduplicated per WORKFLOW.md 5.1.4):

| Label IDs | Signature (labels.json) | QLL branch | Source-code evidence |
| --- | --- | --- | --- |
| src-045, src-046 | flask `request.path`, flow_kind field | `requestAttributeRead`: `Attribute` with object `Name "request"` and name `path`/`headers`/`method`, `source.asExpr() = a` | `flask_cors/extension.py:178` `if try_match(request.path, res_regex):`; `:180` `request.path` in `LOG.debug(...)`; `from flask import request` (extension.py:11) |
| src-023 | flask `request.headers`, field | same branch | `flask_cors/core.py:245` `get_cors_headers(options, request.headers, request.method)` |
| src-024 | flask `request.method`, field | same branch | `flask_cors/core.py:245` (same call, distinct Attribute node) |
| src-037 | flask `request.method`, field | same branch | `flask_cors/decorator.py:125` `request.method == 'OPTIONS'`; `from flask import make_response, request, current_app` (decorator.py:13) |
| src-011, src-014, src-016 | `request_headers.get` (return value), module flask_cors.core | `requestHeaderValueRead`: `Call` whose func is `Attribute "get"` on `Name "request_headers"`, `source.asExpr() = c` | `flask_cors/core.py:177` `request_headers.get('Origin')`; `:194` `request_headers.get(ACL_REQUEST_METHOD, '')`; `:203` `request_headers.get(ACL_REQUEST_HEADERS)`; the parameter is fed from `request.headers` at core.py:245 |

**Scope verification performed this round** (grep over the whole snapshot excluding only the nested `flask-cors-db/` directory): the two structural patterns match **exactly** the 10 audited AST nodes and nothing else - `request.(path|headers|method)` appears only at the 5 audited sites; `request_headers.get` only at the 3 audited sites; tests/ contain none of these patterns and no `open()` calls. Therefore no file-path exclusion predicates (and no Windows/Unix separator string matching) are needed in the QLLs; matching is purely structural.

### 1.2 Sinks -> `MySinks::isSink(node, "path_traversal")`

One rule (signature deduplication: `open` / builtins / argument 0):

| Label IDs | QLL rule | Source-code evidence |
| --- | --- | --- |
| sink-011, sink-014, sink-017 | `fileOpenPathArgument`: `Call` whose func is `Name "open"`, sink node = `c.getArg(0)` (the path text) | `setup.py:15` `open(join(dirname(__file__), 'flask_cors/version.py'), 'r')`; `setup.py:18` `open (join(dirname(__file__), 'requirements.txt'), 'r')` (space before `(` - still a `Name "open"` call); `setup.py:29` `open('README.rst')`; import context `setup.py:13 from os.path import join, dirname` |

Verified: bare-name `open` calls exist exactly at setup.py:15/:18/:29 in the entire snapshot (flask_cors modules have zero filesystem calls; tests/ have no `open()`; the only other `join`/`dirname` text occurrences are attribute-form `', '.join(...)` in core.py:171/:328, which the `Name` form does not match). No file-response (`send_file`/`send_from_directory`), file-write, delete, or archive-extraction sink family exists anywhere in the snapshot.

### 1.3 Sanitizers -> `MySanitizers::isBarrier(node, "path_traversal")`

`none()` - zero sanitizer labels. See section 4.

### 1.4 Summary steps -> `MySummaries::isAdditionalTaintStep(from, to, "path_traversal")`

One rule, scoped to the audited instances:

| Label IDs | QLL rule | Source-code evidence |
| --- | --- | --- |
| sink-012, sink-015 (os.path.join), sink-013, sink-016 (os.path.dirname) | `pathConstructionStep`: `Call` with func `Name "join"` or `Name "dirname"`, enclosing module name `"setup"`, step from `c.getArg(0)` to the call result `c` | `setup.py:15` `join(dirname(__file__), 'flask_cors/version.py')`; `setup.py:18` `join(dirname(__file__), 'requirements.txt')`; the from-import alias at `setup.py:13` |

### 1.5 Labels intentionally NOT modeled (role=none, 52 entries)

None-role labels map to no predicate by design; documented so the mapping is complete:

- **src-001, src-027, src-028, src-031, src-038, src-039, src-042** (config_param) and **src-003..src-006, src-008, src-012, src-013, src-015, src-017..src-021, src-029, src-030, src-032..src-036, src-040, src-041** (config_field, 22 rows): operator-trust configuration (DEFAULT_OPTIONS core.py:52-63, app.config CORS_* core.py:310-314, decorator/constructor kwargs) - not attacker input, so not sources; no sink is reachable from them either.
- **src-002, src-007, src-009, src-010, src-025, src-026** (request_value_param): internal helper parameters carrying request-derived values (Origin/ACRM/ACRH/Headers/method). Not modeled as sources (internal parameter is not automatically a source) and not given summary edges: their values terminate in `re.match` (core.py:278/:280), `LOG.debug`, and response-header writes - no pass-1 sink is downstream, so no cross-function propagation is needed or justified.
- **src-022, src-043** (wrapper_param) and **src-044** (response_header): response-object boundaries used only for header reads/writes - not path-shaped.
- **sink-001..sink-010, sink-018..sink-021** (examples/docs dirname/abspath/sys.path.insert, 14 rows): constant `__file__`-derived import-path hacks; not file access, not taint-relevant, and explicitly not sanitizers.

## 2. Source boundaries: input controllability and access conditions

All 8 sources sit on the Flask `request` proxy - the library's only untrusted boundary. flask-cors applies **no authentication and no authorization of its own**; any HTTP client reaching a Flask app that uses the extension controls these values (the CORS origin allow-list is a response-header policy, not an input permission check):

| Source | Boundary | Attacker control | In-library consumption |
| --- | --- | --- | --- |
| `request.path` (src-045/src-046) | URL path, percent-decoded by Werkzeug before the library sees it | Full (any client) | regex match subject only (extension.py:178 -> core.py:275-285); LOG.debug (:180) |
| `request.headers` (src-023) | full request header mapping | Full (any client) | passed to get_cors_headers; Origin/ACRM/ACRH read from it |
| `request.method` (src-024/src-037) | request-line verb | Full (any client) | `== 'OPTIONS'` preflight branch only |
| `request_headers.get('Origin'/'ACRM'/'ACRH')` (src-011/src-014/src-016) | individual header values | Full (any client) | origin matching, method allow-check, header-name echo |

Note on decoding: the library performs no URL decoding of its own; the single decoded value visible to it is `request.path` (decoded upstream by Flask/Werkzeug), and it is consumed by `re.match` only - never used to construct or locate a filesystem path. Therefore no decode-then-use step needs modeling.

## 3. Sinks: real file operations, dangerous argument, access type, call relationships

| Sink | Operation | Dangerous path arg | Access type | Call relationships |
| --- | --- | --- | --- | --- |
| setup.py:15 | `open(join(dirname(__file__), 'flask_cors/version.py'), 'r')` | index 0 (the join result - path **text**, not the file object `f`) | read (packaging-time) | result `f.read()` is `exec`'d at setup.py:16 - Pass 4 material, deliberately outside this Pass 1 query |
| setup.py:18 | `open(join(dirname(__file__), 'requirements.txt'), 'r')` | index 0 | read (packaging-time) | result split into `install_requires` (setup.py:19) |
| setup.py:29 | `open('README.rst')` | index 0 | read (packaging-time) | result `.read()` feeds `long_description` in `setup()` |

All three instances carry literal/`__file__`-derived constant paths; the audited classification is fp, and the sink role is retained so the pass query catches any future taint into the path argument. The sink node models the path argument expression, distinguishing it from the opened file object and from `.read()` results.

## 4. Barriers: why none is emitted (and why that is safe)

Each candidate mechanism was checked against the real code and rejected - no barrier can be *proven* to block a specific traversal mechanism here:

- **Allowed-root containment**: none exists (no `startswith(base)`, no `relative_to`, no realpath-equality check, no fixed-filename map, no whitelist). The audited code serves no files, so there is no declared root directory to escape from in the first place.
- **`os.path.abspath`** (examples/*.py:17, docs/conf.py:21): canonicalization **without** base-dir containment, applied to constant `__file__` inputs; a function name is not neutralization evidence, and no attacker value ever passes through it.
- **`os.path.dirname`**: component extraction, not a traversal filter.
- **`try_match`/`try_match_any`** (core.py:271-285): regex/string allow-checks selecting CORS options for `request.path`; never guards a filesystem path (no file API downstream), so it is not a path barrier.
- **Symlinks / TOCTOU**: not applicable - no symlink resolution and no check-then-use file sequence exists anywhere (zero FS access in flask_cors).

Safety argument for the empty barrier set: no source-to-sink path exists in this codebase (section 6), so an empty `isBarrier` cannot create false positives; it would only matter if a future taint path reached an `open()` path argument, at which point a proven containment check would need to be added *from new labels*, not hand-written here.

## 5. Extra propagation edges (summary steps)

Only the four audited `os.path.join`/`os.path.dirname` argument-0 -> call-result steps were added (section 1.4), scoped to the `setup` module and justified by the real chain `dirname(__file__) -> join(...) -> open(...)` at setup.py:15/:18. They are semantically exact for these pure path helpers (no unconditional cross-function pollution), and they are likely redundant with the standard codeql/python-all stdlib flow-through models (API graphs resolve the `from os.path import join, dirname` alias), acting as a conservative audited fallback. All other intermediate wrappers (try_match, get_cors_headers, get_cors_origins, get_allow_headers, set_cors_headers, flexible_str, serialize_option) deliberately received **no** summary edges: request-derived values terminate in regex matching, logging and response headers, with no file API downstream.

## 6. Expected result and diagnostic paths (not part of the official Pass 1 output)

- **Expected alert count: zero.** The 8 sources all terminate inside flask_cors (regex matching / logging / response headers; the package has zero filesystem APIs), and the 3 sinks sit behind constant paths in the packaging script. Any alert produced by `Pass1_PathTraversal.ql` on this DB would be a false positive by construction (recorded as review point 5 in `labels/phase1_review.md` and to be filtered at Step 6).
- **Diagnostics (not generated this round per the six-file contract)**: wrapper/debug checks - e.g. counting `isSource`/`isSink` node matches (expected 10 and 3), verifying the two summary edges, and confirming `Pass1Flow::PathNode` connectivity - belong under `iris/diagnostics/` as plain select queries and must not be counted as Pass 1 findings. They can be added in the execution round if node-count sanity checks are wanted before the formal analysis.
- **Known extraction under-coverage carried from Phase 1** (detection.json uncoveredCases; no label omission found, so no re-review of labels.json was required): `serialize_option` subscript reads (core.py:334-336, config-only) and Flask URL-rule variable binding (inside the external flask package, invisible to this DB). Neither is a path traversal flow in this codebase.

## 7. Limitations and honest uncertainty

- **Name-anchored AST matching** (match_kind `ast`, medium precision): the source/sink branches anchor on syntactic names (`request`, `request_headers`, `open`, `join`/`dirname` + module `setup`). An aliased request import (`from flask import request as req`) or a renamed local would be missed - not observed in this tree. A local function named `open`/`join`/`dirname` elsewhere would over-match - verified absent in this snapshot.
- **No API-graph resolution** was used, so a same-named member on an unrelated receiver is a theoretical false-match vector (analyzed and excluded for this tree; the `', '.join(...)` string-method calls are attribute-form and not matched).
- **Module-name scoping** (`getEnclosingModule().getName() = "setup"`) in MySummaries assumes the file module's name is its stem (`setup`); if this resolved differently the summary steps would silently match nothing - which has zero alert impact here (the steps only affect the constant setup.py chain, where no source flows).
- **Not compiled**: per the task contract this round is generation-only; compile validation (`codeql query compile` / pack install) is deferred to the execution round. The structural QL shapes (Attribute/Name/Call, `getFunc`/`getArg`/`getObject`/`getName`/`getId`, `asExpr`, `getScope().getEnclosingModule()`, `ConfigSig`/`TaintTracking::Global`/`PathGraph`) reuse the API set already compiled successfully on CLI 2.25.1 + codeql/python-all in this series (per detection.json toolchain notes).
- **Windows path separators**: avoided entirely - no QL rule matches on file path strings; all scoping is structural (names, module name), so the separator ambiguity of `getLocation().getFile().getAbsolutePath()` on this Windows-built DB does not affect the model.

## 8. Experiment independence

No PyVul ground truth, known CVE line numbers, or fix patches were consulted. The source tree, the CodeQL database, the Augur installation, and the Phase 1 labels (`labels.json`, raw artifacts, stats, review notes) were not modified. The only files written this round are the six listed at the top. All modeling decisions derive from the reviewed Pass 1 labels and direct source reads of the audited sites (flask_cors/core.py, decorator.py, extension.py, setup.py, the three examples, docs/conf.py) plus the structural-scope greps documented in sections 1-3.
