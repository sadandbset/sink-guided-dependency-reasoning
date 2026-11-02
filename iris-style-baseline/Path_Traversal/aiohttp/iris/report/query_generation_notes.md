# Query Generation Notes — Augur Phase 2, Step 4–5 (Pass 1: Path Traversal)

Project: aiohttp 4.0.0a2.dev0 (`aiohttp_vuln` source tree)
Pass: 1 (CWE-022 / CWE-023 / CWE-036 / CWE-073) — pass key `path_traversal`
Generated: 2026-10-21
Inputs: `labels/labels.json` (reviewed Pass 1 labels, schema-valid), `labels/labels_raw_pass1.json`, `labels/label_stats.md`, `labels/phase1_review.md`, `assets/taint_query.ql.tmpl`, `references/python.md`, `references/patterns.md`, WORKFLOW.md Phase 2, and the real source under `aiohttp_vuln/` re-read at every cited line.

Note on `labels/review_decision.json`: this optional audit artifact was not written in Step 3 (the Step 3 contract produced `phase1_review.md` as the review payload). The reviewed input for this step is therefore `labels.json` + the review queue in `phase1_review.md`, and the decision to proceed to Phase 2 is the operator instruction initiating Step 4–5. No label was modified, and no `review_decision.json` was fabricated.

## 1. Generated artifacts

| File | Content |
| --- | --- |
| `libraries/MySources.qll` | `module MySources { predicate isSource(DataFlow::Node, string passKey) }` — 21 tp source labels |
| `libraries/MySinks.qll` | `module MySinks { predicate isSink(DataFlow::Node, string passKey) }` — 9 tp sink labels |
| `libraries/MySanitizers.qll` | `module MySanitizers { predicate isBarrier(DataFlow::Node, string passKey) }` — 3 tp sanitizer labels |
| `libraries/MySummaries.qll` | `module MySummaries { predicate isAdditionalTaintStep(DataFlow::Node, DataFlow::Node, string passKey) }` — 5 tp summary labels |
| `queries/Pass1_PathTraversal.ql` | `Pass1Config implements DataFlow::ConfigSig` + `TaintTracking::Global` + `PathGraph`/`flowPath` path problem |

Pack layout: `iris/qlpack.yml` (pack `iris/aiohttp-cwe22`, dependency `codeql/python-all: "*"`, unchanged from Step 0). Libraries are imported with dotted syntax (`import libraries.MySources`) and referenced by module name (`MySources::isSource(source, "path_traversal")`) — the same file-name/module-name convention used by `semmle.python.dataflow.new.DataFlow` (file `DataFlow.qll` declaring `module DataFlow`). The template placeholder `{{SOURCE_MODULE}}::isSource(...)` was rendered with the in-scope module name rather than the full dotted path, which is the only reference form proven valid on this pack family (evidence: `import semmle.python.dataflow.new.DataFlow::DataFlow as DataFlow` in `ApiGraphModelsSpecific.qll` shows files are path-qualified modules; queries reference inner modules by name).

API surface verified against the locally installed `codeql/python-all 7.1.2` and `codeql/dataflow 2.1.7` packs: `DataFlow::Node.asExpr()` (DataFlowPublic.qll:200/299), `DataFlow::ConfigSig` with 2-arg `isAdditionalFlowStep` (shared TaintTracking.qll:167,175), `TaintTracking::Global<Config>`, `module X::PathGraph` + `flowPath(PathNode, PathNode)` (shared DataFlow.qll:680–830), `Call.getArg(int)` (Exprs.qll:156), `Call.getFunc()`, `Attribute.getName()/getObject()` (Exprs.qll:74/77), `Subscript.getObject()` (Exprs.qll:98), `Name.getId()` (Exprs.qll:429), `AstNode.getLocation()`, `Location.getStartLine()`, `File.getBaseName()` (util FileSystem.qll:117), `File.getAbsolutePath()`. No deprecated or non-existent AST API is used; no variable is named `module`; `API::Node` is not mixed with `DataFlow::Node`.

## 2. Label ID → QLL rule mapping

### 2.1 Sources (`MySources::isSource`, pass key `path_traversal`)

| Label ID (conf) | Location | QL rule | Node shape | External input boundary / access conditions |
| --- | --- | --- | --- | --- |
| p1-src-013 (0.90) | http_parser.py:556 | `requestLinePathSource` | `Call` `line.split(" ", maxsplit=2)` (result node) | HTTP request line off the socket (pure-Python parser; the Cython parser feeds the same yarl URL boundary). `path` (result element 1, reached via tuple unpacking local flow) is the request target; fed into `URL.build(path=path_part, ...)` at :589 → `request.rel_url`. Any network client can set it. |
| p1-src-018 (0.85) | multipart.py:532 | `multipartFilenameSource` | `Call` `content_disposition_filename(params, "name")` | Content-Disposition `name` parameter of a multipart body part. Any POST client controls it (server-side request parsing). |
| p1-src-019 (0.90) | multipart.py:541 | `multipartFilenameSource` | `Call` `content_disposition_filename(params, "filename")` | Content-Disposition `filename` — the uploaded filename. In-tree it only reaches `FileField` metadata (web_request.py:743-749); the part *content* goes to an auto-named `tempfile.TemporaryFile()` (web_request.py:726). Source exists for downstream consumers of `FileField.filename`. |
| p1-src-020 (0.70) | multipart.py:552 | `multipartFilenameSource` | `Attribute` `value.name` | parsed multipart param name, re-serialized into outbound Content-Disposition (client payload mirroring). |
| p1-src-021 (0.70) | multipart.py:553 | `multipartFilenameSource` | `Attribute` `value.filename` | parsed multipart filename, same mirror. |
| p1-src-066 (0.85) | web_request.py:724 | `multipartFilenameSource` | `Attribute` `field.filename` | `Request.post()` multipart branch — the branch condition itself (content → tempfile). |
| p1-src-067 (0.85) | web_request.py:745 | `multipartFilenameSource` | `Attribute` `field.filename` (FileField ctor arg) | same value at the `FileField` construction site. |
| p1-src-049 (0.85) | web_middlewares.py:86 | `requestPathAttributeSource` | `Attribute` `request.raw_path` | raw (undecoded) request path incl. query — any routed request; feeds `request.clone(rel_url=path)` re-resolution (:23). |
| p1-src-050 (0.85) | web_middlewares.py:87 | same rule | `Attribute` `request.raw_path` | same (split("?", 1) branch). |
| p1-src-051 (0.80) | web_middlewares.py:91 | same rule | `Attribute` `request.raw_path` | plain-path branch of the middleware. |
| p1-src-052 (0.80) | web_middlewares.py:95 | same rule | `Attribute` `request.path` | percent-decoded request path (append_slash branch). |
| p1-src-053 (0.80) | web_middlewares.py:97 | same rule | `Attribute` `request.path` | decoded path (remove_slash branch). |
| p1-src-054 (0.80) | web_middlewares.py:109 | same rule | `Attribute` `request.raw_path` | redirect Location construction (pass 9 relevance; untrusted path data here). |
| p1-src-083 (0.80) | web_urldispatcher.py:350 | same rule | `Attribute` `request.rel_url.raw_path` (outer) | raw path fed to `DynamicResource._match` (regex match values decoded at :472). |
| p1-src-084 (0.80) | web_urldispatcher.py:350 | same rule | `Attribute` `request.rel_url` (inner) | carrier attribute of the raw path chain. |
| p1-src-087 (0.90) | web_urldispatcher.py:616 | same rule | `Attribute` `request.rel_url.raw_path` | StaticResource.resolve: prefix matching + slice → `_unquote_path` decode at :625 — directly upstream of the routed filename. |
| p1-src-088 (0.90) | web_urldispatcher.py:616 | same rule | `Attribute` `request.rel_url` | carrier attribute. |
| p1-src-101 (0.80) | web_urldispatcher.py:997 | same rule | `Attribute` `request.rel_url.raw_path` | UrlDispatcher.resolve router walk. |
| p1-src-102 (0.80) | web_urldispatcher.py:997 | same rule | `Attribute` `request.rel_url` | carrier attribute. |
| p1-src-091 (0.95) | web_urldispatcher.py:635 | `matchInfoFilenameSource` | `Subscript` `request.match_info["filename"]` | THE routed filename: the percent-decoded remainder of the URL after the static prefix. Attacker controls the entire relative path (one decode pass; `%2e%2e%2f` → `../`, `%2f` → separator). Populated in `StaticResource.resolve` (:625) and consumed in `_handle` — statically modeled from the read side because the `match_dict → match_info` propagation crosses a framework object boundary CodeQL cannot track (see §6). |
| p1-src-092 (0.90) | web_urldispatcher.py:635 | `matchInfoFilenameSource` | `Attribute` `request.match_info` | carrier attribute of the subscript. |

Rejected source candidates (NOT modeled, per the Step 3 review queue): p1-src-009/p1-src-010 (NETRC env — local operator trust, CWE-73 shape pending review), p1-src-012/p1-src-016/p1-src-017/p1-src-058 (raw wire/body params `feed_data`/`data_received` — genuine but noisy anchors; the precise boundary is the request-line split), all `request`-parameter carrier rows (none/fp), CLI argv (none/fp — operator-local), boolean env flags and header/cookie reads with no path consumer (none/fp). No internal wrapper parameter (e.g. a hypothetical `file_handler(path)`) was promoted to a source.

### 2.2 Sinks (`MySinks::isSink`, pass key `path_traversal`)

Path text vs. file object: all sinks below operate on **path text** (the path expression itself), except the sendfile channel which is explicitly a file-object argument and is retained only for label fidelity.

| Label ID (conf) | Location | QL rule | Real file operation | Dangerous position (access type) |
| --- | --- | --- | --- | --- |
| p1-sink-072 (0.70) | web_urldispatcher.py:657 | `staticPathProbeSink` | `os.stat` via `Path.is_dir()` | receiver `filepath` (read/stat — existence + type oracle). Caller: `StaticResource._handle` after the anchor + containment guards. |
| p1-sink-073 (0.70) | web_urldispatcher.py:667 | `staticPathProbeSink` | `os.stat` via `Path.is_file()` | receiver `filepath` (read/stat). Gates the FileResponse return. |
| p1-sink-074 (0.90) | web_urldispatcher.py:668 | `fileResponseConstructorSink` (instance) | `FileResponse.prepare()`: stat (:141), optional .gz stat (:136), open 'rb' (:288), `loop.sendfile` (:93) | positional arg 0 `filepath` (read — full file body transmission). |
| p1-sink-041 (0.85) | web_fileresponse.py:46 | `fileResponseConstructorSink` (signature) | same as above via `__init__` storing `pathlib.Path(path)` (:54) | `FileResponse.__init__` parameter `path` (label arg_index 1 counts `self`; call-site positional index 0). Implemented as the construction-call matcher `FileResponse(<arg 0>)` (Name or Attribute callable), excluding `/tests/` per the Phase 1 extraction contract — semantically equivalent under global taint arg→parameter edges, and it covers framework-wide misuse (`FileResponse(user_path)` in application code). |
| p1-sink-048 (0.70) | web_fileresponse.py:136 | `fileStatSink` | `os.stat` on the .gz sibling | receiver `gzip_path` (read/stat). Derived from `self._path` via `with_name` (:134). |
| p1-sink-049 (0.85) | web_fileresponse.py:141 | `fileStatSink` | `os.stat` on the served file | receiver `filepath` = `self._path` (read/stat — executed in executor from `prepare()`). |
| p1-sink-050 (0.90) | web_fileresponse.py:288 | `fileOpenSink` | `open()` for reading (pathlib `.open` bound method submitted to `loop.run_in_executor`) | receiver `filepath` of the bare `filepath.open` attribute reference (read — the actual file open of the serving pipeline). |
| p1-sink-046 (0.70) | web_fileresponse.py:93 | `sendfileSink` | zero-copy transmission of the already-open file | argument 1 `fobj` — **file object, not path text**; cannot independently fire on path taint (path consumed at :288). Retained for label fidelity only. |
| p1-sink-077 (0.75) | web_urldispatcher.py:683 | `directoryListingSink` | directory read (scandir) via `Path.iterdir()` | receiver `filepath` (read — directory listing, only under operator opt-in `show_index=True`). |

Rejected sink candidates (NOT modeled): p1-sink-012/014/015/017 (CookieJar save/load/open — operator-configured path params, pending review), p1-sink-025 (netrc read — env-controlled local trust), p1-sink-054 (create_unix_server — operator config), p1-sink-047 (`with_name` — summary candidate, not promoted), p1-sink-062 (url_for joinpath — application-input flow). Rejected sink fps: p1-sink-064/p1-sink-065 (url_for is_file/open — url_for callers are application code, not request data).

### 2.3 Barriers (`MySanitizers::isBarrier`, pass key `path_traversal`)

| Label ID (conf) | Location | QL rule | Mechanism it provably blocks |
| --- | --- | --- | --- |
| p1-sink-068 (0.80) | web_urldispatcher.py:638 | `absolutePathAnchorGuard` (`filename.anchor` node) | Absolute-path traversal forms: `Path("D:\\x").anchor = "D:\\"`, UNC `\\machine\c$` — rejected with HTTPForbidden *before* the join. Not blocked by it: pure-relative `../` (anchor is empty) and POSIX backslash names — which is why it is only sound in combination with the containment guard. |
| p1-sink-071 (0.90) | web_urldispatcher.py:645 | `baseDirectoryContainmentGuard` (`filepath.relative_to(self._directory)` call node) | `../` chains, decoded separators forming `..`, symlink escapes, and any resolved location outside the base: `resolve()` runs BEFORE the check (web_urldispatcher.py:643) and both sides are canonical (`self._directory` resolved at registration, :537), so `relative_to` raises `ValueError` → HTTPNotFound (646-648) for every escaping path under the default `follow_symlinks=False` (:529). Barrier blocks flows routed through the relative_to call; see §6 for the control-flow limitation. |
| p1-sink-027 (0.85) | helpers.py:360 | `basenameExtractionGuard` (`Path(name).name` attribute node) | Directory components in the client-supplied upload filename guess: `.name` extraction discards everything but the final component, so `../` and separators cannot survive (guards the client payload Content-Disposition path, not the StaticResource request path). |

Not promoted: p1-sink-063 (url_for relative_to, candidate). `resolve()` (p1-sink-069) is deliberately a summary, NOT a barrier — canonicalization is taint-preserving (the resolved location is still attacker-positioned); mechanically treating normpath/resolve/basename as safe filters is exactly what the reviewed labels reject.

### 2.4 Additional taint steps (`MySummaries::isAdditionalTaintStep`, pass key `path_traversal`)

| Label ID (conf) | Location | QL rule | Edge |
| --- | --- | --- | --- |
| p1-src-085 (0.80) | web_urldispatcher.py:472 | `unquotePathStep` | `_unquote_path(value)` arg 0 → call result (DynamicResource match-value decode). |
| p1-src-089 (0.85) | web_urldispatcher.py:625 | `unquotePathStep` | `_unquote_path(path[len(prefix)+1:])` arg 0 → call result — THE single percent-decode between wire and filename (`URL.build(path=value, encoded=True).path`, :1242-1243). |
| p1-sink-067 (0.70) | web_urldispatcher.py:637 | `pathConstructorStep` | `Path(rel_url)` arg 0 → result — str→Path coercion of the routed filename. |
| p1-sink-070 (0.70) | web_urldispatcher.py:643 | `joinPathStep` | `self._directory.joinpath(filename)` arg 0 (tainted component; receiver is operator config) → result. |
| p1-sink-069 (0.60) | web_urldispatcher.py:643 | `resolveStep` | `.resolve()` receiver (the joined path) → result (canonicalization preserving attacker positioning). |

Every edge is anchored to the exact labeled call site; there are no unconditional cross-function propagation edges and no any-node-to-any-node steps. Not promoted (candidate summaries): `request.clone(rel_url=path)` re-binding (web_middlewares.py:22), `Path(netrc_env)` (helpers.py:200), `with_name` .gz sibling (web_fileresponse.py:134), url_for joinpath (web_urldispatcher.py:577), the `_handle` request-carrier edge (p1-src-090).

## 3. Evidence for the path pipeline (join / decode / canonicalize / base directory / symlinks / timing)

Verified line-by-line in the real source (`aiohttp/web_urldispatcher.py`, `aiohttp/web_fileresponse.py`):

1. **Decode**: exactly one percent-decode — `match_dict = {"filename": _unquote_path(path[len(self._prefix)+1:])}` (:625); `_unquote_path` = `URL.build(path=value, encoded=True).path` (:1242-1243). No double-decode exists; the router matches on the *raw* path (:616) and decodes only the remainder.
2. **Join + canonicalize**: `filepath = self._directory.joinpath(filename).resolve()` (:643) — join of the tainted component into the operator base, then full resolution (collapses `..`, follows symlinks) BEFORE the containment check.
3. **Allowed root**: `self._directory` is operator configuration (`add_static`/`StaticResource.__init__`, :523/:534), `~`-expanded only for the operator directory (:536 — never for the request filename) and itself resolved at registration (:537), so the `relative_to` comparison (:645) compares canonical against canonical.
4. **Absolute paths**: rejected by the anchor guard (:638-642, HTTPForbidden) — drive and UNC forms.
5. **Symlinks**: default `follow_symlinks=False` (:529) keeps the containment check active; resolved symlink targets outside the base raise at :645. The non-default `follow_symlinks=True` disables the check (operator opt-in, documented in `phase1_review.md` §7).
6. **File-access timing**: guard order is anchor (:638) → join+resolve (:643) → containment (:645) → is_dir/is_file (:657/:667) → FileResponse (:668) → re-stat (web_fileresponse.py:141) → open (:288) → sendfile (:93). A TOCTOU window exists between :645 and the FileResponse re-stat/re-open (symlink swap); this is recorded as a residual risk, not a modeling input.
7. **Multipart channel**: `field.filename` never becomes a path in-tree — content goes to an auto-named `tempfile.TemporaryFile()` (web_request.py:726); no `os.path.join`/`joinpath`/`Path()` consumes it (grep-verified in Step 1).

## 4. Expected query behavior (prediction, not execution — no analysis was run)

The dominant expected path-problem, if executed: source p1-src-091 (`match_info["filename"]`, :635) → local flow → `Path(rel_url)` [summary p1-sink-067] → `joinpath` arg [summary p1-sink-070] → `resolve` [summary p1-sink-069] → `filepath` → sinks p1-sink-072/073 (receivers :657/:667), p1-sink-074/p1-sink-041 (FileResponse arg 0, :668 and any non-test construction site) and p1-sink-077 (`iterdir`, :683, only with `show_index`). This path does **not** route through the `relative_to` barrier node (the guard's protection is control-flow: `ValueError`→404 before the sinks), so the alert is expected to surface and be triaged at Step 6 by the workflow's own Pass-1 FP heuristic ("canonical path checks with base directory containment → FP"), consistent with the Phase 1 conclusion that the default configuration is not traversable. Sources p1-src-087/088 (raw_path, :616) feed the `_unquote_path` summary then dead-end in `match_dict` (framework object boundary, §6); middleware path sources dead-end in `request.clone` (candidate summary not promoted); the request-line source dead-ends in `URL.build` (yarl not in the database); multipart sources have no in-tree path sink.

## 5. Diagnostics paths (not formal Pass 1 alerts)

Internal wrapper debugging (e.g. counting how many nodes each `MySources`/`MySinks` sub-predicate matches, or checking the summary edges fire) should be done with separate `*.ql`/`*.bqrs` count queries under `iris/diagnostics/` (directory already exists) selecting `count(MySources::isSource(...)`-style results. Per the task contract no diagnostics query was generated in this step and none of them counts as a Pass 1 alert.

## 6. CodeQL limitations and known gaps (documented, not silently patched)

1. **Framework object boundary**: `match_dict` (built in `StaticResource.resolve`, :625) → `request.match_info` (read in `_handle`, :635) crosses a framework object; not trackable without a `match_info`-specific model. Mitigated by anchoring a source at the read side (p1-src-091/092) and at the upstream raw_path reads (p1-src-087/088) — recall is preserved at both ends, the middle is intentionally not modeled (no arbitrary propagation).
2. **Interprocedural field flow**: `FileResponse.__init__` `self._path = pathlib.Path(path)` (:54) → `filepath = self._path` in `_get_file_path_stat_and_gzip` (:132) is not a default global-taint step, so the stat sinks (:136/:141) and the open sink (:288) may only fire via the parameter sink (p1-sink-041) rather than the receiver positions. The parameter sink covers the same taint entry.
3. **Executor boundary**: `loop.run_in_executor(None, filepath.open, "rb")` (:288) — taint does not flow into the bound-method argument by default; the sink matcher therefore anchors on the receiver (path text), which is the accurate dangerous position.
4. **Control-flow guards**: `isBarrier` cannot express "flows that survive the relative_to check are certified in-bounds" — the barrier cuts only flows routed through the guard node. Combined with §4 this is the designed Step 6 triage point, not a modeling error.
5. **Dynamic dispatch / name collisions**: `.resolve()`/`.relative_to()`/`.is_file()` matching is line-anchored (not name-global), so the DNS-resolver `resolve` name collisions (connector.py:834/:871, router resolves) cannot fire. The generalized `FileResponse(<arg 0>)` sink matcher is name-based by reviewed-label intent (framework signature) and is restricted to non-test files; keyword-argument construction (`FileResponse(path=x)`) is not matched.
6. **`url_for` flow (application input)**: web_urldispatcher.py:577-588 is excluded (fp labels) — its open/is_file are not sinks and its joinpath/relative_to are not promoted, so the application-input flow cannot produce alerts in this pass.
7. **Yarl / stdlib internals** (`URL.build`, `pathlib` itself) are not part of the database; the summaries in §2.4 are the minimum edges needed at the boundary, all site-anchored.

## 7. Label adequacy check (Step 4 gate)

No reviewed-label omissions were found that would require returning to Step 3: every non-`none` tp label is implemented (38/38: 21 sources, 9 sinks, 3 sanitizers, 5 summaries); every `candidate`/`fp` label is deliberately excluded with the per-entry rationale preserved here and in `labels_raw_pass1.json`. `labels.json` was not modified.

## 8. Experiment independence

No PyVul ground truth (`VULNERABILITY_AUDIT_REPORT.md`, `path_traversal_sinks.csv`), no CVE advisory, no known-vulnerability line numbers, and no fix patches were consulted at any point; all modeling derives from the reviewed Pass 1 labels and direct reading of the `aiohttp_vuln` source. The source tree, the CodeQL database, the Augur installation, and the Phase 1 labels/CSVs were not modified. Only the six contracted artifacts were written. Per the task contract, no compilation or formal analysis was executed in this step (query run is Step 5's execution phase, deferred to the next round).
