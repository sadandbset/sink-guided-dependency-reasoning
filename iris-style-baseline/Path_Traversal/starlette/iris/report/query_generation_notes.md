# Query Generation Notes - Pass 1 Path Traversal (starlette)

Augur Phase 2 Step 4 (CodeQL library generation) + Step 5 (pass query
rendering). Generated 2026-10-23. No CodeQL compilation or analysis was
executed in this step, per the task contract.

- Target: starlette 0.26.1, source tree
  `dataset/codeql_databases/path_traversal_dbs/starlette_vuln`, database
  `starlette-db` (CodeQL CLI 2.25.1, sourceLocationPrefix = the source
  tree root, sha 24c1fac6).
- Label source: `iris/labels/labels.json` v1.0.0 (Pass 1, 189 entries; run
  `starlette-pathtraversal-pass1-step3-20261023`, labeling model glm-5.3),
  together with `iris/labels/phase1_review.md` and
  `iris/labels/label_stats.md`.
- Generated artifacts: `libraries/MySources.qll`, `libraries/MySinks.qll`,
  `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`,
  `queries/Pass1_PathTraversal.ql` (rendered from
  `augur-0.3.0/assets/taint_query.ql.tmpl`). `iris/qlpack.yml` (name
  `iris/starlette-cwe22`, dependency `codeql/python-all: "*"`) already
  exists from Step 0 and is unchanged; all library imports use the
  `libraries.MyXxx` dotted syntax resolved within that pack.
- Pass key: `path_traversal`. Query id: `py/augur/starlette/pass1-path-traversal`,
  `@kind path-problem`, `@problem.severity error`, `@precision medium`,
  tags `security` + CWE-022/023/036/073.

## 0. Review-gate input

`labels/review_decision.json` does not exist (it is an optional audit
artifact per WORKFLOW.md 4.5). The reviewed label set is therefore
`labels/labels.json` as produced by Step 3, whose checkpoint summary is
`labels/phase1_review.md`; per the WORKFLOW automated-mode rule ("log the
summary, self-approve, and continue") this generation proceeds on that
basis. No label was modified during Step 4/5.

## 1. Label ID -> QL predicate mapping

### 1.1 MySources.qll (source predicates)

| QL predicate | Labels rendered (role=source) | External boundary / access conditions |
| --- | --- | --- |
| `scopePathRead` | p1-s-117 (staticfiles.py:111, PRIMARY, 0.97), p1-s-120, p1-s-085/092/097, p1-s-111..114, p1-s-014, p1-s-139 | `scope['path']` / `redirect_scope['path']` subscript reads in staticfiles.py, routing.py, datastructures.py, middleware/wsgi.py. The ASGI server populates the scope with the percent-decoded request path; any network client can set it arbitrarily (GET/HEAD). |
| `scopeKeyRead` | p1-s-005, p1-s-062, p1-s-067, p1-s-088, p1-s-090, p1-s-119, p1-s-121, p1-s-123, p1-s-137, p1-s-140, p1-s-016, p1-s-019 | `scope['method']` / `scope['query_string']` / `scope['headers']` - client-controlled request state; in-tree consumers are method checks, URL construction, query/header parsing (low direct pass-1 relevance, kept for conservative recall). |
| `scopeGetRead` | p1-s-087/094/100/106/063 (path_params), p1-s-015 (query_string), p1-s-013/101/061/138 (root_path/app_root_path - candidate 0.55) | `scope.get('path_params')` etc.: routed path segments from the regex match over `scope['path']`; root_path reads are server/mount-derived and only indirectly request-influenced (labeled candidate - rendered for fidelity, expected to be quiet). |
| `routeVarRead` | p1-s-086, p1-s-093, p1-s-098, p1-s-105 | `match.groupdict()` results (Route/WebSocketRoute/Mount/Host.matches) - the classic route-variable boundary that applications may feed into file APIs. |
| `mountRemainderPop` | p1-s-099 | `matched_params.pop('path')` at Mount.matches (routing.py:394) - the request-path remainder that becomes the child `scope['path']` for mounted apps (e.g. StaticFiles). |
| `headerValueRead` | p1-s-006, p1-s-009, p1-s-017, p1-s-033, p1-s-056, p1-s-064, p1-s-071, p1-s-075, p1-s-104, p1-s-131, p1-s-053 | `headers.get(...)/.getlist(...)` on request headers (`request.headers`, `self.headers`, `request_headers`, multipart `params`) - any client-set header value. |
| `headerSubscriptRead` | p1-s-007, p1-s-008, p1-s-011, p1-s-124, p1-s-125, p1-s-052 | `request_headers['...']` / `self.headers['...']` subscripts (CORS headers, StaticFiles conditional headers - response metadata only, multipart Content-Type). |
| `multipartOptionRead` | p1-s-047, p1-s-049 (filename, 0.90), p1-s-054 | `options[b'name']`, `options[b'filename']`, `params[b'boundary']` from the parsed Content-Disposition/Content-Type - fully attacker-controlled strings (no in-tree path sink; see section 6). |
| `decodeCallResult` | p1-s-040, p1-s-041, p1-s-044, p1-s-046, p1-s-048, p1-s-045, p1-s-051, p1-s-072, p1-s-059 | `unquote_plus` / `_user_safe_decode` / `parse_options_header` / `http_cookies._unquote` call results - percent/charset decode boundaries; the decoded value remains fully attacker-controlled. testclient.py `unquote` labels are none/fp and excluded by the file constraint. |
| `wireRead` | p1-s-068, p1-s-073, p1-s-133, p1-s-134, p1-s-023 | `self._receive()` / `websocket.receive()` call results - raw ASGI message chunks off the socket. |
| `messageGetRead` | p1-s-069, p1-s-070, p1-s-074, p1-s-024, p1-s-026, p1-s-027 | `message.get('body'/'more_body'/'type'/'code'/'text'/'bytes')` on incoming messages. |
| `asgiScopeParameter` | 42 scope-param labels: p1-s-001, 002, 004, 010, 012, 018, 020, 022, 031, 035, 055, 057, 060, 065, 076, 077, 078, 079, 080, 081, 082, 083, 084, 089, 091, 095, 096, 102, 103, 107, 108, 110, 115, 118, 122, 126, 130, 132, 135, 136, 141, 142 | `scope` parameters of externally reachable ASGI entry points, matched by the labeled function-name set (`__call__`, `matches`, `handle`, `not_found`, `app` closures, `build_environ`, `__init__` class-ASGI apps and request wrappers, `get_response`, `file_response`, `simple_response`). The lifespan handler is excluded (p1-s-109 is none/fp). `get_path`'s scope param is NOT here (it is summary p1-s-116). |
| `handlerParameter` | p1-s-021, p1-s-032, p1-s-034, p1-s-036 (request), p1-s-025, p1-s-028, p1-s-029, p1-s-030, p1-s-037 (websocket) | Framework-injected handler parameters (endpoints.py, middleware/errors.py, middleware/exceptions.py) wrapping the attacker-controlled ASGI scope; reachable from route dispatch. |
| `parserParameter` | p1-s-038, p1-s-039, p1-s-042, p1-s-043 (headers/stream), p1-s-066 (receive) | Form/multipart parser inputs: the request's own headers and body async stream. |
| `uploadFileCtor` | p1-s-050 | `UploadFile(...)` construction carrying the attacker-controlled Content-Disposition filename (stored on `UploadFile.filename`, datastructures.py:445). |

**Deliberate source-side deviations (labels NOT rendered as sources):**

- **p1-k-026** (`get_response` `path` param, staticfiles.py:113, label
  source/tp 0.75), **p1-k-032** (`lookup_path` `path` param,
  staticfiles.py:163, source/tp 0.70) and **p1-k-039** (`file_response`
  `full_path` param, staticfiles.py:184, source/candidate 0.60) are
  internal wrapper parameters. Per the Step-4/5 contract ("Source must be
  an actually controllable external input node; an internal
  `file_handler(path)` parameter must not be turned into a Source just to
  get a path"), they are NOT emitted in `MySources::isSource`. The
  propagation they were meant to bridge is realized by the reviewed
  summary edges instead (section 4), so the complete flow runs from the
  true boundary `scope['path']` (p1-s-117) to the sinks. The labels
  themselves are unchanged; this is a rendering decision recorded here.
  If a reviewer prefers them as sources, they can be re-reviewed at the
  Step-5 gate - the labels' own rationale already flags them as
  "secondary source ... flagged for human review".

**Label prose inaccuracies discovered during rendering (recorded, no
re-review requested):** p1-s-060 (requests.py:69), p1-s-122
(staticfiles.py:186) and p1-s-142 (wsgi.py:75) are `scope` parameters of
constructor wrappers but carry the generic "parser input parameter"
rationale template from the Phase-1 batch pass. Their role (source),
classification (tp) and confidence (0.85) are correct and match the other
scope parameters; only the rationale prose is imprecise. Role/classification
are unaffected, so per the escalation rule (only omissions require
returning to Step 5) this is documented rather than escalated;
`labels.json` is untouched.

### 1.2 MySinks.qll (sink predicates)

| QL predicate | Labels | Real file operation | Dangerous path arg | Access type / call relationship |
| --- | --- | --- | --- | --- |
| `anyioOpenFileSink` | p1-k-018 (responses.py:353, tp 0.95) | `anyio.open_file(self.path, mode='rb')` - THE serving file open | arg 0 | read; called from `FileResponse.__call__` (responses.py:352-356), `self.path` set in `FileResponse.__init__` (responses.py:298) from `StaticFiles.file_response` (staticfiles.py:192) |
| `osStatSink` | p1-k-038 (staticfiles.py:177, tp 0.85) | `os.stat(full_path)` in `lookup_path` | arg 0 | stat (metadata); after join+realpath/abspath and the commonprefix check (staticfiles.py:166-175) |
| `runSyncStatSink` | p1-k-017 (responses.py:335, tp 0.80), p1-k-041 (staticfiles.py:209, fp) | `anyio.to_thread.run_sync(os.stat, self.path)` - FileResponse re-stat / check_config stat | arg 1 (arg 0 is the `os.stat` callable) | stat offloaded to a thread; TOCTOU window vs the staticfiles check |
| `fileResponseCtorSink` | p1-k-040 (staticfiles.py:192, tp 0.90), p1-k-031 (staticfiles.py:154, fp - fixed '404.html') | `FileResponse(full_path, ...)` construction; `__call__` then re-stats and opens the file | arg 0 | file response (read); main serving path |
| `fileResponsePathParamSink` | p1-k-016 (responses.py:288, tp 0.85) | `FileResponse.__init__` `path` param -> `self.path` -> stat/open in `__call__` | param pos 1 | definition-side sink; attacker-reachable via `StaticFiles.file_response` |
| `builtinOpenSink` | p1-k-004 (config.py:121, fp) | builtin `open(file_name)` in `Config._read_file` | arg 0 | read; path provenance is the operator-configured `env_file` - no untrusted source in-tree |
| `osPathIsfileSink` | p1-k-002 (config.py:62, fp) | `os.path.isfile(env_file)` | arg 0 | stat; operator config |
| `osPathIsdirSink` | p1-k-020 (staticfiles.py:56, fp), p1-k-023 (staticfiles.py:85, fp) | `os.path.isdir(directory)` | arg 0 | stat; operator bootstrap checks |
| `configEnvFileParamSink` | p1-k-001 (config.py:55, fp) | `Config.__init__` env_file param consumed by isfile/open | param pos 1 | read; operator config |
| `configReadFileParamSink` | p1-k-003 (config.py:119, fp) | `Config._read_file` file_name param consumed by `open()` | param pos 1 | read; operator config |
| `jinja2LoaderSink` | p1-k-043 (templating.py:85, fp) | `jinja2.FileSystemLoader(directory)` - template root; loads happen inside jinja2 (outside DB) | arg 0 | read; operator template root |
| `getTemplateCallSink` | p1-k-045 (templating.py:94, candidate), p1-k-047 (templating.py:112, candidate) | `env.get_template(name)` / `self.get_template(name)` - name joined onto loader dir inside jinja2 | arg 0 | read; in-tree names are app-supplied constants (cross-boundary concern) |
| `templateParamSink` | p1-k-042 (templating.py:67, fp), p1-k-044 (templating.py:93, candidate), p1-k-046 (templating.py:98, candidate) | definition-side template name/directory params | param pos 1 | read; operator root / app-supplied names |

Sink-side distinctions honored: path TEXT operations (`os.path.join`,
`normpath`, `abspath`, `realpath`) are not sinks (they are summary steps);
file-OBJECT operations on already-opened handles (`file.read`,
`UploadFile.file.write/seek/close`, `SpooledTemporaryFile`) are excluded
(the path decision is made at open time and the upload file path is
auto-generated - labels p1-k-005..p1-k-015, p1-k-019, p1-k-021/022 are
role=none and not rendered).

### 1.3 MySanitizers.qll (barrier predicate)

`isBarrier` resolves to `none()` for `path_traversal`. The only
sanitizer-labeled candidate, **p1-k-037** (`os.path.commonprefix`,
staticfiles.py:172, candidate 0.45), is NOT emitted - see section 3.

### 1.4 MySummaries.qll (additional taint steps)

| QL predicate | Labels | Propagation modeled |
| --- | --- | --- |
| `get_pathChainStep` | p1-s-116 (+ p1-k-024/p1-k-025 sites) | `scope['path']` subscript -> `.split('/')` -> starred `os.path.join` -> `os.path.normpath` -> `get_path` return (one statement-local composite edge, staticfiles.py:111) |
| `pathJoinStep` | p1-k-028 (staticfiles.py:136), p1-k-033 (staticfiles.py:166) | `os.path.join(path, 'index.html')` arg0 -> result; `os.path.join(directory, path)` arg1 -> result |
| `canonicalizeStep` | p1-k-034 (staticfiles.py:168 abspath), p1-k-035 (staticfiles.py:170 realpath) | canonicalization arg0 -> result (taint-preserving; the :171 realpath(directory) site shares the shape and is harmless) |
| `threadOffloadArgStep` | p1-k-027 (staticfiles.py:121), p1-k-029 (:137), p1-k-030 (:150, fixed literal) | `anyio.to_thread.run_sync(self.lookup_path, X)` arg1 -> `lookup_path`'s `path` parameter |
| `threadOffloadReturnStep` | (same offload sites) | `lookup_path`'s returned tuple elements -> the `run_sync` call result (and its `await` wrapper) |
| `fileResponseFieldStep` | derived from the p1-k-016 -> p1-k-017/p1-k-018 chain | `FileResponse.__init__` `path` param -> `self.path` attribute reads in `FileResponse.__call__` (field store at responses.py:298) |

## 2. Source boundaries and access conditions (per source family)

- **scope['path'] (primary, p1-s-117)**: set by the ASGI server from the
  request target, percent-decoded ONCE before the scope is built
  (evidence inside the tree: testclient.py:240/258 construct
  `scope['path'] = unquote(path)`); a `%2e%2e`/`%2f` therefore arrives as
  a literal `../`/separator after that single decode, and no second
  decode boundary exists in-tree (no double-decoding). Any unauthenticated
  client controls the full value. Consumption chain (all verified in real
  code): staticfiles.py:102-103 -> 111 -> 121-123 -> 166-177 -> 192 ->
  responses.py:335/353.
- **ASGI entry `scope` params / handler params / parser params**:
  framework-injected carriers of the same client input; externally
  reachable through the ASGI server (Starlette.__call__,
  Router.__call__, middleware stack, Route/Mount dispatch).
- **Route variables (`groupdict`, `pop('path')`, `path_params`)**: the
  matched portion of the client request path; Mount's remainder becomes
  the child scope['path'] (routing.py:394-403), i.e. the same value that
  `StaticFiles.get_path` later reads.
- **Headers / multipart options / wire messages / decode results**:
  client-supplied header values, Content-Disposition filenames, raw body
  chunks and their decoded forms. The multipart filename is fully
  attacker-controlled but has NO in-tree path sink (section 6).
- **root_path reads (candidate labels)**: server/mount-derived, only
  indirectly request-influenced; rendered for label fidelity, expected to
  be quiet (they feed URL/SCRIPT_NAME construction, not file paths).

## 3. Barrier analysis (why `none()`)

The single sanitizer-shaped candidate p1-k-037
(`os.path.commonprefix([full_path, directory]) != directory`,
staticfiles.py:172, guarded by `realpath` on both sides at :170-171) was
tested against the concrete escape mechanisms and CANNOT be proven to
block them in this implementation:

1. **Character-prefix weakness**: `commonprefix` compares raw string
   prefixes, not path components. With base `/static` and a sibling
   directory `/static-evil`, the request path `../static-evil/x` resolves
   to `/static-evil/x`, whose character prefix IS `/static`, so the
   `!= directory` check does not trigger and the sibling file is served
   - escaping the declared root (CWE-22/36).
2. **follow_symlink=True branch**: staticfiles.py:167-168 canonicalizes
   with `os.path.abspath` only; the containment check is never executed,
   so `directory/../../etc/passwd` style requests are not stopped at all.
3. **TOCTOU**: the check (staticfiles.py:170-177) runs in
   `lookup_path`, while the final re-stat and open run later, in a
   thread, inside `FileResponse.__call__` (responses.py:335/353) - a
   symlink swapped in between escapes the root (CWE-59-assisted
   traversal).
4. **Windows separators**: the '/'-split + normpath pipeline lets
   backslash-containing components through as single components, and
   normpath converts separators on Windows; the commonprefix comparison
   then compares Windows-style strings (mixed-separator residual risk,
   recorded in detection.json).

Because a barrier here would also suppress the genuine bypass flow from
`scope['path']` to `anyio.open_file`, and because the label itself is
`candidate`/0.45 with the Phase-1 review recommending against a hard
barrier, `MySanitizers::isBarrier` is `none()`. Likewise `normpath`,
`realpath`, `abspath` (p1-k-024/034/035) are NOT barriers: normpath
collapses `..`/`.` but the collapsed result can remain an upward-relative
path (`a/../..` -> `..`) that escapes when joined onto the base - they
are modeled as taint-preserving summary steps.

## 4. Additional propagation edges (evidence)

Each edge is anchored to concrete statements; no unconditional
node-to-node propagation exists:

- **get_path composite (staticfiles.py:111)**: one statement contains
  `scope["path"]` -> `.split("/")` -> `*`-unpack into `os.path.join` ->
  `os.path.normpath` -> `return`. CodeQL cannot follow the starred
  unpack or unmodeled stdlib calls, so one composite edge
  subscript -> return-value is emitted (justified by label p1-s-116's
  reviewed rationale, which spells out this exact chain).
- **join/canonicalize (staticfiles.py:136/166/168/170)**:
  `os.path.join` / `abspath` / `realpath` argument-to-result taint is not
  modeled by default for these stdlib calls; edges follow the labeled
  argument positions (attacker path at arg 0 at :136, arg 1 at :166,
  arg 0 at :168/:170).
- **Thread offload (staticfiles.py:121/137/150)**:
  `anyio.to_thread.run_sync(self.lookup_path, X)` - argument 1 becomes
  the callback's `path` parameter and the callback's return becomes the
  await result. Both directions are modeled; the first argument is
  constrained to `self.lookup_path` so the `run_sync(os.stat, ...)`
  offloads (staticfiles.py:209, responses.py:335) are not mis-bridged.
- **FileResponse field store (responses.py:298 -> :335/:353)**:
  `self.path = path` bridges the constructor parameter to the
  `self.path` reads in `__call__`. Python data flow does not reliably
  track attribute stores across methods, so this single field-specific
  edge is added (it is the glue the p1-k-016 -> p1-k-017/p1-k-018 sink
  chain requires).

With these edges the complete reviewed flow is representable:
`scope['path']` (source) -> get_path return -> `get_response` path arg
(standard interprocedural step) -> run_sync arg1 -> (edge) `lookup_path`
path param -> join arg1 -> (edge) realpath -> stat sink (p1-k-038) and
return tuple -> (edge) run_sync result -> `file_response(full_path)` ->
`FileResponse` ctor sink (p1-k-040) / `__init__` param sink (p1-k-016) ->
(field edge) `self.path` -> re-stat sink (p1-k-017) -> `anyio.open_file`
sink (p1-k-018). The html-mode branch (`index.html`, :136/:137) rides the
same edges.

## 5. Known gaps, dynamic-dispatch / alias limitations

- **Dict-literal container flow is not modeled**: Mount.matches builds
  the child scope via a dict literal (`{'path': remaining_path, ...}`,
  routing.py:399-405); taint does not flow from `matched_params.pop`
  through the dict literal into the child app's `scope['path']` read.
  This is acceptable because the consumer side is already a direct
  source (`scope['path']` at staticfiles.py:111 and the other http_path
  labels) - the same value is captured where it is used. No edge was
  added to avoid unconditional cross-function pollution.
- **Attribute-call receivers are matched syntactically** (name +
  file constraints) rather than by resolved types: `self.lookup_path`,
  `self.get_template`, `anyio.to_thread.run_sync`, `os.path.*`,
  `anyio.open_file`, `jinja2.FileSystemLoader`. Aliased imports
  (`import anyio as x`) would be missed - none exist in this snapshot
  (all plain imports; verified in Phase 1).
- **`Headers(scope=...)`, `Request(scope, ...)` wrapper constructions**
  are not bridged as taint steps; the scope-parameter sources at those
  constructors (p1-s-060/065, p1-s-012/018) cover the same values at
  entry, and the downstream consumers of `.headers`/`.path_params` are
  separately sourced at the accessor level.
- **jinja2 / anyio internals are outside the database**: the actual
  template file join and the async file open happen in dependencies; the
  starlette-side call sites are the sinks (p1-k-043..047, p1-k-018),
  which is the best in-tree approximation and matches the labels.
- **CodeQL limitations**: starred-argument unpacking, thread-offload
  callbacks, await wrappers and cross-method attribute stores are not
  default flow steps - all four are explicitly bridged in MySummaries
  (section 4). If the local pack already models `os.path.join`
  argument-to-result taint, the join edges are redundant but harmless.
- **Store-target subscripts excluded**: all subscript source families
  (`scopePathRead`, `scopeKeyRead`, `headerSubscriptRead`,
  `multipartOptionRead`) are guarded with `getCtx() instanceof Load`,
  mirroring the extraction queries' write-target exclusion
  (`Assign.getATarget()`); e.g. the `redirect_scope['path'] = ...`
  rewrite at routing.py:733-737 and the `base_url_scope['path'] = '/'`
  write at requests.py:102 are not sources, only the value-side reads are.
- **Not modeled (deliberately)**: multipart filename ->
  `UploadFile.filename` -> (application persistence) is outside this
  codebase; WSGI `PATH_INFO` passthrough (middleware/wsgi.py:25) is a
  source-only boundary whose file use belongs to the wrapped WSGI app.

## 6. Diagnostics-only paths (not counted as formal Pass 1 alerts)

- Flows originating from the secondary bridge parameters
  (p1-k-026/p1-k-032/p1-k-039) do not exist by construction, since those
  nodes are not sources; the formal alerts are expected to start at
  `scope['path']` / scope parameters only.
- The fp sinks (Config env_file chain, StaticFiles bootstrap isdir/
  check_config stat, Jinja2Templates directory, '404.html' fixed-name
  FileResponse) have no untrusted source reaching them in this codebase;
  any alert through them (only possible via future external modeling)
  must be treated as FP at Step 6.
- The candidate template-name sinks (p1-k-044..047) can only fire if an
  application passes request-derived template names - outside this tree;
  in-tree they are expected to stay silent.
- A separate diagnostics query (e.g. counting `MySources` /
  `MySummaries` edge hits standalone, without sink reachability) can be
  written later for wrapper debugging if the pass query under-reports;
  per the six-file contract of this step it was not created.

## 7. API verification basis (local toolchain)

All QL APIs used were verified against the locally cached packs
(`~/.codeql/packages/codeql/python-all/7.1.2`,
`codeql/dataflow/2.1.7`, `codeql/util`):

- `AstNode.getLocation().getFile(): File` (+ `File.getBaseName()`,
  `getRelativePath()`, `getAbsolutePath()` from semmle/python/Files.qll);
  `AstNode.getScope(): Scope`, `Scope.getEnclosingScope()`
  (semmle/python/Scope.qll). `AstNode.getFile()` is NOT used (it does not
  exist).
- `Subscript.getObject()/getIndex()`, `Attribute.getName()/getObject()`,
  `Call.getFunc()/getPositionalArg()/getAPositionalArg()`,
  `StringLiteral.getText()`, `Name.getId()`, `Return.getValue()`,
  `Tuple.getAnElt()`, `Await.getValue()`, `Parameter.getName()`,
  `Function.getAnArg()/getArg(int)/getName()/getEnclosingScope()`
  (AstGenerated.qll / Exprs.qll / Function.qll).
- `DataFlow::parameterNode(Parameter)` and `DataFlow::Node.asExpr()`
  (semmle/python/dataflow/new, used the same way as
  frameworks/Websockets.qll:69).
- `DataFlow::ConfigSig` with `isSource/isSink/isBarrier/isAdditionalFlowStep(Node, Node)`
  and `TaintTracking::Global<Config>` with `flowPath` + nested
  `PathGraph` (codeql/dataflow 2.1.7 DataFlow.qll/TaintTracking.qll,
  re-exported by python-all 7.1.2 `semmle.python.dataflow.new.*`).
- No `module` variable name, no deprecated `StrConst`/`Decorator`
  classes, no mixing of `API::Node` with `DataFlow::Node` (pure
  AST-shape + dataflow-node matching, consistent with the extraction
  queries' `ast` match-kind contract).

## 8. Experimental independence

- No PyVul ground truth, CVE descriptions, patch diffs,
  `VULNERABILITY_AUDIT_REPORT.md` or `path_traversal_sinks.csv` were
  consulted; everything is derived from the reviewed Pass-1 labels and
  direct reading of the starlette_vuln source tree.
- The source tree, the CodeQL database, the Augur installation and all
  Phase-1 artifacts (`extraction/*.csv`, `labels/*`) were read-only
  throughout; only the six Phase-2 files listed above were written.
- No CodeQL compilation or analysis was run (`codeql query compile` /
  `query run` / `database analyze` deferred per the task contract);
  compile-time API mismatches, if any, are to be resolved in the
  execution round (WORKFLOW.md 3.1 compatibility policy: patch template
  imports/config signatures first, then re-render).
