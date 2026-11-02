# Query Generation Notes — Augur Phase 2, Step 4–5 (Pass 1: Path Traversal)

Project: xmpp-http-upload 0.3.0 (`xmpp-http-upload_vuln` source tree, database creation sha `f0fc7443c06a0e8aecb5696fc2bd513a2cc8b611`)
Pass: 1 (CWE-022 / CWE-023 / CWE-036 / CWE-073) — pass key `path_traversal`
Generated: 2026-10-24
Inputs: `labels/labels.json` (reviewed Pass 1 labels, schema-valid, 32 entries), `labels/labels_raw_pass1.json`, `labels/label_stats.md`, `labels/phase1_review.md`, `exploration/detection.json`, `assets/taint_query.ql.tmpl`, `references/python.md`, `references/patterns.md`, `references/flask.md`, WORKFLOW.md Phase 2, and the real source (`xhu.py`, `setup.py`, `config.example.py`) re-read at every cited line.

Note on `labels/review_decision.json`: this optional audit artifact was not written in Step 3 (that round's contract produced `phase1_review.md` as the review payload and stopped at the gate). The reviewed input for this step is therefore `labels.json` + the review queue in `phase1_review.md` §6, and the decision to proceed to Phase 2 is the operator instruction initiating Step 4–5. Entries with `classification=tp` are treated as the approved set; no `candidate`-class entries exist to promote; **no label was modified and no `review_decision.json` was fabricated**.

## 1. Generated artifacts

| File | Content |
| --- | --- |
| `libraries/MySources.qll` | `module MySources { predicate isSource(DataFlow::Node, string passKey) }` — 4 tp source label rows (4 rules) + the route-parameter source directed by the reviewed checkpoint (1 rule, see §2.1) |
| `libraries/MySinks.qll` | `module MySinks { predicate isSink(DataFlow::Node, string passKey) }` — 7 tp sink label rows (7 rules, all receiver-position except `flask.send_file` argument 0) |
| `libraries/MySanitizers.qll` | `module MySanitizers { predicate isBarrier(DataFlow::Node, string passKey) }` — 0 tp sanitizer labels; empty `none()` body with the full no-barrier justification (§5) |
| `libraries/MySummaries.qll` | `module MySummaries { predicate isAdditionalTaintStep(DataFlow::Node, DataFlow::Node, string passKey) }` — 8 tp summary label rows (5 label-backed rules) + 2 documented evidence-based interpolation edges |
| `queries/Pass1_PathTraversal.ql` | `Pass1Config implements DataFlow::ConfigSig` + `TaintTracking::Global<Pass1Config>` + `import Pass1Flow::PathGraph` + `flowPath(PathNode, PathNode)` path-problem, id `py/augur/xmpp-http-upload/pass1-path-traversal`, `@problem.severity error`, `@precision medium` (medium, not high, because the source-to-sink chains rely on site-anchored modeling edges for stdlib boundaries — see §6 — and the read-side traversal scope is constrained by the `.data`/`.meta` suffixes; consistent with the py7zr/aiohttp rounds of this series) |

Pack layout: `iris/qlpack.yml` (pack `iris/xmpp-http-upload-cwe22`, dependency `codeql/python-all: "*"`, unchanged since Step 0). Libraries are imported with dotted syntax (`import libraries.MySources`) and referenced by module name (`MySources::isSource(source, "path_traversal")`) — the file-name/module-name convention proven on this pack family in the py7zr/aiohttp rounds (same CodeQL CLI 2.25.1 + python-all 7.1.x). Every rule is anchored by file base name + line + node shape, so no rule can double-match and the label→rule mapping is one-to-one traceable.

API surface used (existence verified against the locally installed `codeql/python-all 7.1.2` pack sources; the node-binding idioms additionally verified empirically by the read-only `diagnostics/diag_model_bindings.ql` sanity check, see §6.4): `DataFlow::Node.asExpr()`, `DataFlow::ParameterNode` + `getParameter()`, `DataFlow::ConfigSig` with 2-arg `isAdditionalFlowStep`, `TaintTracking::Global<Config>`, `module X::PathGraph` + `flowPath`, `Call.getFunc()`, `Call.getArg(int)`, `Attribute.getName()`, `Attribute.getObject()`, `Name.getId()`, `BinaryExpr.getOp()/getRight()` (AstGenerated.qll:115-123 via Operations.qll:46), `StringLiteral.getText()` (Exprs.qll:557), `Function.getADecorator()/getAnArg()`, `Parameter.getName()`, `AstNode.getLocation()`, `Location.getStartLine()`, `File.getBaseName()`. No deprecated or non-existent AST API is used; no variable is named `module`; `API::Node` is not used at all (pure AST matching, so no API::Node/DataFlow::Node mixing); no `@kind problem`/multi-column shapes; the mandatory `isBarrier` hook exists even though it resolves to `none()` (WORKFLOW.md §5.2.3).

Per the task contract, the formal query was NOT compiled and NOT executed in this step; CodeQL was used only for the read-only binding diagnostics in §6.4.

## 2. Label ID → QLL rule mapping

### 2.1 Sources (`MySources::isSource`, pass key `path_traversal`)

All modeled sources are HTTP request inputs — the only untrusted boundary of this service. No internal wrapper parameter was promoted to a source: the `path` parameters of `sanitized_join`/`get_info` (labels sink-005/sink-014) are realized as summary edges (§2.4), not sources, exactly as reviewed.

| Label ID (conf) | Location | QL rule | Node shape | External input boundary / access conditions |
| --- | --- | --- | --- | --- |
| — (reviewed checkpoint directive, phase1_review.md §6.1/§7; **not a labels.json row**) | xhu.py:105 / :190 / :215 | `routePathParameterSource` | `DataFlow::ParameterNode` of `put_file`/`head_file`/`get_file` param `path` | The Werkzeug `path` converter of `@app.route("/<path:path>", ...)` (:104/:189/:214) captures the URL-decoded remainder of the request URL (slashes included; regex `[^/].*?` so always a *relative* string) and binds it to the same-named handler parameter. Fully attacker-controlled, including `../` segments. GET/HEAD routes are unauthenticated (any HTTP client); the PUT route additionally requires a valid HMAC over `"{path} {length}"` with the operator `SECRET_KEY` (xhu.py:118-130). See §2.5 for why this is not a labels.json omission requiring re-review. |
| src-001 (0.90) | xhu.py:118 | `requestArgsGetSource` | `Call` `flask.request.args.get("v", "")` (result node) | Query-string verification key (PUT). Fully attacker-controlled; per the reviewed rationale it flows only into `hmac.compare_digest` (:125) — never a path, no alert expected. |
| src-002 (0.90) | xhu.py:119 | `requestHeadersGetSource` | `Call` `flask.request.headers.get("Content-Length", 0)` (result node) | Request header, int()-coerced; feeds the HMAC input (:120) and the stream-copy length (:142). Never a path. |
| src-003 (0.85) | xhu.py:132 | `requestHeadersGetSource` | `Call` `flask.request.headers.get("Content-Type", ...)` (result node) | Request header; persisted to the `.meta` JSON (:147) and replayed as a response header (pass-10 adjacent). Never a path. |
| src-004 (0.75) | xhu.py:142 | `requestStreamSource` | `Attribute` `flask.request.stream` (read) | Raw request body — attacker-controlled *content*, consumed by `stream_file` (:92-101) as file content. Never a path. |

The four `flask.request` sources are modeled for label fidelity; per their reviewed rationales none can reach a filesystem path in this codebase, so the expected Pass 1 alerts all originate from `routePathParameterSource`.

### 2.2 Sinks (`MySinks::isSink`, pass key `path_traversal`)

Path text vs. file object: every modeled position carries **path text** (the `pathlib.Path` receiver / the `str(data_file)` argument). The file handles returned by `.open` (`f` at :57/:144, the yielded `fout` at :76) are NOT sinks; `flask.make_response` (:228) is a response wrapper, not a file access.

| Label ID (conf) | Location | QL rule | Real file operation | Dangerous position (arg index / access type) and call relationship |
| --- | --- | --- | --- | --- |
| sink-028 (0.90) | xhu.py:228 | `sendFileSink` | framework file-read-into-HTTP-response (`flask.send_file(str(data_file))`) | **argument 0** (path text via the `str()` coercion — a default taint step). `get_file` GET route — **unauthenticated**, via `get_info` (:217-220). Highest-value sink: reads `<route-path>.data` (suffix-constrained). |
| sink-019 (0.85) | xhu.py:76 | `dataOpenWriteSink` | file open for exclusive-create write (`at.open("xb")`) + body streamed into it (:141-142) | receiver `at` (path text, `<route-path>.data`). `write_file` (:74-81, `@contextlib.contextmanager`) ← `put_file` (:141), after the HMAC gate and the mkdir. EEXIST → 409 (:157-163). |
| sink-013 (0.80) | xhu.py:57 | `metadataOpenReadSink` | file open for reading (metadata JSON, `json.load` at :58) | receiver `metadata_file` (path text, `<route-path>.meta`). `load_metadata` ← `get_info` (:71) ← `head_file`/`get_file` — **unauthenticated**. |
| sink-024 (0.80) | xhu.py:144 | `metadataOpenCreateSink` | file open for exclusive-create write (`metadata_file.open("x")`, JSON dumped :145-150) | receiver `metadata_file` (path text, `<route-path>.meta`). `put_file`, HMAC-gated. |
| sink-023 (0.80) | xhu.py:137 | `parentMkdirSink` | recursive directory creation (`dest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o770)`) | receiver `dest_path.parent` (path-text derivation, realized by `parentAttributeStep`). `put_file`, HMAC-gated; runs BEFORE the writes; **not suffix-constrained** — `../` chains create directories outside DATA_ROOT directly. |
| sink-026 (0.65) | xhu.py:197 | `dataStatSink` | stat probe (existence/size oracle; `st_size` → Content-Length at :206) | receiver `data_file` (path text, `<route-path>.data`). `head_file` HEAD route — **unauthenticated**. No content read. |
| sink-020 (0.65) | xhu.py:80 | `unlinkRollbackSink` | file deletion (`at.unlink()`) | receiver `at` (path text, `<route-path>.data`). `write_file` error path only (exception during body streaming, e.g. the `EOFError` from `stream_file` :100-101, after a successful exclusive create); PUT/HMAC-gated. |

Rejected sink candidates (NOT modeled, per the reviewed `role=none` labels): the 4 `setup.py` packaging literals (sink-001..004 — install-time script, literal `README.rst` path, no untrusted input); the 6 `DATA_ROOT` base-operand rows (sink-006/015/017/022/025/027 — operator config, never attacker-controlled); `Path.absolute()` (sink-007 — not a file access; realized as a pass-through taint step instead, §2.4); the `load_metadata`/`write_file` parameter definition rows (sink-012/018 — their real accesses are the sinks above).

### 2.3 Barriers (`MySanitizers::isBarrier`, pass key `path_traversal`)

**Empty — 0 sanitizer labels survived review.** `isBarrier` resolves to `none()` (mandatory empty hook). Full mechanism-by-mechanism justification in §5; summary: the only containment logic, `sanitized_join`'s `startswith` guard (xhu.py:44), is a lexical check on an **un-normalized** path (see §5.2) and does not block the CWE-22 mechanism, so modeling it as a barrier would sever the genuine flow — which is exactly why the reviewed labels classify it `role=summary` (sink-005), not sanitizer.

### 2.4 Additional taint steps (`MySummaries::isAdditionalTaintStep`, pass key `path_traversal`)

Label-backed rules (site-anchored argument → result edges; no unconditional cross-function propagation):

| Label ID (conf) | Location | QL rule | Edge | Why necessary / why safe |
| --- | --- | --- | --- | --- |
| sink-008 (0.70) | xhu.py:43 | `truedivJoinStep` | right operand `path` → the `root / path` Div result | **Necessary**: pathlib `/` is not a default taint step (the stock `PathlibPathTaintStep` lives in `semmle.python.frameworks.Stdlib`, deliberately not imported — §6.2). Conditional on the exact site, so ordinary divisions elsewhere are untouched. |
| sink-009 / sink-010 (0.75) | xhu.py:50 / :51 | `pathConstructorStep` | `pathlib.Path(...)` argument 0 → constructor result | **Necessary**: same stdlib-boundary reason. Only the two `get_paths` sites are matched; the four `DATA_ROOT` constructions (:66/:109/:194/:219, labels role=none) are not — an edge there would be vacuous. |
| sink-005 / sink-016 / sink-021 (0.70–0.80) | xhu.py:64 / :107 | `sanitizedJoinStep` | call argument 0 (`path`) → call result | Redundant-but-explicit: the in-tree definition (:42-46) is also covered by standard interprocedural flow; the call-site edges realize the reviewed wrapper label (param 0 → return) in the py7zr-series style. NOT a barrier (§5.2). |
| sink-011 (0.70) | xhu.py:69 / :138 | `getPathsStep` | call argument 0 (`dest_path`) → call result | Same style; the `.data`/`.meta` suffixing inside (:49-53) is name-mangling, not a guard — it constrains which files are reachable, never whether the path escapes. |
| sink-014 (0.70) | xhu.py:192 / :217 | `getInfoStep` | call argument 0 (`path`) → call result | Same style; carries the unauthenticated read-side flow. |

Interpolation edges (not label rows; below Phase 1 extraction granularity — pure stdlib path derivations with no candidate rows — added with real-code evidence in the same site-anchored style, exactly as the py7zr round did for `.parent`/`.decode`):

| Location | QL rule | Edge | Evidence |
| --- | --- | --- | --- |
| xhu.py:43 | `absoluteCallStep` | receiver (`root / path`) → `.absolute()` result | `Path.absolute()` prepends the CWD for relative inputs only; it preserves path content verbatim (no `..` collapse, no symlink resolution). Without this edge the flow dies inside `sanitized_join` (label sink-007 is role=none — "neither a file access nor a normalizer" — and is realized here as a pass-through, not a barrier). |
| xhu.py:137 | `parentAttributeStep` | `dest_path` → the `dest_path.parent` attribute read | Realizes the receiver position of sink-023; `.parent` is a pure path-text derivation of the attacker-influenced joined path (with `../` segments it walks the escaped chain). |

Deliberately NOT emitted (verified default taint steps in `semmle.python.dataflow.new.internal.TaintTrackingPrivate.qll`, always active without extra imports): `str()` coercions (:50/:51/:229, `stringManipulation`), the `+` concatenations `<base> + ".data"/".meta"` (:50/:51, `concatStep`). Deliberately NOT emitted (native interprocedural machinery, always active): argument→parameter flow into `sanitized_join`/`get_paths`/`get_info`/`write_file` (all bodies in the database; the `@contextlib.contextmanager` generator is dispatched natively — `DataFlowDispatch.qll:294-304` `hasContextmanagerDecorator` + `YieldNodeInContextManagerFunction`), and the tuple returns of `get_paths`/`get_info` unpacked at :138/:192/:217 (native tuple-content flow through `IterableUnpacking`).

### 2.5 The supplemental route-parameter source (review provenance)

`labels.json` contains no route-param source row because Step 2's extraction emitted none: sources.csv has only the 4 `flask.request.*` rows. The root cause was **verified** in Step 3 (read-only diagnostics, `iris/diagnostics/diag_route_param.ql`/`diag_decorator.ql`/`diag_parent_chain.ql`): `flaskRouteHandler` in `extraction/sources.ql` casts `Function.getADecorator()` to `Attribute`, but for the parameterized decorators `@app.route("/<path:path>", methods=[...])` the API returns the decorator **Call** node — the `.(Attribute)` cast fails and family 1 (route_param) emitted zero rows.

This is therefore **not a newly discovered omission in the reviewed labels** (which would require returning to the review gate): the gap, its verified root cause, and the fix were already reviewed and dispositioned in `phase1_review.md` §6.1, whose directed action is precisely "Phase 2 must add the three route handler parameters to MySources.qll or Pass1_PathTraversal.ql will produce zero alerts". `routePathParameterSource` implements that reviewed directive; `labels.json` was not modified; the alternative (re-running extraction with the fixed predicate `dec.(Call).getFunc().(Attribute).getName() = "route"` — verified to match all four handlers — and re-labeling) remains available to the operator if they prefer the strict CSV-only source set.

## 3. Source external input boundaries and access conditions (consolidated)

The service's untrusted boundary is HTTP (Flask behind the nginx reverse proxy per `contrib/nginx-example.conf`):

1. **Route path** (modeled): the URL itself. Werkzeug percent-decodes the request URL and the `path` converter captures the whole remainder — attacker-controlled path text with `../`, `%2e%2e`-decoded dots, and arbitrary nested segments. `get_file` (GET) and `head_file` (HEAD) apply **no authentication**; `put_file` (PUT) requires the `v` query parameter to equal `HMAC-SHA256(SECRET_KEY, "{path} {length}")` — an authorization gate over the *exact* path (the XMPP slot server signs it), not a containment mechanism.
2. **Query string** (`v`, :118 — modeled, no path reachability), **headers** (Content-Length/Content-Type, :119/:132 — modeled, no path reachability), **raw body** (`flask.request.stream`, :142 — modeled, content-only).
3. **NOT sources** (operator trust): `app.config` reads — `DATA_ROOT` (:66/:109/:194/:219), `SECRET_KEY` (:121), `ENABLE_CORS` (:37), `NON_ATTACHMENT_MIME_TYPES` (:178), `from_envvar("XMPP_HTTP_UPLOAD_CONFIG")` (:34) — per `detection.json` inputBoundaryInventory and the reviewed `none` labels.

## 4. Sink dangerous positions (consolidated)

See §2.2 table. Every sink sits on the same derived chain: route param → `sanitized_join` → `(root/path).absolute()` → `get_paths` → `<base>.data`/`<base>.meta` → file API. Dangerous path positions: `flask.send_file` **argument 0** (the only argument-position sink); `.open` (×3), `.stat`, `.unlink`, `.mkdir` **receivers** (the Path-object path text, never the returned file handles). Read-side sinks (:57/:197/:228) are unauthenticated; write-side sinks (:76/:80/:137/:144) are HMAC-gated. Access timing: `sanitized_join` runs first in every handler (check-then-use, see §5.6), `mkdir` (:137) precedes the writes (:76/:144), `unlink` (:80) is error-path only, `stat` (:197) is a metadata probe without content read.

## 5. Path-construction, containment and symlink evidence (why no barrier)

### 5.1 Allowed root directory
`DATA_ROOT` is operator configuration (`app.config["DATA_ROOT"]`; `config.example.py:2` — an absolute path, `/var/lib/xmpp-http-upload`, no trailing slash). It is the declared containment base; every joined path is `(root / path).absolute()`.

### 5.2 Normalization order — the decisive defect
The guard compares `str((root / path).absolute())` against `str(root) + "/"` **lexically, with no normalization at any point**:

- `pathlib.Path.absolute()` "makes the path absolute, without normalization or resolving symlinks" (CPython docs; `resolve()` is the normalizing API and is never called in `xhu.py`).
- The `path` converter yields a *relative* string, so `(root / path)` is a purely textual join: `str(result)` begins with `str(root) + "/"` for **every** converter-supplied request path.
- Therefore the guard is textually satisfied even when the path contains `../` segments; the OS resolves those segments **at file-access time** (:76/:137/:144/:197/:228), outside `DATA_ROOT`. The check runs *before* every access (check-then-use) but blocks nothing on this input class — hence no barrier, and Step 6 must not apply its generic "explicit startswith guard → FP" heuristic here.

### 5.3 Absolute paths
The converter regex `[^/].*?` cannot yield a leading `/` (and `//x` does not match the `/<path:path>` rule), so absolute-path *replacement* of the base is not reachable from the route; the exploitable mechanism is `..` traversal (5.2), not absolutization. (If it were reachable, the guard *would* catch it — the only case the guard actually protects.)

### 5.4 Path separators and decoding
No backslash handling exists anywhere in `xhu.py`; on the POSIX deployment a backslash is an ordinary filename character (no separator confusion, no escape via `\`). Decoding happens exactly once, in the framework (Werkzeug/WSGI percent-decode before the handler), so `%2e%2e%2f` arrives as `../`; the app itself performs no encode/decode on the path.

### 5.5 Symlinks (CWE-36)
No symlink is ever created by the app (uploads create regular files with `"xb"`/`"x"` and directories with `mkdir`); no `resolve()`/`is_symlink()`/`realpath()` exists. The guard is lexical, so a symlink planted *inside* `DATA_ROOT` pointing outside would be followed — but planting one requires independent filesystem write access, which the app does not grant. The check-then-use window (guard at :44, use at :76/:137/:144/:197/:228) is a real TOCTOU surface, recorded as defense-in-depth; the exclusive-create modes and the `at.unlink()` rollback limit overwrite semantics, not redirection. **Recorded as not exploitable via the app alone** — consistent with the reviewed labels (no CWE-36 barrier, no symlink-specific sanitizer).

### 5.6 File-access timing
Per handler: `sanitized_join` (guard) runs before any file access; `put_file` order is guard → HMAC → `mkdir` (:137) → `at.open("xb")` (:76) → body stream → `metadata_file.open("x")` (:144), with `unlink` (:80) only on error; `head_file`/`get_file`: guard → metadata read (:57) → `stat` (:197) / `send_file` (:228). All accesses are after the (ineffective) guard — the ordering cannot rescue containment given 5.2.

### 5.7 What *would* block (not present)
A `resolve()`/`realpath()` before the prefix comparison, a `relative_to()` on a resolved path, `..`-segment rejection, or a fixed-name mapping. None exists — mechanically treating the present `startswith` (or the "sanitized_" name) as a filter is exactly what the reviewed labels reject.

## 6. Additional propagation edges, dispatch/aliasing gaps, CodeQL limitations, diagnostics

### 6.1 Edges that carry the flow (recap)
The source→sink chains cross three non-default boundaries, each covered by a site-anchored edge: the `/` join and `.absolute()` inside `sanitized_join` (:43), the `str() + ".data"/".meta"` + `pathlib.Path(...)` construction in `get_paths` (:50/:51 — `str()`/`+` are default steps, the ctor is my edge), and the `.parent` derivation at :137. Everything else (wrapper calls, tuple returns/unpacking, the `contextmanager` generator dispatch) is native global taint machinery.

### 6.2 Why `semmle.python.frameworks.Stdlib` is not imported
Importing it would automatically register the stock `PathlibPathTaintStep` (pathlib `/`, ctor, `.absolute`, `.parent`, `.joinpath`) and `PathlibFileAccess` sinks for every configuration. The Augur contract keeps the pass libraries self-contained and strictly label-driven, so the labeled edges are re-implemented locally (equivalently to the stock steps but site-anchored) instead of activating the framework model wholesale. Side effect: no stock pathlib sink concepts are active — the sink set is exactly the 7 reviewed labels, nothing broader.

### 6.3 Residual risks / known limitations (to watch at Step 5 execution)
1. **Tuple unpacking**: `data_file, metadata_file = get_paths(dest_path)` (:138) and `data_file, metadata = get_info(...)` (:192/:217) rely on native tuple-content flow through the visible-function returns. If Step 5 shows the :76/:144/:197/:228 sinks unreachable, add explicit call-node → unpacked-target edges then (a diagnostic follow-up, not part of the formal model now).
2. **`BinaryExpr` node binding**: the `truedivJoinStep` target uses `asExpr()` on the Div expression — verified to bind on this database (`diagnostics/diag_model_bindings.ql` check 1).
3. **Anchored sites**: every rule is anchored to exact lines, so refactors that move lines would silently drop rules — the traceability-over-generality tradeoff of this series, acceptable because the query targets this frozen database (sha `f0fc744`).
4. **Dynamic dispatch / aliasing**: none relevant — the module has no dynamic calls on the flow path (all calls are static, receivers are local SSA variables; the `self`-attribute `dest_path` flow is purely local). `flask`/`pathlib` bodies are outside the database — handled by the site-anchored edges above rather than by aliasing assumptions.
5. **`routePattern.getText().matches("%<path:" + p.getName() + ">%")`**: binds the converter variable to the handler parameter by name — exactly Flask's binding semantics; the `index` handler (route `"/"`, no converter) cannot match.

### 6.4 Diagnostics (not counted as formal Pass 1 alerts)
- `diagnostics/diag_model_bindings.ql` (this step): read-only binding sanity check for the six node idioms used by the libraries (`asExpr()` on the :43 Div BinaryExpr, the :57 receiver Name, the :105 ParameterNode, the :137 `.parent` Attribute, the :43 right-operand Name, the :107 wrapper Call). All six bind. This is *not* the formal analysis — no sources, no sinks, no `TaintTracking`, no `flowPath`.
- Step 3 diagnostics (route-param root cause): `diag_route_param.ql`, `diag_decorator.ql`, `diag_parent_chain.ql`.
- Per the task contract, `queries/Pass1_PathTraversal.ql` was neither compiled nor executed in this step; no SARIF/results were produced and no alert of any kind is claimed.

### 6.5 Expected Step 5 alert surface (prediction, not a result)
If the model behaves as designed: up to 7 sink sites reached from the route-param source — :228 (GET, unauthenticated), :57 and :197 (HEAD/GET, unauthenticated), :76/:137/:144 (PUT, HMAC-gated), :80 (PUT error path). The four `flask.request` label sources are expected to contribute nothing (no path reachability). This is a modeling expectation for the execution round, not an experimental result.

## 7. Experiment independence

No PyVul ground truth, known CVE locations or fix patches were consulted. The pre-existing audit artifacts in the source-tree root (`VULNERABILITY_AUDIT_REPORT.md`, `path_traversal_sinks.csv`, `漏洞审查报告.md`, `第一步筛选报告.md`) were not opened. All modeling decisions derive from: the reviewed Phase 1 labels (`labels/labels.json` + `phase1_review.md`), `exploration/detection.json`, the real source files re-read at every cited line, the Augur references, and read-only inspection/diagnostics of the local `codeql/python-all 7.1.2` pack and the `xmpp-http-upload-db` database. The source tree, the database, the Augur installation, and the Phase 1 labels/CSVs were not modified; the only files written are the six artifacts listed in §1 (plus the `diagnostics/` sanity-check query and its bqrs output, which are diagnostics, not formal results). Consistent with the earlier rounds of this series, the formal query is delivered uncompiled and unexecuted, per this step's contract.
