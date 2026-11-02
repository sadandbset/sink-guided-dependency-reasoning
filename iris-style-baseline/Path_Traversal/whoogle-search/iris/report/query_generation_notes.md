# Query Generation Notes — Pass 1 Path Traversal — whoogle-search

**Augur Phase 2, Step 4–5** (library + query generation only; no compilation, no query execution — per task contract)
**Generated**: 2026-10-24 · **Run ID**: `iris-whoogle-search-pass1-20261023`
**Inputs**: `iris/labels/labels.json` (249 reviewed entries, pass 1), the audited source tree, WORKFLOW.md §5, references/python.md, references/patterns.md, references/flask.md, assets/taint_query.ql.tmpl
**Outputs**: `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass1_PathTraversal.ql`

**Review-gate status**: `labels/review_decision.json` does not exist — the Phase-1 checkpoint was advisory (WORKFLOW.md §4.5) and the reviewed labels plus `labels/phase1_review.md` are the approval record; the operator instruction to proceed to Phase 2 is taken as the gate decision. No `review_decision.json` was fabricated.

---

## 1. Label ID → QLL predicate correspondence

### 1.1 MySources.qll (`isSource(n, "path_traversal")`)

| QLL predicate | Label entries (id → location) | Source evidence (real code) |
| --- | --- | --- |
| `flaskRequestLayerAttr` + `requestLayerAttribute` | 33 field-read tp entries, e.g. src-061 (routes.py:54 `request.args`), src-063 (:59 `request.authorization`), src-067/068/069 (:141 method/args/form), src-077/080/129 (`request.url_root`), src-096–100 (`request.data`), src-109/111 (:426/:429 `request.args`), src-119 (:447), src-130/131, src-160–163/165/171 (search.py `request.*` / `self.request.*`) | `from flask import … request …` (routes.py:28-29); every matched attribute is read on the flask request name or on `self.request` (Search). Genuine untrusted HTTP boundary: query string, form body, raw data, headers, method, basic-auth, Host-derived URL root. |
| `requestLayerCallResult` | 15 call-result tp entries: src-078/087 (:164/:246 `request.headers.get`), src-089/091 (:253/:254 `request.args.get('tbm')`), src-110 (:429 `request.args.get('name')`, conf 0.97), src-115 (:437 `request.form.to_dict()`), src-118 (:447 `request.args.get('name')`, conf 0.97), src-121/123/125/127 (:459/:466/:476/:497), src-164 (search.py:62) | The `.get()`/`.to_dict()` RESULT is the tainted value, not the mapping — hence a separate source shape. routes.py:426-429 / :442-447 show the results flowing into `os.path.join(CONFIG_PATH, name)` → `open()`. |
| `requestParamsAlias` + `requestParamsAliasCallResult` | src-070/076/094/095 (routes.py:140/158/271 `g.request_params`/`.get('q')`), src-163/166/167/168/169/170/172/173 (search.py:61/69/70/94/138/172 `self.request_params`/`.get()`) — tp 0.75 | `g.request_params = request.args if request.method == 'GET' else request.form` (routes.py:140-142); `self.request_params = request.args if method == 'GET' else request.form` (search.py:61). Modeled as sources because the reviewed labels assign these reads role `source`; no store→load edge was invented (see §5). |
| `sessionSubscript` | 16 candidate entries: src-062/066/071–075/083–085/101/102/112/113/114/120 (routes.py:55/68/149–155/210–212/316/318/430/432/433/449) | `session['config'] = config_data` from `request.form.to_dict()` (routes.py:449); reloaded as `Config(**session['config'])` (routes.py:155). Semi-trusted (signed cookie, instance SECRET_KEY at app/__init__.py:102-110); no session value reaches a file path — kept for recall per labels. |
| `proxyRequestRead` / `proxyRequestCallResult` / `proxyEnvironSubscript` | src-028/029/030/033/034/035 (misc.py:28/29/31/42/43/45) — candidate 0.6 | `r.environ.get('HTTP_X_FORWARDED_FOR')`, `r.environ['REMOTE_ADDR']`, `r.headers.get('X-Forwarded-Proto'/'X-Forwarded-Host')`, `r.full_path` in `get_client_ip`/`get_proxy_host_url` (misc.py:27-55); client-supplied when ProxyFix is active (app/__init__.py:26). URL/IP construction only. |

**Excluded from sources (labels role = none/fp, and correctly so)**: all ~55 env reads (operator trust; no request value ever flows into env — the only env writes are operator CLI, routes.py:624-638), all 12 CLI rows (no file-path argument), and all constant/literal path rows. No internal function parameter was promoted to a source.

### 1.2 MySinks.qll (`isSink(n, "path_traversal")`)

| QLL predicate | Label entries | Real file operation, dangerous arg, access type, call relationships |
| --- | --- | --- |
| `openSink` (builtin `open`, **arg 0** = path text, never the returned file object) | snk-242 (routes.py:430, **tp 0.97**), snk-243 (routes.py:445, **tp 0.97**), snk-234 (routes.py:103, candidate 0.6), snk-225 (misc.py:11, candidate 0.6), snk-222 (bangs.py:38, candidate 0.55), snk-229 (request.py:55, fp 0.7) | routes.py:430 `pickle.load(open(config_pkl,'rb'))` — **arbitrary read**, PUT /config; routes.py:445 `pickle.dump(config_data, open(join(CONFIG_PATH, name),'wb'))` — **arbitrary write**, POST /config; routes.py:103 `open(file_path,'rb')` session-file read (second-order listdir path); misc.py:11 `open(os.path.join(path, static_file),'rb')` (only constant/internal caller app/__init__.py:156); bangs.py:38 `open(bangs_file,'w')` (only constant caller app/__init__.py:144-147); request.py:55 `open(confloc,'r')` (env WHOOGLE_TOR_CONF — operator trust). |
| `removeSink` (`os.remove`, **arg 0**) | snk-235 (routes.py:117, candidate 0.55) | `os.remove(invalid_session)` deleting listdir-derived session-dir files that failed pickle validation (routes.py:108-120) — **file deletion**, second-order input. |

**Deliberately NOT sinks** (per reviewed labels): `os.path.join`/`dirname`/`abspath`/`splitext` and `pathlib.Path(__file__)` (summary/none — path construction is not file access), `os.path.exists`/`getsize`/`isfile` (probes, none), `os.makedirs`/`os.symlink`/`os.listdir` (constant/none), `send_file` (routes.py:484/:490 pass `io.BytesIO` buffers — **no path argument exists**, none).

**Signature-level matching note**: the two predicates match every `open()`/`os.remove()` call in the extracted tree — a superset of the 7 labeled sink sites. The extra sites (app/__init__.py settings/key/bangs opens, config.py:123, widgets.py:57, misc/update-translations.py:39) were reviewed as role `none` because their path arguments are constants; no labeled source can reach a constant, so the superset cannot produce alerts. Reachability is decided by the taint analysis, not by the sink predicate.

### 1.3 MySanitizers.qll (`isBarrier(n, "path_traversal")`)

**Zero reviewed sanitizer labels; `isBarrier` resolves to `none()`.** Each candidate barrier was checked against the real code and none blocks traversal:

| Candidate | Real behavior | Blocks traversal? |
| --- | --- | --- |
| `os.path.exists(config_pkl)` routes.py:431 | existence probe guarding the read | **No** — not containment; it is the check-then-open (TOCTOU) companion of open() at :430 and only skips missing files |
| `os.path.getsize(file_path)` routes.py:100 | size limit probe (≤ MAX_SESSION_SIZE) | **No** — size check on an already-joined path |
| `os.path.isfile(temp)` request.py:48 | probe of the env-provided tor conf path | **No** — existence probe |
| `os.path.join` | construction | **No** — taint-preserving (modeled as summary step) |
| `os.path.abspath`/`dirname` (__init__.py:24/:29/:45) | normalization applied only to app-constant `__file__`-derived paths at init | **Not applicable** — never applied to request input |
| `Config.is_safe_key` (config.py:200-211) | allowlist of config **key names** in `from_params` | **No** — filters keys, not path values, and is bypassed entirely by the direct `request.args.get('name')` channel |

No `normpath`/`resolve`/`realpath`, no `startswith(base)`, no `relative_to`, no basename extraction, no `'..'` rejection exists anywhere between the request read and the file open in `app/` (verified). The empty barrier is the accurate model.

### 1.4 MySummaries.qll (`isAdditionalTaintStep(from, to, "path_traversal")`)

| QLL predicate | Label entries | Edge semantics & evidence |
| --- | --- | --- |
| `osPathJoinStep` | snk-240 (routes.py:427, tp 0.9), snk-244 (routes.py:445, tp 0.9), snk-232 (routes.py:94, candidate 0.6), snk-226 (misc.py:11, candidate 0.6) | tainted argument → `os.path.join(...)` result, same call only. Evidence: `join` performs no normalization/containment (routes.py:427-429/:445-447 construction of the /config path; routes.py:94 session-dir join; misc.py:11 hash-file join). Arg 1 is the attacker-controlled component at the tp sites; the edge covers any tainted argument (incl. base) which is equally correct join semantics. |
| `urlDecodeStep` | src-099/103/105/106 (routes.py:285/348/383/410), src-042 (request.py:163), src-020/021/022/023 (filter.py:634/639/641/643) — all candidate 0.6 | tainted argument → `urlparse.unquote`/`unquote_plus` result, same call only. All audited sites use `import urllib.parse as urlparse` and the attribute form. Percent-decode is taint-preserving; modeled for double-decode bypass recall. Note: werkzeug already percent-decodes `request.args` before handlers, so no decode node sits on the /config chain itself. |

**Param-row summaries realized WITHOUT explicit edges** (8 entries: src-006 `gen_bangs_json bangs_file`, src-024/025 `gen_file_hash path/static_file`, src-019 `Config.from_params params`, src-159 `Search.__init__ request`, src-043/044 `Request.__init__ normal_ua/root_path`, src-027 `get_client_ip r`, src-032 `get_proxy_host_url r`): CodeQL's standard interprocedural dataflow already taints the callee parameter from a tainted call-site argument and propagates to its uses — exactly the semantics the labels describe. Adding explicit edges would duplicate standard flow and risk arbitrary node-to-node propagation, so none were created.

**g.request_params / self.request_params alias**: NOT a summary edge — the reviewed labels assigned the alias reads role `source` (src-070/076/094/095/163/166–173), so `MySources` covers them directly. No store→load edge between `before_request`'s assignment and later reads was invented.

## 2. Expected flow coverage of the generated query

The only full untrusted→path flow per the labels:
`request.args.get('name')` (src-110/src-118, source) → `os.path.join(CONFIG_PATH, name)` (snk-240/snk-244, summary step, arg 1) → `open(...)` arg 0 (snk-242 read at routes.py:430 / snk-243 write at routes.py:445, sinks). Second-order chains (session-dir open/remove via routes.py:93-120; `gen_file_hash`/`gen_bangs_json` param paths) are structurally reachable in the model but have no source-connected caller in the audited tree, so they should not alert; if they do, that is a Phase-2 Step-6 triage item.

## 3. Allowed-root / normalization / symlink / TOCTOU evidence

- **Allowed root**: `CONFIG_PATH = os.getenv('CONFIG_VOLUME', <static>/config)` (app/__init__.py:70-72) — operator-configured base; the only request input ever joined onto it is `request.args.get('name')`. `SESSION_FILE_DIR`, `BANG_PATH`, `BUILD_FOLDER`, `STATIC_FOLDER` are init-time constants.
- **Normalization order**: none — no `normpath`/`realpath`/`resolve` touches the request value anywhere; the value is joined and opened as-is. `os.path.abspath`/`dirname` are applied only to `__file__` at init.
- **Absolute paths / `..` / separators / drive letters**: all survive; `os.path.join` semantics replace the base entirely when the second argument is absolute. No separator normalization, no `is_absolute`/drive checks exist in the app.
- **Decoding**: single framework-level percent-decode (werkzeug) before the handler; no decode between source and sink; explicit `unquote` sites elsewhere are modeled as taint steps.
- **Symlinks**: `os.symlink` only at init for cache-busting build links over listdir-derived internal names (app/__init__.py:150-163); no symlink creation or following on request-controlled paths; since no canonicalization exists at all, symlink-based root-check bypass is N/A — the direct path escape already succeeds. No symlink-related barrier is modeled.
- **File-access timing**: `os.path.exists` (routes.py:431) then `open` (routes.py:430) — check-then-open TOCTOU; `getsize` (routes.py:100) then `open` (:103). These probes are not barriers and are not sinks; they will appear as intermediate path nodes in alerts (Phase-2 Step-6 contextualization input).

## 4. Known gaps, limitations, diagnostics policy

- **Dynamic channels not tracked by plain dataflow** (documented, not edge-hacked): `g.user_config = Config(**session['config'])` + `from_params` setattr loop (config.py:85-91, routes.py:155-158) — dynamic `setattr`/`__setitem__` config-attribute writes are not standard-flow-trackable; they feed URL/HTML construction, not file paths, so no pass-1 recall is lost. `session['config']` reads are modeled directly as candidate sources instead.
- **Framework-internal static serving**: Flask `static_folder` `/static/<path:filename>` (werkzeug safe_join) lives outside the database — a known coverage gap (detection.json `uncoveredCases`), not modeled as source/sink.
- **`request.args` receiver-name matching**: source predicates match the name `request` (flask's proxied request). In `Search.__init__` the parameter is also named `request` and receives the flask request (search.py:58), so those reads are covered; a differently-named alias would not be — a residual recall limitation, mitigated for the audited tree by the direct `g.request_params`/`self.request_params` source shapes.
- **CodeQL standard-flow reliance for param summaries**: if the standard library's taint models for `os.path.join`/`unquote` already exist in the installed python-all pack, the explicit summary edges are redundant but harmless (same-call arg→result edges, no over-approximation).
- **Diagnostics**: none written this round. If wrapper debugging becomes necessary (e.g. to verify source shapes fire), a separate `diagnostics/` query selecting `MySources::isSource`/`MySinks::isSink` matches directly may be added — it is explicitly NOT a formal Pass-1 alert source and its results must not be merged into `results/pass1.sarif`.
- **No compile/execution was performed during generation** (task contract); WORKFLOW.md §3.1 compatibility checks were deferred to the execution round against codeql CLI 2.25.1 + codeql/python-all 7.1.x (the cached pack used for the API facts in detection.json: `Attribute.getName()/getObject()`, `Call.getFunc()/getArg()/getAnArg()`, `Subscript.getObject()`, `Name.getId()`, `DataFlow::ConfigSig` with optional `isBarrier`/`isAdditionalFlowStep`, `TaintTracking::Global<Config>`, `<Flow>::PathGraph` + `flowPath`).

## 5. Label defect found → returned to Step 5 re-review (labels.json NOT modified)

During QLL rendering, a metadata defect was discovered in two reviewed label entries (a key collision in the Phase-1 label generator, affecting signature metadata only — the role/classification/confidence decisions are unaffected):

- **src-024** (`gen_file_hash` path parameter) currently records `arg_index: 1` and the `static_file` description; per the real signature `gen_file_hash(path: str, static_file: str)` (misc.py:10) it should be `arg_index: 0` (position 0, the `path` parameter).
- **src-043** (`Request.__init__` normal_ua parameter) currently records `arg_index: 2` and the `root_path` description; per the real signature `__init__(self, normal_ua, root_path, config)` (request.py:188) it should be `arg_index: 1` (position 1, `normal_ua`).

Per the Phase-2 contract this is recorded here and returned for Step-5 (checkpoint) re-review instead of editing `labels.json`. Neither defect affects the generated libraries: both parameters are realized through standard interprocedural dataflow (no explicit edge depends on their arg_index), and the corrected indices would change no predicate in the four `.qll` files.

## 6. Post-generation compile check (operator-requested, 2026-10-24)

After generation, the operator ran `codeql query compile --check-only` and hit two pure-syntax defects, which were fixed **without any model change** (no source/sink/sanitizer/summary semantics were altered):

1. `queries/Pass1_PathTraversal.ql` used `libraries.MySources::isSource(...)` in expression position — invalid QL (dots are import-path syntax; expressions use `::`). After `import libraries.MySources`, the module is referenced by its simple name: `MySources::isSource(...)`. All four config predicates were corrected accordingly. (This also documents a correction to WORKFLOW.md §5.2.1a's `{{SOURCE_MODULE}}` substitution intent: the module placeholder must be the simple name in expression position even when the import uses the dotted path.)
2. `libraries/MySummaries.qll` used `from`/`to` as parameter names; `from` is a reserved QL query-clause keyword and broke parsing (all "library modules cannot contain query clauses" / "multiple select clauses" / "predicate requires a body" diagnostics were cascades of this one defect). Renamed to `nodeFrom`/`nodeTo` in `osPathJoinStep`/`urlDecodeStep`.

Verification after the fix:

```
codeql query compile --check-only queries/Pass1_PathTraversal.ql
Done [1/1] ... queries/Pass1_PathTraversal.ql.        # clean: no errors, no warnings
```

The check-only compile confirms: `import libraries.My*` resolves within the `iris/whoogle-search-cwe22` pack, `Pass1Config implements DataFlow::ConfigSig` (incl. optional `isBarrier`/`isAdditionalFlowStep`) is accepted by the installed python-all pack, all predicate interfaces exist and type-check, and the path-problem select shape is valid. No query execution was performed; `results/` and the SARIF stage remain untouched.

## 7. Experiment independence

- No PyVul ground truth, CVE reports (`WHOOSE-VULNERABILITY-REPORT.md`, `WHOOSE-CVE-REPORT-*.md`), `path_traversal_sinks.csv`, fix patches, or `labels/review_decision.json` (nonexistent) were consulted or fabricated.
- Source tree, CodeQL database, Augur installation, and Phase-1 artifacts (labels.json, CSVs, exploration files) were not modified; only the six contracted files under `iris/libraries`, `iris/queries`, and `iris/report` were written.
- Every predicate above is grounded in a reviewed label entry and a cited source location; no unconditional cross-function propagation edge and no evidence-free sanitizer was created.
