# Pass 1 Query Generation Notes — pyload (Path Traversal, CWE-22/23/36/73)

- run_id: `pyload-pass1-20261023` (Phase 2, Step 4–5)
- target: pyLoad 0.5.0b3 / pyload-ng (`pyload_vuln` source tree; CodeQL DB `pyload-db`, `codeql/python-all` 7.1.x, CLI 2.25.1)
- inputs reviewed: `labels/labels.json` (750 pass-1 entries: 87 source, 223 sink, 15 sanitizer, 275 summary, 150 none), `labels/label_stats.md`, `labels/phase1_review.md`. **`labels/review_decision.json` does not exist in this workspace** — the Phase 1 human-review gate was recorded as the automated-mode self-approval in `labels/phase1_review.md` (WORKFLOW.md §4.5: the file is an optional audit artifact, not a gate); that review record was used as the checkpoint input. No modification of `labels.json` or any Phase 1 artifact was made.
- outputs: `libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass1_PathTraversal.ql`. Generated without compiling (per instruction); the files then passed a `codeql query compile --check-only` verification after one binding fix (see §8); no database analysis was executed. Every AST/data-flow API used was verified against the locally installed `codeql/python-all` 7.1.2 library sources (`Subscript.getObject()` Exprs.qll:98, `Call.getArg(int)` Exprs.qll:156, `Parameter.asName()` Function.qll:231, `AstNode.getScope()` AstExtended.qll:17, `DataFlow::parameterNode(Parameter)` DataFlowPublic.qll:350, `TaintTracking::Global` via `TaintFlowMake` in TaintTracking.qll) and follows the shapes already proven on this toolchain by the sibling projects (copyparty, dfetch). `module` is never used as a QL variable name; no `API::Node`/`DataFlow::Node` mixing (AST-only matching); file scoping uses `getAbsolutePath().replaceAll("\\", "/").matches("%/src/pyload/...")` (the proven extraction-query idiom, with `bindingset[relPath]` on the `inFile` helper) because the tree has multiple `__init__.py` files (short names are ambiguous).

## 1. Label ID → QLL predicate mapping

### MySources::isSource(node, "path_traversal") — 87 label entries (85 tp + 2 candidate)

| label family (entries) | representative label IDs | QLL predicate | matching shape |
| --- | --- | --- | --- |
| http_form (49), http_args (12), http_values (1), http_auth (2), http_iter (3) | P1-S-0026..P1-S-0033, P1-S-0030 (items loop, 0.95), P1-S-0038 (pathchooser path), P1-S-0039..P1-S-0059 (CNL), P1-S-0061..P1-S-0100 (json) | `flaskRequestRead` | `Call` whose func is `Attribute(<get/getlist/items>)` on `Attribute(<form/args/values/authorization>)` on `Attribute(request)` on `Name(flask)`; plus `Subscript` whose `getObject()` is the same request-attribute chain — restricted to the five webui request files (api/app/cnl/json blueprints, webui/app/helpers.py). The node is the call/subscript value (schema flow_kind `return`/`field`). |
| http_file (1) | P1-S-0071 (json_blueprint.py:148) | `flaskRequestRead` | `flask.request.files[...]` Subscript. |
| http_file_name (3) | P1-S-0072/-0073/-0074 (json_blueprint.py:150/:152/:155) | `multipartFilename` | `Attribute(filename)` on `Name(file)` inside `add_package()` in json_blueprint.py only. |
| route_param (4) | P1-S-0024/-0025 (rpc func/args), P1-S-0034 (render filename), P1-S-0037 (get_file path) | `routeParameter` | `DataFlow::parameterNode(p)` of the named parameters of functions `rpc`/`render`/`get_file` in the respective blueprint files. |
| api_param (6) | P1-S-0010 (set_config_value.value, candidate), P1-S-0011 (add_package.name), P1-S-0012 (check_online_status_container.container), P1-S-0013 (set_package_name.name), P1-S-0014 (upload_container.filename), P1-S-0015 (set_package_data.data) | `apiParameter` | `parameterNode` of the named parameters of the six named functions in `core/api/__init__.py`. |
| api_dispatch (1, candidate) | P1-S-0031 (call_api func) | `apiDispatchSelector` | `parameterNode` of `func` of `call_api` in api_blueprint.py. Modeled for label fidelity; no path sink is reachable from it (no dispatch edge created, see §6). |
| archive_entry (5) | P1-S-0001/-0002 (UnTar getnames :57/:79), P1-S-0003/-0004/-0005 (UnZip namelist :59/:87/:92) | `archiveEntryName` | `Call` of `Attribute(namelist)` in UnZip.py / `Attribute(getnames)` in UnTar.py. |
| cli (5), cli_arg (7) | all labeled none/fp | — not modeled — | operator-trust (sys.argv, argparse userdir/tempdir/storagedir/pidfile); see §3. |

Sources NOT fabricated: `filemanager(path)` (app_blueprint.py:439) stays a non-source — its route declares no variable and the parameter is unused (Phase 1 discard, P1-S decision recorded in labels_raw_pass1.json). No internal function parameter was promoted to a source anywhere.

### MySinks::isSink(node, "path_traversal") — modeled from the 223 sink entries (141 tp + 82 candidate)

| label family | representative label IDs | QLL predicate | dangerous position |
| --- | --- | --- | --- |
| file_open (42 tp + 8 modeled candidate) | P1-K-0297 (api :535), P1-K-0299 (api :951), P1-K-0375 (cnl :97), P1-K-0530/-0532 (http_chunk :183/:208), P1-K-0134 (MergeFiles :42), P1-K-0020 (CCF :62), P1-K-0166 (TORRENT :74), P1-K-0379 (container :69), P1-K-0002 (Alldebrid :64), P1-K-0145 (Realdebrid :95), P1-K-0205 (UpdateManager :377), P1-K-0222 (YoutubeCom :1057) | `builtinOpen` | arg 0 (path text) of `open` / `io.open`, restricted to the 30 labeled files (see §4). |
| file_save (1) | P1-K-0550 (json_blueprint.py:157) | `uploadSave` | arg 0 of `file.save(...)` in json_blueprint.py `add_package`. |
| file_response (1) | P1-K-0341 (app_blueprint.py:165) | `downloadResponse` | **arg 1** (the path; arg 0 is the fixed base directory) of `flask.send_from_directory`. |
| archive_extract (3) | P1-K-0194 (UnTar.py:23 extractall), P1-K-0196 (UnTar.py:78 `_safe_extractall`), P1-K-0200 (UnZip.py:90 extractall) | `archiveExtract` | arg 0 of `extractall`, **arg 1** of `_safe_extractall` (the dest). |
| process_file_write (2) | P1-K-0160 (SevenZip.py:261), P1-K-0187 (UnRar.py:289) | `extractorProcess` | arg 0 (argv list carrying the dest) of `subprocess.Popen`, restricted to `call_cmd` in the two extractor files (excludes the `find()` binary probes at SevenZip.py:91 / UnRar.py:75/:88, labeled none/fp). |
| dir_create (6) | P1-K-0398 (downloader.py:322), P1-K-0065 (ExtractArchive.py:255), P1-K-0212 (XDCC.py:985) | `dirCreate` | arg 0 of `os.makedirs` in the 5 labeled files. |
| file_delete (49) | P1-K-0079/P1-K-0080 (ExtractArchive :521/:525), P1-K-0397 (downloader :263), P1-K-0377 (container :51), P1-K-0474/P1-K-0476 (fs.py :337/:342), P1-K-0210 (UpdateManager :433) | `fileDeletion` | arg 0 of `os.remove` / `self.remove` / `fs.remove` / `send2trash.send2trash` in the 21 labeled files. |
| dir_delete (5) | P1-K-0076 (ExtractArchive.py:388), P1-K-0077 (:421), fs.py :276/:342, helpers.py :656 | `dirDeletion` | arg 0 of `os.rmdir` / `shutil.rmtree`. |
| file_move (10) | http_download :121, xdcc :164, fs :355/:358, AntiVirus :118/:127/:134, HotFolder :105, YoutubeCom :1182, helpers :650 | `fileMove` | **arg 0 (source path)** of `shutil.move` / `os.rename` — per the reviewed labels, which track the tainted side of these calls. |
| file_copy (2) | helpers.py :596, fs.py :356 | `fileCopy` | arg 0 of `shutil.copytree` / `copy2` / `copy`. |
| file_chmod (10) | plugin.py :137; self.set_permissions rows in downloader :323/:338, ExtractArchive :258/:360/:363, XDCC :986, YoutubeCom :1059/:1117/:1216 | `permissionChange` | arg 0 of `os.chmod` (plugin.py) and of `self.set_permissions(...)` (the wrapper calls labeled as sinks). |
| template_render (2 of 18 modeled) | P1-K-0323 (app_blueprint.py:36, candidate), P1-K-0524 (helpers.py:86, candidate) | `templateLookup` | arg 0 of `render_template` inside `render()` only, and **arg 1** (template name) of `flask_themes2.render_theme_template`. The other 16 fixed-literal rows (none/fp) are excluded by the function restriction. |
| path_stat/dir_list (modeled subset) | P1-K-0358 (listdir app_blueprint.py:289), pathchooser isfile/isdir/isabs/getmtime/getsize rows | `pathchooserProbe` | arg 0, restricted to app_blueprint.py — the only request-reachable probe channel (weak sinks, candidate-classified). |

**Candidate-sink modeling rule** (documented deviation, mirrors the copyparty precedent of excluding all candidates, narrowed to what the pyload labels support): a candidate row is modeled only if a request-derived value can plausibly reach the call (template lookups, FormFile local upload read at http_request.py:258, pathchooser probes, ExtractArchive password file, torrent/tmp writes). NOT modeled: the five captcha-image reads on fixed tempdir patterns (AntiCaptcha.py:111, Captcha9Kw.py:107, DeathByCaptcha.py:144, ExpertDecoders.py:48, ImageTyperz.py:79) and the config-gated `core/config/parser.py` open rows (:76-:96 fixed configpaths, :128/:239 candidate) — their arguments never receive request-derived taint under this source model.

### MySanitizers::isBarrier(node, "path_traversal") — 8 of the 15 sanitizer entries

| label IDs | QLL predicate | mechanism (source evidence) |
| --- | --- | --- |
| P1-K-0635 (purge.py:41, tp 0.8) | `purgeNameBarrier` | `purge.name` replaces slash/backslash/colon + Windows bad chars with `sep` (purge.py:41-50; `PyFile._set_name` passes `sep=""`, pyfile.py:33-34) — no separators left, so multi-component traversal is inert. Applied at pyfile.py:34 and http_chunk.py:349. |
| P1-K-0571, P1-K-0572 (parse.py:45/:47, tp 0.75) | `parseNameBarrier` | `parse.name` applies `os.path.basename` to URL-derived names (parse.py:40-47); used at downloader.py:309 for every download basename. |
| P1-K-0545 (http_request.py:252, tp 0.6), P1-K-0096 (HjSplit.py:57, tp 0.65), P1-K-0250 (ZDF.py:60, tp 0.6), P1-K-0124 (LinksnappyComTorrent.py:195, tp 0.55) | `basenameNeutralizer` | `os.path.basename` reducing the value to a single component before it becomes a file NAME. |

Barrier semantics: the barrier is the sanitizer **call-result node** — taint reaching the call's arguments stops at the call, only normalized values continue.

### MySummaries::isAdditionalTaintStep(from, to, "path_traversal") — from the 275 summary entries

| step | QLL predicate | code evidence |
| --- | --- | --- |
| unquote arg0 → result | `urlDecodeStep` | api_blueprint.py:55 (RPC kwargs), app_blueprint.py:163 (/files/get path), cnl_blueprint.py:63 (CNL urls), webui/app/helpers.py:43 — the only places raw route strings are percent-decoded before use. |
| os.path.join any-arg → result | `pathJoinStep` | two-sided joins throughout: json_blueprint.py:154-156, api/__init__.py:536/:952, ExtractArchive.py:239-249, MergeFiles.py:37, downloader.py:489/:515, cnl_blueprint.py:93, TORRENT.py:71, container.py:64, http_download.py:113. Also the `join = os.path.join` local alias calls in core/utils/fs.py (`_shdorc` :67, `_moverc` :257, `exists` :283, `mtime` :283, `_cleanpy2` :298, `which` :379). |
| os.path normpath/realpath/abspath/relpath/dirname/basename/split/splitext arg0 → result | `pathTransformStep` | pathchooser app_blueprint.py:257/:269/:272/:276-:283, http_download.py:114, extractor name handling (SevenZip.py:138/:300, UnRar.py:132/:329), downloader.py:262. |

## 2. Source boundaries and access conditions

| boundary | reachability / permission | notes |
| --- | --- | --- |
| Flask form/args/values/auth reads | authenticated web UI routes; permission decorators `login_required(...)` per route (helpers.py:188-217); the `/api/*` rpc route checks `api.is_authorized` (api_blueprint.py:40-45) | values are already transport-decoded by Flask/Werkzeug |
| `flask.request.files['add_file']` + `file.filename` | `/json/add_package`, `login_required("ADD")` (json_blueprint.py:136-139) | the filename is used raw — the main upload channel |
| rpc(func, args) route variables | `/api/<func>[/<args>]`, any authenticated session whose permission map authorizes the target method; `func.startswith('_')` is the only name filter (api_blueprint.py:68-70); args go through `ast.literal_eval` | |
| render(filename) | `/render/<path:filename>` — **no login_required decorator on this route** (app_blueprint.py:33-37) | jinja/flask_themes2 loader lookup |
| get_file(path) | `/files/get/<path:path>`, `login_required("DOWNLOAD")` (app_blueprint.py:159-161) | werkzeug safe_join is the external containment |
| pathchooser `args.get('path')` | `/pathchooser/`,`/filechooser/`, `login_required("STATUS")` (app_blueprint.py:252-257) | intentional browser feature |
| CNL form fields | `/flash/*` + `local_check` localhost restriction (cnl_blueprint.py:22-36); `/flashgot` additionally checks the referrer (:158-162) | CORS `*` headers noted in Phase 1 |
| core Api parameters (6) | RPC-reachable via the dynamic dispatcher; `@permission(Perms.ADD/MODIFY/SETTINGS)` per method (core/api/__init__.py:173/:417/:525/:901/:943/:984) | set_config_value is SETTINGS-gated (admin-config FP heuristic applies at triage) |
| archive entry names | remote archive content (downloaded from untrusted hosts) | extraction guarded externally (stdlib zipfile) / internally (UnTar commonprefix) |

## 3. Sinks — real operations and dangerous positions

Every modeled sink is an actual filesystem effect, never a mere path wrapper: `open`/`io.open` (read/write by mode), `FileStorage.save` (upload write), `flask.send_from_directory` (file-response read), `extractall`/`_safe_extractall` (archive extraction write), extractor `Popen` (external binary writes the tree at the supplied dest), `os.makedirs` (dir create), `os.remove`/`send2trash`/`rmtree`/`rmdir` (delete), `shutil.move`/`os.rename` (move), `shutil.copy*` (copy), `os.chmod`/`set_permissions` (permission change), `os.listdir` + os.path probes (directory enumeration/oracle — weak sinks, pathchooser only). The dangerous argument is always the **path text** (arg 0; arg 1 for `send_from_directory`, `_safe_extractall`, `render_theme_template`), never an already-open file object. The call relationships (wrapper → real API) that the default interprocedural analysis follows: `BasePlugin.remove(path)` → `fs.remove` → send2trash/rmtree/os.remove (plugin.py:112-114, fs.py:329-345); `BasePlugin.set_permissions` → `os.chmod` (plugin.py:126-137); webui `render_template` → `flask_themes2.render_theme_template` (helpers.py:84-86); `safejoin`/`safepath`/`safename` bodies (old/__init__.py:36-78); `fs.copy/move/merge/mkfile/exists` bodies (fs.py).

## 4. Path construction, decoding, canonicalization, allowed roots, symlinks

- **Decode order** (`/files/get`): `unquote(path)` THEN `replace('..','')` (app_blueprint.py:163) — single-decode traversal collapses; double-encoded `%252e` stays a literal (harmless) name. Not barriered; werkzeug safe_join (external) rejects absolute paths and residual `..`.
- **Allowed roots**: `storage_folder` (config, SETTINGS-settable), `tempdir`, `userdir` (operator CLI). pyLoad performs **no post-normalization containment check on any channel** — the only prefix checks are the torrent-decrypter `abspath(torrent_filename).startswith(tempdir + os.sep)` guards (branch checks, symlink-blind; AlldebridComTorrent.py:76, DebridlinkFrTorrent.py:121, LinksnappyComTorrent.py:66, RealdebridComTorrent.py:107) and UnTar's `commonprefix` loop; none is modeled as a barrier (see §5).
- **`'tmp_'` prefix pattern** (json_blueprint.py:154-156, api/__init__.py:536/:952): defeats only a *leading bare* `..` component (`tmp_..`); separators elsewhere survive (`x/../../evil`) — this is why the upload channels are the highest-confidence sinks.
- **Symlinks**: no symlink creation/following logic exists in the tree (Phase 1 notObserved); `os.path.realpath` appears only as canonicalization for display/state comparison. TOCTOU sequences recorded in Phase 1: pathchooser `normpath → isfile/isdir → listdir`; ExtractArchive `exists() → makedirs` (:254-255) and `exists(fname) → extract` (:304).
- **Canonicalization**: `normpath`/`realpath`/`abspath` never followed by a containment comparison anywhere — hence propagation steps (MySummaries), not barriers, per the Phase 2 contract.

## 5. Barrier soundness analysis

| candidate guard | barrier? | why |
| --- | --- | --- |
| `purge.name` | **yes** | separator removal proven (pyfile.py:33-34, http_chunk.py:347-350); lone-`..` residual cannot traverse alone |
| `parse.name` + 4 basename sites | **yes** | single-component reduction proven at each site |
| `safepath`/`safename` (old/__init__.py:36/:71) | **no** | split on `os.sep` + per-component bad-char removal, then REJOIN — a standalone `..` component contains no bad chars and survives on posix (verified old/__init__.py:36-68); this is the load-bearing weakness of `PyPackage.folder = safepath(_folder)` (pypackage.py:26-28) feeding downloader.py:319-322 and ExtractArchive.py:239-255 |
| UnTar `commonprefix` guard (UnTar.py:11-23) | **no** | character-prefix boundary (sibling `dest-evil` shares the prefix of `dest`), symlink members unresolved; also a branch check, not a value transform |
| torrent `startswith(tempdir + os.sep)` guards | **no** | branch checks; symlink-blind; upstream traversal already escapes before the check is applied to a path built from the raw package name |
| `/files/get` `replace('..','')` | **no** | unsound as a general barrier (mangles names, and masking it would hide the werkzeug-external-guard triage); alert-level guard note instead |
| CNL separator strip / add_package folder strip | **no barrier node** | inline replace chains on specific locals (cnl_blueprint.py:93-94, api/__init__.py:427-438); real neutralizers for their own writes, covered by guard notes at triage; no standalone label row anchors them |

## 6. Additional edges, dynamic dispatch, alias gaps, CodeQL limitations

**Created** (all code-verified, per §1 table): unquote step; os.path.join any-arg step (+ the fs.py `join` alias); os.path canonicalization/part-extraction step.

**Deliberately NOT created**:
1. **Dynamic RPC dispatch** (`getattr(api, func)(*args, **kwargs)`, api_blueprint.py:72-75): statically unresolved. No blanket RPC-kwarg → Api-param edge: the receiver side is already covered by the six api_param sources, and such an edge would be unconditional cross-function pollution.
2. **The `_folder` persistence chain**: `set_package_data` `setattr(p, '_folder', value)` (api/__init__.py:996-999) → sqlite (`update_package`/`db.add_package`) → `PyPackage` reload → `PyPackage.folder` property → `safejoin`/`join` destinations. The write→read connection crosses the database persistence boundary; no fabricated cross-persistence edge (same policy as copyparty's broker-IPC boundary). Consequence: the folder-chain **sinks** (downloader.py:322 makedirs, ExtractArchive.py:255, MergeFiles/XDCC/Checksum/AntiVirus joins, http_chunk.py:183/:208 chunk writes) and the **source** (set_package_data `data`, P1-S-0015) are both modeled, but a complete source→sink path for that chain will not appear in the results; it is listed here as a manual-review finding, not a CodeQL alert. The intra-object part (constructor `folder` param → `_folder` → property → `safepath`) is left to the default attribute flow.
3. **`safejoin`/`safepath`/`safename`/fs-wrapper arg→result edges**: their Python bodies are followed by the default interprocedural flow; explicit edges would bypass body analysis and could mask future barriers.
4. **str.replace and other string builtins**: left to the default unresolved-method approximation (receiver→result); no steps added.
5. **UnZip extractall `members` keyword**: the entry-name traversal channel is stdlib-guarded (external) — the modeled sink is arg 0 (dest) per the labels; no members-argument sink.

**Known residual gaps / diagnostics (not counted as official Pass 1 alerts)**:
- If wrapper matching (e.g. `self.remove` receiver resolution through the plugin class hierarchy) needs debugging, a separate diagnostics query (source/sink node counts per predicate) should be written — none was generated here; only the six contracted files exist.
- The `items()` iteration into the rpc kwargs loop relies on the default iteration/unpacking flow; if it under-resolves, the api_param sources still independently cover the RPC-receiver chains.
- External guards invisible to CodeQL (triage must weigh them): werkzeug `safe_join` (send_from_directory), jinja2 `split_template_path` + flask_themes2 theme loader (/render), stdlib `zipfile._extract_member` (UnZip members), and the UnTar commonprefix loop (modeled as non-barrier).

**Label review check**: no reviewed-label omission was discovered during generation — the two modeling gaps above are CodeQL/persistence limitations already anticipated by the Phase 1 labels (detection.json `uncoveredCases`, labels note 3), not label errors, so no return to the Phase 1 review step is required.

## 7. Post-generation compile verification (2026-10-23, after Step 4-5)

A `codeql query compile --check-only` of `queries/Pass1_PathTraversal.ql` (run by the operator, then re-verified after the fix) first failed with `'relPath' is not bound to a value` in the `inFile` file-scoping helper of all four libraries: the `relPath` parameter occurred only inside the string concatenation `"%/src/pyload/" + relPath`, a checked position the QL binding analysis cannot bind. The fix applies the idiom already proven by this workspace's own extraction queries (`extraction/sources.ql` `normalizedPathOf`/`excludedPath`): the raw absolute path is forward-slash normalized with `replaceAll("\\", "/")` and the helper is annotated `bindingset[relPath]` (all callers pass string literals, so the parameter is bound on entry). A dangling one-line QLDoc left above the new helper comment in MySources.qll was removed as well. Result: `Done [1/1]`, no errors, no warnings. This was a compile check only — still no database analysis executed, so Step 5/6 remain pending.

## 8. Experimental independence

Per the experiment contract: no PyVul ground truth, no CVE line numbers, no patch diffs, no repo-root audit artifacts (CVE_VULNERABILITY_REPORT.md, CVE_Application_Report_Unassigned.md, VULNERABILITY_AUDIT_REPORT.md, path_traversal_sinks.csv), and no pyload-db database content were consulted; only the pyload_vuln source tree, the reviewed Phase 1 labels, and the Augur assets/references were read. No source files, database, Augur files or Phase 1 artifacts were modified. Only the six contracted files were generated; the only execution since then is the operator-initiated `--check-only` compile verification recorded in §8 (no query run, no database analyze).
