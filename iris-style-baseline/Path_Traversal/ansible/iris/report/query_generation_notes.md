# Phase 2 Step 4–5 — Query Generation Notes (Pass 1 Path Traversal / ansible)

- **Run:** `ansible-pathtraversal-pass1-step3-20261021` (labels) → Step 4 rendering, 2026-10-21
- **Inputs:** `labels/labels.json` (439 entries; 288 usable-role entries: 34 source, 198 sink, 7 sanitizer, 49 summary; 151 `none`/fp entries excluded by design), `labels/labels_raw_pass1.json` (per-site row map), `augur-0.3.0/WORKFLOW.md` §5, `references/python.md`, `references/patterns.md`, `assets/taint_query.ql.tmpl`, and the real source tree (files re-read as cited below).
- **Review gate status:** `labels/review_decision.json` does **not** exist — it was an optional artifact in Step 3 and was not among that step's required outputs; the gate outcome is recorded in `labels/phase1_review.md` §7 (automated mode, self-approved, with follow-up items). Generation therefore proceeded from `labels.json` as reviewed. The Step-3 review items that affected generation are handled in §8–§10 below.
- **Generated files:** `libraries/MySources.qll` (210 lines), `libraries/MySinks.qll` (431 lines), `libraries/MySanitizers.qll` (83 lines), `libraries/MySummaries.qll` (160 lines), `queries/Pass1_PathTraversal.ql` (from the Augur template, placeholders per §12). `qlpack.yml` (`iris/ansible-cwe22`, dep `codeql/python-all: "*"`) already existed at the iris root.
- **Generation method:** deterministic rendering by `labels/work/build_libraries.py` (group by role, dedup signatures, stable ordering, machine-generated headers per WORKFLOW 5.1.4). The script **refuses to emit** unless every one of the 288 usable entries is claimed by exactly one emitted rule — full coverage asserted: 288/288. The label-id→rule map was exported to `labels/work/step4_claims.tsv` and is summarized in §3.
- No CodeQL compilation or analysis was run in this step (per the task contract); all APIs used were verified to exist in the local `codeql/python-all 7.1.2` pack (see §11).

## 1. Rendering contract

- All four libraries expose the pass-key interface required by the template: `MySources::isSource(node, passKey)`, `MySinks::isSink(node, passKey)`, `MySanitizers::isBarrier(node, passKey)`, `MySummaries::isAdditionalTaintStep(from, to, passKey)`, all gated on `passKey = "path_traversal"`.
- The query (`queries/Pass1_PathTraversal.ql`) implements `DataFlow::ConfigSig` (isSource/isSink/isBarrier/isAdditionalFlowStep delegating with the pass key — all four are legal signature predicates; the shared `codeql/dataflow 2.1.7` ConfigSig provides defaults for the barrier/step predicates), builds `Pass1Flow = TaintTracking::Global<Pass1Config>`, imports `Pass1Flow::PathGraph` and selects via `flowPath(source, sink)` with `@kind path-problem`, `@problem.severity error`, `@precision medium`, `@id py/augur/ansible/pass1-path-traversal`, tags `security` + `external/cwe/cwe-022/023/036/073`.
- Node matching is purely AST-level (`Call/Attribute/Name/Subscript/AssignStmt/Function` + `getScope().getEnclosingModule().getName()` / `getLocation().getStartLine()`), converted to `DataFlow::Node` only via `asExpr()` / `DataFlow::ParameterNode.getParameter()`. No `API::Node` is mixed with `DataFlow::Node`; no `module` variable name; no un-proven AST APIs (every accessor verified, §11).

## 2. Sources — external input boundaries and trust/access conditions

| class (MySources) | labels | boundary | who controls it / conditions |
| --- | --- | --- | --- |
| `LookupTermsParam` | p1-src-054/074/075/076/077/087/128/129/137/147 (tp 0.65) | `terms` parameter (position 1, `self` = 0) of `LookupModule.run` in the 10 path-consuming lookups (csvfile, file, fileglob, filetree, first_found, ini, password, passwordstore, shelvefile, template) | Playbook author + **remote `ansible_facts`** spliced by templating before `run()` executes (executor/task_executor.py:588/:694/:758, `C.INJECT_FACTS_AS_VARS`); CLI `--extra-vars`. The lookup then resolves the term into a controller file path with **no base containment** (lookup/__init__.py:108-125 → dataloader.py:264-321: absolute and `~` terms pass through `unfrackpath` unchanged at :283-:287). |
| `RemoteResultLoads` | p1-src-018 (tp 0.80) | the value of the 8 labeled `json.loads` calls over module stdout (winrm.py:494/:624, psrp.py:508, network_cli.py:362, task_executor.py:1106/:1109, interpreter_discovery.py:101, action/__init__.py:990 `_parse_returned_data`) | the **managed node** (data arrives over the SSH/WinRM/PSRP wire). Downstream dict reads on it (fetch.py:100-102 `slurpres.get('source')`, copy.py:355-356 `lnk_source`) are covered by the default container/subscript taint steps (pack: TaintTrackingPrivate.qll `containerStep`/`subscriptStep`). |
| `GalaxyMemberName` | p1-src-135 (tp 0.85) | `member.name` attribute reads at galaxy/role.py:278/:282/:324/:329 | the **galaxy API / github role archive** (role.py:186-203 downloads into a NamedTemporaryFile; opened at :271). Flows into the part filter at :324-329 and the `extract` sink at :330. |
| `TaskVarRead` | 21 entries (candidate 0.50–0.70): p1-src-017/019/042/072/080/088/108/109/112-117/119/120/130/142/143/146/148, rendered as 40 exact (module, line) sites | `task_vars[...]` subscripts and `task_vars.get(...)`/`variables.get(...)` calls | inventory vars + **remote facts** merged into host variables (task_executor.py:694/:758). Highest-value sites: fetch.py:129 (`inventory_hostname` → fetch dest component at :132), network.py:74 / ce_template.py:46 (host name → backup filename), template.py:119 + lookup/template.py:83 (`ansible_search_path` → jinja loader searchpath), passwordstore.py:263 (vars-controlled pass directory). The synchronize/module_common/interpreter_discovery entries (conf 0.50, review item 6.5) were verified during generation to feed mainly non-path uses (rsync/module options, interpreter selection) and a few assignment/delete targets (synchronize.py:118-:132) that cannot produce out-flows; retained per the approved labels, documented as potential noise. |
| `FetchRemoteAddr` | p1-src-073 (candidate 0.60) | `self._play_context.remote_addr` read at fetch.py:131 only | inventory-defined host address (operator-written naming data); fallback `target_name` component of the fetch dest built at fetch.py:132 when `inventory_hostname` is absent. |

Operator-trust boundaries (`context.CLIARGS`, `sys.argv`, CLI `args`, `os.environ` — 16 labels/985 rows) were excluded in Step 3 as `none`/fp and are deliberately **not** rendered. No internal helper parameter (e.g. `file_handler(path)`) was promoted to a source.

## 3. Sinks — real file operations, dangerous argument positions, call relationships

Direct API argument sinks (node = the path **text** argument expression, never the returned file object):

| class | labels (folded) | operation / arg index | access type |
| --- | --- | --- | --- |
| `FileOpenArg` | 7 entries (p1-snk-001 etc.) | `open`/`os.open`/`io.open`/`shelve.open` arg 0 | read or create/write (fetch.py:175 write of fetched file; dataloader.py:157/:355 reads; shelvefile.py:47 dbm open) |
| `FileDeleteArg` | 8 | `os.remove`/`os.unlink`/`os.rmdir`/`shutil.rmtree` arg 0 | destructive delete (user.py:2238 rmtree, galaxy/role.py:349) |
| `FileDirCreateArg` | 4 + 1 | `os.makedirs`/`os.mkdir` arg 0; `makedirs_safe(...)` (bare-name) arg 0 | directory creation (galaxy/role.py:316; fetch.py:168 via `dirname`) |
| `FileCreateArg` | 4 | `os.symlink`/`os.link` arg 1 (the created link) | link planting (file.py:852, timezone.py:772) |
| `FileMoveArg` | 4 | `os.rename`/`shutil.move` arg 0 (destination arg 1 equally reachable via default arg flow) | move/replace |
| `FileCopyArg` | 8 | `shutil.copyfile`/`copy`/`copy2`/`copytree` arg 0 (source; dest arg 1 = write side) | copy/write (local.py:150 controller write) |
| `FileStatArg` | 5 | `os.stat`/`os.lstat`/`os.path.getsize` arg 0 | metadata oracle (candidate grade) |
| `FileReadArg` | 6 | `os.listdir`/`os.walk`/`os.readlink` arg 0 | enumeration/link-target oracle (candidate) |
| `FilePermsArg` | 6 | `os.chmod`/`os.chown`/`os.utime` arg 0 | attribute change (candidate) |
| `PathGlobArg` | 2 | `glob.glob` arg 0 | pattern enumeration (candidate) |
| `ArchiveOpenArg` | 4 | `tarfile.open`/`ZipFile` (bare + `zipfile.ZipFile`) arg 0 | archive read (candidate) |
| `GalaxyExtractArg` | 1 (p1-snk-269) | `role_tar_file.extract(member, self.path)` — see §9 for the arg-0/arg-1 decision | archive extraction write (galaxy/role.py:330) |

Wrapper call-site sinks (argument node at the call — **does not depend on CodeQL resolving `self._loader`/`self`/`self._connection` dispatch**):

| class | labels | shape |
| --- | --- | --- |
| `LoaderCallArg` (17) | `get_real_file`/`_get_file_contents`/`load_from_file`/`cleanup_tmp_file` on `self._loader`, arg 0 → reaches `open()` at dataloader.py:157/:355 |
| `ActionCallArg` (22) | `_transfer_file` args 0/1, `_transfer_data`/`_execute_remote_stat`/`_remote_checksum` arg 0 on `self` → `self._connection.put_file` (action/__init__.py:415/:433) |
| `ConnectionCallArg` (4) | `fetch_file`/`put_file` args 0/1 on `self._connection` — arg 1 is the transfer destination; for `fetch_file` it is the **controller-side** dest (fetch.py:172; paramiko sftp.get localpath, local.py:156-162, chroot.py:194) |

Wrapper definition parameter sinks — `WrapperDefParam` (95 labels → 94 deduped `(module, function, paramIdx)` rows): the `path`-carrying parameters of `DataLoader._get_file_contents/get_real_file/load_from_file/list_directory/cleanup_tmp_file`, `ActionBase._transfer_file/_transfer_data/_execute_remote_stat/_remote_checksum/_get_diff_data`, `FileVaultSecret._read_file`/`ScriptVaultSecret._read_file` (see §9), `utils/path.makedirs_safe/cleanup_tmp_file`, and `put_file`/`fetch_file` of all 21 concrete connection plugins (base `ConnectionBase`/`NetworkConnectionBase` defs were labeled `none` and excluded). These fire only when CodeQL resolves the call→definition edge and are secondary recall to the call-site rules.

Module-side sites (1,010 of the labeled sink rows) are included by the signature-level rules and only fire if taint reaches them — the `module.params` boundary was deliberately not extracted (detection.json uncoveredCases), so no pass-1 source reaches module code (documented limitation, §10).

**Fold note:** the labels' receiver-split duplicate signatures (bare-name vs `os`-qualified rows of the same call sites, e.g. `os.remove`) were folded into one rule per API — all evidence line texts show the qualified form at both signature rows, so the qualified rule covers all real sites. Both `os.path.join(...)` and `from os import path; path.join(...)` spellings are matched (labels kept both forms).

## 4. Sanitizers — do the barriers actually block?

| class | labels | what it really blocks |
| --- | --- | --- |
| `BasenameCallValue` (barrier at the `os.path.basename` **call value**) | p1-snk-036 (candidate 0.55) | Strips the directory component, so the output cannot carry `../` segments in the filename position — neutralizes the fetch flat-branch (`base = os.path.basename(source_local)`, fetch.py:118-122), fileglob.py:60, template.py:171, uri.py:45. **Not a proven barrier:** `basename('..') == '..'` (a whole-path `..` survives a subsequent `join`), and only `os.sep` is split (alternate separators survive on other platforms). Barrier position = call value (argument itself not blocked), so filename-only taint is intentionally stopped. |
| `RemoteExpandUserCallValue` (barrier at the `self._remote_expand_user(...)` call value; realizes all 6 `_remote_expand_user` labels incl. the definition-row label p1-snk-103) | p1-snk-023/092/103/136/163/182 (candidate 0.45–0.50) | `action/__init__.py:686-687` raises `AnsibleError` when `'..'` appears in `os.path.dirname(expanded).split('/')` — a genuine `..`-segment rejection, but only for `~`-prefixed paths and only after remote expansion; non-tilde paths pass through unvalidated. The definition-row label was realized via the call-site value barriers rather than an input-side parameter barrier, because a parameter-entry barrier would also block the unvalidated non-tilde pass-through flows (over-sanitization → false negatives). |

Nothing else was accepted as a barrier: `normpath`, `realpath`, `unfrackpath`, `path_dwim*` are canonicalization/resolution **without any base-directory containment** (utils/path.py:31-62 — its own docstring shows `$HOME/../../var/mail`; dataloader.py:181/:222/:283 absolute/`~` passthrough) and are modeled as taint **propagators** (§5). No allowed-root containment check exists anywhere in the audited chains (checked: fetch, DataLoader, ActionBase, connection plugins, galaxy); the only root-ish check in the tree is chroot.py `_prefix_login_path` (join-to-`/` + normpath — **no** `..` containment, so not a barrier).

## 5. Summaries — path connection/decoding/normalization edges

Rendered from the 49 summary labels (each step is shape-conditional, never node-to-node unconditionally):

- `pathJoinStep` — `os.path.join`: every argument **and the `*args` value** (`getStarArg()`) → result (fetch.py:122/:132, dataloader search stacks, galaxy role.py:329). 2 labels.
- `pathExpandStep` — `expanduser`/`expandvars` arg 0 → result (tilde/env expansion turns relative values absolute — fetch.py:111; can escape a relative base). 3 labels.
- `pathResolveStep` — `dirname`/`splitext`/`split`/`realpath`/`normpath`/`abspath`/`relpath` arg 0 → result: component extraction and canonicalization, taint-preserving, no containment. 8 labels.
- `nameFuncStep(unfrackpath)` — bare-name `unfrackpath(...)` arg 0 → result (utils/path.py:31-62). 2 labels (call + def row).
- `wrapperStep` — argument → call value for `self._loader.path_dwim` (arg 0), `.path_dwim_relative` / `.path_dwim_relative_stack` (arg 2), `.find_vars_files` (arg 1), `self._find_needle` (arg 1), `self.find_file_in_search_path` (arg 2): models that the wrapper returns a path derived from the argument, without containment. 28 call-site labels.
- 6 def-row summary labels (path_dwim family, `_find_needle`, `find_file_in_search_path` definitions) are realized **def-side** (resolution-dependent): when CodeQL resolves the call, the body flows via `pathJoinStep`/`nameFuncStep(unfrackpath)`/`to_*` and the default return-value edges.

**Covered by the default taint library — no custom step emitted** (verified in `semmle/python/dataflow/new/internal/TaintTrackingPrivate.qll`): `%`-string formatting (`stringManipulation`, Mod operand → result — fetch.py:132), `str.replace`/`str.split` object → result (fetch.py:134, role.py:324), dict subscript and `<tainted>.get(k)` reads (`subscriptStep`/`containerStep` — fetch.py:100-102, copy.py:355), `for x in tainted:` iteration (`forReadStep` — role.py:326), `sep.join(iterable)` (arg 0 → result), `+` concatenation. This resolves Step-3 review item 6.2 without new edges.

## 6. Generation-time additions (beyond the labels) — each evidence-backed

| step / position | evidence | why needed |
| --- | --- | --- |
| `nameFuncStep` for `to_bytes` / `to_text` / `to_native` | fetch.py:175 `open(to_bytes(dest, ...))`, local.py:150 `shutil.copyfile(to_bytes(in_path), to_bytes(out_path))`, utils/path.py:62 `return to_text(os.path.normpath(...))` | identity-ish encoding converters used in every ansible path chain; without them taint stops one call before `open`/`copyfile` |
| `nameFuncStep` for `unquote` | dataloader.py:178 `given = unquote(given)` inside `path_dwim` | def-side realization of the path_dwim summary label |
| `listAppendStep` (`lst.append(x)`: arg 0 → list object) | galaxy/role.py:328 `final_parts.append(part)` | carries the filtered, still-untrusted parts into the `join` |
| `nameAttrStoreStep` (`obj.name = <tainted>` → `obj`) | galaxy/role.py:329 `member.name = os.path.join(*final_parts)` then :330 `extract(member, self.path)` | carries the rebuilt member name onto the member object that enters the extract sink |
| `GalaxyExtractArg` argument 0 | galaxy/role.py:330 | see §9 (review-return item) |

No edge was created between arbitrary nodes; every step is conditional on a concrete AST shape found in the real code above.

## 7. Expected end-to-end chains (sanity design check, not executed)

- **fetch dest:** `task_vars['inventory_hostname']` (fetch.py:129) / `remote_addr` (:131) / slurp `source` (:100-102 via `RemoteResultLoads` + default dict steps) → `"%s/%s/%s" %` (:132, default Mod step) → `dest.replace("//","/")` (:134, default) → `makedirs_safe(os.path.dirname(dest))` (:168 sink via `pathResolveStep`), `open(to_bytes(dest),'wb')` (:175 sink via `to_bytes` step), `self._connection.fetch_file(source, dest)` (:172 `ConnectionCallArg` arg 1). The flat-branch `basename` (:121) is a barrier — matching the labels' analysis that only the non-flat branch keeps the traversal.
- **galaxy extract:** `member.name` (:324 source) → default `replace`/`split`/`for` steps → `append`/`join(*final_parts)` (custom steps) → `member.name =` store (:329) → `extract(member, self.path)` (:330 sink, arg 0).
- **lookup reads:** `terms` param → `find_file_in_search_path` / `path_dwim_relative` (wrapperStep) → `self._loader._get_file_contents` / `shelve.open` / `glob.glob` sinks.

## 8. Effect of the known Step-3 gaps

- **task_args family missing** (extraction defect, review item 6.1): task `src`/`dest` values (fetch/copy/template/include_vars arguments) are **not** sources in this query, so the operator-argument halves of those chains cannot fire; only the fact/remote-result/lookup-term halves modeled above are reachable. Fixing the extraction predicate remains the recommended pre-Step-5 action.
- **`module.params` boundary absent** → module-side sinks unreachable by pass-1 sources (expected zero module-side findings; they are kept for the module-focused future pass).

## 9. Deviations found during rendering — returned for re-review (labels.json NOT modified)

1. **`GalaxyExtractArg` argument 0 (label p1-snk-269 says arg_index 1).** The labeled index 1 is `self.path` (the extraction destination, roles-path config — never tainted); the untrusted path component is `member.name`, which enters through argument 0. The query sinks **both** positions (arg 1 kept per the label; arg 0 added) because `tarfile.extract(member, path)` writes files named `member.name` under `path`. Without arg 0 the galaxy chain — one of the two headline flows — would be dead. Recorded here as a review-return item for the label gate rather than a silent change.
2. **`ScriptVaultSecret._read_file` (p1-snk-110).** The labels' def table contains two `_read_file` entries in module `ansible.parsing.vault.__init__` (FileVaultSecret + ScriptVaultSecret, both rendered sink/tp); the ScriptVaultSecret variant executes the file (subprocess) rather than opening it — its pass-1 relevance is as an existence/exec check only. Kept per labels; flagged for re-review.
3. Minor rendering folds (documented, no semantic change): receiver-split duplicate signatures folded; bare-name `open` matched at signature level (460 labeled sites); `_read_file` dedup (2 identical (module,callable,arg) rows → 1 table row).

## 10. Dynamic-dispatch/alias omissions and CodeQL limitations (documented, not silently fixed)

- `win_copy.py:107` uses `loader.get_real_file(...)` (receiver named `loader`, not `self._loader`) — that call shape is outside both the extraction families and the emitted rules (a real, unmodeled sink site; would need an alias-aware rule or API-graph resolution).
- `self._loader` / `self._connection` attribute dispatch resolution in Python CodeQL is weak — this is exactly why the labels' call-site argument sinks/summaries exist and why `WrapperDefParam` is secondary.
- The 5 source candidates at confidence 0.50 (synchronize/module_common/interpreter_discovery) may contribute noise paths (documented in `labels/label_stats.md` and `phase1_review.md` §6.5).
- `makedirs_safe` TOCTOU (realpath → makedirs → later open, CWE-059 timing) is not statically distinguishable; the barrier/sink model cannot express it.
- Windows alternate separators are not split by `basename`/`os.sep`-based filters (barrier and galaxy-filter residual).

## 11. API verification record (against `codeql/python-all 7.1.2` + `codeql/dataflow 2.1.7` in the local pack cache)

Verified to exist before use: `DataFlow::Node.asExpr()` (DataFlowPublic.qll:200), `DataFlow::ParameterNode.getParameter()` (:334), `class ... extends DataFlow::Node/ParameterNode` (Concepts.qll:29, SensitiveDataSources.qll:316), `Call.getFunc()/getArg(int)/getAnArg()/getStarArg()` (Exprs.qll:156-:190, star arg returns the Starred's value), `Subscript.getObject()`, `Attribute.getName()/getObject()`, `Name.getId()`, `Function.getArg(int)/getName()/getScope()` (AstGenerated.qll:536, Function.qll:10/:21), `AstNode.getScope().getEnclosingModule().getName()`, `getLocation().getStartLine()` (proven by the Phase-1 extraction run), `AssignStmt.getATarget()/getValue()` (Stmts.qll:76-:89), `BinaryExpr/Mod` (Operations.qll — used only by the default library), `x in [..]` set membership (TaintTrackingPrivate.qll:114), `DataFlow::ConfigSig` with isSource/isSink/isBarrier/isAdditionalFlowStep defaults (dataflow 2.1.7 DataFlow.qll:401-:427), `TaintTracking::Global<DataFlow::ConfigSig>` (TaintTracking.qll:313) and `flowPath`/`PathGraph` (DataFlow.qll:723). Default-step coverage for %-format/replace/split/dict-read/for-read/str.join confirmed in TaintTrackingPrivate.qll:77-:190.

## 12. Query metadata and template substitution

`Pass1_PathTraversal.ql` renders `assets/taint_query.ql.tmpl` with: QUERY_NAME "Ansible: path traversal from untrusted boundaries to file operations"; QUERY_ID `py/augur/ansible/pass1-path-traversal`; PRECISION `medium` (oracle-grade candidate sinks and resolution-dependent param sinks keep precision at medium); CWE_PRIMARY `022` + EXTRA_TAGS cwe-023/036/073; LANGUAGE_IMPORTS `import python` + `import semmle.python.dataflow.new.DataFlow` + `import semmle.python.dataflow.new.TaintTracking`; SOURCE/SINK/SANITIZER/SUMMARY modules `libraries.My*`; CONFIG_NAME `Pass1Config`; FLOW_MODULE `Pass1Flow`; PASS_KEY `path_traversal`; RESULT_MESSAGE as in the file. Per the task contract, **no diagnostics query was written and no compilation/analysis was executed** — the only formal Pass 1 alert source is `queries/Pass1_PathTraversal.ql`; internal wrapper debugging (if ever needed before the Step-5 run) belongs in `iris/diagnostics/` and is excluded from formal results.

## 13. Experimental independence

Same principles as the earlier steps of this series: the PyVul ground truth (PATH_TRAVERSAL_AUDIT_REPORT.md, CVE_APPLICATION_REPORT.md, CVE申请报告.md, 漏洞审查报告.md, path_traversal_sinks.csv), known CVE lines and fix patches were **not** read; all modeling evidence comes from `labels/labels.json` (itself produced without ground-truth access) and first-hand source reading. Neither the ansible_vuln source tree, nor ansible-db, nor the Augur installation, nor the Phase-1 artifacts (labels/labels.json, extraction CSVs/QL) were modified — the only writes were the six files listed at the top plus the generator/claims artifacts under `labels/work/`.
