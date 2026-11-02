# Augur Phase 2 Step 4 — Query Generation Notes (dfetch, Pass 1: Path Traversal)

- **Run:** `iris-dfetch-pathtraversal-pass1-20261022` · 2026-10-22 · model `glm-5.3`
- **Inputs:** `iris/labels/labels.json` (160 entries, schema-valid; 11 source / 16 sink /
  33 summary / 0 sanitizer / 100 none), `labels/label_stats.md`,
  `labels/phase1_review.md`, WORKFLOW.md §5, `assets/taint_query.ql.tmpl`,
  `references/python.md`, `references/patterns.md`, and the dfetch source tree
  (`dfetch_vuln`, snapshot sha 81020d5, dfetch 0.5.1).
- **Generated files:** `libraries/MySources.qll`, `libraries/MySinks.qll`,
  `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`,
  `queries/Pass1_PathTraversal.ql`, this report.
- **Compile validation:** `codeql query compile --check-only` against the local toolchain
  (CLI 2.25.1 + `codeql/python-all` 7.1.2 resolved from the user pack cache) **passes with
  zero errors and zero warnings** (WORKFLOW §3.1.1 compatibility policy honored). A first
  compile attempt surfaced five API-level corrections, all fixed against the installed
  pack source (see §7). **Not performed:** `database analyze`, taint execution, SARIF —
  those belong to Step 5.
- **Review basis:** `labels/review_decision.json` does **not exist** in the workspace
  (it is the optional audit artifact of WORKFLOW.md §4.5; Phase 1 recorded its checkpoint
  in `labels/phase1_review.md` instead). No review_decision.json was fabricated. The
  Step-4 rendering is based on `labels/labels.json` plus the review points recorded in
  `phase1_review.md`. The four manual-review points of that file are honored as follows:
  (a) manifest-as-untrusted trust model → kept (sources rendered); (b) operator-trust
  CLI dismissal → kept (no CLI source rendered); (c) `sink-015` sparse-checkout row →
  kept as a sink (classification `candidate`) — it can never fire (literal path
  argument), see §3; (d) no re-asking was needed.
- **No label omissions discovered:** every pass-1 `source`/`sink` label is rendered
  exactly once below; every `summary` label is either rendered as an explicit taint step
  or realized by native flow (§5). No return to Step 3/5 review is required.

---

## 1. Label → QLL predicate mapping

### 1.1 MySources.qll (11 source labels → 8 private predicates → `isSource(n, "path_traversal")`)

| Label id | Location | Predicate | External input boundary & access conditions |
| --- | --- | --- | --- |
| src-022 | manifest/manifest.py:139 | `isYamlSafeLoadBoundary` (manifest.py branch) | `yaml.safe_load(text)` in `Manifest._load_yaml` ← `Manifest.from_yaml` ← `from_file` ← `get_manifest`/`get_childmanifests`. Untrusted whenever dfetch.yaml originates from fetched/foreign repository content: child-manifests are walked out of FETCHED destinations (manifest.py:263-280, CWD = `project.destination` set by update.py:76 / check.py:70); `dfetch import` writes manifests built from remote subprocess output. Read access to the file is ordinary user-level read in the operator's tree — the trust question is *content provenance*, not privilege. |
| src-032 | project/metadata.py:71 | `isYamlSafeLoadBoundary` (metadata.py branch) | `yaml.safe_load(metadata_file)` in `Metadata.from_file` — the `.dfetch_data.yaml` inside a fetched destination; a malicious fetched repo can ship or modify it before dfetch overwrites it (dfetch writes it only after a successful fetch of the same path). Current consumers read version/hash; the dict also carries `destination`/`patch` keys. |
| src-023 | manifest/manifest.py:129 | `isManifestRootRead` | `loaded_yaml["manifest"]` — root-dict read of the parsed manifest; container of all project/remote fields. |
| src-031 | project/metadata.py:71 | `isMetadataRootRead` | `yaml.safe_load(metadata_file)["dfetch"]` — root-dict read of the parsed metadata file. |
| src-033 | manifest/project.py:268 | `isProjectEntryFieldRead` | `yamldata[key]` loop in `ProjectEntry.from_yaml` over `ProjectEntryDict.__annotations__` keys — per-field manifest value read (name/dst/src/patch/…). Taints every field value including `name` (needed for the diff.py:171 patch-write chain C9). |
| src-027 | manifest/project.py:245 | `isProjectEntryPathField` (key `"src"`) | manifest `src` field — subtree/file/glob inside the fetched repo; `kwargs.get("src", "")`. Schema type ANY; only restriction in the whole tree is the svn-side single-`*` check (svn.py:227-236), which does not block `..`/absolute. |
| src-028 | manifest/project.py:246 | `isProjectEntryPathField` (key `"dst"`) | manifest `dst` field — THE destination; `kwargs.get("dst", self._name)` (defaults to project name). Fully attacker-controlled path string; absolute/`..`/mixed-separator values all pass pykwalify (type str + unique only, schema.yaml:25). |
| src-029 | manifest/project.py:248 | `isProjectEntryPathField` (key `"patch"`) | manifest `patch` field — `kwargs.get("patch", "")`; schema.yaml:32 type str, no content constraint; read/parse at vcs.py:134, applied at vcs.py:138. |
| src-025 | project/metadata.py:46 | `isMetadataDestinationField` (key `"destination"`) | `kwargs.get("destination", "")` in `Metadata.__init__` — via `from_project_entry` (vcs.py:35) it is `ProjectEntry.destination` (manifest `dst`); via `from_file` it is the `destination` field of the re-read `.dfetch_data.yaml`. Keyed to `"destination"` only: the other metadata keys are reviewed fp (the metadata `patch` field is never used as a path). |
| src-017 | vcs/git.py:229 | `isSubmoduleStdout` | `.stdout` of `git submodule foreach --quiet echo $name $sm_path $sha1 $toplevel` inside `GitLocalRepo.submodules()` — `sm_path` is the remote-controlled `.gitmodules` content of the audited repo; becomes an imported `ProjectEntry dst` (import_.py:180). Genuinely untrusted remote data; no local validation of any kind. Enclosing-function guard (`submodules`) excludes the fp stdout rows of the same module (version/SHA/branch/diff-text at :24/:184/:194/:212/:296). |
| src-046 | project/svn.py:46 | `isExternalsStdout` | `.stdout` of `svn propget svn:externals -R` inside `SvnRepo.externals()` — parsed `local_path`/`name` become `External.path` (svn.py:70) then an imported `dst` (import_.py:158). Enclosing-function guard (`externals`) excludes the fp rows (:141 tags, :149 version). |

The 50 `none`/fp source rows are not matched: 23 CLI rows (operator-trust; `run(argv)`,
`Command.__call__` params, `args.*` fields — a file-handling wrapper's parameter is never
auto-promoted to a source in this model), 8 non-path stdout rows, 17 non-path
manifest/metadata fields (branch/tag/revision/url/repo-path/hash/remote-name — version or
URL material), 2 serialization writes.

### 1.2 MySinks.qll (16 sink labels → 16 private predicates → `isSink(n, "path_traversal")`)

| Label id | Location (predicate) | Real file operation / dangerous position / access type / call relationships |
| --- | --- | --- |
| sink-059 (`isPatchFileWrite`) | commands/diff.py:171 | `open(patch_name, "w")` — **file write**, arg **0**. `patch_name` = `f"{project.name}.patch"` (diff.py:114, name from manifest/yamldata) → `_dump_patch(path, revs, project, patch_name, patch)` (diff.py:119). Name with `../` writes outside the manifest dir (CWD = manifest dir, diff.py:106). Fixed `.patch` suffix limits but does not prevent traversal. |
| sink-015 (`isSparseCheckoutAppend`) | vcs/git.py:149 | `open('.git/info/sparse-checkout', 'a')` — **file append**, arg 0 is a **string literal**, so this predicate can never match a tainted node; rendered only because the reviewed label kept it as `candidate`. The flagged channel (manifest `src` written as content, then git materializes files per pattern) is anchored at the `src` source label instead; git-internal pattern handling is the open manual-review question. |
| sink-081 (`isMetadataRead`) | project/metadata.py:70 | `open(path, "r")` — **file read**, arg **0** (the `from_file` parameter, reached via `Metadata.path` = `realpath(join(destination, FILENAME))`). Bounded impact (parse/compare/log). Arg-shape guard (Name `path`) distinguishes it from the write at :165. |
| sink-089 (`isMetadataWrite`) | project/metadata.py:165 | `open(self.path, "w+")` — **file overwrite/create**, arg **0** (Attribute `self.path`). Called from `VCS.update` (vcs.py:130) for every fetched project. Arg-shape guard (Attribute) distinguishes it from the read at :70. |
| sink-093 (`isHashFileRead`) | util/util.py:107 | `open(file_path, "rb")` — **file read**, arg **0**; `hash_file` ← `hash_directory(self.local_path)` (vcs.py:125/:269). Bounded impact (MD5 digest, never printed). |
| sink-020 (`isSubtreeMove`) | vcs/git.py:169 | `shutil.move(src + "/" + file_to_copy, ".")` — **file move**, arg **0** (concatenated manifest-`src` path). Caller: `GitLocalRepo.checkout_version` (:168 listdir feeds it), CWD = manifest dst. |
| sink-062 (`isSvnNonMatchingRemove`) | project/svn.py:206 | `os.remove(file)` — **file delete**, arg **0**; files yielded by `find_non_matching_files(self.local_path, file_pattern)` (svn.py:205 → util.py:20-25 walk rooted at dst). |
| sink-076 (`isSafeRemove`) | util/util.py:33 | `os.remove(path)` — **file delete**, arg **0**; the `safe_rm` primitive, called `safe_rm(self.local_path)` from `VCS.update` (vcs.py:105) — pre-fetch clearing of the manifest dst. |
| sink-079 (`isRecursiveDelete`) | util/util.py:39 | `shutil.rmtree(path, onerror=...)` — **recursive directory delete**, arg **0**; callers: `safe_rmtree(local_path)` (vcs.py:105), `safe_rmtree(join(local_path, '.git'))` (project/git.py:80), `safe_rmtree(PurePath(src).parts[0])` (vcs/git.py:170 — the `..`/root-component amplifier). Strongest Pass 1 sink. |
| sink-083 (`isWorkingDirChange`) | util/util.py:52 | `os.chdir(path)` — **working-directory change**, arg **0** (Name `path`; the restore `chdir(pwd)` at :54 is excluded by the arg-shape guard). `in_directory` callers: update.py:70/:76, check.py:63/:70, vcs/git.py:121/:142/:178/:198/:288, svn.py:122. Absolute/`..` dst escapes the CWD scoping — the mechanism itself is a reviewed sink, not a guard. |
| sink-071 (`isChmodOnDelete`) | util/util.py:14 | `os.chmod(path, stat.S_IWUSR)` — **permission change**, arg **0** (Name `path`); rmtree onerror callback — paths supplied by rmtree from the (possibly escaped) deleted tree. |
| sink-054 (`isDstDirCreate`) | project/git.py:70 | `pathlib.Path(self.local_path).mkdir(parents=True, exist_ok=True)` — **directory creation**, dangerous position = **receiver** of `.mkdir` (the `Path(...)` construction). `self.local_path` = manifest `dst` (vcs.py:177-180). Creates every missing parent anywhere the path points. |
| sink-058 (`isDstParentDirCreate`) | project/svn.py:196 | `pathlib.Path(os.path.dirname(self.local_path)).mkdir(parents=True, exist_ok=True)` — **directory creation**, dangerous position = **receiver** (same semantics as sink-054 for the dst parent chain). |
| sink-064 (`isSvnExportDst`) | project/svn.py:245 | `run_on_cmdline(logger, ['svn','export','--force'] + rev.split(' ') + [url, dst])` — **process file write**: the svn process writes the exported tree at `dst`. Reviewed label documents flattened-list index **6** (valid while `rev` = `'--revision <N>'`, which `_determine_what_to_fetch` guarantees by enforcing a numeric revision, svn.py:179-184; a `rev=""` call would shift it to 5 — noted for future review). Rendered structurally: the `dst` Name use inside `SvnRepo._export` (enclosing-function guard). |
| sink-094 (`isPatchFileRead`) | project/vcs.py:134 | `patch_ng.fromfile(self.__project.patch)` — **file read/parse**, arg **0** (manifest `patch` field). Caller: `VCS.apply_patch` ← `VCS.update` (vcs.py:116-118). |
| sink-095 (`isPatchApplyRoot`) | project/vcs.py:138 | `patch_set.apply(0, root=self.local_path, fuzz=True)` — **patch-driven file writes** under `root` = manifest dst; the dangerous position is the **`root=` keyword value** (no positional index exists — the reviewed label records flow_kind `unknown` for exactly this reason). Patch-internal target paths are parsed inside patch-ng (not in this database). |

Path TEXT versus file OBJECT distinction: every sink anchors on the expression that
names a file LOCATION (argument or receiver of the accessing call), never on a returned
file object; pure path-construction nodes (`Path()`, `join`, `dirname`, `realpath`,
`basename`, `walk`, `listdir`) are never sinks — they are propagation (§5).

### 1.3 MySanitizers.qll (0 sanitizer labels → `none()`)

`isBarrier(n, "path_traversal")` resolves to `none()` — the WORKFLOW §5.2.3 mandated
empty fallback. Justification that no reviewed barrier exists (per-label evidence,
re-verified in source):

| Guard-shaped code | Why it does NOT block traversal |
| --- | --- |
| pykwalify validation (manifest/validate.py → resources/schema.yaml) | type/structure only: `dst: str unique`, `patch: str`, `src: any` — no `..`/absolute/separator/charset constraint. |
| `os.path.realpath` (metadata.py:129/:132, manifest.py:247/:270) | normalization only; result never compared to an allowed base; still used directly as the access path. |
| `relative_to` (manifest.py:274) | display/error prefix construction; constrains walked child-manifest paths only, never dst/src/patch; raises uncaught `ValueError` (prefix_runtime_exceptions catches `RuntimeError` only). |
| `basename` (metadata.py:131) | neutralizes only the FILENAME component; the containing directory `dirname(dst)` (:133) stays attacker-controlled. |
| `os.path.isdir/exists/isfile` probes | existence checks, no containment semantics (vcs.py:103/:117 TOCTOU windows documented). |
| single-`*` check on `src` (svn.py:227-236) | does not reject `..` or absolute values. |
| CWD scoping `in_directory`/`chdir` | itself reviewed sink-083; cannot confine an absolute or `..`-escaping destination. |
| symlinks | no `islink`/`lexists` anywhere — nothing to evaluate; `realpath` resolves links *before* use with no post-check, so symlink placement cannot be blocked by this code (documented, not modeled as a barrier). |

No allowed-root directory, no canonicalize-then-contain ordering, no whitelist exists in
the audited code — hence an empty barrier set is the faithful rendering, and no real flow
can be suppressed by the query.

### 1.4 queries/Pass1_PathTraversal.ql

Rendered from `assets/taint_query.ql.tmpl` with: QUERY_NAME "Path traversal in dfetch via
manifest-controlled paths", QUERY_ID `py/augur/dfetch/pass1-path-traversal`, PRECISION
**medium**, CWE_PRIMARY 022 + EXTRA_TAGS cwe-023/cwe-036/cwe-073, `@kind path-problem`,
`@problem.severity error`, `@tags security`; SOURCE/SINK/SANITIZER/SUMMARY modules =
`libraries.MySources` / `MySinks` / `MySanitizers` / `MySummaries` (dot-syntax imports,
all four `isSource`/`isSink`/`isBarrier`/`isAdditionalTaintStep` interfaces exist with the
2-/3-argument pass-key signatures); CONFIG_NAME `Pass1Config`, FLOW_MODULE `Pass1Flow`,
PASS_KEY `path_traversal`; Python import block `import python` +
`semmle.python.dataflow.new.DataFlow` + `semmle.python.dataflow.new.TaintTracking`;
`module Pass1Flow = TaintTracking::Global<Pass1Config>` + `import Pass1Flow::PathGraph`
+ `flowPath(source, sink)` select. `@precision medium` rationale: AST-level (name-based)
matching plus property-hop summary edges — structurally precise on this fixed codebase,
but not type-resolved.

## 2. Path construction / decoding / normalization / root & symlink evidence

- **Decoding:** no URL/percent decoding exists anywhere in the dfetch path pipeline
  (detection.json `notObserved`); manifest YAML scalars reach the filesystem byte-for-byte.
  No multi-decode concern is modeled.
- **Construction:** `os.path.join(dst, …)` (metadata.py:129/:133, project/git.py:80,
  util.py:25/:95), string concatenation `src + "/" + file` (vcs/git.py:169) and f-strings
  (`f"{project.name}.patch"`, diff.py:114) — all preserve `..` components and absolute
  prefixes; `os.path.join` with an absolute right-hand operand discards the base entirely.
  Rendered as propagation (E10 / native), never as sanitization.
- **Normalization:** `realpath` at metadata.py:129/:132 and manifest.py:247/:270
  (normalization only), `PurePath(src).parts[0]` at vcs/git.py:170 (component EXTRACTION —
  a traversal amplifier: `src: ../x` yields `..`), `"/".join(...split(os.sep))` at svn.py:70
  (separator normalization for imported externals paths).
- **Allowed root:** none exists. The only scoping is process CWD (`in_directory` → chdir),
  which does not confine absolute or `..`-containing values (rendered as sink-083, and
  documented in phase1_review.md C7).
- **Symlinks:** no symlink-aware check exists; `shutil.rmtree` follows the tree as-is;
  `realpath` resolves links without any subsequent containment comparison. Recorded as
  "not applicable / unhandled" — no barrier rendered.
- **Access timing:** `exists → safe_rm` (vcs.py:103-105) and `exists(patch) → fromfile`
  (vcs.py:117-134) TOCTOU windows documented in Phase 1; not separately modelable as nodes.

## 3. Propagation modeling (MySummaries.qll)

TaintTracking::Global natively covers: call-argument → callee-parameter, local flow,
subscript/attribute reads of tainted values, and str method calls (decode/split/join).
Therefore most reviewed `summary` labels (internal wrapper params: `safe_rm`, `safe_rmtree`,
`in_directory`, `find_non_matching_files`, `hash_directory`, `hash_file`,
`Metadata.from_file`, `_dump_patch`, `checkout_version`, `SvnRepo._export`;
walk/listdir enumeration feeding them) need NO explicit step — they are realized by native
flow. Explicit steps are added only for the cross-object hops CodeQL cannot see:

| Step | Edge | Label basis & source evidence |
| --- | --- | --- |
| E1 | `yamldata[key]` (project.py:268) → reads of `.name`/`.destination`/`.source`/`.patch` in dfetch/** | src-033 + property getters project.py:326-343 (`name`/`destination`/`source`/`patch` return `_name`/`_dst`/`_src`/`_patch`). Needed for chains C1-C10 incl. the diff.py name→patch write (C9). |
| E2 | `kwargs.get("dst")` → `.destination` reads | src-028 + project.py:335-338. |
| E3 | `kwargs.get("src")` → `.source` reads | src-027 + project.py:331-333. |
| E4 | `kwargs.get("patch")` → `.patch` reads | src-029 + project.py:340-343 (read sites vcs.py:117-141). |
| E5 | `self.__project.destination` read (vcs.py:180) → `self.local_path` reads in dfetch/** | VCS.local_path getter vcs.py:177-180; enables project/git.py:70/:80, vcs.py:103-105, svn.py:191-221. |
| E6 | `self.__project.source` read (vcs.py:200) → `self.source` reads in dfetch/project/** | VCS.source getter vcs.py:197-200; enables project/git.py:77 and svn.py:192/:213. |
| E7 | `kwargs.get("destination")` (metadata.py:46) → `self._destination` reads (metadata.py:128-133) AND `.path` property reads (metadata.py:165, vcs.py:129/:188/:190/:232/:244, report.py:105) | src-025 + Metadata.path getter metadata.py:125-134. Read-site list is enumerated from the reviewed labels. |
| E8 | `GitLocalRepo.__init__` `path` parameter → `self._path` reads (vcs/git.py) | sink-013 + git.py:114-117 store, reads :121/:142/:178/:198/:285/:288 (in_directory/chdir and `.git` join consumers). |
| E9 | `pathlib.Path`/`PurePath` constructor argument → constructor result (project/git.py:70, project/svn.py:196, vcs/git.py:170) | sink-055/sink-060/sink-021 — makes the mkdir receivers (sink-054/sink-058) and the `.parts[0]` amplifier reachable regardless of stdlib model availability. |
| E10 | `os.path.join`/`dirname`/`realpath`/`basename` argument → result, at the reviewed dfetch sites only | sink-041…sink-053 summary rows (metadata.py:129/:131/:132/:133, vcs/git.py:162/:237, svn.py:70, project/git.py:80, util.py:25/:51/:95) — pure stdlib path semantics, mirrored so chains do not depend on pack model availability. |

**Deliberately NOT created** (would be fabricated propagation):
- No edge from the subprocess stdout sources (src-017/src-046) across the process/invocation
  boundary: `dfetch import` *writes* the manifest to disk (import_.py:130) and a separate
  `dfetch update` invocation re-parses it. That is two CLI runs, not one dataflow path.
  Consequence: src-017/src-046 are rendered as genuine boundaries but are expected to
  yield NO intra-run path to the Pass 1 sinks in Step 5; the exploit chain's second half
  is covered intra-run by the manifest sources. This is an honest modeling limit, recorded
  here rather than bridged with a fake edge.
- No `VCS.metadata_path` (vcs.py:188-190) hop: its consumers pass the path to
  `git log --` (vcs/git.py:179-184) — Pass 2 command-injection material, not a Pass 1 sink.
- No `Remote` property hops (url material — reviewed fp for this pass).
- `svn.py:207` listdir and `util.py:83` find_file rows are role `none`/fp — not rendered.

## 4. Expected query behavior (for Step 5 planning — not executed here)

Anticipated intra-run flow families, all starting at the manifest/metadata sources:
dst → E2/E5 → mkdir receivers (sink-054/058), rmtree (sink-079), os.remove (sink-076/062),
svn export dst (sink-064), chdir (sink-083), metadata write/read (sink-089/081) via E7;
src → E3 → subtree move (sink-020), PurePath amplifier → rmtree; patch → E4 →
fromfile (sink-094) and apply root (sink-095); name → E1 → patch write (sink-059);
hash read (sink-093) under a traversing dst. sink-015 cannot fire (literal argument).
sink-071 fires only along rmtree paths. No barrier suppresses any of these.

## 5. Diagnostics & known limitations (not part of the formal Pass 1 alert set)

- **Diagnostics:** none written (task contract: six files only). If wrapper debugging is
  needed before Step 5, a non-alert `@kind problem` query selecting the MySummaries edge
  endpoints (or `MySources::isSource` nodes alone) can be placed in `iris/diagnostics/`
  — such a query is explicitly NOT a Pass 1 alert and must not be run via
  `database analyze` into `iris/results/`.
- **Dynamic dispatch / alias limits:** `.stdout`/`.mkdir`/`.apply` matching is
  name-based (receiver identity cannot be proven syntactically); the enclosing-function
  and module guards pin every such row to its reviewed site, and no receiver-name
  collisions exist in this snapshot (detection.json matchKindSemantics).
- **CodeQL limits:** cross-object field flow is invisible (hence E1-E8); process CWD is
  invisible (child-manifest discovery under a traversed dst is anchored at chdir/mkdir
  instead); f-string/concatenation path building is anchored at the consuming sinks;
  patch-ng internals and git sparse-checkout pattern handling are outside the database;
  `run_on_cmdline` dst index 6 is call-site-dependent (documented in §1.2).
- **fp summary labels not rendered:** the 50 `none`/fp sink rows (stat probes,
  display-only relpath/dirname, walked/literal-path opens and moves, operator outfile)
  are intentionally absent from MySinks so they cannot generate alerts.

## 6. Experiment independence

- No PyVul ground truth, CVE publications, fix patches or known-vulnerability line
  numbers were consulted; the repo-root `CVE_APPLICATION_REPORT.md`,
  `PATH_TRAVERSAL_AUDIT_REPORT.md`, `GITHUB_PRIVATE_VULN_REPORT*.md` were never opened.
- No source file, CodeQL database, Augur file, or Phase 1 artifact (labels.json,
  labels_raw_pass1.json, CSVs) was modified; the only writes are the six Phase 2 Step 4
  files listed above.
- All QL uses the local modular API (`DataFlow::ConfigSig`,
  `TaintTracking::Global<Config>`, `PathGraph`, `flowPath`), no `module` variable name,
  no `AstNode.getFile()`, no deprecated `StrConst`/`Decorator` classes, no
  API::Node/DataFlow::Node mixing; predicates match the shapes already executed by the
  Phase 1 extraction queries on the same CLI 2.25.1 + codeql/python-all family.
- Per WORKFLOW §5.2.4 and the task contract: **no taint query was executed** (no
  `database analyze`, no SARIF, no results written); `--check-only` compilation is the
  only validation performed. Sequential execution belongs to Step 5.

## 7. Compile validation and API corrections (python-all 7.1.2, CLI 2.25.1)

The first `--check-only` compile failed with five distinct error classes; each fix was
verified against the installed pack source (`~/.codeql/packages/codeql/python-all/7.1.2`)
before re-applying, and the corrected files compile clean:

| # | Error | Root cause | Fix (verified against pack source) |
| --- | --- | --- | --- |
| 1 | `unexpected input 'MySources' expecting one of '('` at every `libraries.X::pred(...)` call | QL qualified names are `Module::member` with a single Upperid; dotted paths are only valid in `import` statements, never as `A.B::c` references | `import libraries.MySources` kept (resolves correctly); call sites changed to `MySources::isSource(...)`, `MySinks::isSink(...)`, `MySanitizers::isBarrier(...)`, `MySummaries::isAdditionalTaintStep(...)` |
| 2 | `getValue() cannot be resolved for type Exprs::StringLiteral` | python-all 7.1.2 has no `StringLiteral.getValue()`; the value accessor is `getText()` (Exprs.qll: `string getText() { result = this.getS() }`, used officially e.g. in `Call.getANamedArgumentName`) | all 10 key/literal comparisons changed from `.getValue()` to `.getText()` (manifest keys src/dst/patch/destination, the sparse-checkout literal, summary key matches) |
| 3 | `getEnclosingFunction() cannot be resolved for type Scope::Scope` | `Scope` in this pack exposes `getEnclosingScope()`/`getEnclosingModule()` only; but `Function extends Function_, Scope` and `AstNode.getScope()` returns the *innermost* enclosing scope, which IS the function for body expressions | `a.getScope().getEnclosingFunction().getName()` → `a.getScope().(Function).getName()` (submodules/externals stdout guards, `_export` dst guard) |
| 4 | `getKeywordArg(string) cannot be resolved for type Exprs::Call` | no such member; keyword arguments are accessed via `Call.getAKeyword()` returning `Keyword`, whose name/value are `Keyword.getArg()`/`getValue()` (Keyword_ in AstGenerated.qll) | `sink-095` apply-root match rewritten as `rootKw = c.getAKeyword() and rootKw.getArg() = "root" and sink.asExpr() = rootKw.getValue()` |
| 5 | `'modulePathPattern' is not bound to a value` | `string.matches(pattern)` does not bind its pattern argument, so the `inModule` body left the parameter unbound (same issue the Phase 1 extraction queries solved with `bindingset`) | `bindingset[modulePathPattern]` added to `inModule` in all three library files; every call site passes a string literal, satisfying the binding contract |

No semantic change resulted from any fix: source/sink/summary/barrier membership is
identical to the reviewed label rendering — only the API spellings and the module-name
qualification syntax were corrected. `Parameter` remains usable as a DataFlow expr
(parameters are Name/Tuple subtypes; E8 compares `p = nodeFrom.asExpr()` directly).
