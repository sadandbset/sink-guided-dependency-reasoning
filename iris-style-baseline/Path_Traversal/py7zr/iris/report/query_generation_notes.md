# Query Generation Notes — Augur Phase 2, Step 4–5 (Pass 1: Path Traversal)

Project: py7zr ~0.20.0+ unreleased (`py7zr_vuln` source tree, database creation sha `04e3af5a`)
Pass: 1 (CWE-022 / CWE-023 / CWE-036 / CWE-073) — pass key `path_traversal`
Generated: 2026-10-23
Inputs: `labels/labels.json` (reviewed Pass 1 labels, schema-valid, 191 entries), `labels/labels_raw_pass1.json`, `labels/label_stats.md`, `labels/phase1_review.md`, `assets/taint_query.ql.tmpl`, `references/python.md`, `references/patterns.md`, WORKFLOW.md Phase 2, and the real source under `py7zr_vuln/` re-read at every cited line.

Note on `labels/review_decision.json`: this optional audit artifact was not written in Step 3 (the Step 3 contract produced `phase1_review.md` as the review payload, with §9 requesting the approve/adjust decision). The reviewed input for this step is therefore `labels.json` + the review queue in `phase1_review.md`, and the decision to proceed to Phase 2 is the operator instruction initiating Step 4–5. Consistent with `phase1_review.md` §9's recommendation, entries with `classification=tp` are treated as the approved set and `candidate` entries are NOT promoted; no label was modified and no `review_decision.json` was fabricated.

## 1. Generated artifacts

| File | Content |
| --- | --- |
| `libraries/MySources.qll` | `module MySources { predicate isSource(DataFlow::Node, string passKey) }` — 10 tp source label rows (6 unique AST sites after moduleHint-twin collapse) |
| `libraries/MySinks.qll` | `module MySinks { predicate isSink(DataFlow::Node, string passKey) }` — 11 tp sink label rows (11 unique sites, 8 rules) |
| `libraries/MySanitizers.qll` | `module MySanitizers { predicate isBarrier(DataFlow::Node, string passKey) }` — 0 tp sanitizer labels; empty `none()` body with the full no-barrier justification |
| `libraries/MySummaries.qll` | `module MySummaries { predicate isAdditionalTaintStep(DataFlow::Node, DataFlow::Node, string passKey) }` — 12 tp summary label rows (11 unique sites, 5 label-backed rules) + 2 documented evidence-based interpolation edges |
| `queries/Pass1_PathTraversal.ql` | `Pass1Config implements DataFlow::ConfigSig` + `TaintTracking::Global<Pass1Config>` + `import Pass1Flow::PathGraph` + `flowPath(PathNode, PathNode)` path problem, id `py/augur/py7zr/pass1-path-traversal` |

Pack layout: `iris/qlpack.yml` (pack `iris/py7zr-cwe22`, dependency `codeql/python-all: "*"`, unchanged from Step 0). Libraries are imported with dotted syntax (`import libraries.MySources`) and referenced by module name (`MySources::isSource(source, "path_traversal")`) — the file-name/module-name convention proven on this pack family in the aiohttp round of this series (same CodeQL CLI 2.25.1 + python-all 7.1.x). ModuleHint-twin label rows (`py7zr` vs `py7zr.py7zr` bindings of the same AST node) are inherently collapsed here: every rule is anchored by file base name + line + node shape, which is binding-agnostic; no rule can double-match.

API surface used (verified against the locally installed `codeql/python-all 7.1.2` in earlier rounds of this series and identical to the aiohttp query set): `DataFlow::Node.asExpr()`, `DataFlow::ConfigSig` with 2-arg `isAdditionalFlowStep`, `TaintTracking::Global<Config>`, `module X::PathGraph` + `flowPath`, `Call.getFunc()`, `Call.getArg(int)`, `Attribute.getName()`, `Attribute.getObject()`, `Name.getId()`, `Subscript` (instanceof only), `AstNode.getLocation()`, `Location.getStartLine()`, `File.getBaseName()`. No deprecated or non-existent AST API is used; no variable is named `module`; `API::Node` is not mixed with `DataFlow::Node`; no `@kind problem`/multi-column shapes.

## 2. Label ID → QLL rule mapping

### 2.1 Sources (`MySources::isSource`, pass key `path_traversal`)

All modeled sources are archive **content** — the only genuinely untrusted boundary of this project (a library + local CLI; no HTTP surface). No internal wrapper parameter was promoted to a source.

| Label ID (conf) | Location | QL rule | Node shape | External input boundary / access conditions |
| --- | --- | --- | --- | --- |
| p1-src-001 (0.95) | archiveinfo.py:757 | `entryNameDecodeSource` | `Call` `read_utf16(buffer)` (result node) | 7z header PROPERTY.NAME block: `FilesInfo._read_name` decodes attacker-supplied UTF-16LE name bytes (read_utf16 defined at archiveinfo.py:192). Reachable by anyone who can supply a 7z to `SevenZipFile(..., "r")`, `unpack_7zarchive` (shutil.unpack_format hook), or the `py7zr x` CLI. No authentication/authorization applies — the archive is the input. |
| p1-src-002 (0.95) | archiveinfo.py:757 | `entryNameStoreSource` | `Subscript` `f["filename"]` (store target) | Same boundary, write-side anchor: the decoded name enters the file_info dicts that become `ArchiveFile` objects (py7zr.py:79-81; `.filename` property :111-113). Read-side recall is independently anchored by the next rule because the dict→ArchiveFile container crossing is not trackable by default (§6.1). |
| p1-src-023 / p1-src-024 (0.95, twins) | py7zr.py:561 | `entryNameReadSource` | `Attribute` `f.filename` (read) | THE read feeding the extraction pipeline: `outname = f.filename` in `SevenZipFile._extract`, then `remove_relative_path_marker` → `Path()`/`joinpath` → `register_filelike` → Worker sinks. Same access conditions as above. |
| p1-src-025 / p1-src-026 (0.90, twins) | py7zr.py:565 | `entryNameReadSource` | `Attribute` `f.filename` (read) | Duplicate-name branch `outname = f.filename + "_%d" % i` — the suffix is collision handling, not a guard; the name remains attacker-controlled. |
| p1-src-057 / p1-src-058 (0.95, twins) | py7zr.py:1333 | `linkTargetSource` | `Call` `ofp.read()` (result node) | Junction-target payload: decompressed bytes of a link member read out of an in-memory `io.BytesIO` (`self.decompress(..., ofp, ...)` at :1332); becomes `dst` of `_winapi.CreateJunction(str(fileish), dst)` at :1338 with no validation. Selected by the archive-supplied `is_junction` attribute (py7zr.py:184-191). |
| p1-src-059 / p1-src-060 (0.95, twins) | py7zr.py:1343 | `linkTargetSource` | `Call` `omfp.read()` (result node) | Symlink-target payload: same mechanism, becomes `sym_target` → `fileish.symlink_to(sym_target)` at :1347. Selected by the archive-supplied `is_symlink` attribute (py7zr.py:174-182). |

Rejected source candidates (NOT modeled, per the Step 3 review queue in `phase1_review.md` §5): all 33 `source/candidate` rows — CLI argv reads (`args.arcfile`/`args.odir`/`args.filenames`, `Cli.run` arg, `parse_args`), public API path params (`SevenZipFile.__init__` file, `_extract`/`extractall`/`extract` path, `writeall`/`write` path, `is_7zfile` file, `unpack_7zarchive` archive/path, `pack_7zarchive` base_name/base_dir). Rationale: local-operator / caller-authorized paths; an internal wrapper's path parameter is not a source merely to produce a path. Promoting them would fabricate flows the reviewed labels deliberately left pending.

### 2.2 Sinks (`MySinks::isSink`, pass key `path_traversal`)

Path text vs. file object: every modeled position carries **path text** (the path expression itself or the archive-payload target string). The only file-object channel in the labeled set, `fileish.open()`'s return `obfp` (py7zr.py:1349), is NOT a sink — the sink is the receiver path. The in-memory MemIO branch (`:1359`) touches no filesystem and is excluded.

| Label ID (conf) | Location | QL rule | Real file operation | Dangerous position (arg index / access type) and call relationship |
| --- | --- | --- | --- | --- |
| p1-sink-052 (0.90) | py7zr.py:625 | `extractDirectoryMkdirSink` | directory creation (`mkdir(parents=True)`) | receiver `target_dir` (path text). Collected at :612 from `outfilename` for entry directories; executed in `SevenZipFile._extract` after the (weak) relative_to guard. |
| p1-sink-055 (0.80) | py7zr.py:659 | `postExtractMetadataSink` | timestamp write (`os.utime(str(outfilename), times=...)`) | argument 0 (path text via `str()`). Post-extract loop over `target_files` (populated at :613/:622 from `outfilename`); times are archive-supplied `lastwritetime` (:655). |
| p1-sink-056 (0.80) | py7zr.py:663 | `postExtractMetadataSink` | permission change (`outfilename.chmod(st_mode)`) | receiver `outfilename` (path text). `st_mode` is archive-supplied `posix_mode` (:660-662); posix branch only. |
| p1-sink-057 (0.75) | py7zr.py:668 | `postExtractMetadataSink` | permission change (readonly-fallback `chmod`) | receiver `outfilename` (path text); mode from current `stat()` & ro_mask — path still entry-controlled. |
| p1-sink-101 (0.95) | py7zr.py:1328 | `workerParentMkdirSink` | directory creation (`fileish.parent.mkdir(parents=True, exist_ok=True)`) | receiver `fileish.parent` (path-text derivation; realized by `parentAttributeStep`, §2.4). `fileish = self.target_filepath.get(f.id)` (:1320) — the register_filelike carrier; runs inside `Worker._extract_single` for every extracted member, before the write. |
| p1-sink-103 (0.90) | py7zr.py:1336 | `preLinkUnlinkSink` | file deletion (`fileish.unlink()`) | receiver `fileish` (path text). Junction branch, after `fileish.exists()` — the exists/unlink pair is the TOCTOU window (`phase1_review.md` §6). |
| p1-sink-104 (0.95) | py7zr.py:1338 | `junctionCreationSink` | NTFS junction creation (`_winapi.CreateJunction(str(fileish), dst)`) | argument 0 (link path, via `str()`) **and** argument 1 (`dst`, raw payload target). Both positions are attacker-controlled per the reviewed label rationale; arg 1 carries the p1-src-057 flow directly, arg 0 the entry-name flow (via `str()`, §6.3). Windows-only branch. |
| p1-sink-107 (0.90) | py7zr.py:1346 | `preLinkUnlinkSink` | file deletion (`fileish.unlink()`) | receiver `fileish`. Symlink branch pre-collision clobber. |
| p1-sink-108 (0.95) | py7zr.py:1347 | `symlinkCreationSink` | symlink creation (`fileish.symlink_to(sym_target)`) | argument 0 (`sym_target`, archive-payload target, path text) **and** receiver `fileish` (entry-name link path) — both per the reviewed label rationale. |
| p1-sink-109 (0.97) | py7zr.py:1349 | `extractFileWriteSink` | file open for writing + decompressed payload write (`fileish.open(mode="wb")`, then `self.decompress(..., obfp, ...)`) | receiver `fileish` (path text — THE Zip-Slip write sink). Runs for every non-empty, non-link member. |
| p1-sink-110 (0.90) | py7zr.py:1357 | `emptyFileTouchSink` | empty-file creation (`fileish.touch()`) | receiver `fileish` (path text). Empty members only. |

Rejected sink candidates (NOT modeled): p1-sink-039 (`path.mkdir` :545 — caller-authorized output base, pending review), all write-side rows, all stat/probe rows, the MemIO `:1359` open, all archive-open rows (operator path; the untrusted content is carried by the sources, not the open path).

### 2.3 Barriers (`MySanitizers::isBarrier`, pass key `path_traversal`)

**Empty — 0 sanitizer labels survived review.** `isBarrier` resolves to `none()` (the mandatory empty hook, WORKFLOW.md §5.2.3). Justification per mechanism, verified in the real source:

| Guard examined | Location | Does it block traversal? | Why not a barrier |
| --- | --- | --- | --- |
| `relative_to` containment, path=None branch | py7zr.py:576-579 | **No** for `../` chains; **yes** only for absolute-path replacement | Lexical prefix check: CPython pathlib preserves `..` as literal parts — `Path(cwd).joinpath("../../../evil").relative_to(cwd)` returns `..\..\..\evil` without raising (verified on CPython 3.14.4, `phase1_review.md` §3). Reviewed label: role=none/fp. |
| `relative_to` containment, path branch | py7zr.py:583-586 | same | same — the main `Bad7zFile` guard; `..` segments pass unchanged. Reviewed label: role=none/fp. |
| `remove_relative_path_marker` | helpers.py:424-433 | **No** | Strips only one leading `./`; `..`/absolute/backslash all pass. Reviewed label: role=summary (taint-preserving). |
| `WindowsPath("\\\\?\\" + ...)` prefixing | py7zr.py:596-597 | **No** | Prefixes (does not reject) absolute outfilename; also a candidate summary, not promoted. |
| `'_%d'` duplicate suffixing | py7zr.py:562-568 | **No** | Name-collision handling, not a path guard (labeled source-side flow, §2.1). |
| `fileish.exists()` pre-checks | :1335/:1345 | **No** | Read-only TOCTOU probes preceding unlink/creation. |

No `resolve()`, `realpath()`, basename mapping, fixed-name mapping or whitelist exists anywhere between the decode (archiveinfo.py:757) and the file accesses (:625/:659/:663/:1328-:1357) — mechanically treating normpath/resolve/basename as safe filters is exactly what the reviewed labels reject. Consequence for the query: alert paths that "pass" the guards are expected findings, not false positives to be cut; Step 6 triage owns the final verdict.

### 2.4 Additional taint steps (`MySummaries::isAdditionalTaintStep`, pass key `path_traversal`)

Label-backed rules (site-anchored arg/receiver → result edges; no unconditional cross-function propagation):

| Label ID (conf) | Location | QL rule | Edge |
| --- | --- | --- | --- |
| p1-sink-001 (0.90) | archiveinfo.py:757 | `entryNameReplaceStep` | `read_utf16(buffer).replace("\\", "/")`: receiver (source p1-src-001) → result. The separator rewrite makes Windows-style `..\` traversal payloads effective posix `../` — taint-widening, never sanitizing. |
| p1-sink-044 / 046 / 048 (0.90) | py7zr.py:577 / :580 / :582 | `removeRelativePathMarkerStep` | `remove_relative_path_marker(outname)`: arg 0 → result. The `./`-stripping wrapper (helpers.py:424-433; def label p1-sink-026 is realized by standard interprocedural arg→param→return flow, so no separate def-site edge is emitted — the three call-site edges subsume it per the reviewed labels). |
| p1-sink-042 / 047 (0.90) | py7zr.py:577 / :582 | `joinPathStep` | `joinpath(remove_relative_path_marker(outname))`: arg 0 (the attacker name; receiver base is cwd/caller dir) → result. The traversal decision point — `..` segments survive joinpath semantics. |
| p1-sink-037 / 045 / 105 (0.60/0.90) | py7zr.py:542 / :580 / :1343 | `pathConstructorStep` | `pathlib.Path(x)`: arg 0 → result. `:580` carries the path=None entry-name branch; `:1343` carries the raw link-target payload into the symlink sink; `:542` is label fidelity only (no promoted source feeds the caller-side str path). |
| p1-sink-119 / 120 (0.90, twins) | py7zr.py:619 / :621 → :1320 | `registerFilelikeStep` | `register_filelike(f.id, outfilename)` arg 1 → `self.target_filepath.get(f.id, None)` at :1320. The reviewed label marks the register_filelike **definition** (param `fileish`, py7zr.py:1500); the edge is realized at the two call sites that carry real path text (:619 link/junction, :621 regular) — the `:599` (None) and `:609` (MemIO) registrations carry none. This is the dict-store → dynamic-load carrier global taint cannot see; without it no Worker sink can fire. |

Interpolated edges (NOT label rows — `.decode`/`.parent` were below the Phase 1 extraction granularity, i.e. no candidate rows were ever emitted for them, so this is not a review omission; they are added with real-code evidence to realize the reviewed source→sink chains, in the same site-anchored style):

| Edge | Location | QL rule | Evidence |
| --- | --- | --- | --- |
| `fileish` → `fileish.parent` | py7zr.py:1328 | `parentAttributeStep` | pathlib `.parent` is a pure path-text derivation; the reviewed sink p1-sink-101 models the mkdir with receiver `fileish.parent`, and the attribute read is not a default taint step (pathlib not in the database). |
| `ofp.read()` / `omfp.read()` → `.decode("utf-8")` result | py7zr.py:1333 / :1343 | `linkTargetDecodeStep` | `str.decode` is value-preserving; connects the labeled sources p1-src-057/059 to the labeled sinks p1-sink-104 (arg 1) and, via `pathConstructorStep`, p1-sink-108 (arg 0). |

Not promoted (candidate summaries): `WindowsPath("\\\\?\\" + ...)` (py7zr.py:597), `helpers.py:299 Path(res)`, `win32compat.py:198 WindowsPath(rpath)`.

## 3. Evidence for the path pipeline (join / decode / canonicalize / base directory / symlinks / timing)

Verified line-by-line in the real source (`py7zr/archiveinfo.py`, `py7zr/py7zr.py`, `py7zr/helpers.py`):

1. **Decode/normalization order**: entry name is decoded once at `archiveinfo.py:757` (`read_utf16(buffer).replace("\\", "/")` — UTF-16 decode plus backslash→slash rewrite at the boundary); afterwards only `remove_relative_path_marker` (one leading `./`) touches the string before the join. There is **no second decode**, no URL unquoting, no `normpath`, no `resolve`, no `realpath`, no canonicalization anywhere on the entry-name path.
2. **Join**: `pathlib.Path(os.getcwd()).joinpath(name)` (:577, path=None branch) / `path.joinpath(name)` (:582, path branch) / `pathlib.Path(name)` (:580, path=None branch, relative path resolved against cwd at open time). pathlib joinpath keeps `..` parts and replaces the base for an absolute argument.
3. **Allowed root**: the declared base is `os.getcwd()` (path=None: `extractall()` with no path, `read()`, `readall()`) or the caller-supplied `path` (extractall/extract/CLI `args.odir`). Both bases are compared against the **non-canonical** joined path, so the comparison is lexical.
4. **Absolute paths**: caught by the relative_to guards **only** when the joined path's leading parts differ from the base (absolute replacement or a different drive) → `ValueError` → `Bad7zFile` (py7zr.py:578-579/:585-586). Windows `\\?\` long-path prefixing at :596-597 happens only for the surviving absolute `outfilename` (base-absolute paths).
5. **`..` traversal**: survives both guards (lexical prefix check; verified empirically on CPython 3.14.4 stdlib during Step 3) and is resolved by the OS at `mkdir`/`open`/`unlink`/`touch`/`symlink_to`/`CreateJunction` time — i.e., the file access itself performs the escape.
6. **Symlinks/junctions**: the archive-supplied `is_symlink`/`is_junction` attributes (py7zr.py:174-191) route members to link creation. The link **location** (`fileish`) goes through the same weakly-guarded pipeline; the link **target** (`dst`/`sym_target`, raw payload at :1333/:1343) has **no check at all** — the relative_to guards never see it. A pre-existing file at the link location is `unlink()`ed first (:1335-1336/:1345-1346; TOCTOU window between `exists()` and creation). The created link can then pivot later writes (the classic symlink-following escalation, CWE-23/36 shapes).
7. **File-access timing**: guard order is decode (:757) → duplicate-name suffix (:560-568) → rpm + join + relative_to (:576-586) → register_filelike (:619/:621) → target_dirs mkdir (:623-632) → Worker: parent mkdir (:1328) → link unlink (:1335/:1345) → junction/symlink creation (:1338/:1347) or `open("wb")` write (:1349) / `touch` (:1357) → post-extract `utime`/`chmod` (:651-668). TOCTOU windows exist at exists→mkdir (:543-552, :610-615) and exists→unlink→create (:1335-1338, :1345-1347); recorded as residual risks, not modeling inputs.
8. **`str()` coercions** on entry-controlled paths before file APIs: `os.utime(str(outfilename))` (:659), `CreateJunction(str(fileish), dst)` (:1338) — builtin coercion, taint-preserving in reality (CodeQL modeling caveat §6.3).

## 4. Expected query behavior (prediction, not execution — no analysis was run)

Dominant expected path-problems, if executed:

- **Zip-Slip write**: p1-src-023 (`f.filename`, :561) → `outname` → `removeRelativePathMarkerStep` (:577/:582 or :580) → `joinPathStep`/`pathConstructorStep` → `outfilename` → `registerFilelikeStep` (:619/:621 → :1320) → `fileish` → p1-sink-109 (`open("wb")` :1349), p1-sink-110 (`touch` :1357), p1-sink-103/107 (`unlink` :1336/:1346), p1-sink-101 (`fileish.parent.mkdir` :1328 via `parentAttributeStep`), p1-sink-104 arg 0 (junction link path, via `str()`, §6.3), p1-sink-108 receiver (symlink location), p1-sink-052/055/056/057 (dir mkdir / utime / chmod, §6.2/§6.3 permitting).
- **Link-target channel**: p1-src-057 (`ofp.read()` :1333) → `linkTargetDecodeStep` → p1-sink-104 arg 1 (`CreateJunction` target); p1-src-059 (`omfp.read()` :1343) → `linkTargetDecodeStep` → `pathConstructorStep` (:1343) → p1-sink-108 arg 0 (`symlink_to` target).
- **Dead-ends by design**: the :757 sources flow through `entryNameReplaceStep` into the dict store and stop at the dict→ArchiveFile container crossing (§6.1) — recall is preserved by the read-side anchors p1-src-023/025. The :565 duplicate-branch source additionally depends on BinOp string-concat modeling (§6.4).

Because no barrier is modeled (§2.3), the surviving guard check cannot cut these paths; the alerts are the expected Step 6 input.

## 5. Diagnostics paths (not formal Pass 1 alerts)

No diagnostics query was generated (the task contract allows only the six artifacts). If wrapper debugging is wanted later, it belongs in separate `*.ql`/`*.bqrs` count queries under `iris/diagnostics/` (directory exists, empty), e.g.: per-sub-predicate match counts (`select count(...) over MySources::isSource(...)`), a check that `registerFilelikeStep`'s `from`/`to` nodes both bind, and a check whether `str()`-coerced sink positions and the `target_dirs.append → for target_dir` container hop are modeled by the local python-all build (§6.2/§6.3). None of these counts as a Pass 1 alert.

## 6. CodeQL limitations and known gaps (documented, not silently patched)

1. **Dict → ArchiveFile container crossing**: `f["filename"] = ...` (archiveinfo.py:757) → `ArchiveFile._file_info` (py7zr.py:79-81) → `.filename` property (:111-113) → `f.filename` (:561) is not a default global-taint step. Mitigated by anchoring sources at BOTH ends (p1-src-001/002 write-side, p1-src-023/025 read-side); the middle is intentionally not modeled (no arbitrary propagation).
2. **List container hop for p1-sink-052**: `target_dirs.append(outfilename)` (:612-613) → `for target_dir in sorted(target_dirs)` (:623) depends on the standard library's list append→iteration modeling. If the local python-all build does not model it, the :625 mkdir sink will not fire; the Worker-side mkdir (:1328) covers the same taint via `registerFilelikeStep`. A label change is NOT warranted (the label marks the sink itself; the container hop is standard-modeling territory) — check via §5 diagnostics.
3. **`str()` coercions**: sink positions `os.utime(str(outfilename))` (:659, arg 0) and `CreateJunction(str(fileish), dst)` (:1338, arg 0) fire only if the builtin `str()` is modeled as taint-preserving. The neighboring positions (chmod receivers :663/:668; CreateJunction arg 1; symlink_to arg 0/receiver; all `fileish` receivers) do not depend on it, so alert coverage of both flows is robust either way.
4. **BinOp string concatenation** at :565 (`f.filename + "_%d" % i`): if not modeled, only the :561 branch of the entry-name flow alerts (duplicate-name archives only).
5. **Dynamic dispatch**: every `fileish`/`outfilename`/`target_dir` member call is resolved by line-anchored matchers, not by type — MemIO/NullIO duck-typed stubs (helpers.py:307-383) cannot collide because their `open/mkdir/parent/touch` definitions contain no call sites and no rule matches definitions. The `os.stat`/`os.utime`/`os.path` name collisions elsewhere in the tree cannot fire (line-anchored).
6. **Control-flow guards**: `isBarrier` cannot express "`relative_to` raising Bad7zFile kills the flow" — and per §2.3 it must not, because the guard does not reject `..`. The guard's real protection (absolute-path replacement) is control-flow, not node-level; this is the designed Step 6 triage point, not a modeling error.
7. **External boundary**: `pathlib`, `os`, `io`, `_winapi`, `multivolumefile` are not part of the database; the summaries in §2.4 are the minimum site-anchored edges needed at that boundary. `_winapi` is conditionally imported (py7zr.py:60-61) and the junction branch is win32-gated — the query matches statically regardless of platform branch evaluation (documented in detection.json uncoveredCases).
8. **Worker concurrency**: `Worker.extract` may run `extract_single` in `Thread`s/`Process`es (py7zr.py:1240-1259); the taint model is call-site anchored (register_filelike call → get load), so it is unaffected by the concurrency mechanism.
9. **The `mp`/parallel re-open** at py7zr.py:1239 (`open(filename, "rb")`) uses the archive's own operator path — not a sink, per the reviewed labels.

## 7. Label adequacy check (Step 4 gate)

No reviewed-label omissions were found that would require returning to Step 3 for re-review: every `tp` label row is implemented (33/33: 10 source rows → 6 unique sites / 4 rules; 11 sink rows → 11 sites / 8 rules; 12 summary rows → 11 unique sites / 5 label-backed rules); every `candidate`/`fp` label is deliberately excluded with the per-entry rationale preserved in `labels_raw_pass1.json` and `phase1_review.md`. The two interpolated edges in §2.4 (`parentAttributeStep`, `linkTargetDecodeStep`) are not label omissions — `.decode`/`.parent` were never extraction candidates (below the Phase 1 extraction granularity, recorded in detection.json's pure-path-predicate exclusions) — so they are added here as evidence-based realizations of already-reviewed source→sink chains, and `labels.json` was not modified. No return to the labeling review step is needed.

## 8. Experiment independence

No PyVul ground truth (`VULNERABILITY_AUDIT_REPORT.md`, `path_traversal_*.{csv,md}` at the `py7zr_vuln` repo root), no CVE advisory, no known-vulnerability line numbers, and no fix patches were consulted at any point; all modeling derives from the reviewed Pass 1 labels and direct reading of the `py7zr_vuln` source. The source tree, the CodeQL database, the Augur installation, and the Phase 1 labels/CSVs were not modified. Only the six contracted artifacts were written (`libraries/MySources.qll`, `libraries/MySinks.qll`, `libraries/MySanitizers.qll`, `libraries/MySummaries.qll`, `queries/Pass1_PathTraversal.ql`, `report/query_generation_notes.md`; the pre-existing `qlpack.yml` at the iris root is unchanged). Per the task contract, no compilation or formal analysis was executed in this step — `codeql pack install` / query compile / `database analyze` belong to Step 5's execution round and were deferred.
