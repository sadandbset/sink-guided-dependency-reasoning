# Pass 1 (Path Traversal) — Phase 1 Step 3 LLM Labeling Review

Human-review-gate payload (Augur WORKFLOW.md §4.5). Advisory checkpoint: this file
records the labeling outcome and the judgment calls a reviewer should confirm before
Phase 2 (library + taint query generation) consumes `labels.json`.

- Project: py7zr (~0.20.0+ unreleased, `py7zr_vuln` source tree, database creation sha `04e3af5a`)
- Pass: 1 — Path Traversal (CWE-022 / CWE-023 / CWE-036 / CWE-073)
- Model: glm-5.3 (Claude Code CLI agent, single session, in-session labeling; no external LLM API)
- Generated: 2026-10-23 (see `labels.json` metadata.generated_at for the exact timestamp)
- Candidates: 66 source rows + 125 sink rows = **191**, all labeled, 0 skipped, 0 merged or dropped
- Batches: 6 code-region batches (B1 archiveinfo 3; B2 CLI/dev-tools 27; B3 SevenZipFile read/extract pipeline 73; B4 Worker extraction core 38; B5 write-side/metadata 35; B6 compat helpers 15)
- Schema: `labels.json` validates against `assets/labels_schema.json` (jsonschema 4.26.0, Draft 2020-12, 0 errors)

## 1. Label counts

| role | tp | candidate | fp | total |
| --- | --- | --- | --- | --- |
| source | 10 | 33 | — | 43 |
| sink | 11 | 1 | — | 12 |
| sanitizer | 0 | 0 | — | 0 |
| summary | 12 | 3 | — | 15 |
| none | — | — | 121 | 121 |

Every sink-heavy code region that the archive-entry flow reaches has at least one
confirmed sink (`tp`), so the "at least one sink per enabled pass" quality check is
satisfied with margin.

## 2. Top high-risk sinks (confirmed, entry-name-fed)

The dominant attack surface is the archive extraction pipeline. The full confirmed
Zip-Slip chain (every hop verifiable in the real source):

1. **Source** `archiveinfo.py:757` — `f['filename'] = read_utf16(buffer).replace('\\', '/')`
   decodes attacker-controlled UTF-16LE entry names from the 7z header and rewrites
   backslashes to forward slashes (a Windows-style `..\..\evil` payload becomes an
   effective `../../evil` on every platform).
2. **Propagation** `py7zr.py:561` `outname = f.filename` → `remove_relative_path_marker`
   (`helpers.py:424-433`, strips only one leading `./`) → `py7zr.py:580/:582`
   `pathlib.Path(...)` / `path.joinpath(...)` (labeled summary steps).
3. **Guard (ineffective)** `py7zr.py:577/:584` `relative_to` containment checks — see §3.
4. **Propagation** `py7zr.py:619/:621` → `Worker.register_filelike` (`py7zr.py:1500`,
   dict store into `target_filepath`) → `fileish = self.target_filepath.get(f.id)`
   (`py7zr.py:1320`) — the dict/dynamic-dispatch edge CodeQL cannot see without the
   labeled summary step.
5. **Sinks** (all confirmed `tp`):
   - `py7zr.py:1349` `fileish.open(mode='wb')` + `decompress` — **the arbitrary-file-write sink** (conf 0.97)
   - `py7zr.py:1328` `fileish.parent.mkdir(parents=True, exist_ok=True)` — directory creation (conf 0.95)
   - `py7zr.py:625` `target_dir.mkdir(parents=True)` — entry-directory creation (conf 0.90)
   - `py7zr.py:1347` `fileish.symlink_to(sym_target)` — arbitrary symlink creation; **both** link path and target are archive-controlled, target is raw payload (`:1343`) with no validation (conf 0.95)
   - `py7zr.py:1338` `_winapi.CreateJunction(str(fileish), dst)` — arbitrary junction creation; `dst` is raw payload (`:1333`), unvalidated (conf 0.95)
   - `py7zr.py:1336/:1346` `fileish.unlink()` — pre-collision deletion at the entry-controlled path (conf 0.90)
   - `py7zr.py:1357` `fileish.touch()` — empty-file creation (conf 0.90)
   - `py7zr.py:659` `os.utime(str(outfilename))` and `:663/:668` `chmod` — post-extract metadata on entry-controlled paths; `posix_mode` and `lastwritetime` are archive-supplied (conf 0.75–0.80)

**Secondary untrusted channel (link targets, CWE-23/36):** `py7zr.py:1333` `ofp.read()`
and `:1343` `omfp.read()` (labeled source/tp, conf 0.95) are decompressed archive
payload strings that become junction/symlink targets with **no validation at all** —
not even the (weak) `relative_to` check applies to them, since the check only guards
the link's own path, not its target. An absolute target escapes any base by design.

## 3. Key judgment call: the `relative_to` guards are NOT sanitizers

Both containment checks were labeled `none` (not `sanitizer`) — **this is the decision
most worth human scrutiny**, because labeling them sanitizers would make `isBarrier`
sever the main flow in Phase 2.

Code (`py7zr.py:576-586`):

```python
try:
    pathlib.Path(os.getcwd()).joinpath(remove_relative_path_marker(outname)).relative_to(os.getcwd())
except ValueError:
    raise Bad7zFile
outfilename = pathlib.Path(remove_relative_path_marker(outname))
...
outfilename = path.joinpath(remove_relative_path_marker(outname))
try:
    outfilename.relative_to(path)
except ValueError:
    raise Bad7zFile
```

Analysis (verified empirically against the CPython 3.14.4 stdlib — project code was
not executed, only stdlib semantics probed):

- pathlib **preserves `..` as a literal path part** (`PurePosixPath('/a/../b').parts == ('/', 'a', '..', 'b')`) and never canonicalizes it.
- `Path(cwd).joinpath('../../../evil').relative_to(cwd)` returns `..\..\..\evil` **without raising** — the parts prefix `('C:\\', 'cwd')` matches and the `..` remainder is simply returned. Both guards therefore **pass `../`-traversal entry names**.
- `joinpath` with an **absolute** argument replaces the base, and `relative_to` then raises `ValueError` → `Bad7zFile`; a different drive letter (`D:/x` vs `C:/out`) is likewise caught. So the guards block absolute-path replacement only.
- `remove_relative_path_marker` (`helpers.py:424-433`) strips only one leading `./`; it does not reject `..`, embedded separators, or absolute names.

Conclusion: in this source tree the declared base directory (cwd or caller `path`) can
be escaped with `../` segments in archive entry names, and the extraction write at
`py7zr.py:1349` lands outside it. No other guard exists on the path between decode and
file access (no `resolve()`, no `realpath`, no basename mapping, no `..` rejection).

Sanitizer list is therefore **empty**; `MySanitizers.qll` in Phase 2 should render an
empty `isBarrier` (the `none()` fallback), preserving recall of the flow above.

## 4. Source trust model (why so many `candidate` and so few confirmed sources)

py7zr is a **library plus an argparse CLI** — there is no HTTP/routing/request surface
at all (detection.json framework.selected = none). The genuinely untrusted boundary is
the **archive content**, which yields the 10 confirmed `source/tp` rows:

- `archiveinfo.py:757` (entry-name decode, 2 rows: call + dict store),
- `py7zr.py:561/:565` (outname assignment + duplicate-name branch, 4 rows),
- `py7zr.py:1333/:1343` (link/junction target payloads, 4 rows).

The 33 `source/candidate` rows are the CLI argv reads and public-API `path`/`file`
parameters. Rationale: an internal function parameter is not automatically a source —
the caller/operator authorized these locations — but embedding applications (notably
`unpack_7zarchive`, the `shutil.register_unpack_format()` hook where
`shutil.unpack_archive()` forwards caller paths straight into py7zr) can carry
user-influenced values into them. They are deliberately kept low-confidence
(`0.45–0.60`) and routed to the human-review queue rather than asserted as `tp`.

## 5. Human-review queue (37 entries)

All have `classification = candidate` (no `unknown` remained; nothing was left
unresolved that source reading could settle). Grouped:

| group | entries | question for the reviewer |
| --- | --- | --- |
| `unpack_7zarchive` / `pack_7zarchive` params (8 rows: py7zr.py:1167 ×4, :1176 ×4) | conf 0.45–0.60 | Treat the `shutil` hook params as trusted library boundaries (→ none/fp) or as service-style external sources (→ source/tp)? Recommended: keep candidate; the hook is the most realistic externally-reachable entry. |
| CLI argv boundary (11 rows: cli.py:95, 96, 200, 297, 322, 355, 356, 390, 391, 434, 435) | conf 0.45–0.55 | Local-operator trust by design; keep candidate for forwarded-args embedding scenarios or downgrade to none/fp. |
| Public API params (14 rows: py7zr.py:320, 526, 974, 986, 1012, 1023, 1144 ×2 each) | conf 0.45–0.55 | Library-callers-are-trusted convention vs. conservative recall for embedding apps. |
| `py7zr.py:545` `path.mkdir(parents=True)` (sink/candidate, conf 0.60) | 1 | Confirmed FS mutation but caller-authorized base; keep candidate or promote to tp if param sources above are promoted. |
| write-side / compat str→Path conversions (helpers.py:299, py7zr.py:597 WindowsPath, win32compat.py:198) | conf 0.40–0.50 | Summary steps on flows that are fp in-tree; harmless to keep, droppable for noise reduction. |

## 6. Residual risks and notes recorded during labeling

- **TOCTOU windows** (documented, not separately labeled): `path.exists()` → `path.mkdir()` (`py7zr.py:543-552`), `target_dir` collect-then-mkdir (`:623-632`), and `fileish.exists()` → `fileish.unlink()` → link creation (`:1335-1338`, `:1345-1347`).
- **`\\?\` long-path prefixing** (`py7zr.py:596-597`): prefixes rather than rejects absolute `outfilename` (only reachable after the guard passed, i.e. base-absolute paths); labeled summary/candidate.
- **Archive-supplied metadata**: `posix_mode` → `chmod` (`:663`), `lastwritetime` → `utime` (`:659`); attacker influences bits/times on entry-controlled paths.
- **MemIO branch is clean**: `read()`/`readall()` dict mode routes `fileish` to the in-memory `MemIO` stub — no filesystem access (`:1359` labeled none/fp).
- **Parallel branch**: `Worker.extract` re-opens the archive by its own operator path (`:1239`), not by entry names; `mp=True` uses `multiprocessing.Process` — same path decisions as the threaded path.
- **`multivolumefile`** is an external dependency outside the database; its internal file operations are invisible to this analysis (documented in detection.json uncoveredCases).
- **win32compat block** is gated on `sys.platform == 'win32'`; rows are extracted statically and labeled on their cross-platform merits.
- **moduleHint twins**: 32 candidate pairs (26 source + 6 sink) are the same AST node matched under two module bindings (`py7zr` / `py7zr.py7zr`); both rows were labeled identically and retained for 1:1 CSV auditability. **Phase 2 signature rendering must dedup module-agnostically** or the generated libraries will double-match.
- **matchKind**: all rows are `ast` (syntax-level); no API-graph resolution was possible (pathlib/os/_winapi are not in the database).

## 7. Exclusions summary (role=none, classification=fp — 121 rows)

- CLI/dev-tool operator paths (cli.py Path/exists/is_dir/stat/open rows, utils/bench_result.py:50) — local operator, self-directed usage.
- Write-side walker/metadata rows (py7zr.py:722-731, 826-898, 1015-1026, 1417-1432, 1460) — operator-supplied paths being archived; no untrusted input on the write side.
- Operator archive-open family (py7zr.py:344-364, 1155/:1158, 1239, 1288; cli.py:301) — the untrusted data is the archive *content*, whose sources are labeled separately.
- Comparison-only `targets` params (py7zr.py:527/:982/:986) — membership filter, never a path.
- Display/progress/exception-message-only entry-name reads (py7zr.py:560, 598, 926, 959, 1316, 1353, 1362, 1375; cli.py:274).
- Read-only stat/probe/TOCTOU rows and the readlink compat family (helpers.py, win32compat.py).
- The two `relative_to` containment rows (py7zr.py:577/:584) — checks exist but are lexically ineffective against `..` (§3); labeled none specifically to avoid severing the real flow as a barrier.

## 8. Constraints honored

- No PyVul ground truth was consulted: `VULNERABILITY_AUDIT_REPORT.md` and the
  `path_traversal_*.{csv,md}` files at the `py7zr_vuln` repo root were not opened; no
  patch diffs, no CVE advisories. Labels derive only from repository evidence and the
  loaded Augur references (`WORKFLOW.md`, `references/python.md`, `references/patterns.md`,
  `assets/labels_schema.json`; no framework reference matched this tree).
- The stdlib semantics check in §3 executed only CPython stdlib calls (`pathlib`,
  `os.getcwd`) — no project code, no CodeQL, no database commands were run.
- Nothing outside `iris/labels/` was modified: source tree, CodeQL database, Augur
  installation, and the Phase 1 CSVs are untouched.

## 9. Requested decision

Approve `labels.json` for Phase 2 as-is (recommended: the entry-name/link-target chain
and the guard-ineffectiveness judgment in §3 are the load-bearing findings), or adjust:
(a) promote/demote the param-family source candidates (§5), (b) re-classify the
`relative_to` rows if a reviewer judges the lexical-prefix behavior differently.
