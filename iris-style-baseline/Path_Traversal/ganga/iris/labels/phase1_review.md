# Augur Phase 1 Step 3 — Phase 1 Review (ganga, Pass 1: Path Traversal)

**Checkpoint artifact (WORKFLOW.md 4.5). This run stops here: no Phase 2 libraries,
queries, execution or reports were generated.**

- Run: `iris-ganga-pathtraversal-pass1-20261022` — model `glm-5.3 (Claude Code CLI harness)`, 13 batches, 111 source rows (102 unique after removing 9 exact duplicates) and
  907 sink rows (900 unique after 7 removals) labeled; schema-validated against `assets/labels_schema.json`.
- Grounding: every tp/fp decision on the GangaGUI surface, the Persistency export/load chains,
  GPIFunctions, Runtime.getScriptPath, files.py, Sandbox/WNSandbox, GaudiExecMerger and job_tools
  was made by direct reading of the cited code in `ganga_vuln` (Ganga 8.4.2, db sha `0c0f9e33`);
  core/plugin family verdicts rest on module-role analysis with spot-reads of representative
  sites plus the Step-1 first-hand exploration inventory (detection.json).

## 1. What is confirmed vulnerable (classification=tp, 27 entries)

### Chain A — CWE-22 arbitrary file read + directory listing via the job browser

| # | ID | Location | Role | Conf. | Step |
| --- | --- | --- | --- | --- | --- |
| 1 | src-065 | `GangaGUI/gui/routes.py:639` | source/tp | 0.95 | `path` param of `/job/<int:job_id>/browse/<path:path>` — Flask path converter, URL-decoded, `..`/`/` allowed; @login_required bounds the attacker population, not the value |
| 2 | sink-778 | `gui/routes.py:659` | summary/tp | 0.90 | `abs_path = os.path.join(job_base_dir, path)` — join keeps `..` lexically; absolute value replaces the base; base itself is repository content (:651) |
| 3 | sink-780 | `gui/routes.py:665` | sink/tp | 0.60 | `os.path.exists(abs_path)` — OS-level existence oracle, gate |
| 4 | sink-781 | `gui/routes.py:670` | sink/tp | 0.70 | `os.path.isfile(abs_path)` — file-type oracle, branch selector |
| 5 | sink-782 | `gui/routes.py:671` | sink/tp | **0.95** | **`send_file(abs_path)` — PRIMARY arbitrary file read** |
| 6 | sink-783 | `gui/routes.py:676` | sink/tp | 0.90 | `os.listdir(abs_path)` — directory listing disclosure |

No resolve/realpath, no `..` rejection, no base-dir containment anywhere in the flow.

### Chain B — CWE-22 arbitrary file read + listing via the storage browser

| # | ID | Location | Role | Conf. | Step |
| --- | --- | --- | --- | --- | --- |
| 1 | src-069 | `GangaGUI/gui/routes.py:925` | source/tp | 0.95 | `path` param of `/storage/<path:path>` (GET+POST) |
| 2 | sink-797 | `gui/routes.py:934` | summary/tp | 0.90 | `abs_path = os.path.join(STORAGE_FOLDER, path)` — unchecked join |
| 3 | sink-803 | `gui/routes.py:969` | sink/tp | 0.60 | `exists` oracle/gate |
| 4 | sink-804 | `gui/routes.py:974` | sink/tp | 0.70 | `isfile` gate |
| 5 | sink-805 | `gui/routes.py:975` | sink/tp | **0.95** | **`send_file(abs_path)` — PRIMARY arbitrary file read** |
| 6 | sink-806 | `gui/routes.py:980` | sink/tp | 0.90 | `listdir` listing disclosure |

### Chain C — CWE-22 arbitrary file WRITE via the storage upload (POST branch)

| # | ID | Location | Role | Conf. | Step |
| --- | --- | --- | --- | --- | --- |
| 1 | src-070 | `gui/routes.py:941` | source/tp | 0.85 | `request.files['storagefile']` — upload boundary |
| 2 | src-072 | `gui/routes.py:953` | source/tp | 0.80 | `.filename` read — feeds secure_filename (its own component is sanitized; kept as the anchor for Phase 2 modeling) |
| 3 | sink-797 | `gui/routes.py:934` | summary/tp | 0.90 | route path → `abs_path` (the DIRECTORY component is never sanitized) |
| 4 | sink-799 | `gui/routes.py:953` | **sanitizer/tp** | 0.90 | `secure_filename(filename)` — neutralizes the filename component ONLY; emit as isBarrier on this call node only |
| 5 | sink-798 | `gui/routes.py:949` | sink/tp | 0.60 | `isdir(abs_path)` — upload gate, stat oracle |
| 6 | sink-800 | `gui/routes.py:954` | summary/tp | 0.85 | `save_path = join(abs_path, filename)` — tainted arg 0 |
| 7 | sink-801 | `gui/routes.py:955` | sink/tp | **0.90** | **`storagefile.save(save_path)` — PRIMARY arbitrary file write** (e.g. `POST /storage/../../` with a multipart file escapes `gangadir/gui/storage`) |

### Chain D — CWE-22 arbitrary file write/read via the unauthenticated internal API

| # | ID | Location | Role | Conf. | Step |
| --- | --- | --- | --- | --- | --- |
| 1 | src-016 | `GangaGUI/api/routes.py:223` | source/tp | 0.90 | `save_path = request.args.get('path')` of `/internal/jobs/<id>/export` — no auth on any internal route, localhost bind (start.py:99/:109); reachable by any local process and by drive-by cross-origin GETs |
| 2 | sink-490 | `GangaCore/GPIDev/Persistency/__init__.py:35` | summary/tp | 0.90 | GPI `export(item, filename, mode)` |
| 3 | sink-491 | `Persistency/__init__.py:41` | summary/tp | 0.90 | `stripped_export` — filename → `fullpath` → open |
| 4 | sink-493 | `Persistency/__init__.py:140` | summary/tp | 0.85 | `fullpath` = abspath/expandvars/expanduser — normalizes `..` WITHOUT containment |
| 5 | sink-492 | `Persistency/__init__.py:85` | sink/tp | **0.90** | **`open(filepath, mode)` — arbitrary file WRITE** |
| 6 | src-045 | `api/routes.py:977` | source/tp | 0.90 | `path = request.args.get('path')` of `/internal/load` |
| 7 | sink-494 | `Persistency/__init__.py:154` | summary/tp | 0.90 | GPI `load(filename)` |
| 8 | sink-396 | `GangaCore/Utility/Runtime.py:28` | summary/tp | 0.85 | `getScriptPath` — returns the expanded name verbatim when it exists |
| 9 | sink-495 | `Persistency/__init__.py:190` | sink/tp | **0.90** | **`open(filepath)` — arbitrary file READ** (content then eval'd at :209 — Pass 4 carry-over) |

## 2. Sanitizers

- **Confirmed (tp): `secure_filename`** (`gui/routes.py:953`) — werkzeug name sanitizer; concrete
  neutralization of the uploaded FILENAME (path separators, `..`, absolute names). PARTIAL: the
  DIRECTORY component of the upload destination (route path via joins :934/:954) is untouched,
  which is exactly where the confirmed write traversal flows. Phase 2: isBarrier on the
  `secure_filename` **call node only** — it cannot suppress the confirmed finding because the
  tainted directory component never passes through it.
- **Rejected (fp): `allowed_file`** (`gui/routes.py:1799`) — extension allowlist (`txt`/`py`),
  applied only to the loadfile/runfile channels whose save paths are fixed; constrains extension,
  never path components. Must not be rendered as a barrier.
- **Nothing else qualifies**: no `resolve()`/`realpath` + containment, no `startswith(base)` check,
  no `relative_to` on resolved paths, no explicit `..` rejection, no basename extraction exists on
  any confirmed chain (verified by reading the full handlers). Symlinks: none created or followed
  on the chains; not applicable (recorded as not observed).

## 3. Rejected candidate families (rationale summary)

| Family | Rows | Verdict |
| --- | --- | --- |
| `os.getenv`/`os.environ.get` env reads | 16 (S1) | operator/deployment trust (proxy/scratch/config env); no request data influences env in this codebase |
| internal-API job/template filter params (status/application/backend/recent/length/offset/ids/auto-validate-ids) + GUI page params | ~58 (S2/S6) | forwarded to registry selects and pagination arithmetic; never a filesystem path (only `path` at :223/:977/:1001 is file-targeting) |
| `/internal/runfile?path=` | 1 (S2) | genuine boundary, but runpy execution is Pass 4 primary (source/fp carry-over) |
| GUI form fields `runfile-data`/`edited-job-info`/`config-data` | 3 (S3) | request CONTENT written into FIXED server paths (open 'w' at :375/:606/:274); Pass 4/5 channels (exec/eval/config injection), not traversal |
| loadfile/runfile uploads + `.filename` reads | 6 (S4) | fixed save paths (`UPLOAD_FOLDER/loadfile.txt`, `runfile.py`); filename used only for the extension check; Pass 4 carry-over |
| login credentials, request.json of token/create endpoints, X-Access-Token header | 12 (S3/S6) | auth/DB lookup/template selection only; no path flow |
| GUI fixed-path opens/joins/sends (gangarc, export.txt, logs, job stdout/stderr of int-selected jobs) | ~35 (K1) | server-fixed paths or repository content; request data (if any) is content, not path |
| Persistency `files.py` `expandfilename`/`fullpath`, FileWorkspace, GangaRepository, SessionLock, bootstrap, GPIDev, Utility, LCG core plumbing | ~430 (K4) | gangadir/job-id/module-constant/operator-CLI paths; no request-derived path reaches these sites |
| GangaAtlas/GangaLHCb plugin job machinery | ~250 (K5/K6) | job objects, config and env inputs chosen by the operator; the HTTP surface never routes request paths into these modules |
| other plugins/scripts (Dirac/Panda/NA62/ND280/Gaudi/SNOplus/SuperB/SAGA/Robot/Tutorial/Service/Release tools) | ~160 (K7) | worker-node/release tooling, several py2-era; not request-reachable |
| archive extraction (`extractall`, 6 sites) | 6 (K3) | no `filter=` argument, but the tarballs are ganga/worker-produced with basename-sanitized member names (Sandbox.py:92-94/:109); request attacker has no channel — residual risk recorded (see 4) |

## 4. Manual review points (candidate/unknown + residual risks)

1. **`src-079` (source/candidate, 0.5)** — `request.json` of `job_action_endpoint`
   (`gui/routes.py:1258`) is dispatched dynamically (`getattr`/`setattr` over
   `Job._exportmethods` and schema attributes, `api/routes.py:126-186`). Whether a settable
   attribute (e.g. a file namePattern) can carry request strings into the job-workspace file
   machinery cannot be confirmed or refuted at AST level. **Human review: enumerate the Job
   schema items that reach File/FileWorkspace paths.**
2. **Archive extraction residual risk** — 6 `extractall` sites without `filter=` (Sandbox.py:154,
   WNSandbox.py:71, GaudiExecMerger.py:226, job_tools.py:310/:322, plus SAGAWrapperScript.py:87
   outside the CSV scope). Entry names are basename-sanitized at creation, and the archives are
   backend/worker-produced, so the request-attacker model does not reach them; a grid/backend
   compromise or a future code path feeding request data into sandbox creation would make these
   live. Labeled none/fp at 0.7 with this note. On Python ≥3.12 the default filter also changes
   the semantics (runtime property, outside this database).
3. **Pass 4 carry-overs** (flagged in labels, to be re-labeled in the pass-4 round):
   `/internal/runfile?path=` → `runpy.run_path` (arbitrary code execution); `load()` evals file
   content (Persistency:209); the runfile-data/edited-job-info/config-data fixed-path content
   channels (exec/eval/config injection); the socketio pty channel writes to an FD (Pass 2).
4. **TOCTOU shape** on the browser flows (exists/isfile then send_file/save) — both sides of each
   race are already attacker-reachable in the confirmed chains; no additional label.

## 5. Phase 2 hand-off instructions (recorded in labels.json notes)

- Render **only `classification=tp`** entries into `MySources/MySinks/MySummaries`.
- Required MySummaries taint steps: `os.path.join` (any tainted argument → result; the joins at
  gui/routes.py:659/:934/:954 are StrJoin nodes not covered by AST extraction), Persistency
  `export`/`stripped_export`/`fullpath`/`load` (param → open argument), `Runtime.getScriptPath`
  (param → return).
- `MySanitizers` must contain exactly one barrier: the `secure_filename` **call node**
  (gui/routes.py:953). `allowed_file` must NOT become a barrier.
- Model both components of the storage upload destination: filename (source :953 → barrier →
  join :954 arg 1) and directory (source :925 → join :934/:954 arg 0 → save :955).

## 6. Independence statement

No PyVul ground truth, patch diffs, CVE publications, or the vulnerability reports present in the
source-tree root (`GANGA-VULNERABILITY-REPORT.md`, `GANGA-CVE-REPORT-STORAGE.md`,
`path_traversal_sinks.csv`) were consulted. The source tree, the CodeQL database, the Augur
installation, and the Phase 1 CSVs were not modified. **Phase 2 was not started.**
