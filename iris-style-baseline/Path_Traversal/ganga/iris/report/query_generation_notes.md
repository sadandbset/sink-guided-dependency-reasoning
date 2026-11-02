# Augur Phase 2 Step 4–5 — Query Generation Notes (ganga, Pass 1: Path Traversal)

Run `iris-ganga-pathtraversal-pass1-20261022` · 2026-10-22 · model `glm-5.3`
(Claude Code CLI harness) · target `ganga` (Ganga 8.4.2) @ db sha `0c0f9e33`
(database `ganga-db`, CodeQL CLI 2.25.1, `codeql/python-all` 7.1.1/7.1.2 from the
local pack cache — per `iris/exploration/detection.json` toolchain record).

Generated files (this step, and nothing else):

| File | Contents |
| --- | --- |
| `iris/libraries/MySources.qll` | 5 source predicates (from the 6 reviewed tp source labels) |
| `iris/libraries/MySinks.qll` | 10 sink predicates over 3 shared shapes (from the 12 reviewed tp sink labels) |
| `iris/libraries/MySanitizers.qll` | 1 barrier (the single reviewed sanitizer/tp label) + documented rejection of `allowed_file` |
| `iris/libraries/MySummaries.qll` | 10 anchored taint steps (from the 8 reviewed tp summary labels; two labels render dual edges) |
| `iris/queries/Pass1_PathTraversal.ql` | pass query rendered from `assets/taint_query.ql.tmpl` |
| `iris/report/query_generation_notes.md` | this document |

`qlpack.yml` (`iris/ganga-cwe22`, dependency `codeql/python-all`) already
existed from Step 0 and was reused; during post-generation compile
verification its dependency was pinned from `"*"` to the locally cached
`7.1.2` (a `"*"` makes CLI 2.25.1 try to fetch the newest registry pack
7.2.8, whose manifest format this CLI cannot parse; 7.1.2 is the series'
proven toolchain per `exploration/detection.json`), and `codeql pack install`
was run once to write `codeql-pack.lock.yml` (all packs resolved from the
local cache). **Compilation was verified after generation** (`codeql query
compile --check-only` → Done, no errors/warnings); no database analysis or
query execution was performed. One compile defect was found and fixed during
that verification: `MySanitizers.qll` initially called the `inModule/2`
helper without defining it (the helper block existed only in the other three
libraries) — the helpers were added, and the `isBarrier` QLDoc was re-attached.
The QL below
`AstNode.getLocation().getFile().getAbsolutePath()`/`getStartLine()`,
`Call.getFunc()/getArg(int)/getAnArg()`, `Attribute.getName()/getObject()`,
`Subscript.getObject()`, `Function.getName()/getArgByName()`,
`DataFlow::Node.asExpr()` and `DataFlow::parameterNode(Parameter)` (verified in
the local pack: `semmle/python/Exprs.qll:156` for `getArg`,
`semmle/python/Function.qll:65` for `getArgByName`,
`semmle/python/dataflow/new/internal/DataFlowPublic.qll:350` for
`parameterNode`, used as `DataFlow::parameterNode` in
`semmle/python/frameworks/Websockets.qll:69`), the shared
`codeql/dataflow/2.1.3` `ConfigSig` signature (`isSource`/`isSink`/`isBarrier`/
`isAdditionalFlowStep`, all default-`none()`-able), and
`TaintTracking::Global<Config>` + `PathGraph` + `flowPath` — the exact query
shape of the fides pass-1 query of this series, which executed successfully on
this toolchain.

## 0. Checkpoint input state

- `labels/labels.json` — schema-valid, 1002 entries (from 111 source + 907
  sink CSV rows, 16 exact-duplicate decode artifacts removed); rendered here
  are exactly the 27 entries with `classification=tp` (6 source, 12 sink,
  8 summary, 1 sanitizer), the 1 `source/candidate` entry (NOT rendered, see
  §7), and none of the 974 fp entries.
- `labels/review_decision.json` — **does not exist**. Step 3 ended with the
  advisory checkpoint artifact `labels/phase1_review.md` (WORKFLOW.md §4.5:
  the review gate is advisory; `review_decision.json` is an optional audit
  file and none was written in the Step 3 round). Its human-review payload
  (label counts, the four confirmed chains, the sanitizer verdicts, the
  manual-review points) is the reviewed state this step consumes; the
  instruction to execute Step 4–5 is the checkpoint approval. No label was
  modified and none needed re-approval (see §7).
- Relevant source re-read for this step: `GangaGUI/gui/routes.py`
  (636–689, 922–992, 953–955, 1799–1800), `GangaGUI/api/routes.py`
  (212–232, 966–986), `GangaCore/GPIDev/Persistency/__init__.py`
  (35–41, 83–85, 140–151, 154–190), `GangaCore/Utility/Runtime.py` (28–61),
  `GangaCore/Runtime/bootstrap.py` (147–163, GPI wiring), plus the Phase 1
  reading of `GangaGUI/start.py`, `GangaGUI/gui/config.py` and
  `GangaCore/GPI/__init__.py`.

## 1. Label ID → QL predicate mapping

Every rendered rule, its reviewed label, and its source evidence:

| Label ID | Role/Class (conf.) | QL predicate | Anchored at | Evidence |
| --- | --- | --- | --- | --- |
| `src-016` | source/tp (0.90) | `MySources::internalApiPathParamSource` | `api/routes.py:223` `request.args.get("path")` (call result) | `@internal.route("/internal/jobs/<job_id>/export")` :212, no auth on any internal route; `export(jobs(job_id), save_path)` :227 → GPI write chain |
| `src-045` | source/tp (0.90) | `MySources::internalApiPathParamSource` | `api/routes.py:977` `request.args.get("path")` (call result) | `@internal.route("/internal/load")` :966; `load(path)` :981 → GPI read chain |
| `src-065` | source/tp (0.95) | `MySources::jobBrowsePathParamSource` | `gui/routes.py:639` `job_browse` parameter `path` (`DataFlow::parameterNode`) | route `/job/<int:job_id>/browse/<path:path>` :636–637; join :659 → exists/isfile/send_file/listdir :665–676 |
| `src-069` | source/tp (0.95) | `MySources::storagePagePathParamSource` | `gui/routes.py:925` `storage_page` parameter `path` | route `/storage/<path:path>` (GET+POST) :922–923; join :934 → read sinks :969–980 and write chain :954→:955 |
| `src-070` | source/tp (0.85) | `MySources::storageUploadFileSource` | `gui/routes.py:941` `request.files["storagefile"]` (Subscript) | POST upload branch :937–959; `storagefile.save(save_path)` :955 |
| `src-072` | source/tp (0.80) | `MySources::storageUploadFilenameSource` | `gui/routes.py:953` `.filename` attribute read | feeds `secure_filename(...)` :953 → join :954 arg 1 (cut by the barrier) |
| `sink-780` | sink/tp (0.60) | `MySinks::jobBrowseStatProbe` (os.path.exists, arg 0) | `gui/routes.py:665` | stat oracle + gate for the job-browser disclosure |
| `sink-781` | sink/tp (0.70) | `MySinks::jobBrowseStatProbe` (os.path.isfile, arg 0) | `gui/routes.py:670` | file-type oracle, branch selector send_file vs listdir |
| `sink-782` | sink/tp (0.95) | `MySinks::jobBrowseSendFile` (send_file, arg 0) | `gui/routes.py:671` | **PRIMARY job-browser arbitrary file read** |
| `sink-783` | sink/tp (0.90) | `MySinks::jobBrowseListdir` (os.listdir, arg 0) | `gui/routes.py:676` | arbitrary directory listing |
| `sink-798` | sink/tp (0.60) | `MySinks::storageUploadGateProbe` (os.path.isdir, arg 0) | `gui/routes.py:949` | upload-branch gate, stat oracle on the write destination |
| `sink-803` | sink/tp (0.60) | `MySinks::storageStatProbe` (os.path.exists, arg 0) | `gui/routes.py:969` | stat oracle + gate |
| `sink-804` | sink/tp (0.70) | `MySinks::storageStatProbe` (os.path.isfile, arg 0) | `gui/routes.py:974` | branch selector |
| `sink-805` | sink/tp (0.95) | `MySinks::storageSendFile` (send_file, arg 0) | `gui/routes.py:975` | **PRIMARY storage arbitrary file read** |
| `sink-806` | sink/tp (0.90) | `MySinks::storageListdir` (os.listdir, arg 0) | `gui/routes.py:980` | arbitrary directory listing |
| `sink-801` | sink/tp (0.90) | `MySinks::storageFileSave` (storagefile.save, arg 0) | `gui/routes.py:955` | **PRIMARY storage arbitrary file write** (destination directory unsanitized) |
| `sink-492` | sink/tp (0.90) | `MySinks::persistencyExportOpen` (open, arg 0) | `Persistency/__init__.py:85` | **PRIMARY internal-API arbitrary file write** (mode "w"/"a") |
| `sink-495` | sink/tp (0.90) | `MySinks::persistencyLoadOpen` (open, arg 0) | `Persistency/__init__.py:190` | **PRIMARY internal-API arbitrary file read** |
| `sink-799` | sanitizer/tp (0.90) | `MySanitizers::isBarrier` (secure_filename call node) | `gui/routes.py:953` | concrete neutralization of the FILENAME component only |
| `sink-778` | summary/tp (0.90) | `MySummaries::joinStep` (line 659) | `gui/routes.py:659` `os.path.join(job_base_dir, path)` | any-arg → result; `..` survives lexically, absolute arg replaces base |
| `sink-797` | summary/tp (0.90) | `MySummaries::joinStep` (line 934) | `gui/routes.py:934` `os.path.join(storage_folder, path)` | same join semantics on the storage root |
| `sink-800` | summary/tp (0.85) | `MySummaries::joinStep` (line 954) | `gui/routes.py:954` `os.path.join(abs_path, filename)` | write-destination join; arg 0 carries the route-path taint |
| `sink-490` | summary/tp (0.90) | `MySummaries::exportBridgeStep` | `api/routes.py:227` arg 1 → `export` param `filename` (Persistency:35) | GPI namespace is runtime-populated → static import resolution fails |
| `sink-491` | summary/tp (0.90) | `MySummaries::strippedExportForwardStep` | `Persistency/__init__.py:36` arg 1 → `stripped_export` param `filename` (:41) | same-module forwarding; anchored rendering of the reviewed fact |
| `sink-493` | summary/tp (0.85) | `MySummaries::fullpathCallSiteStep` (:83 arg 0 → result) **and** `MySummaries::fullpathDefSideStep` (:149 param → outer `os.path.abspath` call) | `Persistency/__init__.py:83/:149` | abspath/expandvars/expanduser: normalization WITHOUT containment; stdlib calls carry no pack taint summary |
| `sink-494` | summary/tp (0.90) | `MySummaries::loadBridgeStep` | `api/routes.py:981` arg 0 → `load` param `filename` (Persistency:154) | same GPI runtime-namespace rationale |
| `sink-396` | summary/tp (0.85) | `MySummaries::getScriptPathCallSiteStep` (:188 arg 0 → result) **and** `MySummaries::getScriptPathDefSideStep` (Runtime:47 param → outer `os.path.expanduser` call) | `Persistency/__init__.py:188`, `Runtime.py:47` | exists-branch returns the expanded attacker name verbatim (Runtime:47–49) |

All 975 remaining label entries are `fp` (or `candidate`) and are **not
rendered**; the mapping of every excluded family is in
`labels/label_stats.md` ("Rejected candidate families") and
`labels/phase1_review.md` §3.

## 2. Sources: external input boundary and access conditions

| Source | Boundary | Authority / access conditions |
| --- | --- | --- |
| `src-016` (api:223) | flask query string of `/internal/jobs/<job_id>/export` | internal Flask app has **no authentication on any route** and is bound to `localhost` (`APIServerThread("GangaGUIAPI", "localhost", port)`, `GangaGUI/start.py:99/:109`). Reachable by any local process and by a remote drive-by page issuing a cross-origin GET (the export executes server-side; SOP only blocks reading the response). The GUI's own job-export view calls it with a fixed `UPLOAD_FOLDER/export.txt` path — the arbitrary-path usage is the direct request. |
| `src-045` (api:977) | flask query string of `/internal/load` | same unauthenticated localhost-bound internal app; the GUI's create/edit views call it with fixed `loadfile.txt` paths. |
| `src-065` (gui:639) | Flask path converter of `/job/<int:job_id>/browse/<path:path>` — the URL-decoded path remainder, `/` and `..` accepted | `@login_required` (gui/routes.py:638) — authenticated GUI user; constrains the attacker population, not the value. |
| `src-069` (gui:925) | Flask path converter of `/storage/<path:path>` (GET+POST) | `@login_required` (:924) — authenticated GUI user. |
| `src-070` (gui:941) | multipart file upload (`request.files["storagefile"]`) of the storage POST branch | authenticated GUI user; content fully controlled. |
| `src-072` (gui:953) | the multipart filename header (`.filename` read) | authenticated GUI user; neutralized by the barrier before path use — rendered to make the sanitization explicit (see §5). |

Decode semantics: Flask/Werkzeug percent-decodes the request path **once**
before routing (external to the database); no application-level re-decoding
exists anywhere on the chains, so no multi-decode concern applies. The
operator-trust families (env vars, optparse CLI, job/template filters,
login/json/header fields) are not sources per the reviewed labels.

## 3. Sinks: real file operation, dangerous position, access type, call context

| Sink | Real file operation | Dangerous position | Access type | Call relationship |
| --- | --- | --- | --- | --- |
| `sink-782` `send_file` gui:671 | flask `send_file` opens the path (inside external flask/werkzeug, not in this DB) and streams the bytes as the HTTP response | **arg 0** — the path text `abs_path` (argument expression; the response object is never a sink node) | file **read** disclosed to the authenticated GUI client | called from `job_browse` after the `isfile` gate; no containment on the joined path |
| `sink-805` `send_file` gui:975 | same | arg 0 (`abs_path`) | file **read** | called from `storage_page` after the `isfile` gate |
| `sink-783`/`sink-806` `os.listdir` :676/:980 | builtin directory listing; the OS resolves `..`/absolute replacement at syscall time | arg 0 | directory metadata **read** (names, then per-entry browsing) | same handlers, directory branch |
| `sink-780`/`sink-803` `os.path.exists` :665/:969 | stat-family probe on the traversal-laden path | arg 0 | metadata **read** (existence oracle outside the declared root) | gates the send_file/listdir disclosure |
| `sink-781`/`sink-804` `os.path.isfile` :670/:974 | stat-family probe | arg 0 | metadata **read** + branch selector | selects send_file vs listdir |
| `sink-798` `os.path.isdir` :949 | stat-family probe | arg 0 | metadata **read** | upload-branch gate that the write destination "directory" exists |
| `sink-801` `storagefile.save` :955 | werkzeug `FileStorage.save` writes the uploaded content at `save_path` (open inside external werkzeug) | **arg 0** — the path text `save_path` (the FileStorage receiver is not the sink) | file **write** | `storage_page` POST branch; destination = join(abs_path, secure_filename(filename)) — directory component unsanitized |
| `sink-492` `open` Persistency:85 | builtin `open(filepath, mode)` with mode "w"/"a" | arg 0 (`filepath` — the path text; the file object is not a sink) | file **write** | `stripped_export` on the GPI export chain fed by `/internal/jobs/<id>/export?path=` |
| `sink-495` `open` Persistency:190 | builtin `open(filepath)` | arg 0 | file **read** (content then eval'd at :209 — Pass 4 carry-over, not this pass) | `load` on the GPI load chain fed by `/internal/load?path=` |

Path **text** vs opened file **object**: every sink is anchored on the
argument expression that names the file location; no returned file, response
or listing object is a sink. All twelve sinks are line- and module-anchored
(plus receiver/func-name shape checks), so the ~35 fixed-path GUI rows
(gangarc/export.txt/logs/job-stdout of int-selected jobs) and the ~870
core/plugin operator-level rows reviewed `none/fp` are not matched.

## 4. Path join / decode / canonicalization / allowed root / symlink evidence

- **Join:** the three reviewed `os.path.join` sites (gui/routes.py:659/:934/:954)
  concatenate without normalizing — `..` segments survive **lexically** and an
  absolute argument **replaces** the base entirely. Modeled as taint steps
  (any argument → result), never as barriers. `job_base_dir` itself
  (`os.path.dirname(os.path.dirname(job_info["outputdir"]))`, :651) is
  repository content of an integer-selected job — not request-derived;
  `storage_folder` is the config constant `gangadir/gui/storage`
  (`GangaGUI/gui/config.py:35`).
- **Allowed roots:** the *declared* roots are the job base directory
  (browse) and `gangadir/gui/storage` (storage) — **neither is enforced**:
  no resolve/realpath + containment, no `startswith(base)`, no
  `relative_to`, no `..` rejection, no basename extraction exists anywhere
  on the chains (verified by reading the full handlers :639–:689 and
  :925–:992).
- **Canonicalization order:** none before access on the GUI chains — the
  OS resolves `..` at the exists/isfile/send_file/listdir/save syscalls,
  i.e. normalization happens *at access time*, which is the defect. On the
  internal-API export chain `fullpath` (Persistency:140) applies
  abspath/expandvars/expanduser **after** the request value is already the
  whole path — normalization without confinement (abspath collapses `..`,
  defeating lexical checks, but confines to nothing); on the load chain
  `getScriptPath` (Runtime:28) returns the expanded name **verbatim** on
  the exists-branch (:47–:49) and only basenames on the not-found
  search-path branch (:52–:58).
- **Decode:** single percent-decode in the Flask/Werkzeug router
  (external); `request.args` values are form-decoded once; no application
  re-decoding on any chain.
- **Symlinks:** no symlink creation or link-following policy exists on any
  confirmed chain and the job/storage roots are not attacker-writable via
  the audited flows — symlink/TOCTOU recorded as **not applicable / not
  observed** (labels note). The exists→send_file and isdir→save sequences
  are separate syscalls (TOCTOU shape), but both sides of each race are
  already attacker-reachable in the confirmed chains, so it adds no
  additional modeled behavior. Windows drive/UNC forms cannot occur for
  the route params on the deployed POSIX server; absolute-path replacement
  (`/etc/passwd` as route value) is the modeled equivalent.
- **`match_route`-style selectors:** ganga has no fixed-map selector on
  these chains (unlike the fides run) — the browsers join the raw route
  path directly.

## 5. Barrier analysis

**Exactly one barrier is rendered** (`MySanitizers::isBarrier`), from the
single reviewed sanitizer/tp label `sink-799`:

- `secure_filename(storagefile.filename)` at gui/routes.py:953 — anchored
  on the **call node**. Real blocking power (verified werkzeug semantics):
  it strips path separators, `..` and absolute-name components from the
  uploaded FILENAME (`../../etc/passwd` → `etc_passwd`), so the filename
  component of the join at :954 argument 1 is genuinely neutralized. It is
  PARTIAL by design: the DIRECTORY component (`abs_path`, the route-path
  join result of :934) never passes through this call, so the barrier
  cannot suppress the confirmed write traversal
  (src-069 → join :934/:954 arg 0 → save :955) — it cuts precisely and only
  the sanitized component (src-072 → join :954 arg 1). This is the
  labels' explicit Phase 2 instruction, honored exactly.

**Rejected barriers (documented, not rendered):**

- `allowed_file` (gui/routes.py:1799, sanitizer/fp 0.85): extension
  allowlist `{"txt","py"}` — constrains only the extension, never path
  components, and is applied only to the loadfile/runfile channels whose
  save paths are FIXED (:301/:327). Rendering it as a barrier would
  falsely suggest the upload channels are path-contained.
- `os.path.join` / `fullpath` (abspath) / `getScriptPath` —
  value-preserving path construction/normalization without containment:
  modeled as taint steps (§4), not barriers. Mechanical
  "normalize ⇒ safe" treatment would suppress every confirmed chain.
- No other neutralization exists in the tree (labels: "Sanitizers: 1
  confirmed").

## 6. Additional flow steps, known limitations, diagnostics

**Additional propagation edges (10, all code-anchored to file+line+shape):**

1. join :659 any-arg → result (sink-778);
2. join :934 any-arg → result (sink-797);
3. join :954 any-arg → result (sink-800);
4. export bridge: api/routes.py:227 arg 1 → `export` param `filename`
   (sink-490) — **required** because the GPI namespace is populated at
   runtime via `exportToInterface(my_interface, ...)`
   (bootstrap.py:147–:163; `GangaCore/GPI/__init__.py` is only a
   docstring), so `from GangaCore.GPI import export` cannot be resolved
   statically and default global taint tracking does not cross the call;
5. stripped_export forward: Persistency:36 arg 1 → param (sink-491) —
   same-module call that resolves natively; the anchored edge is the
   dual rendering of the reviewed fact (redundant-but-sound);
6. fullpath call-site: Persistency:83 arg 0 → result (sink-493, form 1);
7. fullpath def-side: param → the outer `os.path.abspath` call at :149
   (sink-493, form 2) — the stdlib `abspath/expandvars/expanduser`
   nesting carries no pack taint summary;
8. load bridge: api/routes.py:981 arg 0 → `load` param `filename`
   (sink-494) — same GPI rationale as (4);
9. getScriptPath call-site: Persistency:188 arg 0 → result (sink-396,
   form 1);
10. getScriptPath def-side: Runtime:47 param `name` → the outer
    `os.path.expanduser` call (sink-396, form 2).

Dual modeling (6/7 and 9/10) is deliberate: generated without compiling,
both anchored forms of the same reviewed fact are included — if the default
library already covers the interprocedural return and the stdlib calls, the
edges at worst duplicate a path segment; if it does not, either form keeps
the source→sink chain connected. No edge is unconditional.

**Dynamic-call / aliasing / resolution limitations (CodeQL, recorded not
fixed):**

- The GPI runtime namespace (exportToInterface wiring) breaks static
  resolution of `export`/`load` from `GangaCore.GPI` — bridged by edges 4
  and 8, anchored to the two reviewed call sites only. `jobs(job_id)` /
  `query_internal_api` (GUI→internal HTTP hop) are not needed on any
  modeled chain (the internal-API sources are the direct request reads).
- `send_file` / `FileStorage.save` / the stat probes perform the actual
  file access inside external libraries (flask/werkzeug, not in this
  database) — the sinks mark the boundary at the call sites.
- `storagefile.filename` (src-072) → join :954 arg 1 has no unblocked
  route: the object→attribute taint step and the call result both sit
  behind the secure_filename barrier, so this source is expected to
  produce paths that terminate at the barrier (or none at all, since
  object→attribute taint is not modeled by default) — that is the
  reviewed, intended outcome, not a gap.
- `src-070` (the FileStorage object) likewise has no object→path flow by
  default; it is rendered because the reviewed label marks the upload
  boundary tp. The write-channel alert is produced by src-069.
- Stdlib taint modeling of `os.path.join`/`abspath`/`expanduser`/
  `expandvars` by the pack is unverified (no compile in this experiment) —
  mitigated by the anchored edges above; if already modeled, the edges are
  redundant but sound.
- Dual summary edges may produce two path variants for the same
  source→sink pair (one through each edge form) — a display artifact only.

**Diagnostic paths (NOT part of the official Pass 1 alert set):**

- The four stat-oracle/gate sinks (`sink-780`/`sink-798`/`sink-803`/
  `sink-804`, conf 0.60) and the two branch-selector sinks
  (`sink-781`/`sink-804`, 0.70) are deliberately kept at reduced
  confidence per the reviewed labels; alerts terminating there (without
  reaching send_file/listdir/save/open) are expected to be triaged or
  filtered in Step 6, since the same probes also fire on ordinary
  non-traversal browse requests (the probes precede every listing).
- Wrapper-debug queries (e.g. verifying that the two GPI bridge edges fire,
  or that the secure_filename barrier cuts only the filename component)
  belong in `iris/diagnostics/` and must not be counted as Pass 1
  findings; none were created in this step (no compilation allowed).

## 7. Label completeness check (Step 5 feedback loop)

No omission was found in the reviewed labels:

- the 6 source/tp entries cover every request-reachable path value on the
  four confirmed chains (2 route params, 2 internal-API query params, the
  upload object and its filename);
- the 12 sink/tp entries cover every actual file access on those chains
  (send_file ×2, listdir ×2, stat probes ×6, FileStorage.save, open ×2),
  each with its dangerous argument position;
- the 8 summary/tp entries cover every propagation gap that the default
  library cannot cross (3 joins, 2 GPI bridges, 2 dual-edge stdlib
  wrappers, 1 same-module forward);
- the single sanitizer/tp entry is the only real neutralization in the
  tree, and the one sanitizer/fp rejection (`allowed_file`) is correct.

**No label needed re-review; `labels.json` was not modified.** The one
`source/candidate` entry (`src-079`, the job_action dynamic
getattr/setattr dispatch) remains unconfirmed by review and is therefore
deliberately NOT rendered — rendering it would fabricate a source without
reviewed evidence; it stays a Step 6/8 manual-review point exactly as the
labels record.

## 8. Experiment independence

Consistent with the prior projects of this series
(aiohttp/airflow/ansible/coderedcms/copyparty/dfetch/django/fides):

- No PyVul ground truth, patch diffs, CVE publications, or the vulnerability
  reports present in the source-tree root (`GANGA-VULNERABILITY-REPORT.md`,
  `GANGA-CVE-REPORT-STORAGE.md`, `path_traversal_sinks.csv`) were consulted.
- The source tree, the CodeQL database (`ganga-db`), the Augur installation,
  and the Phase 1 labels/CSVs were not modified; the only writes this step
  are the six generated files listed at the top.
- The pass query follows `assets/taint_query.ql.tmpl` with the required
  metadata: `@kind path-problem`, `@problem.severity error`,
  `@precision medium` (the reviewed label set mixes 0.95 primary sinks with
  0.60–0.70 secondary oracle/gate sinks, and the dual summary edges can
  duplicate path variants — medium is the honest precision), `@tags
  security` + `external/cwe/cwe-022/023/036/073`, query id
  `py/augur/ganga/pass1-path-traversal`; `isBarrier` is present in the
  config and delegates to `MySanitizers` (exactly the one reviewed
  barrier).
- Compilation was verified with `codeql query compile --check-only` after the
  user's first attempt surfaced the missing `inModule/2` helper in
  `MySanitizers.qll` (fixed; see §0). Result: `Done [1/1]`, no errors, no
  warnings. No database analysis or query execution was performed —
  sequential `database analyze` execution belongs to the analysis round.
