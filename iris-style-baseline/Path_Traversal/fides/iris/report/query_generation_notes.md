# Augur Phase 2 Step 4–5 — Query Generation Notes (fides, Pass 1: Path Traversal)

Run `iris-fides-pathtraversal-pass1-20261022` · 2026-10-22 · model `glm-5.3`
(Claude Code CLI harness) · target `ethyca-fides` @ sha `1212eadf`
(database `fides-db`, CodeQL CLI 2.25.1, `codeql/python-all` 7.1.x from the local
pack cache — per `iris/exploration/detection.json` toolchain record).

Generated files (this step, and nothing else):

| File | Contents |
| --- | --- |
| `iris/libraries/MySources.qll` | 1 source predicate (from 1 reviewed tp source label) |
| `iris/libraries/MySinks.qll` | 2 sink predicates (from 2 reviewed tp sink labels) |
| `iris/libraries/MySanitizers.qll` | empty `isBarrier` (`none()`) — 0 confirmed sanitizer labels |
| `iris/libraries/MySummaries.qll` | 2 anchored taint steps (from 1 reviewed tp summary label) |
| `iris/queries/Pass1_PathTraversal.ql` | pass query rendered from `assets/taint_query.ql.tmpl` |
| `iris/report/query_generation_notes.md` | this document |

`qlpack.yml` (`iris/fides-cwe22`, dependency `codeql/python-all: "*"`) already
existed from Step 0 and was reused unchanged. Per the experiment contract,
**no compilation or query execution was performed in this step** — the QL below
reuses only AST/dataflow API shapes already proven on this CLI/pack family by
the extraction queries of this series (documented in
`iris/exploration/detection.json` `toolchain.compatibilityBasis`), plus the
long-stable `BinaryExpr`/`getLeft`/`getRight` core AST API.

## 0. Checkpoint input state

- `labels/labels.json` — schema-valid, 204 entries; rendered here are exactly
  the 4 entries with `classification=tp` (1 source, 2 sinks, 1 summary).
- `labels/review_decision.json` — **does not exist**. Step 3 ended with the
  advisory checkpoint artifact `labels/phase1_review.md` (WORKFLOW.md §4.5:
  the review gate is advisory; `review_decision.json` is an optional audit
  file, and none was written in the Step 3 round). The human-review payload of
  that checkpoint (label counts, high-risk sinks, rejected sanitizer list,
  manual-review points) is the reviewed state this step consumes; no label was
  modified and none needed re-approval (see §7).
- Relevant source re-read for this step: `src/fides/api/main.py` (154–197),
  `src/fides/api/ui.py` (17–146), plus the Phase 1 reading of
  `saas_config_endpoints.py`, `connector_registry_service.py` and the
  middleware/endpoint files backing the exclusion rationale.

## 1. Label ID → QL predicate mapping

Every rendered rule, its reviewed label, and its source evidence:

| Label ID | Role/Class (conf.) | QL predicate | Anchored at | Evidence |
| --- | --- | --- | --- | --- |
| `src-044` | source/tp (0.95) | `MySources::catchallPathParamSource` | `main.py:160` Subscript `request.path_params["catchall"]` | `@app.get("/{catchall:path}")` at `main.py:154`; the value drives `match_route`/`get_path_to_admin_ui_file` → `is_file` → `FileResponse` |
| `sink-064` | sink/tp (0.95) | `MySinks::fileResponseSink` | `main.py:180` `FileResponse(ui_file)`, arg 0 | starlette `FileResponse` opens + streams the file at response time; reached from the unauthenticated catch-all handler |
| `sink-063` | sink/tp (0.65) | `MySinks::isFileExistenceProbe` | `main.py:170` `ui_file.is_file()`, receiver | stat-family probe on the unresolved Path: existence oracle outside the UI root + gate for the FileResponse read |
| `sink-097` | summary/tp (0.90) | `MySummaries::getPathToAdminUiFileCallStep` (main.py:167 arg 0 → call result) **and** `MySummaries::pathlibTruedivJoinStep` (ui.py:42 right operand `path` → outer `/` BinaryExpr) | `main.py:167`, `ui.py:42` | callee body `return package_path / ADMIN_UI_DIRECTORY / path` (ui.py:38–42) derives the result from the argument; `..` survives lexically |

All 200 remaining label entries are `fp` (or sanitizer/fp) and are **not**
rendered; the mapping of every excluded family is §6 of
`labels/label_stats.md` ("Rejected candidate families") and §4 of
`labels/phase1_review.md`.

## 2. Source: external input boundary and access conditions

`src-044` — `request.path_params["catchall"]` (`main.py:160`):

- **Boundary:** the URL remainder after the leading `/` of any request not
  matched by a more specific route. The Starlette router **percent-decodes**
  the path before populating `path_params`, so the attacker controls the full
  decoded string, including `..` segments and `/` separators
  (`GET /..%2F..%2F..%2Fetc%2Fpasswd` → catchall = `../../etc/passwd`).
  Exactly one decode pass exists (in the router, external to the database);
  no application-level re-decoding exists anywhere on the chain, so no
  multi-decode concern applies. The value is always **relative** (leading `/`
  stripped), which is precisely what keeps the lexical guard satisfiable.
- **Authority/access:** the catch-all route decorator
  (`main.py:154`) registers **no** `dependencies=`/`Security(...)` scope —
  the parameter is reachable by an unauthenticated remote HTTP client of the
  webserver. The `API_PREFIX` 404 branch (`main.py:183`) only affects
  api-prefixed paths; middlewares on the app do logging/CORS, not gating.
- **Modeled shape:** the Subscript itself (`source.asExpr() = s`) — not the
  whole `Request` object (the reviewed `src-043` fp explicitly rejects that
  to avoid over-tainting every request field, python.md §7.4) and not the
  zip-upload body (`src-068` fp: in-memory only, Pass 4 carry-over).

## 3. Sinks: real file operation, dangerous position, access type, call context

| Sink | Real file operation | Dangerous position | Access type | Call relationship |
| --- | --- | --- | --- | --- |
| `sink-064` `main.py:180` | `FileResponse(ui_file)` — starlette opens the path (`open`/`os.stat` inside the external starlette library, not in this database) and streams the bytes as the HTTP response | **arg 0** — the Path object naming the file (matched as the argument expression; the response object itself is never a sink node, keeping path-text vs file-object distinct) | file **read** disclosed to the remote client | called from `read_other_paths`, the unauthenticated catch-all handler, after the `is_file` gate and the (non-blocking) guard |
| `sink-063` `main.py:170` | `ui_file.is_file()` — pathlib stat-family probe; the OS resolves the lexical `..` at stat time | **receiver** — the Path object `ui_file` (matched as the receiver expression, not the boolean result) | metadata **read** (existence/fstype oracle outside the UI root) | same handler, one line above the FileResponse branch; secondary sink at conf 0.65 because it also fires on the safe `match_route` branch (`main.py:163` returns trusted map paths) |

Both sinks are line-anchored within `%/src/fides/api/main.py` (path unique in
the tree — verified), so the fixed-`index.html` `FileResponse` at `ui.py:50`
(`sink-099`, none/fp) is not matched.

## 4. Path join / decode / canonicalization / allowed root / symlink evidence

- **Join:** `get_path_to_admin_ui_file` (ui.py:32–42) returns
  `package_path / ADMIN_UI_DIRECTORY / path` — a pathlib `__truediv__` chain
  that preserves `..` lexically; an absolute right operand would *replace*
  the base, but the router's leading-`/` stripping makes that unreachable.
  `package_path` comes from `importlib.util.find_spec` (ui.py:24–27) — the
  installed-package location, operator trust.
- **Allowed root:** the packaged admin-UI directory
  (`<package_path>/ui-build/static/admin/`) is the *declared* root, but it is
  never enforced on a resolved path (see §5).
- **Canonicalization order:** none. No `resolve()`, `normpath()`,
  `abspath()`, or `relative_to()` runs anywhere on the chain before file
  access; the only containment attempt (`path_is_in_ui_directory`) compares
  against the **unresolved** path (below), and `is_file()`/`FileResponse`
  perform the OS-level resolution of `..` at access time — normalization
  (by the OS) happens *after* the check, which is the defect.
- **Decode:** single percent-decode in the Starlette router (external); no
  application-level decoding on the chain.
- **Symlinks:** no symlink creation or link-following policy exists in the
  audited code; the packaged admin-UI directory is not attacker-writable, so
  symlink/TOCTOU is recorded as **not applicable / not observed** (and the
  lexical guard would not stop a symlink escape anyway). Windows drive/UNC
  forms cannot occur because the value is relative and `pathlib` on the
  deployed (POSIX) server treats backslashes as ordinary filename characters.
- **`match_route` (`main.py:163`) is deliberately NOT a propagation edge:**
  the user string is only a `re.fullmatch` selector over the boot-time map
  built from `ui_path.glob("**/*.html")` (ui.py:82); the map's patterns use
  `[a-zA-Z10-9-_]+`/`[a-zA-Z10-9-_/]+` classes **without dots**, so `..`
  payloads never match and the flow always falls through to the vulnerable
  `get_path_to_admin_ui_file` fallback (`main.py:166-167`). An arg-1→result
  edge would fabricate taint (the returned Path always comes from the trusted
  map) — reviewed label `sink-105` (none/fp).

## 5. Barrier analysis

`MySanitizers::isBarrier` resolves to `none()` — **zero barriers are
rendered**, matching the reviewed label set (no sanitizer/tp entry exists).
The two sanitizer candidates were reviewed and REJECTED:

- `sink-106` (`path_is_in_ui_directory`, ui.py:134) / `sink-107` (the
  `path.parents` read, ui.py:141): the guard is
  `return ui_directory in path.parents` — a **lexical** containment check on
  the **unresolved** Path. pathlib keeps `..` as an ordinary component, so
  the lexical parents of `<ui_dir>/../../../etc/passwd` still contain
  `<ui_dir>` exactly (verified during labeling:
  `Path("/a/b/c") in (Path("/a/b/c")/".."/".."/"x").parents == True`). The
  guard therefore **passes for precisely the `..` payloads that escape at OS
  level** and only rejects the absolute-path replacement case, which the
  router already makes unreachable. It cannot block any of the traversal
  mechanisms at stake (`../` chains, encoded separators decoded once by the
  router, repeated `..`). Rendering it as `isBarrier` would suppress the
  confirmed finding; the labels carry this instruction explicitly and the
  generated `MySanitizers.qll` documents it.
- No other candidate neutralization exists in the tree (no
  canonicalize-then-contain, no `..` rejection, no basename, no separator
  whitelist) — per `labels/label_stats.md` §"Sanitizers: 0 confirmed".
- `match_route`'s fixed-map lookup is a real *selector* containment for its
  own branch, but it is not modeled as a barrier: barriers are
  node-conditional cuts, and taint that reaches the fallback call at
  `main.py:167` never passes through a `match_route` node on the vulnerable
  path (also documented in the label rationale).

## 6. Additional flow steps, known limitations, diagnostics

**Additional propagation edges (both from the single reviewed summary label
`sink-097`, both code-anchored):**

1. `main.py:167` argument 0 → call result (call-site summary of
   `get_path_to_admin_ui_file`), and
2. `ui.py:42` right operand `path` → the outer `/` BinaryExpr (the
   intra-callee operator step).

Dual modeling is deliberate: this step was generated **without compiling**, so
both anchored forms of the same reviewed fact are included — if
`TaintTracking::Global`'s default models already cover the interprocedural
return and/or the `/` operator, the two edges at worst duplicate a path
segment; if they do not, either one alone keeps the source→sink chain
connected. Neither edge is unconditional: each is pinned to one file+line+shape.

**Dynamic-call / aliasing / resolution limitations (CodeQL, recorded not
fixed):**

- `FileResponse`'s actual `open` happens inside starlette (external to the
  database) — the modeled sink marks the boundary at the call site (same
  treatment as the fideslang/toml rows in Phase 1).
- `get_ui_file_map()` is `@lru_cache`d and built from a runtime `glob` —
  irrelevant to taint (map values are packaged files), but it means the safe
  branch's paths are only knowable at runtime, not in the DB.
- `get_package_path()` resolves through `importlib.util.find_spec` at runtime;
  the base of the vulnerable join is therefore opaque to CodeQL. Harmless
  here (the base is operator trust), but it means no query-side check could
  ever compare the joined path against the real install root.
- `request.path_params` is an attribute/subscript on the starlette `Request`
  (external library): the source is matched at AST level
  (`request.path_params["catchall"]`, receiver name `request` — the scoping
  convention of the Phase 1 extraction), not through API resolution.
- `pathlib` `/` operator modeling by the pack is unverified (no compile in
  this experiment) — mitigated by edge 2 above.
- If the default library already models `pathlib` or the call, the
  `isAdditionalFlowStep` edges are redundant but sound.

**Diagnostic paths (NOT part of the official Pass 1 alert set):**

- `sink-063` (`is_file` existence probe) is a deliberately-kept secondary
  sink at conf 0.65; alerts terminating there (without reaching
  `FileResponse`) are expected to be triaged/filtered in Step 6, since the
  same `is_file` also gates the safe `match_route` branch.
- Wrapper-debug queries (e.g. checking whether the two summary edges fire,
  or whether `match_route` results ever carry taint) belong in
  `iris/diagnostics/` and must not be counted as Pass 1 findings; none were
  created in this step (no compilation allowed).
- The dual summary edges may produce two path variants for the same
  source→sink pair (one through each edge form) — a display artifact only.

## 7. Label completeness check (Step 5 feedback loop)

No omission was found in the reviewed labels: the 4 tp entries fully cover the
confirmed catch-all chain (source → join wrapper → existence probe → file
response), the guard is correctly classified as a rejected sanitizer, and the
remaining 200 fp entries each carry a code-grounded exclusion rationale that
this step honored verbatim. **No label needed re-review; `labels.json` was not
modified.** The one soft point already flagged by the checkpoint
(`sink-063`'s dual-branch firing) is a rendering-time precision note, not a
label defect, and is handled as a Step 6 triage note rather than a Step 5
return.

## 8. Experiment independence

Consistent with the prior projects of this series
(aiohttp/airflow/ansible/coderedcms/copyparty/dfetch/django):

- No PyVul ground truth, patch diffs, CVE publications, or the vulnerability
  reports present in the source-tree root (`FIDES-VULNERABILITY-REPORT.md`,
  `path_traversal_*.md/csv`) were consulted.
- The source tree, the CodeQL database (`fides-db`), the Augur installation,
  and the Phase 1 labels/CSVs were not modified; the only writes this step
  are the six generated files listed at the top.
- The pass query follows `assets/taint_query.ql.tmpl` with the required
  metadata: `@kind path-problem`, `@problem.severity error`,
  `@precision medium`, `@tags security` + `external/cwe/cwe-022/023/036/073`,
  query id `py/augur/fides/pass1-path-traversal`; `isBarrier` is present in
  the config and delegates to `MySanitizers` (which resolves to `none()`).
- No compilation or analysis was executed (per the step contract); compile
  verification and sequential execution belong to the analysis round.
