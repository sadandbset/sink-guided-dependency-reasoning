# Phase 1 Review — Step 3 LLM Labeling (Pass 1: Path Traversal, Zope)

Human-review-gate payload per WORKFLOW.md 4.5 (advisory). This run covers Step 3 only:
**no Phase 2 work (libraries, pass queries, taint execution, report) has been started.**

## 1. Scope and method

- Project: Zope 5.2.dev0 (`Zope_vuln` source tree, 347 .py files, tests/Testing excluded by
  the Phase 1 extraction scope guard).
- Pass 1 only: Path Traversal (CWE-22, CWE-23, CWE-36, CWE-73).
- Labeling LLM (real model): **glm-5.3**, operating on the extracted candidate CSVs with
  direct verification against the real source code at every decisive site. Batches: 12 × 32
  candidates (376 total: 315 source rows + 61 sink rows; 0 exact duplicates; 0 candidates
  dropped; 0 re-asks below the 0.55 threshold).
- References loaded: `references/python.md`, `references/patterns.md`. **No
  `references/zope.md` exists in augur-0.3.0** (only django/fastapi/flask for Python), so
  framework-specific signatures were derived from repository code per WORKFLOW.md 4.2.3.
- Independence: PyVul ground truth, patch diffs, and CVE announcements were **not**
  consulted. No source code, CodeQL database files, or Phase 1 raw CSVs were modified.
- `labels.json` passes the local Augur `assets/labels_schema.json` (jsonschema 4.26.0).

## 2. Label counts by role

| role | count |
| --- | --- |
| source | 270 |
| sink | 61 |
| none | 45 |
| sanitizer | 0 |
| summary | 0 |

Classification: tp 265, fp 102, candidate 9, unknown 0.

## 3. Top high-risk sink candidates (manual review required)

These four sinks carry request-derived path components with **no in-repo containment
check**; all were classified `candidate` (not tp) because a decisive link lives outside
the repository or requires a compound precondition:

1. **`Products/Five/browser/resource.py:155-170` — the ++resource++ bridge (3 sink entries:
   p1-snk-318/369/375 + source p1-src-294).**
   `DirectoryResource.get(name)` receives the next URL traversal segment under
   `++resource++<dirname>/`, computes `filename = os.path.join(path, name)` (:155) with **no
   '..'/separator/containment filtering in this in-repo override**, existence-checks it
   (:156-157) and hands it to the resource factory (:170) whose external
   zope.browserresource File/FileResource performs the actual read when served. A literal
   `..` segment would make `isdir()` true and yield a DirectoryResourceFactory for the
   parent directory (stepwise traversal); a `%5C`-decoded backslash would be a separator on
   Windows. **Open question for the reviewer:** whether the external
   zope.browserresource/zope.traversing dispatcher filters `..` or other segment shapes
   before calling `get(name)` — that package is not in the CodeQL DB, so this could not be
   verified in-repo.

2. **`OFS/ObjectManager.py:621-622` — manage_exportObject write (p1-snk-343).**
   `f = os.path.join(CONFIG.clienthome, f'{id}.zexp')` with the request-derived `id`, then
   `open(f, 'w+b')`. The `id` must first resolve via `_getOb(id)` (:604), and object ids are
   guarded by `checkValidId` (ObjectManager.py:81-115) — but **`checkValidId` does not reject
   `/` or embedded `..` components** (bad_id regex only rejects control chars, `<>&`; exact
   `.`/`..`; leading `_`/`aq_`/`@@`/`++`; trailing `__`). Since ZMI form values are marshalled
   directly into `manage_addFile(id, ...)` parameters, an object whose id contains `/`
   components can be created (id passes `checkValidId`), and exporting it makes the join
   escape `CONFIG.clienthome`, writing semi-controlled ZODB export data outside the declared
   root. Compound precondition (the id must resolve to an existing object with that exact
   id) → classified `candidate`, confidence 0.65.

3. **`OFS/ObjectManager.py:639-645 / :679` — manage_importObject chain (p1-snk-344-area,
   classified fp with caveats).**
   The request `file` value is guarded by `dirname, file = os.path.split(file); if dirname:
   raise BadRequest` (:639-641) — on the running platform this rejects every
   separator-containing name; the degenerate `..` resolves to the import directory itself and
   the subsequent importFile open fails. Residual risks documented: (a) on Windows, a
   drive-relative name (`C:x`) passes `ntpath.split` with an empty dirname and
   `os.path.join` then resets to drive C's current directory; (b) TOCTOU window between the
   `os.path.exists` check (:645) and the ZODB `connection.importFile` open (:679).

## 4. Top broad source APIs (recall kept deliberately broad)

- `request_subscript` (84 rows) + `request_lookup_get` (33 rows) + `wsgi_environ_subscript`
  (22) + `wsgi_environ_get` (16): the merged HTTPRequest lookup surface. Per-key trust
  varies (server-only keys like SERVER_PORT are not attacker-path-controlled); left broad
  for recall, refinement belongs to Phase 2 triage.
- `http_request_param` (33): published entry points and WebDAV verb handlers — note that
  WebDAV PUT/MKCOL store data in ZODB objects, not on the filesystem.
- `zmi_form_param` (18): mapply-marshalled manage_* parameters, permission-gated but
  HTTP-reachable; `manage_importObject`'s `file` and `manage_exportObject`'s `id` are the
  two that reach filesystem joins.
- `route_path_param` (5, candidate/0.70): BaseRequest.traverse / resolve_url /
  physicalPathFromURL / unrestrictedTraverse / restrictedTraverse — these traverse the ZODB
  object tree, **not** the filesystem; they are kept because traversal segments feed the
  bridges above. Reviewer should confirm whether to keep them as sources in the Pass 1
  query or downgrade to summaries.

## 5. Sanitizer list

No sanitizer entries were labeled — none of the extracted candidates is a proven
neutralizer. The real guard layer (for Phase 2 `MySanitizers.qll` consideration, all
verified in source):

| guard | location | effect | caveat |
| --- | --- | --- | --- |
| `os.path.split` dirname rejection | OFS/ObjectManager.py:639-641 | rejects separator-containing import names | platform-dependent separator set; Windows drive-relative edge |
| `checkValidId` | OFS/ObjectManager.py:84-115 | rejects `.`, `..`, control/angle chars, reserved prefixes | **does not reject `/` or embedded `..`** |
| `_getOb(id)` resolution | OFS/ObjectManager.py:604 | export id must be an existing object | an id created with `/` still resolves |
| `getPath` split guard + `_getPath` join-collapse paranoia | App/Extensions.py:92-95, :47-54 | external-method names must be simple | config boundary anyway |
| `cookId` basename extraction | OFS/Image.py:1002-1010 | strips `/`, `\`, `:` from multipart filenames | only invoked when no explicit id given |
| lock checks + `_verifyObjectPaste` | webdav/NullResource.py:129-138/:181-185 | WebDAV object-creation authorization | ZODB-level, not path-level |

Also relevant: no symlink resolution/checks exist on request-derived paths (only
module-level `realpath` of fixed prefixes at App/ImageFile.py:32, special_dtml.py:40,
FindHomes.py:23-25) — symlink-based escapes are unmitigated but no in-repo path allows a
request to plant symlinks; recorded as "not applicable / unverified" for item 7 of the
review checklist.

## 6. Unresolved / low-confidence items

| item | confidence | why unresolved |
| --- | --- | --- |
| route_path_param sources (5) | 0.70 | filesystem reachability depends on external zope.traversing dispatch |
| resource.py:170 factory sink | 0.70 | external zope.browserresource performs the read; not in DB |
| ObjectManager.py:622 export write | 0.65 | compound precondition (slash-containing object id) |
| ObjectManager.py:679 importFile | 0.65 | guarded in practice; Windows ntpath + TOCTOU residuals |

No entry is at `unknown`; all are `candidate` with named manual-review points.

## 7. Checklist against the 10 review questions

1. **Sources from genuinely untrusted boundaries?** Yes for 270 source entries (WSGI
   environ, request object, form, headers, XML-RPC body, multipart filenames, URL segments,
   ZMI params). 45 entries (env/CLI/config) labeled `none`/`fp` — an internal/config
   parameter is not automatically a source.
2. **Path decoded/normalized/joined/object-converted before file access?** Tracked at each
   step: PATH_INFO PEP 3333 re-encode (WSGIPublisher.py:312-338) → object-tree traversal →
   bridge joins (resource.py:155, ObjectManager.py:621/:644) — all cited in evidence.
3. **Sinks are real file access?** Yes — `open`, `filestream_iterator` (io.FileIO), ZODB
   `importFile`, external resource factory read. `os.path.join`/string concat are treated as
   propagation, not sinks (they are not in the candidate set).
4. **Traversal variants?** `..`, absolute paths, backslash, drive-relative, double-decode:
   each analyzed per site (see §§3, 5). The split guards are platform-dependent; `..` is
   blocked only via dirname rejection; no in-repo `..` filtering exists in
   DirectoryResource.get or the export id join.
5. **Real pre-access root confinement?** Only the import split guard + fixed import roots
   (ObjectManager.py:643-651) and the Extensions guards. **No** containment check exists in
   DirectoryResource.get or manage_exportObject.
6. **Do normpath/basename/startswith/blacklist block escape here?** No normpath/startswith
   usage on these paths; `os.path.split` is effective for separator-containing names
   (platform caveat); cookId basename is effective; checkValidId is **not** sufficient for
   the export join.
7. **Symlinks?** No symlink handling on request-derived paths anywhere in src/ — recorded
   as not applicable (no request-controlled symlink placement exists in-repo).
8. **Authorized file serving?** ImageFile/PageTemplateFile/DTMLFile serving is
   ZCML-registered fixed content — labeled `fp`, not vulnerabilities.
9. **Tests / fixed constants / generated files?** tests/ and Testing/ excluded by the
   Phase 1 scope guard; fixed-constant sinks (ZopePageTemplate default content, inituser
   removal) labeled `fp`; the DB directory is structurally excluded.
10. **Complete untrusted→dangerous-path flow vs. local wrapper flow?** Complete flows exist
    only through the bridges in §3; the CLI/startup/config flows are local
    operator/developer-boundary flows and are labeled `fp` with that rationale.

## 8. Dedup / exclusion record

- Exact duplicate rows removed: **0** (checked on the full 10-column key).
- Candidates excluded outright: **0**. Non-attacker-boundary candidates were labeled
  `none`/`fp` with explicit rationale (env_config 12, cli_argv 5, cli_argv_param 12,
  config_path_param 16 source rows; 57 of 61 sink rows are config/CLI/guarded sites).

## 9. Output artifacts

- `labels/labels.json` — schema-valid, 376 entries
- `labels/labels_raw_pass1.json` — 12 batches, per-candidate decisions, batch policy,
  dedup record
- `labels/label_stats.md` — counts, families, confidence distribution, quality checks
- `labels/phase1_review.md` — this file

**Status: STOPPED after Step 3. Phase 2 (Step 4 library generation, Step 5 taint queries,
Step 6 filtering/report) has not been started, awaiting review approval.**
