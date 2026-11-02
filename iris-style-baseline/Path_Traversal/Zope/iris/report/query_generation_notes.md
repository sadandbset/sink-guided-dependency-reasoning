# Pass 1 Query Generation Notes — Path Traversal (Zope)

Augur Phase 2, Step 4 (library generation) and Step 5 preparation (pass query
rendering). Generated 2026-10-24 from the reviewed Pass 1 labels. **No CodeQL
compilation or analysis was executed in this step** — the six generated files
are `libraries/MySources.qll`, `libraries/MySinks.qll`,
`libraries/MySanitizers.qll`, `libraries/MySummaries.qll`,
`queries/Pass1_PathTraversal.ql` and this note.

## 0. Inputs actually read

- `iris_tools/augur-0.3.0/WORKFLOW.md` (Phase 2, sections 5.1/5.2, template
  substitution guide 5.2.1a), `assets/taint_query.ql.tmpl`,
  `references/python.md`, `references/patterns.md` (no `references/zope.md`
  exists — as recorded in `exploration/detection.json`).
- `iris/labels/labels.json` (376 entries; pass_id=1, cwes 022/023/036/073),
  `iris/labels/phase1_review.md` (the Step 3 human-review payload).
  **`iris/labels/review_decision.json` does not exist** — Step 3 wrote only the
  optional review payload; per WORKFLOW.md 4.5 the decision file is an optional
  audit artifact, and the reviewed `labels.json` is taken as the approval
  basis. No label was modified; no omission requiring a return to the Step 3
  review was found (all 270 source-role and 61 sink-role entries are modeled
  below; the 9 `candidate`-classified entries are kept as-is so the query will
  surface them for the intended human triage).
- Zope_vuln source code at every site cited below (read-only).
- Installed CodeQL packs (for API verification only, no queries run):
  `codeql/python-all 7.1.1/7.1.2`, `codeql/dataflow 2.1.x`.

## 1. Template substitution record (WORKFLOW.md 5.2.1a)

| placeholder | value |
| --- | --- |
| QUERY_NAME | Pass 1: Untrusted request input in filesystem path arguments |
| QUERY_DESCRIPTION | flows from reviewed request boundaries into filesystem path arguments |
| QUERY_ID | py/augur/zope/pass1-path-traversal |
| PRECISION | medium (signature-anchored sources/sinks with name+file constraints; stdlib propagation; no containment check exists in the two candidate bridges, so precision cannot honestly be high) |
| CWE_PRIMARY / EXTRA_TAGS | 022, 023, 036, 073 |
| LANGUAGE_IMPORTS | `import python`, `import semmle.python.dataflow.new.DataFlow`, `import semmle.python.dataflow.new.TaintTracking` |
| SOURCE/SINK/SANITIZER/SUMMARY_MODULE | `libraries.MySources` / `libraries.MySinks` / `libraries.MySanitizers` / `libraries.MySummaries` (imported with dotted paths; predicates referenced as `MySources::isSource` etc. — all four predicate interfaces exist and take `(DataFlow::Node, string passKey)` / `(DataFlow::Node, DataFlow::Node, string)`) |
| CONFIG_NAME / FLOW_MODULE | `Pass1Config` / `Pass1Flow` |
| PASS_KEY | `path_traversal` |
| RESULT_MESSAGE | "Untrusted request input reaches a filesystem path argument (potential path traversal, CWE-22/23/36/73)." |

Metadata on the query: `@kind path-problem`, `@problem.severity error`,
`@tags security` + the four CWE tags; barrier hook present via
`Pass1Config.isBarrier` delegating to `MySanitizers` (never removed, per
WORKFLOW.md 5.2.3). `qlpack.yml` remains at the iris root
(`iris/zope-cwe22`, dep `codeql/python-all: "*"`).

## 2. Label id → MySources.qll rule mapping (270 entries modeled)

API idioms verified against the installed `codeql/python-all 7.1.2`:
`DataFlow::Node.asExpr()`, `DataFlow::ParameterNode.getParameter()`,
`Call.getFunc()/getArg(int)`, `Attribute.getName()/getObject()`,
`Subscript.getObject()`, `Name.getId()`, `Parameter.getName()`,
`Function.getAnArg()/getName()`, `AstNode.getLocation().getFile().getBaseName()`,
`getScope().(Function)`. Parameter sources are matched as
`source.(DataFlow::ParameterNode).getParameter() = p` (parameter-at-entry
value), lookup/subscript/attribute sources as the value node of the
expression. File-base-name anchors were checked for uniqueness in the DB tree
(duplicate base names exist only for `PropertySheets.py`,
`metaconfigure.py`, `utils.py`, `marker.py`, `__init__.py`,
`interfaces.py`; the two `PropertySheets.py` files are disambiguated by
function name, and every file-name set deliberately excludes
`interfaces.py`/`OFS/interfaces.py` and `webdav/interfaces.py`, which the
Phase 1 scope guard also excluded as non-executable interface stubs).

| MySources rule | label ids (count) | external input boundary / access conditions |
| --- | --- | --- |
| `isWsgiBoundaryParameter` | p1-src-005, 006, 244 (3) | raw WSGI environ + body stream at `HTTPRequest.__init__(stdin, environ, ...)` (ZPublisher/HTTPRequest.py:306) and `publish_module(environ, start_response)` (WSGIPublisher.py:302). Outermost untrusted boundary: PATH_INFO, QUERY_STRING, HTTP_*, CONTENT_LENGTH, body. No authentication — this is the transport boundary itself. |
| `isPublishedEntryRequestParameter` | p1-src-188 (1) | `publish(request, module_info)` (WSGIPublisher.py:234): the published request object carrying form/cookies/headers/environ/BODY; drives processInputs, PATH_INFO traversal (:252-255) and mapply (:271). |
| `isWebDavVerbRequestParameter` | p1-src-024, 025, 257–286 (32) | REQUEST/request parameter of WebDAV verb handlers (HEAD/PUT/MKCOL/LOCK/UNLOCK/PROPFIND/PROPPATCH/COPY/MOVE/DELETE/TRACE/OPTIONS) and `dav__init` hooks (webdav/Resource.py:203–665, NullResource.py:90–473, Collection.py:63/76/85, OFS/Application.py:158/163, DTMLMethod.py:371, Image.py:641, App/ImageFile.py:124, ZopePageTemplate.py:348). Unauthenticated request object; the handlers themselves are `@security.protected`-gated per verb. PUT bodies are stored into ZODB objects, not the filesystem. |
| `isZmiFormParameter` | p1-src-298–315 (18) | `id`/`file` parameters of ZMI `manage_*` published methods (ObjectManager.py:636/:589, Image.py:58/:734/:533, DTMLMethod.py:297, Folder.py:35, OrderedFolder.py:26, CopySupport.py:348/:403, OrderSupport.py:240, PropertyManager.py:279, PropertySheets.py:331/:470, VirtualHostMonster.py:257, ZopePageTemplate.py:370). Marshalled from request form values by mapply (WSGIPublisher.py:271); permission-gated (e.g. `import_export_objects`, ObjectManager.py:588) but HTTP-reachable. |
| `isTraversalPathParameter` | p1-src-287–291 (5, classification candidate) | `path`/`url`/`URL` of `BaseRequest.traverse` (BaseRequest.py:353, fed `request.get('PATH_INFO')` at WSGIPublisher.py:255), `HTTPRequest.resolve_url` (:1161), `physicalPathFromURL` (:253), `Traversable.unrestrictedTraverse/restrictedTraverse` (Traversable.py:152/:362; request-driven call at OFS/Cache.py:522 with a form-derived path). URL-derived, unauthenticated; traverse the ZODB object tree — kept because segments feed the bridges. |
| `isUrlSegmentParameter` | p1-src-292, 293, 294 (3) | URL path segments as names: `NullResource.__init__` / `LockNullResource.__init__` `name` (NullResource.py:72/:324, constructed with the not-found URL segment at ObjectManager.py:739; `_setObject` at :189 applies checkValidId) and `DirectoryResource.get(name)` (resource.py:153) — the ++resource++ segment joined onto a registered filesystem directory at :155. Unauthenticated URL data. |
| `isRequestGetLookupValue` | p1-src-026–058, 083–085, 176–187, 189 (49) | `.get()` calls on request-like receivers (request/REQUEST/self.request/root.REQUEST/app.REQUEST/REQUEST.form/request.environ) — `HTTPRequest.get` merged namespaces (HTTPRequest.py:1250); plus the `get_env = environ.get` alias (:323). Form/cookie/header-derived values are attacker-controlled; per-key trust varies (server-only keys are not path-shaped). |
| `isRequestSubscriptValue` | p1-src-059–080, 086–169 (106) | `request[...]`/`environ[...]` subscripts (`HTTPRequest.__getitem__`, HTTPRequest.py:1381; observed keys BODYFILE/BODY/URL/id). Same trust profile as the `.get` family. |
| `isRequestFormFieldValue` | p1-src-081, 082, 170–174 (7) | `REQUEST.form` / `request.form` reads — parsed request form (OFS/Cache.py:518→restrictedTraverse at :522, PropertyManager.py:303/305/327, Five/component/browser.py:29). Attacker-controlled query/form values. |
| `isRequestEnvironmentValue` | p1-src-015–018 (4) | `request.environ` reads (BaseRequest.py:709/710, WSGIPublisher.py:262) — raw WSGI environ at request time; HTTP_* entries attacker-controlled. |
| `isRequestHeaderValue` | p1-src-190–227 (38) | `REQUEST.get_header` / `request.get_header` calls (`HTTPRequest.getHeader`, HTTPRequest.py:1231, alias :1248) — environ['HTTP_*'], fully attacker-controlled header text (If/Depth/Timeout/Lock-Token/content-type, If-Modified-Since/Range). |
| `isMultipartFilenameValue` | p1-src-295–297 (3) | `file.filename` (OFS/Image.py:1004), `item.filename` (HTTPRequest.py:536), `aFieldStorage.filename` (:1664) — client-controlled, path-shaped multipart filenames; only these three receiver names in Image.py/HTTPRequest.py are matched (the FileUpload wrapper is :1653–1697). |
| `isXmlRpcArgumentsValue` | p1-src-175 (1) | `xmlrpc.parse_input(fs.value)` return (HTTPRequest.py:513) — XML-RPC arguments from the text/xml POST body, marshalled into published-method parameters by mapply (WSGIPublisher.py:271). |

**Not modeled (role `none`, 45 entries):** env_config p1-src-001–004, 007–014
(`os.environ` reads: operator/deployment config); cli_argv p1-src-019–023
(`sys.argv` subscripts); cli_argv_param p1-src-245–256 (console utility path
params: zconsole/copyzopeskel/mkwsgiinstance/serve); config_path_param
p1-src-228–243 (ZCML-registration-time path params: ImageFile/PageTemplateFile/
ClassicHTMLFile/DTMLFile/ResourceFactory/Directory/Extensions lookups). These
are operator/developer boundaries with no request reachability — matching the
reviewed labels exactly. No parameter of an internal wrapper was promoted to
a source to manufacture a path.

## 3. Label id → MySinks.qll rule mapping (61 entries, signature-deduplicated)

Sinks match the **path-text argument position** (index 0, or index 1 for the
copy destination / resource-factory filename). File objects returned by
`open`/`filestream_iterator` are never sinks. The Phase 1 extraction was
repo-wide, so each signature below reproduces exactly its labeled call sites
(tests and `Testing/` are outside the DB scope).

| MySinks rule | signature (arg index) | real operation / access type | label ids | call-site relationships |
| --- | --- | --- | --- | --- |
| `isBuiltinOpenSink` | `open` (0) | file read / write / create | p1-snk-339–349 (11) | write: ObjectManager.py:622 (manage_exportObject, `f'{id}.zexp'` under CONFIG.clienthome — candidate); read: App/Extensions.py:178 (external-method source, exec'd at :184), App/ImageFile.py:72 (registration-time sniff), PageTemplateFile.py:194 (debug-mode re-read), ZopePageTemplate.py:115 (fixed default), zconsole.py:20, copyzopeskel.py:221/226, serve.py:236, mkwsgiinstance.py:191, startup.py:52 (CLI/startup). |
| `isOsPathCheckSink` | `os.path.exists/isdir/isfile/getmtime` (0) | existence / metadata probe (TOCTOU-relevant) | p1-snk-316–336, 354, 365–374 (32) | resource.py:156/:157 (URL-derived join — candidate), ObjectManager.py:645 (request-derived import path, guarded), ObjectManager.py:707, Extensions.py:61/:144, Application.py:352/356–358, PageTemplateFile.py:160, ZCML metaconfigure/fiveconfigure/viewlet sites, zcml.py:38, serve.py:234, mkwsgiinstance/copyzopeskel checks. |
| `isOsModuleSink` | `os.stat` (0), `os.listdir` (0), `os.walk` (0), `os.remove` (0), `os.makedirs` (0) | metadata read / directory enumeration / recursive enumeration / deletion / directory creation | p1-snk-350–351, 337–338, 356, 376, 355 (6) | special_dtml.py:78 and ImageFile.py:84 (registered paths), ObjectManager.py:709 + Application.py:370 (fixed dirs), copyzopeskel.py:181/172 (CLI), userfolder.py:309 (fixed inituser removal). |
| `isShutilCopySink` | `shutil.copyfile` (0, 1), `shutil.copymode` (0, 1) | file copy / permission-mode copy | p1-snk-357–364 (8) | copyzopeskel.py:214/215/229 (CLI skeleton copy, operator boundary). |
| `isFilestreamIteratorSink` | `filestream_iterator` (0) | construction opens the file (io.FileIO subclass) and iteration streams it as the HTTP response body — file-response sink | p1-snk-352 (1) | App/ImageFile.py:121, path fixed at ZCML registration (ImageFile.py:57-58) — not request-controlled. |
| `isZodbImportFileSink` | `connection.importFile` (0) | object-export import; the ZODB connection (external) opens the zexp/xml file | p1-snk-353 (1) | ObjectManager.py:679, `filepath = os.path.join(impath, 'import', file)` after the :639-641 split guard (barrier in MySanitizers). |
| `isResourceFactorySink` | `factory(name, filename)` (1) | constructs the external zope.browserresource File/Image/PageTemplate resource which performs the actual file read when served | p1-snk-375 (1) | resource.py:170, `filename = os.path.join(path, name)` from :155 with the URL-derived ++resource++ segment (candidate). Anchored to resource.py because `factory` is a local variable. |

## 4. Path joining / decoding / normalization, allowed roots, symlink evidence

All statements verified in the Zope_vuln source (see also
`exploration/detection.json` → `security_evidence`):

- **Joining**: `os.path.join` at the three request-derived bridges —
  resource.py:155 (registered resource dir + URL segment),
  ObjectManager.py:621 (CONFIG.clienthome + `f'{id}.zexp'`),
  ObjectManager.py:644 (fixed import root + request file name). Taint
  propagation through `os.path.join` is provided by the standard library
  (`Stdlib.qll OsPathJoinCallAdditionalTaintStep` / `OsPathComputation`), so no
  custom step was added.
- **Decoding**: PATH_INFO is latin-1→utf-8 re-encoded per PEP 3333 at
  WSGIPublisher.py:312-338 (percent-decoding itself happens in the WSGI
  server, outside this repo); `unquote` appears in
  `HTTPRequest.physicalPathFromURL` (:271) on URL segments and in cookie
  parsing (:1721-1745). No decoding step is modeled in MySummaries: the
  reviewed sources sit after decoding (request lookups, traversal params,
  ++resource++ name), so an additional edge is not evidence-backed.
- **Normalization**: no `normpath`/`abspath`/`realpath`/`resolve` on any
  request-derived path. `os.path.realpath` appears only on fixed module-level
  prefixes (App/ImageFile.py:32, special_dtml.py:40, FindHomes.py:23-25).
  `os.path.isabs` only at ImageFile.py:52 (registration-time path).
  Consequently **none** of these functions is treated as a sanitizer, and none
  is needed as a step.
- **Allowed roots**: export base `CONFIG.clienthome` (ObjectManager.py:621);
  import bases `CONFIG.instancehome`/`CONFIG.clienthome` + `'import'`
  (:643-645, :695-701); resource base `self.context.path` registered at ZCML
  time (resource.py:154-155); Extensions bases `cfg.instancehome`/`cfg.extensions`
  /`Products.__path__`. Containment is **not** verified after the join at the
  export and ++resource++ bridges (no `startswith`/`relative_to`/prefix check
  anywhere on those paths) — which is exactly why those two flows remain
  alert-producing candidates.
- **Symlinks**: no symlink resolution or check on request-derived paths
  anywhere in src/ (grep-verified; only the fixed-prefix realpath above).
  There is also no request-reachable API that creates symlinks, so
  TOCTOU-via-symlink planting is not a modeled mechanism; recorded as not
  applicable rather than assumed safe.
- **Timing**: the only time-of-check/time-of-use gaps are
  ObjectManager.py:645→:679 (exists → importFile) and
  resource.py:156-157→:170 (probe → factory read) and
  PageTemplateFile.py:160→:194. They are documented; the existence checks are
  sinks (labeled), not barriers.

## 5. Barrier justification (MySanitizers.qll)

labels.json has **zero** `sanitizer`-role entries; the single implemented
barrier comes from the guard inventory in the reviewed
`labels/phase1_review.md` §5:

| barrier | location | what it provably blocks | why it is a real barrier here |
| --- | --- | --- | --- |
| import-file name guard | OFS/ObjectManager.py:639-641, modeled on the `os.path.split(file)` call node inside `manage_importObject` | any request `file` value containing a path separator, before the join (:644) and the `connection.importFile` open (:679) | the guard raises `BadRequest` when `dirname` is non-empty, and the split result (both tuple elements) is what flows onward; pruning the flow at the call node models "the reassigned `file` is separator-free". Standard propagation into the split result exists (`OsPathComputationAdditionalTaintStep`), so without this barrier the tracker would (incorrectly, per the reviewed fp labels) reach the :645/:679 sinks. |

Residual risks intentionally NOT modeled as safe (manual-review notes): on
Windows ntpath, a drive-relative name (`C:x`) passes the split guard while
`os.path.join` resets to the drive; and the :645→:679 TOCTOU window. Both are
recorded here and in the label rationales; they do not change the barrier's
blocking of the separator-based mechanism on the modeled (POSIX-shape) paths.

Guards evaluated and deliberately **not** made barriers:
`checkValidId` (ObjectManager.py:84-115 — does not reject `/` or embedded
`..`, so it cannot block the export join); `cookId` basename (Image.py:1002-1010
— proven over `/`, `\`, `:` but its output only feeds ZODB object ids, which
have no filesystem sink in this model); `App/Extensions.getPath` guards
(:92-95 split rejection, :47-54 join-collapse ValueError — config boundary,
no source reaches them); WebDAV lock/`_verifyObjectPaste` checks (ZODB
authorization, not path neutralization). No function was made a barrier based
on its name alone.

## 6. Additional propagation, unmodeled gaps, diagnostics

**Additional steps required: none.** Every wrapper needed for connectivity is
already in the standard library (verified in the installed pack):
`os.path.*` path computations incl. join/split (Stdlib.qll), f-string
interpolation piece→literal (TaintTrackingPrivate.qll, Fstring), subscript
container→value (same file, SubscriptNode), tuple unpacking
(IterableUnpacking.qll). `MySummaries::isAdditionalTaintStep` therefore
resolves to `none()` — inventing cross-function edges (e.g. mapply argument
dispatch) would violate the no-unwarranted-propagation rule.

**Dynamic dispatch / aliasing gaps (documented, unmodeled):**
- `mapply(obj, request.args, request, ...)` (WSGIPublisher.py:271) marshals
  form/XML-RPC values into published-method parameters dynamically; the
  tracker cannot follow it. Mitigated: the published-method parameters
  themselves are reviewed sources (zmi_form_param family).
- `resource_factories[ext]` dict dispatch at resource.py:165-170: the factory
  call is modeled as a sink at arg 1, but what the external
  zope.browserresource object does with `filename` afterwards is outside the
  DB.
- `ZODB Connection.importFile` opens the file inside the external ZODB
  package — modeled as the sink itself.
- receiver-name matching for request lookups (`request`, `REQUEST`,
  `environ`, `self.request`, `root.REQUEST`, `app.REQUEST`, `REQUEST.form`,
  `request.environ`) reproduces the extracted receiver set; other rebinding
  of request APIs (beyond the labeled `get_env`/`get_header` aliases) would be
  missed.
- `os.path` functions are matched as `os.path.<f>` attribute calls only — no
  labeled site uses `from os.path import ...` (verified by inspection of all
  labeled call sites).

**CodeQL limitations:** path-problem `select` carries the sink node and path
nodes only; the `@precision medium` rating reflects the broad request-lookup
source families and the platform-dependent guard semantics.

**Diagnostic paths (not formal Pass 1 alerts):** if wrapper behavior needs
debugging before the formal run, a separate diagnostics query (e.g. counting
`MySources::isSource`/`MySinks::isSink`/`MySanitizers::isBarrier` matches, or
`DataFlow::localFlow` probes around resource.py:155 and ObjectManager.py:621)
can be written under `iris/diagnostics/` — the directory reserved for that
purpose in this workspace. No such query is part of this deliverable, and
nothing in `iris/diagnostics/` counts as a Pass 1 finding.

## 7. Expected alert surface (prediction, to be confirmed only by the formal Step 5 run)

Based on the model and the reviewed labels:
- `manage_exportObject` id → `open` at ObjectManager.py:622 (p1-snk-343,
  candidate) via f-string + join.
- `DirectoryResource.get` name → `os.path.isfile`/`os.path.isdir` at
  resource.py:156/:157 (p1-snk-369/318, candidate) and → `factory(name,
  filename)` at :170 (p1-snk-375, candidate) via join.
- `manage_importObject` file → `os.path.exists` at ObjectManager.py:645
  (p1-snk-325) / `connection.importFile` at :679 (p1-snk-353) is **cut** by
  the barrier, matching the fp classification of those sinks.
- Config/CLI sink sites have no reachable source and cannot alert.
- The five `route_path_param` candidate sources traverse the ZODB object tree
  only; within the DB no path connects them to a filesystem sink, so they are
  not expected to alert.

## 8. Experiment independence

- No PyVul ground truth, CVE descriptions or patch diffs were consulted; the
  model derives exclusively from the reviewed Pass 1 labels, the Augur
  workflow/reference files, and read-only inspection of the Zope_vuln source.
- No source file, CodeQL database file, or Phase 1 artifact
  (`extraction/*.csv|ql|bqrs`, `labels/labels.json`,
  `exploration/detection.json`) was modified.
- Only the six files listed at the top were created; no compilation or
  analysis was run.
