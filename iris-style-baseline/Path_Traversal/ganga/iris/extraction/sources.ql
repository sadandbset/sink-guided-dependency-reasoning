/**
 * @name ganga CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   ganga CodeQL database (Ganga 8.4.2, CERN workload management framework -
 *   the ganga/ package tree is the audit target): the two Flask route-path
 *   file browsers of the GangaGUI web GUI (the `path` parameters of
 *   job_browse at GangaGUI/gui/routes.py:639 - the
 *   @gui.route("/job/<int:job_id>/browse/<path:path>") registrations at
 *   :636-:637 whose value is joined onto the job base directory with
 *   abs_path = os.path.join(job_base_dir, path) at :659 and reaches
 *   os.path.exists :665 / os.path.isfile :670 / send_file :671 /
 *   os.listdir :676, and of storage_page at :925 - the
 *   @gui.route("/storage/<path:path>") registrations at :922-:923 whose
 *   value is joined onto the storage folder at :934 and reaches
 *   isdir :949 / exists :969 / isfile :974 / send_file :975 / listdir :980
 *   and the upload save destination join at :954 - NO containment guard in
 *   either flow); the internal-API request query parameters (the
 *   request.args.get("path") reads at GangaGUI/api/routes.py:223 - the
 *   /internal/jobs/<job_id>/export route at :212 whose value is passed to
 *   the GPI export write, :977 - /internal/load whose value is passed to
 *   the GPI load read, and :1001 - /internal/runfile whose value is passed
 *   to runpy execution; plus ~50 further request.args.get filter
 *   parameters); the request form fields (request.form.get /
 *   request.form[...] incl. the file-content channels runfile-data
 *   gui/routes.py:374 -> open :375, edited-job-info :604 -> open :606,
 *   config-data :272 -> open :273); the request JSON bodies
 *   (request.json / request.json.get of the two job-create endpoints);
 *   the multipart upload boundary (request.files["storagefile"] :941,
 *   ["loadfile"] :294, ["runfile"] :320 and their .filename reads);
 *   the request header boundary (request.headers["X-Access-Token"]
 *   gui/routes.py:1084); and the environment-variable boundary
 *   (os.environ.get / os.getenv - GANGA_CONFIG_FILE config-path selection
 *   bootstrap.py:336, scratch-dir and X509-proxy selection - OPERATOR
 *   trust level, recorded for labeling to classify, not automatically
 *   attacker sources). Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not
 *   database analyze). This is a plain multi-column select query on
 *   purpose: @kind problem is the wrong shape for candidate tables and
 *   @kind table is not assumed to exist.
 * @id iris/ganga/extraction/sources
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field name (the handler function name
 *                   for parameter rows, "get", "args", "form", "json",
 *                   "files", "filename", "headers", "getenv")
 *   4. flow_kind  - "http_path_param" (the `path` parameter of the two
 *                   Flask path-converter browser routes),
 *                   "http_query_param" (request.args.get(...) call or the
 *                   request.args[...] subscript),
 *                   "http_form_param" (request.form.get(...) call or the
 *                   request.form[...] subscript),
 *                   "http_json" (request.json attribute read or the
 *                   request.json.get(...) call),
 *                   "http_file_upload" (request.files[...] subscript - the
 *                   werkzeug FileStorage boundary),
 *                   "upload_filename" (the .filename attribute read on the
 *                   uploaded FileStorage objects),
 *                   "http_header" (request.headers[...] subscript),
 *                   "env" (os.environ.get / os.getenv reads - operator
 *                   trust level)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "request"/"request.args"/"request.form"/
 *                   "request.json"/"request.files"/"request.headers"/
 *                   "os.environ"/"os" etc., or "" if none; "" for
 *                   parameter rows - the enclosing function is reported
 *                   via callable)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hint "os" for the env channel
 *   7. arg_index  - 0-based positional argument index (index of the key
 *                   argument for keyed reads such as args.get(key),
 *                   args[key], form.get(key), form[key], files[key],
 *                   headers[key], environ.get(name), getenv(name); -1 when
 *                   the tainted value is the return value or the attribute
 *                   itself; the parameter position in the function
 *                   definition for "http_path_param" rows)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced
 * a row). In this project no source row is expected to resolve at API level:
 * flask/werkzeug are external libraries not part of the database (only the
 * ganga/ tree is), the request-object reads flow through the flask request
 * proxy accessed by local name, and the parameter rows are plain
 * definitions. All families below are AST-level matches and the match_kind
 * column is kept "ast" for cross-project contract consistency with the
 * prior projects of this series
 * (aiohttp/airflow/ansible/coderedcms/copyparty/dfetch/django/fides).
 *
 * Receiver-name scoping: the http families match attribute chains whose
 * base local name is exactly "request" (the `from flask import request`
 * import style used throughout GangaGUI); a handler renaming the local
 * would be missed (recorded in detection.json uncoveredCases).
 *
 * Excluded paths (applied to every row, in addition to the positive scope):
 * GangaTest/ (test-runner plugin package), /test/, /old_test/, /testlib/
 * (test fixtures/harnesses of every package), and the two stray test
 * modules GangaCore/Utility/Config/tests.py and
 * GangaCore/Utility/logging/test.py. The CodeQL database ganga-db sits in
 * the source ROOT as a sibling of the ganga/ package, so the positive
 * scope %/ganga/% excludes it by construction; a defensive filter is kept
 * in excludedPath anyway. Repo-root build/test tooling (setup.py,
 * conftest.py, postBuild, bin/) and doc/ are never candidates.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Top-level scripts that are not on an import path
 *  have no dotted module name; their file base name is used instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getShortName()
}

/** Forward-slash-normalized absolute path of the file containing n, so path
 *  matching works with both CodeQL path styles on Windows. */
string normalizedPathOf(AstNode n) {
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
}

/** Base name of the object expression of an attribute access, used as a receiver hint. */
string receiverHint(Attribute a) {
  result = a.getObject().(Name).getId()
  or
  result = a.getObject().(Attribute).getName()
  or
  not a.getObject() instanceof Name and
  not a.getObject() instanceof Attribute and
  result = "<expr>"
}

/** True iff the candidate's file path is one of the excluded trees. Path is
 *  normalized to forward slashes before matching so the query works on both
 *  CodeQL path styles. bindingset[path] declares that the caller passes a
 *  bound path (the path only appears in checked positions such as the
 *  receiver of replaceAll/matches inside this predicate). */
bindingset[path]
predicate excludedPath(string path) {
  path.replaceAll("\\", "/").matches("%/ganga-db/%")
  or
  path.replaceAll("\\", "/").matches("%/GangaTest/%")
  or
  path.replaceAll("\\", "/").matches("%/test/%")
  or
  path.replaceAll("\\", "/").matches("%/old_test/%")
  or
  path.replaceAll("\\", "/").matches("%/testlib/%")
  or
  path.replaceAll("\\", "/").matches("%/GangaCore/Utility/Config/tests.py")
  or
  path.replaceAll("\\", "/").matches("%/GangaCore/Utility/logging/test.py")
}

/** True iff the candidate is inside the audited ganga package tree (positive
 *  scope; the shipped python packages GangaCore/GangaGUI/GangaService plus
 *  the experiment plugins). Same bindingset rationale as excludedPath. */
bindingset[path]
predicate inScope(string path) {
  path.replaceAll("\\", "/").matches("%/ganga/%")
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: the Flask path-converter route parameters - the `path`
     parameters of job_browse (gui/routes.py:639, route registrations
     :636-:637 "/job/<int:job_id>/browse/<path:path>" - joined onto the job
     base dir at :659, then exists :665 / isfile :670 / send_file :671 /
     listdir :676) and of storage_page (:925, registrations :922-:923
     "/storage/<path:path>" - joined onto the storage folder at :934, then
     isdir :949 / exists :969 / isfile :974 / send_file :975 / listdir :980
     and the upload save destination :954). Flask injects the decoded
     request path (the path converter allows '/' and '..' segments); there
     is NO containment guard in either flow. Parameter positions:
     job_browse(job_id, path) -> path at 1; storage_page(path) -> 0. */
  exists(Function f, Parameter p |
    (f.getName() = "job_browse" or f.getName() = "storage_page") and
    normalizedPathOf(f).matches("%/ganga/GangaGUI/gui/routes.py") and
    p.getName() = "path" and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "http_path_param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 2: request query parameters - request.args.get(...) calls
     (api/routes.py:223 - the export WRITE path, :977 - the load READ path,
     :1001 - the runfile EXECUTION path, plus ~50 job/template filter
     parameters across api/routes.py and gui/routes.py:408/:710) and the
     request.args[...] subscripts (api/routes.py:268/:458
     request.args["ids"]). Argument 0 carries the key; the returned value
     is the untrusted data. */
  exists(Call c, Attribute func, Attribute args |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    args = func.getObject().(Attribute) and
    args.getName() = "args" and
    args.getObject().(Name).getId() = "request" and
    node = c and
    flowKind = "http_query_param" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "request.args" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "args" and
    base.getObject().(Name).getId() = "request" and
    node = s and
    flowKind = "http_query_param" and
    callableName = "args" and
    argIndex = 0 and
    receiver = "request" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 3: request form fields - request.form.get(...) calls and the
     request.form[...] subscript (gui/routes.py:272
     request.form['config-data'] -> open(gui_rc, 'w') at :273). The
     file-CONTENT channels: runfile-data (:374 -> open(runfile_path, 'w+')
     :375, then executed via /internal/runfile), edited-job-info
     (:604 -> open(loadfile_path, 'w+') :606), config-data (:272); the rest
     are login/pagination/filter fields. Argument 0 carries the key. */
  exists(Call c, Attribute func, Attribute form |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    form = func.getObject().(Attribute) and
    form.getName() = "form" and
    form.getObject().(Name).getId() = "request" and
    node = c and
    flowKind = "http_form_param" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "request.form" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "form" and
    base.getObject().(Name).getId() = "request" and
    node = s and
    flowKind = "http_form_param" and
    callableName = "form" and
    argIndex = 0 and
    receiver = "request" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 4: request JSON bodies - the bare request.json attribute reads
     (api/routes.py:86/:139, gui/routes.py:1048/:1258 - the job-create
     endpoints; each `request.json if request.json else {}` conditional
     yields two attribute nodes) and the request.json.get(...) calls
     (gui/routes.py:1188/:1189 - template_id/job_name). The attribute VALUE
     carries the parsed body, hence argIndex -1; the .get call form carries
     the key in argument 0. */
  exists(Attribute a |
    a.getName() = "json" and
    a.getObject().(Name).getId() = "request" and
    node = a and
    flowKind = "http_json" and
    callableName = "json" and
    argIndex = -1 and
    receiver = "request" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func, Attribute json |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    json = func.getObject().(Attribute) and
    json.getName() = "json" and
    json.getObject().(Name).getId() = "request" and
    node = c and
    flowKind = "http_json" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "request.json" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 5: the multipart upload boundary - request.files[...] subscripts
     (gui/routes.py:941 request.files["storagefile"] - the storage upload
     whose save destination joins the ROUTE path at :954; :294
     request.files["loadfile"] and :320 request.files["runfile"] - the
     create-page uploads saved to FIXED server paths :301/:327). Argument 0
     carries the key; the FileStorage VALUE is the untrusted data. */
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "files" and
    base.getObject().(Name).getId() = "request" and
    node = s and
    flowKind = "http_file_upload" and
    callableName = "files" and
    argIndex = 0 and
    receiver = "request" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 6: uploaded filename reads - the .filename attribute reads on
     the three FileStorage locals (gui/routes.py:942
     storagefile.filename - fed to secure_filename :953 then the save
     destination join :954; :295 loadfile.filename and :321
     runfile.filename - fed to the allowed_file extension check
     :300/:326). The attribute VALUE carries the client-supplied filename,
     hence argIndex -1. */
  exists(Attribute a |
    a.getName() = "filename" and
    (a.getObject().(Name).getId() = "storagefile"
     or a.getObject().(Name).getId() = "loadfile"
     or a.getObject().(Name).getId() = "runfile") and
    normalizedPathOf(a).matches("%/ganga/GangaGUI/gui/routes.py") and
    node = a and
    flowKind = "upload_filename" and
    callableName = "filename" and
    argIndex = -1 and
    receiver = a.getObject().(Name).getId() and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 7: the request header boundary - request.headers[...] subscripts
     (gui/routes.py:1084 token = request.headers["X-Access-Token"] - the
     JWT auth token of the GUI token endpoint; auth material, not a path
     channel, recorded for labeling completeness). Argument 0 carries the
     key. */
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "headers" and
    base.getObject().(Name).getId() = "request" and
    node = s and
    flowKind = "http_header" and
    callableName = "headers" and
    argIndex = 0 and
    receiver = "request" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 8: environment-variable reads - os.environ.get(...) calls
     (GangaCore/Runtime/bootstrap.py:336 GANGA_CONFIG_FILE - the CLI config
     file path selection; GangaCore/Utility/Config/__init__.py:52
     GANGA_CONFIG_FILE or ~/.gangarc; plus further .get reads) and
     os.getenv(...) calls (~24 sites: scratch-dir selection EDG_WL_SCRATCH/
     TMPDIR in GangaCore/Lib/LCG/ARC.py:534-:537/CREAM.py:563-:566/
     LCG.py:1127-:1130, X509_USER_PROXY VomsProxy.py:159 and
     GangaDirac DiracProxy.py:161/DiracUtilities.py:72, KRB5CCNAME
     AfsToken.py:135, HOME/USER feedback_report.py:227/:475/:579).
     OPERATOR trust level - emitted for labeling to classify, not assumed
     attacker sources. Argument 0 carries the variable name. The
     `environ.get` bare-name form (from os import environ) and the
     os.environ[...] subscript reads (bootstrap.py:673 GANGA_CONFIG_PATH,
     :723 GANGA_SITE_CONFIG_AREA) are NOT matched - documented in
     detection.json uncoveredCases (subscript read/write shape ambiguity). */
  exists(Call c, Attribute func, Attribute environ |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    environ = func.getObject().(Attribute) and
    environ.getName() = "environ" and
    environ.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "env" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "getenv" and
    func.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "env" and
    callableName = "getenv" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  inScope(node.getLocation().getFile().getAbsolutePath()) and
  not excludedPath(node.getLocation().getFile().getAbsolutePath())
select
  node,
  "source_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
