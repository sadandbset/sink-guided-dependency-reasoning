/**
 * @name coderedcms CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   coderedcms CodeQL database (coderedcms 0.22.2, snapshot sha acc37d2c, a
 *   Wagtail 2.14 / Django 3.x CMS): the protected-media URL route variable
 *   (the `path` parameter of serve_protected_file, injected by urls.py:21-25
 *   re_path(r'^(?P<path>.*)$' under PROTECTED_MEDIA_URL and joined onto
 *   PROTECTED_MEDIA_ROOT + open()ed in views.py:114-:117); Django request
 *   field reads (request.GET/POST/FILES/META attribute reads,
 *   request.<field>.get(...) calls and request.<field>[...] subscripts in
 *   views.py, page_models.py, wagtail_flexible_forms and templatetags);
 *   request.session / self.request.session reads (incl. .get and [...] forms)
 *   and request.session.session_key reads (server-generated session id used
 *   as the upload directory component); multipart upload filename reads
 *   (file.name / val.name / value.name flowing into str(Path(directory) /
 *   name) destination construction); uploaded file content reads
 *   (file.chunks / val.chunks / form.cleaned_data['file'].read); the
 *   DB-submission boundary (json.loads of submission.form_data /
 *   thumbnails_by_path / self.data / subscriber_json_data whose values were
 *   user-supplied at form-submission time and are re-used as file paths);
 *   the CLI boundary (sys.argv and the argparse options dict of
 *   coderedcms/bin/coderedcms.py CreateProject.handle - operator trust
 *   level); and cr_settings[...] configuration subscripts (deployment-level
 *   constants, kept for the labeling step to judge). Raw BQRS extraction
 *   query: run with `codeql query run` and decode with `codeql bqrs decode`
 *   (not database analyze). This is a plain multi-column select query on
 *   purpose: @kind problem is the wrong shape for candidate tables and
 *   @kind table is not assumed to exist.
 * @id iris/coderedcms/extraction/sources
 * @tags path-traversal
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sinks.ql and to the prior IRIS manual
 * projects aiohttp/airflow/ansible):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field name (e.g. "serve_protected_file",
 *                   "get", "GET", "session_key", "name", "chunks", "loads",
 *                   "argv", "options", "cr_settings")
 *   4. flow_kind  - "route_param" (URL-injected view kwarg), "http" (Django
 *                   request field read), "session" (request.session read),
 *                   "session_key" (request.session.session_key read),
 *                   "upload_name" (multipart filename read), "upload_content"
 *                   (uploaded file content read), "db_json" (json.loads of
 *                   stored submission/model JSON), "cli" (sys.argv family),
 *                   "cli_options" (argparse options dict of the CLI),
 *                   "config" (cr_settings subscript)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "request", "self.request", "request.POST",
 *                   "sys", "json", "cr_settings", the uploaded-file local
 *                   name, or "" / the enclosing class for parameter rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "json"/"sys"/"coderedcms.settings" for the
 *                   stdlib/config channel families
 *   7. arg_index  - 0-based positional argument index carrying the controlled
 *                   key/value (index 0 for keyed reads; the 0-based parameter
 *                   position in the function definition for parameter rows),
 *                   -1 if N/A
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates/functions), does not
 * assign API::Node values to DataFlow::Node variables, keeps every variable
 * bound through a positive body, and keeps resolved-API matching strictly
 * separate from AST syntax matching (the match_kind column records which one
 * produced a row). Only the json.loads family resolves at API level here
 * (API::moduleImport("json").getMember("loads").getACall()); every other
 * source family is a framework-injected value on local/self attributes or
 * parameters (not module members) and is matched at AST level.
 *
 * Scope (applied to every row): %/coderedcms/% (the shipped coderedcms
 * package), EXCLUDING %/coderedcms/migrations/% (generated migrations),
 * %/coderedcms/tests/% (incl. blocks/tests and models/tests),
 * %/coderedcms/project_template/% (CLI project scaffolding) and the nested
 * %/coderedcms-db/% database directory. Root setup.py, docs/, ci/ and
 * tutorial/ are outside the positive scope.
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

/** Base name of the object expression of an attribute access, used as a
 *  receiver hint. */
string receiverHint(Attribute a) {
  result = a.getObject().(Name).getId()
  or
  result = a.getObject().(Attribute).getName()
  or
  not a.getObject() instanceof Name and
  not a.getObject() instanceof Attribute and
  result = "<expr>"
}

/** True iff the candidate's file path is inside the audited coderedcms
 *  package (%/coderedcms/% but not the generated/scaffold/test subtrees and
 *  not the nested %/coderedcms-db/% database directory). bindingset[path]
 *  declares that the caller passes a bound path (the path only appears in
 *  checked positions such as the receiver of replaceAll/matches inside this
 *  predicate). */
bindingset[path]
predicate coderedSourcePath(string path) {
  path.replaceAll("\\", "/").matches("%/coderedcms/%") and
  not path.replaceAll("\\", "/").matches("%/coderedcms-db/%") and
  not path.replaceAll("\\", "/").matches("%/coderedcms/migrations/%") and
  not path.replaceAll("\\", "/").matches("%/coderedcms/tests/%") and
  not path.replaceAll("\\", "/").matches("%/coderedcms/project_template/%")
}

/** The syntactic Call node behind an API graph call node. */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/** Django request field names whose values are client-controlled
 *  (query string, form body, multipart files, headers). */
private predicate requestFieldName(string name) {
  name in ["GET", "POST", "FILES", "META", "body", "headers", "COOKIES"]
}

/** Holds if o is a syntactic reference to a Django request session object:
 *  `request.session` (local/parameter name request) or `self.request.session`
 *  (the wagtail_flexible_forms Steps shape). */
private predicate requestSessionObject(Expr o) {
  o.(Attribute).getName() = "session" and
  (
    o.(Attribute).getObject().(Name).getId() = "request"
    or
    o.(Attribute).getObject().(Attribute).getName() = "request" and
    o.(Attribute).getObject().(Attribute).getObject().(Name).getId() = "self"
  )
}

/** Receiver hint of a request session object expression. */
private string sessionReceiverHint(Expr o) {
  o.(Attribute).getObject().(Name).getId() = "request" and result = "request"
  or
  o.(Attribute).getObject().(Attribute).getName() = "request" and
  result = "self.request"
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: the protected-media URL route variable: the `path` parameter
     of serve_protected_file(request, path) (views.py:110). urls.py:21-25
     registers re_path(r'^{PROTECTED_MEDIA_URL}(?P<path>.*)$', ...) so the
     whole decoded request path below /protected/ is injected as this kwarg;
     views.py:114 joins it onto PROTECTED_MEDIA_ROOT and :117 opens the
     result. arg_index is the 0-based parameter position (request = 0). */
  exists(Function f, Parameter p |
    f.getName() = "serve_protected_file" and
    normalizedPathOf(f).matches("%/coderedcms/views.py") and
    p = f.getAnArg() and
    p.getName() = "path" and
    not p.isSelf() and
    node = p and
    flowKind = "route_param" and
    callableName = "serve_protected_file" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 2a: Django request proxy attribute reads: request.GET /
     request.POST / request.FILES / request.META / request.body / ... -
     SearchForm(request.GET) at views.py:33 and templatetags:94,
     ImportPagesFromCSVFileForm(request.POST, request.FILES) at views.py:238
     and page_models.py:1404, 'revert' in request.GET at wagtail_hooks:228,
     len(request.GET) at page_models.py:484, the request.POST guards at
     views.py:142/:165/:185/:237. */
  exists(Attribute a |
    requestFieldName(a.getName()) and
    a.getObject().(Name).getId() = "request" and
    node = a and
    flowKind = "http" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "request" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 2b: Django request field keyed reads: request.<field>.get(key) -
     argument 0 carries the key whose value is returned. Sites include
     views.py:86 ('p'), :188 ('page_id'), :208/:213/:214 (pid/start/end),
     page_models.py:487 ('c'), :493, :511, :1941/:1947 (data-format/viewport),
     wff models.py:213 ('step'), :656 ('step'),
     wagtail_hooks.py:222 ('status'), :239 (META 'HTTP_REFERER'). */
  exists(Call c, Attribute func, Attribute field |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    field = func.getObject().(Attribute) and
    requestFieldName(field.getName()) and
    field.getObject().(Name).getId() = "request" and
    node = c and
    flowKind = "http" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "request." + field.getName() and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 2c: Django request field item reads: request.<field>[key] -
     the index carries the key. Sites: views.py:143/:145/:146/:167
     (request.POST['event_pk']/['datetime_start']/['datetime_end']) and
     wagtail_hooks.py:275 (request.GET['page_id']). */
  exists(Subscript s, Attribute field |
    field = s.getObject().(Attribute) and
    requestFieldName(field.getName()) and
    field.getObject().(Name).getId() = "request" and
    node = s and
    flowKind = "http" and
    callableName = field.getName() and
    argIndex = 0 and
    receiver = "request" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 3a: request session object reads: request.session /
     self.request.session used as a value (subscript base at wff:190); the
     parent-node check excludes the session attribute when it is itself the
     receiver of .get(...)/[...] reads or of session_key member access
     (those get their own rows). */
  exists(Attribute sess |
    requestSessionObject(sess) and
    not sess.getParentNode() instanceof Attribute and
    node = sess and
    flowKind = "session" and
    callableName = "session" and
    argIndex = -1 and
    receiver = sessionReceiverHint(sess) and
    moduleHint = moduleHintOf(sess) and
    matchKind = "ast"
  )
  or
  /* family 3b: request session keyed reads: <request session>.get(key) -
     wff models.py:180 self.request.session.get(current_step_session_key,
     0). Argument 0 carries the key. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    requestSessionObject(func.getObject()) and
    node = c and
    flowKind = "session" and
    callableName = "get" and
    argIndex = 0 and
    receiver = sessionReceiverHint(func.getObject()) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3c: request session item reads: <request session>[key] -
     wff models.py:190 self.request.session[page.current_step_session_key]
     = ... The index carries the key. */
  exists(Subscript s |
    requestSessionObject(s.getObject()) and
    node = s and
    flowKind = "session" and
    callableName = "session" and
    argIndex = 0 and
    receiver = sessionReceiverHint(s.getObject()) and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 4: session_key reads: request.session.session_key /
     self.request.session.session_key - the Django session id (server
     -generated random value) used as the upload storage DIRECTORY
     component at page_models.py:1206 and wff models.py:239; extracted for
     completeness, labeling judges the trust level. The object of the
     session_key attribute is the session attribute, validated by
     requestSessionObject. */
  exists(Attribute key |
    key.getName() = "session_key" and
    requestSessionObject(key.getObject()) and
    node = key and
    flowKind = "session_key" and
    callableName = "session_key" and
    argIndex = -1 and
    receiver = sessionReceiverHint(key.getObject()) and
    moduleHint = moduleHintOf(key) and
    matchKind = "ast"
  )
  or
  /* family 5: multipart upload filename reads: file.name / val.name /
     value.name - the client-supplied filename of form uploads, flowing
     into str(Path(directory) / val.name) at page_models.py:1211 and wff
     models.py:244 (pathlib semantics: an absolute name replaces the
     directory) and into the os.path.splitext extension checks at
     forms.py:68/:73. */
  exists(Attribute a |
    a.getName() = "name" and
    a.getObject().(Name).getId() in ["file", "val", "value"] and
    node = a and
    flowKind = "upload_name" and
    callableName = "name" and
    argIndex = -1 and
    receiver = a.getObject().(Name).getId() and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 6: uploaded file content reads: file.chunks() / val.chunks()
     (the write loop of save_files/process_data) and
     form.cleaned_data['file'].read() (the CSV import at views.py:241,
     matched by its Subscript receiver). */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["read", "chunks"] and
    (
      func.getObject().(Name).getId() in ["file", "val"]
      or
      func.getObject() instanceof Subscript
    ) and
    node = c and
    flowKind = "upload_content" and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 7a: the DB-submission boundary, resolved via API graphs:
     json.loads(...) of stored submission/model JSON (submission.form_data,
     self.thumbnails_by_path, self.form_data, self.data,
     subscriber_json_data) whose values were user-supplied at form
     submission time and are re-used as file paths by
     get_thumbnail_path/delete_file/delete_files. */
  exists(API::CallNode cn |
    cn = API::moduleImport("json").getMember("loads").getACall() and
    node = astCallOf(cn) and
    flowKind = "db_json" and
    callableName = "loads" and
    argIndex = 0 and
    receiver = "json" and
    moduleHint = "json" and
    matchKind = "api"
  )
  or
  /* family 7b: syntax-level fallback of the same json.loads family
     (module-qualified attribute calls; every use in this codebase is
     qualified `json.loads`). Sites: wff models.py:204/:327/:356/:377/:444/:605
     and integration_models.py:46/:48/:118. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "loads" and
    func.getObject().(Name).getId() = "json" and
    node = c and
    flowKind = "db_json" and
    callableName = "loads" and
    argIndex = 0 and
    receiver = "json" and
    moduleHint = "json" and
    matchKind = "ast"
  )
  or
  /* family 8: CLI argv boundary: sys.argv attribute reads and sys.argv[...]
     subscripts in coderedcms/bin/coderedcms.py (:128 os.path.basename
     (sys.argv[0]), :146/:153 command/help lookup, :173
     command.run_from_argv(sys.argv)) - the operator-supplied command line. */
  exists(Attribute a |
    a.getName() = "argv" and
    a.getObject().(Name).getId() = "sys" and
    node = a and
    flowKind = "cli" and
    callableName = "argv" and
    argIndex = -1 and
    receiver = "sys" and
    moduleHint = "sys" and
    matchKind = "ast"
  )
  or
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "argv" and
    base.getObject().(Name).getId() = "sys" and
    node = s and
    flowKind = "cli" and
    callableName = "argv" and
    argIndex = 0 and
    receiver = "sys" and
    moduleHint = "sys" and
    matchKind = "ast"
  )
  or
  /* family 9a: CLI options parameter: the **options kwarg dict of
     CreateProject.handle (bin/coderedcms.py:37) - the argparse-parsed CLI
     options (name/directory/template) that flow into the os.path.join
     template-path construction at :60-:63. The kwarg parameter is reached
     through getKwarg() (getAnArg() covers positional parameters only);
     a keyword dict parameter has no positional index. */
  exists(Function f, Parameter p |
    f.getName() = "handle" and
    f.getEnclosingScope() instanceof Class and
    f.getEnclosingScope().(Class).getName() = "CreateProject" and
    normalizedPathOf(f).matches("%/coderedcms/bin/%") and
    (p = f.getAnArg() or f.getKwarg() = p) and
    p.getName() = "options" and
    node = p and
    flowKind = "cli_options" and
    callableName = "handle" and
    argIndex = -1 and
    receiver = "CreateProject" and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 9b: CLI options dict keyed reads within the CLI module:
     options[...] subscripts (:58, :62-:63) and options.get(...)/
     options.pop(...) calls (:39-:40, :77-:93) - argument/index 0 carries
     the key. */
  exists(Subscript s |
    s.getObject().(Name).getId() = "options" and
    normalizedPathOf(s).matches("%/coderedcms/bin/%") and
    node = s and
    flowKind = "cli_options" and
    callableName = "options" and
    argIndex = 0 and
    receiver = "options" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["get", "pop"] and
    func.getObject().(Name).getId() = "options" and
    normalizedPathOf(c).matches("%/coderedcms/bin/%") and
    node = c and
    flowKind = "cli_options" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "options" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 10: configuration reads: cr_settings[...] subscripts - the
     deployment-level coderedcms settings (PROTECTED_MEDIA_ROOT/URL, upload
     whitelist/blacklist) from coderedcms/settings.py DEFAULTS + django
     settings overrides; operator trust level, not attacker input - kept
     for the labeling step to judge. Sites: views.py:114, forms.py:67/:68/
     :72/:73, page_models.py:1216/:1224/:1225/:1715/:1716, utils.py:30. */
  exists(Subscript s |
    s.getObject().(Name).getId() = "cr_settings" and
    node = s and
    flowKind = "config" and
    callableName = "cr_settings" and
    argIndex = 0 and
    receiver = "cr_settings" and
    moduleHint = "coderedcms.settings" and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  coderedSourcePath(normalizedPathOf(node))
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
