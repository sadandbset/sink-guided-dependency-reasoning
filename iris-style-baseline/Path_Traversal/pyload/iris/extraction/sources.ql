/**
 * @name pyload CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   pyload CodeQL database (snapshot 14a9f11, pyLoad 0.5.0b3 / pyload-ng):
 *   the Flask HTTP surface of the webui (flask.request.form[...] subscripts
 *   and .get/.getlist reads - login form app_blueprint.py:53-54,
 *   api_blueprint.py:83-84, log form app_blueprint.py:355-363, the CNL
 *   package/source/referer/urls/passwords/crypted/jk fields
 *   cnl_blueprint.py:59-121/:164-167 and the json add_name/add_links/
 *   add_password fields json_blueprint.py:142-145; flask.request.args.get -
 *   THE pathchooser 'path' app_blueprint.py:257 plus the json id/pid/pos/
 *   fid/category/section selectors json_blueprint.py:80/:98/:113/:127/:236-
 *   237/:263; the rpc kwargs loop chain(flask.request.args.items(),
 *   flask.request.form.items()) api_blueprint.py:53 whose EVERY query/form
 *   key becomes an unquote()d rpc kwarg at :55; flask.request.files
 *   ['add_file'] multipart upload json_blueprint.py:148 with the
 *   file.filename attribute read :152 feeding package_name and the
 *   'tmp_' + file.filename join :154-156; flask.request.authorization.get
 *   api_blueprint.py:28-29); the route-variable parameters (get_file(path)
 *   app_blueprint.py:161 - the /files/get/<path:path> download path that
 *   reaches flask.send_from_directory after unquote(path).replace('..','')
 *   at :163; render(filename) :34 - /render/<path:filename>;
 *   rpc(func, args) api_blueprint.py:24 - the /api/<func>[/<args>] dynamic
 *   RPC selector and literal_eval'd argument string; filemanager(path)
 *   app_blueprint.py:439 whose route declares no variable); the core Api
 *   methods those RPC calls reach (add_package name core/api/__init__.py:418
 *   - the package name that becomes the per-package download folder after
 *   the :427-438 separator-strip; upload_container filename :944;
 *   check_online_status_container container :526; set_package_data data
 *   :985 - setattr incl. the '_folder' key written by the json edit_package
 *   route json_blueprint.py:187-204; set_package_name name :902;
 *   set_config_value value :174 - SETTINGS-level users can move
 *   storage_folder / ExtractArchive destination+passwordfile through
 *   /json/save_config json_blueprint.py:258-275; plus the call_api func
 *   dispatch parameter api_blueprint.py:65 -> getattr(api, func) :72-75);
 *   the archive-entry-name boundary (z.namelist() UnZip.py:55/:87 and
 *   t.getnames() UnTar.py:57/:79 - remote-controlled names feeding
 *   extractall members); and the operator-level CLI (sys.argv
 *   __main__.py:282 and core/__init__.py:309-342, parsed argparse
 *   Namespace fields args.userdir/tempdir/storagedir/pidfile/daemon/quit
 *   __main__.py:287-292 - OPERATOR-trust level, recorded for labeling to
 *   classify, not automatically attacker sources). Raw BQRS extraction
 *   query: run with `codeql query run` and decode with `codeql bqrs
 *   decode` (not database analyze). This is a plain multi-column select
 *   query on purpose: @kind problem is the wrong shape for candidate
 *   tables and @kind table is not assumed to exist.
 * @id iris/pyload/extraction/sources
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field name ("form"/"files"/"get"/"getlist"
 *                   /"items"/"filename" for the flask layer reads, "namelist"/
 *                   "getnames" for the archive-entry reads, "argv" for the CLI,
 *                   the argparse field name for cli_arg rows, the function name
 *                   for route_param/api_param/api_dispatch parameter rows)
 *   4. flow_kind  - "http_form" (flask.request.form subscript and .get/.getlist),
 *                   "http_args" (flask.request.args.get), "http_values"
 *                   (flask.request.values.get - redirect-only surface, kept
 *                   for labeling), "http_auth" (flask.request.authorization
 *                   .get), "http_iter" (args.items()/form.items() - the rpc
 *                   kwargs loop), "http_file" (flask.request.files subscript),
 *                   "http_file_name" (FileStorage.filename attribute read),
 *                   "route_param" (route-variable parameters), "api_param"
 *                   (core Api method parameters receiving RPC values),
 *                   "api_dispatch" (the call_api func selector of the
 *                   getattr(api, func) dynamic dispatch), "archive_entry"
 *                   (zipfile namelist / tarfile getnames return values),
 *                   "cli" (sys.argv), "cli_arg" (parsed argparse Namespace
 *                   attribute reads - operator-trust level)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "flask.request" for the request layers,
 *                   "file" for the FileStorage filename, the object base name
 *                   for namelist/getnames; "args"/"sys"; "" for module-level
 *                   parameter rows; "Api" for core Api method parameter rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "flask.request"/"flask"/"sys"/"zipfile"/"tarfile"
 *                   for the external channels
 *   7. arg_index  - 0-based positional argument index (index argument 0
 *                   carries the dict key for the request-layer subscripts
 *                   and .get calls; -1 when the value is the return value
 *                   (items/namelist/getnames/argv) or the attribute itself
 *                   (filename, argparse Namespace reads); parameter
 *                   position in the function definition including the self
 *                   slot for parameter rows)
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
 * a row). In this project NO source row is expected to resolve at API level:
 * flask/werkzeug are external libraries not part of the database (only the
 * pyload tree is), the request-layer shapes flow through attribute chains on
 * the unresolved name `flask`, the archive-entry reads are instance members
 * on local variables (z/t), and the RPC boundary flows through route
 * parameters of webui functions and parameters of core Api methods. All
 * families below are AST-level matches and the match_kind column is kept
 * "ast" for cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /tests/ (unit test tree) and
 * /pyload-db/ (the CodeQL database directory nested inside the source
 * tree). setup.py at the repo root is kept in scope (build script - rows,
 * if any, expected to be labeled none/FP). Ground-truth-looking artifacts
 * at the repo root were never opened (experiment independence).
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
  path.replaceAll("\\", "/").matches("%/tests/%")
  or
  path.replaceAll("\\", "/").matches("%/pyload-db/%")
}

/** True iff layer is one of the flask.request.<...> data layers (the
 *  syntactic qualifier chain on the unresolved external name `flask`).
 *  Only literal string comparisons are used in the body (the proven
 *  binding-safe style from the earlier Path_Traversal projects). */
private predicate isFlaskRequestDataLayer(Attribute layer) {
  (
    layer.getName() = "form" or
    layer.getName() = "args" or
    layer.getName() = "values" or
    layer.getName() = "authorization" or
    layer.getName() = "files"
  ) and
  layer.getObject().(Attribute).getName() = "request" and
  layer.getObject().(Attribute).getObject().(Name).getId() = "flask"
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: form subscripts - flask.request.form["username"] /
     flask.request.form["password"] (login app_blueprint.py:53-54,
     api_blueprint.py:83-84), flask.request.form["urls"] (CNL add
     cnl_blueprint.py:63), flask.request.form["crypted"] (addcrypted :96,
     addcrypted2 :119), flask.request.form["add_links"]/
     ["add_dest"] (json add_package json_blueprint.py:143-144),
     flask.request.form["pack_id"]/["pack_name"]/["pack_folder"]/
     ["pack_pws"] (json edit_package :193-197 - pack_folder is THE
     package-folder override), flask.request.form["from"] (logs
     app_blueprint.py:355). Index argument 0 carries the dict key. */
  exists(Subscript s, Attribute layer |
    layer = s.getObject().(Attribute) and
    layer.getName() = "form" and
    layer.getObject().(Attribute).getName() = "request" and
    layer.getObject().(Attribute).getObject().(Name).getId() = "flask" and
    node = s and
    flowKind = "http_form" and
    callableName = "form" and
    argIndex = 0 and
    receiver = "flask.request" and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  /* family 2: multipart upload boundary - flask.request.files["add_file"]
     json_blueprint.py:148: the FileStorage whose .filename (family 3)
     feeds package_name and the join(storage_folder, "tmp_" + filename)
     path at :154-156 that file.save writes at :157. Index argument 0
     carries the dict key. */
  exists(Subscript s, Attribute layer |
    layer = s.getObject().(Attribute) and
    layer.getName() = "files" and
    layer.getObject().(Attribute).getName() = "request" and
    layer.getObject().(Attribute).getObject().(Name).getId() = "flask" and
    node = s and
    flowKind = "http_file" and
    callableName = "files" and
    argIndex = 0 and
    receiver = "flask.request" and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  /* family 3: .get/.getlist calls on the request layers -
     flask.request.args.get('path', "") (THE pathchooser path
     app_blueprint.py:257), flask.request.args.get('id'/'pid'/'pos'/'fid'/
     'category'/'section') (json_blueprint.py:80/:98/:113/:127/:236-237/:263),
     flask.request.form.get('package', form.get('source', form.get
     ('referer'))) (CNL cnl_blueprint.py:59-61/:89-91/:116-118/:164),
     flask.request.form.get('passwords') (:67/:100/:121),
     flask.request.form.get('add_name'/'add_password') (json :142/:145),
     flask.request.form.get('perpage'/'reversed') (logs app_blueprint
     :360-363), flask.request.form.getlist('new_perms'/
     '<name>|perms') (json :367/:413), flask.request.values.get('next')
     (helpers.py:44 - redirect-only surface, kept for labeling),
     flask.request.authorization.get('username'/'password')
     (api_blueprint.py:28-29), flask.request.form.get('u'/'p')
     (rpc auth api_blueprint.py:31-32). Argument 0 carries the key. */
  exists(Call c, Attribute func, Attribute layer |
    func = c.getFunc().(Attribute) and
    (func.getName() = "get" or func.getName() = "getlist") and
    layer = func.getObject().(Attribute) and
    isFlaskRequestDataLayer(layer) and
    (
      (layer.getName() = "form" and flowKind = "http_form")
      or
      (layer.getName() = "args" and flowKind = "http_args")
      or
      (layer.getName() = "values" and flowKind = "http_values")
      or
      (layer.getName() = "authorization" and flowKind = "http_auth")
    ) and
    node = c and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "flask.request" and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  /* family 4: the rpc kwargs loop - chain(flask.request.args.items(),
     flask.request.form.items()) api_blueprint.py:53: EVERY query-string
     and form key of /api/<func> becomes an rpc kwarg (unquote()d at :55,
     literal_eval()d at :74) for the getattr(api, func) dispatch; the
     RETURN VALUE (the item pairs) carries the external data, hence
     argIndex -1. */
  exists(Call c, Attribute func, Attribute layer |
    func = c.getFunc().(Attribute) and
    func.getName() = "items" and
    layer = func.getObject().(Attribute) and
    isFlaskRequestDataLayer(layer) and
    node = c and
    flowKind = "http_iter" and
    callableName = "items" and
    argIndex = -1 and
    receiver = "flask.request" and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  /* family 5: multipart filename - file.filename attribute read
     json_blueprint.py:152 (inside `if file.filename:`): the uploaded
     file's client-provided name, used as package_name fallback and as
     the second component of join(storage_folder, "tmp_" + file.filename)
     at :154-156; the attribute VALUE carries the data, argIndex -1. */
  exists(Attribute a |
    a.getName() = "filename" and
    a.getObject().(Name).getId() = "file" and
    normalizedPathOf(a).matches("%/webui/app/blueprints/json_blueprint.py") and
    node = a and
    flowKind = "http_file_name" and
    callableName = "filename" and
    argIndex = -1 and
    receiver = "file" and
    moduleHint = "werkzeug.datastructures" and
    matchKind = "ast"
  )
  or
  /* family 6: route-variable parameters of the path-relevant handlers -
     get_file(path) app_blueprint.py:161 (the /files/get/<path:path>
     download path: unquote(path).replace('..','') :163 then
     flask.send_from_directory(storage_folder, path) :165),
     render(filename) app_blueprint.py:34 (/render/<path:filename> ->
     render_template(filename) :36), filemanager(path)
     app_blueprint.py:439 (route declares no variable - runtime-dead,
     kept for labeling to discard), rpc(func, args) api_blueprint.py:24
     (the /api/<func>[/<args>] dynamic RPC selector and the comma-split
     literal_eval'd argument string :47-49/:72-75), and the call_api(func)
     module function api_blueprint.py:65 (the dispatch helper's selector
     parameter). arg_index is the 0-based position in the function
     definition (module-level functions, no self slot). */
  exists(Function f, Parameter p |
    (
      (
        f.getName() = "get_file" and
        p.getName() = "path" and
        normalizedPathOf(f).matches("%/webui/app/blueprints/app_blueprint.py") and
        flowKind = "route_param"
      )
      or
      (
        f.getName() = "render" and
        p.getName() = "filename" and
        normalizedPathOf(f).matches("%/webui/app/blueprints/app_blueprint.py") and
        flowKind = "route_param"
      )
      or
      (
        f.getName() = "filemanager" and
        p.getName() = "path" and
        normalizedPathOf(f).matches("%/webui/app/blueprints/app_blueprint.py") and
        flowKind = "route_param"
      )
      or
      (
        f.getName() = "rpc" and
        (p.getName() = "func" or p.getName() = "args") and
        normalizedPathOf(f).matches("%/webui/app/blueprints/api_blueprint.py") and
        flowKind = "route_param"
      )
      or
      (
        f.getName() = "call_api" and
        p.getName() = "func" and
        normalizedPathOf(f).matches("%/webui/app/blueprints/api_blueprint.py") and
        flowKind = "api_dispatch"
      )
    ) and
    p = f.getAnArg() and
    node = p and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 7: core Api method parameters receiving RPC/webui-controlled
     values (the receiver side of the getattr(api, func) dispatch and of
     the direct api.<method>(...) webui calls): add_package(name, links,
     dest) core/api/__init__.py:418 - the package name becomes the
     per-package download folder (separator-strip at :427-438, '..'
     survives as a separator-less component) that reaches safejoin +
     os.makedirs in plugins/base/downloader.py:318-322 and the extraction
     destination in plugins/addons/ExtractArchive.py:239-255;
     upload_container(filename, data) :944 - filename is joined as
     "tmp_" + filename into open(..., "wb") at :951-956 with NO
     sanitization of the second join component; check_online_status_
     container(urls, container, data) :526 - same "tmp_" + container
     shape at :535-540; set_package_data(package_id, data) :985 - the
     data dict is setattr'd onto the package (json edit_package feeds
     {"_folder": form["pack_folder"]} json_blueprint.py:194-200);
     set_package_name(package_id, name) :902; set_config_value(category,
     option, value, section) :174 - value reaches config options incl.
     storage_folder / ExtractArchive destination+passwordfile through
     /json/save_config json_blueprint.py:267-273. arg_index is the
     0-based position including the self slot. */
  exists(Function f, Parameter p |
    (
      (f.getName() = "add_package" and p.getName() = "name" and argIndex = 1)
      or
      (f.getName() = "upload_container" and p.getName() = "filename" and argIndex = 1)
      or
      (f.getName() = "check_online_status_container" and p.getName() = "container" and argIndex = 2)
      or
      (f.getName() = "set_package_data" and p.getName() = "data" and argIndex = 2)
      or
      (f.getName() = "set_package_name" and p.getName() = "name" and argIndex = 2)
      or
      (f.getName() = "set_config_value" and p.getName() = "value" and argIndex = 3)
    ) and
    normalizedPathOf(f).matches("%/core/api/__init__.py") and
    p = f.getAnArg() and
    not p.isSelf() and
    f.getEnclosingScope() instanceof Class and
    f.getEnclosingScope().(Class).getName() = "Api" and
    node = p and
    flowKind = "api_param" and
    callableName = f.getName() and
    receiver = "Api" and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 8: archive-entry-name boundary - z.namelist() UnZip.py:56/:87
     (the zip member names that become the extractall members list at
     :87-90 and the self.files join list at :91-93) and t.getnames()
     UnTar.py:57/:79 (tar member names); archive content is
     remote-controlled (downloaded files), the RETURN VALUE carries the
     names, hence argIndex -1. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (
      (func.getName() = "namelist" and moduleHint = "zipfile")
      or
      (func.getName() = "getnames" and moduleHint = "tarfile")
    ) and
    normalizedPathOf(c).matches("%/plugins/extractors/%") and
    node = c and
    flowKind = "archive_entry" and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = receiverHint(func) and
    matchKind = "ast"
  )
  or
  /* family 9: CLI input - sys.argv attribute reads: __main__.py:282
     (main(cmd_args=sys.argv[1:])) and core/__init__.py:309-310/:341-342
     (the embedded-console bootstrap argv handling). Operator-trust
     level - recorded for labeling, not automatically an attacker
     source. */
  exists(Attribute a |
    a.getName() = "argv" and
    a.getObject().(Name).getId() = "sys" and
    (
      normalizedPathOf(a).matches("%/src/pyload/__main__.py")
      or
      normalizedPathOf(a).matches("%/src/pyload/core/__init__.py")
    ) and
    node = a and
    flowKind = "cli" and
    callableName = "argv" and
    argIndex = -1 and
    receiver = "sys" and
    moduleHint = "sys" and
    matchKind = "ast"
  )
  or
  /* family 10: parsed CLI argument reads - args.<field> attribute reads
     in __main__.py:287-292: args.userdir/args.tempdir/args.storagedir
     (the directory anchors that Core.__init__ makedirs core/__init__
     .py:119-120/:141), args.pidfile, args.daemon, args.quit.
     Operator-trust level: the person invoking pyload is the same trust
     domain as the config it consumes - the labeling step decides
     whether any of these cross a real untrusted boundary. */
  exists(Attribute a |
    a.getObject().(Name).getId() = "args" and
    (
      a.getName() = "storagedir" or
      a.getName() = "userdir" or
      a.getName() = "tempdir" or
      a.getName() = "pidfile" or
      a.getName() = "daemon" or
      a.getName() = "quit"
    ) and
    normalizedPathOf(a).matches("%/src/pyload/__main__.py") and
    node = a and
    flowKind = "cli_arg" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "args" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
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
