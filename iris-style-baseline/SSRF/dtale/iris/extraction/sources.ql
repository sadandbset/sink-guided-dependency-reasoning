/**
 * @name dtale CWE-918 source candidate extraction
 * @description Extract source candidates from the D-Tale CodeQL database
 *   (snapshot 063423aa): input boundaries of a Flask + React data
 *   visualization server for Pass 3 / CWE-918 (SSRF). Source families
 *   derived from real source inspection (all line evidence verified
 *   against the checked-out snapshot):
 *     1. query-string wrapper calls: get_str_arg / get_json_arg /
 *        get_int_arg / get_float_arg / get_bool_arg (142 call sites:
 *        views.py 120, column_analysis.py 20, query.py 2). The five
 *        wrappers are defined in utils.py:114/:134/:151/:171/:191 and
 *        each is built on `val = r.args.get(name)` (the actual
 *        flask.request.args read). The SSRF-relevant reads are
 *        views.py:3930 `url = get_str_arg(request, "url")` and
 *        views.py:3931 `proxy = get_str_arg(request, "proxy")` inside
 *        web_upload (route /web-upload, views.py:3921, unauthenticated
 *        in the default deployment: global_state.py:38 AUTH_SETTINGS
 *        active=False; auth.py:37 requires_auth only gates when active).
 *     2. full query-string dictionaries: request.args.to_dict()
 *        (views.py:1429, :3799, :3814, :3825).
 *     3. JSON body reads: request.json.get(...) (views.py:1677, :1785,
 *        :1791, :3991, :4008) and the bare `cfg = request.json`
 *        (views.py:4153).
 *     4. form body reads: request.form.get / request.form[...] /
 *        `in request.form` (views.py:3871-3880 build_csv_kwargs;
 *        auth.py:20/:24/:25 login).
 *     5. uploaded files: request.files attribute reads
 *        (views.py:3888-3891, the /upload multipart boundary).
 *     6. CLI input: click.option(...) decorator calls under dtale/cli/
 *        (22 @click.option in cli/script.py plus the dynamic
 *        loader-options constructor in clickutils.py:91 inside
 *        loader_options; the generated --<loader>-path / --<loader>-
 *        proxy options are the CLI twin of the /web-upload url/proxy
 *        parameters and reach handle_path -> requests.get).
 *     7. environment variable reads: os.environ.get(...) /
 *        request.environ.get(...) (10 + 1 sites: config.py:28,
 *        cli/loaders/__init__.py:108, app.py:425/:597/:598/:621,
 *        utils.py:42, views.py:1248/:1250, layout.py:106).
 *     8. configuration file loads: config.read(path) on the
 *        configparser object (config.py:23, dtale.ini; admin-facing).
 *   Internal helper parameters that merely forward already-derived URLs
 *   (handle_path `path`/`kwargs`, loader_func `path`/`proxy`, load_zip
 *   `url`) are NOT listed as sources here (covered on the sink side as
 *   funnel/wrapper candidates); the earliest untrusted boundary of the
 *   /web-upload flow is get_str_arg(request, "url"/"proxy") at
 *   views.py:3930-3931. dash callback parameters (35+ @app.callback
 *   sites) are not extracted: no path from a callback value to network
 *   I/O exists in this tree (see detection.json uncoveredCases).
 *   Rows under tests/, dtale-db/ and the pre-existing root-level
 *   ssrf_analyzer.py / ssrf_precise_analyzer.py artifacts are excluded
 *   by path.
 *   Raw BQRS extraction query: run with `codeql query run` and decode
 *   with `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong
 *   shape for candidate tables and @kind table is not assumed to exist.
 * @id iris/dtale-cwe918/extraction/sources
 * @tags ssrf
 */

import python

/* ------------------------------------------------------------------ */
/* Column contract (identical order to sinks.ql):                      */
/* ------------------------------------------------------------------ */

/*
 *   1. node       - candidate AST node (location-backed, decodes as
 *                   file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - wrapper name, attribute/subscript name or call name
 *                   at the boundary
 *   4. flow_kind  - "http_query_arg" (get_*_arg wrapper call reading
 *                   request.args)
 *                   "request_args_dict" (request.args.to_dict())
 *                   "request_json"      (request.json.get(...) /
 *                                        bare request.json read)
 *                   "request_form"      (request.form.get(...) /
 *                                        request.form[...] /
 *                                        bare request.form read)
 *                   "request_files"     (request.files read)
 *                   "cli_arg"           (click.option(...) call)
 *                   "env"               (os.environ.get(...) /
 *                                        request.environ.get(...) /
 *                                        os.environ[...])
 *                   "config_file"       (config.read(path) ini load)
 *   5. receiver   - syntactic receiver hint: base name of the object
 *                   expression ("request" / "req" for wrapper calls,
 *                   "os"/"request"/"config" for the direct reads, ""
 *                   if none)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here)
 *   7. arg_index  - 0-based positional index of the argument carrying
 *                   the parameter NAME or KEY where applicable:
 *                   1 for get_*_arg calls (position of the literal
 *                   query-parameter-name argument; the tainted value is
 *                   the call result), 0 for .get(key)/config.read(path)
 *                   and for click.option (option-name argument),
 *                   -1 for whole-object reads (to_dict, bare json/form/
 *                   files/environ reads)
 *   8. file       - absolute file path, obtained through the Location
 *                   API (AstNode.getLocation().getFile().getAbsolutePath();
 *                   AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "ast" (every input boundary in this codebase is
 *                   first-party code; the flask request object is never
 *                   reached through an import that needs API-graph
 *                   resolution, so no "api" rows exist in this query)
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Path filter (Augur candidate strategy: exclude tests/fixtures, the
 *  nested CodeQL database directory and the pre-existing root-level
 *  SSRF analysis artifacts, which are not D-Tale source). Both
 *  forward-slash and backslash separators are covered; `string` is an
 *  infinite-domain QL type, so the predicate is only called with paths
 *  obtained from CodeQL File locations (input binding set declared
 *  explicitly). */
bindingset[p]
predicate isExcludedPath(string p) {
  p.matches("%/tests/%")
  or
  p.matches("%\\tests\\%")
  or
  p.matches("%/test_%.py")
  or
  p.matches("%\\test_%.py")
  or
  p.matches("%/conftest.py")
  or
  p.matches("%\\conftest.py")
  or
  p.matches("%dtale-db%")
  or
  p.matches("%ssrf_analyzer.py")
  or
  p.matches("%ssrf_precise_analyzer.py")
}

/** Dotted path of the python module containing n (used as moduleHint).
 *  Files that are not on an import path (top-level scripts) have no
 *  dotted module name; their file base name is used instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getBaseName()
}

/** Terminal name of an expression for display only: the id of a Name
 *  or the attribute name of an Attribute, "<expr>" otherwise. Used for
 *  the receiver column of get_*_arg calls (first argument is the flask
 *  request under whatever name the scope uses: "request" in views.py,
 *  "req" in column_analysis.py/query.py). */
string firstArgName(Call c) {
  result = receiverHintOfExpr(c.getPositionalArg(0))
}

string receiverHintOfExpr(Expr e) {
  e instanceof Name and
  result = e.(Name).getId()
  or
  e instanceof Attribute and
  result = e.(Attribute).getName()
  or
  not e instanceof Name and
  not e instanceof Attribute and
  result = "<expr>"
}

/** True if a is the object expression of an attribute access that is
 *  itself the callee of a call (e.g. the inner `request.json` of
 *  `request.json.get(...)`). Used to keep bare attribute-read rows from
 *  duplicating call rows. */
predicate isCalleeObjectOfCall(Attribute a) {
  exists(Call c, Attribute attr |
    attr = c.getFunc().(Attribute) and
    attr.getObject() = a
  )
}

/** True if a is the value expression of a subscript (e.g. the inner
 *  `request.form` of `request.form["separator"]`). Used to keep bare
 *  attribute-read rows from duplicating subscript rows. */
predicate isSubscriptValue(Attribute a) {
  exists(Subscript s | s.getValue() = a)
}

/* ------------------------------------------------------------------ */
/* Source family 1: query-string wrapper calls                         */
/* ------------------------------------------------------------------ */

/** The five flask query-string reader wrappers defined in
 *  dtale/utils.py:114-204 (each reads r.args.get(name) and converts).
 *  Constrained to the wrapper names, NOT to any first-argument name, so
 *  both views.py (`request`) and column_analysis.py/query.py (`req`)
 *  call sites are covered without marking generic function parameters
 *  as sources. */
predicate queryArgWrapperName(string name) {
  name in ["get_str_arg", "get_json_arg", "get_int_arg",
           "get_float_arg", "get_bool_arg"]
}

predicate queryArgWrapperCall(Call c, string callableName) {
  c.getFunc() instanceof Name and
  queryArgWrapperName(callableName) and
  callableName = c.getFunc().(Name).getId()
}

/* ------------------------------------------------------------------ */
/* Source family 2: request.args.to_dict()                             */
/* ------------------------------------------------------------------ */

/** `request.args.to_dict()`: Call whose func is the attribute `to_dict`
 *  on the attribute `args` of the name `request`. 4 sites (views.py
 *  :1429, :3799, :3814, :3825). */
predicate requestArgsToDictCall(Call c) {
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() = "to_dict" and
  c.getFunc().(Attribute).getObject() instanceof Attribute and
  c.getFunc().(Attribute).getObject().(Attribute).getName() = "args" and
  c.getFunc().(Attribute).getObject().(Attribute).getObject() instanceof Name and
  c.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = "request"
}

/* ------------------------------------------------------------------ */
/* Source family 3: request.json body reads                            */
/* ------------------------------------------------------------------ */

/** `request.json.get(...)`: Call whose func is the attribute `get` on
 *  the attribute `json` of the name `request` (views.py:1677, :1785,
 *  :1791, :3991, :4008). */
predicate requestJsonGetCall(Call c) {
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() = "get" and
  c.getFunc().(Attribute).getObject() instanceof Attribute and
  c.getFunc().(Attribute).getObject().(Attribute).getName() = "json" and
  c.getFunc().(Attribute).getObject().(Attribute).getObject() instanceof Name and
  c.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = "request"
}

/** Bare `request.json` attribute reads that are not already the object
 *  of a `.get(...)` call (views.py:4153 `cfg = request.json`). */
predicate requestJsonAttrRead(Attribute a) {
  a.getName() = "json" and
  a.getObject() instanceof Name and
  a.getObject().(Name).getId() = "request" and
  not isCalleeObjectOfCall(a)
}

/* ------------------------------------------------------------------ */
/* Source family 4: request.form body reads                            */
/* ------------------------------------------------------------------ */

/** `request.form.get(...)`: Call whose func is the attribute `get` on
 *  the attribute `form` of the name `request` (views.py:3871, :3875;
 *  auth.py:20). */
predicate requestFormGetCall(Call c) {
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() = "get" and
  c.getFunc().(Attribute).getObject() instanceof Attribute and
  c.getFunc().(Attribute).getObject().(Attribute).getName() = "form" and
  c.getFunc().(Attribute).getObject().(Attribute).getObject() instanceof Name and
  c.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = "request"
}

/** `request.form["key"]` subscripts (views.py:3876, :3880;
 *  auth.py:25). */
predicate requestFormSubscript(Subscript s) {
  s.getValue() instanceof Attribute and
  s.getValue().(Attribute).getName() = "form" and
  s.getValue().(Attribute).getObject() instanceof Name and
  s.getValue().(Attribute).getObject().(Name).getId() = "request"
}

/** Bare `request.form` attribute reads that are not the object of a
 *  `.get(...)` call and not the value of a subscript (covers
 *  `"header" in request.form` at views.py:3879 and the tuple-generator
 *  receiver at auth.py:20). */
predicate requestFormAttrRead(Attribute a) {
  a.getName() = "form" and
  a.getObject() instanceof Name and
  a.getObject().(Name).getId() = "request" and
  not isCalleeObjectOfCall(a) and
  not isSubscriptValue(a)
}

/* ------------------------------------------------------------------ */
/* Source family 5: request.files reads                                */
/* ------------------------------------------------------------------ */

/** `request.files` attribute reads (views.py:3888 `if not
 *  request.files:`, :3890 `for filename in request.files:`, :3891 the
 *  value expression of `request.files[filename]`). */
predicate requestFilesAttrRead(Attribute a) {
  a.getName() = "files" and
  a.getObject() instanceof Name and
  a.getObject().(Name).getId() = "request"
}

/* ------------------------------------------------------------------ */
/* Source family 6: CLI click option calls                             */
/* ------------------------------------------------------------------ */

/** `click.option(...)` calls: the 22 @click.option decorators of the
 *  `main` command in cli/script.py plus the dynamic option constructor
 *  inside loader_options (clickutils.py:91), which builds the
 *  --<loader>-path / --<loader>-proxy options that flow into
 *  handle_path -> requests.get. */
predicate clickOptionCall(Call c) {
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() = "option" and
  c.getFunc().(Attribute).getObject() instanceof Name and
  c.getFunc().(Attribute).getObject().(Name).getId() = "click"
}

/* ------------------------------------------------------------------ */
/* Source families 7+8: environment and configuration reads            */
/* ------------------------------------------------------------------ */

/** Environment reads: `<env-holder>.environ.get(...)` where the holder
 *  is `os` (10 sites) or `request` (app.py:425 WSGI request environ),
 *  plus `os.environ[...]` subscripts. The django dispatcher's bare
 *  `environ.get(...)` (parameter, not attribute) is deliberately not
 *  matched. */
predicate envRead(AstNode n, string callableName, string receiver, int argIndex) {
  exists(Call c |
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "get" and
    c.getFunc().(Attribute).getObject() instanceof Attribute and
    c.getFunc().(Attribute).getObject().(Attribute).getName() = "environ" and
    c.getFunc().(Attribute).getObject().(Attribute).getObject() instanceof Name and
    c.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = "os" and
    n = c and
    callableName = "get" and
    receiver = "os" and
    argIndex = 0
  )
  or
  exists(Call c |
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "get" and
    c.getFunc().(Attribute).getObject() instanceof Attribute and
    c.getFunc().(Attribute).getObject().(Attribute).getName() = "environ" and
    c.getFunc().(Attribute).getObject().(Attribute).getObject() instanceof Name and
    c.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = "request" and
    n = c and
    callableName = "get" and
    receiver = "request" and
    argIndex = 0
  )
  or
  exists(Subscript s |
    s.getValue() instanceof Attribute and
    s.getValue().(Attribute).getName() = "environ" and
    s.getValue().(Attribute).getObject() instanceof Name and
    s.getValue().(Attribute).getObject().(Name).getId() = "os" and
    n = s and
    callableName = "environ" and
    receiver = "os" and
    argIndex = -1
  )
}

/** Configuration file loads: `config.read(path)` on the configparser
 *  object in config.py:23 (dtale.ini, located via DTALE_CONFIG env or
 *  $HOME/.config/dtale.ini; admin-facing). */
predicate configFileRead(Call c) {
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() = "read" and
  c.getFunc().(Attribute).getObject() instanceof Name and
  c.getFunc().(Attribute).getObject().(Name).getId() = "config"
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: query-string wrapper calls */
  exists(Call c |
    queryArgWrapperCall(c, callableName) and
    node = c and
    flowKind = "http_query_arg" and
    receiver = firstArgName(c) and
    argIndex = 1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
  or
  /* family 2: request.args.to_dict() */
  exists(Call c |
    requestArgsToDictCall(c) and
    node = c and
    callableName = "to_dict" and
    flowKind = "request_args_dict" and
    receiver = "request" and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
  or
  /* family 3: request.json body reads */
  exists(Call c |
    requestJsonGetCall(c) and
    node = c and
    callableName = "get" and
    flowKind = "request_json" and
    receiver = "request" and
    argIndex = 0 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
  or
  exists(Attribute a |
    requestJsonAttrRead(a) and
    node = a and
    callableName = "json" and
    flowKind = "request_json" and
    receiver = "request" and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(a)
  )
  or
  /* family 4: request.form body reads */
  exists(Call c |
    requestFormGetCall(c) and
    node = c and
    callableName = "get" and
    flowKind = "request_form" and
    receiver = "request" and
    argIndex = 0 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
  or
  exists(Subscript s |
    requestFormSubscript(s) and
    node = s and
    callableName = "__getitem__" and
    flowKind = "request_form" and
    receiver = "request" and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(s)
  )
  or
  exists(Attribute a |
    requestFormAttrRead(a) and
    node = a and
    callableName = "form" and
    flowKind = "request_form" and
    receiver = "request" and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(a)
  )
  or
  /* family 5: request.files reads */
  exists(Attribute a |
    requestFilesAttrRead(a) and
    node = a and
    callableName = "files" and
    flowKind = "request_files" and
    receiver = "request" and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(a)
  )
  or
  /* family 6: CLI click option calls */
  exists(Call c |
    clickOptionCall(c) and
    node = c and
    callableName = "option" and
    flowKind = "cli_arg" and
    receiver = "click" and
    argIndex = 0 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
  or
  /* family 7: environment variable reads */
  exists(AstNode n |
    envRead(n, callableName, receiver, argIndex) and
    node = n and
    flowKind = "env" and
    matchKind = "ast" and
    moduleHint = moduleHintOf(n)
  )
  or
  /* family 8: configuration file loads */
  exists(Call c |
    configFileRead(c) and
    node = c and
    callableName = "read" and
    flowKind = "config_file" and
    receiver = "config" and
    argIndex = 0 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint,
    argIndex, matchKind) and
  not isExcludedPath(node.getLocation().getFile().getAbsolutePath())
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
