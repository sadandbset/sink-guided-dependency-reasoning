/**
 * @name arches CWE-89 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the arches
 *   CodeQL database (snapshot 75ce8f7, arches 7.1.0-beta, Django): Django request
 *   state (request.GET/POST/body/FILES/META attribute reads, their .get() calls and
 *   subscript reads), call sites passing request.body to JSON deserializers, handler
 *   entry-point parameters (function views whose first parameter is `request`, and
 *   get/post/put/delete/patch handler methods of class-based views, including URL
 *   route parameters such as conceptid/nodeid/zoom/x/y), django management command
 *   CLI input (parser.add_argument registrations, options[...] reads, handle()
 *   parameters, sys.argv), built-in open()/codecs.open()/ .read() file input,
 *   settings.<ATTR> config reads, os.environ environment reads, and call sites that
 *   hand positional arguments to internal functions which directly execute SQL
 *   (view -> Concept().get_e55_domain(conceptid) style transfers). Raw BQRS
 *   extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain multi-column select
 *   query on purpose: a problem-shaped query is the wrong shape for candidate
 *   tables, and no table query kind is assumed to exist.
 * @id iris/arches/extraction/sources
 * @tags sql-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable name (member name, function name, attribute name, or
 *                   field name for request-state rows)
 *   4. flow_kind  - "http_request" (request.<field> state read), "request_param"
 *                   (request.<field>.get(...) / request.<field>[...] read),
 *                   "http_body" (call receiving request.body), "param" (handler
 *                   parameter), "cli" (management command input), "env", "file",
 *                   "config" (settings read), "internal_transfer" (positional
 *                   argument handed to an internal SQL-executing function)
 *   5. receiver   - syntactic receiver hint (base name of the object expression,
 *                   "request"/"request.GET"/"settings"/"options"/"sys"/"self" or ""
 *                   if none; "<expr>" when the object expression is neither Name
 *                   nor Attribute)
 *   6. moduleHint - module hint: external module name, or dotted python module path
 *                   for internal candidates (variable intentionally named
 *                   moduleHint; `module` is not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index (parameter position in the
 *                   function definition for "param" rows; index of the request.body
 *                   argument for "http_body" rows; index of the transferred
 *                   positional argument for "internal_transfer" rows), -1 if N/A
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound through
 * a positive body, and keeps resolved-API matching strictly separate from AST
 * syntax matching (the match_kind column records which one produced a row).
 * In this project no source row is expected to resolve at API level: the Django
 * request object, management command options and settings are framework-injected
 * values, not module members, so all families below are AST-level matches and the
 * match_kind column is kept "ast" for cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /tests/, /fixtures/, /arches-db/,
 * /arches-safe-db/ (the CodeQL database directories sit inside the source tree),
 * /node_modules/, /media/, /webpack/, /cypress/.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for internal
 *  candidates). Top-level scripts that are not on an import path (manage.py,
 *  setup.py, docker/*.py) have no dotted module name; their file base name is used
 *  instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getShortName()
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

/** Receiver hint for the callee expression of a call ("" when there is no attribute receiver). */
string receiverHintOfCall(Call c) {
  exists(Attribute a |
    a = c.getFunc() and
    result = receiverHint(a)
  )
  or
  not c.getFunc() instanceof Attribute and result = ""
}

/** Syntactic name of the callee of a call ("<expr>" if it is neither Name nor Attribute). */
string calledNameOf(Call c) {
  result = c.getFunc().(Name).getId()
  or
  result = c.getFunc().(Attribute).getName()
  or
  not c.getFunc() instanceof Name and
  not c.getFunc() instanceof Attribute and
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
  path.replaceAll("\\", "/").matches("%/fixtures/%")
  or
  path.replaceAll("\\", "/").matches("%/arches-db/%")
  or
  path.replaceAll("\\", "/").matches("%/arches-safe-db/%")
  or
  path.replaceAll("\\", "/").matches("%/node_modules/%")
  or
  path.replaceAll("\\", "/").matches("%/media/%")
  or
  path.replaceAll("\\", "/").matches("%/webpack/%")
  or
  path.replaceAll("\\", "/").matches("%/cypress/%")
}

/* ------------------------------------------------------------------ */
/* Shared SQL-execution shapes (kept identical in spirit to sinks.ql)  */
/* ------------------------------------------------------------------ */

/**
 * SQL execution members observed in this project: cursor.execute (django.db and
 * psycopg2 cursors, and schema_editor.execute in migration operations) and
 * cursor.callproc (models/graph.py). Matching is receiver-name-agnostic on
 * purpose: cursors are obtained as local variables (connection.cursor() as
 * cursor, self.dbcursor, schema_editor parameters), so the receiver identity
 * cannot be resolved syntactically. executemany / executescript are NOT
 * observed in this project and are deliberately not matched.
 */
private predicate sqlExecuteMember(string member) {
  member = "execute"
  or
  member = "callproc"
}

/** Any call site of an SQL execution member (syntax-level, alias-tolerant). */
private predicate sqlExecuteCall(Call c) {
  sqlExecuteMember(c.getFunc().(Attribute).getName())
}

/** Functions whose body directly executes SQL through an execute/callproc call. */
private predicate sqlWrapperFunction(Function f) {
  exists(Call c |
    sqlExecuteCall(c) and
    c.getScope().(Function) = f
  )
}

/**
 * Holds if c is a call site whose callee plausibly targets the SQL wrapper
 * function f: an attribute call whose member name matches f's name with a
 * receiver that is `self`, a class instantiation (e.g. Concept().get_e55_domain),
 * or a name equal to the enclosing class name; or, for module-level wrapper
 * functions, a bare-name call. Name-only resolution is subject to dynamic
 * dispatch ambiguity (documented in detection.json uncoveredCases).
 */
private predicate callsSqlWrapper(Call c, Function f) {
  sqlWrapperFunction(f) and
  (
    f.getEnclosingScope() instanceof Class and
    c.getFunc().(Attribute).getName() = f.getName() and
    (
      c.getFunc().(Attribute).getObject().(Name).getId() = "self"
      or
      c.getFunc().(Attribute).getObject() instanceof Call
      or
      c.getFunc().(Attribute).getObject().(Name).getId() =
        f.getEnclosingScope().(Class).getName()
    )
    or
    not f.getEnclosingScope() instanceof Class and
    c.getFunc().(Name).getId() = f.getName()
  )
}

/* ------------------------------------------------------------------ */
/* Source family shapes                                                */
/* ------------------------------------------------------------------ */

/**
 * Request state fields actually observed in arches request handling:
 * request.GET (181 reads), request.POST (91), request.body (29),
 * request.FILES (12), request.META (9). request.user / request.method /
 * request.LANGUAGE_CODE are framework-computed identity/state, and the DRF
 * shapes (request.data / request.query_params / request.headers /
 * request.COOKIES) are not used in this project; none of those is emitted.
 */
private predicate requestField(string field) {
  field = "GET"
  or
  field = "POST"
  or
  field = "body"
  or
  field = "FILES"
  or
  field = "META"
}

/**
 * Django handler entry points:
 *   - module-level (or nested) functions whose parameter at position 0 is named
 *     `request` (the Django function-view convention, dispatched from
 *     arches/urls.py, e.g. concept.dropdown / concept.paged_dropdown /
 *     search.buffer);
 *   - get/post/put/delete/patch/head methods of any class whose parameters
 *     include `request` (class-based views: api.MVT(APIBase).get(self, request,
 *     nodeid, zoom, x, y) etc.).
 * dispatch()/as_view() plumbing is intentionally not treated as a handler.
 */
private predicate isDjangoHandler(Function f) {
  exists(Parameter p |
    p = f.getAnArg() and
    p.getName() = "request" and
    not p.isSelf() and
    (
      not f.getEnclosingScope() instanceof Class and
      p.getPosition() = 0
      or
      f.getEnclosingScope() instanceof Class and
      f.getName() in ["get", "post", "put", "delete", "patch", "head"]
    )
  )
}

/** Django management command handle() entry points (class Command(BaseCommand)). */
private predicate isCommandHandle(Function f) {
  f.getName() = "handle" and
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName() = "Command"
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: request state reads: request.GET / request.POST / request.body /
     request.FILES / request.META */
  exists(Attribute a |
    requestField(a.getName()) and
    a.getObject().(Name).getId() = "request" and
    node = a and
    flowKind = "http_request" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "request" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 2: request.<field>.get(...) reads (key name at argument 0) */
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    base = func.getObject().(Attribute) and
    requestField(base.getName()) and
    base.getObject().(Name).getId() = "request" and
    node = c and
    flowKind = "request_param" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "request." + base.getName() and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3: request.<field>[...] subscript reads (index carries the key) */
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    requestField(base.getName()) and
    base.getObject().(Name).getId() = "request" and
    node = s and
    flowKind = "request_param" and
    callableName = base.getName() and
    argIndex = 0 and
    receiver = "request." + base.getName() and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 4: calls receiving request.body positionally, e.g.
     JSONDeserializer().deserialize(request.body) - argument index recorded
     (i is bound by range membership before the indexed getPositionalArg
     lookup; calls with more than 10 positional arguments are not scanned) */
  exists(Call c, Attribute body, int i |
    i in [0 .. 9] and
    body = c.getPositionalArg(i).(Attribute) and
    body.getName() = "body" and
    body.getObject().(Name).getId() = "request" and
    node = c and
    flowKind = "http_body" and
    callableName = calledNameOf(c) and
    argIndex = i and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 5: handler entry-point parameters (function views and class-based
     view methods; includes the `request` parameter itself and URL route
     parameters such as conceptid / nodeid / zoom / x / y; self is excluded;
     arg_index is the 0-based position in the function definition) */
  exists(Function f, Parameter p |
    isDjangoHandler(f) and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    matchKind = "ast" and
    moduleHint = moduleHintOf(f) and
    (
      f.getEnclosingScope() instanceof Class and
      receiver = f.getEnclosingScope().(Class).getName()
      or
      not f.getEnclosingScope() instanceof Class and
      receiver = ""
    )
  )
  or
  /* family 6: management command handle() parameters (cli boundary) */
  exists(Function f, Parameter p |
    isCommandHandle(f) and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "cli" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    matchKind = "ast" and
    moduleHint = moduleHintOf(f) and
    receiver = f.getEnclosingScope().(Class).getName()
  )
  or
  /* family 7: CLI option registration: parser.add_argument(...) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "add_argument" and
    node = c and
    flowKind = "cli" and
    callableName = "add_argument" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 8: CLI option loads: options["operation"] / options["username"] */
  exists(Subscript s |
    s.getObject().(Name).getId() = "options" and
    node = s and
    flowKind = "cli" and
    callableName = "options" and
    argIndex = 0 and
    receiver = "options" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 9: raw sys.argv read (arches/app/utils/profile_stats.py) */
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
  /* family 10: environment reads: os.environ / os.environ[...] /
     os.environ.get(...) (settings_docker.py, celery/wsgi bootstrap;
     operator-level trust) */
  exists(Attribute a |
    a.getName() = "environ" and
    a.getObject().(Name).getId() = "os" and
    node = a and
    flowKind = "env" and
    callableName = "environ" and
    argIndex = -1 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "environ" and
    base.getObject().(Name).getId() = "os" and
    node = s and
    flowKind = "env" and
    callableName = "environ" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    base = func.getObject().(Attribute) and
    base.getName() = "environ" and
    base.getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "env" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 11: file input: built-in open(...) and codecs.open(...) (path at
     argument 0) */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    node = c and
    flowKind = "file" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtins" and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "open" and
    func.getObject().(Name).getId() = "codecs" and
    node = c and
    flowKind = "file" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "codecs" and
    moduleHint = "codecs" and
    matchKind = "ast"
  )
  or
  /* family 12: file content reads: <obj>.read() (return value carries file
     content, e.g. packages.load_sql: sql = f.read()) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "read" and
    node = c and
    flowKind = "file" and
    callableName = "read" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "file" and
    matchKind = "ast"
  )
  or
  /* family 13: config reads: settings.<ATTR> (operator-level trust; includes
     settings.DATABASES credentials and SRID/LANGUAGE constants that reach
     SQL construction in v3migration.py / concept.py) */
  exists(Attribute a |
    a.getObject().(Name).getId() = "settings" and
    node = a and
    flowKind = "config" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "settings" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 14: positional arguments handed to internal SQL-executing functions
     (view/processor -> data access layer transfers, e.g.
     Concept().get_e55_domain(conceptid) and _buffer(geometry, width, unit));
     one row per positional argument, arg_index is the argument position
     (i is bound by range membership before the indexed getPositionalArg
     lookup; calls with more than 10 positional arguments are not scanned).
     Keyword-argument transfers (e.g. query=query in
     get_child_collections_hierarchically) are NOT captured - see
     detection.json uncoveredCases. */
  exists(Call c, Function f, int i |
    i in [0 .. 9] and
    callsSqlWrapper(c, f) and
    node = c.getPositionalArg(i) and
    flowKind = "internal_transfer" and
    callableName = f.getName() and
    argIndex = i and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
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
