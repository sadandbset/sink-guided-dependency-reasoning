/**
 * @name django CWE-89 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   django CodeQL database (snapshot eb3699e, Django 2.2.4 - the Django
 *   framework source itself is the audit target): WSGI environ reads at the
 *   request parse boundary (django/core/handlers/wsgi.py and
 *   django/http/request.py HttpHeaders/QueryDict, e.g. environ[...],
 *   environ.get(...), environ.items(), self.environ[...],
 *   get_script_name(environ)); Django request state reads
 *   (request.<field> / self.request.<field> for GET/POST/body/COOKIES/FILES/
 *   META, their .get()/.getlist() calls, their [key] subscript reads, and
 *   whole-mapping reads .items()/.copy()/.urlencode()); handler entry-point
 *   parameters (plain functions whose first parameter is `request`, class
 *   methods whose second parameter is `request` - covers CBV get/post/put/
 *   delete/patch and contrib.admin changelist_view/response_add style
 *   methods); class-based view URL route kwargs (self.kwargs reads);
 *   django management command CLI input (parser.add_argument registrations,
 *   options[...] reads, Command.handle() parameters, sys.argv); built-in
 *   open() / codecs.open() / .read() file input; settings.<ATTR> config
 *   reads; os.environ environment reads; and call sites that hand positional
 *   arguments to internal functions which directly execute SQL (e.g.
 *   introspection.get_table_list(cursor), CursorWrapper.execute ->
 *   _execute_with_wrappers hand-offs). Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not database
 *   analyze). This is a plain multi-column select query on purpose: @kind
 *   problem is the wrong shape for candidate tables and @kind table is not
 *   assumed to exist.
 * @id iris/django/extraction/sources
 * @tags sql-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable name (member name, function name, attribute name,
 *                   or field name for request-state rows)
 *   4. flow_kind  - "http_request" (WSGI environ or request.<field> state read,
 *                   including whole-mapping reads), "request_param"
 *                   (request.<field>.get(...)/.getlist(...)/[...] read),
 *                   "param" (handler parameter or self.kwargs route kwarg),
 *                   "cli" (management command input), "env", "file",
 *                   "config" (settings read), "internal_transfer" (positional
 *                   argument handed to an internal SQL-executing function)
 *   5. receiver   - syntactic receiver hint (base name of the object expression,
 *                   "request"/"request.GET"/"self.request"/"settings"/"options"/
 *                   "sys"/"self"/"environ" or "" if none; "<expr>" when the
 *                   object expression is neither Name nor Attribute)
 *   6. moduleHint - module hint: dotted python module path of the containing
 *                   module (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index (parameter position in
 *                   the function definition for "param"/"cli" rows; index of
 *                   the environ argument for environ-receiving calls; index of
 *                   the transferred positional argument for
 *                   "internal_transfer" rows; 0 for keyed reads), -1 if N/A
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
 * the Django request object, the WSGI environ, management command options and
 * settings are framework-injected values, not module members, so all families
 * below are AST-level matches and the match_kind column is kept "ast" for
 * cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /tests/, /django-db/ (the CodeQL
 * database directory sits inside the source tree), /docs/, /js_tests/,
 * /node_modules/, /fixtures/. The database source archive also covers tests/
 * (1883 files), docs/ (2 files) and repo-root scripts, which are filtered by
 * these path rules.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Top-level scripts that are not on an import path
 *  (manage.py, setup.py, docker/*.py) have no dotted module name; their file
 *  base name is used instead. */
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
  path.replaceAll("\\", "/").matches("%/django-db/%")
  or
  path.replaceAll("\\", "/").matches("%/docs/%")
  or
  path.replaceAll("\\", "/").matches("%/js_tests/%")
  or
  path.replaceAll("\\", "/").matches("%/node_modules/%")
  or
  path.replaceAll("\\", "/").matches("%/fixtures/%")
}

/* ------------------------------------------------------------------ */
/* Shared SQL-execution shapes (kept identical in spirit to sinks.ql)  */
/* ------------------------------------------------------------------ */

/**
 * SQL execution members observed in this project: cursor.execute
 * (django.db cursors, schema_editor in migration operations, driver cursors
 * reached through CursorWrapper._execute), cursor.executemany
 * (django/db/backends/utils.py:89, mysql/base.py:81, oracle/base.py:524,
 * sqlite3/base.py:387) and cursor.callproc
 * (django/db/backends/utils.py:59-64). Matching is receiver-name-agnostic on
 * purpose: cursors are obtained as local variables (cursor =
 * connection.cursor() as cursor, self.cursor, schema_editor parameters), so
 * the receiver identity cannot be resolved syntactically. executescript is
 * NOT observed in this project and is deliberately not matched.
 */
private predicate sqlExecuteMember(string member) {
  member = "execute"
  or
  member = "executemany"
  or
  member = "callproc"
}

/** Any call site of an SQL execution member (syntax-level, alias-tolerant). */
private predicate sqlExecuteCall(Call c) {
  sqlExecuteMember(c.getFunc().(Attribute).getName())
}

/** Functions whose body directly executes SQL through an
 *  execute/executemany/callproc call. */
private predicate sqlWrapperFunction(Function f) {
  exists(Call c |
    sqlExecuteCall(c) and
    c.getScope().(Function) = f
  )
}

/**
 * Holds if c is a call site whose callee plausibly targets the SQL wrapper
 * function f: an attribute call whose member name matches f's name (any
 * receiver - covers self.<method>(), connection.introspection.<method>(),
 * compiler.<method>() chains), or, for module-level wrapper functions, a
 * bare-name call. Wrapper functions whose own name is an SQL execution
 * member (execute/executemany/callproc) are excluded here: direct
 * .execute(...) call sites are modeled as sinks in sinks.ql, so only calls
 * that hand values INTO the SQL layer through a named wrapper (e.g.
 * CursorWrapper.execute -> _execute_with_wrappers, introspection helpers)
 * become internal_transfer rows. Name-only resolution is subject to dynamic
 * dispatch ambiguity (documented in detection.json uncoveredCases).
 */
private predicate callsSqlWrapper(Call c, Function f) {
  sqlWrapperFunction(f) and
  not sqlExecuteMember(f.getName()) and
  (
    exists(Attribute a |
      a = c.getFunc() and
      a.getName() = f.getName()
    )
    or
    c.getFunc().(Name).getId() = f.getName() and
    not f.getEnclosingScope() instanceof Class
  )
}

/* ------------------------------------------------------------------ */
/* Source family shapes                                                */
/* ------------------------------------------------------------------ */

/**
 * Request state fields actually observed in django request handling
 * (non-test framework code): request.GET (29 reads), request.POST (56),
 * request.META (36), request.COOKIES (7), request.FILES (5) plus 18
 * self.request.<field> reads in class-based views. request.body has NO read
 * sites outside tests (only defined at django/http/request.py and mentioned
 * in comments), and request.headers (property defined at
 * django/http/request.py:71) has NO read sites in non-test code; both stay
 * in the field list only where a read exists - body/header rows are
 * therefore not expected. request.user / request.method / request.path /
 * request.LANGUAGE_CODE are framework-computed identity/state and are NOT
 * emitted.
 */
private predicate requestField(string field) {
  field = "GET"
  or
  field = "POST"
  or
  field = "body"
  or
  field = "COOKIES"
  or
  field = "FILES"
  or
  field = "META"
}

/**
 * Whole-mapping accessor methods observed on request.<field>:
 * request.GET.items() (3), request.POST.items()/copy() (1+4),
 * request.FILES.items(), request.COOKIES.items(), request.GET.urlencode().
 * .update() (a write, django/views/debug.py) is not a source read and is
 * excluded.
 */
private predicate requestDictMethod(string method) {
  method = "items"
  or
  method = "copy"
  or
  method = "urlencode"
}

/** True iff e is the request object expression: the name `request` or the
 *  attribute `self.request` (class-based views store the request there,
 *  django/views/generic/base.py:87). */
private predicate isRequestExpr(Expr e) {
  e.(Name).getId() = "request"
  or
  e.(Attribute).getName() = "request" and
  e.(Attribute).getObject().(Name).getId() = "self"
}

/**
 * Django handler entry points:
 *   - module-level (or nested) functions whose parameter at position 0 is
 *     named `request` (the Django function-view convention);
 *   - methods of any class whose parameter at position 1 (after self) is
 *     named `request` - this covers CBV http verb methods
 *     (get/post/put/delete/patch/head: def get(self, request, ...)) and the
 *     contrib.admin ModelAdmin view methods (changelist_view(self, request,
 *     extra_context=None), response_add(self, request, obj, ...), add_view /
 *     change_view / delete_view) as well as middleware __call__(self,
 *     request) and process_request(self, request).
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
      p.getPosition() = 1
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
  /* family 1: request state reads: request.GET / request.POST /
     request.body / request.COOKIES / request.FILES / request.META and the
     self.request.<field> variants of class-based views */
  exists(Attribute a, Expr obj |
    requestField(a.getName()) and
    obj = a.getObject() and
    isRequestExpr(obj) and
    node = a and
    flowKind = "http_request" and
    callableName = a.getName() and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(a) and
    (
      obj.(Name).getId() = "request" and receiver = "request"
      or
      obj.(Attribute).getName() = "request" and receiver = "self.request"
    )
  )
  or
  /* family 2: request.<field>.get(...) / .getlist(...) reads (key name at
     argument 0); 56+ call sites in contrib.admin, contrib.auth, views,
     middleware */
  exists(Call c, Attribute func, Attribute base, Expr obj |
    func = c.getFunc().(Attribute) and
    (func.getName() = "get" or func.getName() = "getlist") and
    base = func.getObject().(Attribute) and
    requestField(base.getName()) and
    obj = base.getObject() and
    isRequestExpr(obj) and
    node = c and
    flowKind = "request_param" and
    callableName = func.getName() and
    argIndex = 0 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c) and
    (
      obj.(Name).getId() = "request" and
      receiver = "request." + base.getName()
      or
      obj.(Attribute).getName() = "request" and
      receiver = "self.request." + base.getName()
    )
  )
  or
  /* family 3: request.<field>[...] / self.request.<field>[...] subscript
     reads (index carries the key), e.g. request.META['SCRIPT_NAME']
     (django/contrib/admin/sites.py:295) or request.GET['year']
     (django/views/generic/dates.py:39) */
  exists(Subscript s, Attribute base, Expr obj |
    base = s.getObject().(Attribute) and
    requestField(base.getName()) and
    obj = base.getObject() and
    isRequestExpr(obj) and
    node = s and
    flowKind = "request_param" and
    callableName = base.getName() and
    argIndex = 0 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(s) and
    (
      obj.(Name).getId() = "request" and
      receiver = "request." + base.getName()
      or
      obj.(Attribute).getName() = "request" and
      receiver = "self.request." + base.getName()
    )
  )
  or
  /* family 4: whole-mapping reads on request state:
     request.<field>.items() / .copy() / .urlencode() - e.g.
     dict(request.GET.items()) (django/contrib/admin/views/main.py:70),
     request.POST.copy() (django/contrib/admin/options.py:1360) */
  exists(Call c, Attribute func, Attribute base, Expr obj |
    func = c.getFunc().(Attribute) and
    requestDictMethod(func.getName()) and
    base = func.getObject().(Attribute) and
    requestField(base.getName()) and
    obj = base.getObject() and
    isRequestExpr(obj) and
    node = c and
    flowKind = "http_request" and
    callableName = func.getName() and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c) and
    (
      obj.(Name).getId() = "request" and
      receiver = "request." + base.getName()
      or
      obj.(Attribute).getName() = "request" and
      receiver = "self.request." + base.getName()
    )
  )
  or
  /* family 5: handler entry-point parameters (function views, CBV verb
     methods, ModelAdmin/middleware methods; includes the `request`
     parameter itself and URL route parameters such as the generic date
     views' year/month/day or the detail view's pk/slug; self is excluded;
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
  /* family 6: class-based view URL route kwargs (self.kwargs, bound in
     django/views/generic/base.py View.setup; read in the date views as
     self.kwargs['year'] and in the detail view as
     self.kwargs.get(self.pk_url_kwarg)) */
  exists(Attribute a |
    a.getName() = "kwargs" and
    a.getObject().(Name).getId() = "self" and
    node = a and
    flowKind = "param" and
    callableName = "kwargs" and
    argIndex = -1 and
    receiver = "self" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    base = func.getObject().(Attribute) and
    base.getName() = "kwargs" and
    base.getObject().(Name).getId() = "self" and
    node = c and
    flowKind = "param" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "self.kwargs" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "kwargs" and
    base.getObject().(Name).getId() = "self" and
    node = s and
    flowKind = "param" and
    callableName = "kwargs" and
    argIndex = 0 and
    receiver = "self.kwargs" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 7: WSGI environ reads at the framework request parse boundary:
     environ[...] / environ.get(...) / environ.items() /
     self.environ[...] / self.environ.get(...) (django/core/handlers/wsgi.py
     WSGIRequest.__init__ and django/http/request.py HttpHeaders.__init__)
     and calls that receive environ positionally (get_script_name(environ),
     get_path_info(environ)) */
  exists(Subscript s |
    s.getObject().(Name).getId() = "environ" and
    node = s and
    flowKind = "http_request" and
    callableName = "environ" and
    argIndex = 0 and
    receiver = "environ" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (func.getName() = "get" or func.getName() = "items") and
    func.getObject().(Name).getId() = "environ" and
    node = c and
    flowKind = "http_request" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "environ" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  exists(Attribute a |
    a.getName() = "environ" and
    a.getObject().(Name).getId() = "self" and
    node = a and
    flowKind = "http_request" and
    callableName = "environ" and
    argIndex = -1 and
    receiver = "self" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  exists(Subscript s, Attribute base |
    base = s.getObject().(Attribute) and
    base.getName() = "environ" and
    base.getObject().(Name).getId() = "self" and
    node = s and
    flowKind = "http_request" and
    callableName = "environ" and
    argIndex = 0 and
    receiver = "self.environ" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    base = func.getObject().(Attribute) and
    base.getName() = "environ" and
    base.getObject().(Name).getId() = "self" and
    node = c and
    flowKind = "http_request" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "self.environ" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  exists(Call c, int i |
    i in [0 .. 9] and
    c.getPositionalArg(i).(Name).getId() = "environ" and
    node = c and
    flowKind = "http_request" and
    callableName = calledNameOf(c) and
    argIndex = i and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 8: CLI option registration: parser.add_argument(...) - 182 call
     sites across django/core/management and contrib apps */
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
  /* family 9: CLI option loads: options["operation"] / options["username"]
     - 166 subscript reads in management commands */
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
  /* family 10: management command handle() parameters (cli boundary);
     covers the *args/**options parameters of Command.handle */
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
  /* family 11: raw sys.argv read (django/core/management/__init__.py and
     dev utilities) */
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
  /* family 12: environment reads: os.environ / os.environ[...] /
     os.environ.get(...) (django/conf and bootstrap paths; operator-level
     trust) */
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
  /* family 13: file input: built-in open(...) (85 call sites, template
     loaders, file storage, fixture loading) and codecs.open(...) (path at
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
  /* family 14: file content reads: <obj>.read() (return value carries file
     content, e.g. fixture/fixture-file loads in
     django/core/management/commands/loaddata.py) */
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
  /* family 15: config reads: settings.<ATTR> (465 reads; operator-level
     trust; includes settings.DATABASES consumed by the backends) */
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
  /* family 16: positional arguments handed to internal SQL-executing
     functions (view/processor -> data access layer transfers, e.g.
     connection.introspection.get_table_list(cursor) and the
     CursorWrapper.execute -> _execute_with_wrappers(sql, params) chain;
     one row per positional argument, arg_index is the argument position
     (i is bound by range membership before the indexed getPositionalArg
     lookup; calls with more than 10 positional arguments are not scanned).
     Keyword-argument transfers are NOT captured - see detection.json
     uncoveredCases. */
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
