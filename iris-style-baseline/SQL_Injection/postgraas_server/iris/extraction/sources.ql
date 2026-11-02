/**
 * @name postgraas_server CWE-89 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   postgraas_server CodeQL database (snapshot bd4f1b8, postgraas_server
 *   v2.0.0b1, a Flask / flask-restful "PostgreSQL-as-a-service" management
 *   server with a psycopg2 pg_cluster backend): flask-restful
 *   reqparse.RequestParser().parse_args() call sites in the two REST
 *   resources (the HTTP POST/DELETE argument boundary - postgraas_instance_
 *   name / db_name / db_username / db_pwd in the collection POST,
 *   management_resources.py:133, db_pwd in the item DELETE,
 *   management_resources.py:74); parameters of flask-restful Resource verb
 *   methods (get/delete(self, id) - the /api/v2/postgraas_instances/<int:id>
 *   URL converter boundary) and of @<obj>.route-decorated handler functions;
 *   click CLI entry parameters (prometheus_app run_server test/port); config
 *   file input (built-in open() and json.load() in configuration.py:
 *   application.cfg and /secrets - operator-level trust, labeling decides);
 *   parameters of the SQL data-access layer functions
 *   (postgraas_server/backends/postgres_cluster/postgres_cluster_driver.py:
 *   _create_pg_connection / check_db_or_user_exists / create_postgres_db /
 *   get_normalized_username / delete_database / delete_user - the trust
 *   boundary through which handler values enter SQL construction);
 *   parameters of the backend wrapper classes (PGClusterBackend /
 *   DockerBackend create/delete/exists/__init__ - intermediate propagation
 *   nodes); internal transfer call sites handing values toward the data
 *   layer (pgcd.* driver calls in backends/postgres_cluster/__init__.py,
 *   current_app.postgraas_backend.create/delete/exists dynamic dispatch in
 *   management_resources.py, and the DBInstance(...) constructor keyword
 *   arguments built from POST values); and ORM query call sites
 *   (<model>.query.get/all/filter_by) whose return values carry meta-DB row
 *   content (entity.db_name/entity.username are re-fed into the backend
 *   delete path). Raw BQRS extraction query: run with `codeql query run` and
 *   decode with `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: a problem-shaped query is the wrong
 *   shape for candidate tables, and no table query kind is assumed to exist.
 * @id iris/postgraas_server/extraction/sources
 * @tags sql-injection
 */

import python

/*
 * Column contract (identical order to sinks.ql and to the previous arches /
 * django / piccolo runs):
 *   1. node       - candidate AST node (location-backed, decodes as
 *                   file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable name (handler verb, function name, member name,
 *                   or builtin name)
 *   4. flow_kind  - "http_request" (reqparse parse_args boundary),
 *                   "route_param" (Resource verb / route-decorated handler
 *                   parameter), "cli" (click entry parameter),
 *                   "config_file" (open()), "config_load" (json.load()),
 *                   "api_param" (SQL driver function parameter - the
 *                   data-access-layer trust boundary), "wrapper_param"
 *                   (backend class method parameter - intermediate node),
 *                   "internal_transfer" (positional/keyword argument handed
 *                   toward the data layer at a call site), "db_content" (ORM
 *                   query call whose return value carries DB rows)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression, e.g. "parser" / "query" / "pgcd" /
 *                   "current_app.postgraas_backend"; "" if none; enclosing
 *                   class name for method/parameter rows)
 *   6. moduleHint - module hint: dotted python module path of the containing
 *                   module, or the external module name for stdlib families
 *                   (variable intentionally named moduleHint; `module` is not
 *                   a valid QL variable name here)
 *   7. arg_index  - 0-based positional index (parameter position in the
 *                   function definition with `self` excluded for
 *                   api_param/wrapper_param/route_param rows; argument index
 *                   for the open()/json.load() families; -1 when not
 *                   applicable, including keyword-argument transfer rows)
 *   8. file       - absolute file path, obtained through the Location API
 *                   (AstNode.getLocation().getFile().getAbsolutePath();
 *                   AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates and functions),
 * does not assign API::Node values to DataFlow::Node variables, and keeps
 * every variable bound through a positive body. In this project no source
 * row is expected to resolve at API level: the request data arrives through
 * flask-restful reqparse instances and framework-injected method parameters,
 * the backend dispatch goes through the Flask app object attribute
 * current_app.postgraas_backend, and the SQL driver is reached through the
 * aliased module import `pgcd` - none of these bind to library API graph
 * nodes. All families below are AST-level matches and the match_kind column
 * is kept "ast" for cross-project contract consistency.
 *
 * Absent channels (documented in detection.json, no rules fabricated):
 * no flask request.args/form/json/body/header/cookie attribute reads (the
 * HTTP surface is reqparse + the <int:id> URL converter only), no sys.argv
 * reads, no input() prompts, no os.environ reads, no message-queue
 * consumers, no Django shapes.
 *
 * Excluded paths (applied to every row): /tests/, /postgraas_server-db/,
 * /postgraas_server-safe-db/ (the CodeQL database directories sit inside the
 * source tree), /docs/.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Scripts that are not on an import path (setup.py,
 *  docs/conf.py) have no dotted module name; their file base name is used
 *  instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getShortName()
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

/** 0-based parameter position of p in the definition of f, with a leading
 *  `self`/`cls` parameter (Parameter.isSelf()) excluded so the first real
 *  argument of a method gets index 0; module-level functions are counted
 *  from 0 directly. */
int paramIndex(Function f, Parameter p) {
  exists(Parameter s |
    s = f.getAnArg() and
    s.isSelf() and
    p.getPosition() > 0 and
    result = p.getPosition() - 1
  )
  or
  not exists(Parameter s | s = f.getAnArg() and s.isSelf()) and
  result = p.getPosition()
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
  path.replaceAll("\\", "/").matches("%/postgraas_server-db/%")
  or
  path.replaceAll("\\", "/").matches("%/postgraas_server-safe-db/%")
  or
  path.replaceAll("\\", "/").matches("%/docs/%")
}

/** True iff the path is the pg_cluster SQL driver module (the data-access
 *  layer whose function parameters form the api_param family). */
bindingset[path]
predicate driverModulePath(string path) {
  path.replaceAll("\\", "/").matches("%/backends/postgres_cluster/postgres_cluster_driver.py")
}

/** True iff the path is inside the backends package but is not the SQL
 *  driver module itself (the backend wrapper classes form the wrapper_param
 *  family; the driver is covered by api_param). */
bindingset[path]
predicate wrapperModulePath(string path) {
  path.replaceAll("\\", "/").matches("%/postgraas_server/backends/%") and
  not path.replaceAll("\\", "/").matches("%/backends/postgres_cluster/postgres_cluster_driver.py")
}

/** HTTP verb method names of flask-restful Resource classes. */
predicate resourceVerbName(string name) {
  name in ["get", "post", "put", "delete", "patch", "head", "options"]
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: HTTP request boundary - flask-restful
     reqparse.RequestParser().parse_args() call sites; the returned dict
     carries the POST/DELETE request arguments (db_pwd in the item DELETE,
     postgraas_instance_name / db_name / db_username / db_pwd in the
     collection POST) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "parse_args" and
    node = c and
    flowKind = "http_request" and
    callableName = "parse_args" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 2a: route parameters - parameters of flask-restful Resource verb
     methods (classes with a `Resource` base); the URL rule
     /api/v2/postgraas_instances/<int:id> maps the <int:id> converter onto
     the `id` parameter of DBInstanceResource.get/delete (arg_index is the
     0-based position with self excluded) */
  exists(Function f, Class cls, Parameter p |
    resourceVerbName(f.getName()) and
    f.getEnclosingScope() = cls and
    cls.getABase().(Name).getId() = "Resource" and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "route_param" and
    callableName = f.getName() and
    argIndex = paramIndex(f, p) and
    receiver = cls.getName() and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 2b: route parameters - parameters of functions decorated with
     @<obj>.route(...) (Flask app / blueprint routes; the handlers in this
     snapshot take no parameters, so this family is expected to yield no
     rows, but the shape is the flask.md route-handler boundary) */
  exists(Function f, Parameter p, Call dec, Attribute decFunc |
    dec = f.getADecorator().(Call) and
    decFunc = dec.getFunc().(Attribute) and
    decFunc.getName() = "route" and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "route_param" and
    callableName = f.getName() and
    argIndex = paramIndex(f, p) and
    receiver = "" and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 3: CLI boundary - parameters of click entry points (functions
     decorated with @<obj>.command(...) / @<obj>.option(...), i.e. the
     prometheus_app console script run_server(test, port)); the two
     argument-less main() console scripts yield no rows */
  exists(Function f, Parameter p, Call dec, Attribute decFunc |
    dec = f.getADecorator().(Call) and
    decFunc = dec.getFunc().(Attribute) and
    decFunc.getName() in ["command", "option"] and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "cli" and
    callableName = f.getName() and
    argIndex = paramIndex(f, p) and
    receiver = "" and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 4: config file input - built-in open(...) (path at argument 0):
     application.cfg (get_config) and /secrets (_load_secrets);
     operator-level trust, labeling decides */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    node = c and
    flowKind = "config_file" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtins" and
    matchKind = "ast"
  )
  or
  /* family 5: config deserialization - json.load(...) (the parsed config
     dict at argument 0) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "load" and
    func.getObject().(Name).getId() = "json" and
    node = c and
    flowKind = "config_load" and
    callableName = "load" and
    argIndex = 0 and
    receiver = "json" and
    moduleHint = "json" and
    matchKind = "ast"
  )
  or
  /* family 6: data-access-layer trust boundary - parameters of the SQL
     driver functions (postgres_cluster_driver.py: _create_pg_connection /
     check_db_or_user_exists / create_postgres_db / get_normalized_username
     / delete_database / delete_user); the labeled taint source for CWE-89
     at the SQL layer is exactly these parameter nodes */
  exists(Function f, Parameter p |
    driverModulePath(f.getLocation().getFile().getAbsolutePath()) and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "api_param" and
    callableName = f.getName() and
    argIndex = paramIndex(f, p) and
    receiver = "" and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 7: backend wrapper parameters - methods of the backend wrapper
     classes (PGClusterBackend / DockerBackend create / delete / exists /
     __init__); intermediate propagation nodes between the HTTP handlers and
     the driver, emitted for labeling triage (the driver module itself is
     covered by the api_param family) */
  exists(Function f, Parameter p |
    wrapperModulePath(f.getLocation().getFile().getAbsolutePath()) and
    f.getEnclosingScope() instanceof Class and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "wrapper_param" and
    callableName = f.getName() and
    argIndex = paramIndex(f, p) and
    receiver = f.getEnclosingScope().(Class).getName() and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 8a: internal transfers - positional arguments of the aliased
     driver calls pgcd.<fn>(...) in backends/postgres_cluster/__init__.py
     (create_postgres_db(connection_info, self.config),
     delete_database(entity.db_name, self.config),
     delete_user(entity.username, self.config),
     check_db_or_user_exists(entity.db_name, entity.username, self.config));
     i is bound by range membership before the indexed getPositionalArg
     lookup; calls with more than 10 positional arguments are not scanned */
  exists(Call c, Attribute func, int i |
    func = c.getFunc().(Attribute) and
    func.getObject().(Name).getId() = "pgcd" and
    i in [0 .. 9] and
    exists(Expr arg | arg = c.getPositionalArg(i)) and
    node = c.getPositionalArg(i) and
    flowKind = "internal_transfer" and
    callableName = func.getName() and
    argIndex = i and
    receiver = "pgcd" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 8b: internal transfers - positional arguments of the backend
     dispatch calls current_app.postgraas_backend.<create/delete/exists>(...)
     in management_resources.py; the target implementation (DockerBackend
     vs PGClusterBackend) is resolved at runtime via the BACKENDS registry,
     so this is a dynamic-dispatch boundary that AST matching cannot
     resolve further */
  exists(Call c, Attribute func, Attribute backend, int i |
    func = c.getFunc().(Attribute) and
    backend = func.getObject().(Attribute) and
    backend.getName() = "postgraas_backend" and
    func.getName() in ["create", "delete", "exists"] and
    i in [0 .. 9] and
    exists(Expr arg | arg = c.getPositionalArg(i)) and
    node = c.getPositionalArg(i) and
    flowKind = "internal_transfer" and
    callableName = func.getName() and
    argIndex = i and
    receiver = "current_app.postgraas_backend" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 8c: internal transfers - positional arguments of the
     DBInstance(...) model constructor call (management_resources.py:150);
     the entity fields persist the POST-derived values into the meta DB and
     are re-read on the delete path */
  exists(Call c, int i |
    c.getFunc().(Name).getId() = "DBInstance" and
    i in [0 .. 9] and
    exists(Expr arg | arg = c.getPositionalArg(i)) and
    node = c.getPositionalArg(i) and
    flowKind = "internal_transfer" and
    callableName = "DBInstance" and
    argIndex = i and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 8d: internal transfers - keyword arguments of the DBInstance(...)
     constructor call; in this snapshot all constructor arguments are
     keyword arguments (postgraas_instance_name=, db_name=, username=,
     password=, hostname=, port=), which carry the POST-derived values;
     keyword arguments have no positional index, so arg_index is -1 (the
     keyword names are visible at the node location) */
  exists(Call c, Keyword kw |
    c.getFunc().(Name).getId() = "DBInstance" and
    kw = c.getAKeyword().(Keyword) and
    node = kw.getValue() and
    flowKind = "internal_transfer" and
    callableName = "DBInstance" and
    argIndex = -1 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 9: DB content - ORM query call sites <model>.query.get/all/
     filter_by(...) whose return values carry meta-DB rows (entity.db_name /
     entity.username are re-fed into the backend delete path ->
     DROP DATABASE / DROP USER SQL); chained calls whose object expression
     is a Call (e.g. .filter_by(...).first()) only capture the inner
     filter_by row - see detection.json uncoveredCases */
  exists(Call c, Attribute func, Attribute obj |
    func = c.getFunc().(Attribute) and
    obj = func.getObject().(Attribute) and
    obj.getName() = "query" and
    func.getName() in ["get", "all", "first", "one", "filter_by", "filter"] and
    node = c and
    flowKind = "db_content" and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = receiverHint(func) and
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
  "source_candidate" as role,
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
