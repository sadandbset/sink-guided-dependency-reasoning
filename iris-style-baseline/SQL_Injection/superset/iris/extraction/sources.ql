/**
 * @name superset CWE-89 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   superset CodeQL database (snapshot 2f468900, Apache Superset 3.0.1 - the
 *   Superset application itself is the audit target): Flask request state
 *   reads (request.args / request.form / request.json / request.files /
 *   request.cookies / request.headers / request.data attribute reads, their
 *   .get()/.getlist() calls, their [key] subscript reads, and whole-mapping
 *   .to_dict()/.items() reads - request.values / request.query_string /
 *   request.get_json() have no read sites and are not matched);
 *   Flask-AppBuilder REST/view handler entry points (parameters of the 199
 *   @expose-decorated handlers, e.g. charts/api.py pk, sqllab/api.py
 *   client_id, and of the single @app.route health handler in
 *   views/health.py); the FAB @rison query-parsing injection boundary
 *   (kwargs["rison"] subscript reads and kwargs.get("rison") calls - the
 *   decorator parses request.args["q"] and injects the value as the keyword
 *   "rison"); click CLI input (parameters of <group>.command() /
 *   @click.group command functions plus @click.option / @click.argument
 *   registration rows across superset/cli); celery task input (parameters of
 *   @celery_app.task / @shared_task functions in superset/tasks and
 *   sql_lab.py); built-in open() / <obj>.read() file input (import/export
 *   ZIP/YAML bundle processing); os.environ environment reads; current_app
 *   config reads (operator-level trust); and call sites that hand positional
 *   arguments to internal functions which directly execute SQL or build
 *   SQLAlchemy TextClauses (e.g. sql_lab execute_sql_statement /
 *   execute_sql_statements, db_engine_spec.execute / apply_limit_to_sql /
 *   select_star, self.text(where) / get_text_clause(clause) clause hand-offs
 *   for WHERE/HAVING/RLS filters). Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not database
 *   analyze). This is a plain multi-column select query on purpose: @kind
 *   problem is the wrong shape for candidate tables and @kind table is not
 *   assumed to exist.
 * @id iris/superset/extraction/sources
 * @tags sql-injection
 */

import python

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable name (member name, function name, attribute name,
 *                   field name for request-state rows, decorator member name
 *                   for CLI registration rows)
 *   4. flow_kind  - "http_request" (request.<field> state read, including
 *                   whole-mapping reads), "request_param" (request.<field>
 *                   .get(...) / .getlist(...) / [key] read, kwargs["rison"] /
 *                   kwargs.get("rison") rison-injected query args),
 *                   "param" (@expose / @app.route handler parameter),
 *                   "cli" (click command parameter or option registration),
 *                   "task_param" (celery task parameter), "env", "file",
 *                   "config" (current_app.config / app.config read),
 *                   "internal_transfer" (positional argument handed to an
 *                   internal function that directly executes SQL or builds a
 *                   TextClause)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "request"/"request.<field>"/"kwargs"/"os"/
 *                   "current_app"/"click"/"self" or "" if none; "<expr>" when
 *                   the object expression is neither Name nor Attribute;
 *                   enclosing class name for handler/task/CLI function
 *                   parameter rows)
 *   6. moduleHint - module hint: dotted python module path of the containing
 *                   module (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "os"/"builtins"/"file" for environment and file
 *                   input families
 *   7. arg_index  - 0-based positional argument index (parameter position in
 *                   the function definition for "param"/"cli"/"task_param"
 *                   rows, including the self/cls slot for methods; index of
 *                   the key argument for keyed reads; index of the transferred
 *                   positional argument for "internal_transfer" rows), -1 if
 *                   N/A
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
 * the flask request object, FAB-injected kwargs, click options, celery
 * payloads, os.environ and current_app.config are framework-injected values,
 * not module members, so all families below are AST-level matches and the
 * match_kind column is kept "ast" for cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /tests/ (integration_tests,
 * unit_tests, fixtures), /superset-db/ (the CodeQL database directory sits
 * inside the source tree), /migrations/ (290 alembic version files - static
 * migration SQL, classified FP for all passes by the workflow's Step 6
 * heuristics), /node_modules/, /superset-frontend/, /superset-websocket/,
 * /docs/.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Top-level scripts that are not on an import path
 *  (setup.py, scripts/*.py) have no dotted module name; their file base name
 *  is used instead. */
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

/** Receiver hint for the callee expression of a call ("" when there is no attribute receiver). */
string receiverHintOfCall(Call c) {
  exists(Attribute a |
    a = c.getFunc() and
    result = receiverHint(a)
  )
  or
  not c.getFunc() instanceof Attribute and result = ""
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
  path.replaceAll("\\", "/").matches("%/superset-db/%")
  or
  path.replaceAll("\\", "/").matches("%/migrations/%")
  or
  path.replaceAll("\\", "/").matches("%/node_modules/%")
  or
  path.replaceAll("\\", "/").matches("%/superset-frontend/%")
  or
  path.replaceAll("\\", "/").matches("%/superset-websocket/%")
  or
  path.replaceAll("\\", "/").matches("%/docs/%")
}

/* ------------------------------------------------------------------ */
/* Shared SQL-channel shapes (kept consistent with sinks.ql)            */
/* ------------------------------------------------------------------ */

/**
 * SQL execution members observed in this project: <obj>.execute(...) is the
 * only execution member with call sites (cursor.execute on DBAPI cursors
 * from engine.raw_connection(), engine.execute / db.engine.execute,
 * connection.execute / db.session.execute of SQLAlchemy Core constructs,
 * engine-spec execute adapters). executemany / executescript / callproc are
 * NOT observed anywhere in the application tree (grep over superset/
 * excluding migrations and tests) and are deliberately not matched.
 * Matching is receiver-name-agnostic on purpose: cursors, engines,
 * connections and sessions are obtained as local variables or attributes
 * (conn.cursor(), engine.raw_connection(), db.session, self.db_engine_spec),
 * so receiver identity cannot be resolved syntactically.
 */
private predicate sqlExecuteMember(string member) {
  member = "execute"
}

/** Any call site of an SQL execution member (syntax-level, alias-tolerant). */
private predicate sqlExecuteCall(Call c) {
  sqlExecuteMember(c.getFunc().(Attribute).getName())
}

/** pandas SQL execution: pd.read_sql_query(...) (3 call sites observed;
 *  plain read_sql is only mentioned in docstrings and is not matched). */
private predicate pandasSqlCall(Call c) {
  c.getFunc().(Attribute).getName() = "read_sql_query"
}

/** SQLAlchemy TextClause construction calls (SQL object creation, candidate
 *  intermediate nodes): bare text(...) imported from sqlalchemy, the
 *  project's own <obj>.text(...) wrappers (ExploreMixin.text /
 *  SqlaTable.text), and <obj>.get_text_clause(...) (BaseEngineSpec). The SQL
 *  fragment is argument 0 in all three shapes. */
private predicate textClauseCall(Call c) {
  c.getFunc().(Name).getId() = "text"
  or
  c.getFunc().(Attribute).getName() = "text"
  or
  c.getFunc().(Attribute).getName() = "get_text_clause"
}

/**
 * The SQL Lab execution entry points (module-level functions in
 * superset/sql_lab.py): execute_sql_statement (sql_statement at parameter
 * position 0) directly drives db_engine_spec.execute_with_cursor /
 * cursor.execute, and execute_sql_statements (rendered_query at parameter
 * position 1) splits the rendered (jinja-processed) query into statements
 * and drives execute_sql_statement. Matched by function name and file path
 * so engine-spec-local helpers with the same names cannot collide.
 */
private predicate sqlLabExecutionFunction(Function f) {
  (
    f.getName() = "execute_sql_statement"
    or
    f.getName() = "execute_sql_statements"
  ) and
  normalizedPathOf(f).matches("%/superset/sql_lab.py")
}

/** Functions whose body directly executes SQL (execute-family call or
 *  pandas SQL execution) or builds a TextClause (text / self.text /
 *  get_text_clause call), plus the SQL Lab entry points above. */
private predicate sqlWrapperFunction(Function f) {
  sqlLabExecutionFunction(f)
  or
  exists(Call c |
    (sqlExecuteCall(c) or pandasSqlCall(c) or textClauseCall(c)) and
    c.getScope().(Function) = f
  )
}

/**
 * Holds if c is a call site whose callee plausibly targets the SQL wrapper
 * function f: an attribute call whose member name matches f's name (any
 * receiver - covers self.<method>(), database.<method>(),
 * db_engine_spec.<method>() chains), or, for module-level wrapper functions,
 * a bare-name call. Wrapper functions whose own name is an SQL channel
 * member (execute / text / get_text_clause / read_sql_query) are excluded
 * here: direct <obj>.execute(...) call sites are modeled as sink rows in
 * sinks.ql and direct text()/self.text()/get_text_clause() calls as
 * text-clause rows, so only calls that hand values INTO the SQL layer
 * through a differently-named wrapper (e.g. execute_sql_statement,
 * execute_sql_statements, apply_limit_to_sql, select_star, query-builder
 * methods) become internal_transfer rows. Name-only resolution is subject
 * to dynamic dispatch ambiguity (documented in detection.json
 * uncoveredCases).
 */
private predicate callsSqlWrapper(Call c, Function f) {
  sqlWrapperFunction(f) and
  not sqlChannelMember(f.getName()) and
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

/** Names whose call sites are already modeled directly as sink rows in
 *  sinks.ql (execution members, TextClause members, pandas SQL execution). */
private predicate sqlChannelMember(string name) {
  name = "execute"
  or
  name = "text"
  or
  name = "get_text_clause"
  or
  name = "read_sql_query"
}

/* ------------------------------------------------------------------ */
/* Source family shapes                                                */
/* ------------------------------------------------------------------ */

/**
 * Request state fields actually observed with read sites in the application
 * tree (non-test, non-migration): request.args (61 reads),
 * request.form (70), request.json (52), request.files (7),
 * request.cookies (3), request.headers (3), request.data (1).
 * request.values and request.query_string have ZERO read sites and are not
 * listed. request.method / request.path / request.remote_addr are
 * framework-computed request metadata and are NOT emitted.
 */
private predicate requestField(string field) {
  field = "args"
  or
  field = "form"
  or
  field = "json"
  or
  field = "files"
  or
  field = "cookies"
  or
  field = "headers"
  or
  field = "data"
}

/**
 * Whole-mapping accessor methods observed on request state:
 * request.form.to_dict() (2 sites), request.args.to_dict() (1),
 * request.args.items() (1). The form data of chart-data / explore
 * endpoints flows through these.
 */
private predicate requestDictMethod(string method) {
  method = "to_dict"
  or
  method = "items"
}

/**
 * Flask-AppBuilder handler entry points: functions decorated with
 * @expose(...) (from flask_appbuilder.api import expose - 199 sites in 52
 * per-domain api.py files plus superset/views FAB views). Both the called
 * form @expose("/<pk>") and a bare @expose (not observed, harmless) match.
 */
private predicate isExposeHandler(Function f) {
  exists(Call dc |
    dc = f.getADecorator().(Call) and
    (
      dc.getFunc().(Name).getId() = "expose"
      or
      dc.getFunc().(Attribute).getName() = "expose"
    )
  )
  or
  exists(Expr d |
    d = f.getADecorator() and
    d.(Name).getId() = "expose"
  )
}

/** Flask route handler entry points: functions decorated with
 *  <obj>.route(...) (the single @app.route site is views/health.py:23-26). */
private predicate isRouteHandler(Function f) {
  exists(Call dc |
    dc = f.getADecorator().(Call) and
    dc.getFunc().(Attribute).getName() = "route"
  )
}

/**
 * click CLI command entry points: functions decorated with
 * <group>.command() / @click.group(...) (superset/cli/main.py
 * @click.group + @superset.command(), cli/examples.py @click.command, and
 * the other superset/cli modules - 76 click/with_appcontext decorator
 * sites). Command parameters are click-injected CLI input.
 */
private predicate isClickCommand(Function f) {
  exists(Call dc |
    dc = f.getADecorator().(Call) and
    (
      dc.getFunc().(Attribute).getName() = "command"
      or
      dc.getFunc().(Attribute).getName() = "group"
    )
  )
}

/**
 * celery task entry points: functions decorated with @celery_app.task(...)
 * or @shared_task(...) (10 sites: superset/sql_lab.py, superset/tasks/
 * async_queries.py, cache.py, scheduler.py, thumbnails.py). Task parameters
 * carry request-derived payloads (queue consumer boundary).
 */
private predicate isCeleryTask(Function f) {
  exists(Call dc |
    dc = f.getADecorator().(Call) and
    (
      dc.getFunc().(Attribute).getName() = "task"
      or
      dc.getFunc().(Name).getId() = "shared_task"
    )
  )
  or
  exists(Expr d |
    d = f.getADecorator() and
    d.(Name).getId() = "shared_task"
  )
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: request state attribute reads: request.args / request.form /
     request.json / request.files / request.cookies / request.headers /
     request.data (the flask request proxy is always accessed through the
     plain name `request` in this codebase; a `self.request` variant is not
     observed) */
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
  /* family 2: request.<field>.get(...) / .getlist(...) reads (argument 0
     carries the key); 51 request.args.get sites, 14 request.form.get,
     8 request.json.get, 7 request.files.get, 1 request.headers.get,
     1 request.cookies.get, 1 request.args.getlist */
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    (func.getName() = "get" or func.getName() = "getlist") and
    base = func.getObject().(Attribute) and
    requestField(base.getName()) and
    base.getObject().(Name).getId() = "request" and
    node = c and
    flowKind = "request_param" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "request." + base.getName() and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3: request.<field>[...] subscript reads (index carries the key),
     e.g. json.loads(request.form["passwords"]) (charts/api.py:1098),
     json.loads(request.form["form_data"]) (charts/data/api.py:225),
     request.args["q"] */
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
  /* family 4: whole-mapping reads on request state:
     request.<field>.to_dict() / .items() */
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    requestDictMethod(func.getName()) and
    base = func.getObject().(Attribute) and
    requestField(base.getName()) and
    base.getObject().(Name).getId() = "request" and
    node = c and
    flowKind = "http_request" and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = "request." + base.getName() and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 5: FAB @rison injection boundary: the @rison decorator parses
     request.args["q"] (rison format) and injects the parsed value as the
     keyword "rison"; the boundary visible in this tree is the kwargs read -
     kwargs["rison"] (32 sites) with a literal "rison" index */
  exists(Subscript s |
    s.getObject().(Name).getId() = "kwargs" and
    s.getIndex().(StringLiteral).getText() = "rison" and
    node = s and
    flowKind = "request_param" and
    callableName = "kwargs" and
    argIndex = 0 and
    receiver = "kwargs" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 5b: kwargs.get("rison") (views/base_api.py:574) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    func.getObject().(Name).getId() = "kwargs" and
    c.getPositionalArg(0).(StringLiteral).getText() = "rison" and
    node = c and
    flowKind = "request_param" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "kwargs" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 6: FAB handler entry-point parameters (@expose handlers - route
     path variables such as pk / client_id / digest / dashboard_id_or_slug
     and ordinary handler parameters; self is excluded; arg_index is the
     0-based position in the function definition including the self slot
     for methods) */
  exists(Function f, Parameter p |
    isExposeHandler(f) and
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
  /* family 7: Flask route handler parameters (@app.route - the health
     endpoint in views/health.py) */
  exists(Function f, Parameter p |
    isRouteHandler(f) and
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
  /* family 8: click CLI command parameters (parameters of functions
     decorated with <group>.command() / @click.group - click injects the
     parsed option values into them) */
  exists(Function f, Parameter p |
    isClickCommand(f) and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "cli" and
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
  /* family 9: click option/argument registrations: @click.option("--foo")
     / @click.argument("name") decorator calls (argument 0 carries the
     option name); the receiver hint records the group (click / superset /
     cli / db) */
  exists(Function f, Call dc, Attribute func |
    dc = f.getADecorator().(Call) and
    func = dc.getFunc().(Attribute) and
    (func.getName() = "option" or func.getName() = "argument") and
    node = dc and
    flowKind = "cli" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(dc) and
    matchKind = "ast"
  )
  or
  /* family 10: celery task parameters (queue consumer boundary; parameters
     carry request-derived payloads, e.g. fetch_url(data, headers),
     cache_warmup(strategy_name, *args, **kwargs)) */
  exists(Function f, Parameter p |
    isCeleryTask(f) and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "task_param" and
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
  /* family 11: environment reads: os.environ / os.environ[...] /
     os.environ.get(...) (13 sites; operator-level trust) */
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
  /* family 12: config reads: current_app.config[...] / app.config[...]
     subscript reads and current_app.config.get(...) calls (83 sites;
     operator-level trust, NOT attacker input - emitted for labeling to
     classify as such) */
  exists(Subscript s, Attribute cfg |
    cfg = s.getObject().(Attribute) and
    cfg.getName() = "config" and
    (
      cfg.getObject().(Name).getId() = "current_app"
      or
      cfg.getObject().(Name).getId() = "app"
    ) and
    node = s and
    flowKind = "config" and
    callableName = "config" and
    argIndex = 0 and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast" and
    (
      cfg.getObject().(Name).getId() = "current_app" and
      receiver = "current_app.config"
      or
      cfg.getObject().(Name).getId() = "app" and
      receiver = "app.config"
    )
  )
  or
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    base = func.getObject().(Attribute) and
    base.getName() = "config" and
    (
      base.getObject().(Name).getId() = "current_app"
      or
      base.getObject().(Name).getId() = "app"
    ) and
    node = c and
    flowKind = "config" and
    callableName = "get" and
    argIndex = 0 and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast" and
    (
      base.getObject().(Name).getId() = "current_app" and
      receiver = "current_app.config"
      or
      base.getObject().(Name).getId() = "app" and
      receiver = "app.config"
    )
  )
  or
  /* family 13: file input: built-in open(...) (17 sites - import/export
     ZIP/YAML bundle readers); the path is argument 0 */
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
  /* family 14: file content reads: <obj>.read() (return value carries file
     content) */
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
  /* family 15: positional arguments handed to internal SQL-channel
     functions (view/processor/task -> data access layer transfers, e.g.
     execute_sql_statement(statement, ...) / execute_sql_statements(...,
     rendered_query, ...) in sql_lab.py, database.select_star(...) /
     db_engine_spec.apply_limit_to_sql(...) / select_star(...) calls, and
     the query-builder methods that receive request-derived query objects;
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
