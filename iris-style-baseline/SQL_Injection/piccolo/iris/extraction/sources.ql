/**
 * @name piccolo CWE-89 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   piccolo CodeQL database (snapshot e4946d8, piccolo 1.1.0, Python ORM
 *   library with a targ CLI): parameters of CLI command callables
 *   (module-level functions under the piccolo/apps/<app>/commands
 *   modules, argv is mapped
 *   onto function parameters by the targ CLI registered in main.py),
 *   interactive input() prompts, raw sys.argv reads, os.environ reads,
 *   file input (built-in open(), <obj>.read() / read_text() content reads,
 *   load_json() deserialiser calls), parameters of the ORM's SQL-relevant
 *   public API methods (Table.raw / WhereRaw / QueryString.__init__ /
 *   where-limit-offset-order_by-as_of-values-on_conflict delegates / Column
 *   comparison operators / engine run_ddl-run_querystring-_run_in_* /
 *   Savepoint / rollback_to / Alter DDL name methods) - the trust boundary
 *   through which an embedding application's values enter SQL construction,
 *   dynamic table/column schema-name reads (_meta.tablename /
 *   _meta.db_column_name / get_formatted_tablename()) that feed SQL f-string
 *   templates, and internal_transfer rows for positional arguments handed to
 *   the raw()/where()/limit()/... API at call sites inside the repo's own
 *   apps. Raw BQRS extraction query: run with `codeql query run` and decode
 *   with `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: a problem-shaped query is the wrong
 *   shape for candidate tables, and no table query kind is assumed to exist.
 * @id iris/piccolo/extraction/sources
 * @tags sql-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sinks.ql and to the previous arches /
 * django runs):
 *   1. node       - candidate AST node (location-backed, decodes as
 *                   file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable name (member name, function name, builtin name,
 *                   or attribute name for state-read rows)
 *   4. flow_kind  - "cli" (CLI command function parameter), "interactive"
 *                   (input() prompt), "argv" (sys.argv read), "env"
 *                   (os.environ read), "file" (open / read / read_text /
 *                   load_json), "api_param" (ORM public API parameter - the
 *                   application-facing trust boundary), "schema_name"
 *                   (dynamic table/column name read feeding SQL templates),
 *                   "internal_transfer" (positional argument handed to the
 *                   ORM SQL API at an app-layer call site)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression, e.g. "sys" / "os" / "request-like" local
 *                   names / enclosing class name for methods; "" if none;
 *                   "<expr>" when the object expression is neither Name nor
 *                   Attribute)
 *   6. moduleHint - module hint: dotted python module path of the containing
 *                   module, or the external module name for stdlib families
 *                   (variable intentionally named moduleHint; `module` is not
 *                   a valid QL variable name here)
 *   7. arg_index  - 0-based positional index (parameter position in the
 *                   function definition for "cli"/"api_param" rows; argument
 *                   index for the open()/load_json() families; -1 when not
 *                   applicable)
 *   8. file       - absolute file path, obtained through the Location API
 *                   (AstNode.getLocation().getFile().getAbsolutePath();
 *                   AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, and keeps every variable
 * bound through a positive body. In this project no source row is expected
 * to resolve at API level: the asyncpg/aiosqlite drivers are LazyLoader
 * locals, the targ CLI injects argv into plain function parameters, and the
 * ORM API boundary is framework-injected state rather than module members,
 * so all families below are AST-level matches and the match_kind column is
 * kept "ast" for cross-project contract consistency.
 *
 * Absent channels (documented in detection.json, no rules fabricated):
 * no HTTP request surface (no request.GET/POST/body, no route parameters,
 * no web framework handlers), no message-queue consumers, no DRF shapes.
 * Config values (piccolo_conf DB engine config, engine.config reads) are
 * operator-level trust and not emitted.
 *
 * Excluded paths (applied to every row): /tests/, /piccolo-db/,
 * /piccolo-safe-db/ (the CodeQL database directories sit inside the source
 * tree), /piccolo_migrations/ (generated migration code), /docs/.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Top-level scripts that are not on an import path
 *  (main.py, setup.py, piccolo_conf.py, profiling/*.py) have no dotted
 *  module name; their file base name is used instead. */
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

/** True iff the candidate's file path is one of the excluded trees. Path is
 *  normalized to forward slashes before matching so the query works on both
 *  CodeQL path styles. bindingset[path] declares that the caller passes a
 *  bound path (the path only appears in checked positions such as the
 *  receiver of replaceAll/matches inside this predicate). */
bindingset[path]
predicate excludedPath(string path) {
  path.replaceAll("\\", "/").matches("%/tests/%")
  or
  path.replaceAll("\\", "/").matches("%/piccolo-db/%")
  or
  path.replaceAll("\\", "/").matches("%/piccolo-safe-db/%")
  or
  path.replaceAll("\\", "/").matches("%/piccolo_migrations/%")
  or
  path.replaceAll("\\", "/").matches("%/docs/%")
}

/** True iff the path is a piccolo CLI command module (approximation of the
 *  targ command registration in piccolo/main.py: every module-level function
 *  in these files is a candidate; helpers are filtered by labeling). */
bindingset[path]
predicate commandsModulePath(string path) {
  path.replaceAll("\\", "/").matches("%/piccolo/apps/%/commands/%")
}

/* ------------------------------------------------------------------ */
/* ORM SQL API surface (kept consistent with sinks.ql)                 */
/* ------------------------------------------------------------------ */

/**
 * (enclosing class, method name) pairs of the ORM's SQL-relevant public API,
 * all verified to exist in this snapshot. These are the points where an
 * embedding application's values enter SQL construction (Table.raw /
 * WhereRaw sql templates, where-limit-offset-order_by-as_of-values-
 * on_conflict clause delegates, Column comparison operator values, engine
 * query/ddl strings, savepoint names, Alter DDL name arguments).
 */
private predicate sqlApiMethod(string className, string methodName) {
  /* raw SQL channels */
  className = "Table" and methodName = "raw"
  or
  className = "WhereRaw" and methodName = "__init__"
  or
  className = "QueryString" and methodName = "__init__"
  or
  /* where clause construction */
  className = "Where" and methodName = "__init__"
  or
  className = "Column" and
  methodName in ["like", "ilike", "not_like", "is_in", "not_in",
                 "__eq__", "__ne__", "__lt__", "__le__", "__gt__", "__ge__"]
  or
  /* clause delegates whose arguments become template text */
  className = "LimitDelegate" and methodName = "limit"
  or
  className = "OffsetDelegate" and methodName = "offset"
  or
  className = "AsOfDelegate" and methodName = "as_of"
  or
  className = "OrderByDelegate" and methodName = "order_by"
  or
  className = "WhereDelegate" and methodName = "where"
  or
  className = "ValuesDelegate" and methodName = "values"
  or
  className = "OnConflictDelegate" and methodName = "on_conflict"
  or
  className = "DistinctDelegate" and methodName = "distinct"
  or
  className = "GroupByDelegate" and methodName = "group_by"
  or
  className = "ReturningDelegate" and methodName = "returning"
  or
  /* engine execution-layer string parameters */
  className = "Engine" and methodName in ["run_ddl", "run_querystring"]
  or
  className = "PostgresEngine" and
  methodName in ["run_ddl", "run_querystring", "_run_in_new_connection",
                 "_run_in_pool"]
  or
  className = "SQLiteEngine" and
  methodName in ["run_ddl", "run_querystring", "_run_in_new_connection",
                 "_run_in_existing_connection", "_get_inserted_pk"]
  or
  /* savepoint names - interpolated into SAVEPOINT statement f-strings */
  className = "Savepoint" and methodName = "__init__"
  or
  className = "PostgresTransaction" and methodName = "rollback_to"
  or
  className = "SQLiteTransaction" and methodName = "rollback_to"
  or
  /* ALTER DDL name arguments (incl. the verbatim using_expression) */
  className = "Alter" and
  methodName in ["rename_table", "rename_column", "set_column_type",
                 "drop_constraint", "set_schema"]
}

/**
 * Members through which app code hands values to the ORM SQL layer at call
 * sites (used for the internal_transfer family). Mirrors the api_param
 * method set plus the variadic clause builders.
 */
private predicate sqlApiMember(string member) {
  member = "raw"
  or
  member = "where"
  or
  member = "limit"
  or
  member = "offset"
  or
  member = "order_by"
  or
  member = "as_of"
  or
  member = "values"
  or
  member = "on_conflict"
  or
  member = "group_by"
  or
  member = "distinct"
  or
  member = "returning"
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: CLI command parameters - targ maps argv onto the parameters
     of command callables registered in piccolo/main.py; approximated as
     every non-lambda function at module level in the
     piccolo/apps/<app>/commands/ modules (arg_index is the 0-based parameter
     position, self excluded - these are module-level functions) */
  exists(Function f, Parameter p |
    f.getScope() instanceof Module and
    not f.isLambda() and
    commandsModulePath(f.getLocation().getFile().getAbsolutePath()) and
    p = f.getAnArg() and
    node = p and
    flowKind = "cli" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 2: interactive input() prompts (user create, migration
     backwards/clean confirmations, schema_differ rename prompts, asgi
     new) - the return value carries the interactive input */
  exists(Call c |
    c.getFunc().(Name).getId() = "input" and
    node = c and
    flowKind = "interactive" and
    callableName = "input" and
    argIndex = -1 and
    receiver = "" and
    moduleHint = "builtins" and
    matchKind = "ast"
  )
  or
  /* family 3: raw sys.argv reads (main.py diagnose flag / targ handoff) */
  exists(Attribute a |
    a.getName() = "argv" and
    a.getObject().(Name).getId() = "sys" and
    node = a and
    flowKind = "argv" and
    callableName = "argv" and
    argIndex = -1 and
    receiver = "sys" and
    moduleHint = "sys" and
    matchKind = "ast"
  )
  or
  /* family 4: environment reads: os.environ / os.environ[...] /
     os.environ.get(...) (PICCOLO_CONF resolution, tester env handling;
     operator-level trust - labeling decides) */
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
  /* family 5: file input - built-in open(...) (path at argument 0) */
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
  /* family 6: file content reads - <obj>.read() / <obj>.read_text()
     (return value carries the file content, e.g. fixtures load
     `contents = f.read()`) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["read", "read_text"] and
    node = c and
    flowKind = "file" and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "file" and
    matchKind = "ast"
  )
  or
  /* family 7: JSON deserialiser entry - load_json(...) (piccolo's
     orjson/json wrapper; fixtures file contents and DB JSON column values
     pass through it) */
  exists(Call c |
    c.getFunc().(Name).getId() = "load_json" and
    node = c and
    flowKind = "file" and
    callableName = "load_json" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "piccolo.utils.encoding" and
    matchKind = "ast"
  )
  or
  /* family 8: ORM SQL API parameters - the application-facing trust
     boundary (one row per non-self parameter; arg_index is the 0-based
     parameter position in the definition). The labeled taint source for
     CWE-89 in an ORM library is exactly these parameter nodes. */
  exists(Function f, Parameter p |
    sqlApiMethod(f.getEnclosingScope().(Class).getName(), f.getName()) and
    p = f.getAnArg() and
    not p.isSelf() and
    node = p and
    flowKind = "api_param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = f.getEnclosingScope().(Class).getName() and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 9: dynamic table/column schema-name reads - `x._meta.tablename`
     and `x._meta.db_column_name` attribute reads plus
     `x.get_formatted_tablename()` calls; these names are interpolated
     into SQL f-string templates (select.py FROM clause, ALTER/CREATE DDL)
     and originate from Table class definitions or DB reflection */
  exists(Attribute a, Attribute meta |
    meta = a.getObject().(Attribute) and
    meta.getName() = "_meta" and
    a.getName() in ["tablename", "db_column_name"] and
    node = a and
    flowKind = "schema_name" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "_meta" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get_formatted_tablename" and
    not exists(Expr arg | arg = c.getPositionalArg(0)) and
    node = c and
    flowKind = "schema_name" and
    callableName = "get_formatted_tablename" and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 10: internal transfers - positional arguments handed to the ORM
     SQL API at call sites inside the repo's own apps (e.g. schema
     generate.py `table_class.raw(template, schema_name, tablename)` where
     schema_name comes from the generate(schema_name) CLI parameter, and
     user tables.py `.where(...)` username clauses; i is bound by range
     membership before the indexed getPositionalArg lookup; calls with more
     than 10 positional arguments are not scanned). Keyword-argument
     transfers (Savepoint(name=...), SetColumnType(using_expression=...))
     are NOT captured - see detection.json uncoveredCases. */
  exists(Call c, Attribute func, int i |
    func = c.getFunc().(Attribute) and
    sqlApiMember(func.getName()) and
    i in [0 .. 9] and
    exists(Expr arg | arg = c.getPositionalArg(i)) and
    node = c.getPositionalArg(i) and
    flowKind = "internal_transfer" and
    callableName = func.getName() and
    argIndex = i and
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
  "source_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
