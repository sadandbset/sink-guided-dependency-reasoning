/**
 * @name django CWE-89 sink candidate extraction
 * @description Extract SQL execution sink candidates from the django CodeQL
 *   database (snapshot eb3699e, Django 2.2.4 - the Django framework source
 *   itself is the audit target): every <obj>.execute(...) /
 *   <obj>.executemany(...) / <obj>.callproc(...) call site (the SQL text
 *   argument is positional index 0) covering the ORM compilers
 *   (django/db/models/sql/compiler.py execute_sql), the central
 *   django.db CursorWrapper (django/db/backends/utils.py), the driver
 *   cursor wrappers of the mysql / oracle / sqlite3 backends, the
 *   schema_editor in migration operations, the GIS backends and the DB
 *   cache backend; companion "bound_params" rows marking the parameterized
 *   channel (argument index 1) wherever a bound argument list is passed;
 *   dynamic SQL construction nodes ('%'-formatting of a literal SQL
 *   template, .format() template calls, f-string literals, and string
 *   concatenation with a literal operand) both directly as the SQL text
 *   argument of an execution call and inside functions that directly
 *   execute SQL (e.g. 'CREATE DATABASE %(dbname)s %(suffix)s' % parameters
 *   in base/creation.py, 'SELECT * FROM %s LIMIT 1' %
 *   quote_name(table_name) in mysql/sqlite3 introspection, PRAGMA
 *   table_info(%s) construction, the GIS sql_add_spatial_index % {...}
 *   schema templates); the internal SQL wrapper functions themselves; and
 *   definition rows for the framework's own raw SQL channel APIs
 *   (QuerySet.raw / QuerySet.extra, RawSQL.__init__, RawQuery.__init__,
 *   RawQuerySet.__init__, CursorWrapper/SQLiteCursorWrapper/
 *   FormatStylePlaceholderCursor/BaseDatabaseSchemaEditor execute /
 *   executemany / callproc definitions) with the position of the
 *   SQL-text parameter and of the bound-parameter parameter. Raw BQRS
 *   extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong shape
 *   for candidate tables and @kind table is not assumed to exist.
 * @id iris/django/extraction/sinks
 * @tags sql-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable name ("execute" / "executemany" / "callproc"
 *                   for execution rows, "percent_format" / "format" /
 *                   "fstring" / "concat" for construction rows, function
 *                   name for wrapper rows, API member name for
 *                   sql_api_def rows)
 *   4. flow_kind  - "sql_text" (argument 0 of an execution call, or the
 *                   SQL-text parameter of a raw-SQL API definition, or the
 *                   procedure name of callproc, carries the SQL query text
 *                   or a SQL fragment affecting SQL syntax), "bound_params"
 *                   (argument 1 of an execution call, or the bound-parameter
 *                   parameter of a raw-SQL API definition, carries the bound
 *                   parameter list - the safe channel, emitted so the
 *                   labeling step can mark it as such),
 *                   "sql_percent_format" / "sql_format_call" / "sql_fstring"
 *                   / "sql_concat" (dynamic SQL construction),
 *                   "internal_sql_wrapper" (function whose body directly
 *                   executes SQL) and "sql_api_def" (definition row of a
 *                   framework raw SQL channel API)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression, e.g. "cursor" / "self" / "schema_editor";
 *                   enclosing class name for wrapper and API definition
 *                   rows; "" if none; "<expr>" if the object expression is
 *                   neither Name nor Attribute)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module` is
 *                   not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index carrying the SQL text
 *                   (or 1 for bound_params call rows; the parameter
 *                   position for sql_api_def rows), -1 for construction and
 *                   wrapper rows
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Sink modeling decision (per the task contract): only "the SQL query text
 * executed by the database, or SQL fragments able to influence SQL syntax"
 * is modeled as the dangerous sink (argument index 0 of
 * execute/executemany/callproc, and the SQL-text parameter of the raw SQL
 * channel API definitions). String construction expressions and SQL
 * template strings are extracted as candidate intermediate nodes
 * (sql_percent_format / sql_format_call / sql_fstring / sql_concat rows)
 * together with their actual execution relationship (direct argument of an
 * execution call, or located inside a function that directly executes
 * SQL). The bound parameter list (argument index 1 / the params parameter)
 * is extracted as its own flow kind so that safe parameterization is
 * distinguishable from SQL text - a call with a bound parameter list is NOT
 * treated as a dangerous sink by virtue of that binding. The framework's
 * ORM filter()/exclude()/order_by() channel compiles to parameterized SQL
 * and is deliberately not extracted as raw SQL.
 *
 * In this project no sink row is expected to resolve at API level: all SQL
 * execution flows through local cursor variables (cursor =
 * connection.cursor() as cursor, self.cursor, schema_editor parameters,
 * wrapper chains), which API graphs cannot bind to django.db or driver
 * members. The match_kind column is kept for cross-project contract
 * consistency and all rows are "ast".
 *
 * Channels NOT observed in this project (no rules fabricated for them, see
 * detection.json): QuerySet.from_statement(), cursor.executescript(),
 * SQLAlchemy (text() / from_statement()), psycopg2/mogrify execution,
 * connection.execute(). Manager.raw()/Manager.extra() definitions do not
 * exist as defs (QuerySet methods are copied onto Manager at runtime).
 *
 * Excluded paths (applied to every row): /tests/, /django-db/ (the CodeQL
 * database directory sits inside the source tree), /docs/, /js_tests/,
 * /node_modules/, /fixtures/.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint).
 *  Top-level scripts that are not on an import path (setup.py) have no
 *  dotted module name; their file base name is used instead. */
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
/* Sink family 1: SQL execution call sites                             */
/* ------------------------------------------------------------------ */

/**
 * SQL execution members observed in this project: cursor.execute,
 * cursor.executemany and cursor.callproc - 224 execute-family call sites
 * under django/ (ORM compilers, backends, GIS backends, DB cache,
 * management commands). Matching is receiver-name-agnostic on purpose:
 * cursors are obtained as local variables (connection.cursor() as cursor,
 * self.cursor, schema_editor parameters, wrapper chains), so receiver
 * identity cannot be resolved syntactically; every <obj>.execute(...) /
 * <obj>.executemany(...) / <obj>.callproc(...) call in a non-excluded file
 * is extracted and receiver-collision noise is left to the labeling step.
 * executescript is NOT observed and deliberately not matched.
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

/* ------------------------------------------------------------------ */
/* Sink family 2: dynamic SQL construction nodes                       */
/* ------------------------------------------------------------------ */

/**
 * Dynamic SQL string construction shapes:
 *   - '%' string-formatting (BinaryExpr with a Mod operator and a literal
 *     template string on the left), e.g. 'CREATE DATABASE %(dbname)s
 *     %(suffix)s' % parameters (base/creation.py:156), "SELECT * FROM %s
 *     LIMIT 1" % quote_name(table_name) (mysql/sqlite3 introspection),
 *     'PRAGMA table_info(%s)' % quote_name(name) (sqlite3 introspection);
 *   - .format(...) template calls;
 *   - f-string literals (Fstring);
 *   - string concatenation (BinaryExpr with an Add operator where at least
 *     one operand is a string literal).
 * Variable-template '%' formatting (sql % {...} where the template is a
 * variable, e.g. django/db/backends/base/schema.py:796/:826,
 * django/db/models/constraints.py:40) is NOT captured by this shape - see
 * detection.json uncoveredCases.
 */
private predicate isSqlConstructionExpr(AstNode n) {
  n.(BinaryExpr).getOp() instanceof Mod and
  n.(BinaryExpr).getLeft() instanceof StringLiteral
  or
  n.(BinaryExpr).getOp() instanceof Add and
  (
    n.(BinaryExpr).getLeft() instanceof StringLiteral
    or
    n.(BinaryExpr).getRight() instanceof StringLiteral
  )
  or
  n instanceof Fstring
  or
  n.(Call).getFunc().(Attribute).getName() = "format"
}

/**
 * A construction candidate is either
 *   (a) directly the SQL text argument (positional index 0) of an
 *       execute/executemany/callproc call, or
 *   (b) a construction expression located inside a function that directly
 *       executes SQL and not itself directly executed as an argument (the
 *       value is stored in a variable first, e.g. sql = 'UPDATE %s...' % x
 *       followed by cursor.execute(sql)).
 * Cross-function construction (value built in one function, executed in
 * another) is not traced here - see detection.json uncoveredCases.
 */
private predicate sqlConstructionCandidate(AstNode n) {
  isSqlConstructionExpr(n) and
  (
    exists(Call c |
      sqlExecuteCall(c) and
      n = c.getPositionalArg(0)
    )
    or
    (
      exists(Function f |
        sqlWrapperFunction(f) and
        n.getScope().(Function) = f
      )
      and
      not exists(Call c |
        sqlExecuteCall(c) and
        n = c.getPositionalArg(0)
      )
    )
  )
}

/* ------------------------------------------------------------------ */
/* Sink family 5: framework raw SQL channel API definitions            */
/* ------------------------------------------------------------------ */

/**
 * Raw SQL channel APIs of the framework itself, matched on (class name,
 * member name) of the definition plus the parameter position of the SQL
 * text (role "sql") and of the bound parameter list (role "bound"):
 *   - QuerySet.raw(self, raw_query, params=None, ...):
     django/db/models/query.py:781 - raw_query at 1, params at 2;
 *   - QuerySet.extra(self, select=None, where=None, params=None,
     tables=None, order_by=None, select_params=None): django/db/models/
     query.py:1087 - fragment-bearing select(1)/where(2)/tables(4)/
     order_by(5), bound params(3)/select_params(6);
 *   - RawSQL.__init__(self, sql, params, output_field=None):
     django/db/models/expressions.py:686 - sql at 1, params at 2;
 *   - RawQuery.__init__(self, sql, using, params=None):
     django/db/models/sql/query.py:71 - sql at 1, params at 3;
 *   - RawQuerySet.__init__(self, raw_query, model=None, query=None,
     params=None, ...): django/db/models/query.py:1330 - raw_query at 1,
     params at 4;
 *   - CursorWrapper.execute/executemany/callproc
     (django/db/backends/utils.py:48-70) and the mysql backend's
     CursorWrapper.execute/executemany (django/db/backends/mysql/base.py:
     67-84): SQL text at 1, bound list at 2;
 *   - CursorDebugWrapper.execute/executemany
     (django/db/backends/utils.py:96-116): same positions;
 *   - SQLiteCursorWrapper.execute/executemany
     (django/db/backends/sqlite3/base.py:379-387): same positions;
 *   - FormatStylePlaceholderCursor.execute/executemany
     (django/db/backends/oracle/base.py:505-524): same positions;
 *   - BaseDatabaseSchemaEditor.execute(self, sql, params=())
     (django/db/backends/base/schema.py:116): same positions.
 * Class-name matching is syntactic; the moduleHint column carries the
 * defining module so the labeling step can disambiguate.
 */
private predicate sqlApiParam(string cls, string member, string role, int argIndex) {
  (
    cls = "QuerySet" and member = "raw" and
    (role = "sql" and argIndex = 1 or role = "bound" and argIndex = 2)
  )
  or
  (
    cls = "QuerySet" and member = "extra" and
    (
      role = "sql" and argIndex = 1
      or role = "sql" and argIndex = 2
      or role = "sql" and argIndex = 4
      or role = "sql" and argIndex = 5
      or role = "bound" and argIndex = 3
      or role = "bound" and argIndex = 6
    )
  )
  or
  (
    (cls = "RawSQL" or cls = "RawQuery") and member = "__init__" and
    (
      (cls = "RawSQL" and role = "sql" and argIndex = 1)
      or
      (cls = "RawSQL" and role = "bound" and argIndex = 2)
      or
      (cls = "RawQuery" and role = "sql" and argIndex = 1)
      or
      (cls = "RawQuery" and role = "bound" and argIndex = 3)
    )
  )
  or
  (
    cls = "RawQuerySet" and member = "__init__" and
    (role = "sql" and argIndex = 1 or role = "bound" and argIndex = 4)
  )
  or
  (
    (
      cls = "CursorWrapper" or cls = "CursorDebugWrapper" or
      cls = "SQLiteCursorWrapper" or cls = "FormatStylePlaceholderCursor" or
      cls = "BaseDatabaseSchemaEditor"
    ) and
    (member = "execute" or member = "executemany" or member = "callproc") and
    (role = "sql" and argIndex = 1 or role = "bound" and argIndex = 2)
  )
}

/**
 * A framework raw SQL channel API definition: a function whose enclosing
 * class name and member name are covered by sqlApiParam. role/argIndex are
 * passed through to the row (paramRole is "sql" -> sql_text row,
 * "bound" -> bound_params row).
 */
private predicate sqlApiDefinition(Function f, string paramRole, int argIndex) {
  exists(Class cls, string member |
    f.getEnclosingScope() = cls and
    member = f.getName() and
    sqlApiParam(cls.getName(), member, paramRole, argIndex)
  )
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: SQL text argument of execute/executemany/callproc calls
     (argument index 0 carries the SQL query text, or the procedure name
     for callproc, which equally affects SQL structure) */
  exists(Call c |
    sqlExecuteCall(c) and
    node = c and
    callableName = c.getFunc().(Attribute).getName() and
    flowKind = "sql_text" and
    argIndex = 0 and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 2: bound-parameter channel - emitted only where the execution call
     passes a second positional argument (the bound parameter list), marking
     the call as parameterized; the SQL text itself stays in the family 1 row
     and the bound list is NOT treated as a dangerous sink argument */
  exists(Call c, Expr bound |
    sqlExecuteCall(c) and
    bound = c.getPositionalArg(1) and
    node = c and
    callableName = c.getFunc().(Attribute).getName() and
    flowKind = "bound_params" and
    argIndex = 1 and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3: dynamic SQL construction nodes
     ('%'-formatting / .format() / f-strings / concatenation) */
  exists(AstNode n |
    sqlConstructionCandidate(n) and
    node = n and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(n) and
    (
      /* '%' formatting of a literal SQL template */
      n.(BinaryExpr).getOp() instanceof Mod and
      flowKind = "sql_percent_format" and
      callableName = "percent_format" and
      receiver = ""
      or
      /* .format() template call on the SQL string variable */
      n.(Call).getFunc().(Attribute).getName() = "format" and
      flowKind = "sql_format_call" and
      callableName = "format" and
      receiver = receiverHint(n.(Call).getFunc().(Attribute))
      or
      /* f-string literal */
      n instanceof Fstring and
      flowKind = "sql_fstring" and
      callableName = "fstring" and
      receiver = ""
      or
      /* string concatenation with a literal operand */
      n.(BinaryExpr).getOp() instanceof Add and
      flowKind = "sql_concat" and
      callableName = "concat" and
      receiver = ""
    )
  )
  or
  /* family 4: internal SQL wrapper functions (functions whose body directly
     executes SQL - summary-step candidates for the labeling stage) */
  exists(Function f |
    sqlWrapperFunction(f) and
    node = f and
    flowKind = "internal_sql_wrapper" and
    callableName = f.getName() and
    argIndex = -1 and
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
  /* family 5: framework raw SQL channel API definitions (QuerySet.raw /
     QuerySet.extra / RawSQL / RawQuery / RawQuerySet / cursor wrapper and
     schema editor execute/executemany/callproc definitions); role "sql"
     yields a sql_text row at the SQL-text parameter position, role "bound"
     yields a bound_params row at the bound-parameter position */
  exists(Function f, string paramRole |
    sqlApiDefinition(f, paramRole, argIndex) and
    node = f and
    callableName = f.getName() and
    matchKind = "ast" and
    moduleHint = moduleHintOf(f) and
    receiver = f.getEnclosingScope().(Class).getName() and
    (
      paramRole = "sql" and flowKind = "sql_text"
      or
      paramRole = "bound" and flowKind = "bound_params"
    )
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  not excludedPath(node.getLocation().getFile().getAbsolutePath())
select
  node,
  "sink_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
