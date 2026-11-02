/**
 * @name piccolo CWE-89 sink candidate extraction
 * @description Extract SQL execution sink candidates from the piccolo CodeQL
 *   database (snapshot e4946d8, piccolo 1.1.0, Python ORM library): every
 *   <obj>.execute(...) / <obj>.fetch(...) / <obj>.cursor(...) call site in
 *   the engine layer (the SQL text is positional argument 0) covering the
 *   asyncpg channels of PostgresEngine/CockroachEngine
 *   (connection.fetch / connection.execute / connection.cursor) and the
 *   aiosqlite channels of SQLiteEngine (connection.execute / cursor.execute
 *   - bound parameters at argument 1); companion "bound_params" rows
 *   marking the parameterized channel wherever a second positional argument
 *   is present so safe parameterization is distinguishable from SQL text;
 *   "raw_sql_template" / "raw_bound_args" rows for Table.raw(...) /
 *   WhereRaw(...) / OrderByRaw(...) call sites (execution chain:
 *   Raw -> Query._run -> engine.run_querystring -> connection.fetch /
 *   execute); "dynamic_sql_template" rows for QueryString(...) calls whose
 *   template argument is not a string literal (Where.querystring,
 *   Table.raw, ON CONFLICT assembly, select.py query += assembly); dynamic
 *   SQL construction nodes (f-strings, '%'-formatting of a literal template,
 *   .format() template calls, string concatenation) that are (a) directly
 *   the SQL text argument of an execution call (engine SAVEPOINT / BEGIN /
 *   ROWID-lookup f-strings), (b) directly the template argument of a
 *   QueryString(...) call (LIMIT / OFFSET / AS OF / ORDER BY / GROUP BY /
 *   RETURNING / DISTINCT ON f-string templates), (c) inside SQL-producing
 *   functions (default_querystrings / *_querystrings / querystring /
 *   values_querystring / target_string / action_string / ddl / *_ddl /
 *   _get_joins - select.py FROM/join assembly, the operator template
 *   .format() assembly in Where.querystring, ALTER and CREATE DDL
 *   statements), or (d) directly the template argument of a raw-family
 *   call; and the internal SQL wrapper functions themselves (engine
 *   functions that directly execute SQL, and app-layer functions that await
 *   a raw-family call). Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not database
 *   analyze). This is a plain multi-column select query on purpose: a
 *   problem-shaped query is the wrong shape for candidate tables, and no
 *   table query kind is assumed to exist.
 * @id iris/piccolo/extraction/sinks
 * @tags sql-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sources.ql and to the previous arches
 * / django runs):
 *   1. node       - candidate AST node (location-backed, decodes as
 *                   file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable name ("execute" / "fetch" / "cursor" for
 *                   execution rows, "raw" / "WhereRaw" / "OrderByRaw" /
 *                   "QueryString" for construction-boundary rows,
 *                   "percent_format" / "format" / "fstring" / "concat" for
 *                   construction rows, function name for wrapper rows)
 *   4. flow_kind  - "sql_text" (argument 0 of an execution call carries the
 *                   SQL query text), "bound_params" (argument 1 carries the
 *                   bound parameter list - the safe channel, emitted so the
 *                   labeling step can mark it as such), "raw_sql_template"
 *                   / "raw_bound_args" (Table.raw / WhereRaw / OrderByRaw
 *                   call sites - the raw SQL API boundary),
 *                   "dynamic_sql_template" (QueryString call whose template
 *                   argument is not a string literal),
 *                   "sql_percent_format" / "sql_format_call" / "sql_fstring"
 *                   / "sql_concat" (dynamic SQL construction),
 *                   "internal_sql_wrapper" (function whose body directly
 *                   executes SQL), "raw_call_wrapper" (function whose body
 *                   awaits a raw-family call)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression, e.g. "connection" / "cursor" / "self" /
 *                   "table_class"; "" if none; "<expr>" if the object
 *                   expression is neither Name nor Attribute)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module` is
 *                   not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index carrying the SQL text
 *                   (1 for bound_params / raw_bound_args rows), -1 for
 *                   construction and wrapper rows
 *   8. file       - absolute file path, obtained through the Location API
 *                   (AstNode.getLocation().getFile().getAbsolutePath();
 *                   AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Sink modeling decision (per the task contract): only "the SQL query text
 * executed by the database, or SQL fragments able to influence SQL syntax"
 * is modeled as the dangerous sink (argument index 0 of the asyncpg
 * fetch/execute/cursor and aiosqlite execute calls). String construction
 * expressions and SQL template strings are extracted as candidate
 * intermediate nodes (sql_* construction rows / dynamic_sql_template rows)
 * together with their actual execution relationship (direct argument of an
 * execution call, template of a QueryString, inside a SQL-producing
 * function, or template of a raw-family call). The bound parameter channels
 * (asyncpg *args after the query text, aiosqlite execute(query, args)
 * argument 1, QueryString/Raw args after the template) are extracted as
 * their own flow kinds so that safe parameterization is NOT treated as a
 * dangerous sink by virtue of that binding.
 *
 * In this project no sink row is expected to resolve at API level: asyncpg
 * and aiosqlite are loaded through LazyLoader into local names
 * (postgres.py:15, sqlite.py:21, cockroach.py:10), so API graphs cannot
 * bind connection.fetch/execute/cursor to library members. Matching is
 * receiver-name-agnostic on purpose (connections/cursors are local
 * variables or attributes); all rows are "ast" and the match_kind column is
 * kept for cross-project contract consistency.
 *
 * Channels NOT observed in this project (no rules fabricated for them, see
 * detection.json): cursor.executemany(), cursor.executescript(),
 * cursor.callproc(), psycopg / psycopg2, SQLAlchemy text() /
 * from_statement(), django connection.cursor() / Manager.raw() / RawSQL() /
 * extra(), direct stdlib sqlite3 DB-API execution (sqlite3 is used only for
 * register_adapter / register_converter / sqlite_version_info).
 * QueryString.__str__ renders values into a display string via
 * template.format - it is debug output, never executed, and deliberately
 * not a sink family.
 *
 * Excluded paths (applied to every row): /tests/, /piccolo-db/,
 * /piccolo-safe-db/ (the CodeQL database directories sit inside the source
 * tree), /piccolo_migrations/ (generated migration code), /docs/.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint).
 *  Top-level scripts that are not on an import path (main.py, setup.py,
 *  piccolo_conf.py, profiling/*.py) have no dotted module name; their file
 *  base name is used instead. */
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

/** Receiver hint for the callee expression of a call ("" when there is no
 *  attribute receiver). */
string receiverHintOfCall(Call c) {
  exists(Attribute a |
    a = c.getFunc() and
    result = receiverHint(a)
  )
  or
  not c.getFunc() instanceof Attribute and result = ""
}

/** Syntactic name of the callee of a call ("<expr>" if it is neither Name
 *  nor Attribute). */
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
  path.replaceAll("\\", "/").matches("%/piccolo-db/%")
  or
  path.replaceAll("\\", "/").matches("%/piccolo-safe-db/%")
  or
  path.replaceAll("\\", "/").matches("%/piccolo_migrations/%")
  or
  path.replaceAll("\\", "/").matches("%/docs/%")
}

/* ------------------------------------------------------------------ */
/* Sink family 1: SQL execution call sites                             */
/* ------------------------------------------------------------------ */

/**
 * SQL execution members observed in this project: asyncpg
 * connection.fetch / connection.execute / connection.cursor (engine
 * postgres.py, inherited by cockroach) and aiosqlite
 * connection.execute / cursor.execute (engine sqlite.py). Matching is
 * receiver-name-agnostic on purpose: connections and cursors are local
 * variables or attributes (connection, current_transaction.connection,
 * self.connection, self.cursor, cursor), so receiver identity cannot be
 * resolved syntactically; every <obj>.fetch(...) / <obj>.execute(...) /
 * <obj>.cursor(...) call in a non-excluded file is extracted and
 * receiver-collision noise is left to the labeling step. In non-test
 * library code these members only occur in the engine layer.
 * executemany / executescript / callproc are NOT observed in this project
 * and are deliberately not matched.
 */
private predicate sqlExecuteMember(string member) {
  member = "execute"
  or
  member = "fetch"
  or
  member = "cursor"
}

/** Any call site of an SQL execution member (syntax-level,
 *  alias-tolerant). */
private predicate sqlExecuteCall(Call c) {
  sqlExecuteMember(c.getFunc().(Attribute).getName())
}

/** Functions whose body directly executes SQL through a fetch/execute/
 *  cursor call. */
private predicate sqlWrapperFunction(Function f) {
  exists(Call c |
    sqlExecuteCall(c) and
    c.getScope().(Function) = f
  )
}

/* ------------------------------------------------------------------ */
/* Sink family 2: raw SQL API boundary call sites                      */
/* ------------------------------------------------------------------ */

/**
 * Raw SQL API call sites: `Table.raw(template, *args)` (attribute call on
 * the table class), `WhereRaw(sql, *args)` and `OrderByRaw(sql)` (name
 * calls). Execution chain: Raw -> Query._run (query/base.py) ->
 * engine.run_querystring -> connection.fetch / connection.execute. The
 * template string is positional argument 0; arguments 1+ are the bound
 * parameter channel. WhereRaw/OrderByRaw have no non-test call sites in
 * library code (docstring usage only) but the API exists and is matched.
 */
private predicate rawFamilyCall(Call c) {
  c.getFunc().(Attribute).getName() = "raw"
  or
  c.getFunc().(Name).getId() in ["WhereRaw", "OrderByRaw"]
}

/** Functions whose body awaits / calls a raw-family call (app-layer SQL
 *  wrappers, e.g. schema generate.py get_indexes / get_tablenames). */
private predicate rawWrapperFunction(Function f) {
  exists(Call c |
    rawFamilyCall(c) and
    c.getScope().(Function) = f
  )
}

/* ------------------------------------------------------------------ */
/* Sink families 3: dynamic SQL construction nodes                     */
/* ------------------------------------------------------------------ */

/**
 * Dynamic SQL string construction shapes:
 *   - '%' string-formatting (BinaryExpr with a Mod operator and a literal
 *     template string on the left), e.g. the '%s' Readable templates;
 *   - .format(...) template calls, e.g. the operator template formatting
 *     in Where.querystring (combination.py) and QueryString.__str__;
 *   - f-string literals (Fstring), e.g. all the delegate templates and
 *     engine statement strings;
 *   - string concatenation (BinaryExpr with an Add operator where at least
 *     one operand is a string literal).
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
 * SQL-producing functions: the engine-dispatched querystring/DDL properties
 * of the query builders and DDL statements (default_querystrings,
 * postgres/sqlite/cockroach_querystrings, default/postgres/sqlite/
 * cockroach_ddl, ddl), the per-clause querystring properties of the
 * delegates and combinables (querystring, querystring_for_update,
 * values_querystring) and the ON CONFLICT string builders (target_string,
 * action_string), plus the join-clause builder _get_joins of select.py.
 * Construction expressions inside these functions feed the SQL text even
 * when the final QueryString call receives an intermediate variable (e.g.
 * `query += f" {columns_str} FROM {tablename}"`, or the operator template
 * .format() assembly in Where.querystring).
 */
private predicate sqlProducingFunction(Function f) {
  f.getName() = "default_querystrings"
  or
  f.getName() = "postgres_querystrings"
  or
  f.getName() = "sqlite_querystrings"
  or
  f.getName() = "cockroach_querystrings"
  or
  f.getName() = "default_ddl"
  or
  f.getName() = "postgres_ddl"
  or
  f.getName() = "sqlite_ddl"
  or
  f.getName() = "cockroach_ddl"
  or
  f.getName() = "ddl"
  or
  f.getName() = "querystring"
  or
  f.getName() = "querystring_for_update"
  or
  f.getName() = "values_querystring"
  or
  f.getName() = "target_string"
  or
  f.getName() = "action_string"
  or
  f.getName() = "_get_joins"
}

/**
 * A construction candidate is
 *   (a) directly the SQL text argument (positional index 0) of a
 *       fetch/execute/cursor call (engine statement f-strings: SAVEPOINT,
 *       BEGIN, ROLLBACK TO SAVEPOINT, the ROWID lookup SELECT, CREATE
 *       EXTENSION),
 *   (b) directly the template argument (positional index 0) of a
 *       QueryString(...) call (LIMIT / OFFSET / AS OF / ORDER BY /
 *       GROUP BY / RETURNING / DISTINCT ON / VALUES f-string templates),
 *   (c) directly the template argument (positional index 0) of a
 *       raw-family call (e.g. the f"SELECT {RowMeta...} FROM
 *       information_schema.columns" template in schema generate.py), or
 *   (d) a construction expression located inside a SQL-producing function
 *       and not itself directly executed/bound as an argument (the value
 *       is assembled into a variable first, e.g. select.py query += ...
 *       followed by QueryString(query, *args), or ALTER/CREATE DDL
 *       statements returned from ddl properties).
 * Cross-function construction (value built outside any SQL-producing
 * function and outside these direct-argument positions) is not traced here
 * - see detection.json uncoveredCases.
 */
private predicate sqlConstructionCandidate(AstNode n) {
  isSqlConstructionExpr(n) and
  (
    exists(Call c |
      sqlExecuteCall(c) and
      n = c.getPositionalArg(0)
    )
    or
    exists(Call c |
      c.getFunc().(Name).getId() = "QueryString" and
      n = c.getPositionalArg(0)
    )
    or
    exists(Call c |
      rawFamilyCall(c) and
      n = c.getPositionalArg(0)
    )
    or
    (
      exists(Function f |
        sqlProducingFunction(f) and
        n.getScope().(Function) = f
      )
      and
      not exists(Call c |
        (sqlExecuteCall(c) or rawFamilyCall(c)) and
        n = c.getPositionalArg(0)
      )
      and
      not exists(Call c |
        c.getFunc().(Name).getId() = "QueryString" and
        n = c.getPositionalArg(0)
      )
    )
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
  /* family 1: SQL text argument of fetch/execute/cursor calls
     (argument index 0 carries the SQL query text) */
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
  /* family 2: bound-parameter channel - emitted only where the execution
     call passes a second positional argument (aiosqlite
     execute(query, args); asyncpg fetch(query, *args)), marking the call
     as parameterized; the SQL text itself stays in the family 1 row and
     the bound list is NOT treated as a dangerous sink argument */
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
  /* family 3: raw SQL API boundary - Table.raw / WhereRaw / OrderByRaw
     call sites; argument 0 is the SQL template (influences SQL syntax),
     arguments 1+ ride the bound-parameter channel (i is bound by range
     membership before the indexed getPositionalArg lookup; calls with
     more than 10 positional arguments are not scanned) */
  exists(Call c, int i |
    rawFamilyCall(c) and
    i in [0 .. 9] and
    exists(Expr arg | arg = c.getPositionalArg(i)) and
    node = c and
    (
      i = 0 and
      flowKind = "raw_sql_template"
      or
      i > 0 and
      flowKind = "raw_bound_args"
    ) and
    callableName = calledNameOf(c) and
    argIndex = i and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 4: dynamic SQL template - QueryString(...) calls whose template
     argument (positional index 0) is not a string literal, e.g.
     Where.querystring QueryString(template, *args), Table.raw
     QueryString(sql, *args), the ON CONFLICT assembly
     QueryString(query.rstrip(","), *values) and select.py
     QueryString(query, *args) after `query += ...` assembly; the
     concatenated "({} " + operator + " {})" template in Combination is
     covered here as well (a non-literal concat expression) */
  exists(Call c, Expr template |
    c.getFunc().(Name).getId() = "QueryString" and
    template = c.getPositionalArg(0) and
    not template instanceof StringLiteral and
    node = c and
    flowKind = "dynamic_sql_template" and
    callableName = "QueryString" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 5: dynamic SQL construction nodes
     ('%'-formatting / .format() / f-strings / concatenation) qualified by
     their actual execution relationship (direct SQL text argument of an
     execution call, direct template argument of QueryString / a raw-family
     call, or inside a SQL-producing function) */
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
      /* .format() template call (e.g. the operator template formatting in
         Where.querystring) */
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
  /* family 6: internal SQL wrapper functions (engine functions whose body
     directly executes SQL through fetch/execute/cursor - summary-step
     candidates for the labeling stage) */
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
  /* family 7: raw-call wrappers - app-layer functions whose body calls /
     awaits a raw-family call (Table.raw await sites in schema
     generate.py); these are the internal wrappers standing between app
     data and the engine execution chain */
  exists(Function f |
    rawWrapperFunction(f) and
    not sqlWrapperFunction(f) and
    node = f and
    flowKind = "raw_call_wrapper" and
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
