/**
 * @name arches CWE-89 sink candidate extraction
 * @description Extract SQL execution sink candidates from the arches CodeQL
 *   database (snapshot 75ce8f7, arches 7.1.0-beta, Django): every
 *   <obj>.execute(...) / <obj>.callproc(...) call site (the SQL text argument is
 *   positional index 0) covering django.db cursor.execute, schema_editor.execute
 *   in migration operations, and the direct psycopg2 cursors of
 *   setup_db.py / v3migration.py; companion "bound_params" rows marking the
 *   parameterized channel (argument index 1) wherever a bound argument list is
 *   passed; dynamic SQL construction nodes ('%'-formatting of a literal SQL
 *   template, .format() template calls, f-string literals, and string
 *   concatenation) both directly as the SQL text argument of an execution call
 *   and inside functions that directly execute SQL (e.g. the request-derived
 *   sql.format(query=...) in views/concept.py paged_dropdown, the
 *   '%%%s%%' subquery construction in models/concept.py get_child_edges, the
 *   .format(conceptid) in get_e55_domain, and the CLI-driven formats in
 *   setup_db.py / export.py); and the internal SQL wrapper functions
 *   themselves. Raw BQRS extraction query: run with `codeql query run` and
 *   decode with `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: a problem-shaped query is the wrong
 *   shape for candidate tables, and no table query kind is assumed to exist.
 * @id iris/arches/extraction/sinks
 * @tags sql-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable name ("execute" / "callproc" for execution rows,
 *                   "percent_format" / "format" / "fstring" / "concat" for
 *                   construction rows, function name for wrapper rows)
 *   4. flow_kind  - "sql_text" (argument 0 carries the SQL query text or a SQL
 *                   fragment affecting SQL syntax, e.g. the procedure name of
 *                   callproc), "bound_params" (argument 1 carries the bound
 *                   parameter list of a parameterized call - the safe channel,
 *                   emitted so the labeling step can mark it as such),
 *                   "sql_percent_format" / "sql_format_call" / "sql_fstring" /
 *                   "sql_concat" (dynamic SQL construction), and
 *                   "internal_sql_wrapper" (function whose body directly
 *                   executes SQL)
 *   5. receiver   - syntactic receiver hint (base name of the object expression,
 *                   e.g. "cursor" / "dbcursor" / "schema_editor" / "self" / "sql";
 *                   "" if none; "<expr>" if the object expression is neither
 *                   Name nor Attribute)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module` is not a
 *                   valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index carrying the SQL text
 *                   (or 1 for bound_params rows), -1 for construction and
 *                   wrapper rows
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Sink modeling decision (per the task contract): only "the SQL query text
 * executed by the database, or SQL fragments able to influence SQL syntax" is
 * modeled as the dangerous sink (argument index 0 of execute/callproc). String
 * construction expressions and SQL template strings are extracted as candidate
 * intermediate nodes (sql_*_format / sql_fstring / sql_concat rows) together
 * with their actual execution relationship (direct argument of an execution
 * call, or located inside a function that directly executes SQL). The bound
 * parameter list (argument index 1) is extracted as its own flow kind so that
 * safe parameterization is distinguishable from SQL text - a call with a bound
 * parameter list is NOT treated as a dangerous sink by virtue of that binding.
 *
 * In this project no sink row is expected to resolve at API level: all SQL
 * execution flows through local cursor variables (cursor = connection.cursor()
 * as cursor, self.dbcursor from psycopg2.connect, schema_editor parameters
 * injected by the migration framework), which API graphs cannot bind to
 * django.db or psycopg2 members. The match_kind column is kept for
 * cross-project contract consistency and all rows are "ast".
 *
 * Channels NOT observed in this project (no rules fabricated for them, see
 * detection.json): Manager.raw(), RawSQL(), QuerySet.extra(),
 * QuerySet.from_statement(), cursor.executemany(), cursor.executescript(),
 * sqlite3, SQLAlchemy (text() / from_statement()).
 *
 * Excluded paths (applied to every row): /tests/, /fixtures/, /arches-db/,
 * /arches-safe-db/ (the CodeQL database directories sit inside the source
 * tree), /node_modules/, /media/, /webpack/, /cypress/.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint).
 *  Top-level scripts that are not on an import path (manage.py, setup.py,
 *  docker/*.py) have no dotted module name; their file base name is used
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
/* Sink family 1: SQL execution call sites                             */
/* ------------------------------------------------------------------ */

/**
 * SQL execution members observed in this project: cursor.execute (django.db
 * cursors, schema_editor in migration operations, psycopg2 cursors) and
 * cursor.callproc. Matching is receiver-name-agnostic on purpose: cursors are
 * obtained as local variables (connection.cursor() as cursor, self.dbcursor,
 * schema_editor parameters), so receiver identity cannot be resolved
 * syntactically; every <obj>.execute(...) / <obj>.callproc(...) call in a
 * non-excluded file is extracted and receiver-collision noise is left to the
 * labeling step. executemany / executescript are NOT observed and deliberately
 * not matched.
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

/* ------------------------------------------------------------------ */
/* Sink families 2: dynamic SQL construction nodes                     */
/* ------------------------------------------------------------------ */

/**
 * Dynamic SQL string construction shapes:
 *   - '%' string-formatting (BinaryExpr with a Mod operator and a literal
 *     template string on the left), e.g. the '%%%s%%' LIKE subquery in
 *     models/concept.py get_child_edges and the '%s' templates in
 *     check_if_concept_in_use / post_tile_save;
 *   - .format(...) template calls, e.g. sql.format(query=..., conceptid=...)
 *     in views/concept.py paged_dropdown and models/concept.py
 *     get_child_edges / get_e55_domain;
 *   - f-string literals (Fstring);
 *   - string concatenation (BinaryExpr with an Add operator where at least one
 *     operand is a string literal).
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
 *       execute/callproc call, or
 *   (b) a construction expression located inside a function that directly
 *       executes SQL and not itself directly executed as an argument (the
 *       value is stored in a variable first, e.g. sql = sql.format(...)
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
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: SQL text argument of execute/callproc calls
     (argument index 0 carries the SQL query text, or the procedure name for
     callproc, which equally affects SQL structure) */
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
