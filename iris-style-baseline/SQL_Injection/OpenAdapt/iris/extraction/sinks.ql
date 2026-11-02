/**
 * @name openadapt CWE-89 sink candidate extraction
 * @description Extract SQL execution sink candidates from the OpenAdapt
 *   CodeQL database (snapshot 0a0208e, openadapt 0.1.0 - a desktop
 *   GUI-automation recorder with a SQLAlchemy 1.4.43 data layer): every
 *   <obj>.execute(...) call site - exactly two exist in this project:
 *   db.execute(sa.insert(table), to_insert) (openadapt/crud.py:48,
 *   SQLAlchemy Session.execute over a Core insert statement with bound row
 *   values) and connection.execute(sql) (openadapt/crud.py:180, SQLAlchemy
 *   Connection.execute over a RAW SQL STRING received as create_db's sql
 *   parameter - the only injection-shaped execution channel), with the SQL
 *   text argument at positional index 0 and a companion "bound_params" row
 *   wherever a second positional argument (the bound value list) is passed;
 *   dynamic SQL construction nodes ('%'-formatting of a literal SQL
 *   template, .format() template calls, f-string literals, and string
 *   concatenation with a literal operand) captured under three relevance
 *   conditions - directly executed as the SQL text argument, located inside
 *   a function that directly executes SQL, or assigned to a local variable
 *   named `sql` (the observed case: the f-string
 *   "INSERT INTO recording VALUES (...)" built from DB-derived recording
 *   values at crud.py:142 and executed cross-function via
 *   create_db/connection.execute); the internal SQL wrapper functions
 *   themselves (_insert, create_db); and the SQLAlchemy Core statement
 *   construction call sa.insert(table) (crud.py:48, directly executed as
 *   argument 0 of db.execute). Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not database
 *   analyze). This is a plain multi-column select query on purpose: @kind
 *   problem is the wrong shape for candidate tables and @kind table is not
 *   assumed to exist.
 * @id iris/openadapt/extraction/sinks
 * @tags sql-injection
 */

import python

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable name ("execute" for execution rows,
 *                   "percent_format" / "format" / "fstring" / "concat" for
 *                   construction rows, function name for wrapper rows,
 *                   "insert" for the sql_object_construction row)
 *   4. flow_kind  - "sql_text" (argument 0 of an execution call, carries the
 *                   SQL query text or the SQL statement object that
 *                   determines the query syntax), "bound_params" (argument 1
 *                   of an execution call, carries the bound value list - the
 *                   safe channel, emitted so the labeling step can mark it
 *                   as such), "sql_percent_format" / "sql_format_call" /
 *                   "sql_fstring" / "sql_concat" (dynamic SQL construction),
 *                   "internal_sql_wrapper" (function whose body directly
 *                   executes SQL) and "sql_object_construction" (SQLAlchemy
 *                   Core statement construction call)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression, e.g. "db" / "connection" / "sa";
 *                   "" if none; "<expr>" if the object expression is
 *                   neither Name nor Attribute)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module` is
 *                   not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index carrying the SQL text
 *                   (or 1 for bound_params rows), -1 for construction,
 *                   wrapper and statement-object rows
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Sink modeling decision (per the task contract): only "the SQL query text
 * executed by the database, or SQL fragments able to influence SQL syntax"
 * is modeled as the dangerous sink (argument index 0 of execute; here
 * crud.py:48's argument 0 is a SQLAlchemy Core insert statement object and
 * crud.py:180's argument 0 is a raw SQL string). String construction
 * expressions are extracted as candidate intermediate nodes
 * (sql_percent_format / sql_format_call / sql_fstring / sql_concat rows)
 * together with their actual execution relationship (directly executed as
 * argument 0 of an execution call, located inside a function that directly
 * executes SQL, or assigned to the local variable `sql` that is handed to
 * the SQL layer - see uncoveredCases in detection.json for the
 * cross-function flow). The bound value list (argument index 1) is
 * extracted as its own flow kind so that safe parameterization is
 * distinguishable from SQL text - a call with a bound value list is NOT
 * treated as a dangerous sink by virtue of that binding. The ORM chains
 * (db.query(...).filter(...)/.order_by(...), db.add/commit/refresh) compile
 * to parameterized SQL and are deliberately not extracted as raw SQL.
 *
 * In this project NO row is expected to resolve at API level: the execute
 * methods belong to the sqlalchemy library (Session/Connection), which is
 * not part of the CodeQL database, so API graphs cannot bind the call sites
 * to library members. The match_kind column is kept for cross-project
 * contract consistency and all rows are "ast".
 *
 * Channels NOT observed in this project (no rules fabricated for them, see
 * detection.json): DB-API cursor.execute/executemany/executescript/callproc
 * (no cursor objects in project code), SQLAlchemy text() / from_statement(),
 * Query.raw()/extra() (no Django), psycopg/psycopg2, mogrify, and any other
 * execute-family member besides plain `execute`.
 *
 * Excluded paths (applied to every row): /tests/ (5 files of the database
 * snapshot) and /OpenAdapt-db/ (the CodeQL database directory sits inside
 * the source tree).
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
  path.replaceAll("\\", "/").matches("%/OpenAdapt-db/%")
}

/* ------------------------------------------------------------------ */
/* Sink family 1: SQL execution call sites                             */
/* ------------------------------------------------------------------ */

/**
 * SQL execution members observed in this project: only `execute` - the two
 * call sites are db.execute(sa.insert(table), to_insert)
 * (openadapt/crud.py:48, db = Session() at crud.py:23, SQLAlchemy 1.4
 * Session.execute with Core statement + values) and connection.execute(sql)
 * (openadapt/crud.py:180, connection from `with engine.begin()` at
 * crud.py:179, SQLAlchemy Connection.execute over a raw SQL string).
 * executemany, executescript and callproc are NOT observed and deliberately
 * not matched. Matching is receiver-name-agnostic on purpose: the Session
 * and Connection objects are local variables, so receiver identity cannot
 * be proven syntactically; every <obj>.execute(...) call in a non-excluded
 * file is extracted and receiver-collision noise is left to the labeling
 * step.
 */
private predicate sqlExecuteMember(string member) {
  member = "execute"
}

/** Any call site of an SQL execution member (syntax-level, alias-tolerant). */
private predicate sqlExecuteCall(Call c) {
  sqlExecuteMember(c.getFunc().(Attribute).getName())
}

/** Functions whose body directly executes SQL through an execute call:
 *  _insert (openadapt/crud.py:30-53, db.execute at :48) and create_db
 *  (openadapt/crud.py:150-184, connection.execute at :180). */
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
 *     template string on the left);
 *   - .format(...) template calls;
 *   - f-string literals (Fstring);
 *   - string concatenation (BinaryExpr with an Add operator where at least
 *     one operand is a string literal).
 * The only construction site in this project that builds SQL text is the
 * f-string at crud.py:142 (INSERT INTO recording VALUES (...)); the other
 * subshapes produce no rows in this snapshot but are part of the same
 * construction family.
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
 * A construction candidate is an SQL construction expression that is
 *   (a) directly the SQL text argument (positional index 0) of an execute
 *       call (no site in this snapshot: crud.py:48 passes sa.insert(table)
 *       and crud.py:180 passes the variable `sql`),
 *   (b) a construction expression located inside a function that directly
 *       executes SQL and not itself directly executed as an argument (the
 *       observed rows are create_db's NON-SQL f-strings at crud.py:161/164/
 *       169 - filename/env-line constructions expected as candidate noise
 *       for the labeling step to reject), or
 *   (c) assigned to a local variable named `sql` (the observed case:
 *       crud.py:142 `sql = f"INSERT INTO recording VALUES (...)"` inside
 *       export_sql - built in one function, executed in another via
 *       create_db's connection.execute; cross-function flow is not traced
 *       at extraction time, see detection.json uncoveredCases).
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
    or
    exists(Assign a |
      a.getATarget().(Name).getId() = "sql" and
      a.getValue() = n
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
  /* family 1: SQL text argument of execute calls (argument index 0 carries
     the SQL query structure: a SQLAlchemy Core insert statement object at
     crud.py:48 - parameterized, values bound at argument 1 - and a RAW SQL
     STRING at crud.py:180, the injection-shaped channel) */
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
     passes a second positional argument (the bound value list: to_insert at
     crud.py:48), marking the call as parameterized; the SQL text itself
     stays in the family 1 row and the bound list is NOT treated as a
     dangerous sink argument */
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
     executes SQL: _insert and create_db - summary-step candidates for the
     labeling stage; create_db's sql parameter is the raw-SQL hand-off point
     reached from export_recording at crud.py:209) */
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
  /* family 5: SQLAlchemy Core statement construction call - sa.insert(table)
     (crud.py:48, `import sqlalchemy as sa` at crud.py:8); the statement
     object is directly executed as argument 0 of db.execute in the same
     expression. Recorded as a candidate intermediate node carrying the SQL
     structure; the row values (to_insert) are the bound channel. sa.text()
     and other statement constructors are NOT observed in this project and
     are deliberately not matched. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "insert" and
    receiverHint(func) = "sa" and
    node = c and
    flowKind = "sql_object_construction" and
    callableName = "insert" and
    argIndex = -1 and
    receiver = "sa" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
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
