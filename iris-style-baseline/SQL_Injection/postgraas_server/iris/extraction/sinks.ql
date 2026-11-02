/**
 * @name postgraas_server CWE-89 sink candidate extraction
 * @description Extract SQL execution sink candidates from the
 *   postgraas_server CodeQL database (snapshot bd4f1b8, postgraas_server
 *   v2.0.0b1, Flask / flask-restful "PostgreSQL-as-a-service" with a
 *   psycopg2 pg_cluster backend): every <obj>.execute(...) call site in
 *   non-excluded code (the SQL text is positional argument 0) covering the
 *   six psycopg2 cursor.execute channels of the pg_cluster driver
 *   (postgres_cluster_driver.py:22/:24/:43/:44/:50/:52, receivers are the
 *   local `cur` from `with con.cursor() as cur`) and the static-literal
 *   channel of the prometheus collector (prometheus_app.py:40); companion
 *   "bound_params" rows marking the parameterized channel wherever a second
 *   positional argument is present (none exists in this project - no
 *   DB-API bound parameters are used anywhere); dynamic SQL construction
 *   nodes ('.format()' template calls, '%' formatting of a literal template,
 *   f-strings, string concatenation) that are (a) directly the SQL text
 *   argument of an execute call (the datname/rolname SELECT templates of
 *   check_db_or_user_exists) or (b) inside a function whose body executes
 *   SQL (the CREATE USER / GRANT / CREATE DATABASE / DROP ROLE templates of
 *   create_postgres_db and the DROP DATABASE / DROP USER templates of
 *   delete_database / delete_user, which are formatted into locals and
 *   executed afterwards); the internal SQL wrapper functions themselves
 *   (check_db_or_user_exists / create_postgres_db / delete_database /
 *   delete_user / do_count_query - summary-step candidates for the labeling
 *   stage); and the SQLAlchemy ORM parameterized channels
 *   (<model>.query.get/filter_by/all and db.session.add/delete/commit -
 *   emitted as "orm_query" rows so the labeling step can mark the safe
 *   parameter binding as such). Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not database
 *   analyze). This is a plain multi-column select query on purpose: a
 *   problem-shaped query is the wrong shape for candidate tables, and no
 *   table query kind is assumed to exist.
 * @id iris/postgraas_server/extraction/sinks
 * @tags sql-injection
 */

import python

/*
 * Column contract (identical order to sources.ql and to the previous arches
 * / django / piccolo runs):
 *   1. node       - candidate AST node (location-backed, decodes as
 *                   file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable name ("execute" for execution rows, "format" /
 *                   "percent_format" / "fstring" / "concat" for construction
 *                   rows, function name for wrapper rows, member name for
 *                   orm_query rows)
 *   4. flow_kind  - "sql_text" (argument 0 of an execute call carries the
 *                   SQL query text), "bound_params" (argument 1 carries the
 *                   bound parameter list - the safe channel, emitted so the
 *                   labeling step can mark it as such),
 *                   "sql_percent_format" / "sql_format_call" / "sql_fstring"
 *                   / "sql_concat" (dynamic SQL construction, qualified by
 *                   its actual execution relationship),
 *                   "internal_sql_wrapper" (function whose body directly
 *                   executes SQL), "orm_query" (SQLAlchemy ORM
 *                   parameterized channel - NOT a dangerous sink)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression, e.g. "cur" / "cursor" / "query" / "session";
 *                   "" if none; "<expr>" if the object expression is neither
 *                   Name nor Attribute)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module` is
 *                   not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index carrying the SQL text
 *                   (1 for bound_params rows), -1 for construction /
 *                   wrapper / orm_query rows
 *   8. file       - absolute file path, obtained through the Location API
 *                   (AstNode.getLocation().getFile().getAbsolutePath();
 *                   AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Sink modeling decision (per the task contract): only "the SQL query text
 * executed by the database, or SQL fragments able to influence SQL syntax"
 * is modeled as the dangerous sink (argument index 0 of the psycopg2
 * cursor.execute calls). String construction expressions are extracted as
 * candidate intermediate nodes together with their actual execution
 * relationship (direct SQL text argument of an execute call, or inside a
 * function that executes SQL). The bound parameter channel (execute
 * argument 1) is extracted as its own flow kind so safe parameterization is
 * NOT treated as a dangerous sink by virtue of that binding; the SQLAlchemy
 * ORM channels are extracted as orm_query rows for the same reason.
 *
 * In this project no sink row is expected to resolve at API level: psycopg2
 * cursors are local variables from `with con.cursor() as cur` context
 * managers, so API graphs cannot bind cur.execute to a psycopg2 member.
 * Matching is receiver-name-agnostic on purpose; in non-test package code
 * .execute call sites occur only in postgres_cluster_driver.py and
 * prometheus_app.py, and all rows are "ast" with the match_kind column kept
 * for cross-project contract consistency.
 *
 * Channels NOT observed in this project (no rules fabricated for them, see
 * detection.json): cursor.executemany(), cursor.executescript(),
 * cursor.callproc(), SQLAlchemy text() / from_statement() / engine.execute(),
 * flask-sqlalchemy raw channels (db.engine, connection.cursor()), Django
 * connection.cursor() / Manager.raw() / RawSQL() / extra(), psycopg2
 * mogrify. psycopg2.connect(...) keyword arguments (user / password /
 * database / host / port, four call sites) are a connection-credential
 * channel, not SQL text, and are deliberately NOT emitted as sink rows.
 * con.cursor() acquisition calls are not SQL execution and are not emitted.
 *
 * Excluded paths (applied to every row): /tests/, /postgraas_server-db/,
 * /postgraas_server-safe-db/ (the CodeQL database directories sit inside the
 * source tree), /docs/.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint).
 *  Scripts that are not on an import path (setup.py, docs/conf.py) have no
 *  dotted module name; their file base name is used instead. */
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

/* ------------------------------------------------------------------ */
/* Sink family 1: SQL execution call sites                             */
/* ------------------------------------------------------------------ */

/**
 * SQL execution member observed in this project: cursor.execute (psycopg2
 * DB-API). Matching is receiver-name-agnostic on purpose: cursors are local
 * variables (`cur` from `with con.cursor() as cur`, `cursor` from
 * `with conn.cursor() as cursor`), so receiver identity cannot be resolved
 * syntactically; every <obj>.execute(...) call in a non-excluded file is
 * extracted and receiver-collision noise is left to the labeling step. In
 * non-test package code this member occurs only in the pg_cluster driver
 * and in prometheus_app.do_count_query. executemany / executescript /
 * callproc are NOT observed in this project and are deliberately not
 * matched.
 */
private predicate sqlExecuteCall(Call c) {
  c.getFunc().(Attribute).getName() = "execute"
}

/** Functions whose body directly executes SQL through an execute call. */
private predicate executeWrapperFunction(Function f) {
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
 *   - .format(...) template calls (the only shape actually observed in this
 *     project: all 8 construction sites in postgres_cluster_driver.py are
 *     .format() calls on string-literal templates);
 *   - '%' string-formatting (BinaryExpr with a Mod operator and a literal
 *     template string on the left);
 *   - f-string literals (Fstring);
 *   - string concatenation (BinaryExpr with an Add operator where at least
 *     one operand is a string literal).
 * The last three shapes are expected to yield zero rows in this snapshot
 * (not observed in non-test code); they are kept qualified so they can only
 * fire on genuinely SQL-executing paths, never on arbitrary code.
 */
private predicate isSqlConstructionExpr(AstNode n) {
  n.(Call).getFunc().(Attribute).getName() = "format"
  or
  n instanceof Fstring
  or
  (
    n.(BinaryExpr).getOp() instanceof Mod and
    n.(BinaryExpr).getLeft() instanceof StringLiteral
  )
  or
  (
    n.(BinaryExpr).getOp() instanceof Add and
    (
      n.(BinaryExpr).getLeft() instanceof StringLiteral
      or
      n.(BinaryExpr).getRight() instanceof StringLiteral
    )
  )
}

/**
 * A construction candidate is
 *   (a) directly the SQL text argument (positional index 0) of an execute
 *       call (the datname/rolname SELECT templates at
 *       postgres_cluster_driver.py:22/:24, formatted inline in the execute
 *       call), or
 *   (b) a construction expression located inside a function whose body
 *       executes SQL and not itself directly executed as an execute
 *       argument (the CREATE USER / GRANT / CREATE DATABASE / DROP ROLE
 *       templates at :36-41 and the DROP DATABASE / DROP USER templates at
 *       :65/:75, which are formatted into locals and executed afterwards).
 * Cross-function construction (a value built outside any execute-wrapper
 * function and outside the direct-argument position) is not traced here -
 * see detection.json uncoveredCases.
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
        executeWrapperFunction(f) and
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
  /* family 1: SQL text argument of execute calls (argument index 0 carries
     the SQL query text) */
  exists(Call c |
    sqlExecuteCall(c) and
    node = c and
    callableName = "execute" and
    flowKind = "sql_text" and
    argIndex = 0 and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 2: bound-parameter channel - emitted only where the execution
     call passes a second positional argument (PEP-249
     execute(query, params)); marking the call as parameterized; the SQL
     text itself stays in the family 1 row and the bound list is NOT
     treated as a dangerous sink argument. No call site in this project
     passes one, so this family is expected to yield zero rows (kept for
     cross-project contract consistency) */
  exists(Call c, Expr bound |
    sqlExecuteCall(c) and
    bound = c.getPositionalArg(1) and
    node = c and
    callableName = "execute" and
    flowKind = "bound_params" and
    argIndex = 1 and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3: dynamic SQL construction nodes ('%'-formatting / .format() /
     f-strings / concatenation) qualified by their actual execution
     relationship (direct SQL text argument of an execute call, or inside a
     function whose body executes SQL) */
  exists(AstNode n |
    sqlConstructionCandidate(n) and
    node = n and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(n) and
    (
      /* .format() template call (e.g. "... WHERE datname='{}';".format(db_name)
         and the CREATE USER / DROP templates formatted with
         **connection_dict / keyword values) */
      n.(Call).getFunc().(Attribute).getName() = "format" and
      flowKind = "sql_format_call" and
      callableName = "format" and
      receiver = receiverHint(n.(Call).getFunc().(Attribute))
      or
      /* f-string literal (none observed in non-test code) */
      n instanceof Fstring and
      flowKind = "sql_fstring" and
      callableName = "fstring" and
      receiver = ""
      or
      /* '%' formatting of a literal SQL template (none observed) */
      n.(BinaryExpr).getOp() instanceof Mod and
      flowKind = "sql_percent_format" and
      callableName = "percent_format" and
      receiver = ""
      or
      /* string concatenation with a literal operand (none observed) */
      n.(BinaryExpr).getOp() instanceof Add and
      flowKind = "sql_concat" and
      callableName = "concat" and
      receiver = ""
    )
  )
  or
  /* family 4: internal SQL wrapper functions - functions whose body
     directly executes SQL through an execute call (check_db_or_user_exists,
     create_postgres_db, delete_database, delete_user,
     prometheus_app.do_count_query) - summary-step candidates for the
     labeling stage */
  exists(Function f |
    executeWrapperFunction(f) and
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
  /* family 5: SQLAlchemy ORM parameterized channels - the meta-DB access
     layer (DBInstance.query.get / filter_by / all reads, db.session.add /
     delete / commit writes). These compile to parameterized SQL by
     construction and are emitted as channel rows so the labeling step can
     mark them as the safe binding channel; they are NOT dangerous sinks
     for pass 5. db.drop_all()/create_all() and db.init_app() have Name
     receivers and are not matched. */
  exists(Call c, Attribute func, Attribute obj |
    func = c.getFunc().(Attribute) and
    obj = func.getObject().(Attribute) and
    (
      (
        obj.getName() = "query" and
        func.getName() in ["get", "all", "first", "one", "filter_by", "filter"]
      )
      or
      (
        obj.getName() = "session" and
        func.getName() in ["add", "delete", "commit", "rollback"]
      )
    ) and
    node = c and
    flowKind = "orm_query" and
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
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  not excludedPath(node.getLocation().getFile().getAbsolutePath())
select
  node,
  "sink_candidate" as role,
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
