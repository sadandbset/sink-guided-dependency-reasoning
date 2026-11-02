/**
 * @name superset CWE-89 sink candidate extraction
 * @description Extract SQL execution sink candidates from the superset
 *   CodeQL database (snapshot 2f468900, Apache Superset 3.0.1 - the
 *   Superset application itself is the audit target): every
 *   <obj>.execute(...) call site (SQL text/construct at positional argument
 *   0) covering the DBAPI cursor channel (cursor.execute from
 *   models/core.py:531 Database.get_raw_connection, db_engine_specs/base.py:
 *   1551 BaseEngineSpec.execute and the hive/postgres/presto/mysql/
 *   snowflake/gsheets/ocient/trino/redshift engine-spec call sites, the
 *   sqlalchemy legacy Engine channel (engine.execute / db.engine.execute,
 *   hive.py:210/:232, impala.py:74, models/dashboard.py:367/:384) and the
 *   SQLAlchemy Connection/Session channel (connection.execute /
 *   db.session.execute of Core constructs, security/manager.py,
 *   common/tags.py, importers); pd.read_sql_query(...) execution sites
 *   (connectors/sqla/models.py:170/:817, models/helpers.py:1365, SQL at
 *   parameter 0); companion "bound_params" rows marking the parameterized
 *   channel (argument index 1) wherever an execute call passes a second
 *   positional argument (e.g. presto.py:810 cursor.execute(sql, params));
 *   SQLAlchemy TextClause construction sites (text(...) / <obj>.text(...) /
 *   <obj>.get_text_clause(...), fragment at argument 0) as candidate
 *   intermediate SQL-object nodes (base.py:557/:871/:1405, hive.py:233,
 *   utils/encrypt.py:175, the RLS/WHERE/HAVING clause hand-offs in
 *   models/helpers.py:806/:816/:1918/:1936 and
 *   connectors/sqla/models.py:1069/:1079); dynamic SQL construction nodes
 *   ('%'-formatting of a literal SQL template, .format() template calls,
 *   f-string literals, and string concatenation with a literal operand)
 *   both directly as the argument 0 of an execution / pandas / text-clause
 *   call and inside functions that directly execute SQL or build
 *   TextClauses (e.g. cursor.execute(f"KILL CONNECTION {cancel_query_id}")
 *   mysql.py:297, cursor.execute(f"SELECT GET_METADATA(\"{table_name}\")")
 *   gsheets.py:117, engine.execute(f"DROP TABLE IF EXISTS {str(table)}")
 *   hive.py:210, text(f"UPDATE {table_name} SET {set_cols} ...")
 *   utils/encrypt.py:175, postgres.py:433-436 and redshift.py:176-179
 *   cancel-query f-strings, presto.py:981/:1269 SHOW statements); the
 *   internal SQL wrapper functions themselves (including the SQL Lab
 *   entry points execute_sql_statement / execute_sql_statements in
 *   sql_lab.py and every function whose body calls an execute member,
 *   read_sql_query or a text-clause member); and definition rows for the
 *   project's own SQL channel APIs (BaseEngineSpec.execute /
 *   execute_with_cursor / get_text_clause / apply_limit_to_sql /
 *   select_star and their engine-spec overrides, Database.select_star /
 *   apply_limit_to_sql, ExploreMixin.text / SqlaTable.text, the
 *   databases/api.py select_star action, the SqlJsonExecutor.execute
 *   definitions in sqllab/sql_json_executer.py, and the module-level
 *   sql_lab.py entry points) with the position of the SQL-text parameter
 *   located by parameter name (query/sql/clause/sql_statement/
 *   rendered_query/table_name/schema). Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not database
 *   analyze). This is a plain multi-column select query on purpose: @kind
 *   problem is the wrong shape for candidate tables and @kind table is
 *   assumed not to exist.
 * @id iris/superset/extraction/sinks
 * @tags sql-injection
 */

import python

/*
 * Column contract (identical order to sources.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable name ("execute" / "read_sql_query" for execution
 *                   rows, "text" / "get_text_clause" for TextClause rows,
 *                   "percent_format" / "format" / "fstring" / "concat" for
 *                   construction rows, function name for wrapper and API
 *                   definition rows)
 *   4. flow_kind  - "sql_text" (argument 0 of an execution or pandas call,
 *                   or the SQL-text parameter of a SQL channel API
 *                   definition, carries the SQL query text / SQL construct /
 *                   a SQL fragment able to influence SQL syntax),
 *                   "bound_params" (argument 1 of an execute call, carries
 *                   the bound parameter list - the safe channel, emitted so
 *                   the labeling step can mark it as such),
 *                   "sql_text_clause" (SQLAlchemy TextClause construction:
 *                   text(...) / <obj>.text(...) / <obj>.get_text_clause(...),
 *                   argument 0 carries the SQL fragment - SQL object
 *                   creation, a candidate intermediate node, NOT final
 *                   execution by itself),
 *                   "sql_percent_format" / "sql_format_call" / "sql_fstring"
 *                   / "sql_concat" (dynamic SQL string construction),
 *                   "internal_sql_wrapper" (function whose body directly
 *                   executes SQL, executes pandas SQL, or builds a
 *                   TextClause) and "sql_api_def" (definition row of a
 *                   project SQL channel API, carrying the SQL-text
 *                   parameter position)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression, e.g. "cursor" / "conn" / "engine" / "db" /
 *                   "self" / "db_engine_spec" / "database"; enclosing class
 *                   name for wrapper and API definition rows; "" if none;
 *                   "<expr>" if the object expression is neither Name nor
 *                   Attribute)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module` is
 *                   not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index carrying the SQL text
 *                   (1 for bound_params call rows; the parameter position
 *                   for sql_api_def rows, including the self/cls slot),
 *                   -1 for construction and wrapper rows
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
 * engine/connection/session/cursor .execute(...) and of pd.read_sql_query,
 * plus the SQL-text parameters of the project's own SQL channel API
 * definitions). SQLAlchemy TextClause construction (text / self.text /
 * get_text_clause) and string construction expressions are extracted as
 * candidate intermediate nodes (sql_text_clause / sql_percent_format /
 * sql_format_call / sql_fstring / sql_concat rows) together with their
 * actual execution relationship (direct argument of an execution call, or
 * located inside a function that directly executes SQL or builds a
 * TextClause). The bound parameter list (argument index 1) is extracted as
 * its own flow kind so that safe parameterization is distinguishable from
 * SQL text - a call with a bound parameter list is NOT treated as a
 * dangerous sink by virtue of that binding. The ORM channel
 * (db.session / Query.filter() / order_by(), marshmallow-validated model
 * loads) compiles to parameterized SQL and is deliberately not extracted
 * beyond the generic .execute rows, where argument 0 carries a SQLAlchemy
 * Core construct rather than raw SQL text (labeling classifies those).
 *
 * Position caveat for engine-spec execute adapters: BaseEngineSpec.execute
 * is execute(cls, cursor, query, **kwargs), so at call sites such as
 * db_engine_spec.execute(cursor, statement) (sql_lab.py) and
 * cls.execute(cursor, sql, async_=True) (base.py:1069) the SQL text is
 * positional argument 1, not 0. The generic receiver-agnostic row reports
 * arg_index 0 (correct for the DBAPI cursor / engine / connection / session
 * execute shapes), the bound_params companion row reports arg_index 1, and
 * the sql_api_def definition rows record the true SQL-text parameter
 * position located by parameter name (2 for the classmethod base shape,
 * 1 for the hive @staticmethod shape). The labeling step must reconcile
 * these (documented in detection.json uncoveredCases).
 *
 * In this project no sink row is expected to resolve at API level: all SQL
 * execution flows through local cursor/engine/connection/session variables
 * and wrapper chains (conn.cursor(), engine.raw_connection(), db.session,
 * self.db_engine_spec, self.text), which API graphs cannot bind to driver
 * or SQLAlchemy members. The match_kind column is kept for cross-project
 * contract consistency and all rows are "ast".
 *
 * Channels NOT observed in this project (no rules fabricated for them, see
 * detection.json): cursor.executemany / executescript / callproc,
 * SQLAlchemy 1.4 exec_driver_sql and Query.from_statement(), psycopg /
 * psycopg2 direct driver usage (incl. mogrify), sqlite3/MySQLdb direct
 * cursors, Django raw-SQL channels (Manager.raw / extra / RawSQL), and
 * plain pandas read_sql (only read_sql_query has real call sites).
 *
 * Excluded paths (applied to every row): /tests/, /superset-db/ (the CodeQL
 * database directory sits inside the source tree), /migrations/ (290
 * alembic version files - static migration SQL), /node_modules/,
 * /superset-frontend/, /superset-websocket/, /docs/.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint).
 *  Top-level scripts that are not on an import path (setup.py,
 *  scripts/*.py) have no dotted module name; their file base name is used
 *  instead. */
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
/* Sink family 1: SQL execution call sites                             */
/* ------------------------------------------------------------------ */

/**
 * SQL execution members observed in this project: <obj>.execute(...) - 90
 * call sites under superset/ outside migrations, covering DBAPI cursors
 * (conn.cursor() / engine.raw_connection() paths), the SQLAlchemy legacy
 * Engine (engine.execute, db.engine.execute), SQLAlchemy Connection/Session
 * (connection.execute, db.session.execute - argument 0 is a SQLAlchemy Core
 * construct on those sites), and engine-spec execute adapters. Matching is
 * receiver-name-agnostic on purpose: cursors, engines, connections and
 * sessions are obtained as local variables or attributes, so receiver
 * identity cannot be resolved syntactically; receiver-collision noise
 * (e.g. command-executor objects with an execute method) is left to the
 * labeling step. executemany / executescript / callproc are NOT observed
 * anywhere in the application tree and are deliberately not matched.
 */
private predicate sqlExecuteMember(string member) {
  member = "execute"
}

/** Any call site of an SQL execution member (syntax-level, alias-tolerant). */
private predicate sqlExecuteCall(Call c) {
  sqlExecuteMember(c.getFunc().(Attribute).getName())
}

/** pandas SQL execution: pd.read_sql_query(...) (3 real call sites; the SQL
 *  statement is parameter 0 - passed positionally at
 *  connectors/sqla/models.py:170 and as the sql= keyword at
 *  models/helpers.py:1365 / connectors/sqla/models.py:817, in which case
 *  arg_index 0 refers to the sql parameter semantically). */
private predicate pandasSqlCall(Call c) {
  c.getFunc().(Attribute).getName() = "read_sql_query"
}

/* ------------------------------------------------------------------ */
/* Sink family 2: TextClause construction (SQL object creation)         */
/* ------------------------------------------------------------------ */

/**
 * SQLAlchemy TextClause construction calls: bare text(...) (imported from
 * sqlalchemy in db_engine_specs/base.py and hive.py), the project's own
 * <obj>.text(...) wrappers (ExploreMixin.text at models/helpers.py:1077,
 * SqlaTable.text at connectors/sqla/models.py:1095 - they feed
 * template-processed WHERE/HAVING/RLS clauses into the query), and
 * <obj>.get_text_clause(...) (BaseEngineSpec.get_text_clause at
 * db_engine_specs/base.py:548, reached via
 * self.db_engine_spec.get_text_clause(...)). The SQL fragment is argument
 * 0 in all three shapes. These are candidate intermediate nodes: a
 * TextClause only becomes executed SQL when the enclosing query is run
 * (engine.execute / cursor.execute / pd.read_sql_query), which the
 * construction and wrapper families record.
 */
private predicate textClauseCall(Call c) {
  c.getFunc().(Name).getId() = "text"
  or
  c.getFunc().(Attribute).getName() = "text"
  or
  c.getFunc().(Attribute).getName() = "get_text_clause"
}

/* ------------------------------------------------------------------ */
/* Sink family 3: SQL Lab execution entry points and wrapper functions   */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* Sink family 4: dynamic SQL construction nodes                        */
/* ------------------------------------------------------------------ */

/**
 * Dynamic SQL string construction shapes:
 *   - '%' string-formatting (BinaryExpr with a Mod operator and a literal
 *     template string on the left);
 *   - .format(...) template calls (also matches sqlparse.format(sql, ...)
 *     pretty-printing calls that carry SQL text - documented low-risk
 *     noise);
 *   - f-string literals (Fstring) - the dominant shape in this project
 *     (mysql.py:297, gsheets.py:117, snowflake.py:254, ocient.py:389,
 *     hive.py:210, presto.py:981/:1269, postgres.py:436, redshift.py:179,
 *     utils/encrypt.py:175);
 *   - string concatenation (BinaryExpr with an Add operator where at least
 *     one operand is a string literal).
 * Variable-template construction (sql % {...} where the template is a
 * variable, or jinja template rendering in jinja_context.py / common/*,
 * which produces the rendered SQL text for SQL Lab and chart queries) is
 * NOT captured by this shape - see detection.json uncoveredCases.
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
 *   (a) directly the argument 0 (the SQL text / fragment position) of an
 *       execute-family call, a pandas SQL call or a TextClause call, or
 *   (b) a construction expression located inside a function that directly
 *       executes SQL / executes pandas SQL / builds a TextClause (the SQL
 *       Lab entry points included) and is not itself directly passed as
 *       argument 0 of such a call (the value is stored in a variable
 *       first, e.g. sql = f"WHERE pid='{cancel_query_id}'" followed by
 *       cursor.execute(sql) in postgres.py:433-436 / redshift.py:176-179).
 * Cross-function construction (value built in one function, executed in
 * another) is not traced here - see detection.json uncoveredCases.
 */
private predicate sqlConstructionCandidate(AstNode n) {
  isSqlConstructionExpr(n) and
  (
    exists(Call c |
      (sqlExecuteCall(c) or pandasSqlCall(c) or textClauseCall(c)) and
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
        (sqlExecuteCall(c) or pandasSqlCall(c) or textClauseCall(c)) and
        n = c.getPositionalArg(0)
      )
    )
  )
}

/* ------------------------------------------------------------------ */
/* Sink family 5: project SQL channel API definitions                   */
/* ------------------------------------------------------------------ */

/**
 * Definitions of the project's own SQL channel APIs. The SQL-text parameter
 * is located BY PARAMETER NAME (robust against signature variations such as
 * the hive @staticmethod execute(cursor, query, async_) versus the
 * BaseEngineSpec classmethod execute(cls, cursor, query, **kwargs)), and
 * the emitted arg_index is that parameter's position in the definition
 * (0-based, including the self/cls slot):
 *   - "execute" under /db_engine_specs/ (base.py:1531 BaseEngineSpec
 *     execute(cls, cursor, query, **kwargs) - query at 2; hive.py:544
 *     @staticmethod execute(cursor, query, async_) - query at 1;
 *     impala.py:92 execute(cls, cursor, query, **kwargs) - query at 2):
 *     parameter "query";
 *   - "execute" in /sqllab/sql_json_executer.py (SqlJsonExecutor.execute /
 *     SynchronousSqlJsonExecutor.execute / ASynchronousSqlJsonExecutor.
 *     execute(self, execution_context, rendered_query, log_params)):
 *     parameter "rendered_query" at 2;
 *   - "execute_with_cursor" under /db_engine_specs/ (base.py:1057 (cls,
 *     cursor, sql, query, session) - sql at 2; trino.py:189 override):
 *     parameter "sql";
 *   - "get_text_clause" under /db_engine_specs/ (base.py:548 (cls, clause)
 *     - clause at 1): parameter "clause";
 *   - "apply_limit_to_sql" (base.py:855 (cls, sql, limit, database, force)
 *     - sql at 1; models/core.py:661 Database.apply_limit_to_sql):
 *     parameter "sql";
 *   - "select_star" (BaseEngineSpec.select_star at base.py:1363 - table_name
 *     at 2, schema at 4; Database.select_star at models/core.py:637 -
 *     table_name at 1, schema at 2; engine-spec overrides bigquery.py:631 /
 *     hive.py:475 / presto.py:1071; the databases/api.py:811 action
 *     (self, database, table_name, schema_name) - table_name at 1):
 *     parameters "table_name" and "schema" (identifier fragments that
 *     determine the SQL structure of the generated SELECT);
 *   - "text" methods (ExploreMixin.text at models/helpers.py:1077 and
 *     SqlaTable.text at connectors/sqla/models.py:1095, both
 *     (self, clause) - clause at 1): parameter "clause";
 *   - module-level sql_lab.py entry points: execute_sql_statement
 *     (sql_statement at 0) and execute_sql_statements (rendered_query at
 *     1).
 */
private predicate sqlApiParam(Function f, string paramName) {
  (
    f.getName() = "execute" and
    normalizedPathOf(f).matches("%/db_engine_specs/%") and
    paramName = "query"
  )
  or
  (
    f.getName() = "execute" and
    normalizedPathOf(f).matches("%/sqllab/sql_json_executer.py") and
    paramName = "rendered_query"
  )
  or
  (
    f.getName() = "execute_with_cursor" and
    normalizedPathOf(f).matches("%/db_engine_specs/%") and
    paramName = "sql"
  )
  or
  (
    f.getName() = "get_text_clause" and
    normalizedPathOf(f).matches("%/db_engine_specs/%") and
    paramName = "clause"
  )
  or
  (
    f.getName() = "apply_limit_to_sql" and
    paramName = "sql"
  )
  or
  (
    f.getName() = "select_star" and
    (paramName = "table_name" or paramName = "schema")
  )
  or
  (
    f.getName() = "text" and
    exists(Class cls |
      f.getEnclosingScope() = cls and
      (cls.getName() = "ExploreMixin" or cls.getName() = "SqlaTable")
    ) and
    paramName = "clause"
  )
  or
  (
    f.getName() = "execute_sql_statement" and
    normalizedPathOf(f).matches("%/superset/sql_lab.py") and
    paramName = "sql_statement"
  )
  or
  (
    f.getName() = "execute_sql_statements" and
    normalizedPathOf(f).matches("%/superset/sql_lab.py") and
    paramName = "rendered_query"
  )
}

/**
 * A project SQL channel API definition: a function covered by sqlApiParam
 * together with the position of its SQL-text parameter (the parameter whose
 * name matches paramName). All these parameters carry the SQL query text or
 * SQL fragments (identifiers) and are emitted as sql_text rows.
 */
private predicate sqlApiDefinition(Function f, int argIndex) {
  exists(string paramName |
    sqlApiParam(f, paramName) and
    exists(Parameter p |
      p = f.getAnArg() and
      p.getName() = paramName and
      argIndex = p.getPosition()
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
  /* family 1: SQL text argument of <obj>.execute(...) calls (argument index
     0 carries the SQL query text / SQL construct - DBAPI cursor.execute,
     legacy engine.execute, connection.execute / session.execute Core
     constructs; engine-spec adapter call sites carry the SQL at argument 1,
     see the position caveat in the header comment) */
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
  /* family 1b: pandas SQL execution: pd.read_sql_query(...) (SQL statement
     at parameter 0; keyword sql= form included, see header comment) */
  exists(Call c |
    pandasSqlCall(c) and
    node = c and
    callableName = "read_sql_query" and
    flowKind = "sql_text" and
    argIndex = 0 and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 2: bound-parameter channel - emitted only where an execute call
     passes a second positional argument (the bound parameter list or, on
     engine-spec adapter call sites, the SQL text - see the position
     caveat), marking the call as parameterized where applicable; the SQL
     text itself stays in the family 1 row and the bound list is NOT
     treated as a dangerous sink argument (e.g. presto.py:810
     cursor.execute(sql, params)) */
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
  /* family 3: SQLAlchemy TextClause construction sites (SQL object
     creation - candidate intermediate nodes): text(...) /
     <obj>.text(...) / <obj>.get_text_clause(...), argument 0 carries the
     SQL fragment */
  exists(Call c |
    textClauseCall(c) and
    node = c and
    argIndex = 0 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c) and
    (
      c.getFunc().(Name).getId() = "text" and
      callableName = "text" and
      receiver = ""
      or
      c.getFunc().(Attribute).getName() = "text" and
      callableName = "text" and
      receiver = receiverHint(c.getFunc().(Attribute))
      or
      c.getFunc().(Attribute).getName() = "get_text_clause" and
      callableName = "get_text_clause" and
      receiver = receiverHint(c.getFunc().(Attribute))
    )
    and
    flowKind = "sql_text_clause"
  )
  or
  /* family 4: dynamic SQL construction nodes
     ('%'-formatting / .format() / f-strings / concatenation) directly
     executed as the SQL argument or located inside SQL wrapper functions */
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
      /* .format() template call (incl. sqlparse.format noise) */
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
  /* family 5: internal SQL wrapper functions (functions whose body
     directly executes SQL / executes pandas SQL / builds a TextClause,
     plus the SQL Lab entry points - summary-step candidates for the
     labeling stage) */
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
  /* family 6: project SQL channel API definitions (engine-spec execute /
     execute_with_cursor / get_text_clause / apply_limit_to_sql /
     select_star, Database.select_star / apply_limit_to_sql, ExploreMixin /
     SqlaTable text wrappers, the sqllab executor execute definitions and
     the module-level sql_lab.py entry points); the SQL-text parameter is
     located by name and its position is reported in arg_index */
  exists(Function f |
    sqlApiDefinition(f, argIndex) and
    node = f and
    flowKind = "sql_text" and
    callableName = f.getName() and
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
