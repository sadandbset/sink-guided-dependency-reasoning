/**
 * Augur Phase 2 - Pass 5 (CWE-89 SQL Injection) sink library.
 *
 * Project : superset (CodeQL DB superset-db, Apache Superset 3.0.1, snapshot
 *           sha 2f468900 - the on-disk tree matches the DB snapshot)
 * Labels  : iris/labels/labels.json, pass 5 (approved; see
 *           iris/labels/phase1_review.md)
 *
 * Label id -> modeling:
 *
 *   Call-site SQL text / SQL argument (receiver name discriminates the
 *   dangerous argument index; the audited file universe is the union of the
 *   Phase 1 execute-call-site groups G-S01..G-S04):
 *     p5-sink-001  cursor/conn/bind .execute(sql)         -> RawExecuteSqlTextArgument (arg 0)
 *                 (DBAPI cursor channel: BaseEngineSpec.execute
 *                 base.py:1551, get_raw_connection prequeries core.py:531,
 *                 engine-spec cancel/EXPLAIN/metadata sites, get_columns_
 *                 description utils.py:156, encrypt.py:125/:174, gsheets
 *                 :117/:286, inspector-bind presto.py:823/:981,
 *                 postgres.py:343, snowflake.py:186, sqlite PRAGMA
 *                 utils/core.py:872)
 *     p5-sink-002  engine .execute(sql)                   -> RawExecuteSqlTextArgument (arg 0)
 *                 (legacy SQLAlchemy Engine: hive.py:210 f-string DROP
 *                 TABLE / :232 CREATE TABLE, impala.py:74 'SHOW SCHEMAS',
 *                 models/dashboard.py:367/:384 Core selects,
 *                 mock_data.py:207/:210/:287, benchmark_migration.py:158)
 *     p5-sink-003  session/connection .execute(construct) -> CoreExecuteArgument (arg 0)
 *                 (SQLAlchemy Core construct channel: common/tags.py 14,
 *                 security/manager.py 21, importers, cachekeys/api.py:118,
 *                 connectors/sqla/models.py:1464 - bound-parameter Core
 *                 execution; kept as a sink for recall because a raw string
 *                 passed here is executed as SQL text)
 *     p5-sink-004  db_engine_spec/cls/_sql_json_executor
 *                 .execute(cursor, sql, ...)              -> EngineSpecAdapterSqlArgument (arg 1)
 *                 (CORRECTED position: the CSV's generic row reports arg 0,
 *                 but on the adapter sites the SQL text is positional
 *                 argument 1 - models/core.py:598/:608/:611,
 *                 connectors/sqla/utils.py:138/:157, presto_db.py:76,
 *                 base.py:1070, trino.py:206, presto.py:1271,
 *                 sqllab/commands/execute.py:156)
 *     p5-sink-017  pd.read_sql_query(statement)           -> ReadSqlQueryStatement (arg 0 / sql=)
 *                 (connectors/sqla/models.py:170/:817, models/helpers.py:1365)
 *
 *   Definition-side SQL-text / SQL-fragment parameters (the sink fires where
 *   taint enters the project's own SQL channel APIs, before execution):
 *     p5-sink-005  BaseEngineSpec.execute(cls, cursor, query, **kwargs)
 *                 query at param 2 (base.py:1531; ImpalaEngineSpec.execute
 *                 impala.py:92 same shape)        -> SqlTextDefinitionParameter
 *     p5-sink-006  HiveEngineSpec.execute @staticmethod (cursor, query, ...)
 *                 query at param 1 (hive.py:544)  -> SqlTextDefinitionParameter
 *     p5-sink-007  SqlJsonExecutor.execute / Synchronous / ASynchronous
 *                 (execution_context, rendered_query, log_params)
 *                 rendered_query at param 2 (sql_json_executer.py:52/:87/:160)
 *                                              -> SqlTextDefinitionParameter
 *     p5-sink-008  BaseEngineSpec.execute_with_cursor(cls, cursor, sql,
 *                 query, session) sql at param 2 (base.py:1057;
 *                 TrinoEngineSpec.execute_with_cursor trino.py:189 same
 *                 shape)                          -> SqlTextDefinitionParameter
 *     p5-sink-009  sql_lab.execute_sql_statement(sql_statement, ...) param 0
 *                 (sql_lab.py:194)                -> SqlTextDefinitionParameter
 *     p5-sink-010  sql_lab.execute_sql_statements(query_id, rendered_query,
 *                 ...) rendered_query at param 1 (sql_lab.py:375)
 *                                              -> SqlTextDefinitionParameter
 *     p5-sink-015  BaseEngineSpec.get_text_clause(cls, clause) param 1
 *                 (base.py:548 - returns text(clause), colon-escape only)
 *                                              -> SqlTextDefinitionParameter
 *     p5-sink-016  ExploreMixin.text / SqlaTable.text (self, clause) param 1
 *                 (models/helpers.py:1077, connectors/sqla/models.py:1095)
 *                                              -> SqlTextDefinitionParameter
 *     p5-sink-011  BaseEngineSpec.select_star table_name (param 2) / schema
 *                 (param 4) + engine-spec overrides bigquery.py:631 /
 *                 hive.py:475 / presto.py:1071 (same shape)
 *                                              -> SelectStarIdentifierParameter
 *     p5-sink-012  Database.select_star table_name (param 1) / schema
 *                 (models/core.py:637)           -> SelectStarIdentifierParameter
 *     p5-sink-013  DatabaseRestApi.select_star handler table_name (param 1)
 *                 / schema_name (databases/api.py:811)
 *                                              -> SelectStarIdentifierParameter
 *
 *   Construction nodes (labels p5-sink-019..022, 025) get NO dedicated sink
 *   classes: the f-string/concat/format expressions are the argument-0
 *   expressions of the execute calls above or flow into the text-clause /
 *   select_star definition parameters, so taint embedded by string
 *   interpolation is caught at the point where the SQL text enters an
 *   execution API (string-construction taint is standard CodeQL
 *   propagation; see report/query_generation_notes.md section 2).
 *
 *   Bound-parameter channels are NOT sinks (label p5-san-030 treats them as
 *   the sanitizer): positional arg 1 / keyword values of
 *   cursor/session/connection/engine execute calls are modeled as the
 *   barrier in MySanitizers, and on the adapter sites (db_engine_spec/cls/
 *   _sql_json_executor) argument 1 is the SQL text sink, never a bound
 *   value (the documented position caveat).
 *
 *   Name-collision false positives (labeled none/fp) fall outside the
 *   audited file universe by construction: 316 session.query ORM rows, CLI
 *   command dispatch, non-SQL f-strings, sqlparse.format reformatting.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  /** Holds if `n` is a sink for the pass identified by `passKey`. */
  predicate isSink(DataFlow::Node n, string passKey) {
    passKey = "sql_injection" and
    (
      n instanceof RawExecuteSqlTextArgument
      or n instanceof CoreExecuteArgument
      or n instanceof EngineSpecAdapterSqlArgument
      or n instanceof ReadSqlQueryStatement
      or n instanceof SqlTextDefinitionParameter
      or n instanceof SelectStarIdentifierParameter
    )
  }

  /**
   * The audited SQL execution layer: the union of the Phase 1
   * execute-call-site groups (G-S01 DBAPI cursor/conn/bind, G-S02 legacy
   * engine, G-S03 Core session/connection, G-S04 engine-spec adapters),
   * i.e. every file that carries an approved .execute call-site row (the
   * extraction query matched ALL <obj>.execute calls in scope, so this
   * universe is exactly the audited one). Paths inside this CodeQL
   * database use forward slashes (verified against the extraction CSVs).
   */
  private predicate auditedExecuteLayer(AstNode n) {
    inScope(n) and
    (
      n.getLocation().getFile().getAbsolutePath().matches("%/superset/db_engine_specs/%")
      or fileIs(n, "superset/models/core.py") // G-S01 core.py:531 prequeries; G-S04 get_df :598/:608/:611
      or fileIs(n, "superset/connectors/sqla/utils.py") // G-S01 :156; G-S04 :138/:157
      or fileIs(n, "superset/utils/core.py") // G-S01 :872 sqlite PRAGMA
      or fileIs(n, "superset/utils/encrypt.py") // G-S01 :125/:174 SecretsMigrator
      or fileIs(n, "superset/models/dashboard.py") // G-S02 :367/:384
      or fileIs(n, "superset/utils/mock_data.py") // G-S02 :207/:210/:287
      or fileIs(n, "scripts/benchmark_migration.py") // G-S02 :158
      or fileIs(n, "superset/common/tags.py") // G-S03 (14 rows)
      or fileIs(n, "superset/security/manager.py") // G-S03 (21 rows)
      or fileIs(n, "superset/cachekeys/api.py") // G-S03 :118
      or fileIs(n, "superset/commands/importers/v1/assets.py") // G-S03 :142/:147
      or fileIs(n, "superset/commands/importers/v1/examples.py") // G-S03 :173/:204
      or fileIs(n, "superset/dashboards/commands/importers/v1/__init__.py") // G-S03 :127/:149
      or fileIs(n, "superset/connectors/sqla/models.py") // G-S03 :1464; G-S13 read_sql_query :170/:817
      or fileIs(n, "superset/sql_validators/presto_db.py") // G-S04 :76
      or fileIs(n, "superset/sqllab/commands/execute.py") // G-S04 :156
    )
  }

  /** Phase 1 extraction scope filter (same as MySources). */
  private predicate inScope(AstNode n) {
    not excludedPath(n.getLocation().getFile().getAbsolutePath())
  }

  bindingset[p]
  private predicate excludedPath(string p) {
    p.matches("%/tests/%")
    or p.matches("%/superset-db/%")
    or p.matches("%/migrations/%")
    or p.matches("%/node_modules/%")
    or p.matches("%/superset-frontend/%")
    or p.matches("%/superset-websocket/%")
    or p.matches("%/docs/%")
  }

  bindingset[relPath]
  private predicate fileIs(AstNode n, string relPath) {
    n.getLocation().getFile().getAbsolutePath().matches("%/" + relPath)
  }

  /**
   * Base name of the object expression of the called member, i.e. the
   * receiver hint used throughout the Phase 1 extraction (`session` covers
   * both `session` and `db.session`; `engine` covers `engine` and
   * `db.engine`; `db_engine_spec` covers `db_engine_spec` and
   * `self.db_engine_spec`). `<expr>`-shaped receivers (method chains like
   * `conn.cursor().execute`) did not occur in the audited rows.
   */
  private predicate receiverName(Call c, string name) {
    exists(Attribute fn |
      fn = c.getFunc() and
      (
        fn.getObject() instanceof Name and fn.getObject().(Name).getId() = name
        or
        fn.getObject() instanceof Attribute and fn.getObject().(Attribute).getName() = name
      )
    )
  }

  /** A .execute(...) call in the audited execution layer. */
  private predicate executeCall(Call c) {
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "execute" and
    auditedExecuteLayer(c)
  }

  /**
   * Raw-SQL execute calls: DBAPI cursor / raw-connection / inspector-bind
   * execute (labels p5-sink-001) and the legacy SQLAlchemy Engine.execute
   * channel (label p5-sink-002), with the SQL text at positional
   * argument 0.
   */
  private predicate rawReceiverExecute(Call c) {
    executeCall(c) and
    (
      receiverName(c, "cursor")
      or receiverName(c, "conn")
      or receiverName(c, "bind")
      or receiverName(c, "engine")
    )
  }

  /**
   * The SQL-text argument (positional index 0) of raw-SQL execute calls
   * (labels p5-sink-001/002): base.py:1551 cursor.execute(query),
   * mysql.py:297 cursor.execute(f'KILL CONNECTION {cancel_query_id}'),
   * presto.py:810 cursor.execute(sql, params), gsheets.py:117
   * cursor.execute(f'SELECT GET_METADATA("{table_name}")'), hive.py:210
   * engine.execute(f'DROP TABLE IF EXISTS {str(table)}'),
   * mock_data.py:287 db.engine.execute(f'SELECT {column_name} FROM
   * {table_name} LIMIT 1'). The dynamic f-string constructions of labels
   * p5-sink-019/020/021 are the argument-0 expressions of exactly these
   * calls and need no separate sink node.
   */
  private class RawExecuteSqlTextArgument extends DataFlow::Node {
    RawExecuteSqlTextArgument() {
      exists(Call c | rawReceiverExecute(c) | this.asExpr() = c.getPositionalArg(0))
    }
  }

  /**
   * The statement argument (positional index 0) of SQLAlchemy Core
   * session/connection execute calls (label p5-sink-003, tp 0.7): argument
   * 0 carries an Insert/Update/Select/Delete construct whose values are
   * bound parameters at every observed site (common/tags.py:56
   * db.session.execute(query), security/manager.py:1157-1161
   * connection.execute(...), importers). A tainted raw string passed here
   * would be executed as SQL text, so the channel is a sink; the bound
   * values themselves are the MySanitizers barrier.
   */
  private class CoreExecuteArgument extends DataFlow::Node {
    CoreExecuteArgument() {
      exists(Call c |
        executeCall(c) and
        (receiverName(c, "session") or receiverName(c, "connection"))
      |
        this.asExpr() = c.getPositionalArg(0)
      )
    }
  }

  /**
   * The SQL-text argument (positional index 1, CORRECTED from the CSV's
   * generic arg 0) of engine-spec adapter / SQL-JSON-executor execute
   * calls (label p5-sink-004): BaseEngineSpec.execute is
   * execute(cls, cursor, query, **kwargs), so at call sites like
   * self.db_engine_spec.execute(cursor, sql_) (models/core.py:598/:608/:611,
   * connectors/sqla/utils.py:138/:157, sql_validators/presto_db.py:76),
   * cls.execute(cursor, sql, async_=True) (base.py:1070, trino.py:206,
   * presto.py:1271) and self._sql_json_executor.execute(execution_context,
   * rendered_query, log_params) (sqllab/commands/execute.py:156) the SQL
   * text is the second positional argument.
   */
  private class EngineSpecAdapterSqlArgument extends DataFlow::Node {
    EngineSpecAdapterSqlArgument() {
      exists(Call c |
        executeCall(c) and
        (
          receiverName(c, "db_engine_spec")
          or receiverName(c, "cls")
          or receiverName(c, "_sql_json_executor")
        )
      |
        this.asExpr() = c.getPositionalArg(1)
      )
    }
  }

  /**
   * The SQL statement of pd.read_sql_query(...) calls (label p5-sink-017):
   * positional argument 0 (connectors/sqla/models.py:170) or the sql=
   * keyword (models.py:817, models/helpers.py:1365 - arg_index 0 refers to
   * the sql parameter semantically per the extraction caveat). The
   * statement is a SQLAlchemy-compiled select with literal_binds=True
   * (dialect-escaped literal rendering, not bound parameters).
   */
  private class ReadSqlQueryStatement extends DataFlow::Node {
    ReadSqlQueryStatement() {
      exists(Call c |
        c.getFunc() instanceof Attribute and
        c.getFunc().(Attribute).getName() = "read_sql_query" and
        inScope(c) and
        (fileIs(c, "superset/connectors/sqla/models.py") or fileIs(c, "superset/models/helpers.py"))
      |
        this.asExpr() = c.getPositionalArg(0)
        or
        exists(Keyword kw |
          c.getAKeyword() = kw and
          kw.getArg() = "sql" and
          this.asExpr() = kw.getValue()
        )
      )
    }
  }

  /**
   * The SQL-text / SQL-fragment parameter of the project's own SQL channel
   * API definitions (labels p5-sink-005..010, 015, 016). Located by
   * function name + parameter name + file, mirroring the Phase 1
   * sql_api_def family:
   *   - execute adapters under /db_engine_specs/: parameter `query`
   *     (BaseEngineSpec.execute base.py:1531 with cls at 0 / cursor at 1 /
   *     query at 2; ImpalaEngineSpec.execute impala.py:92 same classmethod
   *     shape; HiveEngineSpec.execute hive.py:544 @staticmethod with
   *     cursor at 0 / query at 1 - matched by name so both shapes are
   *     covered);
   *   - execute in sqllab/sql_json_executer.py: parameter `rendered_query`
   *     (SqlJsonExecutor :52, SynchronousSqlJsonExecutor :87,
   *     ASynchronousSqlJsonExecutor :160);
   *   - execute_with_cursor under /db_engine_specs/: parameter `sql`
   *     (base.py:1057, trino.py:189);
   *   - execute_sql_statement / execute_sql_statements in sql_lab.py:
   *     parameters `sql_statement` (:194) / `rendered_query` (:375);
   *   - get_text_clause under /db_engine_specs/: parameter `clause`
   *     (base.py:548);
   *   - text in models/helpers.py + connectors/sqla/models.py: parameter
   *     `clause` (ExploreMixin.text :1077, SqlaTable.text :1095 - the only
   *     `def text(self, clause)` definitions in those files).
   */
  private class SqlTextDefinitionParameter extends DataFlow::Node {
    SqlTextDefinitionParameter() {
      exists(Parameter p, Function f |
        f.getAnArg() = p and
        sqlTextApiParameter(f, p) and
        inScope(f) and
        this = DataFlow::parameterNode(p)
      )
    }
  }

  private predicate sqlTextApiParameter(Function f, Parameter p) {
    (
      f.getName() = "execute" and
      f.getLocation().getFile().getAbsolutePath().matches("%/superset/db_engine_specs/%") and
      p.getName() = "query"
    )
    or
    (
      f.getName() = "execute" and
      fileIs(f, "superset/sqllab/sql_json_executer.py") and
      p.getName() = "rendered_query"
    )
    or
    (
      f.getName() = "execute_with_cursor" and
      f.getLocation().getFile().getAbsolutePath().matches("%/superset/db_engine_specs/%") and
      p.getName() = "sql"
    )
    or
    (
      f.getName() = "execute_sql_statement" and
      fileIs(f, "superset/sql_lab.py") and
      p.getName() = "sql_statement"
    )
    or
    (
      f.getName() = "execute_sql_statements" and
      fileIs(f, "superset/sql_lab.py") and
      p.getName() = "rendered_query"
    )
    or
    (
      f.getName() = "get_text_clause" and
      f.getLocation().getFile().getAbsolutePath().matches("%/superset/db_engine_specs/%") and
      p.getName() = "clause"
    )
    or
    (
      f.getName() = "text" and
      (fileIs(f, "superset/models/helpers.py") or fileIs(f, "superset/connectors/sqla/models.py")) and
      p.getName() = "clause"
    )
  }

  /**
   * The identifier-fragment parameters of the select_star API family
   * (labels p5-sink-011/012/013 - table_name and schema/schema_name, which
   * determine the SQL structure of the generated SELECT):
   *   - BaseEngineSpec.select_star (base.py:1363, table_name at 2, schema
   *     at 4) and the engine-spec overrides bigquery.py:631 / hive.py:475 /
   *     presto.py:1071 (same signature) - matched by name under
   *     /db_engine_specs/;
   *   - Database.select_star (models/core.py:637, table_name at 1);
   *   - the DatabaseRestApi.select_star REST handler
   *     (databases/api.py:811, table_name and schema_name URL path
   *     segments).
   * Identifiers are quoted downstream via dialect
   * identifier_preparer.quote (base.py:1399-1403) - quoting is NOT a
   * barrier (see MySanitizers), so identifier taint reaching these
   * parameters is checked here.
   */
  private class SelectStarIdentifierParameter extends DataFlow::Node {
    SelectStarIdentifierParameter() {
      exists(Parameter p, Function f |
        f.getAnArg() = p and
        selectStarApiParameter(f, p) and
        inScope(f) and
        this = DataFlow::parameterNode(p)
      )
    }
  }

  private predicate selectStarApiParameter(Function f, Parameter p) {
    f.getName() = "select_star" and
    p.getName() in ["table_name", "schema", "schema_name"] and
    (
      f.getLocation().getFile().getAbsolutePath().matches("%/superset/db_engine_specs/%")
      or fileIs(f, "superset/models/core.py")
      or fileIs(f, "superset/databases/api.py")
    )
  }
}
