/**
 * Augur Phase 2 - Pass 5 (CWE-89 SQL Injection) sanitizer (barrier) library.
 *
 * Project : superset (CodeQL DB superset-db, Apache Superset 3.0.1, snapshot
 *           sha 2f468900 - the on-disk tree matches the DB snapshot)
 * Labels  : iris/labels/labels.json, pass 5 (approved; see
 *           iris/labels/phase1_review.md)
 *
 * Label id -> modeling:
 *
 *   p5-san-030 (tp, 0.85) - the bound-parameter channel:
 *     (a) positional argument 1 of cursor/conn/bind/engine execute calls -
 *         the DBAPI `parameters` channel, e.g. presto.py:810
 *         cursor.execute(sql, params) with params = {"schema": schema}
 *         (presto.py:798 - the safe contrast to hive's backtick
 *         interpolation) and mock_data.py:210
 *         engine.execute(table.insert(), data);
 *     (b) positional argument 1 of session/connection execute calls - the
 *         SQLAlchemy executemany `values` channel, e.g.
 *         dashboards/commands/importers/v1/__init__.py:149
 *         session.execute(dashboard_slices.insert(), values);
 *     (c) keyword values of session/connection/engine execute calls - the
 *         SQLAlchemy bound-value keywords, e.g. common/tags.py:225-229
 *         db.session.execute(insert, name=..., type=...) and hive.py:232-239
 *         engine.execute(text(...), location=...).
 *     -> BoundParameterArgument.
 *     Values substituted by the DB driver / SQLAlchemy compilation cannot
 *     alter SQL text; this is the proven parameterization barrier for pass
 *     5 and is modeled as isBarrier.
 *
 *   Position caveat (labels.json metadata note, from detection.json
 *   uncoveredCases): on the engine-spec adapter sites (receivers
 *   db_engine_spec / cls / _sql_json_executor) positional argument 1 is
 *   the SQL TEXT (p5-sink-004), not a bound list - those receivers are
 *   deliberately excluded from the barrier so the barrier can never block
 *   the SQL-text argument of an adapter call.
 *
 *   p5-san-067 (tp, 0.75) - sanitize_clause (superset/sql_parse.py:522-549)
 *   + validate_adhoc_subquery (superset/models/helpers.py:105-134) is
 *   deliberately NOT modeled as an isBarrier node:
 *   - it is a STATEMENT-STRUCTURE guard (sqlparse single-statement
 *     enforcement, paren-balance, multiline-comment checks, subquery
 *     rejection unless the ALLOW_ADHOC_SUBQUERY feature flag), verified at
 *     models/helpers.py:832-850 _process_sql_expression;
 *   - its own label rationale records that it does NOT escape quote
 *     characters, i.e. it does not neutralize value-level SQL syntax;
 *   - making it a barrier would suppress genuine alerts where an ad-hoc
 *     clause passes the structural check and still injects SQL syntax
 *     (e.g. a quote-escaped payload inside a balanced single statement).
 *   Per the Phase 1 review recommendation (phase1_review.md section 7
 *   item 5) it is kept as documentation only - taint that survives the
 *   structural guard still flows into the self.text()/literal_column
 *   fragment sinks and raises an alert. The same applies to the Jinja
 *   SandboxedEnvironment (jinja_context.py:448): it constrains template
 *   CODE, not the rendered SQL text, so it is not a barrier either.
 *
 *   Quoting helpers are NOT barriers either (consistent with the Phase 1
 *   labels): engine.dialect.identifier_preparer.quote
 *   (base.py:1399-1403) and quote_identifier (presto.py:977) wrap
 *   identifiers without escaping embedded quote characters, so a tainted
 *   table/schema name that is interpolated into SQL structure still flows
 *   to the select_star identifier sinks and raises an alert - binding does
 *   not protect dynamic SQL structure.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /** Holds if `n` is a taint barrier for the pass identified by `passKey`. */
  predicate isBarrier(DataFlow::Node n, string passKey) {
    passKey = "sql_injection" and n instanceof BoundParameterArgument
  }

  /**
   * The audited SQL execution layer and scope filter (identical positive
   * scoping to MySinks, which keeps the barrier aligned with the sinks:
   * the adapter receivers whose argument 1 is SQL text are excluded from
   * boundReceiverExecute below).
   */
  private predicate auditedExecuteLayer(AstNode n) {
    inScope(n) and
    (
      n.getLocation().getFile().getAbsolutePath().matches("%/superset/db_engine_specs/%")
      or fileIs(n, "superset/models/core.py")
      or fileIs(n, "superset/connectors/sqla/utils.py")
      or fileIs(n, "superset/utils/core.py")
      or fileIs(n, "superset/utils/encrypt.py")
      or fileIs(n, "superset/models/dashboard.py")
      or fileIs(n, "superset/utils/mock_data.py")
      or fileIs(n, "scripts/benchmark_migration.py")
      or fileIs(n, "superset/common/tags.py")
      or fileIs(n, "superset/security/manager.py")
      or fileIs(n, "superset/cachekeys/api.py")
      or fileIs(n, "superset/commands/importers/v1/assets.py")
      or fileIs(n, "superset/commands/importers/v1/examples.py")
      or fileIs(n, "superset/dashboards/commands/importers/v1/__init__.py")
      or fileIs(n, "superset/connectors/sqla/models.py")
      or fileIs(n, "superset/sql_validators/presto_db.py")
      or fileIs(n, "superset/sqllab/commands/execute.py")
    )
  }

  /** Phase 1 extraction scope filter (same as MySources/MySinks). */
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

  /** Base name of the object expression of the called member (see MySinks). */
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

  /**
   * Execute calls whose argument 1 / keyword values are bound values: the
   * DBAPI parameters channel (cursor/conn/bind), the legacy Engine
   * parameters channel (engine) and the SQLAlchemy Core executemany
   * values / bound-keyword channel (session/connection). The adapter
   * receivers (db_engine_spec/cls/_sql_json_executor) are excluded on
   * purpose: their argument 1 is the SQL text (label p5-sink-004 and the
   * position caveat in labels.json metadata).
   */
  private predicate boundReceiverExecute(Call c) {
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "execute" and
    auditedExecuteLayer(c) and
    (
      receiverName(c, "cursor")
      or receiverName(c, "conn")
      or receiverName(c, "bind")
      or receiverName(c, "engine")
      or receiverName(c, "session")
      or receiverName(c, "connection")
    )
  }

  /**
   * Bound-parameter nodes (label p5-san-030):
   *   positional argument 1 - e.g. cursor.execute(sql, params)
   *   (presto.py:810 with params = {"schema": schema} at :798),
   *   session.execute(dashboard_slices.insert(), values)
   *   (dashboards/commands/importers/v1/__init__.py:149),
   *   engine.execute(table.insert(), data) (utils/mock_data.py:210);
   *   keyword values - the SQLAlchemy bound-value keywords, e.g.
   *   db.session.execute(insert, name=..., type=...)
   *   (common/tags.py:225-229), engine.execute(text(...), location=...)
   *   (hive.py:232-239).
   * The barrier applies only to the bound-value channel; it never blocks
   * the SQL-text argument (argument 0 of these calls is the
   * MySinks::RawExecuteSqlTextArgument / CoreExecuteArgument sink).
   */
  private class BoundParameterArgument extends DataFlow::Node {
    BoundParameterArgument() {
      exists(Call c | boundReceiverExecute(c) |
        this.asExpr() = c.getPositionalArg(1)
        or
        exists(Keyword kw | c.getAKeyword() = kw | this.asExpr() = kw.getValue())
      )
    }
  }
}
