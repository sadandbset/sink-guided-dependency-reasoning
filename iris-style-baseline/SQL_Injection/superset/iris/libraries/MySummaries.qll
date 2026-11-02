/**
 * Augur Phase 2 - Pass 5 (CWE-89 SQL Injection) additional taint-step library.
 *
 * Project : superset (CodeQL DB superset-db, Apache Superset 3.0.1, snapshot
 *           sha 2f468900 - the on-disk tree matches the DB snapshot)
 * Labels  : iris/labels/labels.json, pass 5 (approved; see
 *           iris/labels/phase1_review.md)
 *
 * The Python data-flow library does not track cross-method object field
 * flow, ORM-model fields, or external Jinja rendering, so the audited SQL
 * Lab pipeline (label key finding 1 in labels.json metadata notes:
 * request.json['sql'] -> SqlJsonExecutionContext -> Jinja render ->
 * execute_sql_statements -> BaseEngineSpec.execute -> cursor.execute)
 * would be disconnected without the four edge families below. Each edge is
 * individually verified against the snapshot source and tightly scoped by
 * file + name; no unconditional propagation is established.
 *
 * Modeled edges:
 *
 *   (1) SqlJsonExecutionContext field flow  [p5-src-040 -> p5-sink-009/010]
 *       The context constructor __init__(query_params) (and
 *       _init_from_query_params / CreateTableAsSelect.create_from, all in
 *       superset/sqllab/sqllab_execution_context.py) stores
 *       query_params.get("sql")/... into instance fields
 *       (sqllab_execution_context.py:71-97, 199-209); the command layer
 *       reads them back cross-method: self.sql / self.create_table_as_
 *       select.target_table_name inside create_query (:169-196),
 *       self._execution_context.<field> in sqllab/commands/execute.py
 *       (:127-129, :164, :205-212), execution_context.template_params in
 *       sqllab/query_render.py:63.
 *       Edge: parameter `query_params` -> the audited context-field reads.
 *
 *   (2) Query ORM-model field flow           [continuation of (1)]
 *       create_query() builds Query(sql=self.sql, schema=...,
 *       tmp_table_name=self.create_table_as_select.target_table_name, ...)
 *       (sqllab_execution_context.py:169-186); the render step reads
 *       query_model.sql back (sqllab/query_render.py:62) and the CTAS
 *       branch reads query.tmp_table_name / query.tmp_schema_name
 *       (superset/sql_lab.py:235-244). ORM-model fields are not tracked.
 *       Edge: the audited `Query(...)` constructor keyword -> the matching
 *       `.sql` / `.tmp_table_name` / `.tmp_schema_name` / `.schema` reads.
 *
 *   (3) ParsedQuery method flow              [p5-sink-009/010 funnel]
 *       ParsedQuery(sql) stores the parsed statements
 *       (superset/sql_parse.py) and .stripped() / .get_statements() /
 *       .as_create_table(...) rebuild SQL text from them - used at
 *       sqllab/query_render.py:61-63 (rendered template), sql_lab.py:219
 *       (sql = parsed_query.stripped()), :407-414 (statements loop),
 *       :240-244 (CTAS wrap, which also embeds the table_name argument
 *       UNQUOTED per sql_parse.py:436-441). Cross-method field flow is
 *       not tracked.
 *       Edge: ParsedQuery(...) argument 0 -> .stripped() /
 *       .get_statements() / .as_create_table() call results; and
 *       .as_create_table(table_name, schema_name=...) arguments -> its
 *       call result (the CTAS identifier construction).
 *
 *   (4) Jinja template render flow           [p5-sink-010 / p5-sink-022]
 *       BaseTemplateProcessor.process_template(sql, **kwargs) renders via
 *       SandboxedEnvironment: template = self._env.from_string(sql);
 *       kwargs.update(self._context); return template.render(context)
 *       (jinja_context.py:458-469 - the template text passes verbatim
 *       into the rendered output and the kwarg values are substituted
 *       into it); NoOpTemplateProcessor.process_template returns the sql
 *       unchanged (jinja_context.py:495-497). jinja2 is an external
 *       package not present in this database, so the propagation through
 *       .render() is not modeled by default.
 *       Edge: process_template(...) argument 0 and keyword values -> the
 *       call result. This connects both the SQL Lab render
 *       (query_render.py:61-64) and the ad-hoc clause render
 *       (models/helpers.py:1904/:1922, connectors/sqla/models.py
 *       RLS/template processing).
 *
 * Summary labels that intentionally get NO extra edge (adding one would
 * create unconditional propagation the source code does not warrant;
 * standard interprocedural argument flow already connects them, and the
 * definition-side sinks in MySinks fire at the API boundary):
 *   p5-sum-014  apply_limit_to_sql (base.py:855, models/core.py:661): the
 *               sql parameter flows to the returned SQL through the
 *               ordinary return statement.
 *   p5-sum-018  TextClause construction call sites (text/self.text/
 *               get_text_clause, 21 rows): the clause argument reaches the
 *               MySinks::SqlTextDefinitionParameter entries through
 *               ordinary argument flow.
 *   p5-sum-031  engine-spec metadata wrappers (get_view_names/
 *               get_catalog_names/...): ordinary argument flow into the
 *               execute calls (which are RawExecuteSqlTextArgument sinks).
 *   p5-sum-032  query-builder wrappers (get_df/get_sqla_query/
 *               get_from_clause/values_for_column/...): ordinary argument
 *               flow into the execute/read_sql_query calls.
 *   p5-sum-054/055/056/057/058/059/061/062  datasource .query / select_star /
 *               apply_limit_to_sql / get_df / SQL Lab funnel / estimate /
 *               metadata / query-builder call-site rows: ordinary argument
 *               flow into the MySinks definition parameters.
 *   p5-sum-033/035/036/060/064  cache-invalidation, cancel-query, ORM-glue
 *               wrappers and their call sites: values terminate in
 *               bound-parameter Core execution (the MySanitizers barrier)
 *               or engine-derived ids; no SQL-text propagation to add.
 *   The celery .delay dispatch (sqllab/sql_json_executer.py:169-178) needs
 *   no edge either: the get_sql_results task parameters are modeled
 *   directly as a SOURCE (label p5-src-051), which is the broker boundary.
 *
 * NOT modeled (documented limitations, see report/query_generation_notes.md):
 *   marshmallow schema loads (ChartDataQueryContextSchema().load(form_data)
 *   in charts/data/api.py - marshmallow is external), the QueryContext/
 *   QueryObject object graph of the chart-data path, and the RLS insertion
 *   branch (sql_lab.py:207-217, feature-flagged, reads
 *   parsed_query._parsed[0]).
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  /** Holds if taint may step from node `nodeFrom` to node `nodeTo` for `passKey`. */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "sql_injection" and
    (
      executionContextFieldFlow(nodeFrom, nodeTo)
      or queryModelFieldFlow(nodeFrom, nodeTo)
      or parsedQueryFlow(nodeFrom, nodeTo)
      or templateRenderFlow(nodeFrom, nodeTo)
    )
  }

  /** Phase 1 extraction scope filter (same as the other libraries). */
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

  /* ------------------------------------------------------------------ */
  /* (1) SqlJsonExecutionContext field flow                              */
  /* ------------------------------------------------------------------ */

  /**
   * The context input parameter is `query_params` in __init__ (:66),
   * _init_from_query_params (:71) and CreateTableAsSelect.create_from
   * (:198) of superset/sqllab/sqllab_execution_context.py.
   */
  private predicate contextInputParameter(Parameter p) {
    p.getName() = "query_params" and
    exists(Function f |
      f.getAnArg() = p and
      fileIs(f, "superset/sqllab/sqllab_execution_context.py")
    )
  }

  /**
   * The fields stored from query_params (sqllab_execution_context.py:72-97
   * and create_from :199-209). `query` is deliberately NOT in the set: it
   * is set via set_query() from the ORM model, not from query_params.
   */
  private predicate contextField(string name) {
    name in [
      "sql", "schema", "template_params", "limit", "status", "client_id",
      "sql_editor_id", "tab_name", "expand_data", "database_id",
      "async_flag", "create_table_as_select", "ctas_method",
      "target_schema_name", "target_table_name"
    ]
  }

  /**
   * Audited context-field reads: any receiver inside the context class
   * itself (self.sql / self.create_table_as_select.target_table_name in
   * create_query and _get_ctas_target_schema_name), and the
   * `execution_context` / `self._execution_context` receivers of the
   * sqllab command layer (superset/sqllab/**).
   */
  private predicate contextFieldRead(Attribute a) {
    contextField(a.getName()) and
    inScope(a) and
    (
      fileIs(a, "superset/sqllab/sqllab_execution_context.py")
      or
      (
        a.getObject() instanceof Name and
        a.getObject().(Name).getId() = "execution_context" and
        a.getLocation().getFile().getAbsolutePath().matches("%/superset/sqllab/%")
      )
      or
      (
        a.getObject() instanceof Attribute and
        a.getObject().(Attribute).getName() = "_execution_context" and
        a.getLocation().getFile().getAbsolutePath().matches("%/superset/sqllab/%")
      )
    )
  }

  /** Edge (1): context constructor input -> audited context-field reads. */
  private predicate executionContextFieldFlow(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Parameter p, Attribute a |
      contextInputParameter(p) and
      contextFieldRead(a) and
      nodeFrom = DataFlow::parameterNode(p) and
      nodeTo.asExpr() = a
    )
  }

  /* ------------------------------------------------------------------ */
  /* (2) Query ORM-model field flow                                      */
  /* ------------------------------------------------------------------ */

  /**
   * The audited Query(...) construction is create_query() in
   * sqllab_execution_context.py:169-186 (both the CTAS and the plain
   * branch), passing the sql/schema/tmp_table_name/tmp_schema_name
   * keywords. The Query ORM model is
   * superset.models.sql_lab.Query; its constructor keyword values are the
   * store side.
   */
  private predicate queryConstructorKeyword(Keyword kw) {
    kw.getArg() in ["sql", "schema", "tmp_table_name", "tmp_schema_name"] and
    exists(Call c |
      c.getAKeyword() = kw and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "Query" and
      fileIs(c, "superset/sqllab/sqllab_execution_context.py")
    )
  }

  /**
   * Audited Query-model field reads: query_model.sql in the render step
   * (sqllab/query_render.py:62) and query.tmp_table_name /
   * query.tmp_schema_name / query.schema in the CTAS branch and engine
   * acquisition of superset/sql_lab.py (:235-244, :412/:455/:634).
   */
  private predicate queryModelFieldRead(Attribute a) {
    inScope(a) and
    (
      (a.getName() = "sql" and fileIs(a, "superset/sqllab/query_render.py"))
      or
      (a.getName() in ["tmp_table_name", "tmp_schema_name", "schema"] and fileIs(a, "superset/sql_lab.py"))
    )
  }

  /** Edge (2): Query(...) constructor keyword -> matching model-field reads. */
  private predicate queryModelFieldFlow(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Keyword kw, Attribute a |
      queryConstructorKeyword(kw) and
      queryModelFieldRead(a) and
      a.getName() = kw.getArg() and
      nodeFrom.asExpr() = kw.getValue() and
      nodeTo.asExpr() = a
    )
  }

  /* ------------------------------------------------------------------ */
  /* (3) ParsedQuery method flow                                         */
  /* ------------------------------------------------------------------ */

  /**
   * ParsedQuery(...) constructor calls (superset/sql_parse.py class):
   * sqllab/query_render.py:62, sql_lab.py:206/:209/:219/:407,
   * db_engine_specs/base.py:877/:1452/:1485 and the validators.
   */
  private predicate parsedQueryConstructor(Call c) {
    c.getFunc() instanceof Name and
    c.getFunc().(Name).getId() = "ParsedQuery" and
    inScope(c)
  }

  /**
   * ParsedQuery methods that rebuild SQL text from the parsed statements:
   * stripped() (sql_lab.py:219, query_render.py:62),
   * get_statements() (sql_lab.py:407-414) and as_create_table()
   * (sql_lab.py:240-244). The method names are distinctive to
   * superset/sql_parse.py ParsedQuery.
   */
  private predicate parsedQueryMethodCall(Call c) {
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() in ["stripped", "get_statements", "as_create_table"] and
    inScope(c)
  }

  /**
   * Edge (3a): ParsedQuery(argument 0) -> .stripped() / .get_statements()
   * / .as_create_table() call results (the parsed SQL text is rebuilt from
   * the constructor input).
   * Edge (3b): as_create_table(table_name, schema_name=...) own arguments
   * -> its call result: sql_parse.py:436-441 interpolates
   * f"{schema_name}.{table_name}" and the stripped SELECT into
   * "CREATE {method} {full_table_name} AS {sql}" UNQUOTED (the TODO at
   * :437 acknowledges the missing quoting; label p5-cand-029).
   */
  private predicate parsedQueryFlow(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    // (3a) constructor input -> method results
    exists(Call ctor, Call m |
      parsedQueryConstructor(ctor) and
      parsedQueryMethodCall(m) and
      nodeFrom.asExpr() = ctor.getPositionalArg(0) and
      nodeTo.asExpr() = m
    )
    or
    // (3b) CTAS identifier arguments -> as_create_table result
    exists(Call m |
      parsedQueryMethodCall(m) and
      m.getFunc().(Attribute).getName() = "as_create_table" and
      (
        nodeFrom.asExpr() = m.getPositionalArg(0)
        or
        exists(Keyword kw |
          m.getAKeyword() = kw and
          kw.getArg() = "schema_name" and
          nodeFrom.asExpr() = kw.getValue()
        )
      ) and
      nodeTo.asExpr() = m
    )
  }

  /* ------------------------------------------------------------------ */
  /* (4) Jinja template render flow                                      */
  /* ------------------------------------------------------------------ */

  /**
   * process_template(...) calls (BaseTemplateProcessor.process_template /
   * JinjaTemplateProcessor / NoOpTemplateProcessor and the
   * sqllab/estimation render path): sqllab/query_render.py:61-64,
   * models/helpers.py:1904/:1922, connectors/sqla/models.py:908 and
   * related sites.
   */
  private predicate processTemplateCall(Call c) {
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "process_template" and
    inScope(c)
  }

  /**
   * Edge (4): process_template(sql, **kwargs) argument 0 and keyword
   * values -> the call result. Evidence: jinja_context.py:458-469
   * `template = self._env.from_string(sql); kwargs.update(self._context);
   * return template.render(context)` (the template text passes verbatim
   * into the rendered output, and the kwarg values are substituted into
   * it) and jinja_context.py:495-497 NoOpTemplateProcessor.process_template
   * returning the sql unchanged. jinja2 is external to this database, so
   * .render() propagation is not modeled by default.
   */
  private predicate templateRenderFlow(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      processTemplateCall(c) and
      (
        nodeFrom.asExpr() = c.getPositionalArg(0)
        or
        exists(Keyword kw | c.getAKeyword() = kw | nodeFrom.asExpr() = kw.getValue())
      ) and
      nodeTo.asExpr() = c
    )
  }
}
