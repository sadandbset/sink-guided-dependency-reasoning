/**
 * Augur Phase 2 - Pass 5 (CWE-89 SQL Injection) source library.
 *
 * Project : superset (CodeQL DB superset-db, Apache Superset 3.0.1, snapshot
 *           sha 2f468900 - the on-disk tree matches the DB snapshot, so all
 *           file/line references below are the tree's numbering)
 * Labels  : iris/labels/labels.json, pass 5 (approved at the Phase 1 review
 *           gate per this round's instruction; see iris/labels/phase1_review.md)
 *
 * Label id -> modeling:
 *   p5-src-038  request.args   field read            -> RequestFieldRead
 *   p5-src-039  request.form   field read            -> RequestFieldRead
 *   p5-src-040  request.json   field read            -> RequestFieldRead
 *   p5-src-041  request.files/headers/cookies/data
 *               field reads                          -> RequestFieldRead
 *   p5-src-042  request.<field>.to_dict()/items()    -> RequestWholeMappingCall
 *   p5-src-043  request.<field>.get()/getlist()      -> RequestAccessorCall
 *   p5-src-044  request.<field>[...] keyed reads     -> RequestSubscriptRead
 *   p5-src-045  kwargs["rison"] / kwargs.get("rison")
 *               (FAB @rison-injected query params)   -> RisonKwargsRead
 *   p5-src-046  parameters of @expose / @app.route
 *               handlers (route path variables such
 *               as pk / client_id / table_name and
 *               ordinary handler parameters)         -> ExposeHandlerParam
 *   p5-src-051  parameters of the sql_lab.get_sql_results
 *               celery task (rendered_query at param 2
 *               is the Jinja-rendered SQL text)      -> CeleryGetSqlResultsParam
 *
 * Deliberately NOT modeled (labels/phase1_review.md section 7, unmodified
 * labels):
 *   p5-src-047 (click CLI parameters, classification 'candidate'):
 *     operator-level input - the CLI runs with DB credentials and is not an
 *     attacker-reachable boundary in the audited threat model.
 *   p5-src-052 (other celery task parameters, classification 'candidate'):
 *     mixed trust (thumbnails pass int ids; cache warmup passes stored
 *     second-order payloads); only get_sql_results carries SQL text.
 *   p5-none-048..053 (current_app.config / app.config, os.environ,
 *     open()/read(), session.query ORM rows, non-SQL internal wrappers):
 *     labeled fp for pass 5.
 *
 * Only externally attacker-influenced boundaries are sources. No parameter of
 * a function that merely contains a cursor.execute call is a source by
 * itself; SQL Lab's celery task parameters are a source because the broker
 * payload re-enters the application from outside the process (label
 * p5-src-051, tp 0.75).
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  /** Holds if `n` is a source for the pass identified by `passKey`. */
  predicate isSource(DataFlow::Node n, string passKey) {
    passKey = "sql_injection" and
    (
      n instanceof RequestFieldRead
      or n instanceof RequestWholeMappingCall
      or n instanceof RequestAccessorCall
      or n instanceof RequestSubscriptRead
      or n instanceof RisonKwargsRead
      or n instanceof ExposeHandlerParam
      or n instanceof CeleryGetSqlResultsParam
    )
  }

  /**
   * Holds if `name` is one of the audited flask request-state fields
   * (labels p5-src-038..041; the flask request proxy is always accessed
   * through the plain name `request` in this codebase - `self.request`
   * variants are not observed).
   */
  private predicate requestField(string name) {
    name in ["args", "form", "json", "files", "headers", "cookies", "data"]
  }

  /**
   * Holds if `n` is inside the audited candidate scope: the Phase 1
   * extraction filtered /tests/, /superset-db/, /migrations/,
   * /node_modules/, /superset-frontend/, /superset-websocket/ and /docs/
   * paths, so the query restricts itself to the same universe. Paths inside
   * this CodeQL database use forward slashes (verified against the
   * extraction CSVs).
   */
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

  /**
   * request.args / request.form / request.json / request.files /
   * request.headers / request.cookies / request.data attribute reads
   * (labels p5-src-038..041, 197 CSV rows).
   * Evidence: superset/sqllab/api.py:300/:308 (request.json - the SQL Lab
   * /execute/ payload), superset/charts/data/api.py:221 (request.json) and
   * :225 (request.form['form_data']), 61 request.args / 70 request.form /
   * 52 request.json sites across the API layer.
   */
  private class RequestFieldRead extends DataFlow::Node {
    RequestFieldRead() {
      exists(Attribute a |
        requestField(a.getName()) and
        a.getObject() instanceof Name and
        a.getObject().(Name).getId() = "request" and
        inScope(a) and
        this.asExpr() = a
      )
    }
  }

  /**
   * request.<field>.to_dict() / .items() call results (label p5-src-042,
   * 4 rows) - whole-mapping reads.
   * Evidence: superset/utils/cache.py:93 request.args.items(),
   * superset/utils/log.py:50/:52 request.form/args.to_dict(),
   * superset/views/sql_lab/views.py:221 request.form.to_dict().
   */
  private class RequestWholeMappingCall extends DataFlow::Node {
    RequestWholeMappingCall() {
      exists(Call c, Attribute func, Attribute base |
        func = c.getFunc().(Attribute) and
        func.getName() in ["to_dict", "items"] and
        base = func.getObject().(Attribute) and
        requestField(base.getName()) and
        base.getObject() instanceof Name and
        base.getObject().(Name).getId() = "request" and
        inScope(c) and
        this.asExpr() = c
      )
    }
  }

  /**
   * request.<field>.get(...) / .getlist(...) call results (label p5-src-043,
   * 83 rows; the key is argument 0) - the highest-signal HTTP accessor
   * shape of the extraction.
   * Evidence: superset/views/utils.py:165-166 request.form.get('form_data')
   * / request.args.get('form_data') (get_form_data), sqllab/api.py:306
   * request.headers.get('USER_AGENT').
   */
  private class RequestAccessorCall extends DataFlow::Node {
    RequestAccessorCall() {
      exists(Call c, Attribute func, Attribute base |
        func = c.getFunc().(Attribute) and
        func.getName() in ["get", "getlist"] and
        base = func.getObject().(Attribute) and
        requestField(base.getName()) and
        base.getObject() instanceof Name and
        base.getObject().(Name).getId() = "request" and
        inScope(c) and
        this.asExpr() = c
      )
    }
  }

  /**
   * request.<field>[...] keyed reads (label p5-src-044, 34 rows; the index
   * carries the key).
   * Evidence: superset/charts/data/api.py:225
   * json.loads(request.form['form_data']), superset/charts/api.py:1098
   * json.loads(request.form['passwords']).
   */
  private class RequestSubscriptRead extends DataFlow::Node {
    RequestSubscriptRead() {
      exists(Subscript s, Attribute base |
        base = s.getObject().(Attribute) and
        requestField(base.getName()) and
        base.getObject() instanceof Name and
        base.getObject().(Name).getId() = "request" and
        inScope(s) and
        this.asExpr() = s
      )
    }
  }

  /**
   * kwargs["rison"] subscript reads and kwargs.get("rison") call results
   * (label p5-src-045, 35 rows) - the FAB @rison decorator parses
   * request.args['q'] (rison format) and injects it as the keyword 'rison';
   * the boundary visible in this tree is the kwargs read.
   * Evidence: superset/views/base_api.py:574 kwargs.get('rison'),
   * superset/sqllab/api.py:241-244 kwargs['rison'],
   * superset/annotations/api.py:192/:249/:492 kwargs['rison'].
   */
  private class RisonKwargsRead extends DataFlow::Node {
    RisonKwargsRead() {
      exists(Subscript s |
        s.getObject() instanceof Name and
        s.getObject().(Name).getId() = "kwargs" and
        s.getIndex().(StringLiteral).getText() = "rison" and
        inScope(s) and
        this.asExpr() = s
      )
      or
      exists(Call c, Attribute func |
        func = c.getFunc().(Attribute) and
        func.getName() = "get" and
        func.getObject() instanceof Name and
        func.getObject().(Name).getId() = "kwargs" and
        c.getPositionalArg(0).(StringLiteral).getText() = "rison" and
        inScope(c) and
        this.asExpr() = c
      )
    }
  }

  /**
   * Non-self parameters of @expose / @app.route handler functions (label
   * p5-src-046, 135 CSV rows over the FAB REST/view handlers) - Flask/FAB
   * route path variables and handler parameters. Route path variables are
   * directly attacker-controlled URL segments; ordinary handler parameters
   * are FAB-injected input. The 135 rows correspond to the handlers that
   * have non-self parameters (most handlers take only `self`).
   * Evidence: superset/databases/api.py:801-812
   * @expose('/<int:pk>/select_star/<path:table_name>/') def select_star(self,
   * database, table_name, schema_name); superset/sqllab/api.py:138-146
   * def export_csv(self, client_id: str); superset/views/core.py:852
   * def dashboard(self, dashboard_id_or_slug, ...); views/health.py:23-26
   * @app.route def health().
   * The decorator shapes mirror the Phase 1 extraction query exactly
   * (isExposeHandler / isRouteHandler): @expose(...) / @<obj>.expose(...) /
   * bare @expose, and @<obj>.route(...).
   */
  private class ExposeHandlerParam extends DataFlow::Node {
    ExposeHandlerParam() {
      exists(Function f, Parameter p |
        isHandler(f) and
        p = f.getAnArg() and
        not p.isSelf() and
        inScope(p) and
        this = DataFlow::parameterNode(p)
      )
    }
  }

  /** FAB @expose(...) / @<obj>.expose(...) / bare @expose, or @<obj>.route(...). */
  private predicate isHandler(Function f) {
    exists(Call dc |
      dc = f.getADecorator().(Call) and
      (
        dc.getFunc().(Name).getId() = "expose"
        or
        dc.getFunc().(Attribute).getName() = "expose"
        or
        dc.getFunc().(Attribute).getName() = "route"
      )
    )
    or
    exists(Expr d |
      d = f.getADecorator() and
      d.(Name).getId() = "expose"
    )
  }

  /**
   * Parameters of the sql_lab.get_sql_results celery task (label
   * p5-src-051, tp 0.75): rendered_query (parameter 2) is the
   * Jinja-rendered SQL Lab query text forwarded verbatim to
   * execute_sql_statements (superset/sql_lab.py:177); the task is reached
   * from the asynchronous /execute/ flow via .delay (superset/sqllab/
   * sql_json_executer.py:169-178), so the broker payload is an input
   * boundary outside the web process. The bind=True `ctask` slot is the
   * task object itself and is excluded.
   * Evidence: superset/sql_lab.py:156-172
   * @celery_app.task(name='sql_lab.get_sql_results', bind=True)
   * def get_sql_results(ctask, query_id, rendered_query, return_results,
   * store_results, username, start_time, expand_data, log_params).
   */
  private class CeleryGetSqlResultsParam extends DataFlow::Node {
    CeleryGetSqlResultsParam() {
      exists(Function f, Parameter p |
        f.getName() = "get_sql_results" and
        f.getLocation().getFile().getAbsolutePath().matches(
          "%/superset/sql_lab.py"
        ) and
        p = f.getAnArg() and
        not p.isSelf() and
        p.getName() != "ctask" and
        this = DataFlow::parameterNode(p)
      )
    }
  }
}
