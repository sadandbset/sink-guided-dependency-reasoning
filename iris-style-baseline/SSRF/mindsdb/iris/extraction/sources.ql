
/**
 * @name mindsdb source candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate external-input source APIs from the
 *              mindsdb Flask/REST + SQL-wire application for subsequent
 *              LLM labeling.
 * @id py/augur/mindsdb/pass3-sources
 *
 * Plain multi-column select query (no @kind) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * Scope: relative paths under mindsdb/ only, excluding per-handler
 * tests/ directories. This excludes the nested mindsdb-db CodeQL
 * database directory (its files would be mindsdb-db/..., which does
 * not match "mindsdb/%") and the repo-root tests/ tree by
 * construction.
 *
 * Output columns:
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("source_candidate")
 *  3. callable            (handler name / dotted signature hint)
 *  4. flow kind           (param | return | field)
 *  5. receiver            (receiver/type hint)
 *  6. module hint         (dotted module path; variable named moduleHint,
 *                          "module" is a QL keyword and must not be used)
 *  7. argument index      (-1 when not applicable)
 *  8. line
 *  9. file:line
 * 10. expression text
 */

import python

// ------------------------------------------------------------
// 1. Scope and location helpers
// ------------------------------------------------------------

/**
 * Restrict extraction to the mindsdb application package, excluding
 * per-handler tests directories. The path string is bound by equality
 * before matches(), so no unbound-variable error can occur.
 */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("mindsdb/%") and
    not path.matches("mindsdb/%/tests/%")
  )
}

/** Restrict a candidate to the Flask HTTP API layer. */
predicate inHttpApiModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("mindsdb/api/http/%")
  )
}

/** Restrict a candidate to the flask_restx namespaces package. */
predicate inNamespacesModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("mindsdb/api/http/namespaces/%")
  )
}

/**
 * Restrict a candidate to the SQL wire-protocol proxy modules that
 * define process_query(self, sql) (also reached from the HTTP
 * /api/sql/query endpoint via the FakeMysqlProxy subclass).
 */
predicate isSqlWireProxyModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    (
      path = "mindsdb/api/mysql/mysql_proxy/mysql_proxy.py"
      or
      path = "mindsdb/api/postgres/postgres_proxy/postgres_proxy.py"
    )
  )
}

/**
 * Restrict a candidate to the two modules whose environment-variable
 * reads were verified to propagate into outbound requests calls
 * (MINDSDB_EXECUTOR_URL -> requests.delete; REGISTRY_URL -> registry
 * -> requests.post).
 */
predicate isExecutorEnvModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    (
      path = "mindsdb/api/mysql/mysql_proxy/controllers/session_controller.py"
      or
      path = "mindsdb/integrations/handlers_wrapper/ml_handler_service.py"
    )
  )
}

/** Dotted module name of a candidate. */
string moduleOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
}

/** Human-readable file and line location. */
string locationOf(AstNode n) {
  result =
    n.getLocation().getFile().getRelativePath() +
    ":" +
    n.getLocation().getStartLine().toString()
}

// ------------------------------------------------------------
// 2. Candidate extraction
// ------------------------------------------------------------

from
  AstNode n,
  string callable,
  string flow_kind,
  string receiver,
  string moduleHint,
  int arg_index
where
  inAnalysisScope(n) and
  moduleHint = moduleOf(n) and
  (
    // --------------------------------------------------------
    // (1) Flask request container attribute reads in the HTTP
    //     API layer: request.<json|args|form|values|files|
    //     headers|stream>
    //     e.g. api/http/namespaces/sql.py:29
    //            query = request.json["query"]
    //          api/http/namespaces/file.py:83
    //            data = request.json
    //            (PUT /api/files/<name> body; source_type == "url"
    //             makes data["source"] a URL fetched server-side)
    //          api/http/namespaces/databases.py:31
    //            database = request.json['database']
    //            (handler connection args incl. url-bearing engines)
    //          api/http/namespaces/auth.py:63
    //            code = request.args.get("code")
    //     The attribute node is the earliest untrusted-input
    //     materialization; subscript/method consumers
    //     (request.json["query"], request.args.get(...),
    //     request.headers["Content-Type"]) read through it.
    // --------------------------------------------------------

    exists(Attribute a, Name req, string container |
      n = a and
      a.getObject() = req and
      req.getId() = "request" and
      a.getName() = container and
      container in ["json", "args", "form", "values", "files", "headers", "stream"] and
      inHttpApiModule(n) and
      not exists(Assign asg | asg.getATarget() = a) and
      callable = "request." + container and
      flow_kind = "field" and
      receiver = "flask.request" and
      arg_index = -1
    )

    or

    // --------------------------------------------------------
    // (2) Path-variable parameters of flask_restx Resource
    //     handler methods in the namespaces package.
    //     Handlers are methods of classes whose base class is the
    //     Name 'Resource' (from flask_restx import Resource);
    //     index 0 is 'self', so only i >= 1 are real parameters.
    //     e.g. api/http/namespaces/file.py:33
    //            def put(self, name: str)
    //          api/http/namespaces/databases.py:58
    //            def get(self, database_name)
    // --------------------------------------------------------

    exists(Parameter p, Function f, Class c, int i |
      n = p and
      f.getArg(i) = p and
      i > 0 and
      f.getScope() = c and
      c.getABase().(Name).getId() = "Resource" and
      inNamespacesModule(n) and
      callable = f.getName() and
      flow_kind = "param" and
      receiver = "flask_restx.resource" and
      arg_index = i
    )

    or

    // --------------------------------------------------------
    // (3) SQL text boundary of the SQL wire-protocol proxies:
    //     MysqlProxy.process_query(self, sql)
    //       (api/mysql/mysql_proxy/mysql_proxy.py:522; also
    //        inherited by FakeMysqlProxy used by the HTTP
    //        POST /api/sql/query endpoint)
    //     PostgresProxy.process_query(self, sql)
    //       (api/postgres/postgres_proxy/postgres_proxy.py:253)
    //     Arbitrary mindsdb SQL arrives here (CREATE DATABASE
    //     ... USING url-bearing connection args, PATH-type
    //     connection args of the form {'url': ...}, web-crawl
    //     selects), and flows into executor_commands ->
    //     download_file(url) -> requests.get.
    // --------------------------------------------------------

    exists(Parameter p, Function f, Class c |
      n = p and
      f.getArg(1) = p and
      p.asName().getId() = "sql" and
      f.getName() = "process_query" and
      f.getScope() = c and
      isSqlWireProxyModule(n) and
      callable = c.getName() + ".process_query" and
      flow_kind = "param" and
      receiver = "sql_wire_protocol" and
      arg_index = 1
    )

    or

    // --------------------------------------------------------
    // (4) Environment-variable boundaries verified to propagate
    //     to outbound network calls:
    //     - session_controller.py:103
    //         executor_url = os.environ.get("MINDSDB_EXECUTOR_URL")
    //         -> requests.delete(url) at :121
    //     - ml_handler_service.py:24
    //         registry_url = os.environ.get("REGISTRY_URL")
    //         -> registry() (handler_helpers.py:48 requests.post)
    // --------------------------------------------------------

    exists(Call c, Attribute getAttr, Attribute envAttr, Name osName, Expr arg0 |
      n = c and
      c.getFunc() = getAttr and
      getAttr.getName() = "get" and
      getAttr.getObject() = envAttr and
      envAttr.getName() = "environ" and
      envAttr.getObject() = osName and
      osName.getId() = "os" and
      c.getArg(0) = arg0 and
      arg0.(StringLiteral).getText() in ["MINDSDB_EXECUTOR_URL", "REGISTRY_URL"] and
      isExecutorEnvModule(n) and
      callable = "os.environ.get" and
      flow_kind = "return" and
      receiver = "os.environ" and
      arg_index = -1
    )
  )

select
  n,
  "source_candidate",
  callable,
  flow_kind,
  receiver,
  moduleHint,
  arg_index,
  n.getLocation().getStartLine(),
  locationOf(n),
  n.toString()
