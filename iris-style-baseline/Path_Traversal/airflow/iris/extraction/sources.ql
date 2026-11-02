/**
 * @name airflow CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the airflow CodeQL
 *   database (Apache Airflow 2.7.0.dev0, snapshot sha 2811ba7): Flask / Flask-AppBuilder
 *   request reads (request.args/form/values/files/headers/json/view_args including
 *   .get/.getlist/.items calls and the www_request alias, concentrated in
 *   airflow/www/views.py, airflow/www/auth.py, airflow/www/decorators.py,
 *   airflow/www/api/experimental/endpoints.py and airflow/utils/serve_logs.py),
 *   handler entry-point parameters (FAB @expose/@action views, flask @*.route handlers
 *   including the /log/<path:filename> serve-logs view, all functions defined in
 *   airflow.api_connexion.endpoints modules whose kwargs are injected by connexion from
 *   the OpenAPI spec, and airflow.cli.commands handlers taking the argparse 'args'
 *   namespace), JSON and itsdangerous token decoding (json.loads; URLSafeSerializer
 *   .loads of file_token/token), framework request wrappers
 *   (get_json_request_dict, FAB urltools get_page_args/get_order_args/get_page_size_args),
 *   environment variables (os.environ / os.environ.get / os.getenv) and configuration
 *   reads (conf.get* of dags_folder/base_log_folder etc. - deployment trust level, kept
 *   for the labeling step to judge), plus sys.argv.
 *   Raw BQRS extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain multi-column select query
 *   on purpose: @kind problem is the wrong shape for candidate tables and @kind table is
 *   not assumed to exist.
 * @id iris/airflow/extraction/sources
 * @tags path-traversal
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sinks.ql and to the prior IRIS manual projects):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable name (API member name, function name, or attribute name)
 *   4. flow_kind  - "http" (flask request read or framework request wrapper), "param"
 *                   (handler/CLI function parameter), "return" (decode API return value:
 *                   json.loads, itsdangerous serializer .loads), "env", "config"
 *                   (conf.get*), "cli" (sys.argv), "internal_transfer" (call handing
 *                   external data to a request/token wrapper)
 *   5. receiver   - syntactic receiver hint (base name of the object expression, "" if none)
 *   6. moduleHint - module hint: external module name, or dotted python module path for
 *                   internal candidates (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index (parameter position in the function
 *                   definition for "param" rows), -1 if N/A
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath(); AstNode.getFile()
 *                    does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast" (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates/functions), avoids assigning
 * API::Node values to DataFlow::Node variables, and keeps resolved-API matching strictly
 * separate from AST syntax matching (the match_kind column records which one produced a row).
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for internal candidates). */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
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

/** Syntactic name of the callee of a call ("<expr>" if it is neither Name nor Attribute). */
string calledNameOf(Call c) {
  result = c.getFunc().(Name).getId()
  or
  result = c.getFunc().(Attribute).getName()
  or
  not c.getFunc() instanceof Name and
  not c.getFunc() instanceof Attribute and
  result = "<expr>"
}

/** Holds if n sits inside a test file: any path under a tests/ directory or conftest.py. */
predicate isTestLocation(AstNode n) {
  n.getLocation().getFile().getAbsolutePath().matches("%/tests/%")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%\\tests\\%")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%/conftest.py")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%\\conftest.py")
}

/** The syntactic Call node behind an API graph call node. */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/* ------------------------------------------------------------------ */
/* Source family 1: resolved decode APIs (API graphs)                  */
/* ------------------------------------------------------------------ */

/**
 * External decoding APIs whose return value may carry attacker-controlled data:
 * json.loads decodes HTTP bodies / query metadata / the varimport upload
 * (airflow/www/views.py:1599, airflow/www/views.py:5170); os.getenv reads the process
 * environment (configuration.py, executors, providers; deployment trust level).
 */
private predicate resolvedDecodeCall(API::CallNode cn, string moduleHint, string member, int argIndex) {
  (
    moduleHint = "json" and member = "loads" and argIndex = 0
    or
    moduleHint = "os" and member = "getenv" and argIndex = 0
  ) and
  cn = API::moduleImport(moduleHint).getMember(member).getACall()
}

/* ------------------------------------------------------------------ */
/* Source family 2: flask request reads (AST shapes)                   */
/* ------------------------------------------------------------------ */

/** Flask request proxy attribute names that carry request data. */
private predicate flaskRequestAttribute(string name) {
  name in ["args", "form", "values", "files", "data", "json", "stream", "headers",
           "cookies", "query_string", "view_args", "host_url", "url", "path",
           "full_path", "method", "remote_addr", "accept_mimetypes", "is_json",
           "mimetype", "content_type"]
}

/**
 * Holds if o is a syntactic reference to the flask request proxy: a Name `request`,
 * an alias Name (`www_request`, `flask_request`) or an Attribute `flask.request` /
 * `<alias>.request`. The www_request alias is real: get_date_time_num_runs_dag_runs_form_data
 * receives the flask request under that name (airflow/www/views.py:205-225).
 */
private predicate requestObject(Expr o) {
  o.(Name).getId() in ["request", "www_request", "flask_request"]
  or
  o.(Attribute).getName() = "request"
}

/**
 * Holds if a is an attribute read on the flask request proxy: `request.<attr>`,
 * `www_request.<attr>` or `flask.request.<attr>` (covers request.args, request.files,
 * request.view_args - the serve-logs URL path variable dict - etc.).
 */
private predicate flaskRequestAttr(Attribute a) {
  flaskRequestAttribute(a.getName()) and requestObject(a.getObject())
}

/** Flask request multivalue-dict fields read via methods (request.args.get etc.). */
private predicate flaskRequestField(Attribute a) {
  a.getName() in ["args", "form", "values", "json", "headers", "cookies"] and
  requestObject(a.getObject())
}

/**
 * Calls reading request fields: `request.get_json(...)` / `request.get_data(...)`
 * directly on the proxy (request_dict.py:26, experimental endpoints.py:86/:376),
 * `request.<field>.get/getlist/items/to_dict/pop(...)` (request.args.get, form.getlist,
 * values.items, view_args.items ...) and `request.accept_mimetypes.best_match(...)`
 * (log_endpoint.py:103, dag_source_endpoint.py:42).
 */
private predicate flaskRequestCall(Call c, string callableName) {
  exists(Attribute func |
    func = c.getFunc().(Attribute) and
    callableName = func.getName() and
    (
      /* request.get_json(...) / request.get_data(...) directly on the proxy */
      func.getName() in ["get_json", "get_data"] and
      requestObject(func.getObject())
      or
      /* request.<field>.get(...) / .getlist(...) / .items(...) / .to_dict(...) / .pop(...) */
      func.getName() in ["get", "getlist", "items", "to_dict", "pop"] and
      (
        flaskRequestField(func.getObject().(Attribute))
        or
        func.getObject().(Attribute).getName() = "view_args" and
        requestObject(func.getObject().(Attribute).getObject())
      )
      or
      /* request.accept_mimetypes.best_match(...) */
      func.getName() = "best_match" and
      func.getObject().(Attribute).getName() = "accept_mimetypes" and
      requestObject(func.getObject().(Attribute).getObject())
    )
  )
}

/* ------------------------------------------------------------------ */
/* Source family 3: handler entry points and CLI handlers              */
/* ------------------------------------------------------------------ */

/**
 * f is an HTTP handler: FAB @expose(...)/@action(...) decorated views
 * (airflow/www/views.py, airflow/www/fab_security/views.py) or flask
 * @<blueprint>.route(...) / @app.route(...) decorated functions
 * (www/api/experimental/endpoints.py, utils/serve_logs.py, www/blueprints.py),
 * or any function defined in an airflow.api_connexion.endpoints module
 * (connexion injects path/query parameters as function kwargs per openapi/v1.yaml).
 */
private predicate isHandlerFunction(Function f) {
  exists(Expr d |
    d = f.getADecorator() and
    (
      /* @expose(...) / @action(...) - from flask_appbuilder import expose / action */
      d.(Call).getFunc().(Name).getId() in ["expose", "action"]
      or
      /* @api_experimental.route(...) / @flask_app.route(...) / @routes.route(...) */
      d.(Call).getFunc().(Attribute).getName() = "route"
    )
  )
  or
  moduleHintOf(f).matches("%.api_connexion.endpoints.%")
}

/**
 * f is an argparse CLI handler: defined in an airflow.cli.commands module
 * (this snapshot's CLI is argparse, not click) and takes the parsed
 * `args` namespace parameter (e.g. dag_processor_command.py:45-47 args.subdir).
 */
private predicate isCliHandlerFunction(Function f) {
  moduleHintOf(f).matches("%.cli.commands.%") and
  exists(Parameter p | p = f.getAnArg() and p.getName() = "args")
}

/* ------------------------------------------------------------------ */
/* Source family 4: itsdangerous token decode (AST shape)             */
/* ------------------------------------------------------------------ */

/**
 * Calls decoding a signed token whose plaintext is request-supplied:
 * `auth_s.loads(file_token)` (dag_source_endpoint.py:37 - decoded path used by DagCode)
 * and `URLSafeSerializer(key).loads(token)` (log_endpoint.py:64).
 */
private predicate serializerLoadsCall(Call c) {
  c.getFunc().(Attribute).getName() = "loads" and
  (
    c.getFunc().(Attribute).getObject().(Name).getId() = "auth_s"
    or
    c.getFunc().(Attribute).getObject() instanceof Call and
    c.getFunc().(Attribute).getObject().(Call).getFunc().(Name).getId() in
      ["URLSafeSerializer", "URLSafeTimedSerializer", "TimedSerializer"]
  )
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1a: resolved decode API calls (API graphs, alias-aware) */
  exists(API::CallNode cn |
    resolvedDecodeCall(cn, moduleHint, callableName, argIndex) and
    node = astCallOf(cn) and
    (
      flowKind = "return" and moduleHint = "json"
      or
      flowKind = "env" and moduleHint = "os"
    ) and
    receiver = "" and
    matchKind = "api"
  )
  or
  /* family 1b: syntax-level fallback of the decode APIs (module-qualified attribute calls) */
  exists(Call c |
    argIndex = 0 and
    (
      moduleHint = "json" and callableName = "loads"
      or
      moduleHint = "os" and callableName = "getenv"
    ) and
    c.getFunc().(Attribute).getName() = callableName and
    c.getFunc().(Attribute).getObject().(Name).getId() = moduleHint and
    node = c and
    (
      flowKind = "return" and moduleHint = "json"
      or
      flowKind = "env" and moduleHint = "os"
    ) and
    receiver = moduleHint and
    matchKind = "ast"
  )
  or
  /* family 2a: flask request proxy attribute reads (request.args, request.files,
     request.view_args, flask.request.data, www_request.values, ...) */
  exists(Attribute a |
    flaskRequestAttr(a) and
    node = a and
    flowKind = "http" and
    callableName = a.getName() and
    argIndex = -1 and
    (
      a.getObject() instanceof Attribute and
      receiver = a.getObject().(Attribute).getName()
      or
      a.getObject() instanceof Name and
      receiver = a.getObject().(Name).getId()
    ) and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 2b: flask request field method calls (request.get_json, request.args.get,
     request.form.getlist, request.values.items, request.accept_mimetypes.best_match, ...) */
  exists(Call c |
    flaskRequestCall(c, callableName) and
    node = c and
    flowKind = "http" and
    argIndex = 0 and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3a: parameters of HTTP handler functions (FAB @expose/@action views,
     flask route handlers incl. serve_logs_view, connexion endpoint functions).
     Keyword-only parameters are included because connexion handlers declare them
     after a bare `*` (e.g. get_log(*, dag_id, dag_run_id, ...)); they have no
     positional index, so arg_index falls back to -1. */
  exists(Function f, Parameter p |
    isHandlerFunction(f) and
    (p = f.getAnArg() or p = f.getAKeywordOnlyArg()) and
    not p.isSelf() and
    node = p and
    flowKind = "param" and
    callableName = f.getName() and
    (
      argIndex = p.getPosition()
      or
      not exists(p.getPosition()) and argIndex = -1
    ) and
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
  /* family 3b: the parsed `args` namespace parameter of argparse CLI handlers
     (airflow dags tasks --subdir, --cfg-path, import/export paths, --log-file, ...) */
  exists(Function f, Parameter p |
    isCliHandlerFunction(f) and
    p = f.getAnArg() and
    p.getName() = "args" and
    node = p and
    flowKind = "param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
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
  /* family 4a: os.environ read (attribute; subscripts and .get read this attribute) */
  exists(Attribute a |
    a.getName() = "environ" and
    a.getObject().(Name).getId() = "os" and
    not a.getParentNode() instanceof Attribute and
    node = a and
    flowKind = "env" and
    callableName = "environ" and
    argIndex = -1 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 4b: os.environ.get(...) / os.environ.pop(...) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["get", "pop"] and
    func.getObject().(Attribute).getName() = "environ" and
    func.getObject().(Attribute).getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "env" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 4c: sys.argv read (airflow/utils/cli.py:140 command echo) */
  exists(Attribute a |
    a.getName() = "argv" and
    a.getObject().(Name).getId() = "sys" and
    node = a and
    flowKind = "cli" and
    callableName = "argv" and
    argIndex = -1 and
    receiver = "sys" and
    moduleHint = "sys" and
    matchKind = "ast"
  )
  or
  /* family 5a: airflow configuration reads (conf.get/getint/getboolean/getfloat/
     get_mandatory_value/getsection - dags_folder, base_log_folder, ...;
     deployment trust level, not automatically an attacker source) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["get", "getint", "getboolean", "getfloat", "get_mandatory_value",
                       "getsection"] and
    func.getObject().(Name).getId() = "conf" and
    node = c and
    flowKind = "config" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "conf" and
    moduleHint = "airflow.configuration" and
    matchKind = "ast"
  )
  or
  /* family 5b: itsdangerous signed-token decode (auth_s.loads(file_token) /
     URLSafeSerializer(key).loads(token)) - decoded value is request-supplied */
  exists(Call c |
    serializerLoadsCall(c) and
    node = c and
    flowKind = "return" and
    callableName = "loads" and
    argIndex = 0 and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 6: internal request/token wrappers handing external data to consumers:
     get_json_request_dict (api_connexion JSON body reader), FAB urltools
     get_page_args/get_order_args/get_page_size_args (pagination/order request args) */
  exists(Call c |
    calledNameOf(c) in ["get_json_request_dict", "get_page_args", "get_order_args",
                        "get_page_size_args"] and
    node = c and
    flowKind = "internal_transfer" and
    callableName = calledNameOf(c) and
    argIndex = -1 and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  not isTestLocation(node)
select
  node,
  "source_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
