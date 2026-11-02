/**
 * Augur generated CWE-78 source library (ray, pass 2).
 *
 * Machine-generated from iris/labels/labels.json (run ray-iris-pass2-20261016,
 * pass_id 2, cwes ["078"]) by Phase 2 Step 4. Only label entries with
 * classification "tp" and role "source"/"summary" are modeled; candidate and
 * fp entries are deliberately excluded from the first query round (see
 * report/query_generation_notes.md for the full label-id-to-predicate mapping
 * and per-site source evidence).
 *
 * Modeled source families (all verified against the ray_vuln tree at sha
 * 79a5643):
 *   - dashboard head/agent HTTP request reads: req.query/match_info/headers
 *     .get(k)/[k] and bare attribute reads, plus await req.json()/req.read()
 *     (unauthenticated aiohttp API, default port 8265)
 *   - route-handler request parameters of @routes.<verb>-decorated functions
 *     in dashboard/modules/**
 *   - 'ray job' CLI parameters (dashboard/modules/job/cli.py, click-bound) -
 *     labeled tp in Phase 1; documented as a local-operator boundary
 *   - gRPC servicer request parameters and request.<field> message reads in
 *     the reporter agent, log agent, event head and the ray client server
 *   - job-pipeline json.loads/load decodes in dashboard/modules/job/**
 *   - serve agent pydantic <X>Schema.parse_obj(await req.json())
 *   - Starlette serve ingress reads in python/ray/serve/http_adapters.py
 *   - runtime-env agent request body reads in
 *     python/ray/_private/runtime_env/agent/main.py
 *
 * The pass key is "command_injection"; predicates return nothing for any
 * other key.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  /* ------------------------------------------------------------------ */
  /* Shared shape predicates (mirror extraction/sources.ql families)     */
  /* ------------------------------------------------------------------ */

  /** Variables that carry an HTTP request object in this codebase:
   * aiohttp dashboard handlers use `req`; Starlette serve adapters use
   * `request` / `raw_request`. */
  private predicate isRequestVarName(string name) {
    name in ["req", "request", "raw_request"]
  }

  /** Request state attribute names read off a request variable (aiohttp:
   * query / match_info / headers; Starlette: query_params). */
  private predicate isRequestStateName(string name) {
    name in ["query", "match_info", "headers", "query_params"]
  }

  /** File-scope helpers: label families are scoped to the modules whose
   * rows were classified tp in Phase 1. Paths are matched against the
   * database sourceLocationPrefix (ray_vuln tree). */
  private predicate inDashboard(AstNode a) {
    a.getLocation().getFile().getAbsolutePath().matches("%/dashboard/%")
  }

  private predicate inJobModule(AstNode a) {
    a.getLocation().getFile().getAbsolutePath().matches("%/dashboard/modules/job/%")
  }

  private predicate inServeAgent(AstNode a) {
    a.getLocation().getFile().getAbsolutePath().matches("%/dashboard/modules/serve/serve_agent.py%")
  }

  private predicate inServeHttpAdapters(AstNode a) {
    a.getLocation().getFile().getAbsolutePath().matches("%/python/ray/serve/http_adapters.py%")
  }

  private predicate inRuntimeEnvAgent(AstNode a) {
    a
      .getLocation()
      .getFile()
      .getAbsolutePath()
      .matches("%/python/ray/_private/runtime_env/agent/main.py%")
  }

  private predicate inGrpcServicerModule(AstNode a) {
    a.getLocation().getFile().getAbsolutePath().matches("%/dashboard/modules/reporter/reporter_agent.py%") or
    a.getLocation().getFile().getAbsolutePath().matches("%/dashboard/modules/log/log_agent.py%") or
    a.getLocation().getFile().getAbsolutePath().matches("%/dashboard/modules/event/event_head.py%") or
    a.getLocation().getFile().getAbsolutePath().matches("%/python/ray/util/client/server/%")
  }

  /** An aiohttp route handler: decorated with @routes.<verb>(...) or
   * @router.<verb>(...) (dashboard head/agent servers register handlers on
   * the aiohttp routes table). */
  private predicate isRouteHandler(Function f) {
    exists(Expr d, Call c, Attribute func |
      d = f.getADecorator() and
      c = d.(Call) and
      func = c.getFunc().(Attribute) and
      func.getName() in ["get", "post", "put", "delete", "patch", "head", "route"] and
      func.getObject().(Name).getId() in ["routes", "router"]
    )
  }

  /** A function with the grpc servicer signature shape: a parameter named
   * request/req/request_iterator next to a parameter named context (the
   * generated *_pb2_grpc base classes are outside the extracted tree). */
  private predicate isGrpcServicerShaped(Function f) {
    exists(Parameter p, Parameter ctx |
      p = f.getAnArg() and
      ctx = f.getAnArg() and
      p != ctx and
      p.getName().regexpMatch("req.*") and
      ctx.getName() = "context"
    )
  }

  /** A click-bound CLI command function (ray job CLI group etc.). */
  bindingset[recv]
  private predicate isClickReceiver(string recv) {
    recv in ["click", "cli"] or
    recv.regexpMatch(".*_group")
  }

  private predicate isClickDecoratorCall(Call c) {
    exists(Attribute func |
      func = c.getFunc().(Attribute) and
      func.getName() in [
          "argument", "option", "command", "group", "version_option", "password_option",
          "confirmation_option", "help_option"
        ] and
      isClickReceiver(func.getObject().(Name).getId())
    )
  }

  private predicate isClickBoundFunction(Function f) {
    exists(Expr d |
      d = f.getADecorator() and
      (
        d instanceof Call and
        isClickDecoratorCall(d.(Call))
        or
        d.(Attribute).getName() in ["command", "group"] and
        isClickReceiver(d.(Attribute).getObject().(Name).getId())
      )
    )
  }

  /* ------------------------------------------------------------------ */
  /* Source families (label tp entries only)                             */
  /* ------------------------------------------------------------------ */

  /**
   * Dashboard HTTP request state reads (label families http_request 2b/2c/2d,
   * tp entries in dashboard/modules/** and dashboard/optional_utils.py):
   *   - `req.query.get("k")` / `req.match_info.get("k")` /
   *     `req.headers.pop("k")` - the source is the call value
   *   - `req.query["pid"]` / `req.match_info["job_id"]` - the source is the
   *     subscript value
   *   - a bare `req.headers` / `req.query` state object read used as a value
   */
  private predicate isDashboardRequestStateRead(DataFlow::Node n) {
    exists(Call c, Attribute func, string requestVar |
      isRequestVarName(requestVar) and
      func = c.getFunc().(Attribute) and
      func.getName() in ["get", "pop"] and
      func.getObject().(Attribute).getName() in ["query", "match_info", "headers"] and
      func.getObject().(Attribute).getObject().(Name).getId() = requestVar and
      n.asExpr() = c and
      inDashboard(c)
    )
    or
    exists(Subscript s, string requestVar |
      isRequestVarName(requestVar) and
      isRequestStateName(s.getObject().(Attribute).getName()) and
      s.getObject().(Attribute).getObject().(Name).getId() = requestVar and
      n.asExpr() = s and
      inDashboard(s)
    )
    or
    exists(DataFlow::AttrRead ar, string requestVar |
      isRequestVarName(requestVar) and
      isRequestStateName(ar.getAttributeName()) and
      ar.getObject().asExpr().(Name).getId() = requestVar and
      n = ar and
      inDashboard(n.asExpr())
    )
  }

  /**
   * Dashboard HTTP request body reads (label family http_request 2e, tp):
   * `await req.json()` / `await req.read()` (and the same shapes for
   * text/post). Source is the call value.
   */
  private predicate isDashboardRequestBodyRead(DataFlow::Node n) {
    exists(Call c, Attribute func, string requestVar |
      isRequestVarName(requestVar) and
      func = c.getFunc().(Attribute) and
      func.getName() in ["json", "read", "text", "post"] and
      func.getObject().(Name).getId() = requestVar and
      n.asExpr() = c and
      inDashboard(c)
    )
  }

  /**
   * Serve ingress reads (labels p2-e-1603, p2-e-1604, tp 0.7):
   * `await request.json()` and the `raw_request.query_params` attribute read
   * in python/ray/serve/http_adapters.py (Starlette ingress adapters).
   */
  private predicate isServeIngressRead(DataFlow::Node n) {
    exists(Call c, Attribute func, string requestVar |
      isRequestVarName(requestVar) and
      func = c.getFunc().(Attribute) and
      func.getName() in ["json", "read", "text", "body"] and
      func.getObject().(Name).getId() = requestVar and
      n.asExpr() = c and
      inServeHttpAdapters(c)
    )
    or
    exists(DataFlow::AttrRead ar, string requestVar |
      isRequestVarName(requestVar) and
      ar.getAttributeName() = "query_params" and
      ar.getObject().asExpr().(Name).getId() = requestVar and
      n = ar and
      inServeHttpAdapters(n.asExpr())
    )
  }

  /**
   * Runtime-env agent HTTP body reads (labels p2-e-0732, p2-e-0733, p2-e-0734,
   * tp 0.8): `await request.read()` in the POST /get_or_create_runtime_env
   * (and sibling) handlers of python/ray/_private/runtime_env/agent/main.py.
   * The body is a serialized GetOrCreateRuntimeEnvRequest whose runtime_env
   * payload drives the conda/pip subprocess chain.
   */
  private predicate isRuntimeEnvAgentBodyRead(DataFlow::Node n) {
    exists(Call c, Attribute func, string requestVar |
      isRequestVarName(requestVar) and
      func = c.getFunc().(Attribute) and
      func.getName() in ["read", "json"] and
      func.getObject().(Name).getId() = requestVar and
      n.asExpr() = c and
      inRuntimeEnvAgent(c)
    )
  }

  /**
   * Route-handler request parameters (label family param 3b for
   * @routes-decorated functions, tp): the `req`/`request` parameter of
   * dashboard head/agent aiohttp handlers. These are the externally invoked
   * handler boundaries, not internal wrapper parameters.
   */
  private predicate isDashboardRouteHandlerParam(DataFlow::Node n) {
    exists(Parameter p, Function f |
      isRouteHandler(f) and
      p = f.getAnArg() and
      not p.isSelf() and
      p.getName() in ["req", "request"] and
      n.(DataFlow::ParameterNode).getParameter() = p and
      inDashboard(f)
    )
  }

  /**
   * 'ray job' CLI parameters (33 tp param entries in
   * dashboard/modules/job/cli.py, p2-e-0228..p2-e-0293 range): parameters of
   * click-bound command functions (submit --entrypoint/--runtime-env, stop,
   * logs, ...). Phase 1 labeled these tp as job-pipeline boundary rows; they
   * are the local CLI twin of the remote submission path and are modeled
   * faithfully to the labels (see query_generation_notes.md section 5).
   */
  private predicate isJobCliParam(DataFlow::Node n) {
    exists(Parameter p, Function f |
      isClickBoundFunction(f) and
      p = f.getAnArg() and
      not p.isSelf() and
      n.(DataFlow::ParameterNode).getParameter() = p and
      f.getLocation().getFile().getAbsolutePath().matches("%/dashboard/modules/job/cli.py%")
    )
  }

  /**
   * gRPC servicer request parameters (label family param 3b for
   * servicer-shaped methods, tp): the request parameter of
   * ReporterAgent.GetTraceback/CpuProfiling/ReportOCMetrics,
   * LogAgent.ListLogs/StreamLog, event head ReportEvents and the ray client
   * server servicers (RayletServicer/DataServicer/LogstreamServicer/proxier).
   */
  private predicate isGrpcServicerParam(DataFlow::Node n) {
    exists(Parameter p, Function f |
      isGrpcServicerShaped(f) and
      p = f.getAnArg() and
      not p.isSelf() and
      p.getName().regexpMatch("req.*") and
      n.(DataFlow::ParameterNode).getParameter() = p and
      inGrpcServicerModule(f)
    )
  }

  /**
   * gRPC message field reads (label family message 3a, tp): `request.<field>`
   * attribute reads inside servicer-shaped functions - the reporter agent
   * pid/duration/format/native fields that feed the py-spy shell commands,
   * the log agent log_file_name/offsets fields, event event_strings and the
   * ray client server message fields.
   */
  private predicate isGrpcMessageFieldRead(DataFlow::Node n) {
    exists(Attribute a, Function f, Parameter p |
      isGrpcServicerShaped(f) and
      a.getScope().(Function) = f and
      p = f.getAnArg() and
      p.getName().regexpMatch("req.*") and
      a.getObject().(Name).getId() = p.getName() and
      n.asExpr() = a and
      inGrpcServicerModule(a)
    )
  }

  /**
   * Job-pipeline JSON decodes (label family return 1 in
   * dashboard/modules/job/**, tp 0.7): json.loads/json.load of job
   * submission payload pieces (runtime_env_json at common.py:173, serialized
   * job info at common.py:223, CLI --headers JSON at cli.py:47). Source is
   * the decode call value.
   */
  private predicate isJobPipelineJsonDecode(DataFlow::Node n) {
    exists(Call c |
      c.getFunc().(Attribute).getName() in ["loads", "load"] and
      c.getFunc().(Attribute).getObject().(Name).getId() = "json" and
      n.asExpr() = c and
      inJobModule(c)
    )
  }

  /**
   * Serve agent deployment-config decodes (labels p2-e-0457, p2-e-0459,
   * tp 0.75): ServeApplicationSchema.parse_obj(await req.json()) /
   * ServeDeploySchema.parse_obj(await req.json()) in the PUT
   * /api/serve/deployments|applications handlers. Source is the parse_obj
   * call value (pydantic validates shape only).
   */
  private predicate isServeAgentConfigDecode(DataFlow::Node n) {
    exists(Call c, Attribute func |
      func = c.getFunc().(Attribute) and
      func.getName() in ["parse_obj", "parse_raw"] and
      func.getObject().(Name).getId().regexpMatch(".*Schema") and
      n.asExpr() = c and
      inServeAgent(c)
    )
  }

  /* ------------------------------------------------------------------ */
  /* Public interface                                                    */
  /* ------------------------------------------------------------------ */

  /**
   * Holds if `n` is a CWE-78 taint source for the given pass key, according
   * to the Phase 1 tp labels of run ray-iris-pass2-20261016.
   */
  predicate isSource(DataFlow::Node n, string passKey) {
    passKey = "command_injection" and
    (
      isDashboardRequestStateRead(n) or
      isDashboardRequestBodyRead(n) or
      isServeIngressRead(n) or
      isRuntimeEnvAgentBodyRead(n) or
      isDashboardRouteHandlerParam(n) or
      isJobCliParam(n) or
      isGrpcServicerParam(n) or
      isGrpcMessageFieldRead(n) or
      isJobPipelineJsonDecode(n) or
      isServeAgentConfigDecode(n)
    )
  }
}
