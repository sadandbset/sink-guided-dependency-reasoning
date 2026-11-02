/**
 * @name ray CWE-78 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the ray
 *   CodeQL database (snapshot 79a5643): aiohttp dashboard request reads (req.query /
 *   req.match_info / req.json() / req.read() on the head and agent HTTP servers),
 *   grpc message-field reads on servicer-shaped methods (reporter agent pid/duration/
 *   format, ray client server request fields), Starlette serve ingress reads
 *   (request.json()/body()/query_params), JSON/YAML decoding (json.loads, yaml.safe_load
 *   incl. the autoscaler cluster config loads), environment reads (os.environ /
 *   os.environ.get / os.getenv), click CLI decorators and sys.argv, open() file input,
 *   pydantic Schema.parse_obj/parse_raw payload decoding, handler entry-point parameters
 *   (route-decorated aiohttp handlers, (self, request*, context) grpc servicer methods,
 *   click-bound CLI commands), and the internal job request-transfer wrapper
 *   parse_and_validate_request. Raw BQRS extraction query: run with `codeql query run`
 *   and decode with `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong shape for
 *   candidate tables and @kind table is not assumed to exist.
 * @id iris/ray/extraction/sources
 * @tags command-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable name (API member name, function name, or attribute name)
 *   4. flow_kind  - "return" (tainted return value of a decode API), "http_request"
 *                   (aiohttp/Starlette request read), "message" (grpc message field
 *                   read on a servicer-shaped method), "param" (handler / servicer /
 *                   CLI function parameter), "cli" (click decorator, sys.argv),
 *                   "env" (os.environ read), "config" (pydantic payload decode),
 *                   "file" (open() input), "internal_transfer" (call handing external
 *                   data to a handler / parser)
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
 * Note: this file defines no QL classes (only predicates), avoids assigning API::Node
 * values to DataFlow::Node variables, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced a row).
 * Ray's dynamic receiver boundaries (req.query attribute chains, grpc request.<field>
 * reads, pydantic Schema.parse_obj classmethod calls) resolve only at AST level.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for internal
 *  candidates). Top-level scripts that are not on an import path (setup-dev.py,
 *  raysort/main.py, ...) have no dotted module name; their file base name is used
 *  instead. */
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

/** Variable names that carry an HTTP request object in this codebase:
 *  aiohttp dashboard handlers use req; Starlette serve adapters use
 *  request / raw_request. */
private predicate requestVarName(string name) {
  name in ["req", "request", "raw_request"]
}

/** Request state attribute names read off a request variable (aiohttp: query,
 *  match_info, headers; Starlette: query_params). */
private predicate requestStateName(string name) {
  name in ["query", "match_info", "headers", "query_params"]
}

/* ------------------------------------------------------------------ */
/* Source family 1: resolved decode APIs (API graphs)                  */
/* ------------------------------------------------------------------ */

/**
 * External decoding/lookup APIs whose return value may carry attacker-controlled data:
 * json.loads decodes HTTP bodies / config blobs, yaml.safe_load/yaml.load decodes the
 * user-supplied autoscaler cluster config and runtime_env files, os.getenv reads the
 * process environment. All three are heavily used in this snapshot.
 */
private predicate resolvedDecodeCall(API::CallNode cn, string moduleHint, string member, int argIndex) {
  (
    moduleHint = "json" and member in ["loads", "load"] and argIndex = 0
    or
    moduleHint = "yaml" and member in ["safe_load", "load", "full_load"] and argIndex = 0
    or
    moduleHint = "os" and member = "getenv" and argIndex = 0
  ) and
  cn = API::moduleImport(moduleHint).getMember(member).getACall()
}

/** The syntactic Call node behind an API graph call node. */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/* ------------------------------------------------------------------ */
/* Source family 2: handler / servicer / CLI function shapes           */
/* ------------------------------------------------------------------ */

/**
 * Functions with the grpc servicer signature shape: a parameter named request/req/
 * request_iterator next to a parameter named context. This catches the generated
 * servicer overrides in this codebase (ReporterAgent.GetTraceback/CpuProfiling,
 * RayletServicer.*, DataServicer.Datapath, LogstreamServicer.*) whose base classes
 * live in generated *_pb2_grpc modules outside the extracted source tree.
 */
private predicate isGrpcServicerShaped(Function f) {
  exists(Parameter p, Parameter ctx |
    p = f.getAnArg() and
    ctx = f.getAnArg() and
    p != ctx and
    p.getName().regexpMatch("req.*") and
    ctx.getName() = "context"
  )
}

/** click decorator receivers observed in this codebase (click, cli, job_cli_group,
 *  logs_state_cli_group, summary_state_cli_group). */


bindingset[name]
private predicate clickReceiver(string name) {
  name in ["click", "cli"]
  or
  name.regexpMatch(".*_group")
}

/** click decorators that attach arguments/options to CLI commands or define commands. */
private predicate clickDecoratorCall(Call c) {
  exists(Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["argument", "option", "command", "group", "version_option",
                       "password_option", "confirmation_option", "help_option"] and
    clickReceiver(receiverHint(func))
  )
}

/** Functions whose decorators make them CLI entry points or attach CLI arguments (click). */
private predicate clickBoundFunction(Function f) {
  exists(Expr d |
    d = f.getADecorator() and
    (
      d instanceof Call and clickDecoratorCall(d.(Call))
      or
      d.(Attribute).getName() in ["command", "group"] and
      clickReceiver(receiverHint(d.(Attribute)))
    )
  )
}

/** f is an aiohttp route handler: decorated with a @routes.<verb>(...) decorator
 *  (dashboard head/agent servers register handlers on the aiohttp routes table). */
private predicate isRouteHandler(Function f) {
  exists(Expr d |
    d = f.getADecorator() and
    d.(Call).getFunc().(Attribute).getName() in
      ["get", "post", "put", "delete", "patch", "head", "route"] and
    receiverHint(d.(Call).getFunc().(Attribute)) in ["routes", "router"]
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
  /* family 1: resolved decode API calls (API graphs, alias-aware) */
  exists(API::CallNode cn |
    resolvedDecodeCall(cn, moduleHint, callableName, argIndex) and
    node = astCallOf(cn) and
    flowKind = "return" and
    receiver = "" and
    matchKind = "api"
  )
  or
  /* family 2a: syntax-level fallback of the decode APIs (module-qualified calls) */
  exists(Call c |
    argIndex = 0 and
    (
      moduleHint = "json" and callableName in ["loads", "load"]
      or
      moduleHint = "yaml" and callableName in ["safe_load", "load", "full_load"]
      or
      moduleHint = "os" and callableName = "getenv"
    ) and
    c.getFunc().(Attribute).getName() = callableName and
    c.getFunc().(Attribute).getObject().(Name).getId() = moduleHint and
    node = c and
    flowKind = "return" and
    receiver = moduleHint and
    matchKind = "ast"
  )
  or
  /* family 2b: aiohttp/Starlette request state attribute reads
     (req.query / req.match_info / req.headers / request.query_params, e.g.
     'task_id' in req.query). Excluded when the attribute is itself the receiver of
     a .get(...) call (family 2c) or of a subscript (family 2d) to avoid duplicate
     rows. */
  exists(Attribute a, string requestVar |
    requestVarName(requestVar) and
    requestStateName(a.getName()) and
    a.getObject().(Name).getId() = requestVar and
    not a.getParentNode() instanceof Attribute and
    not a.getParentNode() instanceof Subscript and
    node = a and
    flowKind = "http_request" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = requestVar and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 2c: request state field reads: req.query.get("k") /
     req.match_info.get("k") / req.headers.get("k") */
  exists(Call c, Attribute func, string requestVar |
    requestVarName(requestVar) and
    func = c.getFunc().(Attribute) and
    func.getName() in ["get", "pop"] and
    requestStateName(func.getObject().(Attribute).getName()) and
    func.getObject().(Attribute).getObject().(Name).getId() = requestVar and
    node = c and
    flowKind = "http_request" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = requestVar + "." + func.getObject().(Attribute).getName() and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 2d: request state subscripts: req.match_info["job_id"] /
     req.query["pid"] / req.headers[...] */
  exists(Subscript s, string requestVar |
    requestVarName(requestVar) and
    requestStateName(s.getObject().(Attribute).getName()) and
    s.getObject().(Attribute).getObject().(Name).getId() = requestVar and
    node = s and
    flowKind = "http_request" and
    callableName = s.getObject().(Attribute).getName() and
    argIndex = -1 and
    receiver = requestVar + "." + s.getObject().(Attribute).getName() and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 2e: request body reads: await req.json() / req.read() / req.text()
     (aiohttp dashboard handlers) and await request.json() / raw_request.body()
     (Starlette serve ingress adapters) */
  exists(Call c, Attribute func, string requestVar |
    requestVarName(requestVar) and
    func = c.getFunc().(Attribute) and
    func.getName() in ["json", "read", "text", "post"] and
    func.getObject().(Name).getId() = requestVar and
    node = c and
    flowKind = "http_request" and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = requestVar and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3a: grpc message field reads: request.pid / request.duration /
     request.format / req.<field> on a servicer-shaped function's request parameter */
  exists(Attribute a, Function f, Parameter p |
    isGrpcServicerShaped(f) and
    a.getScope().(Function) = f and
    p = f.getAnArg() and
    p.getName().regexpMatch("req.*") and
    p.getName() = a.getObject().(Name).getId() and
    node = a and
    flowKind = "message" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = p.getName() and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 3b: parameters of handler entry-point functions
     (aiohttp route handlers, grpc servicer-shaped methods, click-bound CLI commands;
     arg_index is the 0-based position in the function definition) */
  exists(Function f, Parameter p |
    (
      isRouteHandler(f)
      or
      isGrpcServicerShaped(f)
      or
      clickBoundFunction(f)
    ) and
    p = f.getAnArg() and
    not p.isSelf() and
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
  /* family 4a: click decorator calls (option/argument/command registration) */
  exists(Call c |
    clickDecoratorCall(c) and
    node = c and
    flowKind = "cli" and
    callableName = c.getFunc().(Attribute).getName() and
    argIndex = 0 and
    receiver = receiverHintOfCall(c) and
    moduleHint = "click" and
    matchKind = "ast"
  )
  or
  /* family 4b: sys.argv read */
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
  /* family 5a: os.environ read (attribute; subscripts and .get read this attribute) */
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
  /* family 5b: os.environ.get(...) / os.environ.pop(...) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["get", "pop"] and
    func.getObject().(Attribute).getName() = "environ" and
    func.getObject().(Attribute).getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "env" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 6a: pydantic payload decoding: <X>Schema.parse_obj(...) / .parse_raw(...)
     (serve_agent parses ServeApplicationSchema/ServeDeploySchema from request JSON) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["parse_obj", "parse_raw"] and
    func.getObject().(Name).getId().regexpMatch(".*Schema") and
    node = c and
    flowKind = "config" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = "pydantic" and
    matchKind = "ast"
  )
  or
  /* family 6b: builtin open() calls (cluster config files, runtime_env files,
     job package / log / config input) */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    node = c and
    flowKind = "file" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtin" and
    matchKind = "ast"
  )
  or
  /* family 7: internal calls handing external data to handlers / parsers
     (parse_and_validate_request hands the aiohttp job submission body to the job
     pipeline; called by bare name in job_agent.py / job_head.py) */
  exists(Call c |
    calledNameOf(c) = "parse_and_validate_request" and
    node = c and
    flowKind = "internal_transfer" and
    callableName = "parse_and_validate_request" and
    argIndex = 0 and
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
