/**
 * @name mlflow CWE-78 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the mlflow CodeQL
 *   database (snapshot 330bf0b, MLflow 2.5.1.dev0): Flask request reads (tracking server
 *   REST handlers and pyfunc scoring server), click CLI arguments/options and the parameters
 *   of the decorated CLI functions, JSON/YAML decoding (request bodies, MLmodel, MLproject,
 *   gateway config, conda envs), environment variables (os.environ/os.getenv and the
 *   MLFLOW_* environment-variable registry), config/file loads (Model.load, load_project,
 *   open), handler entry-point parameters, and internal input-wrapper calls
 *   (_get_request_message, _get_request_json, parse_csv_input, parse_json_input).
 *   Raw BQRS extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain multi-column select query
 *   on purpose: @kind problem is the wrong shape for candidate tables and @kind table is
 *   not assumed to exist.
 * @id iris/mlflow/extraction/sources
 * @tags command-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable name (API member name, function name, or attribute name)
 *   4. flow_kind  - "return" (tainted return value), "http" (flask request read), "param"
 *                   (handler/CLI function parameter), "env", "cli" (click decorator /
 *                   sys.argv), "config" (config loader call), "file" (open call),
 *                   "internal_transfer" (call handing external data to a wrapper)
 *   5. receiver   - syntactic receiver hint (base name of the object expression, "" if none)
 *   6. moduleHint - module hint: external module name, or dotted python module path for
 *                   internal candidates (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index (parameter position in the function
 *                   definition for "param" rows, key position for field reads), -1 if N/A
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

/* ------------------------------------------------------------------ */
/* Source family 1: resolved decode APIs (API graphs)                  */
/* ------------------------------------------------------------------ */

/**
 * External decoding/lookup APIs whose return value may carry attacker-controlled data:
 * json.loads/load decodes HTTP bodies and payloads, yaml.safe_load/yaml.load decodes
 * MLmodel / MLproject / conda env / gateway config files, os.getenv reads the process
 * environment (all three are heavily used in this snapshot).
 */
private predicate resolvedDecodeCall(API::CallNode cn, string moduleHint, string member, int argIndex) {
  (
    moduleHint = "json" and member in ["loads", "load"] and argIndex = 0
    or
    moduleHint = "yaml" and member in ["safe_load", "load"] and argIndex = 0
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
/* Source family 2: HTTP-shaped AST reads (flask request proxy)        */
/* ------------------------------------------------------------------ */

/** Flask request proxy attributes that carry request data. */
private predicate flaskRequestAttribute(string name) {
  name in ["args", "query_string", "form", "values", "files", "data", "json",
           "stream", "headers", "cookies", "method", "content_type", "url",
           "url_rule", "remote_addr", "full_path"]
}

/**
 * Holds if a is an attribute read on a flask request proxy: `request.<attr>`,
 * `flask_request.<attr>` or `flask.request.<attr>`.
 */
private predicate flaskRequestAttr(Attribute a) {
  flaskRequestAttribute(a.getName()) and
  (
    a.getObject().(Name).getId() in ["request", "flask_request"]
    or
    a.getObject().(Attribute).getName() = "request"
  )
}

/**
 * Calls reading request fields: `request.get_json(...)`, `request.get_data(...)`,
 * and `<requestattr>.get/getlist/to_dict/pop(...)` such as request.args.get(...)
 * or request.headers.get(...).
 */
private predicate flaskRequestCall(Call c, string callableName) {
  exists(Attribute func |
    func = c.getFunc().(Attribute) and
    callableName = func.getName() and
    (
      /* request.get_json(...) / request.get_data(...) directly on the proxy */
      func.getName() in ["get_json", "get_data"] and
      (
        func.getObject().(Name).getId() in ["request", "flask_request"]
        or
        func.getObject().(Attribute).getName() = "request"
      )
      or
      /* request.<attr>.get(...) / .getlist(...) / .to_dict(...) / .pop(...) */
      func.getName() in ["get", "getlist", "to_dict", "pop"] and
      flaskRequestAttr(func.getObject().(Attribute))
    )
  )
}

/* ------------------------------------------------------------------ */
/* Source family 3: click CLI shapes and handler functions             */
/* ------------------------------------------------------------------ */

/** click decorators that attach arguments/options to CLI commands or define commands. */
private predicate clickDecoratorCall(Call c) {
  exists(Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["argument", "option", "command", "group", "version_option",
                       "password_option", "confirmation_option", "help_option"] and
    receiverHint(func) in ["click", "cli", "deployment_group", "gateway_cli"]
  )
}

/** Functions whose decorators make them CLI entry points or attach CLI arguments (click). */
private predicate clickBoundFunction(Function f) {
  exists(Expr d |
    d = f.getADecorator() and
    (
      d instanceof Call and clickDecoratorCall(d.(Call))
      or
      /* @cli.command / @click.command without parentheses */
      d.(Attribute).getName() in ["command", "group"] and
      receiverHint(d.(Attribute)) in ["click", "cli", "deployment_group", "gateway_cli"]
    )
  )
}

/** f is an HTTP handler: decorated with a route decorator or @catch_mlflow_exception. */
private predicate isHandlerFunction(Function f) {
  exists(Expr d |
    d = f.getADecorator() and
    (
      /* @app.route(...) / @<blueprint>.route(...) / fastapi @app.get/post(...) */
      d.(Call).getFunc().(Attribute).getName() in
        ["route", "get", "post", "put", "delete", "patch"]
      or
      /* mlflow/server/handlers.py endpoint wrappers */
      d.(Name).getId() = "catch_mlflow_exception"
      or
      d.(Call).getFunc().(Name).getId() = "catch_mlflow_exception"
    )
  )
  or
  /* pyfunc scoring-server handler functions (nested in the flask app factory) */
  f.getName() in ["invocations", "ping"]
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
  /* family 2a: syntax-level fallback of the decode APIs (module-qualified attribute calls) */
  exists(Call c |
    argIndex = 0 and
    (
      moduleHint = "json" and callableName in ["loads", "load"]
      or
      moduleHint = "yaml" and callableName in ["safe_load", "load"]
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
  /* family 2b: flask request proxy attribute reads (request.args, flask.request.data, ...) */
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
  /* family 2c: flask request field reads (request.get_json, request.args.get, ...) */
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
  /* family 3a: click decorator calls (argument/option/command registration) */
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
  /* family 3b: parameters of click-bound CLI functions (mlflow run <uri>, deployments, ...) */
  exists(Function f, Parameter p |
    clickBoundFunction(f) and
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
  /* family 4c: MLFLOW_* environment-variable registry reads
     (e.g. MLFLOW_WHEELED_MODEL_PIP_DOWNLOAD_OPTIONS.get() / .get_raw() / .is_defined) */
  exists(Attribute a |
    a.getName() in ["get", "get_raw", "is_defined"] and
    a.getObject().(Name).getId().regexpMatch("MLFLOW_.*") and
    node = a and
    flowKind = "env" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = a.getObject().(Name).getId() and
    moduleHint = "mlflow.environment_variables" and
    matchKind = "ast"
  )
  or
  /* family 4d: sys.argv read */
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
  /* family 5a: model/config loader calls (Model.load, load_project) */
  exists(Call c |
    (
      /* Model.load(path) */
      c.getFunc().(Attribute).getName() = "load" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "Model" and
      moduleHint = "mlflow.models.model" and
      callableName = "load"
      or
      /* load_project(directory) */
      c.getFunc().(Name).getId() = "load_project" and
      moduleHint = "mlflow.projects._project_spec" and
      callableName = "load_project"
    ) and
    argIndex = 0 and
    node = c and
    flowKind = "config" and
    receiver = receiverHintOfCall(c) and
    matchKind = "ast"
  )
  or
  /* family 5b: builtin open() calls (config/model/project/artifact file input) */
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
  /* family 6: parameters of HTTP handler functions (route-decorated /
     catch_mlflow_exception-wrapped / scoring-server handlers) */
  exists(Function f, Parameter p |
    isHandlerFunction(f) and
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
  /* family 7: internal input-wrapper calls handing external data to decoding logic */
  exists(Call c |
    calledNameOf(c) in ["_get_request_message", "_get_request_json",
                        "parse_csv_input", "parse_json_input"] and
    node = c and
    flowKind = "internal_transfer" and
    callableName = calledNameOf(c) and
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
