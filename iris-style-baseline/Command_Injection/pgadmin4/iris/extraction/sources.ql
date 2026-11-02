/**
 * @name pgadmin4 CWE-78 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the pgadmin4
 *   CodeQL database (snapshot 61fa8b1): Flask request state (request.data / form / args /
 *   json / values / files / cookies / headers / environ / get_json, plus the observed
 *   alias spellings 'req' and 'request_object'), request field subscripts and .get()
 *   reads, JSON body decoding (json.loads / json.load), Flask-SocketIO '/pty' handler
 *   parameters (@sio.on), Flask route handler parameters (@blueprint.route URL path
 *   params), environment reads (os.environ[...] / os.environ.get / os.getenv), CLI input
 *   (sys.argv, argparse registration and parse calls), config module reads (config.<NAME>),
 *   and internal calls handing external data toward command-execution plumbing
 *   (set_binary_path / replace_binary_path / get_connection_str). Raw BQRS extraction
 *   query: run with `codeql query run` and decode with `codeql bqrs decode`
 *   (not database analyze). This is a plain multi-column select query on purpose:
 *   @kind problem is the wrong shape for candidate tables and @kind table is not
 *   assumed to exist.
 * @id iris/pgadmin4/extraction/sources
 * @tags command-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable name (API member name, function name, or attribute name)
 *   4. flow_kind  - "return" (tainted return value of a decode API),
 *                   "http_request" (Flask request proxy state read),
 *                   "request_param" (request field subscript or .get() read),
 *                   "param" (route / socket handler parameter),
 *                   "env" (environment read), "cli" (argv / argparse input),
 *                   "config" (config module read),
 *                   "internal_transfer" (call handing external data toward exec plumbing)
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
 * The Flask request object is a runtime local proxy, so request.<field> reads only match
 * at AST level; the observed request-object spellings are request, req (file_manager's
 * 'request as req' import) and request_object (browser get_delete_data helper parameter).
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for internal
 *  candidates). Top-level scripts that are not on an import path (pgAdmin4.py,
 *  setup.py) have no dotted module name; their file base name is used instead. */
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

/** Holds if n sits in a file excluded from candidate extraction: the web/regression
 *  feature-test harness, any per-module tests/ directory, or the repo-root tools/
 *  dev scripts. Both path separators are matched. */
predicate excludedLocation(AstNode n) {
  exists(string p |
    p = n.getLocation().getFile().getAbsolutePath() and
    (
      p.matches("%/regression/%") or
      p.matches("%\\regression\\%") or
      p.matches("%/tests/%") or
      p.matches("%\\tests\\%") or
      p.matches("%\\pgadmin4_vuln\\tools\\%") or
      p.matches("%/pgadmin4_vuln/tools/%")
    )
  )
}

/** Observed spellings of the Flask request object: 'request' (from flask import request),
 *  'req' (from flask import request as req, misc/file_manager) and 'request_object'
 *  (parameter convention of the browser get_delete_data helpers). */
predicate requestObjectName(Name name) {
  name.getId() in ["request", "req", "request_object"]
}

/* ------------------------------------------------------------------ */
/* Source family 1: resolved decode APIs (API graphs)                  */
/* ------------------------------------------------------------------ */

/**
 * External decoding APIs whose return value may carry attacker-controlled data:
 * json.loads decodes request bodies (json.loads(request.data) is the pgadmin4 idiom),
 * os.getenv reads the process environment. These modules are imported by real module
 * name throughout web/pgadmin, so API-graph resolution is expected to work.
 */
private predicate resolvedDecodeCall(API::CallNode cn, string moduleHint, string member, int argIndex) {
  (
    moduleHint = "json" and member in ["loads", "load"] and argIndex = 0
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
/* Source family 2: Flask request state and field reads (AST shapes)   */
/* ------------------------------------------------------------------ */

/** Request proxy state attributes read in pgadmin4 handlers. */
private predicate requestStateName(string name) {
  name in ["data", "form", "args", "json", "values", "files", "cookies",
           "headers", "environ"]
}

/* ------------------------------------------------------------------ */
/* Source family 3: handler entry-point functions                      */
/* ------------------------------------------------------------------ */

/**
 * Handler boundary detection (decorator shapes):
 *   - Flask-SocketIO event handlers: a decorator Call '<x>.on(event, namespace=...)'
 *     (web/pgadmin/tools/psql/__init__.py @sio.on(..., namespace='/pty'))
 *   - Flask route handlers: a decorator Call '<blueprint>.route(rule, ...)'
 *     (269 sites across web/pgadmin/**)
 * Both shapes are matched syntactically; the flask/SocketIO layers are runtime
 * frameworks, so no resolved-binding claim is made (match_kind stays "ast").
 */
private predicate hasHandlerDecorator(Function f, string kind) {
  exists(Call dec |
    dec = f.getADecorator() and
    dec.getFunc() instanceof Attribute and
    (
      kind = "socket_handler" and
      dec.getFunc().(Attribute).getName() = "on" and
      dec.getFunc().(Attribute).getObject() instanceof Name
      or
      kind = "route_handler" and
      dec.getFunc().(Attribute).getName() = "route" and
      dec.getFunc().(Attribute).getObject() instanceof Name
    )
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
    not excludedLocation(astCallOf(cn)) and
    node = astCallOf(cn) and
    flowKind = "return" and
    receiver = "" and
    matchKind = "api"
  )
  or
  /* family 2: Flask request proxy state attribute reads
     (request.data / form / args / json / values / files / cookies / headers / environ,
      plus the req and request_object alias spellings) */
  exists(Attribute a |
    requestStateName(a.getName()) and
    requestObjectName(a.getObject().(Name)) and
    not excludedLocation(a) and
    node = a and
    flowKind = "http_request" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = a.getObject().(Name).getId() and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  /* family 2b: request.get_json(...) call */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get_json" and
    requestObjectName(func.getObject().(Name)) and
    not excludedLocation(c) and
    node = c and
    flowKind = "http_request" and
    callableName = "get_json" and
    argIndex = -1 and
    receiver = func.getObject().(Name).getId() and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  /* family 2c: request field subscript - request.form['data'], request.args['sid'],
     request_object.data[...] style reads */
  exists(Subscript s |
    requestStateName(s.getObject().(Attribute).getName()) and
    requestObjectName(s.getObject().(Attribute).getObject().(Name)) and
    not excludedLocation(s) and
    node = s and
    flowKind = "request_param" and
    callableName = s.getObject().(Attribute).getName() and
    argIndex = -1 and
    receiver = s.getObject().(Attribute).getObject().(Name).getId() +
               "." + s.getObject().(Attribute).getName() and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  /* family 2d: request field .get(...) / .getlist(...) call -
     request.args.get('sid'), req.form.get('currentpath') style reads */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["get", "getlist"] and
    requestStateName(func.getObject().(Attribute).getName()) and
    requestObjectName(func.getObject().(Attribute).getObject().(Name)) and
    not excludedLocation(c) and
    node = c and
    flowKind = "request_param" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = func.getObject().(Attribute).getObject().(Name).getId() +
               "." + func.getObject().(Attribute).getName() and
    moduleHint = "flask.request" and
    matchKind = "ast"
  )
  or
  /* family 2e: json decode at AST level - json.loads(...) / json.load(...) and the
     bare from-imported name 'loads' (bare 'load' is too collision-prone). This is the
     pgadmin4 body-decoding idiom: json.loads(request.data) / json.loads(request.form['data']) */
  exists(Call c |
    not excludedLocation(c) and
    (
      c.getFunc().(Attribute).getName() in ["loads", "load"] and
      c.getFunc().(Attribute).getObject().(Name).getId() = "json"
      or
      c.getFunc().(Name).getId() = "loads"
    ) and
    node = c and
    flowKind = "return" and
    callableName = calledNameOf(c) and
    argIndex = 0 and
    receiver = "json" and
    moduleHint = "json" and
    matchKind = "ast"
  )
  or
  /* family 3a: Flask-SocketIO event handler parameters (@sio.on(...)) - the socket
     message body (start_process(data), socket_input(data), resize(data), ...) */
  exists(Function f, Parameter p |
    hasHandlerDecorator(f, "socket_handler") and
    p = f.getAnArg() and
    not p.isSelf() and
    not excludedLocation(f) and
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
  /* family 3b: Flask route handler parameters (@blueprint.route(...)) - URL path
     parameters (trans_id, sid, did, ...) are externally supplied values */
  exists(Function f, Parameter p |
    hasHandlerDecorator(f, "route_handler") and
    p = f.getAnArg() and
    not p.isSelf() and
    not excludedLocation(f) and
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
  /* family 4a: os.environ[...] subscript read (includes json.loads(os.environ[user])
     in the psql socket server and the PROCID->PGPASSWORD plumbing) */
  exists(Subscript s |
    s.getObject().(Attribute).getName() = "environ" and
    s.getObject().(Attribute).getObject().(Name).getId() = "os" and
    not excludedLocation(s) and
    node = s and
    flowKind = "env" and
    callableName = "environ" and
    argIndex = -1 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 4b: os.environ.get(...) read */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    func.getObject().(Attribute).getName() = "environ" and
    func.getObject().(Attribute).getObject().(Name).getId() = "os" and
    not excludedLocation(c) and
    node = c and
    flowKind = "env" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 4c: os.getenv(...) AST fallback (bare from-imported name) */
  exists(Call c |
    c.getFunc().(Name).getId() = "getenv" and
    not excludedLocation(c) and
    node = c and
    flowKind = "env" and
    callableName = "getenv" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "<unresolved>" and
    matchKind = "ast"
  )
  or
  /* family 4d: sys.argv read */
  exists(Attribute a |
    a.getName() = "argv" and
    a.getObject().(Name).getId() = "sys" and
    not excludedLocation(a) and
    node = a and
    flowKind = "cli" and
    callableName = "argv" and
    argIndex = -1 and
    receiver = "sys" and
    moduleHint = "sys" and
    matchKind = "ast"
  )
  or
  /* family 4e: argparse registration and parsing
     (ArgumentParser(...) construction, add_argument(...), parse_args(...),
     parse_known_args(...)) - web/setup.py and web/pgacloud/pgacloud.py CLIs */
  exists(Call c |
    (
      c.getFunc().(Name).getId() = "ArgumentParser"
      or
      c.getFunc().(Attribute).getName() = "ArgumentParser" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "argparse"
      or
      c.getFunc().(Attribute).getName() in ["add_argument", "parse_args",
                                            "parse_known_args", "add_argument_group"]
    ) and
    not excludedLocation(c) and
    node = c and
    flowKind = "cli" and
    callableName = calledNameOf(c) and
    argIndex = 0 and
    matchKind = "ast" and
    moduleHint = "argparse" and
    receiver = receiverHintOfCall(c)
  )
  or
  /* family 5: config module reads - config.<NAME> (web/config.py local settings,
     including PGADMIN_CONFIG_* environment overrides applied at config.py:913 and
     MASTER_PASSWORD_HOOK consumed by the master-password exec hook) */
  exists(Attribute a |
    a.getObject().(Name).getId() = "config" and
    not a.getName() in ["environ"] and
    not excludedLocation(a) and
    node = a and
    flowKind = "config" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "config" and
    moduleHint = "config" and
    matchKind = "ast"
  )
  or
  /* family 6: internal calls handing external data toward command-execution plumbing:
     set_binary_path / replace_binary_path (binary path from the validate_binary_path
     request and preferences), get_connection_str (psql argv construction for the
     Popen at psql/__init__.py:182). Called bare or as attribute calls. */
  exists(Call c |
    (
      c.getFunc().(Attribute).getName() in ["set_binary_path", "replace_binary_path",
                                            "get_connection_str"]
      or
      c.getFunc().(Name).getId() in ["set_binary_path", "replace_binary_path",
                                     "get_connection_str"]
    ) and
    not excludedLocation(c) and
    node = c and
    flowKind = "internal_transfer" and
    callableName = calledNameOf(c) and
    argIndex = 0 and
    matchKind = "ast" and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c)
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind)
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
