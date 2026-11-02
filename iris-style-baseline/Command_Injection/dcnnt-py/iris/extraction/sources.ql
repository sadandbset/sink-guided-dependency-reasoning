/**
 * @name dcnnt-py CWE-78 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the dcnnt-py CodeQL
 *   database (snapshot 4084ea1): socket receives, AES-decrypted message bodies, JSON/JSON-RPC
 *   decoding, UDP request unpacking, request.params field reads, handler entry-point
 *   parameters, internal message-transfer calls, and environment/CLI/config reads. Raw BQRS
 *   extraction query: run with `codeql query run` and decode with `codeql bqrs decode`
 *   (not database analyze). This is a plain multi-column select query on purpose: @kind
 *   problem is the wrong shape for candidate tables and @kind table is not assumed to exist.
 * @id iris/dcnnt-py/extraction/sources
 * @tags command-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable name (API member name, function name, or attribute name)
 *   4. flow_kind  - "return" (tainted return value), "param" (handler parameter),
 *                   "request_param" (request field read), "env", "cli", "config",
 *                   "internal_transfer" (call handing external data to a handler)
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

/* ------------------------------------------------------------------ */
/* Source family 1: resolved decode APIs (API graphs)                  */
/* ------------------------------------------------------------------ */

/**
 * External decoding/lookup APIs whose return value may carry attacker-controlled data.
 * json.loads decodes protocol payloads; base64.b64decode decodes pairing data; os.getenv
 * reads the process environment (none in this repo - predicate simply stays empty there).
 */
private predicate resolvedDecodeCall(API::CallNode cn, string moduleHint, string member, int argIndex) {
  (
    moduleHint = "json" and member in ["loads", "load"] and argIndex = 0
    or
    moduleHint = "base64" and member in ["b64decode", "b64encode"] and argIndex = 0
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
/* Source family 2: protocol-shaped AST calls (syntax-level matches)   */
/* ------------------------------------------------------------------ */

/**
 * Internal/protocol input calls matched by AST shape: socket receives, dcnnt.common decrypt,
 * JSON-RPC object factories, the UDP request unpacker, plugin message readers, and the
 * syntax-level fallback of the resolved decode APIs above.
 */
private predicate protocolSourceCall(Call c, string moduleHint, string callableName, int argIndex) {
  /* socket receive: <obj>.recv(n) / recvfrom / recv_into / recvfrom_into */
  moduleHint = "socket" and
  callableName in ["recv", "recvfrom", "recv_into", "recvfrom_into"] and
  argIndex = 0 and
  c.getFunc().(Attribute).getName() = callableName
  or
  /* AES-GCM decrypt from dcnnt.common (bare name import or attribute call) */
  moduleHint = "dcnnt.common" and
  callableName = "decrypt" and
  argIndex = 0 and
  (
    c.getFunc().(Attribute).getName() = "decrypt"
    or
    c.getFunc().(Name).getId() = "decrypt"
  )
  or
  /* JSON-RPC 2.0 object factory: RPCRequest/RPCResponse/RPCError.from_dict */
  moduleHint = "dcnnt.common.jsonrpc" and
  callableName = "from_dict" and
  argIndex = 0 and
  c.getFunc().(Attribute).getName() = "from_dict"
  or
  /* UDP server-search request unpacker */
  moduleHint = "dcnnt.server_search" and
  callableName = "unpack_raw_request" and
  argIndex = 0 and
  (
    c.getFunc().(Attribute).getName() = "unpack_raw_request"
    or
    c.getFunc().(Name).getId() = "unpack_raw_request"
  )
  or
  /* plugin message readers: self.rpc_read() / self.read() */
  moduleHint = "dcnnt.plugins.base" and
  argIndex = -1 and
  (
    callableName = "rpc_read" and c.getFunc().(Attribute).getName() = "rpc_read"
    or
    callableName = "read" and
    c.getFunc().(Attribute).getName() = "read" and
    c.getFunc().(Attribute).getObject().(Name).getId() = "self"
  )
  or
  /* syntax-level fallback of family 1: json.loads / base64.b64decode / os.getenv by prefix */
  argIndex = 0 and
  (
    moduleHint = "json" and callableName in ["loads", "load"]
    or
    moduleHint = "base64" and callableName in ["b64decode", "b64encode"]
    or
    moduleHint = "os" and callableName = "getenv"
  ) and
  c.getFunc().(Attribute).getName() = callableName and
  c.getFunc().(Attribute).getObject().(Name).getId() = moduleHint
}

/* ------------------------------------------------------------------ */
/* Source family 3: handler entry-point functions                      */
/* ------------------------------------------------------------------ */

/**
 * Functions that sit at an external-data boundary: TCP/UDP request handlers (BaseRequestHandler
 * subclasses), plugin request handlers, dispatchers and message receivers. The logging helper
 * method `log` is excluded (pure logging, not an input boundary).
 */
private predicate isHandlerFunction(Function f) {
  not f.getName() = "log" and
  (
    f.getName() = "handle"
  or
    f.getName() = "main"
  or
    f.getName() = "process_request"
  or
    f.getName() = "dispatch"
  or
    f.getName() = "recv"
  or
    f.getName() = "read"
  or
    f.getName() = "rpc_read"
  or
    f.getName() = "unpack_raw_request"
  or
    f.getName() = "receive_file"
  or
    f.getName() = "receive_file_to_path"
  or
    f.getName().matches("handle%")
  or
    (
      f.getEnclosingScope() instanceof Class and
      (
        f.getEnclosingScope().(Class).getName().matches("%Handler")
        or
        f.getEnclosingScope().(Class).getName().matches("%Plugin")
      )
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
    node = astCallOf(cn) and
    flowKind = "return" and
    receiver = "" and
    matchKind = "api"
  )
  or
  /* family 2: protocol-shaped input calls */
  exists(Call c |
    protocolSourceCall(c, moduleHint, callableName, argIndex) and
    node = c and
    flowKind = "return" and
    receiver = receiverHintOfCall(c) and
    matchKind = "ast"
  )
  or
  /* family 3a: request.params['key'] */
  exists(Subscript s, Attribute a |
    a = s.getObject().(Attribute) and
    a.getName() = "params" and
    node = s and
    flowKind = "request_param" and
    callableName = "params" and
    argIndex = -1 and
    receiver = receiverHint(a) and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 3b: request.params.get('key') / request.params.pop('key') */
  exists(Call c, Attribute func, Attribute obj |
    func = c.getFunc().(Attribute) and
    func.getName() in ["get", "pop"] and
    obj = func.getObject().(Attribute) and
    obj.getName() = "params" and
    node = c and
    flowKind = "request_param" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = receiverHint(obj) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3c: .get()/.pop() on the decoded UDP JSON request dict */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["get", "pop"] and
    func.getObject().(Name).getId() = "request" and
    node = c and
    flowKind = "request_param" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "request" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3d: bare request.params attribute load (excluding subscript/attribute parents) */
  exists(Attribute a |
    a.getName() = "params" and
    a.getObject().(Name).getId() = "request" and
    not a.getParentNode() instanceof Subscript and
    not a.getParentNode() instanceof Attribute and
    node = a and
    flowKind = "request_param" and
    callableName = "params" and
    argIndex = -1 and
    receiver = "request" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 4a: os.environ read */
  exists(Attribute a |
    a.getName() = "environ" and
    a.getObject().(Name).getId() = "os" and
    node = a and
    flowKind = "env" and
    callableName = "environ" and
    argIndex = -1 and
    receiver = "os" and
    moduleHint = "os" and
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
  /* family 4c: argparse registration and parsing */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["add_argument", "parse_args", "parse_known_args"] and
    node = c and
    flowKind = "cli" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = "argparse" and
    matchKind = "ast"
  )
  or
  /* family 5a: plugin config read via self.conf(...) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "conf" and
    func.getObject().(Name).getId() = "self" and
    node = c and
    flowKind = "config" and
    callableName = "conf" and
    argIndex = 0 and
    receiver = "self" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 5b: JSON config file loader constructor (path is argument 1) */
  exists(Call c |
    c.getFunc().(Name).getId() = "ConfigLoader" and
    node = c and
    flowKind = "config" and
    callableName = "ConfigLoader" and
    argIndex = 1 and
    receiver = "" and
    moduleHint = "dcnnt.common.jsonconf" and
    matchKind = "ast"
  )
  or
  /* family 6: parameters of handler entry-point functions
     (arg_index is the 0-based position in the function definition; self is excluded) */
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
  /* family 7: internal calls handing external data to handlers / plugins
     (plugin(...).main() passes the handler via the receiver, hence arg_index -1) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (
      func.getName() in ["process_request", "rpc_read", "receive_file",
                         "receive_file_to_path", "dispatch"]
      or
      func.getName() = "main"
    ) and
    node = c and
    flowKind = "internal_transfer" and
    callableName = func.getName() and
    (
      (func.getName() = "main" and argIndex = -1)
      or
      (func.getName() != "main" and argIndex = 0)
    ) and
    matchKind = "ast" and
    receiver = receiverHint(func) and
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
