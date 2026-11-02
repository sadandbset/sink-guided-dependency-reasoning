/**
 * @name maltrail CWE-78 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the maltrail
 *   CodeQL database (snapshot bb4d24b): HTTP request state (request path, POST body,
 *   headers, client address) on the BaseHTTPRequestHandler subclass, urllib query/body
 *   decoding (parse_qs / unquote_plus / unquote), request params dict reads, pcapy packet
 *   reads and struct.unpack decoding, the internal retrieve_content network fetch wrapper,
 *   built-in open()/read() file input, environment / sys.argv / optparse CLI input,
 *   config AttribDict reads, handler entry-point parameters, and internal calls handing
 *   external data to handlers (read_config / log_event / _process_packet / dynamic
 *   getattr dispatch). Raw BQRS extraction query: run with `codeql query run` and decode
 *   with `codeql bqrs decode` (not database analyze). This is a plain multi-column select
 *   query on purpose: @kind problem is the wrong shape for candidate tables and @kind
 *   table is not assumed to exist.
 * @id iris/maltrail/extraction/sources
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
 *                   "http_request" (request state on the HTTP handler),
 *                   "request_param" (decoded request params dict read), "env", "cli",
 *                   "config", "file", "internal_transfer" (call handing external data
 *                   to a handler / parser)
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
 * maltrail imports urllib/BaseHTTPServer through the vendored thirdparty.six.moves
 * compatibility layer, so those boundaries are expected to resolve only at AST level.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for internal
 *  candidates). Top-level scripts that are not on an import path (sensor.py, server.py,
 *  core/update.py) have no dotted module name; their file base name is used instead. */
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

/* ------------------------------------------------------------------ */
/* Source family 1: resolved decode APIs (API graphs)                  */
/* ------------------------------------------------------------------ */

/**
 * External decoding/lookup APIs whose return value may carry attacker-controlled data:
 * json.loads decodes JSON payloads, os.getenv reads the process environment, urllib
 * parse_qs/unquote decode request strings, urllib.request.urlopen returns a remote
 * response. None of the json/os shapes is exercised in this snapshot (maltrail reads
 * the environment through the os.environ attribute family instead) and the urllib
 * shapes only resolve when urllib is imported without the six indirection.
 */
private predicate resolvedDecodeCall(API::CallNode cn, string moduleHint, string member, int argIndex) {
  (
    moduleHint = "json" and member in ["loads", "load"] and argIndex = 0
    or
    moduleHint = "os" and member = "getenv" and argIndex = 0
    or
    moduleHint = "urllib.parse" and member in ["parse_qs", "parse_qsl", "unquote_plus", "unquote"] and argIndex = 0
    or
    moduleHint = "urllib.request" and member = "urlopen" and argIndex = 0
  ) and
  (
    moduleHint != "urllib.parse" and cn = API::moduleImport(moduleHint).getMember(member).getACall()
    or
    moduleHint = "urllib.parse" and
    cn = API::moduleImport("urllib").getMember("parse").getMember(member).getACall()
  )
}

/** The syntactic Call node behind an API graph call node. */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/* ------------------------------------------------------------------ */
/* Source family 2: protocol-shaped AST calls (syntax-level matches)   */
/* ------------------------------------------------------------------ */

/**
 * Internal/protocol input calls matched by AST shape: urllib query/body decoding through
 * the six.moves alias (or plain import), the internal retrieve_content network fetch
 * wrapper, pcapy packet reads, struct.unpack packet decoding, built-in open() and
 * file-like .read() calls, and glob directory reads.
 */
private predicate protocolSourceCall(Call c, string moduleHint, string callableName, int argIndex) {
  /* urllib parse decode: <mod>.parse.parse_qs(...) / unquote_plus(...) / unquote(...)
     (the six.moves alias makes the module name syntactically invisible, so any base name
     before ".parse." is accepted; bare from-imported names are also accepted) */
  moduleHint = "urllib.parse" and
  callableName in ["parse_qs", "parse_qsl", "unquote_plus", "unquote"] and
  argIndex = 0 and
  c.getFunc().(Attribute).getName() = callableName and
  c.getFunc().(Attribute).getObject().(Attribute).getName() = "parse"
  or
  /* bare from-imported urllib.parse decode names */
  moduleHint = "urllib.parse" and
  callableName in ["parse_qs", "parse_qsl", "unquote_plus", "unquote"] and
  argIndex = 0 and
  c.getFunc().(Name).getId() = callableName
  or
  /* urllib request fetch: <mod>.request.urlopen(...) */
  moduleHint = "urllib.request" and
  callableName = "urlopen" and
  argIndex = 0 and
  c.getFunc().(Attribute).getName() = "urlopen" and
  c.getFunc().(Attribute).getObject().(Attribute).getName() = "request"
  or
  /* bare urlopen */
  moduleHint = "urllib.request" and
  callableName = "urlopen" and
  argIndex = 0 and
  c.getFunc().(Name).getId() = "urlopen"
  or
  /* json decode: json.loads(...)/json.load(...) / bare loads(...) (bare "load" is
     too collision-prone for a syntax-level match) */
  moduleHint = "json" and
  argIndex = 0 and
  (
    c.getFunc().(Attribute).getName() = callableName and
    c.getFunc().(Attribute).getObject().(Name).getId() = "json" and
    callableName in ["loads", "load"]
    or
    callableName = "loads" and
    c.getFunc().(Name).getId() = "loads"
  )
  or
  /* os.getenv syntax-level fallback */
  moduleHint = "os" and
  callableName = "getenv" and
  argIndex = 0 and
  c.getFunc().(Attribute).getName() = "getenv" and
  c.getFunc().(Attribute).getObject().(Name).getId() = "os"
  or
  /* struct.unpack: packet header field extraction (buffer is argument 1) */
  moduleHint = "struct" and
  callableName = "unpack" and
  argIndex = 1 and
  c.getFunc().(Attribute).getName() = "unpack" and
  c.getFunc().(Attribute).getObject().(Name).getId() = "struct"
  or
  /* pcapy packet read: <cap>.next() */
  moduleHint = "pcapy" and
  callableName = "next" and
  argIndex = -1 and
  c.getFunc().(Attribute).getName() = "next"
  or
  /* internal network fetch wrapper: retrieve_content(...) (bare or attribute call) */
  moduleHint = "core.common" and
  callableName = "retrieve_content" and
  argIndex = 0 and
  (
    c.getFunc().(Attribute).getName() = "retrieve_content"
    or
    c.getFunc().(Name).getId() = "retrieve_content"
  )
  or
  /* built-in open(): file input (path is argument 0) */
  moduleHint = "builtins" and
  callableName = "open" and
  argIndex = 0 and
  c.getFunc().(Name).getId() = "open"
  or
  /* file-like read: <obj>.read() */
  moduleHint = "file" and
  callableName = "read" and
  argIndex = -1 and
  c.getFunc().(Attribute).getName() = "read"
  or
  /* glob.glob(...) */
  moduleHint = "glob" and
  callableName = "glob" and
  argIndex = 0 and
  c.getFunc().(Attribute).getName() = "glob" and
  c.getFunc().(Attribute).getObject().(Name).getId() = "glob"
}

/* ------------------------------------------------------------------ */
/* Source family 3: handler entry-point functions                      */
/* ------------------------------------------------------------------ */

/**
 * Functions that sit at an external-data boundary: HTTP request handler methods
 * (BaseHTTPRequestHandler subclass ReqHandler and its dynamic "_%s" dispatch targets),
 * the pcapy packet handler and packet processor, event/plugin distribution, the network
 * fetch and config-file readers, and the feed fetch() functions. Protocol-plumbing
 * methods (setup/finish/log_message/...) and dunders are excluded: they only carry
 * already-seen bytes to the wire, not external data in.
 */
private predicate isHandlerFunction(Function f) {
  f.getName() in ["do_GET", "do_POST", "packet_handler", "_process_packet", "plugin",
                  "log_event", "read_config", "retrieve_content", "load_trails",
                  "read_whitelist", "fetch", "main"]
  or
  f.getName().matches("_%") and
  not f.getName().matches("__%") and
  f.getEnclosingScope() instanceof Class
  or
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName().matches("%Handler") and
  not f.getName() in ["setup", "finish", "log_message", "version_string", "end_headers",
                      "server_bind", "finish_request", "shutdown_request", "__init__"]
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
  /* family 2: protocol-shaped input calls
     (self.rfile.read is the HTTP request body; open/read/glob are file input;
     everything else is a decode/network read whose return value is tainted) */
  exists(Call c |
    protocolSourceCall(c, moduleHint, callableName, argIndex) and
    node = c and
    (
      (
        callableName = "read" and
        c.getFunc().(Attribute).getObject().(Attribute).getName() = "rfile" and
        flowKind = "http_request"
      )
      or
      (
        callableName in ["open", "read", "glob"] and
        not (callableName = "read" and c.getFunc().(Attribute).getObject().(Attribute).getName() = "rfile") and
        flowKind = "file"
      )
      or
      (
        not callableName in ["open", "read", "glob"] and
        flowKind = "return"
      )
    ) and
    receiver = receiverHintOfCall(c) and
    matchKind = "ast"
  )
  or
  /* family 3a: request handler state attributes: self.path / self.data /
     self.headers / self.rfile / self.client_address / self.request */
  exists(Attribute a |
    a.getName() in ["path", "data", "headers", "rfile", "client_address", "request"] and
    a.getObject().(Name).getId() = "self" and
    node = a and
    flowKind = "http_request" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "self" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 3b: self.headers.get(...) header read */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    func.getObject().(Attribute).getName() = "headers" and
    func.getObject().(Attribute).getObject().(Name).getId() = "self" and
    node = c and
    flowKind = "http_request" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "self.headers" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3c: self.headers[...] header subscript */
  exists(Subscript s |
    s.getObject().(Attribute).getName() = "headers" and
    s.getObject().(Attribute).getObject().(Name).getId() = "self" and
    node = s and
    flowKind = "http_request" and
    callableName = "headers" and
    argIndex = -1 and
    receiver = "self.headers" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 3d: params.get('key') / params.pop('key') on the decoded request dict */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["get", "pop"] and
    func.getObject().(Name).getId() = "params" and
    node = c and
    flowKind = "request_param" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "params" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3e: params['key'] subscript on the decoded request dict */
  exists(Subscript s |
    s.getObject().(Name).getId() = "params" and
    node = s and
    flowKind = "request_param" and
    callableName = "params" and
    argIndex = -1 and
    receiver = "params" and
    moduleHint = moduleHintOf(s) and
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
  /* family 4b: os.environ.get(...) read */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    func.getObject().(Attribute).getName() = "environ" and
    func.getObject().(Attribute).getObject().(Name).getId() = "os" and
    node = c and
    flowKind = "env" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 4c: sys.argv read */
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
  /* family 4d: optparse registration and parsing */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["add_option", "parse_args", "parse_known_args"] and
    node = c and
    flowKind = "cli" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = "optparse" and
    matchKind = "ast"
  )
  or
  /* family 4e: CLI option loads: options.<name> */
  exists(Attribute a |
    a.getObject().(Name).getId() = "options" and
    node = a and
    flowKind = "cli" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "options" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 4f: getattr(options, ...) CLI option copy into config */
  exists(Call c |
    c.getFunc().(Name).getId() = "getattr" and
    c.getPositionalArg(0).(Name).getId() = "options" and
    node = c and
    flowKind = "cli" and
    callableName = "getattr" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 5a: config AttribDict reads: config.<NAME> */
  exists(Attribute a |
    a.getObject().(Name).getId() = "config" and
    node = a and
    flowKind = "config" and
    callableName = a.getName() and
    argIndex = -1 and
    receiver = "config" and
    moduleHint = "core.settings" and
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
  /* family 7: internal calls handing external data to handlers / parsers
     (read_config takes the config path, retrieve_content the URL, log_event the
     packet-derived event tuple, _process_packet the raw packet bytes; all of them
     are called by bare name in this codebase, attribute calls are accepted too) */
  exists(Call c |
    (
      c.getFunc().(Attribute).getName() in ["read_config", "retrieve_content", "log_event", "_process_packet"]
      or
      c.getFunc().(Name).getId() in ["read_config", "retrieve_content", "log_event", "_process_packet"]
    ) and
    node = c and
    flowKind = "internal_transfer" and
    callableName = calledNameOf(c) and
    argIndex = 0 and
    matchKind = "ast" and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c)
  )
  or
  /* family 8: dynamic handler dispatch: <outer>(...) whose callee is a getattr(...) call,
     e.g. getattr(self, "_%s" % path)(params) in core/httpd.py:147 - request path selects
     the handler method and the decoded params are handed over as argument 0 */
  exists(Call c, Call inner |
    inner = c.getFunc().(Call) and
    inner.getFunc().(Name).getId() = "getattr" and
    node = c and
    flowKind = "internal_transfer" and
    callableName = "getattr_dispatch" and
    argIndex = 0 and
    receiver = "getattr" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
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
