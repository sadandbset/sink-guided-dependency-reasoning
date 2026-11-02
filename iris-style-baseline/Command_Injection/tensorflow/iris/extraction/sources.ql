/**
 * @name tensorflow CWE-78 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the tensorflow
 *   CodeQL database (snapshot 349172cf, tensorflow_vuln tree): tfdbg gRPC debug-server
 *   receive methods and their stream-handler callbacks (SendEvents/SendTracebacks/
 *   SendSourceFiles, on_value_event/on_graph_def/on_core_metadata_event parameters),
 *   JSON decoding (json.loads/load including the TF_CONFIG environment specs, debug-event
 *   plugin metadata, SavedModel/keras/tflite configs, HTTP response bodies), environment
 *   variable reads (os.environ/os.environ.get/os.getenv with os/_os aliases), CLI input
 *   (argparse add_argument/parse_args/parse_known_args, sys.argv reads, six.moves.input
 *   and raw input() prompts, the tfdbg readline command loop), file and model input
 *   (builtin open() and gfile.Open/GFile), proto wire decoding (ParseFromString,
 *   including the reassembled network GraphDef chunks), network fetches (urlopen), and
 *   internal calls that hand received data to business handlers (the tfdbg
 *   stream_handler.on_* dispatch sites).
 *   Raw BQRS extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain multi-column select query
 *   on purpose: @kind problem is the wrong shape for candidate tables and @kind table is
 *   not assumed to exist.
 * @id iris/tensorflow/extraction/sources
 * @tags command-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable name (API member name, function/method name, or attribute name)
 *   4. flow_kind  - "return" (tainted return value: json decode), "network" (grpc receive
 *                   method parameters, urlopen returns), "env", "cli" (argparse, sys.argv,
 *                   input prompts), "file" (open/gfile input), "proto_decode"
 *                   (ParseFromString), "internal_transfer" (call handing received data to
 *                   a handler), "param" (receive-callback method parameters)
 *   5. receiver   - syntactic receiver hint (base name of the object expression, "" if none)
 *   6. moduleHint - module hint: external module name, or dotted python module path for
 *                   internal candidates (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index (parameter position in the function
 *                   definition for parameter rows), -1 if N/A
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath(); AstNode.getFile()
 *                    does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast" (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates), avoids assigning API::Node
 * values to DataFlow::Node variables, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced a row).
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

/**
 * Holds if n sits inside a test file or test harness: any path under a tests/, test/ or
 * testing/ directory (bazel test infra and tflite test harnesses), conftest.py, or a
 * *_test.py / *_test_base.py basename.
 */
predicate isTestLocation(AstNode n) {
  n.getLocation().getFile().getAbsolutePath().matches("%/tests/%")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%\\tests\\%")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%/test/%")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%\\test\\%")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%/testing/%")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%\\testing\\%")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%/conftest.py")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%\\conftest.py")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%_test.py")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%\\_test.py")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%_test_base.py")
  or
  n.getLocation().getFile().getAbsolutePath().matches("%\\_test_base.py")
}

/* ------------------------------------------------------------------ */
/* Source family 1: resolved decode/lookup APIs (API graphs)           */
/* ------------------------------------------------------------------ */

/**
 * External decoding/lookup APIs whose return value may carry attacker-controlled data:
 * json.loads/load decodes debug-event metadata, TF_CONFIG environment JSON and
 * model/config files (also reached via the `import json as _json` alias in
 * lite/python/op_hint.py); os.getenv reads the process environment (both are heavily
 * used in this snapshot).
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
/* Source family 2: syntax-level decode and environment shapes         */
/* ------------------------------------------------------------------ */

/** json module aliases observed in this tree (import json / import json as _json / json_lib). */
private predicate jsonModuleName(string name) { name in ["json", "_json", "json_lib"] }

/** os module aliases observed in this tree (import os / import os as _os). */
private predicate osModuleName(string name) { name in ["os", "_os"] }

/** urlopen receiver prefixes observed in this tree (six.moves.urllib.request, urllib.request). */
private predicate urllibReceiver(string name) { name in ["request", "urllib", "_urllib"] }

/**
 * Holds if f is an attribute-based network receive callback or gRPC service method of
 * the tfdbg debug server (the unauthenticated grpc.server listener in grpc_debug_server.py).
 */
private predicate debugReceiveMethodName(string name) {
  name in ["SendEvents", "SendTracebacks", "SendSourceFiles",
           "on_value_event", "on_graph_def", "on_core_metadata_event"]
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
  /* family 2a: syntax-level fallback of the decode APIs (module-qualified attribute
     calls, including the _json/json_lib and _os aliases; moduleHint stays canonical) */
  exists(Call c, string modName |
    argIndex = 0 and
    (
      callableName in ["loads", "load"] and
      jsonModuleName(modName) and
      moduleHint = "json"
      or
      callableName = "getenv" and
      osModuleName(modName) and
      moduleHint = "os"
    ) and
    c.getFunc().(Attribute).getName() = callableName and
    c.getFunc().(Attribute).getObject().(Name).getId() = modName and
    node = c and
    flowKind = "return" and
    receiver = modName and
    matchKind = "ast"
  )
  or
  /* family 2b: os.environ attribute read (subscripts and .get read this attribute) */
  exists(Attribute a |
    a.getName() = "environ" and
    osModuleName(a.getObject().(Name).getId()) and
    not a.getParentNode() instanceof Attribute and
    node = a and
    flowKind = "env" and
    callableName = "environ" and
    argIndex = -1 and
    receiver = a.getObject().(Name).getId() and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 2c: os.environ.get(...) / os.environ.pop(...) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["get", "pop"] and
    func.getObject().(Attribute).getName() = "environ" and
    osModuleName(func.getObject().(Attribute).getObject().(Name).getId()) and
    node = c and
    flowKind = "env" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = "environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 3a: sys.argv read */
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
  /* family 3b: argparse argument declarations (parser.add_argument(...)) */
  exists(Call c |
    c.getFunc().(Attribute).getName() = "add_argument" and
    node = c and
    flowKind = "cli" and
    callableName = "add_argument" and
    argIndex = 0 and
    receiver = receiverHintOfCall(c) and
    moduleHint = "argparse" and
    matchKind = "ast"
  )
  or
  /* family 3c: parsed CLI values (parser.parse_args / parse_known_args) */
  exists(Call c |
    c.getFunc().(Attribute).getName() in ["parse_args", "parse_known_args"] and
    node = c and
    flowKind = "cli" and
    callableName = c.getFunc().(Attribute).getName() and
    argIndex = -1 and
    receiver = receiverHintOfCall(c) and
    moduleHint = "argparse" and
    matchKind = "ast"
  )
  or
  /* family 3d: interactive CLI prompts: bare input(...), six.moves.input(...),
     and the tfdbg readline loop's self._input(...) */
  exists(Call c |
    (
      c.getFunc().(Name).getId() = "input"
      or
      c.getFunc().(Attribute).getName() = "input" and
      receiverHint(c.getFunc().(Attribute)) in ["moves", "six"]
      or
      c.getFunc().(Attribute).getName() = "_input"
    ) and
    node = c and
    flowKind = "cli" and
    callableName = calledNameOf(c) and
    argIndex = -1 and
    receiver = receiverHintOfCall(c) and
    moduleHint = "builtin" and
    matchKind = "ast"
  )
  or
  /* family 4a: builtin open() calls (model/config/project file input) */
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
  /* family 4b: gfile.Open(...) / gfile.GFile(...) tensorflow file reads */
  exists(Call c |
    c.getFunc().(Attribute).getName() in ["Open", "GFile"] and
    receiverHint(c.getFunc().(Attribute)) in ["gfile", "io"] and
    node = c and
    flowKind = "file" and
    callableName = c.getFunc().(Attribute).getName() and
    argIndex = 0 and
    receiver = receiverHintOfCall(c) and
    moduleHint = "tensorflow.python.platform.gfile" and
    matchKind = "ast"
  )
  or
  /* family 5: proto wire-format decoding (msg.ParseFromString(...)), including the
     reassembled network GraphDef chunks in grpc_debug_server.py */
  exists(Call c |
    c.getFunc().(Attribute).getName() = "ParseFromString" and
    node = c and
    flowKind = "proto_decode" and
    callableName = "ParseFromString" and
    argIndex = 0 and
    receiver = receiverHintOfCall(c) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 6: network fetches (urlopen(...) via six.moves.urllib.request.request,
     urllib.request, or a bare from-imported urlopen) */
  exists(Call c |
    (
      c.getFunc().(Name).getId() = "urlopen"
      or
      c.getFunc().(Attribute).getName() = "urlopen" and
      urllibReceiver(receiverHint(c.getFunc().(Attribute)))
    ) and
    node = c and
    flowKind = "network" and
    callableName = "urlopen" and
    argIndex = 0 and
    receiver = receiverHintOfCall(c) and
    moduleHint = "urllib.request" and
    matchKind = "ast"
  )
  or
  /* family 7: parameters of the tfdbg gRPC receive methods and receive callbacks
     (SendEvents/SendTracebacks/SendSourceFiles, on_value_event/on_graph_def/
     on_core_metadata_event) - the network boundary entry points */
  exists(Function f, Parameter p |
    debugReceiveMethodName(f.getName()) and
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
  /* family 8: internal calls handing received data to business handlers
     (stream_handler.on_value_event(...) / .on_graph_def(...) /
     .on_core_metadata_event(...) in grpc_debug_server.py SendEvents) */
  exists(Call c |
    c.getFunc().(Attribute).getName() in
      ["on_value_event", "on_graph_def", "on_core_metadata_event"] and
    node = c and
    flowKind = "internal_transfer" and
    callableName = c.getFunc().(Attribute).getName() and
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
