/**
 * @name transformers CWE-78 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the transformers
 *   CodeQL database (commit 87a6cf4): stdin line-delimited JSON of the git-lfs transfer
 *   agent, JSON decoding of (hub-downloaded) config/preprocessor files, network fetch
 *   returns (requests / huggingface_hub), CLI argument parsing (argparse parse_args /
 *   parse_args_into_dataclasses, HfArgumentParser, sys.argv), environment reads
 *   (os.environ / os.getenv), handler entry-point parameters (CLI *Command classes,
 *   main/export functions), and internal calls handing parsed CLI args or external
 *   messages to command handlers. Raw BQRS extraction query: run with
 *   `codeql query run` and decode with `codeql bqrs decode` (not database analyze).
 *   This is a plain multi-column select query on purpose: @kind problem is the wrong
 *   shape for candidate tables and @kind table is not assumed to exist.
 *   Rows are restricted to the shipped library (files under src/transformers/); the
 *   database covers the whole repository including tests/, examples/ and CI scripts.
 * @id iris/transformers/extraction/sources
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
 *                   "env" (environment read), "cli" (parsed CLI arguments),
 *                   "stdin" (stdin read), "internal_transfer" (call handing external
 *                   data to a command handler / business function)
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
 * separate from AST syntax matching (the match_kind column records which one produced a
 * row). Generic *.from_pretrained(...) sites are intentionally NOT extracted (2112 call
 * sites, single repeated signature) - see exploration/detection.json, uncoveredCases.
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

/** Holds if n sits in a file under src/transformers/ (the shipped library code). */
private predicate inLibrarySource(AstNode n) {
  n.getLocation().getFile().getAbsolutePath().regexpMatch("(?i).*[\\\\/]src[\\\\/]transformers[\\\\/].*")
}

/* ------------------------------------------------------------------ */
/* Source family 1: resolved input APIs (API graphs)                   */
/* ------------------------------------------------------------------ */

/**
 * External decoding / environment / network APIs whose return value may carry
 * attacker-influenced data: json.loads decodes stdin protocol payloads and
 * (hub-downloaded) config JSON; os.getenv reads the process environment;
 * requests fetches remote content; huggingface_hub downloads hub artifacts.
 */
private predicate resolvedInputCall(API::CallNode cn, string moduleHint, string member, int argIndex) {
  (
    moduleHint = "json" and member in ["loads", "load"] and argIndex = 0
    or
    moduleHint = "os" and member = "getenv" and argIndex = 0
    or
    moduleHint = "requests" and member in ["get", "post", "put", "head", "request"] and argIndex = 0
    or
    moduleHint = "huggingface_hub" and member in ["hf_hub_download", "snapshot_download", "cached_download"] and
    argIndex = 0
  ) and
  cn = API::moduleImport(moduleHint).getMember(member).getACall()
}

/** The syntactic Call node behind an API graph call node. */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/* ------------------------------------------------------------------ */
/* Source family 2: protocol-shaped AST calls and reads (syntax-level) */
/* ------------------------------------------------------------------ */

/**
 * Syntax-level matches for the input shapes of this project: the json/os.getenv
 * fallback of family 1, sys.stdin reads (git-lfs line-delimited JSON protocol,
 * pipeline stdin rows), os.environ dict reads, sys.argv reads, argparse value
 * parsing (parse_args / parse_args_into_dataclasses / parse_known_args), and the
 * HfArgumentParser factory.
 */
private predicate astSourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex
) {
  /* json.loads / json.load / os.getenv by syntactic module prefix (alias-unaware fallback) */
  exists(Call c |
    argIndex = 0 and
    (
      moduleHint = "json" and callableName in ["loads", "load"]
      or
      moduleHint = "os" and callableName = "getenv"
    ) and
    c.getFunc().(Attribute).getName() = callableName and
    c.getFunc().(Attribute).getObject().(Name).getId() = moduleHint and
    node = c and
    flowKind = "return" and
    receiver = moduleHint
  )
  or
  /* sys.stdin read (lfs transfer protocol / pipeline stdin); the stdin attribute is the tainted root */
  exists(Attribute a |
    a.getName() = "stdin" and
    a.getObject().(Name).getId() = "sys" and
    node = a and
    flowKind = "stdin" and
    callableName = "stdin" and
    argIndex = -1 and
    receiver = "sys" and
    moduleHint = "sys"
  )
  or
  /* os.environ read (attribute load; covers subscript and .get consumers) */
  exists(Attribute a |
    a.getName() = "environ" and
    a.getObject().(Name).getId() = "os" and
    node = a and
    flowKind = "env" and
    callableName = "environ" and
    argIndex = -1 and
    receiver = "os" and
    moduleHint = "os"
  )
  or
  /* sys.argv read */
  exists(Attribute a |
    a.getName() = "argv" and
    a.getObject().(Name).getId() = "sys" and
    node = a and
    flowKind = "cli" and
    callableName = "argv" and
    argIndex = -1 and
    receiver = "sys" and
    moduleHint = "sys"
  )
  or
  /* argparse value parsing: <parser>.parse_args() / parse_args_into_dataclasses() /
     parse_known_args() - the returned Namespace/dataclass values are the CLI inputs */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["parse_args", "parse_args_into_dataclasses", "parse_known_args"] and
    node = c and
    flowKind = "cli" and
    callableName = func.getName() and
    argIndex = -1 and
    receiver = receiverHint(func) and
    moduleHint = "argparse"
  )
  or
  /* HfArgumentParser factory (dataclass-to-argparse bridge used by Trainer scripts) */
  exists(Call c |
    c.getFunc().(Name).getId() = "HfArgumentParser" and
    node = c and
    flowKind = "cli" and
    callableName = "HfArgumentParser" and
    argIndex = -1 and
    receiver = "" and
    moduleHint = "transformers.hf_argparser"
  )
}

/* ------------------------------------------------------------------ */
/* Source family 3: handler entry-point functions                      */
/* ------------------------------------------------------------------ */

/**
 * Functions that sit at an external-data boundary: main() CLI entries, run()/__init__()
 * of the argparse *Command classes (they receive the parsed Namespace, e.g.
 * LfsEnableCommand uses self.args.path), and the ONNX exporter entry functions that
 * take the full parsed args. Logging helpers are excluded by not being named here.
 */
private predicate isHandlerFunction(Function f) {
  f.getName() = "main"
  or
  (
    f.getName() in ["run", "__init__"] and
    f.getEnclosingScope() instanceof Class and
    f.getEnclosingScope().(Class).getName().matches("%Command")
  )
  or
  f.getName() in ["export_with_optimum", "export_with_transformers"]
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: resolved input API calls (API graphs, alias-aware) */
  exists(API::CallNode cn |
    resolvedInputCall(cn, moduleHint, callableName, argIndex) and
    node = astCallOf(cn) and
    flowKind = "return" and
    receiver = "" and
    matchKind = "api"
  )
  or
  /* family 2: protocol-shaped AST calls and reads */
  astSourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex) and
  matchKind = "ast"
  or
  /* family 3: parameters of handler entry-point functions
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
  /* family 4a: args.func(args) - CLI dispatch of the parsed Namespace into a command
     factory attached via parser.set_defaults(func=lambda args: XCommand(args)) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "func" and
    func.getObject().(Name).getId() = "args" and
    node = c and
    flowKind = "internal_transfer" and
    callableName = "func" and
    argIndex = 0 and
    receiver = "args" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 4b: service.run() - entering the selected CLI command object
     (the Namespace travels via the receiver, hence arg_index -1) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "run" and
    func.getObject().(Name).getId() = "service" and
    node = c and
    flowKind = "internal_transfer" and
    callableName = "run" and
    argIndex = -1 and
    receiver = "service" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 4c: read_msg() - external stdin JSON handed into the upload loop;
     export_with_optimum(args) / export_with_transformers(args) - parsed CLI args
     handed to the ONNX export entry functions */
  exists(Call c |
    c.getFunc().(Name).getId() = "read_msg" and
    node = c and
    flowKind = "internal_transfer" and
    callableName = "read_msg" and
    argIndex = -1 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  exists(Call c |
    c.getFunc().(Name).getId() in ["export_with_optimum", "export_with_transformers"] and
    node = c and
    flowKind = "internal_transfer" and
    callableName = c.getFunc().(Name).getId() and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  inLibrarySource(node)
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
