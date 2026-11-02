/**
 * @name slo-generator CWE-78 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   slo-generator CodeQL database (snapshot 50ce1bf): Functions Framework
 *   request state (request.get_data / get_json / request.data attribute /
 *   request[...] CloudEvent subscripts) on the api/main.py entry points,
 *   config decoding (yaml.safe_load / yaml.load / yaml.util
 *   .load_yaml_guess_indent / json.loads / base64.b64decode, resolved via API
 *   graphs where possible), file input (open / Path.open / .read / glob /
 *   rglob), GCS remote config content (blob.download_as_string), environment
 *   reads (os.environ attribute / subscript / .get, ctx[var] substitution),
 *   click CLI option registration, config dict reads on the config-carrier
 *   variables, handler entry-point parameters (Functions Framework targets,
 *   click commands, do_migrate, config-dispatched backend/exporter methods),
 *   and internal calls handing external data to handlers / parsers
 *   (load_config / load_configs / parse_config / compute / export /
 *   do_migrate / get_exporters / get_backend / get_error_budget_policy).
 *   Raw BQRS extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain multi-column
 *   select query on purpose: @kind problem is the wrong shape for candidate
 *   tables and @kind table is not assumed to exist.
 * @id iris/slo-generator/extraction/sources
 * @tags command-injection
 */

import python
import semmle.python.ApiGraphs

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable name (API member name, function name, or attribute name)
 *   4. flow_kind  - "return" (tainted return value: decode / remote fetch),
 *                   "param" (externally reachable handler parameter),
 *                   "http_request" (Functions Framework request object state),
 *                   "env" (environment read), "cli" (click option registration),
 *                   "config" (dict read on a config-carrier variable),
 *                   "file" (file / directory input),
 *                   "internal_transfer" (call handing external data to a
 *                   handler / parser / pipeline entry)
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
 * The Functions Framework request object is a framework parameter object, so request
 * state is matched at AST level only; json/yaml/base64 decode calls resolve via API
 * graphs (no alias imports observed in this codebase).
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Files not on an import path fall back to the file
 *  base name. */
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

/** Holds if n is inside the analysis scope: the tests/ tree (tests/unit,
 *  fixtures) is excluded as candidate noise per the Augur candidate strategy.
 *  Path matching is separator-agnostic (Windows or POSIX layout). */
predicate inScope(AstNode n) {
  not n.getLocation().getFile().getAbsolutePath().toLowerCase().regexpMatch(
    "^.*[/\\\\]tests[/\\\\].*$"
  )
}

/* ------------------------------------------------------------------ */
/* Source family 1: resolved decode APIs (API graphs)                  */
/* ------------------------------------------------------------------ */

/**
 * External decoding APIs whose return value may carry attacker-controlled data:
 * json.loads/load decode JSON payloads (remote API responses), yaml.safe_load /
 * yaml.load decode configuration (request-supplied string content in API mode),
 * base64.b64decode decodes CloudEvent payloads, os.getenv reads the process
 * environment (not exercised in this snapshot: the os.environ attribute family
 * is used instead, matched at AST level).
 */
private predicate resolvedDecodeCall(API::CallNode cn, string moduleHint, string member, int argIndex) {
  (
    moduleHint = "json" and member in ["loads", "load"] and argIndex = 0
    or
    moduleHint = "yaml" and member in ["safe_load", "load"] and argIndex = 0
    or
    moduleHint = "base64" and member = "b64decode" and argIndex = 0
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
 * Input calls matched by AST shape: Functions Framework request body reads
 * (request.get_data() / request.get_json()), the round-trip YAML loader
 * (yaml.util.load_yaml_guess_indent), built-in open() and file-like
 * .open()/.read() calls, Path glob/rglob directory listings, and the GCS
 * blob download returning remote config content.
 */
private predicate protocolSourceCall(Call c, string moduleHint, string callableName, int argIndex) {
  /* Functions Framework / Flask request body: request.get_data() / request.get_json() */
  moduleHint = "flask.request" and
  callableName in ["get_data", "get_json"] and
  argIndex = -1 and
  c.getFunc().(Attribute).getName() = callableName and
  c.getFunc().(Attribute).getObject().(Name).getId() = "request"
  or
  /* round-trip YAML loader: yaml.util.load_yaml_guess_indent(...) (any module alias) */
  moduleHint = "yaml.util" and
  callableName = "load_yaml_guess_indent" and
  argIndex = 0 and
  c.getFunc().(Attribute).getName() = "load_yaml_guess_indent"
  or
  /* built-in open(): file input (path is argument 0) */
  moduleHint = "builtins" and
  callableName = "open" and
  argIndex = 0 and
  c.getFunc().(Name).getId() = "open"
  or
  /* Path / file-like open: <obj>.open(...) - write-mode ('w') opens excluded */
  moduleHint = "pathlib" and
  callableName = "open" and
  argIndex = -1 and
  c.getFunc().(Attribute).getName() = "open" and
  not exists(StringLiteral mode |
    mode = c.getAPositionalArg() and
    mode.getText() = "w"
  )
  or
  /* file-like read: <obj>.read() */
  moduleHint = "file" and
  callableName = "read" and
  argIndex = -1 and
  c.getFunc().(Attribute).getName() = "read"
  or
  /* directory listing: <obj>.glob(...) / <obj>.rglob(...) */
  moduleHint = "pathlib" and
  callableName in ["glob", "rglob"] and
  argIndex = 0 and
  c.getFunc().(Attribute).getName() = callableName
  or
  /* GCS blob content: <blob>.download_as_string(...) */
  moduleHint = "google.cloud.storage" and
  callableName = "download_as_string" and
  argIndex = -1 and
  c.getFunc().(Attribute).getName() = "download_as_string"
}

/* ------------------------------------------------------------------ */
/* Source family 3: handler entry-point functions                      */
/* ------------------------------------------------------------------ */

/**
 * Functions that sit at an external-data boundary: the Functions Framework
 * target functions (run_compute / run_export), the click CLI commands
 * (main / compute / api / migrate) whose parameters are click-injected
 * CLI/envvar values, the migration entry point do_migrate, and the
 * backend / exporter methods that are selected *by name* from configuration
 * (report.py:193 config['spec']['method'] dispatched with getattr;
 * compute.py:119 instance().export(data, **config)).
 */
private predicate isHandlerFunction(Function f) {
  /* Functions Framework targets and CLI commands (module-restricted to avoid
     name collisions with the internal compute/export pipeline functions) */
  moduleHintOf(f) in ["slo_generator.api.main", "slo_generator.cli",
                      "slo_generator.migrations.migrator"]
  and
  f.getName() in ["run_compute", "run_export", "main", "compute", "api",
                  "migrate", "do_migrate"]
  or
  /* backend methods selected by name from the SLO config ('spec.method') */
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName().matches("%Backend") and
  f.getName() in ["query_sli", "good_bad_ratio", "count", "count_threshold"]
  or
  /* exporter methods selected by name from the exporter config */
  f.getEnclosingScope() instanceof Class and
  f.getEnclosingScope().(Class).getName().matches("%Exporter") and
  f.getName() in ["export", "export_metric"]
}

/* ------------------------------------------------------------------ */
/* Config-carrier variables                                            */
/* ------------------------------------------------------------------ */

/** Names of the variables observed to carry parsed SLO / shared config data
 *  in this codebase (dict-shaped reads on them are config-flow candidates). */
private predicate configCarrierName(string name) {
  name in ["config", "spec", "slo_config", "slo_config_dict", "slo_report",
           "backend", "shared_config"]
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
     (request body reads are request state; open/read/glob are file input;
     load_yaml_guess_indent and download_as_string return tainted data) */
  exists(Call c |
    protocolSourceCall(c, moduleHint, callableName, argIndex) and
    node = c and
    (
      (
        moduleHint = "flask.request" and
        flowKind = "http_request"
      )
      or
      (
        moduleHint in ["builtins", "pathlib", "file"] and
        flowKind = "file"
      )
      or
      (
        moduleHint in ["yaml.util", "google.cloud.storage"] and
        flowKind = "return"
      )
    ) and
    receiver = receiverHintOfCall(c) and
    matchKind = "ast"
  )
  or
  /* family 3a: CloudEvent request attribute: request.data */
  exists(Attribute a |
    a.getName() = "data" and
    a.getObject().(Name).getId() = "request" and
    node = a and
    flowKind = "http_request" and
    callableName = "data" and
    argIndex = -1 and
    receiver = "request" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 3b: CloudEvent request subscript: request["time"] / request["id"] */
  exists(Subscript s |
    s.getObject().(Name).getId() = "request" and
    node = s and
    flowKind = "http_request" and
    callableName = "request" and
    argIndex = -1 and
    receiver = "request" and
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
  /* family 4b: os.environ[...] subscript read */
  exists(Subscript s |
    s.getObject().(Attribute).getName() = "environ" and
    s.getObject().(Attribute).getObject().(Name).getId() = "os" and
    node = s and
    flowKind = "env" and
    callableName = "environ" and
    argIndex = -1 and
    receiver = "os.environ" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 4c: os.environ.get(...) read */
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
  /* family 4d: ctx[var] read - ${VAR} substitution context
     (ctx defaults to os.environ in load_config / parse_config) */
  exists(Subscript s |
    s.getObject().(Name).getId() = "ctx" and
    node = s and
    flowKind = "env" and
    callableName = "ctx" and
    argIndex = -1 and
    receiver = "ctx" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 5: click CLI option / command registration
     (the decorated function parameters carry the parsed CLI values and are
     captured by the param family below) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["option", "command", "group", "argument"] and
    (
      func.getObject().(Name).getId() = "click"
      or
      func.getObject().(Name).getId() = "main"
    ) and
    node = c and
    flowKind = "cli" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = "click" and
    matchKind = "ast"
  )
  or
  /* family 6a: config dict read: <carrier>[...] subscript */
  exists(Subscript s |
    configCarrierName(s.getObject().(Name).getId()) and
    node = s and
    flowKind = "config" and
    callableName = s.getObject().(Name).getId() and
    argIndex = -1 and
    receiver = s.getObject().(Name).getId() and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 6b: config dict read: <carrier>.get(...) / <carrier>.pop(...) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() in ["get", "pop"] and
    configCarrierName(func.getObject().(Name).getId()) and
    node = c and
    flowKind = "config" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = func.getObject().(Name).getId() and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 7: parameters of handler entry-point functions
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
  /* family 8: internal calls handing external data to handlers / parsers
     (load_config takes the request body string / config path, load_configs a
     config folder, compute / _compute the parsed SLO config, export the SLO
     report, do_migrate the CLI migration values; get_exporters / get_backend /
     get_error_budget_policy shape config data for the pipeline) */
  exists(Call c |
    (
      c.getFunc().(Attribute).getName() in ["load_config", "load_configs",
        "parse_config", "compute", "_compute", "export", "do_migrate",
        "get_exporters", "get_backend", "get_error_budget_policy"]
      or
      c.getFunc().(Name).getId() in ["load_config", "load_configs",
        "parse_config", "compute", "_compute", "export", "do_migrate",
        "get_exporters", "get_backend", "get_error_budget_policy"]
    ) and
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
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  inScope(node)
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
