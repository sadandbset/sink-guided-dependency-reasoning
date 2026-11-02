/**
 * @name pymodbus CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   pymodbus CodeQL database (snapshot 927fa4d4, pymodbus 3.6.0dev - a
 *   Modbus protocol library whose only web surface is the simulator's
 *   aiohttp console): the aiohttp request path reads (request.path[1:] at
 *   pymodbus/server/simulator/http_server.py:260 inside
 *   ModbusSimulatorServer.handle_html_static - THE static-file value that
 *   flows into os.path.join(self.web_path, page) at :262 and then open(file)
 *   at :264 / web.FileResponse(file) at :265, registered for routes
 *   GET /{tail:[a-z0-9.]*} and GET / at :172/:173; plus the
 *   request.path.split("/")[-1] page_type reads at :271 in handle_html and
 *   :287 in handle_json, where the last path segment selects an HTML
 *   generator dict entry); the argparse CLI boundary of the simulator entry
 *   point (args = parser.parse_args(cmdline) at
 *   pymodbus/server/simulator/main.py:103, whose Namespace carries
 *   --json_file/--log_file/--custom_actions_module, and the generic
 *   args.__dict__[argument] subscript reads at :110/:111 whose values are
 *   copied into cmd_args and passed as ModbusSimulatorServer(**cmd_args));
 *   and the library/CLI API parameter boundary (ModbusSimulatorServer
 *   __init__ json_file position 6 - opened by open(json_file) at
 *   http_server.py:130 - log_file position 5 - stored at :162, currently
 *   dead config - and custom_actions_module position 7 - consumed by
 *   importlib.import_module at :140; pymodbus_apply_logging_config
 *   log_file_name position 1 and Log.apply_logging_config log_file_name
 *   position 2 - both feed logging.FileHandler(log_file_name) at
 *   pymodbus/logging.py:57; the typer callback server() modbus_config_path
 *   parameter at pymodbus/repl/server/main.py:145-147 - opened by
 *   open(modbus_config_path) at :173; annotate_pymodbus_logs file position
 *   0 at examples/contrib/explain.py:140 - opened/overwritten at :141/:168)
 *   with true parameter positions. External HTTP inputs that are NOT used
 *   to locate files (request.query at http_server.py:272, await
 *   request.post() at :288, await request.json() at
 *   pymodbus/server/reactive/main.py:279 - they feed register/monitor and
 *   response-manipulation settings only) and operator-configured inputs
 *   (TLS certfile/keyfile, serial device strings, the constant REPL
 *   history path) are NOT emitted - documented in detection.json instead.
 *   Raw BQRS extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong shape
 *   for candidate tables and @kind table is not assumed to exist.
 * @id iris/pymodbus/extraction/sources
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sinks.ql and to the previous
 * Path_Traversal iris projects):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - callable/member/field name (e.g. "path", "parse_args",
 *                   "__dict__", or the function name for parameter rows)
 *   4. flow_kind  - "http_request_path" (aiohttp request.path reads, the
 *                   static-file and page-type values),
 *                   "cli" (the argparse parse_args boundary and the
 *                   args.__dict__ CLI value reads),
 *                   "param" (library/CLI API boundary parameters)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "request"/"parser"/"args" etc., "" when
 *                   none, enclosing class name for parameter rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index when a call argument
 *                   carries the value; -1 when the receiver attribute or
 *                   the return value carries it; for "param" rows the true
 *                   parameter position in the function definition,
 *                   including the self/cls slot for methods
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced
 * a row). In this project no source row is expected to resolve at API level:
 * request.path is an attribute read on a handler-local parameter (aiohttp is
 * not part of the database - only the pymodbus tree is), parse_args operates
 * on a local parser object, and the boundary values arrive through function
 * parameters, so all families below are AST-level matches and the
 * match_kind column is kept "ast" for cross-project contract consistency.
 *
 * Excluded paths (applied to every row): /test/ (integration and unit test
 * trees), /pymodbus-db/ (the CodeQL database directory sits inside the
 * source tree), /doc/ (sphinx sources). examples/ is kept in scope (contrib
 * scripts; the annotate_pymodbus_logs parameter row there is a genuine
 * library boundary for the labeling step to judge).
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Top-level scripts that are not on an import path
 *  have no dotted module name; their file base name is used instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getShortName()
}

/** Forward-slash-normalized absolute path of the file containing n, so path
 *  matching works with both CodeQL path styles on Windows. */
string normalizedPathOf(AstNode n) {
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
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

/** True iff the candidate's file path is one of the excluded trees. Path is
 *  normalized to forward slashes before matching so the query works on both
 *  CodeQL path styles. bindingset[path] declares that the caller passes a
 *  bound path (the path only appears in checked positions such as the
 *  receiver of replaceAll/matches inside this predicate). */
bindingset[path]
predicate excludedPath(string path) {
  path.replaceAll("\\", "/").matches("%/test/%")
  or
  path.replaceAll("\\", "/").matches("%/pymodbus-db/%")
  or
  path.replaceAll("\\", "/").matches("%/doc/%")
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: http_request_path - request.path attribute reads in the
     simulator aiohttp handlers. http_server.py:260
     (page := request.path[1:] in handle_html_static - THE static-file
     value: joined onto self.web_path at :262, then opened at :264 and
     served via web.FileResponse(file) at :265; routes GET
     /{tail:[a-z0-9.]*} and GET / registered at :172/:173 - the route
     regex restricts the matched tail to lowercase alnum + dot, but the
     handler reads request.path directly rather than match_info['tail'];
     no containment check, no '..' rejection, only
     FileNotFoundError/IsADirectoryError -> 404 at :266-267);
     http_server.py:271 (handle_html) and :287 (handle_json) - the last
     path segment selects a generator_html/generator_json dict entry
     (page_type). aiohttp request.path is the percent-decoded URL path -
     attacker-controlled request URL input. */
  exists(Attribute a |
    a.getName() = "path" and
    a.getObject().(Name).getId() = "request" and
    normalizedPathOf(a).matches("%/pymodbus/server/simulator/http_server.py") and
    node = a and
    flowKind = "http_request_path" and
    callableName = "path" and
    argIndex = -1 and
    receiver = "request" and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast"
  )
  or
  /* family 2: cli - the argparse parse boundary of the simulator entry
     point: args = parser.parse_args(cmdline) at
     pymodbus/server/simulator/main.py:103 inside get_commandline(); the
     returned Namespace carries --json_file (setup file path, default
     os.path.join(os.path.dirname(__file__), "setup.json") at :88),
     --log_file and --custom_actions_module; run_main() then calls
     ModbusSimulatorServer(**cmd_args) so these CLI values cross into the
     library API boundary of family 4 */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "parse_args" and
    func.getObject().(Name).getId() = "parser" and
    normalizedPathOf(c).matches("%/pymodbus/server/simulator/main.py") and
    node = c and
    flowKind = "cli" and
    callableName = "parse_args" and
    argIndex = -1 and
    receiver = "parser" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3: cli - the generic CLI value reads:
     args.__dict__[argument] subscript reads at
     pymodbus/server/simulator/main.py:110 (None check) and :111 (store
     into cmd_args); the loop copies every non-None argparse value -
     including json_file/log_file/custom_actions_module - into cmd_args,
     which run_main() forwards as ModbusSimulatorServer(**cmd_args). This
     subscript is the actual node where the CLI strings enter the program
     data flow (the project uses a generic __dict__ loop instead of the
     args.<field> attribute reads other projects use) */
  exists(Subscript s, Attribute dictAttr |
    dictAttr = s.getObject().(Attribute) and
    dictAttr.getName() = "__dict__" and
    dictAttr.getObject().(Name).getId() = "args" and
    normalizedPathOf(s).matches("%/pymodbus/server/simulator/main.py") and
    node = s and
    flowKind = "cli" and
    callableName = "__dict__" and
    argIndex = -1 and
    receiver = "args" and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 4: library/CLI API boundary parameters (caller-provided values
     that may carry untrusted input when applications embed pymodbus or
     drive it through the CLIs). Positions include the self slot for
     methods. */

  /* ModbusSimulatorServer.__init__(self, modbus_server, modbus_device,
     http_host, http_port, log_file, json_file, custom_actions_module) -
     json_file (position 6) is opened by open(json_file) at
     http_server.py:130 and parsed as the simulator setup; log_file
     (position 5) is stored as self.log_file at :162 (currently never
     consumed - dead config, emitted for boundary documentation);
     custom_actions_module (position 7) is consumed by
     importlib.import_module at :140 (module import by name - the
     import_module call itself is not a filesystem API and is documented
     in detection.json, not emitted as a sink row). The CLI of family 2/3
     feeds exactly these three parameters. */
  exists(Function fn, Parameter p |
    fn.getName() = "__init__" and
    fn.getEnclosingScope().(Class).getName() = "ModbusSimulatorServer" and
    normalizedPathOf(fn).matches("%/pymodbus/server/simulator/http_server.py") and
    (p = fn.getArgByName("json_file") or p = fn.getArgByName("log_file") or
     p = fn.getArgByName("custom_actions_module")) and
    node = p and
    flowKind = "param" and
    callableName = "__init__" and
    argIndex = p.getPosition() and
    receiver = "ModbusSimulatorServer" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* pymodbus_apply_logging_config(level, log_file_name) - module-level
     function at pymodbus/logging.py:20, log_file_name at position 1;
     forwarded to Log.apply_logging_config (family 5) and ultimately
     opened for append by logging.FileHandler(log_file_name) at
     logging.py:57. In-repo callers pass level only; the path is reachable
     when an embedding application passes it. */
  exists(Function fn, Parameter p |
    fn.getName() = "pymodbus_apply_logging_config" and
    normalizedPathOf(fn).matches("%/pymodbus/logging.py") and
    p = fn.getArgByName("log_file_name") and
    node = p and
    flowKind = "param" and
    callableName = "pymodbus_apply_logging_config" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* Log.apply_logging_config(cls, level, log_file_name) - classmethod at
     pymodbus/logging.py:44, log_file_name at position 2 (cls slot 0,
     level slot 1); opens logging.FileHandler(log_file_name) at :57 */
  exists(Function fn, Parameter p |
    fn.getName() = "apply_logging_config" and
    fn.getEnclosingScope().(Class).getName() = "Log" and
    normalizedPathOf(fn).matches("%/pymodbus/logging.py") and
    p = fn.getArgByName("log_file_name") and
    node = p and
    flowKind = "param" and
    callableName = "apply_logging_config" and
    argIndex = p.getPosition() and
    receiver = "Log" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* server(ctx, ..., modbus_config_path, ...) - the typer CLI callback at
     pymodbus/repl/server/main.py:98 (@app.callback() at :97);
     modbus_config_path is a typer.Option of type Path declared at
     :145-147 ("Path to additional modbus server config") and is opened by
     open(modbus_config_path, encoding="utf-8") + json.load at :172-173 -
     a genuine CLI file-path boundary */
  exists(Function fn, Parameter p |
    fn.getName() = "server" and
    normalizedPathOf(fn).matches("%/pymodbus/repl/server/main.py") and
    p = fn.getArgByName("modbus_config_path") and
    node = p and
    flowKind = "param" and
    callableName = "server" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* annotate_pymodbus_logs(file) - module-level function at
     examples/contrib/explain.py:140, file at position 0; the caller-
     supplied log file path is read by open(file) at :141, overwritten in
     place by shutil.copyfile(out_file.name, file) at :168 and cleaned up
     by os.remove at :170 */
  exists(Function fn, Parameter p |
    fn.getName() = "annotate_pymodbus_logs" and
    normalizedPathOf(fn).matches("%/examples/contrib/explain.py") and
    p = fn.getArgByName("file") and
    node = p and
    flowKind = "param" and
    callableName = "annotate_pymodbus_logs" and
    argIndex = p.getPosition() and
    receiver = "" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  not excludedPath(node.getLocation().getFile().getAbsolutePath())
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
