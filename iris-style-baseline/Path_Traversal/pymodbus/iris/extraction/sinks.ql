/**
 * @name pymodbus CWE-22 sink candidate extraction
 * @description Extract filesystem-operation sink candidates from the
 *   pymodbus CodeQL database (snapshot 927fa4d4, pymodbus 3.6.0dev):
 *   real file opens (builtin open(...) at
 *   pymodbus/server/simulator/http_server.py:130 - the json_file setup
 *   read, :201 - the fixed generator template read, :264 - THE
 *   request.path-derived static-file read inside handle_html_static, and
 *   pymodbus/repl/server/main.py:173 - the typer-supplied modbus config
 *   read, plus examples/contrib/explain.py:141 - the caller-supplied log
 *   read); the aiohttp file response channel (web.FileResponse(file) at
 *   http_server.py:265 - aiohttp opens and streams the file itself, the
 *   internal access is not in the database); path construction
 *   (os.path.join(...) at http_server.py:166 - the fixed web base dir,
 *   :200 - the fixed generator dir join, :262 - THE
 *   request.path-derived page joined onto the web base dir, and
 *   pymodbus/server/simulator/main.py:88 - the literal setup.json default;
 *   pathlib .joinpath(".pymodhis") at pymodbus/repl/client/main.py:157 -
 *   a fully constant REPL history path); file writes
 *   (logging.FileHandler(log_file_name) at pymodbus/logging.py:57 - open
 *   for append on a caller-supplied path; FileHistory(history_file) at
 *   repl/client/main.py:183 - prompt_toolkit persists REPL history lines
 *   to the file); file copy/delete in the contrib example
 *   (shutil.copyfile(out_file.name, file) at examples/contrib/explain.py:168
 *   - argument 1 is the caller-supplied destination overwritten in place,
 *   os.remove(out_file.name) at :170); the ssl certificate read
 *   (ssl.SSLContext.load_cert_chain(certfile=..., keyfile=...) at
 *   pymodbus/transport/transport.py:131-134 - operator-configured TLS
 *   material); the serial device opens (serial.serial_for_url(...) at
 *   pymodbus/client/serial.py:211 and
 *   pymodbus/transport/transport_serial.py:23 - pyserial opens a device
 *   path or socket:// URL, operator-configured comm parameter); and
 *   definition rows for the library's own path-consuming internal APIs
 *   (CommParams.generate_ssl certfile/keyfile, ModbusTlsServer.__init__
 *   certfile/keyfile) with the true parameter positions. Raw BQRS
 *   extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong shape
 *   for candidate tables and @kind table is not assumed to exist.
 * @id iris/pymodbus/extraction/sinks
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sources.ql and to the previous
 * Path_Traversal iris projects):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - callable/member name ("open" / "FileResponse" /
 *                   "join" / "joinpath" / "FileHandler" / "FileHistory" /
 *                   "copyfile" / "remove" / "load_cert_chain" /
 *                   "serial_for_url", or the function name for
 *                   file_api_def definition rows)
 *   4. flow_kind  - "file_open" (builtin open(...) - the path argument),
 *                   "file_response" (web.FileResponse(argument 0) - the
 *                   aiohttp static file response channel),
 *                   "path_join" (os.path.join(argument 0) base joins and
 *                   pathlib .joinpath(argument 0) - pipeline nodes that
 *                   directly determine the accessed path),
 *                   "file_write" (logging.FileHandler(argument 0) open
 *                   for append; FileHistory(argument 0) history
 *                   persistence),
 *                   "file_copy" (shutil.copyfile - argument 1 is the
 *                   overwritten destination, documented in the family
 *                   comment),
 *                   "file_delete" (os.remove(argument 0)),
 *                   "file_read" (ssl load_cert_chain - the certificate
 *                   chain file read),
 *                   "serial_open" (serial.serial_for_url(argument 0) -
 *                   pyserial device/socket open),
 *                   "file_api_def" (definition row of a path-consuming
 *                   internal API, carrying the path parameter position)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression: "web"/"os"/"os.path"/"logging"/"shutil"/
 *                   "serial"/"new_sslctx" etc., "" if none, "<expr>" when
 *                   the object expression is neither Name nor Attribute
 *                   (the pathlib.Path.home().joinpath row); enclosing
 *                   class name for file_api_def rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "builtins"/"aiohttp.web"/"os.path"/"pathlib"/
 *                   "logging"/"shutil"/"ssl"/"serial"/
 *                   "prompt_toolkit.history" for the stdlib/external
 *                   channels
 *   7. arg_index  - 0-based positional argument index carrying the path
 *                   (argument 0 for open/FileResponse/join/joinpath/
 *                   FileHandler/FileHistory/load_cert_chain/serial_for_url/
 *                   remove rows; argument 1 for the copyfile row whose
 *                   destination is the caller-supplied path; the parameter
 *                   position for file_api_def rows, including the self/cls
 *                   slot)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Sink modeling decision (per the task contract): the sink core is the
 * FILE PATH PARAMETER of actual filesystem operations and the
 * path-pipeline nodes that directly determine the accessed file - the
 * open() calls (including the request.path-derived read at
 * http_server.py:264), the web.FileResponse serving channel, the
 * os.path.join/pathlib.joinpath construction feeding them, the
 * FileHandler/FileHistory write channels, copyfile/remove in the contrib
 * example, the ssl load_cert_chain read and the pyserial device open -
 * NOT every path string construction node (the f-string/HTML template
 * building in the generator handlers is pure rendering and is documented
 * in detection.json uncoveredCases instead). No sanitizer families were
 * observed on the static-file path: no realpath/abspath/normpath/
 * relative_to/startswith/'..' rejection anywhere in the handler (the
 * /{tail:[a-z0-9.]*} route regex at http_server.py:172 is the only
 * filter, and the handler reads request.path directly).
 *
 * Note: this file defines no QL classes (only predicates), does not assign
 * API::Node values to DataFlow::Node variables, keeps every variable bound
 * through a positive body, and keeps resolved-API matching strictly separate
 * from AST syntax matching (the match_kind column records which one produced
 * a row). In this project no sink row is expected to resolve at API level:
 * aiohttp/logging/shutil/ssl/serial/prompt_toolkit are external modules not
 * part of the database (only the pymodbus tree is), and the builtin open
 * calls sit on local variables, so all families below are AST-level matches
 * and the match_kind column is kept "ast" for cross-project contract
 * consistency. Member-name matching is file-scoped on purpose to avoid
 * name-collision noise; receiver hints are emitted for the labeling step.
 *
 * Excluded paths (applied to every row): /test/, /pymodbus-db/ (the CodeQL
 * database directory nested inside the source tree), /doc/ (sphinx
 * sources). examples/ is kept in scope (the explain.py rows are a genuine
 * param-boundary file pipeline for the labeling step to judge).
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

/** One row per sink candidate. */
private predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* -------------------------------------------------------------- */
  /* family 1: file_open - builtin open(...) calls with the path at
     argument 0: http_server.py:130 open(json_file, encoding="utf-8")
     (the ModbusSimulatorServer.__init__ json_file setup read +
     json.load), :201 open(html_file, encoding="utf-8") (the fixed
     generator template read - entry iterates the constant
     generator_html keys "log"/"registers"/"calls"/"server"), :264
     open(file, encoding="utf-8") - THE request.path-derived static-file
     read in handle_html_static (joined at :262, served at :265; wrapped
     in try/except FileNotFoundError/IsADirectoryError -> 404 at
     :266-267, which is error handling, not path validation);
     repl/server/main.py:173 open(modbus_config_path, encoding="utf-8")
     (the typer-supplied modbus config read + json.load);
     examples/contrib/explain.py:141 open(file, encoding="utf-8") (the
     annotate_pymodbus_logs caller-supplied log read) */
  exists(Call c |
    c.getFunc().(Name).getId() = "open" and
    (normalizedPathOf(c).matches("%/pymodbus/%") or
     normalizedPathOf(c).matches("%/examples/%")) and
    node = c and
    flowKind = "file_open" and
    callableName = "open" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "builtins" and
    matchKind = "ast"
  )
  or
  /* family 2: file_response - web.FileResponse(file) at
     http_server.py:265 in handle_html_static: aiohttp opens and streams
     the file at argument 0 to the HTTP client - the static-file serving
     channel of the simulator console; the path is the request.path-derived
     join of family 3. aiohttp is not part of the database, so its
     internal file access cannot be traced - this call site is the sink
     anchor. (Imported via "from aiohttp import web" at :14, so the
     receiver name is the module alias "web".) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "FileResponse" and
    func.getObject().(Name).getId() = "web" and
    normalizedPathOf(c).matches("%/pymodbus/server/simulator/http_server.py") and
    node = c and
    flowKind = "file_response" and
    callableName = "FileResponse" and
    argIndex = 0 and
    receiver = "web" and
    moduleHint = "aiohttp.web" and
    matchKind = "ast"
  )
  or
  /* family 3a: path_join - os.path.join(...) calls with the first path
     component at argument 0: http_server.py:166
     os.path.join(os.path.dirname(__file__), "web") (the fixed
     package-relative web base dir), :200
     os.path.join(self.web_path, "generator", entry) (the fixed generator
     dir plus a constant dict key), :262
     os.path.join(self.web_path, page) - THE request.path-derived page
     (request.path[1:] at :260) joined onto the web base dir, the direct
     predecessor of the open() at :264 and FileResponse at :265;
     simulator/main.py:88 os.path.join(os.path.dirname(__file__),
     "setup.json") (the literal argparse default) */
  exists(Call c, Attribute func, Attribute base |
    func = c.getFunc().(Attribute) and
    base = func.getObject().(Attribute) and
    func.getName() = "join" and
    base.getName() = "path" and
    base.getObject().(Name).getId() = "os" and
    (normalizedPathOf(c).matches("%/pymodbus/server/simulator/http_server.py") or
     normalizedPathOf(c).matches("%/pymodbus/server/simulator/main.py")) and
    node = c and
    flowKind = "path_join" and
    callableName = "join" and
    argIndex = 0 and
    receiver = "os.path" and
    moduleHint = "os.path" and
    matchKind = "ast"
  )
  or
  /* family 3b: path_join - pathlib .joinpath(...) member calls with the
     joined component at argument 0: repl/client/main.py:157
     pathlib.Path.home().joinpath(".pymodhis") - a FULLY CONSTANT REPL
     history path (no attacker control; emitted for completeness so the
     labeling step can confirm none/FP; the object expression is the
     call pathlib.Path.home(), hence the "<expr>" receiver hint) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "joinpath" and
    normalizedPathOf(c).matches("%/pymodbus/repl/client/main.py") and
    node = c and
    flowKind = "path_join" and
    callableName = "joinpath" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = "pathlib" and
    matchKind = "ast"
  )
  or
  /* family 4a: file_write - logging.FileHandler(log_file_name) at
     pymodbus/logging.py:57 inside Log.apply_logging_config: opens the
     caller-supplied log file path at argument 0 for append and attaches
     it to the library logger; the path arrives through
     pymodbus_apply_logging_config(level, log_file_name) /
     Log.apply_logging_config(cls, level, log_file_name) (source param
     rows in sources.ql) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "FileHandler" and
    func.getObject().(Name).getId() = "logging" and
    normalizedPathOf(c).matches("%/pymodbus/logging.py") and
    node = c and
    flowKind = "file_write" and
    callableName = "FileHandler" and
    argIndex = 0 and
    receiver = "logging" and
    moduleHint = "logging" and
    matchKind = "ast"
  )
  or
  /* family 4b: file_write - FileHistory(history_file) at
     pymodbus/repl/client/main.py:183: prompt_toolkit's FileHistory
     persists REPL command history lines to the file at argument 0; the
     path is the constant pathlib.Path.home()/".pymodhis" of family 3b
     (imported via "from prompt_toolkit.history import FileHistory" at
     :9, so the callee is a bare Name) */
  exists(Call c |
    c.getFunc().(Name).getId() = "FileHistory" and
    normalizedPathOf(c).matches("%/pymodbus/repl/client/main.py") and
    node = c and
    flowKind = "file_write" and
    callableName = "FileHistory" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "prompt_toolkit.history" and
    matchKind = "ast"
  )
  or
  /* family 5: file_copy - shutil.copyfile(out_file.name, file) at
     examples/contrib/explain.py:168 inside annotate_pymodbus_logs: copies
     the internal NamedTemporaryFile content over the caller-supplied
     destination - argument 1 ("file", the function's path parameter) is
     the row's path position; argument 0 is the internal temp file name
     (not attacker-controlled). The destination file is overwritten in
     place. */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "copyfile" and
    func.getObject().(Name).getId() = "shutil" and
    normalizedPathOf(c).matches("%/examples/contrib/explain.py") and
    node = c and
    flowKind = "file_copy" and
    callableName = "copyfile" and
    argIndex = 1 and
    receiver = "shutil" and
    moduleHint = "shutil" and
    matchKind = "ast"
  )
  or
  /* family 6: file_delete - os.remove(out_file.name) at
     examples/contrib/explain.py:170: deletion of the internal temp file
     (path at argument 0, internally generated name - expected to be
     labeled none/FP; the internal tempfile.NamedTemporaryFile call at
     :141-143 itself is not emitted) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "remove" and
    func.getObject().(Name).getId() = "os" and
    normalizedPathOf(c).matches("%/examples/contrib/explain.py") and
    node = c and
    flowKind = "file_delete" and
    callableName = "remove" and
    argIndex = 0 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 7: file_read - new_sslctx.load_cert_chain(certfile=certfile,
     keyfile=keyfile, password=password) at
     pymodbus/transport/transport.py:131-134 inside
     CommParams.generate_ssl: ssl reads the certificate chain file (and
     key file) - keyword form of the call, so argument 0 is the "certfile"
     keyword whose value is the operator-configured TLS path (argument 1
     "keyfile" documented here); emitted as a real file-access sink for
     the labeling step to judge, the cert/key params are documented as
     operator-configured in detection.json and not emitted as sources */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "load_cert_chain" and
    normalizedPathOf(c).matches("%/pymodbus/transport/transport.py") and
    node = c and
    flowKind = "file_read" and
    callableName = "load_cert_chain" and
    argIndex = 0 and
    receiver = receiverHint(func) and
    moduleHint = "ssl" and
    matchKind = "ast"
  )
  or
  /* family 8: serial_open - serial.serial_for_url(...) calls with the
     device string at argument 0: pymodbus/client/serial.py:211
     serial.serial_for_url(self.comm_params.host, ...) (the client comm
     device) and pymodbus/transport/transport_serial.py:23
     serial.serial_for_url(*args, **kwargs) (the transport layer -
     argument 0 is the star-args expansion whose first value is the
     device). pyserial opens the device path (or a "socket://..." URL) -
     an operator-configured comm parameter, emitted as a file-access
     family sink for the labeling step to judge */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "serial_for_url" and
    func.getObject().(Name).getId() = "serial" and
    (normalizedPathOf(c).matches("%/pymodbus/client/serial.py") or
     normalizedPathOf(c).matches("%/pymodbus/transport/transport_serial.py")) and
    node = c and
    flowKind = "serial_open" and
    callableName = "serial_for_url" and
    argIndex = 0 and
    receiver = "serial" and
    moduleHint = "serial" and
    matchKind = "ast"
  )
  or
  /* -------------------------------------------------------------- */
  /* family 9: file_api_def - definition rows of the library's own
     path-consuming internal APIs (candidates for summary/propagation
     labeling). Positions include the self/cls slot for methods. */

  /* CommParams.generate_ssl(cls, is_server, certfile, keyfile, password,
     sslctx) - pymodbus/transport/transport.py:108, certfile at position 2
     and keyfile at position 3: forwarded to the load_cert_chain call of
     family 7 */
  exists(Function fn, Parameter p |
    fn.getName() = "generate_ssl" and
    fn.getEnclosingScope().(Class).getName() = "CommParams" and
    normalizedPathOf(fn).matches("%/pymodbus/transport/transport.py") and
    (p = fn.getArgByName("certfile") or p = fn.getArgByName("keyfile")) and
    node = p and
    flowKind = "file_api_def" and
    callableName = "generate_ssl" and
    argIndex = p.getPosition() and
    receiver = "CommParams" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
  or
  /* ModbusTlsServer.__init__(self, context, framer, identity, address,
     sslctx, certfile, keyfile, ...) - pymodbus/server/async_io.py:378,
     certfile at position 6 and keyfile at position 7: forwarded to
     CommParams.generate_ssl (family 9 row above) and then
     load_cert_chain; operator-configured TLS material */
  exists(Function fn, Parameter p |
    fn.getName() = "__init__" and
    fn.getEnclosingScope().(Class).getName() = "ModbusTlsServer" and
    normalizedPathOf(fn).matches("%/pymodbus/server/async_io.py") and
    (p = fn.getArgByName("certfile") or p = fn.getArgByName("keyfile")) and
    node = p and
    flowKind = "file_api_def" and
    callableName = "__init__" and
    argIndex = p.getPosition() and
    receiver = "ModbusTlsServer" and
    moduleHint = moduleHintOf(fn) and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  not excludedPath(node.getLocation().getFile().getAbsolutePath())
select
  node,
  "sink_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind
