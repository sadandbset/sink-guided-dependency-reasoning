/**
 * Augur-generated taint sink models (Phase 2, Step 4).
 *
 * Project : pymodbus (pymodbus_vuln snapshot, 3.6.0dev)
 * Pass    : 1 - Path Traversal (CWE-022 / CWE-023 / CWE-036 / CWE-073)
 * Labels  : iris/labels/labels.json, pass_id=1, role=sink entries
 *           K03, K04, K06, K11, K12, K13, K16, K21 (classification tp)
 *
 * Every sink below is an actual file-access / file-response / file-write
 * API at its reviewed call site, and the bound sink node is the *dangerous
 * path argument* (a path string expression), never the opened file object.
 * Path-construction helpers (os.path.join / Path.joinpath) and
 * constant-operand sites were reviewed and rejected in Phase 1 and are NOT
 * sinks here; the tainted os.path.join call is modeled in MySummaries.qll.
 *
 * Anchoring is structural: file + enclosing function/method + callee shape
 * + argument position (or keyword name for load_cert_chain), so each rule
 * matches exactly the labeled call site.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  /**
   * Holds if `sink` is a reviewed dangerous file-access argument for the
   * given pass key. Only "path_traversal" (Pass 1) is defined.
   */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "path_traversal" and
    (
      simulatorStaticOpenSink(sink)
      or
      simulatorFileResponseSink(sink)
      or
      simulatorSetupOpenSink(sink)
      or
      explainOpenSink(sink)
      or
      explainCopyfileSink(sink)
      or
      loggingFileHandlerSink(sink)
      or
      replConfigOpenSink(sink)
      or
      certChainLoadSink(sink)
    )
  }

  /**
   * K11 - open(file, encoding="utf-8") at
   * pymodbus/server/simulator/http_server.py:264, inside
   * ModbusSimulatorServer.handle_html_static. Dangerous argument: index 0
   * (the joined static-file path derived from request.path).
   * Read access; only FileNotFoundError/IsADirectoryError -> HTTP 404
   * error handling in the surrounding try block, no path validation.
   */
  private predicate simulatorStaticOpenSink(DataFlow::Node sink) {
    exists(Call call |
      isBuiltinOpenCall(call) and
      inSimulatorHttpServerFile(call) and
      inFunction(call, "handle_html_static") and
      sink.asExpr() = call.getArg(0)
    )
  }

  /**
   * K12 - web.FileResponse(file) at http_server.py:265, inside
   * ModbusSimulatorServer.handle_html_static. Dangerous argument: index 0.
   * File-response access: aiohttp opens and streams the file at the given
   * path as the HTTP response body (aiohttp internals are outside the
   * CodeQL database; the call site passes the same unvalidated joined path
   * that open() at :264 already verified to exist).
   */
  private predicate simulatorFileResponseSink(DataFlow::Node sink) {
    exists(Call call |
      isWebModuleCall(call, "FileResponse") and
      inSimulatorHttpServerFile(call) and
      inFunction(call, "handle_html_static") and
      sink.asExpr() = call.getArg(0)
    )
  }

  /**
   * K06 - open(json_file, encoding="utf-8") at http_server.py:130, inside
   * ModbusSimulatorServer.__init__. Dangerous argument: index 0.
   * Read access (json.load of the operator-supplied setup file); kept as a
   * labeled sink for API-model completeness - the labeled inputs into it
   * are operator/CLI configuration, so no alert is expected.
   */
  private predicate simulatorSetupOpenSink(DataFlow::Node sink) {
    exists(Call call |
      isBuiltinOpenCall(call) and
      inSimulatorHttpServerFile(call) and
      inMethod(call, "ModbusSimulatorServer", "__init__") and
      sink.asExpr() = call.getArg(0)
    )
  }

  /**
   * K03 - open(file, encoding="utf-8") at examples/contrib/explain.py:141,
   * inside annotate_pymodbus_logs. Dangerous argument: index 0.
   * Read access on the caller-supplied log-file path.
   */
  private predicate explainOpenSink(DataFlow::Node sink) {
    exists(Call call |
      isBuiltinOpenCall(call) and
      inExplainContribFile(call) and
      inFunction(call, "annotate_pymodbus_logs") and
      sink.asExpr() = call.getArg(0)
    )
  }

  /**
   * K04 - shutil.copyfile(out_file.name, file) at examples/contrib/explain.py:168,
   * inside annotate_pymodbus_logs. Dangerous argument: index 1 (destination
   * path, the caller-supplied file - the tool rewrites the given log file
   * in place). Write/overwrite access.
   */
  private predicate explainCopyfileSink(DataFlow::Node sink) {
    exists(Call call |
      isModuleCall(call, "shutil", "copyfile") and
      inExplainContribFile(call) and
      inFunction(call, "annotate_pymodbus_logs") and
      sink.asExpr() = call.getArg(1)
    )
  }

  /**
   * K13 - logging.FileHandler(log_file_name) at pymodbus/logging.py:57,
   * inside Log.apply_logging_config. Dangerous argument: index 0.
   * Write access (opens/creates the file for appending).
   */
  private predicate loggingFileHandlerSink(DataFlow::Node sink) {
    exists(Call call |
      isModuleCall(call, "logging", "FileHandler") and
      inPymodbusLoggingFile(call) and
      inMethod(call, "Log", "apply_logging_config") and
      sink.asExpr() = call.getArg(0)
    )
  }

  /**
   * K16 - open(modbus_config_path, encoding="utf-8") at
   * pymodbus/repl/server/main.py:173, inside the typer command run().
   * Dangerous argument: index 0 (the CLI-supplied Path object).
   * Read access (json.load of the operator-selected config).
   */
  private predicate replConfigOpenSink(DataFlow::Node sink) {
    exists(Call call |
      isBuiltinOpenCall(call) and
      inReplServerMainFile(call) and
      inFunction(call, "run") and
      sink.asExpr() = call.getArg(0)
    )
  }

  /**
   * K21 - new_sslctx.load_cert_chain(certfile=certfile, keyfile=keyfile,
   * password=password) at pymodbus/transport/transport.py:132, inside
   * CommParams.generate_ssl. Dangerous argument: the keyword argument
   * "certfile" (label arg_index 0; the sibling keyfile keyword, arg 1, is
   * covered by the same label family). Read access to the certificate and
   * key files.
   */
  private predicate certChainLoadSink(DataFlow::Node sink) {
    exists(Call call, Keyword kw |
      isAttributeCall(call, "load_cert_chain") and
      inTransportFile(call) and
      inFunction(call, "generate_ssl") and
      kw = call.getANamedArg() and
      kw.getArg() = "certfile" and
      sink.asExpr() = kw.getValue()
    )
  }

  /** Matches a builtin `open(...)` call (callee is the bare name `open`). */
  private predicate isBuiltinOpenCall(Call call) {
    call.getFunc() instanceof Name and
    call.getFunc().(Name).getId() = "open"
  }

  /** Matches `<module>.<name>(...)` calls such as `shutil.copyfile(...)`. */
  private predicate isModuleCall(Call call, string moduleName, string callableName) {
    call.getFunc() instanceof Attribute and
    call.getFunc().(Attribute).getName() = callableName and
    call.getFunc().(Attribute).getObject() instanceof Name and
    call.getFunc().(Attribute).getObject().(Name).getId() = moduleName
  }

  /** Matches `web.<name>(...)` calls such as `web.FileResponse(...)` (aiohttp). */
  private predicate isWebModuleCall(Call call, string callableName) {
    isModuleCall(call, "web", callableName)
  }

  /** Matches any `<receiver>.<name>(...)` attribute call. */
  private predicate isAttributeCall(Call call, string callableName) {
    call.getFunc() instanceof Attribute and
    call.getFunc().(Attribute).getName() = callableName
  }

  /** Holds if `n` occurs directly inside the function `functionName`. */
  private predicate inFunction(AstNode n, string functionName) {
    n.getScope() instanceof Function and
    n.getScope().(Function).getName() = functionName
  }

  /** Holds if `n` occurs inside `className.methodName`. */
  private predicate inMethod(AstNode n, string className, string methodName) {
    n.getScope() instanceof Function and
    n.getScope().(Function).getName() = methodName and
    n.getScope().(Function).getEnclosingScope() instanceof Class and
    n.getScope().(Function).getEnclosingScope().(Class).getName() = className
  }

  /** Anchors to pymodbus/server/simulator/http_server.py (unique in the DB). */
  private predicate inSimulatorHttpServerFile(AstNode n) {
    n.getLocation().getFile().getAbsolutePath().matches(
      "%pymodbus%server%simulator%http_server.py"
    )
  }

  /** Anchors to examples/contrib/explain.py (unique in the DB). */
  private predicate inExplainContribFile(AstNode n) {
    n.getLocation().getFile().getAbsolutePath().matches(
      "%examples%contrib%explain.py"
    )
  }

  /** Anchors to pymodbus/logging.py (unique in the DB). */
  private predicate inPymodbusLoggingFile(AstNode n) {
    n.getLocation().getFile().getAbsolutePath().matches(
      "%pymodbus%logging.py"
    )
  }

  /** Anchors to pymodbus/repl/server/main.py (unique in the DB). */
  private predicate inReplServerMainFile(AstNode n) {
    n.getLocation().getFile().getAbsolutePath().matches(
      "%pymodbus%repl%server%main.py"
    )
  }

  /** Anchors to pymodbus/transport/transport.py (unique in the DB). */
  private predicate inTransportFile(AstNode n) {
    n.getLocation().getFile().getAbsolutePath().matches(
      "%pymodbus%transport%transport.py"
    )
  }
}
