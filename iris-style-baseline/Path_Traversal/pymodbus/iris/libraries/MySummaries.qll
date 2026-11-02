/**
 * Augur-generated taint summary models (Phase 2, Step 4).
 *
 * Project : pymodbus (pymodbus_vuln snapshot, 3.6.0dev)
 * Pass    : 1 - Path Traversal (CWE-022 / CWE-023 / CWE-036 / CWE-073)
 * Labels  : iris/labels/labels.json, pass_id=1, role=summary entry
 *           K10 (classification tp)
 *
 * Exactly one additional taint step is modeled, and it is required for the
 * only request-reachable file flow:
 *
 *   K10 - os.path.join(self.web_path, page) at
 *   pymodbus/server/simulator/http_server.py:262, inside
 *   ModbusSimulatorServer.handle_html_static:
 *
 *     page (arg 1, from request.path[1:] - source S05)
 *       -> os.path.join(...) call result
 *       -> file -> open(file) (K11) / web.FileResponse(file) (K12)
 *
 * Rationale (real-code evidence, not an unconditional cross-function edge):
 *   - The join result is assigned unchanged to `file` and passed unchanged
 *     to open() (:264) and web.FileResponse() (:265); nothing between the
 *     join and the file access inspects or normalizes the path, so taint
 *     on any argument of this specific call must reach its result for the
 *     labeled flow to be tracked. The reviewed tainted position is
 *     argument index 1 (`page`); argument 0 is the fixed package-relative
 *     base self.web_path (http_server.py:166) and carries no taint, so
 *     propagating from any argument adds no spurious edge.
 *   - The rule is anchored to this one reviewed call site (file + enclosing
 *     function + os.path.join callee shape). The other os.path.join calls
 *     in the same file (:166, :200) and the pathlib joinpath call
 *     (repl/client/main.py:157) were reviewed in Phase 1 as
 *     constant-operand constructions and get no summary edge.
 *   - If the installed codeql/python-all pack already ships an
 *     os.path.join arg->result taint model, this step is redundant but
 *     harmless (it only re-asserts propagation on one call site).
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  /**
   * Holds if taint may flow from `nodeFrom` to `nodeTo` in addition to the
   * normal data-flow steps, for the given pass key.
   * Only "path_traversal" (Pass 1) is defined in this project.
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and
    exists(Call call |
      isReviewedStaticPathJoinCall(call) and
      nodeFrom.asExpr() = call.getArg(_) and
      nodeTo.asExpr() = call
    )
  }

  /**
   * Matches the K10-labeled call `os.path.join(self.web_path, page)`
   * (callee of the form `<expr>.path.join(...)`, anchored to
   * handle_html_static in the simulator http server).
   */
  private predicate isReviewedStaticPathJoinCall(Call call) {
    call.getFunc() instanceof Attribute and
    call.getFunc().(Attribute).getName() = "join" and
    call.getFunc().(Attribute).getObject() instanceof Attribute and
    call.getFunc().(Attribute).getObject().(Attribute).getName() = "path" and
    inSimulatorHttpServerFile(call) and
    inFunction(call, "handle_html_static")
  }

  /** Anchors to pymodbus/server/simulator/http_server.py (unique in the DB). */
  private predicate inSimulatorHttpServerFile(AstNode n) {
    n.getLocation().getFile().getAbsolutePath().matches(
      "%pymodbus%server%simulator%http_server.py"
    )
  }

  /** Holds if `n` occurs directly inside the function `functionName`. */
  private predicate inFunction(AstNode n, string functionName) {
    n.getScope() instanceof Function and
    n.getScope().(Function).getName() = functionName
  }
}
