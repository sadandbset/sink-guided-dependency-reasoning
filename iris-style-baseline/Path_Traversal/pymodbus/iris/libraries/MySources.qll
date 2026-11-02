/**
 * Augur-generated taint source models (Phase 2, Step 4).
 *
 * Project : pymodbus (pymodbus_vuln snapshot, 3.6.0dev)
 * Pass    : 1 - Path Traversal (CWE-022 / CWE-023 / CWE-036 / CWE-073)
 * Labels  : iris/labels/labels.json, pass_id=1, role=source entries
 *           S05, S06, S07 (classification tp)
 *
 * Only the three reviewed, actually attacker-controllable HTTP input
 * boundaries are modeled: the `request.path` attribute reads inside the
 * aiohttp request handlers of ModbusSimulatorServer
 * (pymodbus/server/simulator/http_server.py). Every other Phase 1 source
 * candidate (CLI args, constructor params, logging-config params, contrib
 * helper params) was reviewed and rejected as an operator/embedding-app
 * boundary with no attacker privilege differential, and is therefore NOT
 * modeled here.
 *
 * Sources are anchored structurally (file + enclosing handler function +
 * receiver name) rather than by line number, so the rules keep matching the
 * labeled call sites while remaining robust to line drift.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  /**
   * Holds if `source` is a reviewed untrusted-input boundary for the given
   * pass key. Only "path_traversal" (Pass 1) is defined in this project.
   */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "path_traversal" and
    exists(Attribute attr |
      isReviewedRequestPathRead(attr) and
      source.asExpr() = attr
    )
  }

  /**
   * Matches the `request.path` attribute reads labeled S05/S06/S07:
   *
   *   - S05: handle_html_static (http_server.py:260), flows to
   *          os.path.join -> open / web.FileResponse (the only
   *          request-reachable file flow in this codebase);
   *   - S06: handle_html (http_server.py:271), dict-key usage only;
   *   - S07: handle_json (http_server.py:287), dict-key usage only.
   *
   * The receiver expression is the aiohttp request object (`request`,
   * the handler parameter); `request.path` is the client-controlled,
   * percent-decoded URL path.
   */
  private predicate isReviewedRequestPathRead(Attribute attr) {
    attr.getName() = "path" and
    attr.getObject() instanceof Name and
    attr.getObject().(Name).getId() = "request" and
    inSimulatorHttpServerFile(attr) and
    isSimulatorHandlerFunction(attr.getScope().(Function))
  }

  /** The three labeled aiohttp handler methods of ModbusSimulatorServer. */
  private predicate isSimulatorHandlerFunction(Function f) {
    f.getName() = "handle_html_static"
    or
    f.getName() = "handle_html"
    or
    f.getName() = "handle_json"
  }

  /**
   * Anchors a node to pymodbus/server/simulator/http_server.py
   * (unique file of that basename in the extracted database; `%` wildcards
   * make the pattern separator- and prefix-agnostic).
   */
  private predicate inSimulatorHttpServerFile(AstNode n) {
    n.getLocation().getFile().getAbsolutePath().matches(
      "%pymodbus%server%simulator%http_server.py"
    )
  }
}
