/**
 * Machine-generated from reviewed Phase 1 labels (iris/labels/labels.json, pass 1).
 * Run: streamlit-pathtraversal-pass1-20261023. Do not edit by hand.
 *
 * Additional taint propagation edges for pass key "path_traversal"
 * (Path Traversal, CWE-22/23/36/73).
 *
 * Only edges that are (a) evidenced by real code and (b) necessary for the labeled
 * flows are defined. Verified against the local codeql/python-all 7.1.2 pack
 * (semmle/python/dataflow/new/internal/TaintTrackingPrivate.qll):
 *
 * Already modeled by the default TaintTracking library — NO custom edge needed:
 *  - str.split / str.rsplit receiver -> result
 *    (TaintTrackingPrivate.qll:126-129, stringManipulation) — covers
 *    `path.split("/")` in ComponentRequestHandler.get (components.py:311).
 *  - subscript read: object -> subscript expression
 *    (TaintTrackingPrivate.qll:86-88, subscriptStep) — covers `parts[1:]`
 *    (components.py:319).
 *  - str.join argument 0 -> result
 *    (TaintTrackingPrivate.qll:133-134, stringManipulation) — covers
 *    `"/".join(parts[1:])` (components.py:319).
 *
 * NOT modeled by the default library — custom edge defined below:
 *  - os.path.join: taint of ANY argument -> joined result. The default join rule
 *    only propagates from argument 0 (the string-manipulation rule misapplies to
 *    os.path.join), but in the confirmed flow the tainted operand is argument 1
 *    (`filename`, components.py:320), so without this edge the reviewed
 *    src-012 -> sink-009 flow would not be tracked.
 *
 * No other wrappers get edges: unquote_plus (routes.py:130) feeds a response header,
 * not a path; os.path.expanduser (server.py:189) is on an operator-config flow;
 * open_python_file / streamlit_read / streamlit_write / _require_arg /
 * parse_body_arguments / BackMsg deserialization are recorded as modeling gaps in
 * report/query_generation_notes.md instead of being given unconditional edges.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  /** Holds if taint flows from `nodeFrom` to `nodeTo` via a pass 1 summary edge. */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and
    osPathJoinStep(nodeFrom, nodeTo)
  }

  /**
   * os.path.join(...) propagates path text from any argument to the joined result.
   * This is a genuine path wrapper (not a barrier): a tainted `filename` joined onto
   * a fixed `component_root` keeps the traversal payload, which is exactly the
   * mechanism of the confirmed flow at components.py:320:
   *   `abspath = os.path.join(component_root, filename)`
   * All 11 os.path.join call sites in lib/streamlit are genuine path-text
   * propagation sites (see exploration/detection.json, sanitizer_and_validation_
   * evidence: os.path.join sites treated as propagation nodes, not barriers).
   */
  private predicate osPathJoinStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call call, Attribute func, Attribute qual, Name root, Expr arg |
      func = call.getFunc().(Attribute) and
      func.getName() = "join" and
      qual = func.getValue().(Attribute) and
      qual.getName() = "path" and
      root = qual.getValue().(Name) and
      root.getId() = "os" and
      inLibStreamlit(call) and
      arg = call.getAnArg() and
      nodeFrom = DataFlow::exprNode(arg) and
      nodeTo = DataFlow::exprNode(call)
    )
  }

  /**
   * Holds if `n` is located in the lib/streamlit package — the Phase 1 extraction
   * scope (excludes lib/tests, e2e, scripts, and the nested streamlit-db directory).
   */
  private predicate inLibStreamlit(AstNode n) {
    exists(File f, string abs |
      f = n.getLocation().getFile() and
      abs = f.getAbsolutePath().replaceAll("\\\\", "/") and
      abs.matches("%.*/lib/streamlit/%")
    )
  }
}
