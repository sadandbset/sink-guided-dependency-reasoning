/**
 * @name Pass 1: Path traversal in fides catch-all route file serving
 * @description Tracks the attacker-controlled catch-all route parameter (request.path_params["catchall"], percent-decoded by the Starlette router) through the admin-UI static-file pipeline: the match_route fixed-map selector (no path derivation), the get_path_to_admin_ui_file pathlib join (which preserves ".." lexically), the is_file existence probe and the FileResponse file response. The path_is_in_ui_directory guard is deliberately NOT modeled as a barrier: it compares the UI directory against the LEXICAL parents of the unresolved path, which still contain the UI directory for ".."-laden paths, so it does not confine the served file; alert paths are expected to be triaged by the Step 6 heuristics.
 * @id py/augur/fides/pass1-path-traversal
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

module Pass1Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    MySources::isSource(source, "path_traversal")
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "path_traversal")
  }

  predicate isBarrier(DataFlow::Node node) {
    MySanitizers::isBarrier(node, "path_traversal")
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "path_traversal")
  }
}

module Pass1Flow = TaintTracking::Global<Pass1Config>;
import Pass1Flow::PathGraph

from Pass1Flow::PathNode source, Pass1Flow::PathNode sink
where Pass1Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Tainted request-derived path data ($@) reaches a filesystem access on the catch-all static-file route. The requested path is joined into the packaged admin-UI directory without canonicalization and the lexical path_is_in_ui_directory guard does not reject '..' segments, so the served file may escape the UI root (CWE-022/023/036/073).",
  source.getNode(), "this request path parameter"
