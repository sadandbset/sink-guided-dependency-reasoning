/**
 * @name Path traversal from untrusted request input to filesystem access
 * @description Finds flows where untrusted HTTP request input (flask request
 *   layer, request_params alias, session) reaches the path argument of a
 *   filesystem access API (builtin open or os.remove). The audited whoogle-search
 *   /config route joins request.args 'name' under CONFIG_PATH and opens it with
 *   no containment, so '..', absolute paths and drive letters escape the
 *   intended root (CWE-22/23/36/73).
 * @id py/augur/whoogle-search/pass1-path-traversal
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
  "Untrusted request input reaches the path argument of a filesystem access API with no containment check, allowing traversal outside the intended base directory (CWE-22/23/36/73)."
