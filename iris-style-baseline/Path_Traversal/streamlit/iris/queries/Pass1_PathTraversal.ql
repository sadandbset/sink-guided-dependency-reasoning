/**
 * @name Streamlit: path traversal from request input to filesystem access
 * @description Finds flows in the streamlit framework where untrusted request data
 *   (tornado route captures, request fields/arguments, multipart upload fields)
 *   reaches the path argument of a filesystem operation such as open(), os.remove(),
 *   shutil.rmtree() or a template render. The confirmed example is the
 *   /component/(.*) route: the attacker-controlled capture is joined onto the
 *   component root without any containment check and opened
 *   (lib/streamlit/components/v1/components.py:310-325).
 * @id py/augur/streamlit/pass1-path-traversal
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

module Pass1PathTraversalConfig implements DataFlow::ConfigSig {
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

module Pass1PathTraversalFlow = TaintTracking::Global<Pass1PathTraversalConfig>;
import Pass1PathTraversalFlow::PathGraph

from Pass1PathTraversalFlow::PathNode source, Pass1PathTraversalFlow::PathNode sink
where Pass1PathTraversalFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted request data ($source) flows to the filesystem path argument of $sink. " +
  "A path built from this data can contain '../' segments, percent-encoded traversal, " +
  "or an absolute path that escapes the intended root directory."
