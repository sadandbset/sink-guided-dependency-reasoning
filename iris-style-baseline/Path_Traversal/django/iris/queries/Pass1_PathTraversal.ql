/**
 * @name Django path traversal (Pass 1)
 * @description Tracks request-controlled data (URL path, route-injected
 *   view arguments, request parameters/headers/cookies, multipart upload
 *   filenames, the cookie-derived session key) into the dangerous path
 *   operand of filesystem accesses and file responses: the dev
 *   static-serving open/FileResponse, the admin-docs template read, the
 *   FileSystemStorage write/delete chain, the file move fallback, and the
 *   session/cache file backends (CWE-22/23/36/73).
 * @id py/augur/django/pass1-path-traversal
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
  "Request-controlled data reaches the path operand of a filesystem access; " +
  "unescaped traversal can escape the intended root directory (CWE-22/23/36/73)."
