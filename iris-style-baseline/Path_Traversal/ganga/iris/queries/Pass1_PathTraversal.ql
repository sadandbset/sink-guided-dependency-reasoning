/**
 * @name Pass 1: Path traversal in ganga GUI file browsers and internal API
 * @description Tracks attacker-controlled path data from the reviewed GangaGUI boundaries into filesystem accesses: the two Flask path-converter browser routes (/job/<id>/browse/<path:path> and /storage/<path:path>) join the request path into the job/storage roots with an unchecked os.path.join and reach send_file/listdir (read) and, on the storage POST branch, storagefile.save (write - only the uploaded FILENAME is sanitized by secure_filename, never the route-path directory); the unauthenticated localhost-bound internal API flows its 'path' query parameter through the GPI export/load wrappers into builtin open (write/read). The GPI namespace is populated at runtime, so bridge taint steps connect the reviewed call sites; abspath/expandvars/expanduser normalization is modeled as propagation (not a barrier) because it normalizes without confining to a base directory.
 * @id py/augur/ganga/pass1-path-traversal
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
  "Tainted request-derived path data ($@) reaches a filesystem access on the ganga GUI/internal-API surface. The reviewed chains join the request path without canonicalization or base-directory containment: the job/storage browsers os.path.join the route path and serve it via send_file/listdir (arbitrary file read), the storage upload writes through the unsanitized route-path directory component to FileStorage.save (arbitrary file write - secure_filename covers only the filename), and the unauthenticated internal-API export/load 'path' parameter reaches builtin open through the GPI wrappers (arbitrary file write/read) (CWE-022/023/036/073).",
  source.getNode(), "this request path value"
