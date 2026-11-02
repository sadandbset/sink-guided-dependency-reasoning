/**
 * @name Pass 1: Path traversal in aiohttp request-to-file flows
 * @description Tracks attacker-controlled request path data (the HTTP request line, raw/decoded request path reads, the routed match_info static filename, and multipart Content-Disposition filenames) into filesystem access positions: the static-file serving pipeline (FileResponse construction, stat, open, sendfile), path probes, and directory listings. The reviewed barriers model the StaticResource anchor rejection and canonicalize-then-contain guard; alert paths that pass the containment check are expected to be triaged by the Step 6 heuristics (base-directory containment -> FP).
 * @id py/augur/aiohttp/pass1-path-traversal
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
  "Tainted request-derived path data flows into a filesystem access. If this path is not protected by the StaticResource canonicalize-then-contain guard (resolve + relative_to) or the anchor rejection, an attacker may traverse outside the intended base directory (CWE-022/023/036/073)."
