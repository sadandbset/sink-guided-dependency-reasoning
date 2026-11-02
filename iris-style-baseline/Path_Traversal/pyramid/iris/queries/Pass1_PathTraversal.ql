/**
 * @name Pass 1: Path traversal in pyramid request-driven file access
 * @description Tracks attacker-controlled request data (URL path/subpath, route match values, request params/cookies incl. the _LOCALE_ locale name, WSGI environ entries) into filesystem access and file-response sinks (FileResponse/open static-file serving, locale-negotiated translation directory listdir/open, pkg_resources resource resolution). Rendered from Augur pass 1 labels (run pyramid-pass1-pathtraversal-20261023) via libraries/My{Sources,Sinks,Sanitizers,Summaries}.qll; the _secure_path/split_path_info guards reviewed in Phase 1 are modeled as barriers.
 * @id py/augur/pyramid/pass1-path-traversal
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
  "Pass 1 (CWE-22/23/36/073): attacker-controlled request data reaches a filesystem access or file-response sink (open/listdir/metadata/pkg_resources/FileResponse) without the path being contained by an allowed root."
