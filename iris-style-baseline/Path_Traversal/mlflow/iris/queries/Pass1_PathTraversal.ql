/**
 * @name Pass 1: Path traversal in mlflow artifact serving
 * @description Tracks attacker-controlled request paths (artifact download / list / delete / upload endpoints of the mlflow tracking and mlflow-artifacts server) into filesystem access and file-response sinks. Rendered from Augur pass 1 labels (run mlflow-pt-pass1-20261022) via libraries/My{Sources,Sinks,Sanitizers,Summaries}.qll.
 * @id py/augur/mlflow/pass1-path-traversal
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
  "Pass 1 (CWE-22/23/36/073): request-derived path flows to a filesystem access or file-response sink; the artifact path is not contained by an allowed root before the file access."
