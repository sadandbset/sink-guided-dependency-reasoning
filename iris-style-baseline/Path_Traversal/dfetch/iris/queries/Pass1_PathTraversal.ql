/**
 * @name Path traversal in dfetch via manifest-controlled paths
 * @description Finds flows from untrusted dfetch input boundaries (dfetch.yaml
 *   manifest fields, fetched-project .dfetch_data.yaml content, and git/svn
 *   subprocess output) into dangerous filesystem positions: destination
 *   directory creation/removal (mkdir with parents, rmtree, os.remove),
 *   'svn export' destinations, metadata reads/writes at destination-derived
 *   paths, patch-file reads and patch application roots, working-directory
 *   changes and subtree moves. The dominant unvalidated value is the manifest
 *   'dst' field (schema validation is type-only; absolute and '..'-containing
 *   destinations escape the CWD scoping entirely), with 'src' and 'patch'
 *   fields and the 'name' field (patch-file writes) following.
 * @id py/augur/dfetch/pass1-path-traversal
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
  "Untrusted dfetch input ($@) flows to a filesystem operation at an attacker-influenced path.",
  source.getNode(), "this input boundary"
