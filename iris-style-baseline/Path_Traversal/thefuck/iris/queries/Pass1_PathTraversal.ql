/**
 * @name Pass 1: Path traversal from untrusted input into file operations
 * @description Flows of untrusted data (archive entry names, the failed
 *   command's terminal output/argv, CLI arguments and path-valued
 *   environment variables) into the path argument of file operations
 *   (open/create/truncate, file deletion, directory creation, archive
 *   opens and code loads), based on the reviewed Augur pass-1 labels for
 *   thefuck 3.30.
 * @id py/augur/thefuck/pass1-path-traversal
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
  "Untrusted data from a reviewed pass-1 source (archive entry name, command output/argv, CLI or path-valued environment input) flows into the path argument of this file operation and can reach an unintended location (path traversal)."
