/**
 * @name mindsdb Pass 1: Path Traversal
 * @description Tracks untrusted external input (Flask request reads on the
 *   public HTTP API, python-multipart upload filenames, the SQL / MySQL /
 *   Mongo wire-protocol boundaries, and the integration connection-args
 *   boundary) into filesystem operations on attacker-influenced paths:
 *   file open/read/write, archive open and extraction, file/directory
 *   delete, move and copy destinations, sqlite database files and file
 *   responses. Sources, sinks, barriers and additional propagation steps
 *   are generated from the reviewed Pass 1 labels (CWE-22/23/36/73) for
 *   mindsdb 23.2.2.1.
 * @id py/augur/mindsdb/pass1-path-traversal
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
  "Path traversal (CWE-22/23/36/73): untrusted external input flows into a filesystem operation on an attacker-influenced path."
