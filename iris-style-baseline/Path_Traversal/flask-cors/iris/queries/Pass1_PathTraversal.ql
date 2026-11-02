/**
 * @name Pass 1 Path Traversal (flask-cors)
 * @description Tracks attacker-controlled Flask request values (request.path, request.headers, request.method, Origin / Access-Control-Request-Method / Access-Control-Request-Headers header reads in flask_cors) to the file-open path argument (builtin open, argument 0) for path traversal (CWE-022, CWE-023, CWE-036, CWE-073). Built strictly from the reviewed Pass 1 labels (iris/labels/labels.json, run flask-cors-path-traversal-pass1-20261022).
 * @id py/augur/flask-cors/pass1-path-traversal
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
  "Pass 1 path traversal: an attacker-controlled Flask request value flows into the path argument of a file-open call."
