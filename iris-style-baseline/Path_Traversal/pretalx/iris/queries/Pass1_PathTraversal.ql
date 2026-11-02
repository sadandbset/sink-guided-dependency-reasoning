/**
 * @name Pass 1: Path traversal in pretalx file handling
 * @description Tracks attacker-controlled inputs (Django request fields, form-validated upload values, URL route variables, cfp wizard session data) into filesystem access and file-response sinks (get_static's uncontained static-path open, HTML-export raw pathlib joins, Django storage save/open/delete). Rendered from Augur pass 1 labels (run pretalx-pathtraversal-pass1-20261022) via libraries/My{Sources,Sinks,Sanitizers,Summaries}.qll.
 * @id py/augur/pretalx/pass1-path-traversal
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
  "Pass 1 (CWE-22/23/36/073): attacker-controlled input flows into a filesystem access or file-response sink; the path is not contained by an allowed root before the file access."
