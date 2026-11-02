/**
 * @name Ansible: path traversal from untrusted boundaries to file operations
 * @description Tracks untrusted path data (playbook-templated lookup terms, host variables/remote facts, remote module output, galaxy tar member names, fetch dest name components) into file access, file creation/modification, archive extraction and ansible file-transfer channels on the controller. Pass 1 of the Augur/IRIS flow (CWE-022/023/036/073), rendered from the reviewed labels in iris/labels/labels.json.
 * @id py/augur/ansible/pass1-path-traversal
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
  "Untrusted path data (Pass 1 source: lookup terms / host variables / remote module output / galaxy tar member / fetch dest name) flows into this file operation (path traversal, CWE-022/023/036/073)."
