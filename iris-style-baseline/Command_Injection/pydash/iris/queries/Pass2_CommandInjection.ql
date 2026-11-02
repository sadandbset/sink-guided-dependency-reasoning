/**
 * @name Pass 2: Command injection via invoke.run shell command string
 * @description Finds untrusted data (invoke CLI task parameters such as
 *   `inv test --args` / `inv docs --bind --port`, or environment-derived values)
 *   flowing into the shell command string passed as the first argument of
 *   `invoke.run`, which is executed through the shell (equivalent of
 *   `shell=True`). Rendered by Augur Phase 2 Step 4 from the human-reviewed
 *   Pass 2 labels in iris/labels/labels.json (CWE-78).
 * @id py/augur/pydash/pass2-command-injection
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-077
 *       external/cwe/cwe-088
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

module Pass2Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    MySources::isSource(source, "command_injection")
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "command_injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    MySanitizers::isBarrier(node, "command_injection")
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "command_injection")
  }
}

module Pass2Flow = TaintTracking::Global<Pass2Config>;
import Pass2Flow::PathGraph

from Pass2Flow::PathNode source, Pass2Flow::PathNode sink
where Pass2Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Command injection: untrusted data (CLI task parameter or environment-derived value) flows into the shell command string passed to invoke.run()."
