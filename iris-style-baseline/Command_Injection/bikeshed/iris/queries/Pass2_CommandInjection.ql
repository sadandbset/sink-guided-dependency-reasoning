/**
 * @name Bikeshed command injection (CWE-78)
 * @description Tracks attacker-influenced data from Bikeshed's labeled input
 *   boundaries (spec document file/stdin/https-URL content, the argparse CLI
 *   surface, and retained local-file candidate reads) into command-execution
 *   sinks (subprocess/os shell invocations at their labeled sites) and their
 *   labeled wrapper parameters, using the reviewed Pass 2 label set of run
 *   bikeshed-iris-pass2-step3-20261013. Sources and sinks are exactly the
 *   labeled (tp, candidate) sites; refuted fp sites are not modeled.
 * @id py/bikeshed/iris/pass2-command-injection
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @tags security
 *       external/cwe/cwe-078
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

/** Flow configuration for the Bikeshed Pass 2 (CWE-78) taint analysis. */
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
  "Tainted data from a labeled input boundary reaches a command-execution sink (CWE-78)."
