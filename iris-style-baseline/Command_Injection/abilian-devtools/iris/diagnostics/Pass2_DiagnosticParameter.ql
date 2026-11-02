/**
 * @name Pass 2 diagnostic: internal parameter reaches command sink
 * @description Diagnostic only - NOT a vulnerability query. Verifies that the p2-supp-001 source (parameter `args` of the Typer `check` handler) is connected to the modeled Pass 2 sinks under the same taint configuration, to validate the generated libraries. Must not be merged into official Pass 2 results.
 * @id py/augur/abilian-devtools/pass2-diagnostic-parameter
 * @kind problem
 * @problem.severity warning
 * @tags diagnostics
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

private module Pass2DiagConfig implements DataFlow::ConfigSig {
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

module Pass2DiagFlow = TaintTracking::Global<Pass2DiagConfig>;

from Pass2DiagFlow::PathNode source, Pass2DiagFlow::PathNode sink
where Pass2DiagFlow::flowPath(source, sink)
select sink.getNode(),
  "Sink reachable from internal parameter source (" +
    source.getNode().toString() +
    ") - diagnostic check, not a vulnerability result."
