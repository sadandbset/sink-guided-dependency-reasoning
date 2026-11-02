/**
 * @name Pass 2: Command injection (CWE-78)
 * @description Tracks attacker-controlled CLI input (Typer `check` command arguments) into the shell command executed by os.system via the run() wrapper.
 * @id py/augur/abilian-devtools/pass2-command-injection
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

private module Pass2Config implements DataFlow::ConfigSig {
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
  "CLI-provided file or directory name reaches a shell command executed by os.system (CWE-78)."
