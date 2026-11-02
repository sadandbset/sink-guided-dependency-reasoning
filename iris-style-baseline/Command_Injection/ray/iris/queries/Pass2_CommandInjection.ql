/**
 * @name Ray command/argument injection (pass 2)
 * @description Tracks data from ray's unauthenticated remote boundaries (dashboard head/agent HTTP
 *   API, gRPC reporter/log/client servicers, serve ingress, runtime-env agent) into the Phase-1
 *   labeled command execution sites: the job entrypoint shell exec (subprocess.Popen(shell=True)),
 *   the py-spy profiling shell commands (asyncio.create_subprocess_shell), the runtime-env worker
 *   exec (os.execvp bash -c / Popen shell=True) and the autoscaler ssh/docker exec engine.
 * @id py/augur/ray/pass2-command-injection
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
  "Untrusted data from a remote boundary flows into a system command executed on this line (pass 2 / CWE-78, labels ray-iris-pass2-20261016)."
