/**
 * @name Pass 2: Command/Argument Injection (CWE-78)
 * @description Tracks network input from the paired phone (TCP plugin protocol, UDP
 *   server-search channel, JSON-RPC request params) into shell command strings executed
 *   via subprocess with shell=True. Sources, sinks, barriers and additional taint steps
 *   are rendered from the human-reviewed labels in iris/labels/labels.json
 *   (run dcnnt-py-iris-pass2-20261015-r2, pass 2, classification tp only): five
 *   location-pinned tp sink sites (file_transfer.py:110, notifications.py:58,
 *   opener.py:34, opener.py:44, sync.py:318) and an empty confirmed sanitizer set
 *   (no shlex/escaping exists anywhere in snapshot 4084ea1).
 * @id py/augur/dcnnt-py/pass2-command-injection
 * @kind path-problem
 * @problem.severity error
 * @precision low
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

/**
 * Pass 2 (CWE-78) flow configuration. The pass key "command_injection" selects the
 * reviewed (tp) label set. The barrier predicate always exists (WORKFLOW.md 5.2.3) —
 * it delegates to MySanitizers, whose confirmed set is EMPTY in run r2 (shlex.quote
 * does not exist in snapshot 4084ea1), so it resolves to none(); it never blocks
 * unconditionally.
 */
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
  "Command injection: attacker-controlled value from the phone-side protocol flows " +
  "unquoted into a shell command executed with shell=True."
