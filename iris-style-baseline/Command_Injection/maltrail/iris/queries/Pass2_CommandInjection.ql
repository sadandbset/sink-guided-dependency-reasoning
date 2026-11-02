/**
 * @name Pass 2: Command/Argument Injection (CWE-78)
 * @description Tracks the HTTP request surface of the maltrail reporting server
 *   (request line, headers, POST body, parse_qs-decoded query parameters, the
 *   client socket address, and the `_%s`-dispatched handler parameters) into shell
 *   command strings executed via subprocess with shell=True. Sources, sinks,
 *   barriers and additional taint steps are rendered from the human-reviewed labels
 *   in iris/labels/labels.json (run maltrail-iris-pass2-20261015, pass 2,
 *   classification tp only): one location-pinned tp sink site (core/httpd.py:399,
 *   the `logger` command in ReqHandler._login whose `%`-format substitutions are
 *   params.get("username") and self.client_address) and an empty confirmed
 *   sanitizer set (no quoting/escaping exists anywhere in snapshot bb4d24b0; the
 *   login check is not a gate — the sink executes for failed logins too).
 * @id py/augur/maltrail/pass2-command-injection
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
 * it delegates to MySanitizers, whose confirmed set is EMPTY (no shlex/quote/escape
 * call exists anywhere in the snapshot and the login validity check does not gate
 * the sink), so it resolves to none(); it never blocks unconditionally.
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
  "Command injection: attacker-controlled HTTP request value (request parameter, " +
  "header, POST body or client address) flows unquoted into a shell command string " +
  "executed with shell=True."
