/**
 * @name Pass 2 diagnostics: Command/Argument Injection candidate paths (CWE-78)
 * @description DIAGNOSTICS QUERY — NOT a formal vulnerability result. Uses the
 *   "command_injection_diagnostics" pass key to additionally include the
 *   labels.json entries classified `candidate` (pending human review,
 *   label_stats.md "Candidate" sections): the candidate subprocess site
 *   (sensor.py:1037, the schedtool command whose substitution values are internally
 *   derived), the remote feed/update content sources (retrieve_content/urlopen,
 *   67 entries), and the second-order network-derived event-log/trails/ipcat file
 *   reads (11 entries). The diagnostics sink family is unpinned, so every
 *   subprocess site in the repo is reachable here (the six static-literal sites
 *   produce no flow — all-literal command strings). Per the Phase-1 review no path
 *   from the candidate sources to a command string exists in this snapshot; run
 *   only to verify recall of unreviewed labels. Findings from this query must not
 *   be counted as formal pass-2 results.
 * @id py/augur/maltrail/pass2-command-injection-diagnostics
 * @kind path-problem
 * @problem.severity warning
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
 * Same shape as Pass2Config in queries/Pass2_CommandInjection.ql, but with the
 * diagnostics pass key: confirmed (tp) sources/sinks plus the candidate set.
 */
module Pass2DiagnosticsConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    MySources::isSource(source, "command_injection_diagnostics")
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "command_injection_diagnostics")
  }

  predicate isBarrier(DataFlow::Node node) {
    MySanitizers::isBarrier(node, "command_injection_diagnostics")
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "command_injection_diagnostics")
  }
}

module Pass2DiagnosticsFlow = TaintTracking::Global<Pass2DiagnosticsConfig>;
import Pass2DiagnosticsFlow::PathGraph

from Pass2DiagnosticsFlow::PathNode source, Pass2DiagnosticsFlow::PathNode sink
where Pass2DiagnosticsFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "[DIAGNOSTICS ONLY - candidate label path] Potential command injection path " +
  "reaching a subprocess command execution site."
