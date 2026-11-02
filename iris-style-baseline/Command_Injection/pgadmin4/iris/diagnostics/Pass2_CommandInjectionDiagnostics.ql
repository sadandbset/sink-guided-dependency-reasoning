/**
 * @name Pass 2 diagnostics: Command/Argument Injection candidate paths (CWE-78)
 * @description DIAGNOSTICS QUERY — NOT a formal vulnerability result. Uses the
 *   "command_injection_diagnostics" pass key to additionally include the
 *   labels.json entries classified `candidate` (pending human review,
 *   phase1_review.md §6): the 5 candidate sink sites (passexec.py:36 stored
 *   passexec_cmd behind the SERVER_MODE gate, master_password.py:140
 *   hook-template with username substitution, psql/__init__.py:182 argv-list
 *   Popen and :237 cmd.exe write of the user's own psql terminal,
 *   utils/__init__.py:375 unescaped getoutput probe on the second-order
 *   preference path) and the 24 candidate sources (cloud-provider REST
 *   response / upgrade-check / deploy-log decodes, binary-path preference
 *   values). The diagnostics sink family is unpinned, so every
 *   subprocess/os.popen site in the repo is reachable here (the rejected
 *   static-literal sites produce no flow — all-literal command strings). Per
 *   the Phase-1 review no confirmed path exists from the candidate remote
 *   sources to a command string in this snapshot; run only to verify recall
 *   of the unreviewed labels and the internal wrapper propagation (e.g.
 *   BatchProcess construction → start() transport). Findings from this query
 *   must not be counted as formal pass-2 results.
 * @id py/augur/pgadmin4/pass2-command-injection-diagnostics
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
 * Same shape as Pass2Config in queries/Pass2_CommandInjection.ql, but with
 * the diagnostics pass key: confirmed (tp) sources/sinks plus the candidate
 * set and the unpinned command-execution family.
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
  "[DIAGNOSTICS ONLY - candidate label path] Potential command injection " +
  "path reaching a command-execution site (candidate/unreviewed labels and " +
  "internal wrapper propagation included; not a formal pass-2 finding)."
