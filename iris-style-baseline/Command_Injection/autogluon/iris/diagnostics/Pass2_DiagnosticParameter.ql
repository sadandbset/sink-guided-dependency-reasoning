/**
 * @name DIAGNOSTIC (NOT a vulnerability query): AutoGluon Pass 2 parameter propagation check
 * @description Verifies only whether the parameter proccess_id_string of sync_training_processes can propagate to the shell=True command argument of subprocess.check_output at core/src/autogluon/core/utils/sync_remote.py:50 and :52. This query uses the diagnostic source model (label p2-src-4863): a positive result confirms parameter-to-command propagation inside the model but does NOT prove external attacker control. It must NOT be reported as a CWE-78 vulnerability detection and must NOT be counted as a true positive in the Augur final report.
 * @id py/augur/autogluon/pass2-diagnostic-parameter
 * @kind path-problem
 * @problem.severity warning
 * @precision low
 * @tags diagnostic
 *       external/cwe/cwe-078
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

module Pass2DiagnosticConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Diagnostic source ONLY: label p2-src-4863,
    // sync_training_processes.proccess_id_string (arg 0, sync_remote.py:46).
    MySources::isSourceSyncTrainingProcessId(source)
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

module Pass2DiagnosticFlow = TaintTracking::Global<Pass2DiagnosticConfig>;
import Pass2DiagnosticFlow::PathGraph

from Pass2DiagnosticFlow::PathNode source, Pass2DiagnosticFlow::PathNode sink
where Pass2DiagnosticFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "DIAGNOSTIC ONLY - do not count as a finding or TP: the parameter proccess_id_string of sync_training_processes reaches the shell=True command argument of subprocess.check_output in autogluon.core.utils.sync_remote. This shows in-model propagation only; the sole in-repo caller passes the fixed literal 'dask-scheduler', so it does not establish external attacker control."
