/**
 * @name Paddle Pass 2 diagnostics: wrapper-parameter propagation (NOT a formal finding)
 * @description Diagnostic-only companion to Pass2_CommandInjection. Per the
 *   task directive, internal wrapper parameters are NOT automatically
 *   sources: this query seeds ONLY the wrapper / public-API parameters that
 *   the reviewed labels recorded as Step-4 coverage gaps (labels.json
 *   metadata notes; phase1_review.md section 7) — run_shell_command's cmd,
 *   run_cmd's command, HDFSClient's cmd / hadoop_home / configs, call_cmd's
 *   cmd, _jit_compile's file_path, check_abi_compatibility's compiler, the
 *   public download url, get_online_pass_interval's days/hours,
 *   IrGraph.draw's save_path/name and the PSLib model-loading paths — and
 *   sinks them into the raw process-execution APIs (os.system, os.popen,
 *   subprocess family argument 0 / argv-list elements, core.shell_execute_cmd).
 *   It answers exactly one question per path: does the parameter propagate
 *   to the dangerous call? Results of this query must NOT be counted as
 *   CWE-78 detections or true positives in the Augur final report.
 * @id py/augur/Paddle/pass2-command-injection-diagnostics
 * @kind path-problem
 * @problem.severity warning
 * @precision low
 * @tags diagnostic
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

/**
 * Diagnostics configuration. Source side = wrapperParamSource only (the
 * diagnostics pass key in MySources); sink side = raw exec APIs only (the
 * wrapper-parameter sinks are deliberately excluded under this key so a
 * seeded parameter cannot produce a trivial source==sink path). Barrier and
 * summary plumbing matches the formal query.
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
  "DIAGNOSTIC ONLY (not a CWE-78 finding): wrapper/public-API parameter " +
  "propagates to a process-execution call; confirms in-model reachability, " +
  "not attacker control."
