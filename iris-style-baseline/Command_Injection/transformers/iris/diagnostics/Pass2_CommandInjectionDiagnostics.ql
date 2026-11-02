/**
 * @name Pass 2 diagnostics: Command/Argument Injection candidate paths (CWE-78)
 * @description DIAGNOSTICS QUERY — NOT a formal vulnerability result. Uses the
 *   "command_injection_diagnostics" pass key to additionally include the
 *   labels.json entries classified `candidate` (pending human review,
 *   phase1_review.md section 5): the candidate external boundaries
 *   (os.environ / os.getenv, json.load / json.loads — including the git-lfs
 *   stdin protocol decodes at commands/lfs.py:107/165, requests.* response
 *   bodies, huggingface_hub downloads, the conversion-script raw_args
 *   mains) and the candidate argument-list exec sinks (subprocess
 *   Popen/run/check_output argument 0, asyncio.create_subprocess_exec
 *   argument 0 — including the ffmpeg argv sites and the test-helper
 *   command executors). Per the task directive this also verifies local
 *   propagation from internal wrapper parameters into dangerous calls
 *   (e.g. _ffmpeg_stream's argv parameter, run_command's command list):
 *   wrapper parameters are NOT sources in the formal model, so such paths
 *   can only surface here, and findings from this query must not be
 *   counted as formal pass-2 results.
 * @id py/augur/transformers/pass2-command-injection-diagnostics
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
 * set. The barrier predicate delegates to MySanitizers (empty confirmed
 * set, resolves to none()).
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
  "[DIAGNOSTICS ONLY - candidate label path] Potential command/argument injection path " +
  "reaching a process-execution API (CWE-78)."
