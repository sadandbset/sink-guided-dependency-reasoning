/**
 * @name Pass 2 DIAGNOSTIC: wrapper-parameter propagation (CWE-78)
 * @description DIAGNOSTIC ONLY — results of this query are NOT formal
 *   vulnerability findings and must not be counted toward the pass-2 result
 *   set (task directive: internal wrapper parameters are not automatically
 *   real sources). This query verifies, with full paths, that the internal
 *   recall-boundary parameters labeled source/candidate in Phase 1
 *   (_real_extract url, real_download filename/info_dict, PostProcessor.run
 *   info, and the parseOpts/parse_options/_real_main/main argv entries)
 *   locally propagate into the reviewed command-execution sinks. Use it to
 *   confirm that the wrapper-to-exec modeling in
 *   libraries/MySources.qll::WrapperBoundarySources and libraries/MySinks.qll
 *   is sound, and to review which wrapper params actually reach a dangerous
 *   argument; the formal query queries/Pass2_CommandInjection.ql keeps these
 *   wrappers out of its source set so no alert is produced solely because
 *   data "already looks tainted" at a wrapper boundary.
 * @id py/augur/yt-dlp/pass2-wrapper-diagnostics
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
 * Diagnostics configuration: identical to Pass2Config except for the pass key,
 * which additionally admits the internal wrapper-parameter sources
 * (MySources::WrapperBoundarySources). The sink set is unchanged.
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
  "DIAGNOSTIC (not a formal finding): internal wrapper parameter " +
  "(_real_extract url / real_download filename+info_dict / PostProcessor.run " +
  "info / CLI entry argv) locally propagates into a command-execution API — " +
  "wrapper-to-sink modeling confirmation only."
