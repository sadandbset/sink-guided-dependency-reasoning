/**
 * @name Bikeshed diagnostic: taint reaching internal function parameters (Pass 2)
 * @description DIAGNOSTIC ONLY - NOT a vulnerability query. Reports whether
 *   data from the labeled CWE-78 source boundaries (MySources, pass
 *   "command_injection") reaches, by standard taint propagation ONLY (no
 *   MySummaries additional steps, so the raw reachability signal stays
 *   unperturbed), the parameter nodes of the internal functions that the
 *   Pass 2 label set marks as summary params or wrapper sinks:
 *     - metadata.parse(lines), metadata.fromCommandLine(overrides),
 *       metadata.fromJson(data)      (labels p2-sum-001/002/003)
 *     - processTags(doc), handleProfile(options) (labels p2-sink-002/005)
 *   Use this query to explain which chains of the official
 *   queries/Pass2_CommandInjection.ql fired and where propagation stops
 *   (e.g. the doc.md.inlineTagCommands attribute chain).
 *   Findings produced by this query MUST NOT be counted as vulnerability
 *   true positives in Step 6; they are excluded from pass2.sarif metrics.
 * @id py/bikeshed/iris/pass2-diagnostic-parameter
 * @kind path-problem
 * @problem.severity warning
 * @tags diagnostics
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources

/** Restricts an AST node to the file with the given database-relative path. */
predicate inFile(AstNode n, string path) {
  n.getLocation().getFile().getRelativePath() = path
}

/**
 * Parameter nodes of the labeled internal functions (summary params and
 * wrapper param sinks) — diagnostic sink set, intentionally different from
 * the official Pass 2 sink model.
 */
module LabeledParameterSinks {
  predicate isSink(DataFlow::Node sink) {
    exists(Function f, Parameter p |
      (
        // summary params (labels p2-sum-001/002/003)
        (
          f.getName() = "parse" and
          inFile(f, "bikeshed/metadata.py")
        )
        or
        (
          f.getName() = "fromCommandLine" and
          inFile(f, "bikeshed/metadata.py")
        )
        or
        (
          f.getName() = "fromJson" and
          inFile(f, "bikeshed/metadata.py")
        )
        or
        // wrapper param sinks (labels p2-sink-002/005), mirrored for comparison
        (
          f.getName() = "processTags" and
          inFile(f, "bikeshed/inlineTags/__init__.py")
        )
        or
        (
          f.getName() = "handleProfile" and
          inFile(f, "bikeshed/cli.py")
        )
      ) and
      p = f.getArg(0) and
      sink = DataFlow::parameterNode(p)
    )
  }
}

/** Diagnostic flow configuration: labeled sources, parameter sinks, no extra steps. */
module Pass2DiagnosticConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    MySources::isSource(source, "command_injection")
  }

  predicate isSink(DataFlow::Node sink) {
    LabeledParameterSinks::isSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) { none() }
}

module Pass2DiagnosticFlow = TaintTracking::Global<Pass2DiagnosticConfig>;
import Pass2DiagnosticFlow::PathGraph

from Pass2DiagnosticFlow::PathNode source, Pass2DiagnosticFlow::PathNode sink
where Pass2DiagnosticFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "DIAGNOSTIC (not a vulnerability): tainted source data reaches a labeled internal-function parameter."
