/**
 * @name Pass 2: Command/Argument Injection (CWE-78)
 * @description Tracks CLI input from the transformers-cli and
 *   transformers.onnx entry points (argparse parse_args / parse_known_args
 *   results, sys.argv, the *Command handler parameters and the onnx export
 *   `args` parameters) into the shell command string executed by
 *   `subprocess.Popen(" ".join(cmd_line), shell=True)` at
 *   onnx/__main__.py:59 — the only shell=True execution site in
 *   src/transformers, where --model / --task / --framework / --output CLI
 *   values are interpolated unquoted (no shlex.quote exists anywhere in the
 *   package). Sources, sinks, barriers and additional taint steps are
 *   rendered from the human-reviewed labels in iris/labels/labels.json
 *   (run transformers-cwe78-phase1-step3-20260119, pass 2, classification
 *   tp only): one tp sink shape (Popen shell=True command string) and an
 *   empty confirmed sanitizer set.
 * @id py/augur/transformers/pass2-command-injection
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

/**
 * Pass 2 (CWE-78) flow configuration. The pass key "command_injection"
 * selects the reviewed (tp) label set. The barrier predicate always exists
 * (WORKFLOW.md 5.2.3) — it delegates to MySanitizers, whose confirmed set
 * is EMPTY (no shlex/escaping exists anywhere in snapshot 87a6cf4), so it
 * resolves to none(); it never blocks unconditionally.
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
  "Command injection: CLI-provided value reaches a shell command string executed with " +
  "shell=True (CWE-78)."
