/**
 * @name TensorFlow Pass 2: Command/Argument Injection (CWE-78)
 * @description
 *   Tracks untrusted input into command execution sinks in the TensorFlow
 *   Python layer. Sources are the reviewed pass-2 tp labels: the tfdbg gRPC
 *   debug-server receive boundary (SendEvents / SendTracebacks /
 *   SendSourceFiles request parameters and the on_value_event / on_graph_def
 *   / on_core_metadata_event stream-handler callbacks of the unauthenticated
 *   [::]:port listener), sys.argv / parse_args / parse_known_args / input()
 *   CLI boundaries in runtime library entry points, and urlopen network
 *   responses. Sinks are the reviewed subprocess execution sites: the
 *   run_shell_cmd Popen(shell=True) string command and the argv-list
 *   Popen / check_output / check_call / call / run commands with
 *   environment- or parameter-influenced operands (configure.py
 *   PYTHON_BIN_PATH, flatc / git / grep / objdump / gcloud tooling).
 *   Sanitizer: shlex.quote / _shlex_quote (saved_model_aot_compile.py).
 *   Additional taint steps: the three tfdbg stream_handler.on_* dispatch
 *   hops. Sources, sinks, sanitizers and summaries are Phase 1 reviewed
 *   labels from run tensorflow-iris-pass2-labeling-20261016; a finding is a review candidate, not a confirmed
 *   vulnerability - the reviewed exec sites have static, internally
 *   derived or list-form operands, so no complete source-to-sink path is
 *   expected in this snapshot.
 * @id py/augur/tensorflow/pass2-command-injection
 * @kind path-problem
 * @problem.severity error
 * @precision low
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-077
 *       external/cwe/cwe-088
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

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

  predicate isAdditionalFlowStep(
    DataFlow::Node nodeFrom,
    DataFlow::Node nodeTo
  ) {
    MySummaries::isAdditionalTaintStep(
      nodeFrom, nodeTo, "command_injection"
    )
  }
}

module Pass2Flow = TaintTracking::Global<Pass2Config>;
import Pass2Flow::PathGraph

from Pass2Flow::PathNode source, Pass2Flow::PathNode sink
where Pass2Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted input flows from $@ into a command/argument execution sink ($@). " +
    "Augur pass 2 (CWE-78): the source is a reviewed tp label (tfdbg gRPC " +
    "receive boundary, CLI argument, interactive input or urlopen response) " +
    "and the sink is a labeled subprocess command-execution site (shell=True " +
    "string command or argv-list command with external/parameter-influenced " +
    "operands). The reviewed sites have static, internally derived or " +
    "list-form operands - review before treating this as a vulnerability.",
  source, "untrusted source", sink, "execution sink"
