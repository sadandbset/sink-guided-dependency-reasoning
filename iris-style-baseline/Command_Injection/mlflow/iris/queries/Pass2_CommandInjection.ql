/**
 * @name MLflow Pass 2: Command/Argument Injection (CWE-078)
 * @description
 *   Tracks untrusted input (Flask request fields and request-decoding
 *   wrappers on the tracking/model-registry REST API and scoring server,
 *   click CLI parameters such as `mlflow run` -P parameters and
 *   --docker-args, untrusted project/model artifact metadata (MLproject
 *   entry-point commands, MLmodel / conda.yaml metadata) and MLFLOW_*
 *   environment variables) into command execution sinks: bash/cmd -c
 *   shell-string elements, os.system, subprocess.run with shell=True and
 *   Popen command arguments, plus the internal execution wrappers
 *   (_exec_cmd, Environment.execute, _run_entry_point, PyFuncBackend.serve,
 *   _serve_pyfunc, _install_pyfunc_deps, push_image_to_ecr,
 *   _get_databricks_run_cmd, _download_wheels). Sanitizers: string_utils
 *   quote() and EntryPoint._sanitize_param_dict where the labels confirmed
 *   them. Sources, sinks, sanitizers and summaries are Phase 1 reviewed
 *   labels (classification=tp) from run
 *   mlflow-iris-pass2-labeling-20261015; a finding is a review candidate,
 *   not a confirmed vulnerability.
 * @id py/augur/mlflow/pass2-command-injection
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
  "Untrusted input flows from $@ into a command/code execution sink ($@). " +
    "Augur pass 2 (CWE-78): the source is a reviewed tp label (HTTP request, " +
    "CLI parameter, artifact metadata or MLFLOW_* environment variable) and " +
    "the sink is a labeled shell-string/argv execution site (bash -c / " +
    "os.system / shell=True / Popen argument) in the project-serving and " +
    "model-serving command chain. Review before treating it as a " +
    "vulnerability.",
  source, "untrusted source", sink, "execution sink"
