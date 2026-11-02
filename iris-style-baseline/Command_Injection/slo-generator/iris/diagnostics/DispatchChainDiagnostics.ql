/**
 * @name Dispatch-chain local propagation diagnostics (Augur Pass 2)
 * @description DIAGNOSTIC ONLY - NOT an official vulnerability result. Validates that taint entering the internal name-resolution wrapper parameters (import_dynamic, import_cls, run_backend, get_backend_cls, get_exporter_cls) propagates locally to the dynamically dispatched sinks in utils.py, report.py and compute.py. These parameters are deliberately NOT sources in the official Pass 2 model (internal wrapper parameters are not input boundaries); this query exists solely to verify the internal propagation legs, and its results must not be counted as official findings.
 * @id py/augur/slo-generator/diagnostics/dispatch-chain-local
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @tags security
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySinks

module DispatchDiagnosticsConfig implements DataFlow::ConfigSig {
  /**
   * Internal wrapper parameters (NOT input boundaries, NOT official sources):
   * the name-resolution chain that carries config-derived class/method names
   * toward the dynamic-import and getattr-dispatch sinks.
   */
  predicate isSource(DataFlow::Node source) {
    exists(Function f, Parameter p |
      f.getName() = "import_dynamic" and
      f.getArg(0) = p and
      p.getName() = "package" and
      p.getLocation().getFile().getRelativePath() = "slo_generator/utils.py" and
      source = DataFlow::parameterNode(p)
    )
    or
    exists(Function f, Parameter p |
      f.getName() = "import_dynamic" and
      f.getArg(1) = p and
      p.getName() = "name" and
      p.getLocation().getFile().getRelativePath() = "slo_generator/utils.py" and
      source = DataFlow::parameterNode(p)
    )
    or
    exists(Function f, Parameter p |
      f.getName() = "import_cls" and
      f.getArg(0) = p and
      p.getName() = "cls_name" and
      p.getLocation().getFile().getRelativePath() = "slo_generator/utils.py" and
      source = DataFlow::parameterNode(p)
    )
    or
    exists(Function f, Parameter p |
      f.getName() = "run_backend" and
      f.getArg(_) = p and
      p.getName() in ["config", "backend"] and
      p.getLocation().getFile().getRelativePath() = "slo_generator/report.py" and
      source = DataFlow::parameterNode(p)
    )
    or
    exists(Function f, Parameter p |
      f.getName() in ["get_backend_cls", "get_exporter_cls"] and
      f.getArg(0) = p and
      p.getLocation().getFile().getRelativePath() = "slo_generator/utils.py" and
      source = DataFlow::parameterNode(p)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "command_injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    none()
  }
}

module DispatchDiagnosticsFlow = TaintTracking::Global<DispatchDiagnosticsConfig>;

from DataFlow::Node source, DataFlow::Node sink
where DispatchDiagnosticsFlow::flow(source, sink)
select sink.asExpr(),
  "DIAGNOSTIC ONLY (not an official finding): internal wrapper parameter " +
  "reaches a dynamic-dispatch sink locally (CWE-78 candidate chain validation)."
