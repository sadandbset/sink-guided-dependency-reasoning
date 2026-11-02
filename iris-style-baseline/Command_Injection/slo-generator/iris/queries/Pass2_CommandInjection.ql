/**
 * @name Command injection in slo-generator (Augur Pass 2)
 * @description Tracks externally influenced data (Functions Framework request bodies, CLI values, configuration file and environment content) to the config-controlled name-resolution and dynamic-dispatch boundaries of slo-generator: importlib.import_module module paths, getattr-based member selection, and the invocation of name-resolved backend/exporter/migration callables. This snapshot contains no OS command-execution API, so alerts are CWE-78/88-adjacent candidates for triage, not confirmed command injection vulnerabilities. v2 (post-triage remediation): additionally tracks file-content sources (migration input files, migrator.py:228/263) into unsafe YAML deserialization sinks (yaml.load with Loader=yaml.Loader/UnsafeLoader/FullLoader, migrator.py:229/264) - the project's actual code-execution boundary (CWE-502-class arbitrary Python object construction, the mechanism recorded as CWE-78 impact for this project's fix commit).
 * @id py/augur/slo-generator/pass2-command-injection
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
  "Externally influenced data reaches a dynamically resolved name or dispatch boundary (CWE-78 candidate)."
