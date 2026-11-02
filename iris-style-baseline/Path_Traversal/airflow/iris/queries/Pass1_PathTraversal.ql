/**
 * @name Airflow path traversal (Pass 1)
 * @description Finds flows from audited untrusted request boundaries (flask/FAB request
 *   reads, route-handler parameters, request-derived json.loads sites, signed-token
 *   decodes) to audited filesystem access positions (builtin open, os.* / shutil.* /
 *   zipfile.ZipFile path arguments, flask send_from_directory, SourceFileLoader,
 *   pathlib receiver-path methods, and path-carrying wrapper parameters). Rendered from
 *   the reviewed Pass 1 label set in iris/labels/labels.json by Augur Phase 2 Step 4.
 * @id py/augur/airflow/pass1-path-traversal
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

module Pass1Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    MySources::isSource(source, "path_traversal")
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "path_traversal")
  }

  predicate isBarrier(DataFlow::Node node) {
    MySanitizers::isBarrier(node, "path_traversal")
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "path_traversal")
  }
}

module Pass1Flow = TaintTracking::Global<Pass1Config>;
import Pass1Flow::PathGraph

from Pass1Flow::PathNode source, Pass1Flow::PathNode sink
where Pass1Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted request-derived data flows into a filesystem access path. [Pass 1: path traversal]"
