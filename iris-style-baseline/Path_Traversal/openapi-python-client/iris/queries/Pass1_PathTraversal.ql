/**
 * @name openapi-python-client pass 1: path traversal
 * @description Finds untrusted OpenAPI document content (info.title, schema
 *   titles/refs, operation tags - fetched via --url or read via --path and
 *   parsed by yaml.safe_load) flowing into filesystem paths of the generated
 *   client tree: the project/package directory joins (Path.cwd() /
 *   project_name, project_dir / package_name), the models module file names
 *   (models_dir / f"{module_name}.py") and the raw-tag endpoint module file
 *   names (api_dir / f"{tag}.py"), and from there into .mkdir() receivers,
 *   .write_text() receivers and the shutil.rmtree(package_dir) argument.
 *   No containment, canonicalization or root check exists anywhere in the
 *   audited package (openapi-python-client 0.5.2), so a document title/tag
 *   containing ".." segments, path separators or an absolute prefix escapes
 *   the intended CWD root. Sources, sinks, barriers (none exist) and the
 *   two additional taint steps (pathlib '/' joins, Project field flow) are
 *   rendered from the reviewed Pass 1 labels in iris/labels/labels.json -
 *   see report/query_generation_notes.md for the label-to-predicate mapping
 *   and the documented recall limitations (the parse-side tag source S24 is
 *   not connected to the :235/:237 sinks by any reviewed label; those sink
 *   sites still alert via the title-derived base directory path).
 * @id py/augur/openapi-python-client/pass1-path-traversal
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

module Pass1PathTraversalConfig implements DataFlow::ConfigSig {
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

module Pass1PathTraversalFlow = TaintTracking::Global<Pass1PathTraversalConfig>;
import Pass1PathTraversalFlow::PathGraph

from Pass1PathTraversalFlow::PathNode source, Pass1PathTraversalFlow::PathNode sink
where Pass1PathTraversalFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted OpenAPI document content reaches a filesystem path argument here (path traversal, CWE-022/023/036/073)."
