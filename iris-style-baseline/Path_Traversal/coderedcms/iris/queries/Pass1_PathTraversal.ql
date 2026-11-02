/**
 * @name Path traversal in coderedcms (Augur pass 1)
 * @description Finds flows from untrusted input boundaries (the protected-media URL route parameter, multipart upload filenames, request fields, and stored submission data) into file-access APIs (builtin open, Django FileSystemStorage open/delete, PIL Image open/save, pathlib rmdir). Sources, sinks and barriers come from the reviewed pass-1 labels in iris/labels/labels.json; no sanitizer was confirmed in the project's own code.
 * @id py/augur/coderedcms/pass1-path-traversal
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

/**
 * Pass 1 (Path Traversal, CWE-022/023/036/073) taint configuration for
 * coderedcms, delegating to the label-derived libraries with the unified
 * pass key "path_traversal".
 *
 * - isSource: 57 reviewed source-role entries (route_param, http request
 *   fields, upload_name, db_json). Internal function parameters are NOT
 *   sources unless reviewed as such (the serve_protected_file `path`
 *   parameter is a URL-injected route parameter, reviewed tp 0.97).
 * - isSink: 8 reviewed sink-role entries - real file accesses only; path
 *   construction (Path(), join, storage.path, get_available_name) is
 *   modeled as propagation, not as sinks.
 * - isBarrier: no sanitizer was confirmed (resolves to none()); the
 *   extension whitelist/blacklist, os.path.isfile and login_required were
 *   each examined against the real source and none blocks traversal.
 * - isAdditionalFlowStep: only the evidence-backed propagation edges not
 *   already provided by codeql/python-all 7.1.x (Django storage
 *   get_available_name/path, str() conversion, scoped submission-dict
 *   .get()); pathlib Path()//operator/with_suffix/parent and os.path.join
 *   are handled by the standard library's PathlibPathTaintStep and
 *   OsPathComputationAdditionalTaintStep.
 */
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
  "User-controlled path data flows from $@ into a file-access API and may traverse outside the intended directory.",
  source.getNode(), "this untrusted input"
