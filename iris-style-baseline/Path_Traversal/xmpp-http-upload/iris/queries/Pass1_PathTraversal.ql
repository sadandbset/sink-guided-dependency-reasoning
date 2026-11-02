/**
 * @name Pass 1: Path traversal in xmpp-http-upload route-path file flows
 * @description Tracks the attacker-controlled Werkzeug `path` route-converter bindings of put_file/head_file/get_file (xhu.py:105/:190/:215, the URL-decoded remainder of the request URL) into the filesystem access positions of the upload/download service: the GET file response (flask.send_file str(data_file), xhu.py:228), the data/metadata writes (at.open "xb" :76, metadata_file.open "x" :144), the metadata read (metadata_file.open "r" :57), recursive directory creation (dest_path.parent.mkdir, :137), the stat probe (:197) and the write-rollback unlink (:80). The reviewed Pass 1 labels found the sanitized_join containment guard (xhu.py:42-46) to be a lexical startswith check on the un-normalized (root / path).absolute() string - Path.absolute() performs no ".." normalization - so no barrier is modeled; alert paths that pass that guard are the expected findings and are triaged at Step 6. Read-side routes (GET/HEAD) are unauthenticated; the PUT side is HMAC-gated over the exact path.
 * @id py/augur/xmpp-http-upload/pass1-path-traversal
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
  "Tainted route-parameter path data flows into a filesystem access. The sanitized_join guard at xhu.py:42-46 compares the un-normalized (root / path).absolute() string lexically, so '..' segments in the request path escape the declared DATA_ROOT when the OS resolves them at the file access (CWE-022/023/036/073)."
