/**
 * @name Path traversal from untrusted request boundaries
 * @description Finds flows from copyparty's request boundaries (HTTP request path,
 *   query, headers, cookies, JSON and multipart bodies; FTP command paths and CWD
 *   state; SMB callback paths) into filesystem path operations (file open/read/
 *   write/delete/create, file-response wrappers, directory operations). The
 *   sanitizer model encodes the verified traversal guards: undot applied to
 *   decoded values inside VFS.get (authsrv.py:473) and basename-only sanitize_fn;
 *   the pre-decode undot at httpcli.py:333/:337 is deliberately NOT a barrier, so
 *   percent-encoded traversal that bypasses the second undot (e.g. the .cpr
 *   static-resource join at httpcli.py:782) remains visible. Expected alerts on
 *   guarded channels (main download, PUT/uploads, FTP/SMB resolution, ?doc=
 *   membership check) should be triaged with the guard-chain notes in
 *   report/query_generation_notes.md.
 * @id py/augur/copyparty/pass1-path-traversal
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
  "Untrusted request data flows into this filesystem path operation; verify the " +
    "guard chain (post-decode undot in VFS.get, sanitize_fn basename, opt-in chk_ap) " +
    "applies on this channel before treating it as path traversal."
