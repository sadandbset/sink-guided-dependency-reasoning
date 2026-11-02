/**
 * @name Pass 1: Path traversal in py7zr archive-entry extraction flows
 * @description Tracks attacker-controlled 7z archive content - header entry names (archiveinfo.py:757) and decompressed symlink/junction target payloads (py7zr.py:1333/:1343) - into filesystem access positions during extraction: the Worker file write (fileish.open "wb", py7zr.py:1349), directory creation (py7zr.py:625/:1328), pre-collision unlink (:1336/:1346), junction/symlink creation (:1338/:1347), empty-file touch (:1357), and post-extract utime/chmod (:659/:663/:668). The reviewed Pass 1 labels found the relative_to containment guards (py7zr.py:577/:584) to be lexical prefix checks that preserve ".." segments, so no barrier is modeled; alert paths that survive those guards are the expected findings (Zip-Slip) and are triaged at Step 6.
 * @id py/augur/py7zr/pass1-path-traversal
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
  "Tainted archive-content-derived path data flows into a filesystem access during extraction. The relative_to guards at py7zr.py:577/:584 only reject absolute-path replacement and preserve '..' segments, so an archive entry name (or link/junction target) may traverse outside the declared base directory (CWE-022/023/036/073)."
