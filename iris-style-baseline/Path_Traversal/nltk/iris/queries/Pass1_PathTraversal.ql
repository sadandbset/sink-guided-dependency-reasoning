/**
 * @name nltk Pass 1: Path Traversal
 * @description Tracks untrusted path data (wordnet browser HTTP request path,
 *   downloader network index XML attributes and package zip entry names, and
 *   the public library API parameters of the nltk resource/corpus machinery)
 *   into filesystem access calls (open/gzip/zipfile/sqlite3/mkdir/remove/
 *   listdir/walk) along the audited join/decode/normalize propagation steps.
 *   Sources, sinks, barriers and additional steps are exactly the reviewed
 *   pass-1 labels of labels/labels.json (run nltk-iris-pass1-step3-20261022). Note: the wordnet
 *   browser open(usp) at app/wordnet_app.py:122 is guarded by an exact
 *   literal equality (:119) and is expected to be filtered as a false
 *   positive in Step 6 (label classification fp).
 * @id py/augur/nltk/pass1-path-traversal
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
  "Path traversal (CWE-22/23/36/73): untrusted path data flows from this source into a filesystem access."
