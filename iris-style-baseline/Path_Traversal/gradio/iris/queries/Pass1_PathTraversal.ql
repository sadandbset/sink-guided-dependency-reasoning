/**
 * @name Untrusted request data in file-access path arguments (gradio)
 * @description Tracks reviewed untrusted input boundaries of the gradio package (Flask route path variables, request JSON payload reads, component preprocess parameters, flagging and queue entry parameters) into dangerous file-access path arguments (open, send_file, shutil.copy2, tempfile name components, ffmpy/ffmpeg paths, pydub file I/O). Derived from the reviewed Augur Pass 1 labels (iris/labels/labels.json, run gradio-pathtraversal-pass1-20261022); barrier: werkzeug safe_join containment.
 * @id py/augur/gradio/pass1-path-traversal
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
  "This untrusted request-derived value flows into a file-access path argument and may allow reading, writing or serving files outside the intended directory (path traversal, CWE-22/23/36/73)."
