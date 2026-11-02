/**
 * @name Path traversal in opendiamond (Augur pass 1)
 * @description Finds flows from untrusted input boundaries (Flask path-converter route parameters of the dataretriever stores, the unconstrained sockjs websocket search key, JSON request bodies of the blaster, XDR RPC parameters, and the Django scopeserver request boundary) into file-access APIs (flask send_file, builtin open, ffprobe/ffmpeg Popen, os.stat/utime/rename/link, shutil.copyfile, zipfile.ZipFile). Sources, sinks, the safe_join barrier and additional taint steps come from the reviewed pass-1 labels in iris/labels/labels.json.
 * @id py/augur/opendiamond/pass1-path-traversal
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
 * opendiamond, delegating to the label-derived libraries with the unified
 * pass key "path_traversal".
 *
 * - isSource: 54 reviewed source-role entries (17 Flask route params
 *   including the 2 candidate `classes` params, 3 XDR RPC params,
 *   5 blaster body/json.loads nodes, 2 sockjs event params, 1
 *   ScopeCookie.parse candidate, 26 Django scopeserver request nodes).
 *   Internal function parameters are NOT sources unless reviewed as such -
 *   int-converter and hex-regex-constrained route params, environment
 *   reads (TMPDIR is set by the server itself), operator config paths and
 *   the internal mixer_list parameters were reviewed fp/none and excluded.
 * - isSink: 38 reviewed sink-role entries - real file accesses only;
 *   path construction (os.path.join, split_scheme, dirname/basename),
 *   in-memory ZipFile archives and send_file over stream objects are
 *   modeled as propagation (stdlib) or labeled none, not as sinks.
 * - isBarrier: the single confirmed sanitizer - werkzeug.utils.safe_join
 *   at dataretriever/augment_store.py:156, which contains every
 *   augment_store channel (symlink caveat recorded in the labels).
 * - isAdditionalFlowStep: only the evidence-backed propagation edges not
 *   already provided by codeql/python-all 7.1.2 (str() conversion for the
 *   video chains, helpers.split_scheme for the URI boundary, and the
 *   scoped blaster JSON dict subscript exit); os.path.join and all
 *   first-party wrapper bodies are handled by the standard library /
 *   interprocedural global taint tracking, and no unconditional
 *   param->return edges are added.
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
