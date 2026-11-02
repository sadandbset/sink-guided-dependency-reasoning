/**
 * @name Path traversal from untrusted request boundaries
 * @description Finds flows from pyLoad's untrusted input boundaries (Flask request
 *   form/args/values/auth/multipart reads, the dynamic /api RPC route variables and
 *   receiver-side core Api parameters, and remote archive entry names) into
 *   filesystem path operations (file open/save, download response, archive
 *   extraction, extractor subprocess destinations, directory create, file
 *   delete/move/copy/chmod, template lookups and the pathchooser directory
 *   probes). The sanitizer model encodes only the verified traversal guards:
 *   purge.name separator removal (PyFile names, content-disposition),
 *   parse.name basename extraction and the four verified basename
 *   neutralization sites. safepath/safename are deliberately NOT barriers -
 *   they preserve '..' as a standalone component on posix, which is the
 *   load-bearing weakness of the PyPackage.folder chain. External guards not
 *   visible to CodeQL must be weighed at triage: werkzeug safe_join behind
 *   flask.send_from_directory (/files/get), the jinja2/flask_themes2 template
 *   loaders (/render), stdlib zipfile extractall member sanitization (UnZip),
 *   and the UnTar commonprefix guard (character-prefix weak). Expected alerts
 *   include the unsanitized multipart tmp_ write (/json/add_package ->
 *   file.save, json_blueprint.py:154-157), the RPC tmp_ container writes
 *   (Api.upload_container / check_online_status_container,
 *   core/api/__init__.py:535/:951) and the guarded CNL dlc write
 *   (cnl_blueprint.py:93-97, localhost-only + separator-stripped).
 * @id py/augur/pyload/pass1-path-traversal
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
    "guard chain (purge.name/parse.name barriers, safepath component weakness, " +
    "werkzeug safe_join, jinja loader checks, stdlib archive sanitization) applies " +
    "on this channel before treating it as path traversal."
