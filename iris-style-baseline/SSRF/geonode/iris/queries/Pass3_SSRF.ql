/**
 * @name GeoNode server-side request forgery (Pass 3)
 * @description Tracks untrusted request/form/URL input from GeoNode's external boundaries into the URL argument of a server-side network request (CWE-918). Sources are the reviewed request-entry boundaries (proxy ?url= parameter, service-registration form, set_thumbnail API, DRF dataset payloads, second-order DB URL fields); sinks are the URL argument of requests/OWSLib/arcrest/smart_open calls and the central geonode.utils.HttpClient dispatch.
 * @id py/augur/geonode/pass3-ssrf
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @tags security
 *       external/cwe/cwe-918
 *       external/cwe/cwe-099
 *       external/cwe/cwe-610
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

module Pass3Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    MySources::isSource(source, "ssrf")
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "ssrf")
  }

  predicate isBarrier(DataFlow::Node node) {
    MySanitizers::isBarrier(node, "ssrf")
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "ssrf")
  }
}

module Pass3Flow = TaintTracking::Global<Pass3Config>;
import Pass3Flow::PathGraph

from Pass3Flow::PathNode source, Pass3Flow::PathNode sink
where Pass3Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Server-side request forgery (CWE-918): untrusted input from $@ reaches the URL of a server-side network request at $@.",
  source.getNode(), "this request/form/URL boundary",
  sink.getNode(), "this network request URL argument"
