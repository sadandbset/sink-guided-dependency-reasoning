/**
 * @name Sydent server-side request forgery (SSRF)
 * @description Finds untrusted request data (public identity-server API
 *   parameters, request bodies, and the unauthenticated X-Matrix
 *   federation Authorization header) reaching the URL/host argument of
 *   an outbound server-side request: the matrix:// federation GET/POST
 *   chains of Sydent (account/register openid userinfo lookup, 3pid bind
 *   callbacks, and homeserver key fetching during X-Matrix
 *   authentication), the underlying twisted Agent.request egress, and
 *   the HostnameEndpoint TCP dial targets. The attacker controls the
 *   host (plus optional port) of the target; the scheme and path are
 *   fixed by format strings, and no scheme/host allow-list, redirect
 *   control, or private-address blocking exists on these paths.
 * @id py/augur/sydent/pass3-ssrf
 * @kind path-problem
 * @problem.severity error
 * @precision low
 * @tags security
 *       external/cwe/cwe-918
 *       external/cwe/cwe-99
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
  "Server-side request forgery (CWE-918): untrusted request data reaches the URL/host of a server-side outbound matrix:// federation or HTTPS request."
