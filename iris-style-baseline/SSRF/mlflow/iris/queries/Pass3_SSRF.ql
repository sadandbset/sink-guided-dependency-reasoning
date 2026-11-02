/**
 * @name MLflow server-side request forgery (SSRF)
 * @description Finds untrusted request data or database-stored URI content
 *   reaching the URL of an outbound HTTP request issued by the MLflow
 *   tracking server: the deployments gateway proxy
 *   (/ajax-api/2.0/mlflow/gateway-proxy, path-level control on an
 *   admin-configured target), and the server-side artifact fetch chains
 *   (experiment artifact_location / run artifact_uri / model-version
 *   source driving HttpArtifactRepository and the rest-utils transport,
 *   host-level control). Second-order sources are included because the
 *   tracking server is unauthenticated by default.
 * @id py/augur/mlflow/pass3-ssrf
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
  "Server-side request forgery (CWE-918): untrusted request or DB-content data reaches the URL of a server-side outbound HTTP request."
