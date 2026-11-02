/**
 * @name Pass 3: Server-Side Request Forgery (CWE-918)
 * @description Tracks the reviewed CWE-918 input boundaries of the
 *   recurly-client-python SDK into its single outbound request funnel. Sources,
 *   sinks, barriers and additional taint steps are rendered from the
 *   human-reviewed labels in iris/labels/labels.json (run
 *   recurly-client-python-ssrf-pass3-20261020, pass 3): 21 source entries (the
 *   public-API full-URL parameters of the embedding-application boundary —
 *   http_request/element_for_url/headers_for_url/page_for_url/count_for_url/
 *   paginated/put/post; the server-controlled response URL carriers — XML href
 *   reads, Location/Link headers; the redemption_code first-path-segment read;
 *   the unverified webhook body parameter), 13 sink entries (the
 *   http_client.HTTP(S)Connection host argument, the connection.request
 *   request-line URL, and the argument-0 URL positions of the funnel), zero
 *   sanitizers (verified: no scheme/host allowlist, no private-IP blocking, no
 *   redirect validation exists anywhere in the package — resource.py:240-250
 *   only selects the transport), and five additional taint-step families
 *   (urljoin both-argument propagation, urlencode query propagation, urlsplit
 *   url-to-netloc, ElementTree.fromstring, parse_link_value). The alert message
 *   distinguishes full-URL control, host-level control and second-order
 *   (server-controlled) carriers; all sources carry classification
 *   `candidate` — the SDK boundary set pending host-application context.
 * @id py/augur/recurly-client-python/pass3-ssrf
 * @kind path-problem
 * @problem.severity error
 * @precision low
 * @tags security
 *       external/cwe/cwe-918
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

/**
 * Pass 3 (CWE-918) flow configuration. The pass key "ssrf" selects the reviewed
 * label set. The barrier hook always exists (WORKFLOW.md 5.2.3): it delegates to
 * MySanitizers, whose reviewed sanitizer set is EMPTY (no scheme/host allowlist,
 * no private-IP blocking, no redirect validation anywhere in the snapshot; TLS
 * CA validation and API-key authentication restrict nothing about the request
 * target), so it resolves to none() and never blocks unconditionally.
 */
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

from Pass3Flow::PathNode source, Pass3Flow::PathNode sink,
  string sourceScope, string sinkScope
where
  Pass3Flow::flowPath(source, sink) and
  MySources::scopeOf(source.getNode(), sourceScope) and
  MySinks::scopeOf(sink.getNode(), sinkScope)
select sink.getNode(), source, sink,
  "SSRF (CWE-918): " + sourceScope + " flows into " + sinkScope +
  " without any target validation (no scheme/host allowlist, no private-IP" +
  " blocking, no redirect control)."
