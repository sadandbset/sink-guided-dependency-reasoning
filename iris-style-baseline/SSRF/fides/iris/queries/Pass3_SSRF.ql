/**
 * @name Pass 3: Server-side request forgery via config-boundary request URLs
 * @description Finds boundary data from the (OAuth-scope-gated) connection,
 *   SaaS and messaging configuration request bodies - materialized as
 *   ConnectionConfig.secrets / get_saas_config() / MessagingConfig.details
 *   reads in the service layer - flowing into the URL argument positions of
 *   the server-side network requests: the webhook requests.post of
 *   HTTPSConnector, the SaaS AuthenticatedClient transport
 *   (Session.send / client.send), the FidesConnector httpx requests, the
 *   OAuth2 token requests, and the override-strategy bare post(...) calls.
 *   Attacker control scope is differentiated per reviewed sink (full URL,
 *   scheme+host, host+path, path-only) in the alert message. Rendered by
 *   Augur Phase 2 Step 4-5 from the human-reviewed Pass 3 labels in
 *   iris/labels/labels.json (CWE-918).
 * @id py/augur/fides/pass3-ssrf
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

from Pass3Flow::PathNode source, Pass3Flow::PathNode sink, string msg
where
  Pass3Flow::flowPath(source, sink) and
  ssrfMessage(sink.getNode(), msg)
select sink.getNode(), source, sink, msg

/**
 * The alert message, differentiated by the attacker's URL control scope at
 * the reviewed sink sites (per the labeling rubric: full URL control,
 * scheme+host control, host+path control and path-only control with a
 * pinned host must not be conflated).
 *
 * Scope assignment (per reviewed sink, see libraries/MySinks.qll):
 *   full-url     - snk-026 http_connector.py:48 (webhook HttpsSchema.url)
 *   scheme+host  - snk-013/014/015/020/021/022/023/024/034/035/036/038
 *                  (FidesConnector uri base, SaaS client base URI, OAuth2
 *                  token host, override-strategy domain, constructor
 *                  surrogate URI arguments)
 *   host+path    - snk-011/016/018/019/025/027/028/037/039/040/041/042/043
 *                  (SaaS AuthenticatedClient transport: build_uri host +
 *                  config-derived request path)
 *   path         - snk-017/030/031/032 (yotpo and mailgun fetches: fixed
 *                  host, config-derived path segments only)
 */
private predicate ssrfMessage(DataFlow::Node sink, string msg) {
  exists(string scope |
    MySinks::controlScope(sink, "ssrf", scope) and
    (
      scope = "full-url" and
      msg = "SSRF (full URL control): the persisted connection-secrets request body (HttpsSchema.url, submitted via PUT /api/v1/connection/{key}/secrets, OAuth scope CONNECTION_CREATE_OR_UPDATE, fetched immediately when verify=True) reaches the url argument of the policy-webhook requests.post (src/fides/api/service/connectors/http_connector.py:48). " +
        "Scheme, host, port and path are all chosen by the submitting (privileged) client; HttpsSchema.url is an unvalidated str and no scheme/host/private-IP or redirect check exists on this path."
      or
      scope = "scheme+host" and
      msg = "SSRF (scheme+host control): config-boundary data reaches the base URI (scheme and host) of a server-side request (FidesConnector uri, SaaS client base URI, OAuth2 token-request host, or an override-strategy domain from secrets). " +
        "The destination host is chosen from the (OAuth-scope-gated) connection/messaging request bodies; the path is fixed or derived separately. No scheme/host validation or private-IP blocking exists on this path."
      or
      scope = "host+path" and
      msg = "SSRF (host+path control): config-boundary data reaches the request target of the SaaS AuthenticatedClient transport (base URI from the saas config protocol/host with secrets placeholders; request path from saas-config/secrets placeholders, identity values can additionally shape paths). " +
        "Both the host and the path of the outbound request are derived from the (OAuth-scope-gated) saas config / connection secrets with no URL validation."
      or
      scope = "path" and
      msg = "SSRF (path-only, host pinned): config-boundary data reaches only path segments of a request to a fixed host (api.yotpo.com, or api.mailgun.net / api.eu.mailgun.net selected by a boolean). " +
        "The destination host cannot be relocated by the submitting client; lower severity than host-controllable flows, kept for recall per the reviewed candidate labels."
    )
  )
}
