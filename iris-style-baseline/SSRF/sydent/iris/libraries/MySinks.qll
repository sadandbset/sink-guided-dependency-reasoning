/**
 * Augur-generated sink model for the matrix-sydent CWE-918 (SSRF) pass.
 *
 * Machine-generated in Phase 2 Step 4 from the reviewed labels in
 * iris/labels/labels.json (run sydent-ssrf-pass3-20261020, pass_id 3,
 * pass key "ssrf"). Do not edit by hand; regenerate from the labels.
 *
 * Selection policy: label entries with role "sink" AND classification
 * "tp" are modeled (9 of 17 sink candidates). Excluded:
 *  - 7 fp/none rows: smtplib.SMTP/SMTP_SSL hosts (admin-config
 *    email.smtphost, emailutils.py:96/98/101), ReplicationHttpsClient
 *    .postJson and its arg (operator config / peers table,
 *    httpsclient.py:70, peer.py:200), OpenMarket SMS post (fixed constant
 *    API_BASE_URL, openmarket.py:101), sentry_sdk.init (admin DSN,
 *    sydent.py:210).
 *  - 1 candidate row: twisted.names lookupService (srvresolver.py:125) -
 *    DNS SRV query with attacker-influenced name, but DNS-only egress,
 *    not an HTTP URL sink; remains in the human-review queue.
 *
 * Every modeled sink is anchored at the URL/host-carrying argument of a
 * real outbound network call or of a wrapper call proven (by reading the
 * wrapper body) to pass the URL to the network I/O:
 *  - HTTPClient.get_json(uri) -> self.agent.request(b"GET",
 *    uri.encode("utf8")) (httpclient.py:52-55); post_json_get_nothing
 *    (uri, ...) -> self.agent.request(b"POST", uri.encode("utf8"), ...)
 *    (httpclient.py:91-96).
 *  - MatrixFederationAgent.request(method, uri, ...) -> routing ->
 *    Agent.usingEndpointFactory(...).request(method, uri, ...) and
 *    HostnameEndpoint(reactor, target_host, target_port) (the TCP dial).
 *
 * Attacker control tiers (documented per predicate, kept distinct):
 *  - full URL control: none of the modeled positions - the matrix://
 *    scheme and path are fixed by format strings; the attacker controls
 *    the HOST part (plus optional port) of the server name.
 *  - host control: all four predicates (host comes from
 *    matrix_server_name / mxid server part / X-Matrix origin).
 *  - path/query-only control: the access_token operand of the register
 *    URL (query string) - NOT a sink position; taint there alone does not
 *    fire these sinks since the format-string host operand is the URL-
 *    shaping position (documented in query_generation_notes.md).
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {

  /** Sink dispatch. Pass key "ssrf" = pass 3 (CWE-918/099/610). */
  predicate isSink(DataFlow::Node node, string passKey) {
    passKey = "ssrf" and (
      agentRequestSink(node) or
      hostnameEndpointSink(node) or
      federationGetJsonSink(node) or
      bindCallbackPostSink(node)
    )
  }

  /**
   * twisted.web.client Agent.request(method, uri, ...) call sites: the
   * final HTTP egress. Argument index 1 (index 0 is the method bytes).
   * Call sites (verified in source):
   *  - sydent/http/httpclient.py:52 (get_json:  self.agent.request(b"GET",
   *    uri.encode("utf8")))
   *  - sydent/http/httpclient.py:91 (post_json_get_nothing:
   *    self.agent.request(b"POST", uri.encode("utf8"), headers, ...))
   *  - sydent/http/matrixfederationagent.py:176 (agent.request(method,
   *    uri, headers, bodyProducer) via Agent.usingEndpointFactory)
   *  - sydent/http/matrixfederationagent.py:322 (well-known fetch:
   *    self._well_known_agent.request(b"GET", uri))
   * httpsclient.py:70 (ReplicationHttpsClient.postJson) is the fp-labeled
   * replication sink and is excluded by the file scope.
   * Control tier: host - the uri host derives from request-selected
   * server names.
   * Labels (4 tp): sink-6, sink-7, sink-10, sink-11.
   */
  private predicate agentRequestSink(DataFlow::Node node) {
    exists(Call c, Attribute fn |
      c.getFunc() = fn and
      fn.getName() = "request" and
      c.getLocation().getFile().getRelativePath() =
        ["sydent/http/httpclient.py",
         "sydent/http/matrixfederationagent.py"] and
      node.asExpr() = c.getPositionalArg(1)
    )
  }

  /**
   * TCP endpoint construction: HostnameEndpoint(reactor, host, port) and
   * its LoggingHostnameEndpoint(reactor, host, port) wrapper. Argument
   * index 1 (index 0 is the reactor). Call sites:
   *  - sydent/http/matrixfederationagent.py:168
   *    (LoggingHostnameEndpoint(self._reactor, res.target_host,
   *    res.target_port) inside EndpointFactory.endpointForURI)
   *  - sydent/http/matrixfederationagent.py:366 (HostnameEndpoint(reactor,
   *    host, port) inside LoggingHostnameEndpoint.__init__)
   * Control tier: host:port - the concrete TCP dial target after
   * matrix:// routing (SRV / .well-known / IP literal / explicit port).
   * Labels (2 tp): sink-9, sink-12.
   */
  private predicate hostnameEndpointSink(DataFlow::Node node) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = ["HostnameEndpoint", "LoggingHostnameEndpoint"] and
      c.getLocation().getFile().getRelativePath() =
        "sydent/http/matrixfederationagent.py" and
      node.asExpr() = c.getPositionalArg(1)
    )
  }

  /**
   * FederationHttpClient.get_json(uri, max_size) wrapper call sites:
   * argument index 0 is the full request URL, proven to reach
   * self.agent.request (httpclient.py:52-55) and MatrixFederationAgent
   * routing. Call sites:
   *  - sydent/http/servlets/registerservlet.py:59
   *    ("matrix://%s/_matrix/federation/v1/openid/userinfo?access_token=%s"
   *    built from the UNAUTHENTICATED matrix_server_name field of
   *    /account/register; is_valid_hostname at :52 is a form check only)
   *  - sydent/hs_federation/verifier.py:80
   *    ("matrix://%s/_matrix/key/v2/server/" built from the X-Matrix
   *    origin / signature server names; fetched BEFORE signature
   *    verification at :211)
   * Control tier: host (scheme matrix:// and path are fixed by the format
   * strings; the host is attacker-chosen).
   * Labels (2 tp): sink-15, sink-18.
   */
  private predicate federationGetJsonSink(DataFlow::Node node) {
    exists(Call c, Attribute fn |
      c.getFunc() = fn and
      fn.getName() = "get_json" and
      c.getLocation().getFile().getRelativePath() =
        ["sydent/http/servlets/registerservlet.py",
         "sydent/hs_federation/verifier.py"] and
      node.asExpr() = c.getPositionalArg(0)
    )
  }

  /**
   * HTTPClient.post_json_get_nothing(uri, post_json, opts) wrapper call
   * site: argument index 0 is the request URL, proven to reach
   * self.agent.request (httpclient.py:91-96). Call site:
   *  - sydent/threepid/bind.py:162 (post_url =
   *    "matrix://%s/_matrix/federation/v1/3pid/onbind" built from the mxid
   *    server part supplied by the bind APIs; is_valid_hostname at
   *    bind.py:146 is a form check only)
   * The openmarket.py:101 post (fixed API_BASE_URL constant) is the
   * fp-labeled SMS sink and is excluded by the file scope.
   * Control tier: host (scheme/path fixed by the format string).
   * Labels (1 tp): sink-2.
   */
  private predicate bindCallbackPostSink(DataFlow::Node node) {
    exists(Call c, Attribute fn |
      c.getFunc() = fn and
      fn.getName() = "post_json_get_nothing" and
      c.getLocation().getFile().getRelativePath() =
        "sydent/threepid/bind.py" and
      node.asExpr() = c.getPositionalArg(0)
    )
  }
}
