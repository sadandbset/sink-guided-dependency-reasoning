/**
 * @name Matrix Sydent sink candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate outbound-network request call
 *              sites from the matrix-sydent (Matrix Identity
 *              Server) application source for subsequent LLM
 *              labeling.
 * @id py/augur/sydent/pass3-sinks
 *
 * Plain multi-column select query (NO @kind metadata declared) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * Only network call sites that exist in this source tree are
 * extracted (sydent application code only; twisted, signedjson,
 * nacl, sentry_sdk library internals are external to the database
 * - only six stubs are present - so matching is AST call-site
 * based: module-qualified name + receiver object name + argument
 * index, never invented APIs). Sydent performs ALL of its HTTP
 * egress through twisted.web.client Agent.request; there is no
 * urllib.request.urlopen / urlretrieve / requests / httpx call
 * site anywhere in the indexed source.
 *
 * FINAL NETWORK I/O (twisted Agent / endpoints):
 *
 *   - self.agent.request(b"GET", uri.encode("utf8"))
 *     sydent/http/httpclient.py:52 (HTTPClient.get_json) - the
 *     GET transport of SimpleHttpClient AND FederationHttpClient.
 *     Reached with attacker-influenced URIs from:
 *     sydent/hs_federation/verifier.py:80
 *     "matrix://%s/_matrix/key/v2/server/" % server_name (server
 *     names from signed_json['signatures'] / the X-Matrix origin
 *     header of threepidunbind requests) and
 *     sydent/http/servlets/registerservlet.py:59
 *     "matrix://%s/_matrix/federation/v1/openid/userinfo?..." %
 *     matrix_server (matrix_server_name POST-body field, guarded
 *     by is_valid_hostname at :52).
 *
 *   - self.agent.request(b"POST", uri.encode("utf8"), headers,
 *     bodyProducer=...) sydent/http/httpclient.py:91
 *     (HTTPClient.post_json_get_nothing) - the POST transport.
 *     Reached from sydent/threepid/bind.py:162 post_url
 *     "matrix://%s/_matrix/federation/v1/3pid/onbind" %
 *     mxid-server-part (mxid is a request field, guarded by
 *     is_valid_hostname at bind.py:146) and
 *     sydent/sms/openmarket.py:101 API_BASE_URL (constant).
 *
 *   - self.agent.request(b'POST', uri.encode('utf8'), headers,
 *     ...) sydent/http/httpsclient.py:70
 *     (ReplicationHttpsClient.postJson) - the replication push
 *     transport; uri is self.replication_url built at
 *     sydent/replication/peer.py:133 "https://%s:%i" from the
 *     peers DB table / peer.<name> config.
 *
 *   - agent.request(method, uri, headers, bodyProducer)
 *     sydent/http/matrixfederationagent.py:176
 *     (MatrixFederationAgent.request) - the federation routing
 *     entry: matrix:// URIs are SRV / .well-known resolved here
 *     and the connection is made through the endpoint factory
 *     below. uri is the same matrix:// URL from verifier.py:80 /
 *     registerservlet.py:59 / bind.py:162.
 *
 *   - self._well_known_agent.request(b"GET", uri)
 *     sydent/http/matrixfederationagent.py:322
 *     (_do_get_well_known) - uri is b"https://%s/.well-known/
 *     matrix/server" % server_name at :318; server_name derives
 *     from the matrix:// URI host (request-derived server names).
 *
 *   - HostnameEndpoint(reactor, host, port, ...)
 *     sydent/http/matrixfederationagent.py:366 - the TCP endpoint
 *     actually connected to for federation traffic (host from SRV
 *     resolution / .well-known / the matrix:// URI host). The
 *     LoggingHostnameEndpoint(...) wrapper call at :168 passes
 *     res.target_host / res.target_port through.
 *
 * REPO-INTERNAL HTTP WRAPPERS (call sites; the LLM should decide
 * sink vs summary labels - each forwards to the Agent.request
 * transports above):
 *
 *   - get_json(uri, ...) defined httpclient.py:38; call sites:
 *     sydent/hs_federation/verifier.py:80 (uri at index 0,
 *     server_name interpolated) and
 *     sydent/http/servlets/registerservlet.py:59 (uri at index
 *     0, matrix_server + access_token interpolated).
 *   - post_json_get_nothing(uri, post_json, opts) defined
 *     httpclient.py:66; call sites: sydent/threepid/bind.py:162
 *     (post_url at index 0) and sydent/sms/openmarket.py:101
 *     (constant API_BASE_URL at index 0).
 *   - postJson(uri, jsonObject) defined httpsclient.py:50; call
 *     site: sydent/replication/peer.py:200 (self.replication_url
 *     at index 0).
 *
 * NON-HTTP NETWORK I/O, recorded separately (DNS / SMTP, not
 * canonical CWE-918 HTTP(S) but the same egress class for this
 * service):
 *   - self._dns_client.lookupService(service_name)
 *     sydent/http/srvresolver.py:125 - DNS SRV resolution of
 *     b"_matrix._tcp.%s" % matrix-URI-host (service_name at
 *     index 0); DNS-based SSRF signal.
 *   - smtplib.SMTP(mailServer, mailPort, myHostname) /
 *     smtplib.SMTP_SSL(...) sydent/util/emailutils.py:96/:98/:101
 *     - SMTP egress (mailServer from the 'email.smtphost'
 *     config option; operator-controlled, expected FP material).
 *
 * EXTERNAL SDK EGRESS:
 *   - sentry_sdk.init(dsn=...) sydent/sydent.py:210 - dsn via
 *     keyword argument from the 'sentry_dsn' config option
 *     (operator-controlled, expected FP material; the SDK itself
 *     is external to the database, only the call site is real).
 *
 * Things deliberately NOT extracted as CWE-918 sinks:
 *   - urllib.request.urlopen / urlretrieve / requests / httpx:
 *     no call site exists in the indexed source.
 *   - URI.fromBytes (matrixfederationagent.py:141),
 *     urlparse-style handling in six.moves.urllib stubs and
 *     urllib.parse.quote (registerservlet.py:63, verifier.py /
 *     emailvalidator.py:108-122): URL parsing / construction
 *     only, not network I/O; flows are tracked to the
 *     Agent.request sites above.
 *   - optionsForClientTLS / wrapClientTLS (httpsclient.py:82,
 *     matrixfederationagent.py:172): TLS option construction.
 *   - RedirectAgent / Agent / HTTPConnectionPool constructors
 *     (matrixfederationagent.py:105-107): object construction;
 *     the request happens in Agent.request.
 *   - reactor.listenTCP / listenSSL / start_http_server
 *     (httpserver.py, sydent.py:218): inbound listeners.
 *   - request.setHeader("Location", next_link) redirects
 *     (emailservlet.py:108, msisdnservlet.py:129): open
 *     redirect (Pass 9), not server-side request forgery.
 *   - open() calls (templates, config, pidfile, sqlite scripts):
 *     local file I/O (Pass 1 territory).
 *   - OpenMarketSMS.sendTextSMS / EmailValidator.requestToken /
 *     MsisdnValidator.requestToken wrapper call sites: no
 *     URL-bearing argument at those call sites (the URL is the
 *     constant API_BASE_URL or is built inside the wrapper); the
 *     underlying transports are already extracted.
 *
 * Verified API usage (codeql/python-all 7.1.2 cached under
 * C:\Users\lzh\.codeql\packages, same surface as the earlier
 * label-studio/django/calibre-web/core/mlflow SSRF runs):
 *   - Attribute.getName() / Attribute.getObject() and Name.
 *     getId() for receiver-shape matching; every string used in a
 *     comparison is bound via equality first (no
 *     unbound-variable errors).
 *   - Call.getFunc() / Call.getPositionalArg(int) / casts via
 *     .(Name) / .(Attribute) / .(StringLiteral).
 *   - moduleHint is bound via getScope().getEnclosingModule().
 *     getName(); the variable is named moduleHint because
 *     `module` is a QL keyword.
 *   - Locations use AstNode.getLocation().getFile().
 *     getRelativePath() and getLocation().getStartLine(); there
 *     is no AstNode.getFile() predicate.
 *
 * Scope: path.matches("sydent/%") - this cannot match the nested
 * "sydent-db/" CodeQL database directory (hyphen vs slash at
 * position 7), nor tests/, matrix_is_test/, setup.py, nor the
 * C_/codeql/... extractor stubs.
 *
 * Output columns (same order as the earlier SSRF runs):
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("sink_candidate")
 *  3. callable name       (dotted signature hint)
 *  4. flow kind           ("argument")
 *  5. receiver hint       (receiver/type hint)
 *  6. module hint         (dotted module path; variable named
 *                          moduleHint, "module" is a QL keyword)
 *  7. argument index      (index of the URL/host-bearing
 *                          argument; -1 when keyword-based)
 *  8. line
 *  9. file:line
 * 10. expression text
 */

import python

// ------------------------------------------------------------
// 1. Scope and location helpers
// ------------------------------------------------------------

/**
 * Restrict extraction to the sydent application package.
 *
 * The CodeQL database source root is the repository root, so
 * relative paths of application files look like
 * "sydent/http/httpclient.py". "sydent/%" cannot match the nested
 * "sydent-db/" database directory ('-' vs '/' at position 7), the
 * top-level tests/ or matrix_is_test/ directories, setup.py, or
 * the C_/codeql/... extractor stubs.
 */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("sydent/%")
  )
}

/** Dotted module name of a candidate. */
string moduleOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
}

/** Human-readable file and line location. */
string locationOf(AstNode n) {
  result =
    n.getLocation().getFile().getRelativePath() +
    ":" +
    n.getLocation().getStartLine().toString()
}

// ------------------------------------------------------------
// 2. Candidate extraction
// ------------------------------------------------------------

from
  AstNode n,
  string callableName,
  string flowKind,
  string receiverHint,
  string moduleHint,
  int argIndex
where
  inAnalysisScope(n) and
  moduleHint = moduleOf(n) and
  (
    // --------------------------------------------------------
    // (1) <agent>.request(method, uri, ...) - the FINAL twisted
    //     network I/O of the whole service. Receiver objects
    //     observed in this source: self.agent (httpclient.py:52
    //     GET, :91 POST; httpsclient.py:70 POST), agent
    //     (matrixfederationagent.py:176, the routed federation
    //     request) and self._well_known_agent
    //     (matrixfederationagent.py:322, .well-known fetch).
    //     The URL-bearing argument is the URI at positional
    //     index 1 (index 0 is the HTTP method).
    // --------------------------------------------------------

    exists(Call c, Attribute req, Expr obj, string objName |
      n = c and
      req = c.getFunc().(Attribute) and
      req.getName() = "request" and
      obj = req.getObject() and
      (
        objName = "agent" and
        (obj.(Name).getId() = "agent" or obj.(Attribute).getName() = "agent")
        or
        objName = "_well_known_agent" and
        (obj.(Name).getId() = "_well_known_agent" or obj.(Attribute).getName() = "_well_known_agent")
      ) and
      callableName = "twisted.web.client.Agent.request" and
      flowKind = "argument" and
      receiverHint = "twisted.web.client.Agent." + objName and
      argIndex = 1
    )

    or

    // --------------------------------------------------------
    // (2) <client>.get_json(uri, ...) call sites - the JSON GET
    //     wrapper (defined sydent/http/httpclient.py:38; the
    //     underlying transport is clause (1)). Call sites:
    //     sydent/hs_federation/verifier.py:80 (server_name
    //     interpolated into a matrix:// URL) and
    //     sydent/http/servlets/registerservlet.py:59
    //     (matrix_server + access_token interpolated). The
    //     URL-bearing argument is at index 0. Receiver names
    //     observed: client / self.client.
    // --------------------------------------------------------

    exists(Call c, Attribute m, Expr obj |
      n = c and
      m = c.getFunc().(Attribute) and
      m.getName() = "get_json" and
      obj = m.getObject() and
      (obj.(Name).getId() = "client" or obj.(Attribute).getName() = "client") and
      callableName = "sydent.http.httpclient.HTTPClient.get_json" and
      flowKind = "argument" and
      receiverHint = "sydent.http.httpclient.HTTPClient" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (3) <client>.post_json_get_nothing(uri, post_json, opts)
    //     call sites - the JSON POST wrapper (defined
    //     sydent/http/httpclient.py:66). Call sites:
    //     sydent/threepid/bind.py:162 (post_url) and
    //     sydent/sms/openmarket.py:101 (constant API_BASE_URL).
    //     The URL-bearing argument is at index 0. Receiver names
    //     observed: http_client / self.http_cli.
    // --------------------------------------------------------

    exists(Call c, Attribute m, Expr obj |
      n = c and
      m = c.getFunc().(Attribute) and
      m.getName() = "post_json_get_nothing" and
      obj = m.getObject() and
      (
        obj.(Name).getId() = "http_client" or obj.(Attribute).getName() = "http_client"
        or
        obj.(Name).getId() = "http_cli" or obj.(Attribute).getName() = "http_cli"
      ) and
      callableName = "sydent.http.httpclient.HTTPClient.post_json_get_nothing" and
      flowKind = "argument" and
      receiverHint = "sydent.http.httpclient.HTTPClient" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (4) replicationHttpsClient.postJson(uri, jsonObject) call
    //     site - the replication push wrapper (defined
    //     sydent/http/httpsclient.py:50; underlying transport is
    //     clause (1)). Single call site:
    //     sydent/replication/peer.py:200 with
    //     self.replication_url at index 0 (built from the peers
    //     DB table at peer.py:127-138).
    // --------------------------------------------------------

    exists(Call c, Attribute m |
      n = c and
      m = c.getFunc().(Attribute) and
      m.getName() = "postJson" and
      callableName = "sydent.http.httpsclient.ReplicationHttpsClient.postJson" and
      flowKind = "argument" and
      receiverHint = "sydent.http.httpsclient.ReplicationHttpsClient" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (5) HostnameEndpoint(reactor, host, port, ...) /
    //     LoggingHostnameEndpoint(reactor, target_host,
    //     target_port) constructions - the TCP endpoints that
    //     federation traffic actually connects to (SRV /
    //     .well-known / matrix:// URI resolution results).
    //     sydent/http/matrixfederationagent.py:366 (real
    //     HostnameEndpoint) and :168 (LoggingHostnameEndpoint
    //     wrapper inside EndpointFactory.endpointForURI). The
    //     host-bearing argument is at index 1 (index 0 is the
    //     reactor).
    // --------------------------------------------------------

    exists(Call c, Name fn, string epName |
      n = c and
      fn = c.getFunc().(Name) and
      (
        epName = "HostnameEndpoint" and fn.getId() = "HostnameEndpoint"
        or
        epName = "LoggingHostnameEndpoint" and fn.getId() = "LoggingHostnameEndpoint"
      ) and
      callableName = "sydent.http.matrixfederationagent." + epName and
      flowKind = "argument" and
      receiverHint = "twisted.internet.endpoints.HostnameEndpoint" and
      argIndex = 1
    )

    or

    // --------------------------------------------------------
    // (6) self._dns_client.lookupService(service_name) - DNS SRV
    //     resolution (sydent/http/srvresolver.py:125), queried
    //     with b"_matrix._tcp.%s" % matrix-URI-host from
    //     matrixfederationagent.py:258. DNS egress; the
    //     service-name argument is at index 0.
    // --------------------------------------------------------

    exists(Call c, Attribute m, Expr obj |
      n = c and
      m = c.getFunc().(Attribute) and
      m.getName() = "lookupService" and
      obj = m.getObject() and
      (obj.(Name).getId() = "_dns_client" or obj.(Attribute).getName() = "_dns_client") and
      callableName = "twisted.names.client.lookupService" and
      flowKind = "argument" and
      receiverHint = "sydent.http.srvresolver.SrvResolver._dns_client" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (7) smtplib.SMTP(mailServer, mailPort, myHostname) /
    //     smtplib.SMTP_SSL(...) - SMTP egress of the
    //     verification-email sender (sydent/util/emailutils.py:
    //     96/:98/:101). mailServer is the 'email.smtphost'
    //     config option (operator-controlled, expected FP
    //     material for remote SSRF). Host-bearing argument at
    //     index 0.
    // --------------------------------------------------------

    exists(Call c, Attribute m, Name smtpName, string smtpClass |
      n = c and
      m = c.getFunc().(Attribute) and
      (
        smtpClass = "SMTP" and m.getName() = "SMTP"
        or
        smtpClass = "SMTP_SSL" and m.getName() = "SMTP_SSL"
      ) and
      smtpName = m.getObject().(Name) and
      smtpName.getId() = "smtplib" and
      callableName = "smtplib." + smtpClass and
      flowKind = "argument" and
      receiverHint = "smtplib" and
      argIndex = 0
    )

    or

    // --------------------------------------------------------
    // (8) sentry_sdk.init(dsn=...) - external SDK egress
    //     (sydent/sydent.py:210). The DSN travels via the 'dsn'
    //     keyword argument from the 'sentry_dsn' config option,
    //     so argIndex is -1 (keyword-based, operator-controlled,
    //     expected FP material; the SDK is external to the
    //     database, only the call site is real).
    // --------------------------------------------------------

    exists(Call c, Attribute m, Name sdkName |
      n = c and
      m = c.getFunc().(Attribute) and
      m.getName() = "init" and
      sdkName = m.getObject().(Name) and
      sdkName.getId() = "sentry_sdk" and
      callableName = "sentry_sdk.init" and
      flowKind = "argument" and
      receiverHint = "sentry_sdk" and
      argIndex = -1
    )
  )

select
  n,
  "sink_candidate",
  callableName,
  flowKind,
  receiverHint,
  moduleHint,
  argIndex,
  n.getLocation().getStartLine(),
  locationOf(n),
  n.toString()
