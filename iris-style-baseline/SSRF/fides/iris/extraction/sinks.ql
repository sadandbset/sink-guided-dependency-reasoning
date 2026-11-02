
/**
 * @name Fides sink candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate outbound-network request APIs from the
 *              Fides FastAPI application for subsequent LLM labeling.
 * @id py/augur/fides/pass3-sinks
 *
 * Plain multi-column select query (no @kind) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * Scope: relative paths under src/fides/ only. This excludes the
 * nested fides-db CodeQL database directory, the repo-root tests/
 * harness trees, scripts/ and clients/ by construction.
 *
 * Only network-I/O call sites that exist in this source tree are
 * extracted. urllib.request.urlopen / urlretrieve / aiohttp /
 * http.client are not used anywhere in this project (urllib usage
 * is parse-only) and are therefore absent.
 *
 * Output columns:
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("sink_candidate")
 *  3. callable            (dotted signature hint)
 *  4. flow kind           (argument)
 *  5. receiver            (receiver/type hint)
 *  6. module hint         (dotted module path; variable named moduleHint,
 *                          "module" is a QL keyword and must not be used)
 *  7. argument index      (-1 when not applicable)
 *  8. line
 *  9. file:line
 * 10. expression text
 *
 * flow kind vocabulary:
 *   argument - the tainted URL position is an argument of the call
 *              (positional index given, or the url=/uri= keyword
 *               value node is extracted with arg index -1)
 */

import python

// ------------------------------------------------------------
// 1. Scope and location helpers
// ------------------------------------------------------------

/** Restrict extraction to the Fides application package. */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("src/fides/%")
  )
}

/** Restrict a candidate to the service layer (connectors, dispatch). */
predicate inServiceModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("src/fides/api/service/%")
  )
}

/** Restrict a candidate to the SaaS request override implementations. */
predicate inOverrideImplementations(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("src/fides/api/service/saas_request/override_implementations/%")
  )
}

/** Restrict a candidate to the requests Session transport module. */
predicate inAuthenticatedClientModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path = "src/fides/api/service/connectors/saas/authenticated_client.py"
  )
}

/**
 * Restrict a candidate to the httpx Client transport modules
 * (Fides-to-Fides connector and privacy request result transfer).
 */
predicate inHttpxSendModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    (
      path = "src/fides/api/service/connectors/fides/fides_client.py"
      or
      path = "src/fides/api/service/privacy_request/request_runner_service.py"
    )
  )
}

/** Restrict a candidate to the privacy request polling module. */
predicate inRequestServiceModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path = "src/fides/api/service/privacy_request/request_service.py"
  )
}

/** Restrict a candidate to the CLI utils module. */
predicate inCliUtilsModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path = "src/fides/cli/utils.py"
  )
}

/** Restrict a candidate to the external connector / core packages. */
predicate inConnectorsOrCoreModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    (
      path.matches("src/fides/connectors/%")
      or
      path.matches("src/fides/core/%")
    )
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
  string callable,
  string flow_kind,
  string receiver,
  string moduleHint,
  int arg_index
where
  inAnalysisScope(n) and
  moduleHint = moduleOf(n) and
  (
    // --------------------------------------------------------
    // (1) requests.get/post/put/delete/patch/head/request(...)
    //     module-level calls; URL at positional argument 0, or
    //     at the url= keyword (node = keyword value, arg -1)
    //     e.g. http_connector.py:48
    //            requests.post(url=config.url, headers=..., json=...)
    //          message_dispatch_service.py:418/471/492/512,
    //          core/api.py:28-130, core/user.py:34-112
    // --------------------------------------------------------

    exists(Call c, Attribute attr, Name lib, string verb |
      attr = c.getFunc() and
      attr.getName() = verb and
      verb in ["get", "post", "put", "delete", "patch", "head", "request"] and
      lib = attr.getObject() and
      lib.getId() = "requests" and
      (
        (
          n = c and
          arg_index = 0 and
          not exists(Keyword k |
            k = c.getAKeyword() and
            k.getArg() = "url"
          )
        )
        or
        (
          exists(Keyword k |
            k = c.getAKeyword() and
            k.getArg() = "url" and
            n = k.getValue()
          ) and
          arg_index = -1
        )
      ) and
      callable = "requests." + verb and
      flow_kind = "argument" and
      receiver = "requests"
    )

    or

    // --------------------------------------------------------
    // (2) bare post(...) calls in the SaaS override
    //     implementations (post imported from requests:
    //     authentication_strategy_{adobe_campaign,
    //     friendbuy_nextgen, heap, yotpo_reviews}.py)
    //     URL always at the url= keyword
    //     e.g. authentication_strategy_heap.py:48
    //          post(url=f"https://{domain}/api/public/v0/auth_token", ...)
    // --------------------------------------------------------

    exists(Call c, Name fn, Keyword k |
      fn = c.getFunc() and
      fn.getId() = "post" and
      k = c.getAKeyword() and
      k.getArg() = "url" and
      n = k.getValue() and
      inOverrideImplementations(c) and
      callable = "requests.post" and
      flow_kind = "argument" and
      receiver = "requests" and
      arg_index = -1
    )

    or

    // --------------------------------------------------------
    // (3) bare get(...)/put(...) calls in fides/cli/utils.py
    //     (get/put imported from requests at cli/utils.py:24)
    //     URL at positional argument 0
    //     e.g. cli/utils.py:106
    //          get(f"{config.cli.server_url}{V1_URL_PREFIX}{REGISTRATION}")
    // --------------------------------------------------------

    exists(Call c, Name fn, string verb |
      c = n and
      fn = c.getFunc() and
      fn.getId() = verb and
      verb in ["get", "put"] and
      inCliUtilsModule(c) and
      callable = "requests." + verb and
      flow_kind = "argument" and
      receiver = "requests" and
      arg_index = 0
    )

    or

    // --------------------------------------------------------
    // (4) session.send(...) transport calls
    //     (func Attribute 'send' on object Attribute 'session')
    //     - requests.Session.send in authenticated_client.py:207
    //       (SaaS PreparedRequest transport; URL built at :63-69
    //        from self.uri + request path)
    //     - httpx.Client.send in fides_client.py:125/227/271 and
    //       request_runner_service.py:679 (Fides-to-Fides
    //       connector and result transfer)
    //     request/prepared_request at positional argument 0
    // --------------------------------------------------------

    exists(Call c, Attribute method, Attribute sessionAttr |
      c = n and
      method = c.getFunc() and
      method.getName() = "send" and
      sessionAttr = method.getObject() and
      sessionAttr.getName() = "session" and
      (
        (
          inAuthenticatedClientModule(n) and
          callable = "requests.Session.send" and
          receiver = "requests.Session"
        )
        or
        (
          inHttpxSendModule(n) and
          callable = "httpx.Client.send" and
          receiver = "httpx.Client"
        )
      ) and
      flow_kind = "argument" and
      arg_index = 0
    )

    or

    // --------------------------------------------------------
    // (5) httpx.post(...) module-level calls
    //     URL at positional argument 0
    //     e.g. fides_client.py:59
    //          httpx.post(f"{self.uri}...{urls.LOGIN}", json=ul.dict())
    // --------------------------------------------------------

    exists(Call c, Attribute attr, Name lib |
      c = n and
      attr = c.getFunc() and
      attr.getName() = "post" and
      lib = attr.getObject() and
      lib.getId() = "httpx" and
      callable = "httpx.post" and
      flow_kind = "argument" and
      receiver = "httpx" and
      arg_index = 0
    )

    or

    // --------------------------------------------------------
    // (6) AsyncClient .get(url) polling calls in request_service
    //     URL at positional argument 0
    //     e.g. request_service.py:108/113
    //          await client.get(url, headers=...)
    // --------------------------------------------------------

    exists(Call c, Attribute attr, Name clientObj |
      c = n and
      attr = c.getFunc() and
      attr.getName() = "get" and
      clientObj = attr.getObject() and
      clientObj.getId() in ["client", "async_client"] and
      inRequestServiceModule(n) and
      callable = "httpx.AsyncClient.get" and
      flow_kind = "argument" and
      receiver = "httpx.AsyncClient" and
      arg_index = 0
    )

    or

    // --------------------------------------------------------
    // (7) AuthenticatedClient.send wrapper invocations
    //     (client.send(prepared_request, ...) in the service
    //      layer; URL is assembled inside the wrapper from
    //      ConnectionConfig secrets / saas config host)
    //     e.g. saas_connector.py:137/287/436/539,
    //          authentication_strategy_oauth2_base.py:92,
    //          *_request_overrides.py (braze/domo/friendbuy/
    //          mailchimp/twilio)
    //     request params at positional argument 0
    // --------------------------------------------------------

    exists(Call c, Attribute method, Name clientObj |
      c = n and
      method = c.getFunc() and
      method.getName() = "send" and
      clientObj = method.getObject() and
      clientObj.getId() = "client" and
      inServiceModule(n) and
      callable = "AuthenticatedClient.send" and
      flow_kind = "argument" and
      receiver = "AuthenticatedClient" and
      arg_index = 0
    )

    or

    // --------------------------------------------------------
    // (8a) AuthenticatedClient(uri, ...) constructor calls in
    //      the service layer - URI at positional argument 0
    //      e.g. saas_connector.py:155
    //           AuthenticatedClient(uri, self.configuration, ...)
    //           authentication_strategy_oauth2_base.py:81-85
    // --------------------------------------------------------

    exists(Call c, Name fn |
      c = n and
      fn = c.getFunc() and
      fn.getId() = "AuthenticatedClient" and
      inServiceModule(n) and
      exists(c.getArg(0)) and
      callable = "AuthenticatedClient.__init__" and
      flow_kind = "argument" and
      receiver = "AuthenticatedClient" and
      arg_index = 0
    )

    or

    // --------------------------------------------------------
    // (8b) FidesClient(...) constructor calls - URI at the
    //      uri= keyword (node = keyword value)
    //      e.g. fides_connector.py:57
    //           FidesClient(uri=config.uri, username=..., password=...)
    // --------------------------------------------------------

    exists(Call c, Name fn, Keyword k |
      fn = c.getFunc() and
      fn.getId() = "FidesClient" and
      k = c.getAKeyword() and
      k.getArg() = "uri" and
      n = k.getValue() and
      callable = "FidesClient.__init__" and
      flow_kind = "argument" and
      receiver = "FidesClient" and
      arg_index = -1
    )

    or

    // --------------------------------------------------------
    // (9) get_okta_client(okta_config) wrapper calls
    //     (network I/O happens inside the okta SDK using
    //      orgUrl from the CLI --org-url option / credentials
    //      config; okta_config at positional argument 0)
    //     e.g. fides/connectors/okta.py:58,
    //          fides/core/system.py:189
    // --------------------------------------------------------

    exists(Call c, Name fn |
      c = n and
      fn = c.getFunc() and
      fn.getId() = "get_okta_client" and
      inConnectorsOrCoreModule(n) and
      callable = "get_okta_client" and
      flow_kind = "argument" and
      receiver = "okta.Client" and
      arg_index = 0
    )
  )

select
  n,
  "sink_candidate",
  callable,
  flow_kind,
  receiver,
  moduleHint,
  arg_index,
  n.getLocation().getStartLine(),
  locationOf(n),
  n.toString()
