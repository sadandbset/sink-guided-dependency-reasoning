/**
 * @name recurly-client-python CWE-918 sink candidate extraction
 * @description Extract network-request sink candidates from the
 *   recurly-client-python 2.6.1 CodeQL database (snapshot 9db2d1a) for
 *   Pass 3 / CWE-918 (SSRF). The library performs ALL of its network
 *   access through a single funnel, and no requests/httpx/aiohttp/
 *   urllib.request/socket call sites exist in the tree (see
 *   detection.json absentApis). Sink families (all line evidence
 *   verified against the checked-out snapshot):
 *     1. final network I/O (5 rows, resource.py):
 *        http_client.HTTPConnection(urlparts.netloc) (:245),
 *        http_client.HTTPSConnection(urlparts.netloc) (:247, :250),
 *        connection.request(method, url, body, headers) (:279, URL at
 *        arg 1) and connection.getresponse() (:280) - http_client is
 *        six.moves.http_client, imported at resource.py:14.
 *     2. URL-argument funnel table (13 Function rows):
 *        http_request (:214, the single funnel), element_for_url
 *        (:355), headers_for_url (:346), page_for_url (:127),
 *        count_for_url (:137), paginated (:487), post (:655), put
 *        (:644), delete (:669, sends DELETE to self._url), get (:333,
 *        uuid -> member_path), js.fetch (js.py:41, token -> path),
 *        Plan.get_add_on (__init__.py:1174), GiftCard.redeem
 *        (__init__.py:453, URL from self.redemption_code).
 *     3. internal wrappers whose body directly contains a
 *        funnel-family call (~28 Function rows), including the
 *        follow-the-href closures actionator (resource.py:515) and
 *        relatitator (resource.py:574) that re-request server-provided
 *        hrefs, Page.next_page/first_page (:98/:112),
 *        Resource.all/count/_create/_update, and the __init__.py
 *        resource methods that POST/PUT to urljoin(self._url, ...)
 *        URLs (Account.__getattr__/charge/invoice/build_invoice/notes/
 *        reopen/subscribe/update_billing_info/create_shipping_address,
 *        GiftCard.preview, Coupon.generate/restore, Invoice.pdf/
 *        _create_refund_invoice, Purchase.__invoice,
 *        Subscription.preview/update_notes/create_usage,
 *        Transaction.get_refund_transaction, Plan.create_add_on).
 *     4. URL construction/parsing auxiliaries (33 rows - explicitly NOT
 *        final sinks, candidates for summary labeling):
 *        urljoin (28 sites: __init__.py 23, resource.py 4, js.py 1),
 *        urlsplit (resource.py:240 - netloc selects the connection
 *        host, scheme picks HTTP vs HTTPS), urlencode (resource.py:517/
 *        :577/:611/:621 - kwargs into the query string).
 *   Rows under tests/, fixtures and the nested recurly-client-python-db/
 *   directory are excluded by path; candidates are restricted to the
 *   shipped recurly/ package.
 *   Raw BQRS extraction query: run with `codeql query run` and decode
 *   with `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong
 *   shape for candidate tables and @kind table is not assumed to exist.
 * @id iris/recurly-client-python-cwe918/extraction/sinks
 * @tags ssrf
 */

import python

/* ------------------------------------------------------------------ */
/* Column contract (identical order to sources.ql):                    */
/* ------------------------------------------------------------------ */

/*
 *   1. node       - candidate AST node (location-backed, decodes as
 *                   file:line:col)
 *   2. col1       - role: always "sink_candidate" in this query
 *   3. callableName - called member name ("http_client.HTTPConnection",
 *                   "HTTPConnection.request", "getresponse") or function
 *                   name for wrapper rows, or the construction helper
 *                   name ("urljoin" / "urlsplit" / "urlencode")
 *   4. flowKind   - "network_ctor_host"     (connection constructor on
 *                                             urlsplit netloc, host at
 *                                             arg_index)
 *                   "network_request_url"   (connection.request, URL at
 *                                             arg_index)
 *                   "network_response"      (connection.getresponse)
 *                   "internal_request_funnel" (http_request)
 *                   "internal_fetch_wrapper" (wrapper whose argument or
 *                                             body reaches a request)
 *                   "url_construction"      (urljoin auxiliary)
 *                   "url_parse"             (urlsplit auxiliary)
 *                   "query_construction"    (urlencode auxiliary)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression; enclosing class name for Function rows;
 *                   "" when none)
 *   6. moduleHint - external module name ("six.moves.http_client",
 *                   "six.moves.urllib.parse") for external API rows, or
 *                   the dotted python module path of the candidate
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here)
 *   7. argIndex   - 0-based positional argument index carrying the URL
 *                   (1 for connection.request where arg 0 is the
 *                   method), -1 when not applicable
 *   8. file       - absolute file path, obtained through the Location API
 *                   (AstNode.getLocation().getFile().getAbsolutePath();
 *                   AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. matchKind  - always "ast" in this project (syntax-level match;
 *                   see detection.json matchStrategy)
 *  11. evidence   - one-line evidence summary for LLM labeling
 */

/* ------------------------------------------------------------------ */
/* Generic helpers (identical to sources.ql)                           */
/* ------------------------------------------------------------------ */

/** Path filter (Augur candidate strategy: exclude tests/fixtures and the
 *  nested CodeQL database directory). Both forward-slash and backslash
 *  separators are covered; only called with paths obtained from CodeQL
 *  File locations (input binding set declared explicitly). */
bindingset[p]
predicate isExcludedPath(string p) {
  p.matches("%/tests/%")
  or
  p.matches("%\\tests\\%")
  or
  p.matches("%/test_%.py")
  or
  p.matches("%\\test_%.py")
  or
  p.matches("%/conftest.py")
  or
  p.matches("%\\conftest.py")
  or
  p.matches("%recurly-client-python-db%")
}

/** Restriction to the shipped library package recurly/ (the SDK surface
 *  consumed by host applications; tests and the nested database
 *  directory are excluded separately). The pattern requires a path
 *  segment exactly named recurly, so recurly-client-python-db does not
 *  match. */
bindingset[p]
predicate inRecurlyLibPath(string p) {
  p.matches("%/recurly/%")
  or
  p.matches("%\\recurly\\%")
}

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Files that are not on an import path have no
 *  dotted module name; their file base name is used instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getBaseName()
}

/** Base name of the object expression of an attribute access, used as a
 *  receiver hint. */
string receiverHint(Attribute a) {
  result = a.getObject().(Name).getId()
  or
  result = a.getObject().(Attribute).getName()
  or
  not a.getObject() instanceof Name and
  not a.getObject() instanceof Attribute and
  result = "<expr>"
}

/** Enclosing class name for method rows; "" for module-level or nested
 *  functions (e.g. the actionator/relatitator closures). */
string enclosingReceiver(Function f) {
  f.getEnclosingScope() instanceof Class and
  result = f.getEnclosingScope().(Class).getName()
  or
  not f.getEnclosingScope() instanceof Class and
  result = ""
}

/* ------------------------------------------------------------------ */
/* Sink family 2: URL-argument funnel table                            */
/* ------------------------------------------------------------------ */

/**
 * Core request funnels of the library, with the 0-based positional
 * argument index that carries the URL (or URL path component) and
 * per-row evidence. Each name is unique within the recurly/ package
 * (verified by grep).
 */
predicate funnelFunction(string name, string flowKind, int argIndex, string evidence) {
  name = "http_request" and flowKind = "internal_request_funnel" and argIndex = 0 and
  evidence = "the only funnel: every library request goes http_request(url, ...) -> HTTP(S)Connection -> connection.request"
  or
  name = "element_for_url" and flowKind = "internal_fetch_wrapper" and argIndex = 0 and
  evidence = "GETs the url argument and parses the XML response"
  or
  name = "headers_for_url" and flowKind = "internal_fetch_wrapper" and argIndex = 0 and
  evidence = "HEADs the url argument and returns the response headers"
  or
  name = "page_for_url" and flowKind = "internal_fetch_wrapper" and argIndex = 0 and
  evidence = "fetches the result Page at the url argument"
  or
  name = "count_for_url" and flowKind = "internal_fetch_wrapper" and argIndex = 0 and
  evidence = "HEADs the url argument for the X-Records count"
  or
  name = "paginated" and flowKind = "internal_fetch_wrapper" and argIndex = 0 and
  evidence = "delegates to Page.page_for_url(url)"
  or
  name = "post" and flowKind = "internal_fetch_wrapper" and argIndex = 0 and
  evidence = "POSTs this resource to the url argument"
  or
  name = "put" and flowKind = "internal_fetch_wrapper" and argIndex = 0 and
  evidence = "PUTs this resource to the url argument"
  or
  name = "delete" and flowKind = "internal_fetch_wrapper" and argIndex = -1 and
  evidence = "sends DELETE to self._url (server XML href or Location header, resource.py:662)"
  or
  name = "get" and flowKind = "internal_fetch_wrapper" and argIndex = 0 and
  evidence = "uuid interpolated into member_path ('accounts/%s' style) and fetched"
  or
  name = "fetch" and flowKind = "internal_fetch_wrapper" and argIndex = 0 and
  evidence = "token interpolated into 'recurly_js/result/%s' and fetched (js.py:42)"
  or
  name = "get_add_on" and flowKind = "internal_fetch_wrapper" and argIndex = 0 and
  evidence = "add_on_code interpolated into the request path and fetched"
  or
  name = "redeem" and flowKind = "internal_fetch_wrapper" and argIndex = -1 and
  evidence = "request URL built from self.redemption_code; recipient account goes into the body"
}

/* ------------------------------------------------------------------ */
/* Sink family 3: internal wrapper discovery                           */
/* ------------------------------------------------------------------ */

/** Attribute call names that forward into the request funnel (used for
 *  wrapper discovery). All funnel invocations in the recurly/ package
 *  are attribute calls (self.post(...), Page.page_for_url(...),
 *  recurly.Resource.element_for_url(...), ...). */
predicate funnelCallName(string name) {
  name in [
    "http_request", "element_for_url", "headers_for_url", "page_for_url",
    "count_for_url", "paginated", "post", "put"
  ]
}

/** Functions in this codebase whose body directly issues or forwards a
 *  request through the funnel family: the follow-the-href closures
 *  actionator (resource.py:515) and relatitator (resource.py:574), the
 *  Page walkers next_page/first_page, and the resource methods that
 *  POST/PUT to urljoin(self._url, ...) URLs in __init__.py. */
private predicate internalFetchWrapper(Function f) {
  exists(Call c, string fname |
    funnelCallName(fname) and
    c.getFunc().(Attribute).getName() = fname and
    c.getScope().(Function) = f and
    inRecurlyLibPath(f.getLocation().getFile().getAbsolutePath())
  )
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind, string evidence
) {
  /* family 1a: connection constructors (final network I/O) */
  exists(Call c |
    c.getFunc().(Attribute).getName() in ["HTTPConnection", "HTTPSConnection"] and
    c.getFunc().(Attribute).getObject().(Name).getId() = "http_client" and
    node = c and
    callableName = "http_client." + c.getFunc().(Attribute).getName() and
    flowKind = "network_ctor_host" and
    argIndex = 0 and
    receiver = "http_client" and
    moduleHint = "six.moves.http_client" and
    matchKind = "ast" and
    inRecurlyLibPath(c.getLocation().getFile().getAbsolutePath()) and
    evidence = "host/netloc from urlsplit(url) (resource.py:240) opens the connection - actual network I/O sink"
  )
  or
  /* family 1b: connection.request - final request emission */
  exists(Call c |
    c.getFunc().(Attribute).getName() = "request" and
    c.getFunc().(Attribute).getObject().(Name).getId() = "connection" and
    exists(c.getArg(1)) and
    node = c and
    callableName = "HTTPConnection.request" and
    flowKind = "network_request_url" and
    argIndex = 1 and
    receiver = "connection" and
    moduleHint = "six.moves.http_client" and
    matchKind = "ast" and
    inRecurlyLibPath(c.getLocation().getFile().getAbsolutePath()) and
    evidence = "url argument (arg 1) sent on the open connection - final request emission (resource.py:279)"
  )
  or
  /* family 1c: connection.getresponse - completes the round trip */
  exists(Call c |
    c.getFunc().(Attribute).getName() = "getresponse" and
    c.getFunc().(Attribute).getObject().(Name).getId() = "connection" and
    node = c and
    callableName = "HTTPConnection.getresponse" and
    flowKind = "network_response" and
    argIndex = -1 and
    receiver = "connection" and
    moduleHint = "six.moves.http_client" and
    matchKind = "ast" and
    inRecurlyLibPath(c.getLocation().getFile().getAbsolutePath()) and
    evidence = "completes the HTTP round trip; the buffered request is actually sent on this call (resource.py:280)"
  )
  or
  /* family 2: URL-argument funnel table (Function nodes) */
  exists(Function f |
    funnelFunction(f.getName(), flowKind, argIndex, evidence) and
    node = f and
    callableName = f.getName() and
    receiver = enclosingReceiver(f) and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast" and
    inRecurlyLibPath(f.getLocation().getFile().getAbsolutePath())
  )
  or
  /* family 3: internal wrappers (functions whose body directly issues
   * or forwards a request through the funnel family); functions already
   * covered by the family-2 table are excluded to avoid duplicate rows */
  exists(Function f |
    internalFetchWrapper(f) and
    not exists(string fk, int ai, string ev | funnelFunction(f.getName(), fk, ai, ev)) and
    node = f and
    callableName = f.getName() and
    flowKind = "internal_fetch_wrapper" and
    argIndex = -1 and
    receiver = enclosingReceiver(f) and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast" and
    evidence = "body directly calls a request funnel (http_request/element_for_url/post/put/page_for_url/...); URL typically built from self._url or urljoin(base, path)"
  )
  or
  /* family 4a: urljoin construction sites (auxiliary, not final sinks) */
  exists(Call c |
    c.getFunc().(Name).getId() = "urljoin" and
    node = c and
    callableName = "urljoin" and
    flowKind = "url_construction" and
    argIndex = 1 and
    receiver = "" and
    moduleHint = "six.moves.urllib.parse" and
    matchKind = "ast" and
    inRecurlyLibPath(c.getLocation().getFile().getAbsolutePath()) and
    evidence = "urljoin(base, path): arg 0 usually base_uri()/self._url (server href/Location), arg 1 a code/uuid path; result feeds http_request"
  )
  or
  /* family 4b: urlsplit parse site (auxiliary, not a final sink) */
  exists(Call c |
    c.getFunc().(Name).getId() = "urlsplit" and
    node = c and
    callableName = "urlsplit" and
    flowKind = "url_parse" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "six.moves.urllib.parse" and
    matchKind = "ast" and
    inRecurlyLibPath(c.getLocation().getFile().getAbsolutePath()) and
    evidence = "urlsplit(url) inside http_request; netloc selects the connection host, scheme picks HTTP vs HTTPS (resource.py:240-250)"
  )
  or
  /* family 4c: urlencode query construction (auxiliary, not a final sink) */
  exists(Call c |
    c.getFunc().(Name).getId() = "urlencode" and
    node = c and
    callableName = "urlencode" and
    flowKind = "query_construction" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = "six.moves.urllib.parse" and
    matchKind = "ast" and
    inRecurlyLibPath(c.getLocation().getFile().getAbsolutePath()) and
    evidence = "kwargs serialized into the query string appended to the request URL"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind, string evidence
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind, evidence) and
  not isExcludedPath(node.getLocation().getFile().getAbsolutePath())
select
  node,
  "sink_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind,
  evidence
