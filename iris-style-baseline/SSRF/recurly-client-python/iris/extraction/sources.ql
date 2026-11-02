/**
 * @name recurly-client-python CWE-918 source candidate extraction
 * @description Extract source candidates from the recurly-client-python
 *   2.6.1 CodeQL database (snapshot 9db2d1a) for Pass 3 / CWE-918 (SSRF).
 *   recurly-client-python is a client SDK for the Recurly REST API: it has
 *   no inbound HTTP surface of its own (no routes, no handlers, no
 *   framework), so the untrusted-input boundaries are (a) arguments the
 *   embedding application passes into the public API, (b) module-level
 *   configuration globals the host sets, (c) values the remote Recurly API
 *   controls (XML href attributes, Location/Link response headers) that
 *   the library re-feeds into subsequent requests (second-order SSRF
 *   carriers), and (d) the push-notification webhook XML decoded by
 *   objects_for_push_notification. Source families (all line evidence
 *   verified against the checked-out snapshot):
 *     1. public-API parameter boundaries (15 Function rows):
 *        URL-argument funnels http_request (resource.py:214),
 *        element_for_url (:355), headers_for_url (:346),
 *        page_for_url (resource.py:127), count_for_url (:137),
 *        paginated (:487), post (:655), put (:644); path-component
 *        parameters get (uuid, resource.py:333 -> member_path '%s'),
 *        js.fetch (token, js.py:41 -> 'recurly_js/result/%s'),
 *        Plan.get_add_on (add_on_code, __init__.py:1174);
 *        GiftCard.redeem (__init__.py:453, URL built from
 *        self.redemption_code, arg -1); webhook XML body
 *        objects_for_push_notification (__init__.py:1292); kwargs query
 *        construction all/count (resource.py:599/:615, arg -1).
 *     2. response header reads <resp>.getheader(...) (7 call sites:
 *        resource.py:153 Link, :363 Content-Type, :662 Location;
 *        __init__.py:260, :313, :585, :1084 Location) - Location/Link
 *        values are stored as self._url / next_url and re-requested.
 *     3. response body reads <response>.read() (12 sites: resource.py
 *        :365/:525/:529/:651/:665/:680, __init__.py:255/:271/:296/:317/
 *        :761/:876) - parsed as XML; element href values become URLs.
 *     4. server XML attribute maps <elem>.attrib (23 Attribute nodes:
 *        resource.py:46/:398/:406/:463/:465/:468/:471/:508/:556/:565/
 *        :566/:567/:573/:589/:701, __init__.py:223/:522/:533/:1121/
 *        :1122/:1123, errors.py:239/:240) - href/method values are
 *        remote-controlled; the href reads at resource.py:508/:566/
 *        :573/:589 and __init__.py:223/:1122 feed request URLs.
 *     5. remote XML parse entries ElementTree.fromstring(...) (12
 *        sites: resource.py:367/:527/:531/:653/:667, __init__.py:257/
 *        :273/:298/:319/:878/:1300, errors.py:18) - __init__.py:1300
 *        is the push-notification webhook body.
 *     6. configuration reads BASE_URI / SUBDOMAIN / CA_CERTS_FILE
 *        (6 sites: __init__.py:59/:62 bare module globals,
 *        resource.py:234/:246/:249 recurly.* attributes; assignment
 *        targets excluded via Assign.getATarget()).
 *     7. Link-header parsing parse_link_value(resp.getheader('Link'))
 *        (resource.py:153) - emits start_url/next_url later fetched
 *        by Page.next_page/first_page.
 *   API_KEY / SOCKET_TIMEOUT_SECONDS reads are NOT extracted: they only
 *   reach the Authorization header / socket timeout, never a URL.
 *   Rows under tests/, fixtures and the nested recurly-client-python-db/
 *   directory are excluded by path; candidates are restricted to the
 *   shipped recurly/ package.
 *   Raw BQRS extraction query: run with `codeql query run` and decode
 *   with `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong
 *   shape for candidate tables and @kind table is not assumed to exist.
 * @id iris/recurly-client-python-cwe918/extraction/sources
 * @tags ssrf
 */

import python

/* ------------------------------------------------------------------ */
/* Column contract (identical order to sinks.ql):                      */
/* ------------------------------------------------------------------ */

/*
 *   1. node       - candidate AST node (location-backed, decodes as
 *                   file:line:col)
 *   2. col1       - role: always "source_candidate" in this query
 *   3. callableName - function name at the boundary, or the called
 *                   member name (getheader / read / fromstring /
 *                   parse_link_value / attrib / config variable name)
 *   4. flowKind   - "param_url"              (caller-supplied full URL)
 *                   "param_path_component"   (uuid/token/code interpolated
 *                                             into the request path)
 *                   "param_xml_webhook"      (webhook XML body)
 *                   "param_kwargs_query"     (kwargs -> URL query string)
 *                   "param_attribute_url"    (URL built from a Resource
 *                                             attribute)
 *                   "response_header"        (getheader(...) value)
 *                   "response_body"          (response.read() value)
 *                   "xml_attribute"          (elem.attrib map, incl. href)
 *                   "xml_parse"              (fromstring(...) entry)
 *                   "config"                 (module-level config read)
 *                   "link_header_parse"      (parse_link_value(...) entry)
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression; enclosing class name for Function rows;
 *                   "" when none)
 *   6. moduleHint - dotted python module path of the candidate (variable
 *                   intentionally named moduleHint; `module` is not a
 *                   valid QL variable name here)
 *   7. argIndex   - 0-based positional argument index carrying the
 *                   URL-relevant value, -1 when not applicable
 *   8. file       - absolute file path, obtained through the Location API
 *                   (AstNode.getLocation().getFile().getAbsolutePath();
 *                   AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. matchKind  - always "ast" in this project (syntax-level match;
 *                   see detection.json matchStrategy)
 *  11. evidence   - one-line evidence summary for LLM labeling
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
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

/** Dotted path of the python module containing n (used as moduleHint).
 *  Files that are not on an import path have no dotted module name;
 *  their file base name is used instead. */
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
/* Source family 1: public-API parameter boundary table                */
/* ------------------------------------------------------------------ */

/**
 * Boundary functions of the public SDK API, with the 0-based positional
 * argument index that carries URL-relevant data and per-row evidence.
 * Each name is unique within the recurly/ package (verified by grep);
 * internal helpers that merely forward already-derived URLs are the
 * same rows - for a client SDK the host application IS the external
 * caller, so the earliest untrusted boundary of every flow is one of
 * these parameters (labeling decides which rows are real sources).
 */
predicate boundaryFunction(string name, string flowKind, int argIndex, string evidence) {
  name = "http_request" and flowKind = "param_url" and argIndex = 0 and
  evidence = "public low-level boundary: caller supplies the full request URL; all library requests funnel through it"
  or
  name = "element_for_url" and flowKind = "param_url" and argIndex = 0 and
  evidence = "GETs the resource at the given URL; url argument is the request target"
  or
  name = "headers_for_url" and flowKind = "param_url" and argIndex = 0 and
  evidence = "HEADs the given URL; url argument is the request target"
  or
  name = "page_for_url" and flowKind = "param_url" and argIndex = 0 and
  evidence = "fetches a result Page from the given URL"
  or
  name = "count_for_url" and flowKind = "param_url" and argIndex = 0 and
  evidence = "HEADs the given URL for the X-Records count"
  or
  name = "paginated" and flowKind = "param_url" and argIndex = 0 and
  evidence = "delegates to Page.page_for_url(url)"
  or
  name = "post" and flowKind = "param_url" and argIndex = 0 and
  evidence = "POSTs this resource to the given URL"
  or
  name = "put" and flowKind = "param_url" and argIndex = 0 and
  evidence = "PUTs this resource to the given URL"
  or
  name = "get" and flowKind = "param_path_component" and argIndex = 0 and
  evidence = "uuid interpolated into member_path ('accounts/%s' style) and requested"
  or
  name = "fetch" and flowKind = "param_path_component" and argIndex = 0 and
  evidence = "token interpolated into URL path 'recurly_js/result/%s' (js.py:42)"
  or
  name = "get_add_on" and flowKind = "param_path_component" and argIndex = 0 and
  evidence = "add_on_code interpolated into the request path (urljoin(self._url, '%s/add_ons/%s'))"
  or
  name = "redeem" and flowKind = "param_attribute_url" and argIndex = -1 and
  evidence = "URL built from self.redemption_code (caller- or server-set attribute); account_code goes into the body"
  or
  name = "objects_for_push_notification" and flowKind = "param_xml_webhook" and argIndex = 0 and
  evidence = "externally delivered push-notification XML body parsed via ElementTree.fromstring"
  or
  name = "all" and flowKind = "param_kwargs_query" and argIndex = -1 and
  evidence = "kwargs urlencoded into the query string of the collection URL; host stays base_uri (config)"
  or
  name = "count" and flowKind = "param_kwargs_query" and argIndex = -1 and
  evidence = "kwargs urlencoded into the query string of the collection URL; host stays base_uri (config)"
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind, string evidence
) {
  /* family 1: public-API parameter boundaries (Function nodes) */
  exists(Function f |
    boundaryFunction(f.getName(), flowKind, argIndex, evidence) and
    node = f and
    callableName = f.getName() and
    receiver = enclosingReceiver(f) and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast" and
    inRecurlyLibPath(f.getLocation().getFile().getAbsolutePath())
  )
  or
  /* family 2: response header reads (Location / Link / Content-Type) */
  exists(Call c |
    c.getFunc().(Attribute).getName() = "getheader" and
    node = c and
    callableName = "getheader" and
    flowKind = "response_header" and
    argIndex = -1 and
    receiver = receiverHint(c.getFunc().(Attribute)) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast" and
    inRecurlyLibPath(c.getLocation().getFile().getAbsolutePath()) and
    evidence = "response header value; Location/Link values are stored as _url/next_url and re-requested"
  )
  or
  /* family 3: response body reads */
  exists(Call c |
    c.getFunc().(Attribute).getName() = "read" and
    node = c and
    callableName = "read" and
    flowKind = "response_body" and
    argIndex = -1 and
    receiver = receiverHint(c.getFunc().(Attribute)) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast" and
    inRecurlyLibPath(c.getLocation().getFile().getAbsolutePath()) and
    evidence = "HTTP response body read and parsed as XML; parsed href values may become request URLs"
  )
  or
  /* family 4: server XML attribute maps (elem.attrib, incl. href) */
  exists(Attribute a |
    a = node and
    a.getName() = "attrib" and
    callableName = "attrib" and
    flowKind = "xml_attribute" and
    argIndex = -1 and
    receiver = receiverHint(a) and
    moduleHint = moduleHintOf(a) and
    matchKind = "ast" and
    inRecurlyLibPath(a.getLocation().getFile().getAbsolutePath()) and
    evidence = "server-controlled XML element attributes; href values (resource.py:508/:566/:589, __init__.py:223) feed request URLs"
  )
  or
  /* family 5: remote XML parse entries */
  exists(Call c |
    c.getFunc().(Attribute).getName() = "fromstring" and
    node = c and
    callableName = "ElementTree.fromstring" and
    flowKind = "xml_parse" and
    argIndex = 0 and
    receiver = receiverHint(c.getFunc().(Attribute)) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast" and
    inRecurlyLibPath(c.getLocation().getFile().getAbsolutePath()) and
    evidence = "parses remote/webhook XML into elements whose href attributes are later requested"
  )
  or
  /* family 6a: configuration reads, bare module globals (__init__.py) */
  exists(Name nm |
    nm = node and
    (nm.getId() = "BASE_URI" or nm.getId() = "SUBDOMAIN" or nm.getId() = "CA_CERTS_FILE") and
    not exists(Assign a | a.getATarget() = nm) and
    callableName = nm.getId() and
    flowKind = "config" and
    argIndex = -1 and
    receiver = "" and
    moduleHint = moduleHintOf(nm) and
    matchKind = "ast" and
    inRecurlyLibPath(nm.getLocation().getFile().getAbsolutePath()) and
    evidence = "module-level configuration read: SUBDOMAIN/BASE_URI determine the request host, CA_CERTS_FILE gates TLS validation"
  )
  or
  /* family 6b: configuration reads via recurly.<name> attributes (resource.py) */
  exists(Attribute at |
    at = node and
    (at.getName() = "BASE_URI" or at.getName() = "SUBDOMAIN" or at.getName() = "CA_CERTS_FILE") and
    at.getObject().(Name).getId() = "recurly" and
    callableName = at.getName() and
    flowKind = "config" and
    argIndex = -1 and
    receiver = "recurly" and
    moduleHint = moduleHintOf(at) and
    matchKind = "ast" and
    inRecurlyLibPath(at.getLocation().getFile().getAbsolutePath()) and
    evidence = "module-level configuration read: SUBDOMAIN/BASE_URI determine the request host, CA_CERTS_FILE gates TLS validation"
  )
  or
  /* family 7: Link-header parsing */
  exists(Call c |
    c.getFunc().(Name).getId() = "parse_link_value" and
    node = c and
    callableName = "parse_link_value" and
    flowKind = "link_header_parse" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast" and
    inRecurlyLibPath(c.getLocation().getFile().getAbsolutePath()) and
    evidence = "parses the Link response header into start_url/next_url, later fetched by Page.next_page/first_page"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind, string evidence
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind, evidence) and
  not isExcludedPath(node.getLocation().getFile().getAbsolutePath())
select
  node,
  "source_candidate",
  callableName,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  node.getLocation().getFile().getAbsolutePath() as file,
  node.getLocation().getStartLine() as line,
  matchKind,
  evidence
