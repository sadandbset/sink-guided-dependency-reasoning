/**
 * @name core (Home Assistant) CWE-918 sink candidate extraction
 * @description Extract network-request sink candidates from the Home Assistant
 *   core CodeQL database (snapshot e2dd7f2) for Pass 3 / CWE-918 (SSRF).
 *   Sink families derived from real source inspection (line evidence verified
 *   against the checked-out snapshot):
 *     1. resolved external HTTP-client API calls (API graphs, alias-aware):
 *        requests.get/post/put/head/delete/patch/request/Session,
 *        httpx.get/.../request/stream/Client/AsyncClient,
 *        aiohttp.ClientSession (89 requests.* call sites, 3 direct
 *        aiohttp.ClientSession constructions: auth/indieauth.py:95,
 *        octoprint/config_flow.py:269, octoprint/__init__.py:171)
 *     2. syntax-level shapes of the same external APIs
 *        (`requests.get(...)`, `aiohttp.ClientSession(...)`, ...)
 *     3. session/http-client method calls: <session>.get/post/put/head/
 *        delete/patch/options/ws_connect (URL at arg 0), <session>.request/
 *        stream (URL at arg 1), <session>.send (prepared request at arg 0),
 *        on receivers with a session name (repo-derived table: session,
 *        websession, httpsession, ...) or provenance from the internal
 *        client getters / client constructors in the same file (~76 call
 *        sites, e.g. hassio/handler.py:534 websession.request(method,
 *        f"http://{self._ip}{command}"), blueprint/importer.py:155
 *        session.get(import_url), mjpeg/camera.py:174 client.get)
 *     4. the internal shared client funnels:
 *        homeassistant.helpers.aiohttp_client.async_get_clientsession /
 *        async_create_clientsession (493 importing files) and
 *        homeassistant.helpers.httpx_client.get_async_client /
 *        create_async_httpx_client (28 files) - summary/label candidates,
 *        they hand out the sessions every fetch goes through
 *     5. dynamic-dispatch fetches: getattr(<session>, method)(url, ...)
 *        (rest_command/__init__.py:121, rest/switch.py:206)
 *     6. URL construction sites: yarl.URL(...) / yarl.URL.build(...) /
 *        urljoin(...) (39 + 9 + 8 sites) - candidates for summary labeling,
 *        not final network I/O by themselves
 *     7. internal fetch wrappers: functions whose body directly contains a
 *        fetch call site of families 1/2/3/5 (blueprint importer
 *        fetch_*_from_* at importer.py:144/154/176, hassio handler
 *        api_command at handler.py:520, rest_command handler,
 *        camera image fetchers, ...)
 *   urllib.request.urlopen / urlretrieve have zero call sites in this tree
 *   and are not emitted (operator rule: only APIs proven present; see
 *   detection.json absent_apis). URL parsing/construction alone is not
 *   treated as a final sink; rows under tests/ and core-db/ are excluded.
 *   Raw BQRS extraction query: run with `codeql query run` and decode with
 *   `codeql bqrs decode` (not database analyze). This is a plain multi-column
 *   select query on purpose: @kind problem is the wrong shape for candidate
 *   tables and @kind table is not assumed to exist.
 * @id iris/core-cwe918/extraction/sinks
 * @tags ssrf
 */

import python
import semmle.python.ApiGraphs

/* ------------------------------------------------------------------ */
/* Column contract (identical order to sources.ql):                    */
/* ------------------------------------------------------------------ */

/*
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "sink_candidate" in this query
 *   3. callable   - API member name, function name, or "getattr" for the
 *                   dynamic-dispatch family
 *   4. flow_kind  - "arg"                    (external HTTP API verb call,
 *                                             URL at arg_index)
 *                   "session_ctor"           (ClientSession/Session/
 *                                             AsyncClient/Client construction)
 *                   "session_arg"            (session method call,
 *                                             URL at arg_index)
 *                   "internal_client_getter" (async_get_clientsession /
 *                                             get_async_client funnel call)
 *                   "internal_fetch_wrapper" (function that directly issues
 *                                             a network request)
 *                   "url_build"              (yarl.URL / URL.build / urljoin)
 *                   "getattr_dispatch"       (getattr(session, method)(url))
 *   5. receiver   - syntactic receiver hint (base name of the object
 *                   expression, module prefix for external ast rows,
 *                   enclosing class name for wrapper rows, "" if none)
 *   6. moduleHint - external module name ("requests", "aiohttp", "httpx",
 *                   "yarl", "urllib.parse"), the internal helper module
 *                   ("homeassistant.helpers.aiohttp_client",
 *                   "homeassistant.helpers.httpx_client") for funnel rows,
 *                   or the dotted python module path of the candidate
 *                   (variable intentionally named moduleHint; `module` is
 *                   not a valid QL variable name here)
 *   7. arg_index  - 0-based positional argument index carrying the URL
 *                   (1 for request/stream-style APIs where arg 0 is the
 *                   method), -1 when not applicable
 *   8. file       - absolute file path, obtained through the Location API
 *                   (AstNode.getLocation().getFile().getAbsolutePath();
 *                   AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or
 *                   "ast" (syntax-level match)
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
  p.matches("%core-db%")
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

/**
 * Terminal name of an expression for JOIN positions: the id of a Name or the
 * attribute name of an Attribute (e.g. "websession" for both `websession`
 * and `self._websession`), and NO RESULT for any other expression shape.
 * Unlike the display helper `terminalName` below there is deliberately no
 * "<expr>" fallback: a sentinel string would act as one huge shared join
 * key between "everything not nameable" on both sides of an equality and
 * explode the (assignment x call-site) product on a database this size.
 * Call sites whose receiver is not a Name/Attribute simply produce no rows.
 */
string terminalNameOf(Expr e) {
  e instanceof Name and
  result = e.(Name).getId()
  or
  e instanceof Attribute and
  result = e.(Attribute).getName()
}

/** Terminal name of an expression for DISPLAY ONLY (receiver column):
 *  like terminalNameOf but falls back to "<expr>". Never use in a join. */
string terminalName(Expr e) {
  result = terminalNameOf(e)
  or
  not exists(string s | s = terminalNameOf(e)) and
  result = "<expr>"
}

/** The syntactic Call node behind an API graph call node. */
private Call astCallOf(API::CallNode cn) {
  result = cn.getNode().getNode().(Call)
}

/* ------------------------------------------------------------------ */
/* Sink family 1+2: external HTTP-client APIs (API graphs + AST)       */
/* ------------------------------------------------------------------ */

/**
 * External HTTP-client API table with the 0-based positional argument index
 * that carries the URL. Only APIs proven present in this tree:
 *   - requests: verbs (arg 0), request (method at 0, URL at 1), Session ctor
 *   - httpx: verbs (arg 0), request/stream (arg 1), Client/AsyncClient ctor
 *   - aiohttp: ClientSession ctor (base_url is keyword-only in this snapshot)
 * urllib.request.urlopen/urlretrieve do not occur in the tree and are
 * deliberately absent (operator rule).
 */
predicate httpApiShape(string moduleHint, string member, string flowKind, int argIndex) {
  moduleHint = "requests" and
  member in ["get", "post", "put", "head", "delete", "patch"] and
  flowKind = "arg" and
  argIndex = 0
  or
  moduleHint = "requests" and
  member = "request" and
  flowKind = "arg" and
  argIndex = 1
  or
  moduleHint = "requests" and
  member = "Session" and
  flowKind = "session_ctor" and
  argIndex = -1
  or
  moduleHint = "httpx" and
  member in ["get", "post", "put", "head", "delete", "patch"] and
  flowKind = "arg" and
  argIndex = 0
  or
  moduleHint = "httpx" and
  member in ["request", "stream"] and
  flowKind = "arg" and
  argIndex = 1
  or
  moduleHint = "httpx" and
  member in ["Client", "AsyncClient"] and
  flowKind = "session_ctor" and
  argIndex = -1
  or
  moduleHint = "aiohttp" and
  member = "ClientSession" and
  flowKind = "session_ctor" and
  argIndex = -1
}

/** Holds if cn is a call node genuinely resolved to an external HTTP-client
 *  API (alias-aware, covers `import requests` + `requests.get(...)` and
 *  `from requests import Session` + `Session(...)` idioms). */
private predicate resolvedHttpApiCall(API::CallNode cn, string moduleHint,
                                      string member, string flowKind, int argIndex) {
  httpApiShape(moduleHint, member, flowKind, argIndex) and
  cn = API::moduleImport(moduleHint).getMember(member).getACall()
}

/** AST-only matches: syntactic `<module>.<member>(...)` shapes. Intentionally
 *  redundant with the api family (covers shapes API graphs miss). */
private predicate syntacticHttpApiCall(Call c, string moduleHint, string member,
                                       string flowKind, int argIndex) {
  httpApiShape(moduleHint, member, flowKind, argIndex) and
  c.getFunc() instanceof Attribute and
  c.getFunc().(Attribute).getName() = member and
  c.getFunc().(Attribute).getObject() instanceof Name and
  c.getFunc().(Attribute).getObject().(Name).getId() = moduleHint
}

/* ------------------------------------------------------------------ */
/* Sink family 3: session / http-client method calls (AST)             */
/* ------------------------------------------------------------------ */

/**
 * Session-issued request methods and the argument index carrying the URL.
 * ws_connect opens a websocket to the URL (hassio/ingress.py:135);
 * stream is the httpx streaming request (mjpeg/camera.py:179);
 * send dispatches a prepared request object (tomato/device_tracker.py:102).
 */
predicate sessionMethodArgIndex(string method, int argIndex) {
  method in ["get", "post", "put", "head", "delete", "patch", "options", "ws_connect"] and
  argIndex = 0
  or
  method in ["request", "stream"] and
  argIndex = 1
  or
  method = "send" and
  argIndex = 0
}

/**
 * Receiver names of session variables observed in this tree (terminal name
 * of the object expression, so `websession` covers `self.websession` and
 * `self._websession`). Dict-like receivers such as `session_data` are
 * deliberately not in this table.
 */
predicate sessionReceiverName(string name) {
  name in [
    "session", "websession", "_websession", "httpsession", "http_session",
    "sess", "_session", "_polling_session", "clientsession", "_clientsession"
  ]
}

/**
 * Calls that construct or hand out a session/http client: the two HA helper
 * funnels and client constructors (aiohttp.ClientSession, requests.Session,
 * httpx.AsyncClient/Client, and their from-imported bare names). Used for
 * provenance: a variable assigned from one of these in the same file marks
 * its `.get(...)/.post(...)/...` calls as session method calls.
 */
predicate clientGetterOrCtorCall(Call vc) {
  vc.getFunc() instanceof Name and
  vc.getFunc().(Name).getId() in [
    "async_get_clientsession", "async_create_clientsession",
    "get_async_client", "create_async_httpx_client",
    "Session", "AsyncClient", "Client"
  ]
  or
  vc.getFunc() instanceof Attribute and
  vc.getFunc().(Attribute).getName() in [
    "async_get_clientsession", "async_create_clientsession",
    "get_async_client", "create_async_httpx_client"
  ]
  or
  vc.getFunc() instanceof Attribute and
  vc.getFunc().(Attribute).getName() in ["ClientSession", "Session", "AsyncClient", "Client"] and
  vc.getFunc().(Attribute).getObject() instanceof Name and
  vc.getFunc().(Attribute).getObject().(Name).getId() in ["aiohttp", "requests", "httpx"]
}

/**
 * In-file provenance of session/client variables: (file, terminal target
 * name) of every assignment whose value is a client getter/constructor
 * call. Kept as a small standalone relation so that the provenance check
 * in sessionMethodCall is a selective (file, name) probe against it,
 * instead of an (assignment x call-site) join keyed on a bare string.
 */
predicate clientVarProvenance(File f, string name) {
  exists(AssignStmt a |
    a.getValue() instanceof Call and
    clientGetterOrCtorCall(a.getValue().(Call)) and
    name = terminalNameOf(a.getATarget()) and
    f = a.getLocation().getFile()
  )
}

/**
 * Session/http-client method calls, matched syntactically. Holds when the
 * receiver (by terminal name)
 *   - is a session-named variable (sessionReceiverName table), or
 *   - is itself a client-getter/constructor call (e.g. mjpeg/camera.py:198
 *     `async with get_async_client(...).stream("get", url)`), or
 *   - has a terminal name that is assigned in the same file from a client
 *     getter/constructor (e.g. generic/camera.py:196-197
 *     `async_client = get_async_client(...)` then `async_client.get(url)`;
 *     image/__init__.py:139/172 `self._client = get_async_client(...)`
 *     then `self._client.get(url)`).
 * Receivers that are neither Name nor Attribute nor a client-getter call
 * (dict `client.get("mac")` in unifi_direct/device_tracker.py:135,
 * `d[k].get(...)`) do not match - terminalNameOf produces no result for
 * them, so they never enter the join. SQLAlchemy sessions named `session`
 * can collide and are left for labeling.
 */
private predicate sessionMethodCall(Call c, string callableName, string receiver,
                                    int argIndex) {
  exists(string method, Expr obj |
    c.getFunc() instanceof Attribute and
    method = c.getFunc().(Attribute).getName() and
    obj = c.getFunc().(Attribute).getObject() and
    sessionMethodArgIndex(method, argIndex) and
    callableName = method and
    (
      obj instanceof Name or
      obj instanceof Attribute or
      obj instanceof Call
    ) and
    (
      sessionReceiverName(terminalNameOf(obj))
      or
      obj instanceof Call and
      clientGetterOrCtorCall(obj.(Call))
      or
      exists(File f |
        clientVarProvenance(f, terminalNameOf(obj)) and
        f = c.getLocation().getFile()
      )
    ) and
    receiver = terminalName(obj)
  )
}

/* ------------------------------------------------------------------ */
/* Sink family 4: the internal shared client funnels                   */
/* ------------------------------------------------------------------ */

/**
 * The shared-session funnels, resolved through API graphs. moduleImport()
 * forbids dotted names, so the internal helper modules are addressed as
 * moduleImport("homeassistant").getMember("helpers").getMember(...); this
 * resolves both `from homeassistant.helpers import aiohttp_client` +
 * `aiohttp_client.async_get_clientsession(hass)` and
 * `from homeassistant.helpers.aiohttp_client import async_get_clientsession`
 * + bare-name calls.
 */
private predicate resolvedClientGetterCall(API::CallNode cn, string helperModule,
                                           string member) {
  helperModule = "homeassistant.helpers.aiohttp_client" and
  member in ["async_get_clientsession", "async_create_clientsession"] and
  cn = API::moduleImport("homeassistant").getMember("helpers")
        .getMember("aiohttp_client").getMember(member).getACall()
  or
  helperModule = "homeassistant.helpers.httpx_client" and
  member in ["get_async_client", "create_async_httpx_client"] and
  cn = API::moduleImport("homeassistant").getMember("helpers")
        .getMember("httpx_client").getMember(member).getACall()
}

/** AST-only matches for the funnels: bare-name calls (from-imports) and
 *  attribute calls such as `aiohttp_client.async_get_clientsession(...)`. */
private predicate syntacticClientGetterCall(Call c, string member) {
  member in ["async_get_clientsession", "async_create_clientsession",
             "get_async_client", "create_async_httpx_client"] and
  (
    c.getFunc() instanceof Name and
    c.getFunc().(Name).getId() = member
    or
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = member
  )
}

/** Helper module owning each funnel member (repo-derived, used as the
 *  moduleHint of ast rows as well). */
predicate clientGetterModule(string member, string helperModule) {
  member in ["async_get_clientsession", "async_create_clientsession"] and
  helperModule = "homeassistant.helpers.aiohttp_client"
  or
  member in ["get_async_client", "create_async_httpx_client"] and
  helperModule = "homeassistant.helpers.httpx_client"
}

/* ------------------------------------------------------------------ */
/* Sink family 5: dynamic-dispatch fetches (getattr)                   */
/* ------------------------------------------------------------------ */

/**
 * `getattr(<session>, <method>)(url, ...)`: the outer call dispatches to a
 * session method chosen at runtime. In-tree sites:
 * rest_command/__init__.py:121 `getattr(websession, method)(request_url, ...)`
 * and rest/switch.py:206 `getattr(websession, self._method)(...)`. The URL
 * is positional argument 0 of the outer call.
 */
private predicate getattrSessionDispatch(Call c) {
  exists(Call gc, Expr arg0 |
    gc = c.getFunc().(Call) and
    gc.getFunc() instanceof Name and
    gc.getFunc().(Name).getId() = "getattr" and
    arg0 = gc.getPositionalArg(0) and
    (
      sessionReceiverName(terminalNameOf(arg0))
      or
      arg0 instanceof Call and
      clientGetterOrCtorCall(arg0.(Call))
    )
  )
}

/* ------------------------------------------------------------------ */
/* Sink family 6: URL construction (API graphs + AST)                  */
/* ------------------------------------------------------------------ */

/** yarl URL / URL.build construction resolved through API graphs (covers
 *  both `import yarl` + `yarl.URL(...)` and `from yarl import URL` +
 *  `URL(...)`). */
private predicate resolvedUrlBuildCall(API::CallNode cn, string member) {
  member = "URL" and
  cn = API::moduleImport("yarl").getMember("URL").getACall()
  or
  member = "build" and
  cn = API::moduleImport("yarl").getMember("URL").getMember("build").getACall()
}

/** AST-only URL construction shapes: `yarl.URL(...)`, `yarl.URL.build(...)`
 *  and bare `urljoin(...)` (from urllib.parse import urljoin). */
private predicate syntacticUrlBuildNode(AstNode n, string callableName,
                                        string receiver, string moduleHint) {
  exists(Call c |
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "URL" and
    c.getFunc().(Attribute).getObject() instanceof Name and
    c.getFunc().(Attribute).getObject().(Name).getId() = "yarl" and
    n = c and
    callableName = "URL" and
    receiver = "yarl" and
    moduleHint = "yarl"
  )
  or
  exists(Call c |
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "build" and
    c.getFunc().(Attribute).getObject() instanceof Attribute and
    c.getFunc().(Attribute).getObject().(Attribute).getName() = "URL" and
    c.getFunc().(Attribute).getObject().(Attribute).getObject() instanceof Name and
    c.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = "yarl" and
    n = c and
    callableName = "build" and
    receiver = "yarl.URL" and
    moduleHint = "yarl"
  )
  or
  exists(Call c |
    c.getFunc() instanceof Name and
    c.getFunc().(Name).getId() = "urljoin" and
    n = c and
    callableName = "urljoin" and
    receiver = "" and
    moduleHint = "urllib.parse"
  )
}

/* ------------------------------------------------------------------ */
/* Sink family 7: internal fetch wrappers                              */
/* ------------------------------------------------------------------ */

/** Holds if c is any call site (resolved or syntactic shape) that issues a
 *  network request: an external HTTP API verb call, a session method call,
 *  or a getattr session dispatch. Client constructions and URL building are
 *  not fetch sites by themselves. */
private predicate fetchCallSite(Call c) {
  syntacticHttpApiCall(c, _, _, "arg", _)
  or
  sessionMethodCall(c, _, _, _)
  or
  getattrSessionDispatch(c)
  or
  exists(API::CallNode cn, string moduleHint, string member, int argIndex |
    resolvedHttpApiCall(cn, moduleHint, member, "arg", argIndex) and
    c = astCallOf(cn)
  )
}

/** Functions in this codebase whose body directly issues a network request
 *  (e.g. blueprint/importer.py:144 fetch_blueprint_from_community_post,
 *  hassio/handler.py:520 HassioAPI.api_command,
 *  rest_command/__init__.py:60 async_handle_rest_command). */
private predicate internalFetchWrapper(Function f) {
  exists(Call c |
    fetchCallSite(c) and
    c.getScope().(Function) = f
  )
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per sink candidate. */
predicate sinkCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: resolved external HTTP-client API calls (API graphs) */
  exists(API::CallNode cn, string member |
    resolvedHttpApiCall(cn, moduleHint, member, flowKind, argIndex) and
    node = astCallOf(cn) and
    callableName = member and
    receiver = "" and
    matchKind = "api"
  )
  or
  /* family 2: syntax-level external HTTP-client API shapes */
  exists(Call c |
    syntacticHttpApiCall(c, moduleHint, callableName, flowKind, argIndex) and
    node = c and
    receiver = "" and
    matchKind = "ast"
  )
  or
  /* family 3: session / http-client method calls */
  exists(Call c |
    sessionMethodCall(c, callableName, receiver, argIndex) and
    node = c and
    flowKind = "session_arg" and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
  or
  /* family 4a: resolved internal client funnel calls (API graphs) */
  exists(API::CallNode cn |
    resolvedClientGetterCall(cn, moduleHint, callableName) and
    node = astCallOf(cn) and
    flowKind = "internal_client_getter" and
    receiver = "" and
    argIndex = -1 and
    matchKind = "api"
  )
  or
  /* family 4b: syntax-level internal client funnel calls */
  exists(Call c |
    syntacticClientGetterCall(c, callableName) and
    clientGetterModule(callableName, moduleHint) and
    node = c and
    flowKind = "internal_client_getter" and
    argIndex = -1 and
    matchKind = "ast" and
    (
      c.getFunc() instanceof Name and
      receiver = ""
      or
      c.getFunc() instanceof Attribute and
      receiver = receiverHint(c.getFunc().(Attribute))
    )
  )
  or
  /* family 5: dynamic-dispatch fetches (getattr(session, method)(url)) */
  exists(Call c |
    getattrSessionDispatch(c) and
    node = c and
    callableName = "getattr" and
    flowKind = "getattr_dispatch" and
    receiver = terminalName(c.getFunc().(Call).getPositionalArg(0)) and
    argIndex = 0 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(c)
  )
  or
  /* family 6a: yarl URL construction resolved through API graphs */
  exists(API::CallNode cn, string member |
    resolvedUrlBuildCall(cn, member) and
    node = astCallOf(cn) and
    callableName = member and
    flowKind = "url_build" and
    receiver = "" and
    moduleHint = "yarl" and
    argIndex = 0 and
    matchKind = "api"
  )
  or
  /* family 6b: syntax-level URL construction shapes */
  exists(AstNode n |
    syntacticUrlBuildNode(n, callableName, receiver, moduleHint) and
    node = n and
    flowKind = "url_build" and
    argIndex = 0 and
    matchKind = "ast"
  )
  or
  /* family 7: internal functions that directly issue network requests */
  exists(Function f |
    internalFetchWrapper(f) and
    node = f and
    callableName = f.getName() and
    flowKind = "internal_fetch_wrapper" and
    argIndex = -1 and
    matchKind = "ast" and
    moduleHint = moduleHintOf(f) and
    (
      f.getEnclosingScope() instanceof Class and
      receiver = f.getEnclosingScope().(Class).getName()
      or
      not f.getEnclosingScope() instanceof Class and
      receiver = ""
    )
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sinkCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
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
  matchKind as match_kind
