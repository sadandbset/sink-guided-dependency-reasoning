/**
 * @name starlette CWE-22 source candidate extraction
 * @description Extract attacker-controlled input source candidates from the
 *   starlette CodeQL database (snapshot 24c1fac6, starlette 0.26.1 - the
 *   starlette ASGI framework itself is the audit target): the ASGI scope
 *   request-state key reads (scope["path"] at staticfiles.py:111 StaticFiles
 *   get_path - THE attacker-controlled file-location input feeding the
 *   join/normpath/realpath/stat pipeline - and :141, routing.py:238/:316/:388
 *   route regex matches, :732/:734/:735/:737 redirect-slash rewrites,
 *   datastructures.py:34 URL build, middleware/wsgi.py:25 PATH_INFO;
 *   scope["method"]/["query_string"]/["headers"] state reads); the routed
 *   path-variable boundary (match.groupdict() at routing.py:240/:318/:391,
 *   matched_params.pop("path") at :394 - the Mount remainder that becomes
 *   the child scope["path"]; scope.get("path_params") at routing.py:243/
 *   :321/:396/:481 and requests.py:124); request header reads
 *   (<x>.headers.get(...) at requests.py:130/:257/:312, routing.py:475,
 *   middleware/gzip.py:20, trustedhost.py:38, cors.py:80/:107,
 *   errors.py:247, datastructures.py:452; the request_headers subscripts
 *   at staticfiles.py:227/:235 and self.headers["Content-Type"] at
 *   formparsers.py:228); the multipart Content-Disposition option reads
 *   (options[b"name"]/:b"filename"] at formparsers.py:194/:206 - the
 *   upload filename is stored on UploadFile(filename=...) at :209 while
 *   the content goes to an auto-named SpooledTemporaryFile at :207, the
 *   filename never reaches a filesystem path in this tree; params
 *   charset/boundary at :229/:234; parse_options_header(...) calls at
 *   formparsers.py:189/:228 and requests.py:259); the percent/charset
 *   decode boundaries (unquote_plus at formparsers.py:111/:112,
 *   _user_safe_decode at :162/:193/:206, http_cookies._unquote at
 *   requests.py:55, unquote(path) at testclient.py:240/:258 - evidence
 *   the ASGI server pre-decodes the scope path); the raw wire message
 *   reads (self._receive() at requests.py:221/:301, message.get(...)
 *   at :223/:226/:303); the framework-injected entry parameters (the
 *   `scope` parameter of the ASGI callable functions across the package,
 *   `request`/`websocket` handler parameters in endpoints.py/
 *   authentication.py/middleware errors+exceptions, the headers/stream
 *   parser parameters at formparsers.py:48-54/:122-127 and the receive
 *   parameter of Request.__init__); and the environment read
 *   (os.environ at config.py:16 - operator/local-process trust level).
 *   Raw BQRS extraction query: run with `codeql query run` and decode
 *   with `codeql bqrs decode` (not database analyze). This is a plain
 *   multi-column select query on purpose: @kind problem is the wrong
 *   shape for candidate tables and @kind table is not assumed to exist.
 * @id iris/starlette/extraction/sources
 * @tags path-traversal
 */

import python

/*
 * Column contract (identical order to sinks.ql):
 *   1. node       - candidate AST node (location-backed, decodes as file:line:col)
 *   2. role       - always "source_candidate" in this query
 *   3. callable   - the scope key / member / callable name (e.g. "path",
 *                   "groupdict", "pop", "get", "getlist", "filename",
 *                   "parse_options_header", "unquote_plus",
 *                   "_user_safe_decode", "unquote", "_unquote", "_receive",
 *                   "environ", "UploadFile", the function name for
 *                   parameter rows)
 *   4. flow_kind  - "http_path" (scope path / root_path state),
 *                   "http_request" (scope method/query_string state),
 *                   "http_header" (scope headers state, headers.get/
 *                   getlist calls, header subscripts,
 *                   parse_options_header calls),
 *                   "route_var" (path_params scope reads, groupdict,
 *                   matched_params.pop - the routed path variables),
 *                   "multipart_filename" (options[b"filename"] reads and
 *                   the UploadFile(filename=...) construction),
 *                   "multipart_field" (options[b"name"] and the
 *                   Content-Type params charset/boundary),
 *                   "http_wire" (self._receive() calls and the
 *                   message.get(...) body/type reads),
 *                   "url_decode" (unquote/unquote_plus/
 *                   _user_safe_decode/_unquote decode boundaries),
 *                   "env" (os.environ family), "param" (the ASGI scope
 *                   entry parameters, request/websocket handler
 *                   parameters, parser stream/headers/receive parameters)
 *   5. receiver   - syntactic receiver hint (object base name of the
 *                   subscripted/accessed expression: "scope"/
 *                   "redirect_scope"/"self.scope"/"request.headers"/
 *                   "self.headers"/"match"/"matched_params"/"options"/
 *                   "params"/"message"/"os"/"part" etc., or "" if none;
 *                   enclosing class name for parameter rows)
 *   6. moduleHint - dotted python module path of the containing module
 *                   (variable intentionally named moduleHint; `module`
 *                   is not a valid QL variable name here); literal module
 *                   hints "os" for the env family
 *   7. arg_index  - 0-based positional argument index (index slot of the
 *                   keyed reads and first-argument slot of the decode
 *                   calls; parameter position in the function definition
 *                   for "param" rows, including the self slot for
 *                   methods), -1 if N/A (the UploadFile construction row
 *                   reports -1 because the filename is passed as a
 *                   keyword argument)
 *   8. file       - absolute file path, obtained through the Location API
 *                    (AstNode.getLocation().getFile().getAbsolutePath();
 *                    AstNode.getFile() does not exist)
 *   9. line       - 1-based start line (AstNode.getLocation().getStartLine())
 *  10. match_kind - "api" (resolved real API call via API graphs) or "ast"
 *                   (syntax-level match)
 *
 * Note: this file defines no QL classes (only predicates and functions),
 * does not assign API::Node values to DataFlow::Node variables, keeps
 * every variable bound through a positive body, and keeps resolved-API
 * matching strictly separate from AST syntax matching (the match_kind
 * column records which one produced a row). In this project no source
 * row is expected to resolve at API level: the ASGI scope, routed
 * params, Content-Disposition option dicts, multipart stream and
 * os.environ are framework-injected, parser-produced or
 * interpreter-provided values, not module members, so all families below
 * are AST-level matches and the match_kind column is kept "ast" for
 * cross-project contract consistency. Bytes literals (b"filename") are
 * matched through StringLiteral.getText() because class Bytes extends
 * StringLiteral in this pack (semmle/python/Exprs.qll) and getText()
 * returns the literal value without quotes.
 *
 * Excluded paths (applied to every row): /tests/ (the test tree covered
 * by the database snapshot) and /starlette-db/ (the CodeQL database
 * directory sits inside the source tree). starlette/testclient.py is NOT
 * excluded (shipped library code): its unquote rows carry test-machinery
 * trust caveats and are expected to be labeled none/FP.
 */

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/** Dotted path of the python module containing n (used as moduleHint for
 *  internal candidates). Top-level scripts that are not on an import path
 *  (setup.py, scripts/*.py) have no dotted module name; their file base name
 *  is used instead. */
string moduleHintOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
  or
  not exists(n.getScope().getEnclosingModule().getName()) and
  result = n.getScope().getEnclosingModule().getFile().getShortName()
}

/** Forward-slash-normalized absolute path of the file containing n, so path
 *  matching works with both CodeQL path styles on Windows. */
string normalizedPathOf(AstNode n) {
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
}

/** Base name of the object expression of an attribute access, used as a receiver hint. */
string receiverHint(Attribute a) {
  result = a.getObject().(Name).getId()
  or
  result = a.getObject().(Attribute).getName()
  or
  not a.getObject() instanceof Name and
  not a.getObject() instanceof Attribute and
  result = "<expr>"
}

/** True iff the candidate's file path is one of the excluded trees. Path is
 *  normalized to forward slashes before matching so the query works on both
 *  CodeQL path styles. bindingset[path] declares that the caller passes a
 *  bound path (the path only appears in checked positions such as the
 *  receiver of replaceAll/matches inside this predicate). */
bindingset[path]
predicate excludedPath(string path) {
  path.replaceAll("\\", "/").matches("%/tests/%")
  or
  path.replaceAll("\\", "/").matches("%/starlette-db/%")
}

/* ------------------------------------------------------------------ */
/* Shared starlette shapes (kept consistent with sinks.ql)              */
/* ------------------------------------------------------------------ */

/** Object-expression shapes that hold the ASGI scope: the bare local names
 *  (`scope`, `redirect_scope`, `base_url_scope`) and `self.scope`. */
private predicate scopeObject(Expr obj) {
  obj.(Name).getId() = "scope"
  or
  obj.(Name).getId() = "redirect_scope"
  or
  obj.(Name).getId() = "base_url_scope"
  or
  obj.(Attribute).getName() = "scope" and
  obj.(Attribute).getObject() instanceof Name
}

/** ASGI scope keys carrying request state that this extraction emits
 *  (scope["type"]/["app"]/["router"]/["client"] etc. are server/framework
 *  plumbing and are deliberately not emitted). */
private predicate scopeRequestKey(string key) {
  key = "path"
  or
  key = "path_params"
  or
  key = "query_string"
  or
  key = "method"
  or
  key = "headers"
}

/** flow_kind for a scope state key. */
private string scopeKeyFlowKind(string key) {
  key = "path" and result = "http_path"
  or
  key = "path_params" and result = "route_var"
  or
  key = "query_string" and result = "http_request"
  or
  key = "method" and result = "http_request"
  or
  key = "headers" and result = "http_header"
}

/** Receiver hint for a scope object expression (scopeName for Name objects,
 *  "self.scope" for the self attribute form). */
private string scopeObjectHint(Expr obj) {
  obj instanceof Name and result = obj.(Name).getId()
  or
  obj instanceof Attribute and result = "self.scope"
}

/** Package modules (starlette/ and starlette/middleware/, excluding
 *  testclient.py - the test client CONSTRUCTS scopes rather than receiving
 *  untrusted ones) whose `scope` parameters are the framework-injected ASGI
 *  entry points carrying all HTTP input.
 *  bindingset[path]: the callers pass a bound path (normalizedPathOf of a
 *  bound node); `matches` is a checked position that does not bind its
 *  receiver, so without the annotation the body cannot bind `path`. */
bindingset[path]
private predicate asgiScopeModule(string path) {
  path.matches("%/starlette/staticfiles.py")
  or
  path.matches("%/starlette/routing.py")
  or
  path.matches("%/starlette/responses.py")
  or
  path.matches("%/starlette/requests.py")
  or
  path.matches("%/starlette/datastructures.py")
  or
  path.matches("%/starlette/websockets.py")
  or
  path.matches("%/starlette/applications.py")
  or
  path.matches("%/starlette/endpoints.py")
  or
  path.matches("%/starlette/templating.py")
  or
  path.matches("%/starlette/exceptions.py")
  or
  path.matches("%/starlette/middleware/wsgi.py")
  or
  path.matches("%/starlette/middleware/cors.py")
  or
  path.matches("%/starlette/middleware/gzip.py")
  or
  path.matches("%/starlette/middleware/trustedhost.py")
  or
  path.matches("%/starlette/middleware/errors.py")
  or
  path.matches("%/starlette/middleware/exceptions.py")
  or
  path.matches("%/starlette/middleware/base.py")
}

/** Modules whose `request`/`websocket` parameters are framework-injected
 *  handler objects (endpoint methods, auth wrappers, exception handlers).
 *  bindingset[path]: same checked-position rationale as asgiScopeModule. */
bindingset[path]
private predicate handlerParamModule(string path) {
  path.matches("%/starlette/endpoints.py")
  or
  path.matches("%/starlette/authentication.py")
  or
  path.matches("%/starlette/middleware/errors.py")
  or
  path.matches("%/starlette/middleware/exceptions.py")
}

/** Header-container object shapes for keyed reads: an `headers` attribute on
 *  any base (request.headers / self.headers) or the bare local names
 *  `headers` / `request_headers` (routing.py:475, cors.py:107,
 *  staticfiles.py:227). */
private predicate headerContainer(Expr obj) {
  obj.(Attribute).getName() = "headers"
  or
  obj.(Name).getId() = "headers"
  or
  obj.(Name).getId() = "request_headers"
}

/** Receiver hint for a header-container object expression. */
private string headerContainerHint(Expr obj) {
  obj instanceof Name and result = obj.(Name).getId()
  or
  obj instanceof Attribute and result = receiverHint(obj.(Attribute))
}

/* ------------------------------------------------------------------ */
/* Row assembly                                                        */
/* ------------------------------------------------------------------ */

/** One row per source candidate. */
private predicate sourceCandidate(
  AstNode node, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string matchKind
) {
  /* family 1: ASGI scope state subscripts - scope["path"] /
     redirect_scope["path"] / self.scope["method"] / scope["headers"] etc.;
     write targets are excluded (Assign.getATarget() covers chained
     assignment targets, so only the value-side reads of
     redirect_scope["path"] at routing.py:735/:737 and the RHS read at
     datastructures.py:534 are kept). scope["path"] sites:
     staticfiles.py:111 (get_path - feeds the os.path.join/normpath
     pipeline), :141, routing.py:238/:316/:388 (route regex match input),
     :732/:734/:735/:737 (redirect-slash rewrite), datastructures.py:34
     (URL build), middleware/wsgi.py:25 (PATH_INFO) */
  exists(Subscript s |
    scopeObject(s.getObject()) and
    scopeRequestKey(s.getIndex().(StringLiteral).getText()) and
    not exists(Assign a | a.getATarget() = s) and
    node = s and
    callableName = s.getIndex().(StringLiteral).getText() and
    flowKind = scopeKeyFlowKind(s.getIndex().(StringLiteral).getText()) and
    argIndex = 0 and
    receiver = scopeObjectHint(s.getObject()) and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 2: scope.get(...) keyed reads - scope.get("path_params", {})
     at routing.py:243/:321/:396/:481 and self.scope.get at requests.py:124
     (the request.path_params accessor); scope.get("query_string", b"")
     at datastructures.py:35; scope.get("root_path", "") at
     datastructures.py:34 and routing.py:398 (root_path is server- and
     mount-derived - partially request-influenced via Mount.matches, trust
     caveat recorded in detection.json) */
  exists(Call c, Attribute func, string key |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    scopeObject(func.getObject()) and
    key = c.getPositionalArg(0).(StringLiteral).getText() and
    (
      key = "path_params"
      or
      key = "query_string"
      or
      key = "root_path"
    ) and
    node = c and
    (
      key = "path_params" and flowKind = "route_var"
      or
      key = "query_string" and flowKind = "http_request"
      or
      key = "root_path" and flowKind = "http_path"
    ) and
    callableName = "get" and
    argIndex = 0 and
    receiver = scopeObjectHint(func.getObject()) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 3: routed path-variable extraction - match.groupdict() at
     routing.py:240 (Route.matches), :318 (WebSocketRoute.matches), :391
     (Mount.matches): the regex match over scope["path"] whose
     groupdict() result becomes path_params (then convertor.convert) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "groupdict" and
    func.getObject().(Name).getId() = "match" and
    node = c and
    flowKind = "route_var" and
    callableName = "groupdict" and
    argIndex = -1 and
    receiver = "match" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 4: the Mount remainder - matched_params.pop("path") at
     routing.py:394 (Mount.matches): "/" + the popped remainder becomes
     the child scope["path"] handed to the mounted sub-app (e.g. the
     StaticFiles app mounted at a prefix) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "pop" and
    func.getObject().(Name).getId() = "matched_params" and
    node = c and
    flowKind = "route_var" and
    callableName = "pop" and
    argIndex = 0 and
    receiver = "matched_params" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 5: request header keyed reads - <x>.headers.get(...) /
     headers.get(...) / request_headers.get(...) / <x>.headers.getlist(...)
     call sites: requests.py:130 (cookie), :257 (Content-Type - selects
     the multipart parser), :312 (server-push); routing.py:475 (host,
     Host.matches); middleware/gzip.py:20 (Accept-Encoding - response
     compression only); middleware/trustedhost.py:38 (host);
     middleware/cors.py:80 (origin), :107 (preflight headers);
     middleware/errors.py:247 (accept); datastructures.py:452 (upload
     content-type); testclient.py:233. Argument 0 carries the header key */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    (
      func.getName() = "get"
      or
      func.getName() = "getlist"
    ) and
    headerContainer(func.getObject()) and
    node = c and
    flowKind = "http_header" and
    callableName = func.getName() and
    argIndex = 0 and
    receiver = headerContainerHint(func.getObject()) and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 6: header subscripts - request_headers["if-none-match"] /
     ["if-modified-since"] at staticfiles.py:227/:235 (StaticFiles
     conditional-request handling - response metadata only, never a file
     location) and self.headers["Content-Type"] at formparsers.py:228
     (multipart boundary/charset source); the index carries the key */
  exists(Subscript s |
    headerContainer(s.getObject()) and
    s.getIndex() instanceof StringLiteral and
    not exists(Assign a | a.getATarget() = s) and
    node = s and
    flowKind = "http_header" and
    callableName = s.getIndex().(StringLiteral).getText() and
    argIndex = 0 and
    receiver = headerContainerHint(s.getObject()) and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  /* family 7: multipart Content-Disposition option reads - options[b"name"]
     at formparsers.py:194 (the multipart field name) and
     options[b"filename"] at :206 (THE attacker-controlled multipart upload
     filename, stored on UploadFile(filename=...) at :209 while the content
     goes to an auto-named SpooledTemporaryFile at :207 - the filename never
     reaches a filesystem path in this tree); params.get(b"charset", ...) at
     :229 and params[b"boundary"] at :234 (Content-Type params) */
  exists(Subscript s, string key |
    normalizedPathOf(s).matches("%/starlette/formparsers.py") and
    (
      s.getObject().(Name).getId() = "options"
      or
      s.getObject().(Name).getId() = "params"
    ) and
    key = s.getIndex().(StringLiteral).getText() and
    node = s and
    (
      key = "filename" and flowKind = "multipart_filename"
      or
      not key = "filename" and flowKind = "multipart_field"
    ) and
    callableName = key and
    argIndex = 0 and
    receiver = s.getObject().(Name).getId() and
    moduleHint = moduleHintOf(s) and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func, string key |
    normalizedPathOf(c).matches("%/starlette/formparsers.py") and
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    func.getObject().(Name).getId() = "params" and
    key = c.getPositionalArg(0).(StringLiteral).getText() and
    node = c and
    flowKind = "multipart_field" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "params" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 8: multipart option/header parse boundary -
     parse_options_header(...) calls at formparsers.py:189
     (Content-Disposition of each part), :228 (request Content-Type) and
     requests.py:259 (Content-Type dispatch); the return value carries
     the parsed attacker-supplied header options */
  exists(Call c |
    c.getFunc().(Name).getId() = "parse_options_header" and
    node = c and
    flowKind = "http_header" and
    callableName = "parse_options_header" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 9: percent/charset decode boundaries - unquote_plus(...) at
     formparsers.py:111/:112 (urlencoded form field name/value decode);
     _user_safe_decode(...) at :162/:193/:206 (multipart field/filename
     charset decode); http_cookies._unquote(val) at requests.py:55
     (cookie value decode); unquote(path) at testclient.py:240/:258 (the
     test client builds scope["path"] by percent-decoding - evidence the
     ASGI server pre-decodes the scope path) */
  exists(Call c |
    c.getFunc().(Name).getId() = "unquote_plus" and
    node = c and
    flowKind = "url_decode" and
    callableName = "unquote_plus" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  exists(Call c |
    c.getFunc().(Name).getId() = "_user_safe_decode" and
    node = c and
    flowKind = "url_decode" and
    callableName = "_user_safe_decode" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  exists(Call c |
    c.getFunc().(Name).getId() = "unquote" and
    node = c and
    flowKind = "url_decode" and
    callableName = "unquote" and
    argIndex = 0 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "_unquote" and
    func.getObject().(Name).getId() = "http_cookies" and
    node = c and
    flowKind = "url_decode" and
    callableName = "_unquote" and
    argIndex = 0 and
    receiver = "http_cookies" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 10: raw wire message reads - self._receive() calls at
     requests.py:221 (Request.stream body loop), :301 (is_disconnected)
     and websockets.py:35/:45 (WebSocket.receive); websocket.receive()
     at endpoints.py:77 (WebSocketEndpoint.dispatch); message.get(...)
     keyed reads at requests.py:223/:226/:303 (http.request body/type)
     and endpoints.py:83/:106/:120 (websocket text/bytes/code) - the raw
     ASGI message chunks off the socket before parsing (middleware/base.py
     message.get reads are response-direction and deliberately excluded) */
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "_receive" and
    func.getObject().(Name).getId() = "self" and
    node = c and
    flowKind = "http_wire" and
    callableName = "_receive" and
    argIndex = -1 and
    receiver = "self" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "receive" and
    func.getObject().(Name).getId() = "websocket" and
    node = c and
    flowKind = "http_wire" and
    callableName = "receive" and
    argIndex = -1 and
    receiver = "websocket" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  exists(Call c, Attribute func |
    func = c.getFunc().(Attribute) and
    func.getName() = "get" and
    func.getObject().(Name).getId() = "message" and
    (
      normalizedPathOf(c).matches("%/starlette/requests.py")
      or
      normalizedPathOf(c).matches("%/starlette/endpoints.py")
    ) and
    node = c and
    flowKind = "http_wire" and
    callableName = "get" and
    argIndex = 0 and
    receiver = "message" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
  or
  /* family 11: environment read - os.environ attribute read at
     config.py:16 (the Environ wrapper default; read through
     Environ.__getitem__ and Config.get self.environ[key] - operator/
     local-process trust level) */
  exists(Attribute a |
    a.getName() = "environ" and
    a.getObject().(Name).getId() = "os" and
    node = a and
    flowKind = "env" and
    callableName = "environ" and
    argIndex = -1 and
    receiver = "os" and
    moduleHint = "os" and
    matchKind = "ast"
  )
  or
  /* family 12: framework-injected ASGI entry parameters - parameters
     named `scope` of functions in the ASGI-serving modules
     (staticfiles.py:92 StaticFiles.__call__ and :113 get_response/:184
     file_response; routing.py:236/:314/:386/:472 matches, :265/:340/:442
     handle, :697 Router.__call__, :625 not_found, :668 lifespan, the
     request_response/websocket_session app closures; responses.py:163/
     :269/:332 Response family __call__s; requests.py:193 Request.__init__;
     datastructures.py URL/Headers __init__; websockets.py;
     applications.py; endpoints.py; templating.py; the middleware
     __call__s) - these dicts carry all HTTP input; self is excluded;
     arg_index is the 0-based position in the function definition
     including the self slot for methods. testclient.py is excluded (it
     constructs scopes rather than receiving untrusted ones) */
  exists(Function f, Parameter p |
    p.getName() = "scope" and
    p = f.getAnArg() and
    not p.isSelf() and
    asgiScopeModule(normalizedPathOf(f)) and
    node = p and
    flowKind = "param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
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
  or
  /* family 13: framework-injected handler parameters - parameters named
     `request` / `websocket` of functions in the handler modules
     (endpoints.py:47 HTTPEndpoint.method_not_allowed(request), :122-129
     WebSocketEndpoint on_connect/on_receive/on_disconnect, :92 decode;
     authentication.py requires() wrapper closures;
     middleware/errors.py and middleware/exceptions.py exception
     handlers) - these objects carry the parsed request state */
  exists(Function f, Parameter p |
    (
      p.getName() = "request"
      or
      p.getName() = "websocket"
    ) and
    p = f.getAnArg() and
    not p.isSelf() and
    handlerParamModule(normalizedPathOf(f)) and
    node = p and
    flowKind = "param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
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
  or
  /* family 14: parser boundary parameters - the `headers` and `stream`
     parameters of FormParser.__init__ (formparsers.py:47-54) and
     MultiPartParser.__init__ (:121-127): the request headers object and
     the request-body async stream; plus the `receive` parameter of
     Request.__init__ (requests.py:193-194): the raw message channel */
  exists(Function f, Parameter p |
    f.getName() = "__init__" and
    (
      f.getEnclosingScope().(Class).getName() = "FormParser"
      or
      f.getEnclosingScope().(Class).getName() = "MultiPartParser"
    ) and
    normalizedPathOf(f).matches("%/starlette/formparsers.py") and
    p = f.getAnArg() and
    (
      p.getName() = "headers"
      or
      p.getName() = "stream"
    ) and
    not p.isSelf() and
    node = p and
    flowKind = "param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = f.getEnclosingScope().(Class).getName() and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  exists(Function f, Parameter p |
    f.getName() = "__init__" and
    f.getEnclosingScope().(Class).getName() = "Request" and
    normalizedPathOf(f).matches("%/starlette/requests.py") and
    p = f.getAnArg() and
    p.getName() = "receive" and
    not p.isSelf() and
    node = p and
    flowKind = "param" and
    callableName = f.getName() and
    argIndex = p.getPosition() and
    receiver = "Request" and
    moduleHint = moduleHintOf(f) and
    matchKind = "ast"
  )
  or
  /* family 15: the UploadFile construction at formparsers.py:209-214 -
     UploadFile(file=tempfile, size=0, filename=filename, headers=...):
     the wrapper storing the attacker-controlled Content-Disposition
     filename (a KEYWORD argument, so arg_index is -1; the file content
     goes to the auto-named SpooledTemporaryFile, see sinks.ql) */
  exists(Call c |
    c.getFunc().(Name).getId() = "UploadFile" and
    node = c and
    flowKind = "multipart_filename" and
    callableName = "UploadFile" and
    argIndex = -1 and
    receiver = "" and
    moduleHint = moduleHintOf(c) and
    matchKind = "ast"
  )
}

from AstNode node, string callableName, string flowKind, string receiver,
     string moduleHint, int argIndex, string matchKind
where
  sourceCandidate(node, callableName, flowKind, receiver, moduleHint, argIndex, matchKind) and
  not excludedPath(node.getLocation().getFile().getAbsolutePath())
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
  matchKind
