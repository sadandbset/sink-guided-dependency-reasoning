/**
 * @name streamlit Pass 1 source candidates (Path Traversal)
 * @description Extracts untrusted-input source candidates for CWE-22/23/36/73
 *   from the streamlit 1.11.0 Tornado application: tornado request-handler URL
 *   path captures and message payloads, get_argument request-field reads,
 *   self.request payload reads, multipart upload fields, the request-argument
 *   boundary wrapper, plus environment/CLI boundaries flagged as local (not
 *   network) for labeling judgment. Evidence-derived from
 *   lib/streamlit/components/v1/components.py, lib/streamlit/server/routes.py,
 *   lib/streamlit/server/server.py,
 *   lib/streamlit/server/upload_file_request_handler.py, lib/streamlit/cli.py
 *   and lib/streamlit/config.py.
 *   Multi-column candidate table intended for `codeql query run` followed by
 *   `codeql bqrs decode --format=csv`. This query deliberately has NO @kind
 *   annotation: a @kind problem select shape cannot carry the multi-column
 *   extraction contract, and no @kind table is assumed.
 * @id iris/streamlit-cwe22/extract-sources
 */

import python

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/**
 * Gets the dotted name of a simple name/attribute chain,
 * e.g. "os.environ.get" or "self.request.body". Yields no result for
 * expressions whose object part is not a simple name/attribute chain.
 */
private string dottedName(Expr e) {
  result = e.(Name).getId()
  or
  result = dottedName(e.(Attribute).getValue()) + "." + e.(Attribute).getName()
}

/**
 * Gets the repository-relative path of the file containing this node,
 * e.g. "lib/streamlit/server/routes.py". The primary source is
 * File.getRelativePath() (backslash-normalized); on this Windows-created
 * database the stored source location prefix uses backslashes while file
 * paths are forward-slash normalized, so getRelativePath() may have no
 * result - in that case fall back to capturing the "lib/streamlit/..."
 * suffix from the absolute path (verified forward-slash format in the
 * database string pool and src.zip).
 */
private string relPath(AstNode n) {
  result = n.getLocation().getFile().getRelativePath().replaceAll("\\\\", "/")
  or
  not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
  result = n.getLocation().getFile().getAbsolutePath().regexpCapture(".*/(lib/streamlit/.+)$", 1)
}

/** Derives a module hint such as "streamlit.server.routes" from the file path. */
private string moduleHintOf(AstNode n) {
  result = relPath(n).regexpCapture("^(lib/)?(.+)\\.py$", 2).replaceAll("/", ".")
}

/**
 * Restricts candidates to the lib/streamlit package itself. This structurally
 * excludes the nested streamlit-db CodeQL database directory, lib/tests/,
 * e2e/, scripts/ and the generated proto package, which are noise or out of
 * scope per the Augur policy.
 */
private predicate inStreamlitPackage(AstNode n) {
  relPath(n).matches("lib/streamlit/%") and
  not relPath(n).matches("lib/streamlit/proto/%")
}

/** Gets the enclosing class name for methods, or "" for plain functions. */
private string receiverOf(Function f) {
  f.isMethod() and result = f.getEnclosingScope().(Class).getName()
  or
  not f.isMethod() and result = ""
}

/**
 * Tornado request-handler methods whose positional parameters (after self)
 * receive URL path captures or other request-derived values. `initialize`
 * and `write_error` are excluded: their parameters are server configuration
 * or a status code, not request data.
 */
private predicate isHandlerBoundaryMethod(Function f) {
  f.getName() in [
    "get", "post", "put", "delete", "head", "patch", "options",
    "on_message", "parse_url_path", "set_extra_headers", "check_origin"
  ]
}

/**
 * Per-method context for handler boundary parameters. Branches are mutually
 * exclusive by method name, and no branch uses negation. The '/component/(.*)'
 * handler (ComponentRequestHandler.get, the only handler `get` with request
 * parameters in this codebase) is special-cased at the call site in
 * sourceCandidate using the positively-bound `moduleHint` local, so it has no
 * branch here. parse_url_path has a single definition
 * (streamlit/server/routes.py), so its context is stated directly.
 */
private string handlerContext(string methodName) {
  (
    methodName = "on_message" and
    result = "Tornado WebSocket on_message: parameter is the raw message payload bytes from the browser, parsed as a BackMsg protobuf (server.py:789)"
  )
  or
  (
    methodName = "check_origin" and
    result = "Tornado WebSocket check_origin: parameter is the Origin request header value (CORS decision only)"
  )
  or
  (
    methodName = "parse_url_path" and
    result = "StaticFileHandler.parse_url_path (only definition: streamlit/server/routes.py): decoded URL path from the '/(.*)' static route; page-name lookup against the registered pages set, then deferred to the tornado superclass (framework-side validation outside this database)"
  )
  or
  (
    methodName = "set_extra_headers" and
    result = "Tornado StaticFileHandler response hook: parameter is the request path (response header selection)"
  )
  or
  (
    methodName in ["post", "put", "delete", "head", "patch", "options"] and
    result = "Tornado request handler method: positional parameters after self are URL path captures from the route regex or handler-hook arguments derived from the request"
  )
}

/* ------------------------------------------------------------------ */
/* Source candidate relation                                           */
/* ------------------------------------------------------------------ */

/**
 * Holds for each untrusted-input source candidate. `argIndex` is the real
 * 0-based parameter index (including `self` for methods) for `param` rows,
 * and -1 for field/read candidates where no positional index applies.
 */
private predicate sourceCandidate(
  string nodeRepr, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string context, AstNode node
) {
  /* Family 1: tornado handler method parameters - URL path captures
     (e.g. /component/(.*)), websocket payloads, and path-carrying hooks.
     The ComponentRequestHandler.get site gets a dedicated context via the
     positively-bound moduleHint local; handlerContext covers the remaining
     methods (it has no 'get' branch, so no duplicate rows can arise). */
  exists(Function f, Parameter p, int i |
    i >= 1 and
    f.getArg(i) = p and
    f.isMethod() and
    isHandlerBoundaryMethod(f) and
    f.getEnclosingScope().(Class).getName().matches("%Handler") and
    node = p.asName() and
    inStreamlitPackage(node) and
    nodeRepr = "parameter '" + p.getName() + "' of handler method " +
      f.getEnclosingScope().(Class).getName() + "." + f.getName() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = i and
    (
      (
        moduleHint = "streamlit.components.v1.components" and f.getName() = "get" and
        context = "ComponentRequestHandler.get: '/component/(.*)' route capture; parts[0] selects a registered component, '/'.join(parts[1:]) becomes filename, joined via os.path.join(component_root, filename) (components.py:319-320) then open(abspath, 'rb') (components.py:325) - no containment check observed"
      )
      or
      context = handlerContext(f.getName())
    )
  )
  or
  /* Family 2: request argument reads via self.get_argument(...) - the
     returned value is query-string / form-encoded request data. */
  exists(Call c, string methodName |
    node = c and
    inStreamlitPackage(c) and
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = methodName and
    methodName in [
      "get_argument", "get_arguments", "get_query_argument",
      "get_query_arguments", "get_body_argument", "get_body_arguments"
    ] and
    dottedName(c.getFunc().(Attribute).getValue()) = "self" and
    nodeRepr = "call self." + methodName and
    callableName = "self." + methodName and
    flowKind = "field" and
    receiver = "self" and
    moduleHint = "tornado.web.RequestHandler" and
    argIndex = -1 and
    context = "Tornado request argument read (query string or form-encoded body value returned by the call)"
  )
  or
  /* Family 3: raw request object field reads, e.g. self.request.body. */
  exists(Attribute a, string chain |
    node = a and
    inStreamlitPackage(a) and
    chain = dottedName(a) and
    chain in [
      "self.request.body", "self.request.headers", "self.request.files",
      "self.request.query", "self.request.uri", "self.request.path"
    ] and
    nodeRepr = "request attribute " + chain and
    callableName = chain and
    flowKind = "field" and
    receiver = "self.request" and
    moduleHint = "tornado.httputil.HTTPServerRequest" and
    argIndex = -1 and
    context = "Tornado HTTPServerRequest field read (raw request payload from the browser; multipart bodies are parsed by tornado.httputil.parse_body_arguments)"
  )
  or
  /* Family 4: client-supplied multipart upload fields, e.g.
     file["filename"] over the parsed `files` dict in the upload handler. */
  exists(Subscript s, string fieldName |
    node = s and
    inStreamlitPackage(s) and
    moduleHintOf(s) = "streamlit.server.upload_file_request_handler" and
    s.getObject() instanceof Name and
    s.getObject().(Name).getId() = "file" and
    s.getIndex() instanceof StringLiteral and
    fieldName = s.getIndex().(StringLiteral).getS() and
    nodeRepr = "multipart file field 'file[\"" + fieldName + "\"]'" and
    callableName = "file['" + fieldName + "']" and
    flowKind = "field" and
    receiver = "files (parsed multipart dict)" and
    moduleHint = "tornado.httputil.parse_body_arguments" and
    argIndex = -1 and
    context = "client-supplied multipart upload field parsed by tornado.httputil.parse_body_arguments; 'filename' is the client-controlled upload name stored into UploadedFileRec and later exposed to app scripts via st.file_uploader (uploads stay in memory)"
  )
  or
  /* Family 5: repo boundary wrapper returning parsed request-body values,
     self._require_arg(args, "sessionId" / "widgetId"). */
  exists(Call c, string argName |
    node = c and
    inStreamlitPackage(c) and
    dottedName(c.getFunc()) = "self._require_arg" and
    c.getPositionalArg(1) instanceof StringLiteral and
    argName = c.getPositionalArg(1).(StringLiteral).getS() and
    nodeRepr = "call self._require_arg(args, \"" + argName + "\")" and
    callableName = "self._require_arg" and
    flowKind = "return" and
    receiver = "self" and
    moduleHint = "streamlit.server.upload_file_request_handler" and
    argIndex = -1 and
    context = "boundary wrapper returning a parsed request-body argument value ('" + argName + "' -> args[name][0].decode('utf-8'))"
  )
  or
  /* Family 6: environment variable reads - local operator environment
     (STREAMLIT_* config), not a network boundary; kept for labeling to
     judge whether any cross-boundary flow is plausible. */
  exists(Call c, string dotted |
    node = c and
    inStreamlitPackage(c) and
    dotted = dottedName(c.getFunc()) and
    dotted in ["os.environ.get", "os.getenv"] and
    nodeRepr = "call " + dotted and
    callableName = dotted and
    flowKind = "return" and
    receiver = "os" and
    moduleHint = "os" and
    argIndex = -1 and
    context = "environment variable read (local operator environment, e.g. STREAMLIT_* configuration); not a network-attacker boundary - label as source only if a cross-boundary flow is judged plausible"
  )
  or
  /* Family 7: CLI argument boundary - streamlit run <target>. */
  exists(Function f, Parameter p, int i |
    f.getName() = "main_run" and
    moduleHintOf(f) = "streamlit.cli" and
    p = f.getArgByName("target") and
    f.getArg(i) = p and
    node = p.asName() and
    inStreamlitPackage(node) and
    nodeRepr = "parameter 'target' of main_run" and
    callableName = "main_run" and
    flowKind = "param" and
    receiver = "" and
    moduleHint = "streamlit.cli" and
    argIndex = i and
    context = "click CLI argument 'target' (envvar STREAMLIT_RUN_TARGET): local user input, not a network boundary; a URL target is downloaded to a temp file via open() (cli.py:75, 194-200)"
  )
}

/* ------------------------------------------------------------------ */
/* Select                                                              */
/* ------------------------------------------------------------------ */

from AstNode node, string nodeRepr, string role, string callableName,
     string flowKind, string receiver, string moduleHint, int argIndex,
     string filePath, int line, string context
where
  role = "source_candidate" and
  sourceCandidate(nodeRepr, callableName, flowKind, receiver, moduleHint, argIndex, context, node) and
  inStreamlitPackage(node) and
  filePath = relPath(node) and
  line = node.getLocation().getStartLine()
select nodeRepr, role, callableName, flowKind, receiver, moduleHint, argIndex, filePath, line, context
