/**
 * Name: MySources
 * Description: Source predicates for the Augur IRIS pipeline, rendered
 *   deterministically from iris/labels/labels.json (Pass 1, pass key
 *   "path_traversal", starlette 0.26.1 / starlette_vuln).
 *
 * Every rule below cites the label IDs it renders and the source-tree
 * evidence backing it. Sources are restricted to genuinely untrusted
 * external-input boundaries (ASGI request scope reads, scope parameters of
 * externally reachable ASGI entry points, request headers, multipart
 * Content-Disposition values, raw receive() wire messages and decode
 * boundaries). Internal wrapper parameters (labels p1-k-026 get_response
 * `path`, p1-k-032 lookup_path `path`, p1-k-039 file_response `full_path`)
 * are deliberately NOT rendered here; the propagation they bridge is modeled
 * in MySummaries.qll instead (see report/query_generation_notes.md).
 *
 * Generated: 2026-10-23, Augur Phase 2 Step 4 (labels v1.0.0,
 * run starlette-pathtraversal-pass1-step3-20261023, model glm-5.3).
 */

import python
import semmle.python.dataflow.new.DataFlow

/** Constrain to the audited starlette library package (tests/ and starlette-db/ excluded at extraction). */
private predicate inStarletteLibrary(AstNode n) {
  n.getLocation().getFile().getRelativePath().matches("starlette/%") or
  n.getLocation().getFile().getAbsolutePath().matches("%/starlette/%")
}

private predicate inFile(AstNode n, string baseName) {
  n.getLocation().getFile().getBaseName() = baseName
}

module MySources {
  /** Holds if `node` is a pass-1 (path_traversal) taint source per the reviewed labels. */
  predicate isSource(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and
    (
      scopePathRead(node)
      or scopeKeyRead(node)
      or scopeGetRead(node)
      or routeVarRead(node)
      or mountRemainderPop(node)
      or headerValueRead(node)
      or headerSubscriptRead(node)
      or multipartOptionRead(node)
      or decodeCallResult(node)
      or wireRead(node)
      or messageGetRead(node)
      or asgiScopeParameter(node)
      or handlerParameter(node)
      or parserParameter(node)
      or uploadFileCtor(node)
    )
  }

  /**
   * scope['path'] / redirect_scope['path'] subscript reads (http_path family).
   * Labels: p1-s-117 (staticfiles.py:111 - PRIMARY, conf 0.97), p1-s-120,
   * p1-s-085/092/097 (Route/WebSocketRoute/Mount matches), p1-s-111..114
   * (redirect_slashes), p1-s-014 (URL.__init__), p1-s-139 (WSGI PATH_INFO).
   * Evidence: the ASGI server delivers the percent-decoded request path in
   * scope['path'] (testclient.py:240/258: unquote(path)).
   */
  private predicate scopePathRead(DataFlow::Node node) {
    exists(Subscript sub |
      node.asExpr() = sub and
      sub.getCtx() instanceof Load and
      sub.getIndex().(StringLiteral).getText() = "path" and
      (
        sub.getObject().(Name).getId() = "scope"
        or sub.getObject().(Name).getId() = "redirect_scope"
      ) and
      inStarletteLibrary(sub) and
      (
        inFile(sub, "staticfiles.py")
        or inFile(sub, "routing.py")
        or inFile(sub, "datastructures.py")
        or inFile(sub, "wsgi.py")
      )
    )
  }

  /**
   * scope['method'] / scope['query_string'] / scope['headers'] subscript reads.
   * Labels: p1-s-005, p1-s-062, p1-s-067, p1-s-088, p1-s-090, p1-s-119,
   * p1-s-121, p1-s-123, p1-s-137, p1-s-140, p1-s-016, p1-s-019.
   * Evidence: request-state keys on the attacker-controlled ASGI scope.
   */
  private predicate scopeKeyRead(DataFlow::Node node) {
    exists(Subscript sub, string key |
      node.asExpr() = sub and
      sub.getCtx() instanceof Load and
      sub.getObject().(Name).getId() = "scope" and
      (
        key = "method" or key = "query_string" or key = "headers"
      ) and
      sub.getIndex().(StringLiteral).getText() = key and
      inStarletteLibrary(sub) and
      (
        inFile(sub, "cors.py") or inFile(sub, "requests.py") or
        inFile(sub, "routing.py") or inFile(sub, "staticfiles.py") or
        inFile(sub, "wsgi.py") or inFile(sub, "datastructures.py")
      )
    )
  }

  /**
   * scope.get(...) / base_url_scope.get(...) container reads returning
   * request-derived values: path_params (route variables), query_string,
   * root_path / app_root_path (candidate-confidence labels, see notes).
   * Labels: p1-s-087, p1-s-094, p1-s-100, p1-s-106, p1-s-063 (path_params),
   * p1-s-015 (query_string), p1-s-013, p1-s-101, p1-s-061, p1-s-138
   * (root_path/app_root_path, classification candidate 0.55).
   * Evidence: routing.py:243 scope.get('path_params', {}), requests.py:124
   * path_params accessor, datastructures.py:34-35.
   */
  private predicate scopeGetRead(DataFlow::Node node) {
    exists(Call c, string key |
      node.asExpr() = c and
      c.getFunc().(Attribute).getName() = "get" and
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "scope"
        or c.getFunc().(Attribute).getObject().(Name).getId() = "base_url_scope"
      ) and
      (
        key = "path_params" or key = "query_string" or
        key = "root_path" or key = "app_root_path"
      ) and
      c.getPositionalArg(0).(StringLiteral).getText() = key and
      inStarletteLibrary(c) and
      (
        inFile(c, "routing.py") or inFile(c, "requests.py") or
        inFile(c, "datastructures.py") or inFile(c, "wsgi.py")
      )
    )
  }

  /**
   * match.groupdict() call results: routed path parameters extracted from the
   * regex match over scope['path'] (route_var family).
   * Labels: p1-s-086, p1-s-093, p1-s-098, p1-s-105.
   * Evidence: routing.py:238-244 (Route.matches), :316-321, :388-396, :475-481.
   */
  private predicate routeVarRead(DataFlow::Node node) {
    exists(Call c |
      node.asExpr() = c and
      c.getFunc().(Attribute).getName() = "groupdict" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "match" and
      inStarletteLibrary(c) and
      inFile(c, "routing.py")
    )
  }

  /**
   * matched_params.pop('path') call result: the Mount remainder that becomes
   * the child scope['path'] for the mounted app.
   * Label: p1-s-099 (routing.py:394, conf 0.90).
   * Evidence: routing.py:394-403.
   */
  private predicate mountRemainderPop(DataFlow::Node node) {
    exists(Call c |
      node.asExpr() = c and
      c.getFunc().(Attribute).getName() = "pop" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "matched_params" and
      c.getPositionalArg(0).(StringLiteral).getText() = "path" and
      inStarletteLibrary(c) and
      inFile(c, "routing.py")
    )
  }

  /**
   * <x>.headers.get(...) / .getlist(...) header value reads (http_header).
   * Labels: p1-s-006, p1-s-009, p1-s-017, p1-s-033, p1-s-056, p1-s-064,
   * p1-s-071, p1-s-075, p1-s-104, p1-s-131, p1-s-053 (params.get charset).
   * Evidence: request headers are attacker-controlled; the multipart
   * Content-Type header (requests.py:257) drives the filename parsing chain.
   */
  private predicate headerValueRead(DataFlow::Node node) {
    exists(Call c, Expr obj |
      node.asExpr() = c and
      obj = c.getFunc().(Attribute).getObject() and
      (
        c.getFunc().(Attribute).getName() = "get"
        or c.getFunc().(Attribute).getName() = "getlist"
      ) and
      (
        obj.(Name).getId() = "headers"
        or obj.(Name).getId() = "request_headers"
        or obj.(Name).getId() = "params"
        or obj.(Attribute).getName() = "headers"
      ) and
      inStarletteLibrary(c) and
      (
        inFile(c, "cors.py") or inFile(c, "errors.py") or inFile(c, "gzip.py") or
        inFile(c, "trustedhost.py") or inFile(c, "routing.py") or
        inFile(c, "requests.py") or inFile(c, "datastructures.py") or
        inFile(c, "formparsers.py")
      )
    )
  }

  /**
   * request_headers['...'] / self.headers['...'] header subscript reads.
   * Labels: p1-s-007, p1-s-008, p1-s-011 (CORS), p1-s-124, p1-s-125
   * (StaticFiles conditional headers - response metadata only), p1-s-052
   * (multipart Content-Type).
   * Evidence: staticfiles.py:227/235, formparsers.py:228, cors.py:105-158.
   */
  private predicate headerSubscriptRead(DataFlow::Node node) {
    exists(Subscript sub, Expr obj |
      node.asExpr() = sub and
      sub.getCtx() instanceof Load and
      obj = sub.getObject() and
      sub.getIndex() instanceof StringLiteral and
      (
        obj.(Name).getId() = "request_headers"
        or obj.(Attribute).getName() = "headers"
      ) and
      inStarletteLibrary(sub) and
      (
        inFile(sub, "cors.py") or inFile(sub, "staticfiles.py") or
        inFile(sub, "formparsers.py")
      )
    )
  }

  /**
   * Multipart Content-Disposition/Content-Type option reads:
   * options[b'name'], options[b'filename'], params[b'boundary'].
   * Labels: p1-s-047, p1-s-049 (multipart_filename, conf 0.90), p1-s-054.
   * Evidence: formparsers.py:194/200-206/234 - the filename is fully
   * attacker-controlled (no in-tree path sink; kept per reviewed labels).
   */
  private predicate multipartOptionRead(DataFlow::Node node) {
    exists(Subscript sub, string opt |
      node.asExpr() = sub and
      sub.getCtx() instanceof Load and
      (
        sub.getObject().(Name).getId() = "options"
        or sub.getObject().(Name).getId() = "params"
      ) and
      (
        opt = "name" or opt = "filename" or opt = "boundary"
      ) and
      sub.getIndex().(StringLiteral).getText() = opt and
      inStarletteLibrary(sub) and
      inFile(sub, "formparsers.py")
    )
  }

  /**
   * Decode-boundary call results (url_decode family): unquote_plus,
   * _user_safe_decode, parse_options_header, http_cookies._unquote.
   * Labels: p1-s-040, p1-s-041, p1-s-044, p1-s-046, p1-s-048, p1-s-045,
   * p1-s-051, p1-s-072, p1-s-059.
   * Evidence: formparsers.py:111-112/162/193/206/189/228, requests.py:55/259.
   * (unquote in testclient.py is a none/fp test-machinery label - excluded
   * via the file constraint.)
   */
  private predicate decodeCallResult(DataFlow::Node node) {
    exists(Call c, string fn |
      node.asExpr() = c and
      (
        c.getFunc().(Name).getId() = fn
        or c.getFunc().(Attribute).getName() = fn
      ) and
      (
        fn = "unquote_plus" or fn = "_user_safe_decode" or
        fn = "parse_options_header" or fn = "_unquote"
      ) and
      inStarletteLibrary(c) and
      (
        inFile(c, "formparsers.py") or inFile(c, "requests.py")
      )
    )
  }

  /**
   * Raw ASGI wire reads: self._receive() / websocket.receive() call results.
   * Labels: p1-s-068, p1-s-073, p1-s-133, p1-s-134, p1-s-023.
   * Evidence: requests.py:221/301 (Request.stream body loop), websockets.py:35/45,
   * endpoints.py:77 (WebSocketEndpoint.dispatch).
   */
  private predicate wireRead(DataFlow::Node node) {
    exists(Call c |
      node.asExpr() = c and
      (
        c.getFunc().(Attribute).getName() = "_receive"
        or c.getFunc().(Attribute).getName() = "receive"
      ) and
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "self"
        or c.getFunc().(Attribute).getObject().(Name).getId() = "websocket"
      ) and
      inStarletteLibrary(c) and
      (
        inFile(c, "requests.py") or inFile(c, "websockets.py") or
        inFile(c, "endpoints.py")
      )
    )
  }

  /**
   * message.get(...) reads on incoming ASGI messages (http_wire).
   * Labels: p1-s-069, p1-s-070, p1-s-074, p1-s-024, p1-s-026, p1-s-027.
   * Evidence: requests.py:223/226/303, endpoints.py:83/106/120.
   */
  private predicate messageGetRead(DataFlow::Node node) {
    exists(Call c |
      node.asExpr() = c and
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "message" and
      inStarletteLibrary(c) and
      (
        inFile(c, "requests.py") or inFile(c, "endpoints.py")
      )
    )
  }

  /**
   * `scope` parameters of externally reachable ASGI entry points (param
   * family, 42 labels at conf 0.70-0.90). Function names are exactly the
   * labeled ASGI surface: __call__ / matches / handle / not_found / app
   * closures / build_environ / __init__ (class ASGI apps and request
   * wrappers) / get_response / file_response / simple_response.
   * Labels: p1-s-001..p1-s-142 (scope-param subset; see
   * report/query_generation_notes.md for the full ID list).
   * The lifespan handler is excluded (label p1-s-109 is none/fp: lifecycle
   * events, not request data). get_path's scope parameter is not a source -
   * it is modeled as a summary step (label p1-s-116).
   */
  private predicate asgiScopeParameter(DataFlow::Node node) {
    exists(Parameter p, Function f, string fname |
      node = DataFlow::parameterNode(p) and
      f.getAnArg() = p and
      p.getName() = "scope" and
      f.getName() = fname and
      (
        fname = "__call__" or fname = "matches" or fname = "handle" or
        fname = "not_found" or fname = "app" or fname = "build_environ" or
        fname = "__init__" or fname = "get_response" or
        fname = "file_response" or fname = "simple_response"
      ) and
      fname != "lifespan" and
      inStarletteLibrary(f)
    )
  }

  /**
   * Framework-injected request/websocket handler parameters.
   * Labels: p1-s-021, p1-s-032, p1-s-034, p1-s-036 (request), p1-s-025,
   * p1-s-028, p1-s-029, p1-s-030, p1-s-037 (websocket).
   * Evidence: endpoints.py:47-129, middleware/errors.py:246/255,
   * middleware/exceptions.py:99/107.
   */
  private predicate handlerParameter(DataFlow::Node node) {
    exists(Parameter p |
      node = DataFlow::parameterNode(p) and
      (
        p.getName() = "request" or p.getName() = "websocket"
      ) and
      inStarletteLibrary(p) and
      (
        inFile(p, "endpoints.py") or inFile(p, "errors.py") or
        inFile(p, "exceptions.py")
      )
    )
  }

  /**
   * Form/multipart parser input parameters: headers (arg 1) and stream
   * (arg 2) of FormParser/MultiPartParser, receive (arg 2) of Request.
   * Labels: p1-s-038, p1-s-039, p1-s-042, p1-s-043, p1-s-066.
   * Evidence: formparsers.py:47-54/:121-127, requests.py:194.
   */
  private predicate parserParameter(DataFlow::Node node) {
    exists(Parameter p |
      node = DataFlow::parameterNode(p) and
      (
        (p.getName() = "headers" or p.getName() = "stream") and
        inFile(p, "formparsers.py")
        or
        p.getName() = "receive" and inFile(p, "requests.py")
      ) and
      inStarletteLibrary(p)
    )
  }

  /**
   * UploadFile(...) construction carrying the attacker-controlled multipart
   * filename (stored on the UploadFile.filename field).
   * Label: p1-s-050 (formparsers.py:209, conf 0.85).
   * Evidence: formparsers.py:209-214; datastructures.py:440-448.
   */
  private predicate uploadFileCtor(DataFlow::Node node) {
    exists(Call c |
      node.asExpr() = c and
      c.getFunc().(Name).getId() = "UploadFile" and
      inStarletteLibrary(c) and
      inFile(c, "formparsers.py")
    )
  }
}
