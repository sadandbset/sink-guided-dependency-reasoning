/**
 * Augur Pass 1 (Path Traversal) source model for xmpp-http-upload.
 *
 * Generated deterministically from the reviewed Pass 1 labels in
 * iris/labels/labels.json (the 4 entries with role=source and
 * classification=tp), plus the route-parameter source directed by the
 * reviewed checkpoint labels/phase1_review.md §6.1/§7 (see the
 * routePathParameterSource doc comment below - it is NOT a labels.json
 * row and is attributed to the review decision, not silently added).
 *
 * External input boundary of this service (a Flask app behind a reverse
 * proxy): the HTTP request. Only genuinely attacker-controlled request
 * inputs are modeled:
 *   - the Werkzeug `/<path:path>` route-converter bindings of the three
 *     handlers (put_file :105 / head_file :190 / get_file :215) - the
 *     URL-decoded remainder of the request URL, THE dominant untrusted
 *     file-location input (reviewed: phase1_review.md §6.1);
 *   - the labeled flask.request accessors: args.get("v") :118,
 *     headers.get("Content-Length") :119, headers.get("Content-Type")
 *     :132, request.stream :142 (labels src-001..src-004; per their
 *     reviewed rationales none of these reaches a filesystem path in
 *     this codebase, so they are expected to produce no Pass 1 alerts -
 *     they are modeled for label fidelity).
 *
 * Deliberately NOT sources (reviewed as internal, not external
 * boundaries): the parameter rows of sanitized_join/get_info/get_paths/
 * write_file/load_metadata (labels sink-005/011/012/014/018 -
 * summary/none) and every app.config read (DATA_ROOT / SECRET_KEY /
 * ENABLE_CORS / NON_ATTACHMENT_MIME_TYPES - operator configuration,
 * documented in detection.json inputBoundaryInventory).
 *
 * Unified pass key: "path_traversal" (CWE-022/023/036/073).
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  /**
   * Holds if `source` is a reviewed Pass 1 taint source for pass key
   * `passKey`.
   */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "path_traversal" and (
      routePathParameterSource(source) or
      requestArgsGetSource(source) or
      requestHeadersGetSource(source) or
      requestStreamSource(source)
    )
  }

  /** Restricts an AST node to a file base name and a 1-based start line. */
  private predicate matchLoc(AstNode n, string baseName, int line) {
    n.getLocation().getFile().getBaseName() = baseName and
    n.getLocation().getStartLine() = line
  }

  /**
   * Route-parameter source (reviewed checkpoint decision, labels/
   * phase1_review.md §6.1 + §7; NOT a labels.json entry): the `path`
   * parameters of the three Flask handlers bound by the Werkzeug
   * `path` converter of @app.route("/<path:path>", methods=[...])
   * at xhu.py:104/:189/:214.
   *
   *   xhu.py:104-105: @app.route("/<path:path>", methods=["PUT"])
   *                   def put_file(path):
   *   xhu.py:189-190: @app.route("/<path:path>", methods=["HEAD"])
   *                   def head_file(path):
   *   xhu.py:214-215: @app.route("/<path:path>", methods=["GET"])
   *                   def get_file(path):
   *
   * External input boundary: the request URL. The `path` converter
   * (regex [^/].*?) captures the ENTIRE remainder of the request URL
   * (slashes included) after Werkzeug percent-deoding, and binds it to
   * the same-named handler parameter - fully attacker-controlled,
   * including "../" traversal segments (the Step 3 review verified via
   * iris/diagnostics that getADecorator() returns the decorator Call
   * node here, so the handler matching uses the Call->func-Attribute
   * pattern dec.(Call).getFunc().(Attribute).getName() = "route" and
   * additionally requires the route pattern to textually bind the
   * parameter through a <path:...> converter). Access conditions:
   * get_file/head_file are UNAUTHENTICATED (any HTTP client); put_file
   * additionally requires a valid HMAC over "{path} {length}" signed
   * with the operator SECRET_KEY (xhu.py:118-130) - the attacker
   * controls the path either way, the HMAC bounds who may use the PUT
   * side. The `index` handler (:84, route "/") has no converter and no
   * parameters and is excluded by the pattern check.
   */
  private predicate routePathParameterSource(DataFlow::Node source) {
    exists(Function f, Parameter p, Call dec, Attribute fn, StringLiteral routePattern |
      dec = f.getADecorator() and
      fn = dec.getFunc().(Attribute) and
      fn.getName() = "route" and
      routePattern = dec.getArg(0).(StringLiteral) and
      routePattern.getText().matches("%<path:" + p.getName() + ">%") and
      p = f.getAnArg() and
      (
        matchLoc(p, "xhu.py", 105) or
        matchLoc(p, "xhu.py", 190) or
        matchLoc(p, "xhu.py", 215)
      ) and
      source instanceof DataFlow::ParameterNode and
      source.(DataFlow::ParameterNode).getParameter() = p
    )
  }

  /**
   * src-001 (source/tp 0.90): the PUT verification key from the query
   * string.
   *
   *   xhu.py:118: verification_key = flask.request.args.get("v", "")
   *
   * External input boundary: the request query string (fully
   * attacker-controlled, URL-decoded by the framework). Per the
   * reviewed label rationale it flows only into
   * hmac.compare_digest (xhu.py:125) and never into a filesystem path,
   * so no Pass 1 alert is expected from it.
   */
  private predicate requestArgsGetSource(DataFlow::Node source) {
    exists(Call c, Attribute getAttr |
      c.getFunc() = getAttr and
      getAttr.getName() = "get" and
      getAttr.getObject().(Attribute).getName() = "args" and
      matchLoc(c, "xhu.py", 118) and
      source.asExpr() = c
    )
  }

  /**
   * src-002 (source/tp 0.90, xhu.py:119, Content-Length) and src-003
   * (source/tp 0.85, xhu.py:132, Content-Type): request header reads.
   *
   *   xhu.py:119: length = int(flask.request.headers.get("Content-Length", 0))
   *   xhu.py:132: content_type = flask.request.headers.get("Content-Type", ...)
   *
   * External input boundary: the request headers (attacker-controlled).
   * Per the reviewed label rationales: Content-Length is int()-coerced
   * into the HMAC input and the stream-copy length; Content-Type is
   * persisted to the .meta JSON and replayed as a response header
   * (pass-10 adjacent). Neither ever becomes a filesystem path, so no
   * Pass 1 alert is expected from them.
   */
  private predicate requestHeadersGetSource(DataFlow::Node source) {
    exists(Call c, Attribute getAttr |
      c.getFunc() = getAttr and
      getAttr.getName() = "get" and
      getAttr.getObject().(Attribute).getName() = "headers" and
      (matchLoc(c, "xhu.py", 119) or matchLoc(c, "xhu.py", 132)) and
      source.asExpr() = c
    )
  }

  /**
   * src-004 (source/tp 0.75): the raw request-body object.
   *
   *   xhu.py:142: stream_file(flask.request.stream, fout, length)
   *
   * External input boundary: the request body bytes (fully
   * attacker-controlled). Per the reviewed label rationale the value is
   * consumed only as file CONTENT via stream_file (xhu.py:92-101) and
   * never as a filesystem path, so no Pass 1 alert is expected from it.
   */
  private predicate requestStreamSource(DataFlow::Node source) {
    exists(Attribute streamAttr |
      streamAttr.getName() = "stream" and
      streamAttr.getObject().(Attribute).getName() = "request" and
      matchLoc(streamAttr, "xhu.py", 142) and
      source.asExpr() = streamAttr
    )
  }
}
