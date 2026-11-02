
/**
 * @name Calibre-Web source candidate extraction (Pass 3, CWE-918)
 * @description Extract candidate external-input source APIs from the
 *              Calibre-Web Flask application for subsequent LLM labeling.
 * @id py/augur/calibre-web/pass3-sources
 *
 * Plain multi-column select query (no @kind) for
 *   codeql query run ... && codeql bqrs decode --format=csv
 * NOT intended for `codeql database analyze` SARIF output.
 *
 * Output columns:
 *  1. node                (AST node of the candidate)
 *  2. candidate type      ("source_candidate")
 *  3. callable name       (dotted signature hint)
 *  4. flow kind           (param | return | field | argument)
 *  5. receiver hint       (receiver/type hint)
 *  6. module hint         (dotted module path; variable named moduleHint,
 *                          "module" is a QL keyword and must not be used)
 *  7. argument index      (-1 when not applicable)
 *  8. line
 *  9. file:line
 * 10. expression text
 */

import python

// ------------------------------------------------------------
// 1. Scope and location helpers
// ------------------------------------------------------------

/**
 * Restrict extraction to Calibre-Web production code.
 *
 * The nested calibre-web-db CodeQL database directory and the test/
 * harness tree are outside the cps/ package and are therefore
 * excluded by this path filter.
 */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    (
      path.matches("cps/%")
      or
      path = "cps.py"
    )
  )
}

/**
 * Restrict a candidate to cps/cli.py.
 * The path string is bound by equality before matches()/comparison,
 * so no unbound-variable error can occur (an inPath(n, pattern)
 * predicate would leave "pattern" unbound inside matches()).
 */
predicate inCliModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path = "cps/cli.py"
  )
}

/** Restrict a candidate to the metadata provider package. */
predicate inMetadataProvider(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("cps/metadata_provider/%")
  )
}

/** Restrict a candidate to cps/search_metadata.py. */
predicate inSearchMetadataModule(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path = "cps/search_metadata.py"
  )
}

/** Dotted module name of a candidate. */
string moduleOf(AstNode n) {
  result = n.getScope().getEnclosingModule().getName()
}

/** Enclosing class name, or empty for module-level code. */
string receiverOf(AstNode n) {
  exists(Class c |
    n.getScope().getEnclosingScope+() = c and
    result = c.getName()
  )
  or
  (
    result = "" and
    not exists(Class c |
      n.getScope().getEnclosingScope+() = c
    )
  )
}

/** Human-readable file and line location. */
string locationOf(AstNode n) {
  result =
    n.getLocation().getFile().getRelativePath() +
    ":" +
    n.getLocation().getStartLine().toString()
}

// ------------------------------------------------------------
// 2. Flask request-shape signatures (verified against this source)
// ------------------------------------------------------------

/** Flask request containers whose contents are client input. */
predicate isRequestContainer(string name) {
  name in [
    "args",
    "form",
    "json",
    "values",
    "files",
    "headers"
  ]
}

/**
 * Flask request fields read directly (not as the base of an attribute
 * access, call, or subscript). Client-controlled or client-influenced
 * values only; server-derived fields (host, scheme, endpoint, ...) are
 * intentionally excluded and documented in detection.json.
 */
predicate isRequestField(string name) {
  name in [
    "args",
    "form",
    "json",
    "values",
    "files",
    "headers",
    "data",
    "referrer",
    "full_path",
    "path"
  ]
}

/**
 * Non-container request fields whose chained method calls still expose
 * the raw client-controlled value, e.g. request.full_path.rpartition(...)
 * (cps/kobo.py:69). Containers are covered by the accessor families.
 */
predicate isChainedRequestField(string name) {
  name in [
    "data",
    "referrer",
    "full_path",
    "path"
  ]
}

/** Accessor methods called on request.<container>. */
predicate isRequestAccessor(string name) {
  name in [
    "get",
    "getlist",
    "items",
    "to_dict"
  ]
}

/** Methods called directly on the flask request object. */
predicate isRequestObjectMethod(string name) {
  name in [
    "get_json",
    "get_data"
  ]
}

// ------------------------------------------------------------
// 3. Flask route-handler detection
// ------------------------------------------------------------

/**
 * Flask route handler: a function decorated with `@<bp>.route(...)`.
 *
 * Python CodeQL has no Decorator AST type; Function.getADecorator()
 * returns the decorator func expression (e.g. the `web.route`
 * attribute for `@web.route("/x")`).
 */
predicate isRouteHandler(Function f) {
  exists(Expr dec |
    dec = f.getADecorator() and
    dec instanceof Attribute and
    dec.(Attribute).getName() = "route"
  )
}

// ------------------------------------------------------------
// 4. Candidate extraction
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
    // (1) Parameters of Flask route handlers
    //     (URL path variables and defaulted query parameters)
    // --------------------------------------------------------

    exists(Parameter p, Function f, int i |
      n = p and
      p = f.getArg(i) and
      isRouteHandler(f) and
      callableName = f.getName() and
      flowKind = "param" and
      receiverHint = receiverOf(p) and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (2) request.<container>.<accessor>(...) calls
    //     e.g. request.args.get, request.form.to_dict,
    //          request.files.getlist, request.headers.get
    // --------------------------------------------------------

    exists(Call call, Attribute method, Attribute container, Name req |
      n = call and
      method = call.getFunc() and
      isRequestAccessor(method.getName()) and
      container = method.getObject() and
      isRequestContainer(container.getName()) and
      req = container.getObject() and
      req.getId() = "request" and
      callableName = "request." + container.getName() + "." + method.getName() and
      flowKind = "return" and
      receiverHint = "flask.request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (3) request.get_json() / request.get_data() calls
    // --------------------------------------------------------

    exists(Call call, Attribute method, Name req |
      n = call and
      method = call.getFunc() and
      isRequestObjectMethod(method.getName()) and
      req = method.getObject() and
      req.getId() = "request" and
      callableName = "request." + method.getName() and
      flowKind = "return" and
      receiverHint = "flask.request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (4) Chained .get() on request.get_json() results
    //     e.g. request.get_json().get('parameter', -1)
    // --------------------------------------------------------

    exists(Call call, Attribute method, Call inner, Attribute innerMethod, Name req |
      n = call and
      method = call.getFunc() and
      method.getName() = "get" and
      inner = method.getObject() and
      innerMethod = inner.getFunc() and
      innerMethod.getName() = "get_json" and
      req = innerMethod.getObject() and
      req.getId() = "request" and
      callableName = "request.get_json().get" and
      flowKind = "return" and
      receiverHint = "flask.request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (5) Chained .get() on request.<container>.to_dict() results
    //     e.g. request.form.to_dict().get("query")
    // --------------------------------------------------------

    exists(
      Call call, Attribute method, Call inner, Attribute innerMethod,
      Attribute container, Name req
    |
      n = call and
      method = call.getFunc() and
      method.getName() = "get" and
      inner = method.getObject() and
      innerMethod = inner.getFunc() and
      innerMethod.getName() = "to_dict" and
      container = innerMethod.getObject() and
      isRequestContainer(container.getName()) and
      req = container.getObject() and
      req.getId() = "request" and
      callableName = "request." + container.getName() + ".to_dict().get" and
      flowKind = "return" and
      receiverHint = "flask.request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (6) request.<container>[...] subscripts
    //     e.g. request.form["bookmark"], request.files['btn-upload']
    // --------------------------------------------------------

    exists(Subscript s, Attribute container, Name req |
      n = s and
      container = s.getObject() and
      isRequestContainer(container.getName()) and
      req = container.getObject() and
      req.getId() = "request" and
      callableName = "request." + container.getName() + "[]" and
      flowKind = "field" and
      receiverHint = "flask.request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (7) Subscripts on request.<container>.to_dict() results
    //     e.g. request.form.to_dict()['domainname']
    // --------------------------------------------------------

    exists(Subscript s, Call inner, Attribute innerMethod, Attribute container, Name req |
      n = s and
      inner = s.getObject() and
      innerMethod = inner.getFunc() and
      innerMethod.getName() = "to_dict" and
      container = innerMethod.getObject() and
      isRequestContainer(container.getName()) and
      req = container.getObject() and
      req.getId() = "request" and
      callableName = "request." + container.getName() + ".to_dict()[]" and
      flowKind = "field" and
      receiverHint = "flask.request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (8) Plain request.<field> reads
    //     e.g. request.json, request.data, request.headers,
    //          request.referrer, request.full_path
    //     Only fields not consumed as the base of another attribute
    //     access, call, or subscript (those are covered above).
    // --------------------------------------------------------

    exists(Attribute a, Name req |
      n = a and
      isRequestField(a.getName()) and
      req = a.getObject() and
      req.getId() = "request" and
      not exists(Attribute outer | outer.getObject() = a) and
      not exists(Call c | c.getFunc() = a) and
      not exists(Subscript s | s.getObject() = a) and
      callableName = "request." + a.getName() and
      flowKind = "field" and
      receiverHint = "flask.request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (8b) request.<field> used as the base of a further attribute
    //      access or method call, e.g.
    //      request.full_path.rpartition("/kobo/")  (cps/kobo.py:69)
    //      The inner attribute node is extracted; the raw field value
    //      flows through the chained method.
    // --------------------------------------------------------

    exists(Attribute a, Name req, Attribute outer |
      n = a and
      isChainedRequestField(a.getName()) and
      req = a.getObject() and
      req.getId() = "request" and
      outer.getObject() = a and
      callableName = "request." + a.getName() and
      flowKind = "field" and
      receiverHint = "flask.request" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (9) os.environ.get(...) environment reads
    // --------------------------------------------------------

    exists(Call call, Attribute method, Attribute environ, Name osName |
      n = call and
      method = call.getFunc() and
      method.getName() = "get" and
      environ = method.getObject() and
      environ.getName() = "environ" and
      osName = environ.getObject() and
      osName.getId() = "os" and
      callableName = "os.environ.get" and
      flowKind = "return" and
      receiverHint = "os.environ" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (10) os.getenv(...) environment reads
    // --------------------------------------------------------

    exists(Call call, Attribute method, Name osName |
      n = call and
      method = call.getFunc() and
      method.getName() = "getenv" and
      osName = method.getObject() and
      osName.getId() = "os" and
      callableName = "os.getenv" and
      flowKind = "return" and
      receiverHint = "os" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (11) CLI argparse reads (args.<flag>), restricted to cps/cli.py
    // --------------------------------------------------------

    exists(Attribute a, Name ns |
      n = a and
      ns = a.getObject() and
      ns.getId() = "args" and
      inCliModule(n) and
      callableName = "args." + a.getName() and
      flowKind = "field" and
      receiverHint = "argparse.Namespace" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (12) cover_url dict-key subscripts
    //      e.g. to_save["cover_url"] in cps/editbooks.py
    //      (earliest project-internal materialization of the
    //       attacker-supplied cover URL)
    // --------------------------------------------------------

    exists(Subscript s |
      n = s and
      s.getIndex() instanceof StringLiteral and
      s.getIndex().(StringLiteral).getText() = "cover_url" and
      callableName = "cover_url" and
      flowKind = "field" and
      receiverHint = "request_form_dict" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (13) Book/metadata URL fields (.url / .cover attribute reads),
    //      restricted to the metadata provider package
    //      (MetaRecord values parsed from remote responses)
    // --------------------------------------------------------

    exists(Attribute a |
      n = a and
      a.getName() in ["url", "cover"] and
      inMetadataProvider(n) and
      not exists(Assign asg | asg.getATarget() = a) and
      callableName = "MetaRecord." + a.getName() and
      flowKind = "field" and
      receiverHint = "MetaRecord" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (14) Internal propagation: get_store_url_for_current_request()
    //      (builds the Kobo store URL from request.full_path)
    // --------------------------------------------------------

    exists(Call call, Name fn |
      n = call and
      fn = call.getFunc() and
      fn.getId() = "get_store_url_for_current_request" and
      callableName = "get_store_url_for_current_request" and
      flowKind = "return" and
      receiverHint = receiverOf(n) and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (15) Internal propagation: metadata provider .search(query)
    //      dispatch in cps/search_metadata.py
    //      (query flows into provider-side URL construction)
    //      Covers both the direct call provider.search(...) and the
    //      c.search attribute reference passed as the first argument
    //      of executor.submit(...) (concurrent.futures dispatch).
    // --------------------------------------------------------

    exists(Call call, Attribute method |
      n = call and
      method = call.getFunc() and
      method.getName() = "search" and
      inSearchMetadataModule(n) and
      callableName = "Metadata.search" and
      flowKind = "argument" and
      receiverHint = "cps.services.Metadata" and
      argIndex = 0
    )

    or

    exists(Attribute a, Call submit, Attribute submitMethod |
      n = a and
      a.getName() = "search" and
      submitMethod = submit.getFunc() and
      submitMethod.getName() = "submit" and
      a = submit.getArg(0) and
      inSearchMetadataModule(n) and
      callableName = "Metadata.search" and
      flowKind = "argument" and
      receiverHint = "cps.services.Metadata" and
      argIndex = 0
    )
  )

select
  n,
  "source_candidate",
  callableName,
  flowKind,
  receiverHint,
  moduleHint,
  argIndex,
  n.getLocation().getStartLine(),
  locationOf(n),
  n.toString()
