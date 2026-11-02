
/**
 * @name BinderHub source candidate extraction (Pass 2, CWE-78)
 * @description Extract candidate external-input source APIs from
 *              BinderHub for subsequent LLM labeling.
 * @kind problem
 * @id py/augur/binderhub/pass2-sources
 * @problem.severity recommendation
 */

import python

// ------------------------------------------------------------
// 1. Helpers
// ------------------------------------------------------------

/** HTTP request handler method names. */
predicate isRequestMethod(string name) {
  name in [
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "head",
    "options"
  ]
}

/** Classes that appear to be Tornado request handlers. */
predicate isHandlerClass(Class c) {
  c.getName().matches("%Handler")
  or
  exists(Expr base |
    base = c.getABase() and
    (
      (
        base instanceof Name and
        base.(Name).getId().matches("%Handler")
      )
      or
      (
        base instanceof Attribute and
        base.(Attribute).getName().matches("%Handler")
      )
    )
  )
}

/** Restrict extraction to the BinderHub package. */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("binderhub/%") and
    not path.matches("%/tests/%") and
    not path.matches("%_version.py")
  )
}

/** Module name for the current AST node. */
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
// 2. Candidate source signatures
// ------------------------------------------------------------

/** Tornado request argument accessor names. */
predicate isRequestArgAccessor(string name) {
  name in [
    "get_argument",
    "get_arguments",
    "get_query_argument",
    "get_query_arguments",
    "get_body_argument",
    "get_body_arguments",
    "get_cookie",
    "get_secure_cookie"
  ]
}

/** HTTPServerRequest fields that may contain external data. */
predicate isRequestField(string fieldName) {
  fieldName in [
    "path",
    "uri",
    "query",
    "query_arguments",
    "body",
    "body_arguments",
    "headers",
    "host",
    "protocol",
    "remote_ip",
    "files",
    "cookies",
    "arguments"
  ]
}

/** Project-internal propagation methods. */
predicate isInternalPropagationMethod(string name) {
  name in [
    "get_spec_from_request",
    "get_provider",
    "get_repo_url",
    "get_resolved_ref",
    "get_resolved_spec",
    "get_resolved_ref_url",
    "get_build_slug"
  ]
}

// ------------------------------------------------------------
// 3. Candidate extraction
// ------------------------------------------------------------

/**
 * Output columns:
 *
 *  1. Node
 *  2. Candidate type
 *  3. Callable name
 *  4. Flow kind
 *  5. Receiver
 *  6. Module hint
 *  7. Argument index
 *  8. Line
 *  9. File:line
 * 10. Expression
 *
 * Do not use "module" as a variable: it is a QL keyword.
 */
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
    // (1) Route parameters of request-handler methods
    // --------------------------------------------------------

    exists(Parameter p, Function f, Class c, int i |
      n = p and
      p = f.getArg(i) and
      i >= 1 and
      isRequestMethod(f.getName()) and
      c = f.getEnclosingScope() and
      isHandlerClass(c) and
      callableName = f.getName() and
      flowKind = "param" and
      receiverHint = c.getName() and
      argIndex = i
    )

    or

    // --------------------------------------------------------
    // (2) Tornado request-argument accessor calls
    // --------------------------------------------------------

    exists(Call call, Attribute method |
      n = call and
      method = call.getFunc() and
      isRequestArgAccessor(method.getName()) and
      callableName = method.getName() and
      flowKind = "return" and
      receiverHint = receiverOf(n) and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (3) self.request.<field> attribute reads
    // --------------------------------------------------------

    exists(
      Attribute field,
      Attribute requestAttr,
      Name selfName
    |
      n = field and
      isRequestField(field.getName()) and
      requestAttr = field.getObject() and
      requestAttr.getName() = "request" and
      selfName = requestAttr.getObject() and
      selfName.getId() = "self" and
      callableName = "request." + field.getName() and
      flowKind = "field" and
      receiverHint = "tornado.httputil.HTTPServerRequest" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (4a) os.getenv(...) reads
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
    // (4b) os.environ.get(...) reads
    // --------------------------------------------------------

    exists(
      Call call,
      Attribute method,
      Attribute environAttr,
      Name osName
    |
      n = call and
      method = call.getFunc() and
      method.getName() = "get" and
      environAttr = method.getObject() and
      environAttr.getName() = "environ" and
      osName = environAttr.getObject() and
      osName.getId() = "os" and
      callableName = "os.environ.get" and
      flowKind = "return" and
      receiverHint = "os.environ" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (5) json.loads(...) calls
    // --------------------------------------------------------

    exists(Call call, Attribute method, Name jsonName |
      n = call and
      method = call.getFunc() and
      method.getName() = "loads" and
      jsonName = method.getObject() and
      jsonName.getId() = "json" and
      callableName = "json.loads" and
      flowKind = "return" and
      receiverHint = "json" and
      argIndex = -1
    )

    or

    // --------------------------------------------------------
    // (6) Project-internal propagation methods
    // --------------------------------------------------------

    exists(Call call, Attribute method |
      n = call and
      method = call.getFunc() and
      isInternalPropagationMethod(method.getName()) and
      callableName = method.getName() and
      flowKind = "return" and
      receiverHint = method.getObject().toString() and
      argIndex = -1
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