/**
 * @name pretalx Pass 1 source candidates (Path Traversal)
 * @description Extracts untrusted-input source candidates for CWE-22/23/36/73 from
 *   the pretalx 2.3.1post0 Django application: Django function-view and
 *   request-handler parameters bound from URL routes, request object field reads
 *   (GET/POST/FILES/headers/COOKIES/session/body/path/META), request-field and
 *   route-kwarg subscripts and .get()/.getlist() lookups, form
 *   cleaned_data/files reads (second-order, request-derived), cfp wizard
 *   session data, and environment-configuration reads (with an explicit
 *   operator-boundary caveat). Evidence-derived from pretalx/urls.py,
 *   pretalx/agenda/urls.py, pretalx/common/views.py, pretalx/cfp/flow.py,
 *   pretalx/common/mixins/views.py, pretalx/common/mixins/forms.py,
 *   pretalx/orga/forms/review.py, pretalx/orga/forms/event.py and the
 *   agenda/cfp/orga view modules.
 *   Multi-column candidate table intended for `codeql query run` followed by
 *   `codeql bqrs decode --format=csv`. This query deliberately has NO @kind
 *   annotation: a @kind problem select shape cannot carry the multi-column
 *   extraction contract, and no @kind table is assumed.
 * @id iris/pretalx-cwe22/extract-sources
 */

import python

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/**
 * Gets the dotted name of a simple name/attribute chain,
 * e.g. "os.environ.get" or "self.request.FILES". Yields no result for
 * expressions whose object part is not a simple name/attribute chain.
 */
private string dottedName(Expr e) {
  result = e.(Name).getId()
  or
  result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
}

/**
 * Gets the repository-relative path of the file containing this node,
 * e.g. "src/pretalx/common/views.py". The primary source is
 * File.getRelativePath(); on this Windows-created database the stored source
 * location prefix uses backslashes while file paths are forward-slash
 * normalized, so getRelativePath() may yield backslash forms or no result -
 * in that case fall back to capturing the "src/pretalx/..." suffix from the
 * absolute path (verified forward-slash format in the database string pool).
 */
private string relPath(AstNode n) {
  exists(string p |
    p = n.getLocation().getFile().getRelativePath() and
    result = p.replaceAll("\\", "/")
  )
  or
  not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
  result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/").regexpCapture(".*/(src/pretalx/.+)$", 1)
}

/** Derives a module hint such as "src.pretalx.common.views" from the file path. */
private string moduleHintOf(AstNode n) {
  result = relPath(n).replaceAll(".py", "").replaceAll("/", ".")
}

/**
 * Restricts candidates to the pretalx package itself. This structurally
 * excludes the nested pretalx-db CodeQL database directory, the src/tests
 * tree and repository-root scripts, and per the Augur noise policy it also
 * excludes generated migration files.
 */
private predicate inPretalxPackage(AstNode n) {
  relPath(n).matches("src/pretalx/%") and
  not relPath(n).matches("%/migrations/%")
}

/** Gets the enclosing class name for methods, or "" for plain functions. */
private string receiverOf(Function f) {
  f.isMethod() and result = f.getEnclosingScope().(Class).getName()
  or
  not f.isMethod() and result = ""
}

/**
 * Holds for request-handling functions: module-level functions whose
 * parameter 0 is named "request", and methods whose parameter 1 is named
 * "request" (parameter 0 being "self"). `requestIdx` is the parameter index
 * holding the request object.
 */
private predicate requestHandler(Function f, int requestIdx) {
  exists(Parameter req |
    (
      (
        not f.isMethod() and
        requestIdx = 0 and
        f.getArg(0) = req
      )
      or
      (
        f.isMethod() and
        requestIdx = 1 and
        f.getArg(1) = req
      )
    )
    and
    req.asName().getId() = "request"
  )
}

/** Request object fields whose reads are untrusted HTTP input. */
private predicate isRequestField(string fieldName) {
  fieldName in [
    "GET", "POST", "FILES", "headers", "COOKIES", "session", "body",
    "path", "path_info", "resolver_match", "META", "data"
  ]
}

/**
 * Holds for attribute reads of a request field, matching both
 * "request.<field>" and "self.request.<field>" chains. Only these chains are
 * accepted, so unrelated local variables named "request" elsewhere cannot
 * match unless they shadow the framework request object.
 */
private predicate requestFieldAttr(Attribute a, string fieldName) {
  isRequestField(fieldName) and
  a.getName() = fieldName and
  (
    a.getObject() instanceof Name and
    a.getObject().(Name).getId() = "request"
    or
    a.getObject() instanceof Attribute and
    a.getObject().(Attribute).getName() = "request" and
    a.getObject().(Attribute).getObject() instanceof Name and
    a.getObject().(Attribute).getObject().(Name).getId() = "self"
  )
}

/**
 * Holds for route-kwarg mapping attributes: "self.kwargs" (class-based view
 * URL variables), "url.kwargs" (resolver match kwargs) and
 * "request.resolver_match.kwargs" (raw resolver match kwargs).
 */
private predicate kwargsAttr(Attribute a) {
  a.getName() = "kwargs" and
  (
    a.getObject() instanceof Name and
    a.getObject().(Name).getId() in ["self", "url"]
    or
    a.getObject() instanceof Attribute and
    a.getObject().(Attribute).getName() = "resolver_match"
  )
}

/** Maps a request field name to a flow-kind label for the labeling stage. */
private string requestFieldFlowKind(string fieldName) {
  fieldName = "GET" and result = "request_query"
  or
  fieldName = "POST" and result = "request_form"
  or
  fieldName = "FILES" and result = "request_files"
  or
  fieldName in ["headers", "COOKIES", "META"] and result = "request_headers"
  or
  fieldName = "session" and result = "request_session"
  or
  fieldName = "body" and result = "request_body"
  or
  fieldName in ["path", "path_info"] and result = "http_path"
  or
  fieldName = "resolver_match" and result = "resolver_match"
  or
  fieldName = "data" and result = "request_data"
}

/** Maps a request field name to a short context description. */
private string requestFieldContext(string fieldName) {
  fieldName = "FILES" and
  result = "multipart upload binding: client-supplied filenames and file content flow into Django FileField/FileSystemStorage handling"
  or
  fieldName in ["path", "path_info"] and
  result = "raw HTTP request URL path (attacker-controlled); used for URL resolution, redirects and export path derivation"
  or
  fieldName in ["GET", "POST", "headers", "COOKIES", "META", "body", "data"] and
  result = "untrusted HTTP request field (query/form/header/cookie/raw body data)"
  or
  fieldName = "session" and
  result = "server-side session store; contains user-influenced wizard data and upload tmp_names"
  or
  fieldName = "resolver_match" and
  result = "Django resolver match for the current URL (url_name and route kwargs)"
}

/**
 * Holds for form value container attributes: "self.cleaned_data",
 * "form.cleaned_data", "self.files", "self.cleaned_data.get(...)" objects,
 * i.e. the boundary where request data re-enters code after form validation.
 */
private predicate formValueAttr(Attribute a, string containerName) {
  a.getName() = containerName and
  containerName in ["cleaned_data", "files"] and
  a.getObject() instanceof Name
}

/* ------------------------------------------------------------------ */
/* Source candidate relation                                           */
/* ------------------------------------------------------------------ */

/**
 * Holds for each untrusted-input source candidate. `argIndex` is the real
 * 0-based parameter index (including `self` for methods) for `param` rows,
 * and -1 for field-read candidates where no positional index applies.
 */
private predicate sourceCandidate(
  string nodeRepr, string callableName, string flowKind, string receiver,
  string moduleHint, int argIndex, string context, AstNode node
) {
  /* Family 1: request-handler parameters beyond the request object.
     In Django these bind URL route variables via path()/re_path()
     converters (<slug:event>, <int:pk>, <slug>, <code>, <version>,
     <locale>) or are request-derived values passed by framework callers
     (context processors, middleware, etag helpers). */
  exists(Function f, Parameter p, int i, int requestIdx |
    inPretalxPackage(f) and
    requestHandler(f, requestIdx) and
    f.getArg(i) = p and
    i > requestIdx and
    node = p.asName() and
    (
      f.getName() = "get_static" and
      p.asName().getId() = "path" and
      context = "get_static 'path' parameter: URL-injected value joined via settings.BASE_DIR / 'pretalx/static' / path and then opened; currently routed only at sw.js with the literal 'agenda/js/serviceworker.js' (agenda/urls.py), so attacker control requires a malicious/plugin urlconfig"
      or
      not (f.getName() = "get_static" and p.asName().getId() = "path") and
      context = "Django view/handler parameter bound from URL route via path()/re_path() converters (<slug:event>, <int:pk>, <slug>, <code>, <version>, <locale>) or request-derived value passed by a framework caller"
    ) and
    nodeRepr = "parameter '" + p.asName().getId() + "' of handler " + f.getName() and
    callableName = f.getName() and
    flowKind = "http_route_param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = i
  )
  or
  /* Family 2: request object field reads, e.g. request.GET,
     self.request.FILES, request.headers, request.path. */
  exists(Attribute a, string fieldName, string chain |
    inPretalxPackage(a) and
    requestFieldAttr(a, fieldName) and
    chain = dottedName(a) and
    node = a and
    nodeRepr = "attribute access " + chain and
    callableName = fieldName and
    flowKind = requestFieldFlowKind(fieldName) and
    receiver = chain and
    moduleHint = "django.http" and
    argIndex = -1 and
    context = requestFieldContext(fieldName)
  )
  or
  /* Family 3: subscripts on request fields and route-kwarg mappings,
     e.g. request.GET["q"], self.kwargs["version"], request.META["..."]. */
  exists(Subscript s, Attribute a, string chain |
    inPretalxPackage(s) and
    s.getValue() = a and
    (
      requestFieldAttr(a, callableName)
      or
      kwargsAttr(a) and callableName = "kwargs"
    ) and
    (
      chain = dottedName(a)
      or
      not exists(string d | d = dottedName(a)) and chain = a.toString()
    ) and
    node = s and
    nodeRepr = "subscript of " + chain and
    (
      kwargsAttr(a) and
      flowKind = "route_kwarg" and
      receiver = "kwargs" and
      moduleHint = "django.urls" and
      context = "class-based view route variable read from self.kwargs/url.kwargs/resolver_match.kwargs (URL converter value, e.g. code/slug/version)"
      or
      exists(string reqField | requestFieldAttr(a, reqField)) and
      flowKind = requestFieldFlowKind(callableName) and
      receiver = "request" and
      moduleHint = "django.http" and
      context = "request field subscript read: " + requestFieldContext(callableName)
    ) and
    argIndex = -1
  )
  or
  /* Family 4: .get()/.getlist() lookups on request fields and route kwargs,
     e.g. request.GET.get("lang"), self.request.GET.getlist(key),
     url.kwargs.get("name"). */
  exists(Call c, Attribute obj, string methodName, string chain |
    inPretalxPackage(c) and
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = methodName and
    methodName in ["get", "getlist"] and
    c.getFunc().(Attribute).getObject() = obj and
    (
      requestFieldAttr(obj, callableName)
      or
      kwargsAttr(obj) and callableName = "kwargs"
    ) and
    (
      chain = dottedName(obj)
      or
      not exists(string d | d = dottedName(obj)) and chain = obj.toString()
    ) and
    node = c and
    nodeRepr = "field access " + chain + "." + methodName and
    (
      kwargsAttr(obj) and
      flowKind = "route_kwarg_get" and
      receiver = "kwargs" and
      moduleHint = "django.urls" and
      context = "route kwarg lookup via url.kwargs.get()/self.kwargs.get() (URL converter value)"
      or
      exists(string reqField2 | requestFieldAttr(obj, reqField2)) and
      flowKind = requestFieldFlowKind(callableName) and
      receiver = "request" and
      moduleHint = "django.http" and
      context = "request field lookup: " + requestFieldContext(callableName)
    ) and
    argIndex = -1
  )
  or
  /* Family 5: form value container reads (second-order, request-derived):
     self.cleaned_data["import_file"], self.files["custom_css"] and
     .get() variants. Form validation constrains shape, not path semantics. */
  exists(Subscript s, Attribute a, string containerName |
    inPretalxPackage(s) and
    s.getValue() = a and
    formValueAttr(a, containerName) and
    node = s and
    nodeRepr = "subscript of " + containerName and
    callableName = containerName and
    flowKind = "form_" + containerName and
    receiver = "form" and
    moduleHint = "django.forms" and
    argIndex = -1 and
    context = "form-validated value derived from request POST/FILES (second-order source); e.g. uploaded import files and custom_css reach file handling via cleaned_data/files"
  )
  or
  exists(Call c, Attribute a, string containerName |
    inPretalxPackage(c) and
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "get" and
    c.getFunc().(Attribute).getObject() = a and
    formValueAttr(a, containerName) and
    node = c and
    nodeRepr = "field access " + containerName + ".get" and
    callableName = containerName and
    flowKind = "form_" + containerName and
    receiver = "form" and
    moduleHint = "django.forms" and
    argIndex = -1 and
    context = "form-validated value derived from request POST/FILES (second-order source), read via cleaned_data.get()/files.get()"
  )
  or
  /* Family 6: cfp wizard session data (second-order: previously submitted
     form data and upload tmp_names stored server-side). */
  exists(Call c |
    inPretalxPackage(c) and
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "get" and
    c.getFunc().(Attribute).getObject() instanceof Attribute and
    c.getFunc().(Attribute).getObject().(Attribute).getName() = "cfp_session" and
    node = c and
    nodeRepr = "field access cfp_session.get" and
    callableName = "cfp_session.get" and
    flowKind = "session_data" and
    receiver = "cfp_session" and
    moduleHint = "pretalx.cfp.flow" and
    argIndex = -1 and
    context = "server-side cfp wizard session data; the stored files dict carries upload tmp_names consumed by file_storage.open(tmp_name)"
  )
  or
  /* Family 7: environment-configuration reads. These are deployment
     operator boundaries, not attacker input in standard pretalx
     deployments; extracted as boundary candidates with this caveat. */
  exists(Call c, string dotted |
    inPretalxPackage(c) and
    (
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "getenv" and
      dotted = "os.getenv"
      or
      c.getFunc() instanceof Attribute and
      dotted = dottedName(c.getFunc()) and
      dotted in ["os.environ.get", "os.getenv"]
    ) and
    node = c and
    nodeRepr = "call " + dotted and
    callableName = dotted and
    flowKind = "env_config" and
    receiver = "os" and
    moduleHint = "os" and
    argIndex = 0 and
    (
      exists(c.getPositionalArg(0)) and
      context = "environment variable read (operator/deployment configuration, NOT attacker-controlled input in standard deployments); PRETALX_DATA_DIR/PRETALX_CONFIG_FILE influence data directory and config file paths"
      or
      not exists(c.getPositionalArg(0)) and
      context = "environment variable read via keyword-controlled variable name (operator/deployment configuration, not attacker-controlled)"
    )
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
  inPretalxPackage(node) and
  filePath = relPath(node) and
  line = node.getLocation().getStartLine()
select nodeRepr, role, callableName, flowKind, receiver, moduleHint, argIndex, filePath, line, context
