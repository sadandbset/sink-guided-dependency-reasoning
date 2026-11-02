/**
 * @name gradio Pass 1 source candidates (Path Traversal)
 * @description Extracts untrusted-input source candidates for CWE-22/23/36/73 from
 *   the gradio 2.5.0 Flask application: Flask route path variables, request object
 *   field reads, and internal boundary receiver parameters that directly carry
 *   request-derived data. Evidence-derived from gradio/networking.py,
 *   gradio/interface.py, gradio/inputs.py, gradio/queue.py and
 *   gradio/processing_utils.py.
 *   Multi-column candidate table intended for `codeql query run` followed by
 *   `codeql bqrs decode --format=csv`. This query deliberately has NO @kind
 *   annotation: a @kind problem select shape cannot carry the multi-column
 *   extraction contract, and no @kind table is assumed.
 * @id iris/gradio-cwe22/extract-sources
 */

import python

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/**
 * Gets the dotted name of a simple name/attribute chain,
 * e.g. "os.path.join" or "request.form". Yields no result for
 * expressions whose object part is not a simple name/attribute chain.
 */
private string dottedName(Expr e) {
  result = e.(Name).getId()
  or
  result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
}

/**
 * Gets the repository-relative path of the file containing this node,
 * e.g. "gradio/networking.py". The primary source is File.getRelativePath();
 * on this Windows-created database the stored source location prefix uses
 * backslashes while file paths are forward-slash normalized, so
 * getRelativePath() may have no result - in that case fall back to capturing
 * the "gradio/..." suffix from the absolute path (verified forward-slash
 * format in the database string pool).
 */
private string relPath(AstNode n) {
  result = n.getLocation().getFile().getRelativePath()
  or
  not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
  result = n.getLocation().getFile().getAbsolutePath().regexpCapture(".*/(gradio/.+)$", 1)
}

/** Derives a module hint such as "gradio.networking" from the file path. */
private string moduleHintOf(AstNode n) {
  result = relPath(n).replaceAll(".py", "").replaceAll("/", ".")
}

/**
 * Restricts candidates to the gradio package itself. This structurally
 * excludes the nested gradio-db CodeQL database directory (gradio-db/...)
 * as well as test/ and demo/ files, which are noise per the Augur policy.
 */
private predicate inGradioPackage(AstNode n) {
  relPath(n).matches("gradio/%")
}

/** Flask route registration decorator, e.g. @app.route("/file/<path:path>"). */
private predicate isRouteDecorator(Expr dec) {
  dec instanceof Call and
  dottedName(dec.(Call).getFunc()).matches("%.route")
}

/**
 * Flask request object expressions whose reads are untrusted HTTP input.
 * Only "request.*" chains are accepted, so unrelated local variables
 * named "request" elsewhere cannot match unless they shadow the flask import.
 */
private predicate isRequestObjectExpr(Expr e) {
  dottedName(e) = "request.json" or
  dottedName(e) = "request.form" or
  dottedName(e) = "request.args" or
  dottedName(e) = "request.values" or
  dottedName(e) = "request.headers" or
  dottedName(e) = "request.cookies" or
  dottedName(e) = "request.data" or
  dottedName(e) = "request.files"
}

/** Gets the enclosing class name for methods, or "" for plain functions. */
private string receiverOf(Function f) {
  f.isMethod() and result = f.getEnclosingScope().(Class).getName()
  or
  not f.isMethod() and result = ""
}

/**
 * Handler/boundary functions whose named parameters directly receive
 * request-derived data in this codebase, together with a per-family context.
 */
private predicate isBoundaryReceiver(Function f, string paramName, string context) {
  (
    f.getName() = "process" and f.isMethod() and paramName = "raw_input" and
    context = "Interface.process: raw /api/predict request JSON 'data' list dispatched to component preprocess"
  )
  or
  (
    f.getName() = "interpret" and f.isMethod() and paramName = "raw_input" and
    context = "Interface.interpret: raw /api/interpret request JSON 'data' list"
  )
  or
  (
    f.getName() = "flag_data" and not f.isMethod() and
    paramName in ["input_data", "output_data", "flag_option", "flag_index"] and
    context = "flag_data: request JSON data persisted into the flagging CSV log"
  )
  or
  (
    f.getName() = "preprocess" and f.isMethod() and paramName = "x" and
    context = "component preprocess: raw request JSON payload for this input component"
  )
  or
  (
    f.getName() = "process_single_file" and paramName = "f" and
    context = "nested File.preprocess helper: per-file request JSON dict with client-supplied 'name'/'data' and client-settable 'is_example'"
  )
  or
  (
    f.getName() = "save_flagged" and f.isMethod() and paramName = "data" and
    context = "component save_flagged: flagged request data persisted under the flagging dir"
  )
  or
  (
    f.getName() = "save_flagged_file" and f.isMethod() and paramName = "data" and
    context = "component save_flagged_file: decoded flagged request data written to disk"
  )
  or
  (
    f.getName() = "restore_flagged" and f.isMethod() and paramName = "data" and
    context = "component restore_flagged: flag log.csv content (second-order file-derived data)"
  )
  or
  (
    f.getName() = "push" and not f.isMethod() and moduleHintOf(f) = "gradio.queue" and
    paramName in ["input_data", "action"] and
    context = "queue.push: request JSON data entering the job queue (consumed again by queue_thread)"
  )
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
  /* Family 1: Flask route handler parameters (URL-derived variables,
     including <path:path> converter variables such as /file/<path:path>). */
  exists(Function f, Parameter p, int i |
    isRouteDecorator(f.getADecorator()) and
    f.getArg(i) = p and
    node = p.asName() and
    inGradioPackage(f) and
    nodeRepr = "parameter '" + p.asName().getId() + "' of route handler " + f.getName() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = i and
    context = "Flask route handler parameter (URL-derived; includes <path:path> converter variables)"
  )
  or
  /* Family 2: request object field reads via subscript, e.g. request.json["data"]. */
  exists(Subscript s |
    node = s and
    inGradioPackage(s) and
    isRequestObjectExpr(s.getValue()) and
    nodeRepr = "subscript of " + dottedName(s.getValue()) and
    callableName = dottedName(s.getValue()) and
    flowKind = "field" and
    receiver = "request" and
    moduleHint = "flask" and
    argIndex = -1 and
    context = "Flask request object field read via subscript (HTTP request body/query/form data)"
  )
  or
  /* Family 3: request object field reads via .get(), e.g. request.form.get("username"). */
  exists(Call c |
    node = c and
    inGradioPackage(c) and
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "get" and
    isRequestObjectExpr(c.getFunc().(Attribute).getObject()) and
    nodeRepr = "field access " + dottedName(c.getFunc()) and
    callableName = dottedName(c.getFunc()) and
    flowKind = "field" and
    receiver = "request" and
    moduleHint = "flask" and
    argIndex = -1 and
    context = "Flask request object field read via .get() (HTTP request data)"
  )
  or
  /* Family 4: whole-body request accessors, e.g. request.get_json(). */
  exists(Call c |
    node = c and
    inGradioPackage(c) and
    (
      dottedName(c.getFunc()) = "request.get_json"
      or dottedName(c.getFunc()) = "request.get_data"
    ) and
    nodeRepr = "call " + dottedName(c.getFunc()) and
    callableName = dottedName(c.getFunc()) and
    flowKind = "field" and
    receiver = "request" and
    moduleHint = "flask" and
    argIndex = -1 and
    context = "Flask whole-body request accessor (parsed request JSON or raw body)"
  )
  or
  /* Family 5: internal boundary receiver parameters that directly carry
     request-derived data (component preprocess / flagging / queue push). */
  exists(Function f, Parameter p, string paramName, string familyContext |
    isBoundaryReceiver(f, paramName, familyContext) and
    p = f.getArgByName(paramName) and
    f.getArg(argIndex) = p and
    node = p.asName() and
    inGradioPackage(f) and
    nodeRepr = "parameter '" + paramName + "' of " + f.getName() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    context = familyContext
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
  inGradioPackage(node) and
  filePath = relPath(node) and
  line = node.getLocation().getStartLine()
select nodeRepr, role, callableName, flowKind, receiver, moduleHint, argIndex, filePath, line, context
