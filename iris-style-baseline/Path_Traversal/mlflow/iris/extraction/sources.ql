/**
 * @name mlflow Pass 1 source candidates (Path Traversal)
 * @description Extracts untrusted-input source candidates for CWE-22/23/36/73 from
 *   the mlflow 2.0.0.dev0 Flask tracking/artifacts server: Flask route parameters
 *   (including <path:...> converter variables), the three proto-registered
 *   /mlflow-artifacts/artifacts/<path:artifact_path> handler parameters, query-string
 *   parsed dict field reads, request.query_string / flask_request.get_json boundary
 *   reads, parsed proto request-message path fields, second-order run.info.artifact_uri
 *   reads, and internal boundary parameters that directly carry request-derived paths.
 *   Evidence-derived from mlflow/server/handlers.py, mlflow/server/__init__.py,
 *   mlflow/protos/mlflow_artifacts.proto, mlflow/store/artifact/local_artifact_repo.py
 *   and mlflow/store/artifact/artifact_repo.py.
 *   Multi-column candidate table intended for `codeql query run` followed by
 *   `codeql bqrs decode --format=csv`. This query deliberately has NO @kind
 *   annotation: a @kind problem select shape cannot carry the multi-column
 *   extraction contract, and no @kind table is assumed.
 * @id iris/mlflow-cwe22/extract-sources
 */

import python

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/**
 * Gets the dotted name of a simple name/attribute chain,
 * e.g. "request.query_string" or "run.info.artifact_uri". Yields no result
 * for expressions whose object part is not a simple name/attribute chain.
 */
private string dottedName(Expr e) {
  result = e.(Name).getId()
  or
  result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
}

/**
 * Gets the repository-relative path of the file containing this node,
 * e.g. "mlflow/server/handlers.py". The primary source is File.getRelativePath();
 * on this Windows-created database the stored source location prefix uses
 * backslashes while file paths are forward-slash normalized, so
 * getRelativePath() may have no result - in that case fall back to capturing
 * the "mlflow/..." suffix from the absolute path (verified forward-slash
 * format in the database string pool).
 */
private string relPath(AstNode n) {
  result = n.getLocation().getFile().getRelativePath()
  or
  not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
  result = n.getLocation().getFile().getAbsolutePath().regexpCapture(".*/(mlflow/.+)$", 1)
}

/** Derives a module hint such as "mlflow.server.handlers" from the file path. */
private string moduleHintOf(AstNode n) {
  result = relPath(n).replaceAll(".py", "").replaceAll("/", ".")
}

/**
 * Restricts candidates to the mlflow Python package itself. This structurally
 * excludes the nested mlflow-db CodeQL database directory (mlflow-db/...), the
 * mlflow_vuln ground-truth directory, tests/ and examples/ files, and the
 * generated mlflow/protos/ code, which are noise per the Augur policy.
 */
private predicate inMlflowPackage(AstNode n) {
  relPath(n).matches("mlflow/%") and
  not relPath(n).matches("mlflow/protos/%")
}

/** Flask route registration decorator, e.g. @app.route("/static-files/<path:path>"). */
private predicate isRouteDecorator(Expr dec) {
  dec instanceof Call and
  dottedName(dec.(Call).getFunc()).matches("%.route")
}

/**
 * Holds if expression `e` appears lexically inside a function named `fname`
 * (directly or through nested scopes such as comprehensions or lambdas).
 * `e.getScope+() = f` is the enclosing-scope-chain idiom used by the Python
 * standard library itself (e.g. semmle/python/dataflow/.../VariableCapture.qll).
 */
private predicate inFunctionNamed(Expr e, string fname) {
  exists(Function f |
    f.getName() = fname and
    e.getScope+() = f
  )
}

/** Gets the enclosing class name for methods, or "" for plain functions. */
private string receiverOf(Function f) {
  f.isMethod() and result = f.getEnclosingScope().(Class).getName()
  or
  not f.isMethod() and result = ""
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
  /* Family 1: Flask @app.route handler parameters. In this codebase only
     serve_static_file has a parameter, bound to the URL rule
     /static-files/<path:path> (mlflow/server/__init__.py:65-67). */
  exists(Function f, Parameter p, int i |
    isRouteDecorator(f.getADecorator()) and
    f.getArg(i) = p and
    node = p.asName() and
    inMlflowPackage(f) and
    nodeRepr = "parameter '" + p.asName().getId() + "' of route handler " + f.getName() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = i and
    context = "Flask @app.route handler parameter (URL-derived; <path:path> converter variable feeding send_from_directory)"
  )
  or
  /* Family 2: proto-registered handler parameters bound to the URL rules
     /mlflow-artifacts/artifacts/<path:artifact_path> (GET/PUT/DELETE), which
     mlflow/server/__init__.py:33-34 registers via app.add_url_rule from
     mlflow/protos/mlflow_artifacts.proto. These are Flask path-converter
     route variables even though the handlers carry no @app.route decorator. */
  exists(Function f, Parameter p, string paramName |
    f.getName() = "_download_artifact" and
    moduleHintOf(f) = "mlflow.server.handlers" and
    p = f.getArgByName(paramName) and
    paramName = "artifact_path" and
    f.getArg(argIndex) = p and
    node = p.asName() and
    inMlflowPackage(f) and
    nodeRepr = "parameter 'artifact_path' of " + f.getName() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    context = "URL path-converter variable <path:artifact_path> of /mlflow-artifacts/artifacts/<path:artifact_path> GET; flows to download_artifacts and open(dst, 'rb')"
  )
  or
  exists(Function f, Parameter p, string paramName |
    f.getName() = "_upload_artifact" and
    moduleHintOf(f) = "mlflow.server.handlers" and
    p = f.getArgByName(paramName) and
    paramName = "artifact_path" and
    f.getArg(argIndex) = p and
    node = p.asName() and
    inMlflowPackage(f) and
    nodeRepr = "parameter 'artifact_path' of " + f.getName() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    context = "URL path-converter variable <path:artifact_path> of /mlflow-artifacts/artifacts/<path:artifact_path> PUT; posixpath.split -> os.path.join(tmp_dir, tail) -> open(tmp_path, 'wb') and log_artifact"
  )
  or
  exists(Function f, Parameter p, string paramName |
    f.getName() = "_delete_artifact_mflflow_artifacts" and
    moduleHintOf(f) = "mlflow.server.handlers" and
    p = f.getArgByName(paramName) and
    paramName = "artifact_path" and
    f.getArg(argIndex) = p and
    node = p.asName() and
    inMlflowPackage(f) and
    nodeRepr = "parameter 'artifact_path' of " + f.getName() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    context = "URL path-converter variable <path:artifact_path> of /mlflow-artifacts/artifacts/<path:artifact_path> DELETE; flows to artifact_repo.delete_artifacts -> shutil.rmtree"
  )
  or
  /* Family 3: query-string-parsed dict field reads inside the two get-artifact
     handlers. request_dict comes from querystring_parser.parser.parse over
     request.query_string, so these fields are the raw untrusted query values. */
  exists(Subscript s, string fname |
    node = s and
    inMlflowPackage(s) and
    inFunctionNamed(s, fname) and
    fname in ["get_artifact_handler", "get_model_version_artifact_handler"] and
    s.getObject() instanceof Name and
    s.getObject().(Name).getId() = "request_dict" and
    nodeRepr = "subscript of request_dict (query-string parsed dict) in " + fname and
    callableName = "request_dict[...]" and
    flowKind = "field" and
    receiver = "request_dict" and
    moduleHint = moduleHintOf(s) and
    argIndex = -1 and
    context = "query-string parsed dict field read ('path' key) carrying the requested artifact path; derived from request.query_string via querystring_parser.parser.parse"
  )
  or
  exists(Call c, string fname, string key |
    node = c and
    inMlflowPackage(c) and
    inFunctionNamed(c, fname) and
    fname in ["get_artifact_handler", "get_model_version_artifact_handler"] and
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "get" and
    c.getFunc().(Attribute).getObject() instanceof Name and
    c.getFunc().(Attribute).getObject().(Name).getId() = "request_dict" and
    c.getPositionalArg(0) instanceof StringLiteral and
    key = c.getPositionalArg(0).(StringLiteral).getText() and
    key in ["run_id", "run_uuid", "name", "version"] and
    nodeRepr = "field access request_dict.get(\"" + key + "\") in " + fname and
    callableName = "request_dict.get" and
    flowKind = "field" and
    receiver = "request_dict" and
    moduleHint = moduleHintOf(c) and
    argIndex = -1 and
    context = "query-string parsed dict field read (lookup key '" + key + "' for artifact or model-version location resolution)"
  )
  or
  /* Family 4: raw request.query_string / flask_request.query_string reads. */
  exists(Attribute a |
    node = a and
    inMlflowPackage(a) and
    dottedName(a) in ["request.query_string", "flask_request.query_string"] and
    nodeRepr = "attribute read " + dottedName(a) and
    callableName = dottedName(a) and
    flowKind = "field" and
    receiver = "request" and
    moduleHint = "flask" and
    argIndex = -1 and
    context = "Flask request.query_string read (raw untrusted URL query string; parsed by querystring_parser into request_dict)"
  )
  or
  /* Family 5: whole-body JSON accessor, e.g. flask_request.get_json(...). */
  exists(Call c |
    node = c and
    inMlflowPackage(c) and
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = "get_json" and
    c.getFunc().(Attribute).getObject() instanceof Name and
    c.getFunc().(Attribute).getObject().(Name).getId() in ["request", "flask_request"] and
    nodeRepr = "call " + dottedName(c.getFunc()) and
    callableName = dottedName(c.getFunc()) and
    flowKind = "field" and
    receiver = "request" and
    moduleHint = "flask" and
    argIndex = -1 and
    context = "Flask whole-body request JSON accessor (parsed request body feeding proto request messages and schema validation)"
  )
  or
  /* Family 6: parsed proto request-message path field reads in the two
     artifact listing handlers (request body/query deserialized via parse_dict). */
  exists(Attribute a, string fname |
    node = a and
    inMlflowPackage(a) and
    inFunctionNamed(a, fname) and
    fname in ["_list_artifacts", "_list_artifacts_mlflow_artifacts"] and
    a.getName() = "path" and
    a.getObject() instanceof Name and
    a.getObject().(Name).getId() = "request_message" and
    nodeRepr = "field read request_message.path in " + fname and
    callableName = "request_message.path" and
    flowKind = "field" and
    receiver = "request_message" and
    moduleHint = moduleHintOf(a) and
    argIndex = -1 and
    context = "parsed proto request-message 'path' field (request JSON/query body) listing artifacts under an attacker-controlled sub-path"
  )
  or
  /* Family 7: second-order run.info.artifact_uri reads. The artifact root was
     stored via the CreateExperiment API (artifact_location request field) and
     is read back here to construct the artifact repository root. */
  exists(Attribute a |
    node = a and
    inMlflowPackage(a) and
    dottedName(a) = "run.info.artifact_uri" and
    nodeRepr = "attribute read run.info.artifact_uri" and
    callableName = "run.info.artifact_uri" and
    flowKind = "field" and
    receiver = "run.info" and
    moduleHint = moduleHintOf(a) and
    argIndex = -1 and
    context = "second-order stored run artifact URI (experiment artifact_location supplied through the CreateExperiment API) used to resolve the artifact repository root"
  )
  or
  /* Family 8: internal boundary parameters that directly carry request-derived
     paths (summary-step candidates for taint modeling; the LLM labeling step
     may classify these as summary rather than source). */
  exists(Function f, Parameter p, string paramName, string familyContext |
    internalBoundaryParam(f, paramName, familyContext) and
    p = f.getArgByName(paramName) and
    f.getArg(argIndex) = p and
    node = p.asName() and
    inMlflowPackage(f) and
    nodeRepr = "parameter '" + paramName + "' of " + f.getName() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    context = familyContext
  )
}

/**
 * Internal boundary functions whose named parameters directly carry
 * request-derived path data in this codebase, together with a per-family
 * context. Arg indexes include `self` for methods.
 */
private predicate internalBoundaryParam(Function f, string paramName, string context) {
  (
    f.getName() = "_send_artifact" and
    moduleHintOf(f) = "mlflow.server.handlers" and
    not f.isMethod() and
    paramName = "path" and
    context = "_send_artifact.path: request-derived artifact path passed to artifact_repository.download_artifacts, then os.path.abspath and send_file"
  )
  or
  (
    f.getName() = "_get_proxied_run_artifact_destination_path" and
    moduleHintOf(f) = "mlflow.server.handlers" and
    not f.isMethod() and
    paramName = "relative_path" and
    context = "_get_proxied_run_artifact_destination_path.relative_path: request 'path' field joined (posixpath.join) onto the proxied artifact root"
  )
  or
  (
    f.getName() = "_list_artifacts_for_proxied_run_artifact_root" and
    moduleHintOf(f) = "mlflow.server.handlers" and
    not f.isMethod() and
    paramName = "relative_path" and
    context = "_list_artifacts_for_proxied_run_artifact_root.relative_path: ListArtifacts request 'path' field used for proxied artifact listing"
  )
  or
  (
    f.getName() = "log_artifact" and
    f.isMethod() and
    f.getEnclosingScope().(Class).getName() = "ArtifactRepository" and
    moduleHintOf(f) = "mlflow.store.artifact.artifact_repo" and
    paramName = "artifact_path" and
    context = "ArtifactRepository.log_artifact.artifact_path: base-class dispatch of request-derived upload destination path"
  )
  or
  (
    f.getName() = "log_artifacts" and
    f.isMethod() and
    f.getEnclosingScope().(Class).getName() = "ArtifactRepository" and
    moduleHintOf(f) = "mlflow.store.artifact.artifact_repo" and
    paramName = "artifact_path" and
    context = "ArtifactRepository.log_artifacts.artifact_path: base-class dispatch of request-derived upload destination path"
  )
  or
  (
    f.getName() = "download_artifacts" and
    f.isMethod() and
    f.getEnclosingScope().(Class).getName() = "ArtifactRepository" and
    moduleHintOf(f) = "mlflow.store.artifact.artifact_repo" and
    paramName = "artifact_path" and
    context = "ArtifactRepository.download_artifacts.artifact_path: base-class dispatch of request-derived download path (os.makedirs + _download_file)"
  )
  or
  (
    f.getName() = "_create_download_destination" and
    f.isMethod() and
    f.getEnclosingScope().(Class).getName() = "ArtifactRepository" and
    moduleHintOf(f) = "mlflow.store.artifact.artifact_repo" and
    paramName = "src_artifact_path" and
    context = "ArtifactRepository._create_download_destination.src_artifact_path: request-derived artifact path joined (posixpath.dirname + os.path.join) onto the local destination dir, then os.makedirs"
  )
  or
  (
    f.getName() = "log_artifact" and
    f.isMethod() and
    f.getEnclosingScope().(Class).getName() = "LocalArtifactRepository" and
    moduleHintOf(f) = "mlflow.store.artifact.local_artifact_repo" and
    paramName = "artifact_path" and
    context = "LocalArtifactRepository.log_artifact.artifact_path: request-derived upload destination; verify_artifact_path guard then os.path.join(artifact_dir, ...) + shutil.copyfile"
  )
  or
  (
    f.getName() = "download_artifacts" and
    f.isMethod() and
    f.getEnclosingScope().(Class).getName() = "LocalArtifactRepository" and
    moduleHintOf(f) = "mlflow.store.artifact.local_artifact_repo" and
    paramName = "artifact_path" and
    context = "LocalArtifactRepository.download_artifacts.artifact_path: request-derived path joined onto the local artifact dir (os.path.normpath only, no '..' containment) and returned to send_file/open"
  )
  or
  (
    f.getName() = "list_artifacts" and
    f.isMethod() and
    f.getEnclosingScope().(Class).getName() = "LocalArtifactRepository" and
    moduleHintOf(f) = "mlflow.store.artifact.local_artifact_repo" and
    paramName = "path" and
    context = "LocalArtifactRepository.list_artifacts.path: request-derived listing sub-path joined onto the local artifact dir (os.path.normpath only) for os.path.isdir + list_all"
  )
  or
  (
    f.getName() = "delete_artifacts" and
    f.isMethod() and
    f.getEnclosingScope().(Class).getName() = "LocalArtifactRepository" and
    moduleHintOf(f) = "mlflow.store.artifact.local_artifact_repo" and
    paramName = "artifact_path" and
    context = "LocalArtifactRepository.delete_artifacts.artifact_path: request-derived path joined onto the local artifact dir with NO normalization and NO verify_artifact_path, then shutil.rmtree"
  )
  or
  (
    f.getName() = "_download_file" and
    f.isMethod() and
    f.getEnclosingScope().(Class).getName() = "LocalArtifactRepository" and
    moduleHintOf(f) = "mlflow.store.artifact.local_artifact_repo" and
    paramName = "remote_file_path" and
    context = "LocalArtifactRepository._download_file.remote_file_path: request-derived artifact path joined onto the local artifact dir, then shutil.copyfile"
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
  inMlflowPackage(node) and
  filePath = relPath(node) and
  line = node.getLocation().getStartLine()
select nodeRepr, role, callableName, flowKind, receiver, moduleHint, argIndex, filePath, line, context
