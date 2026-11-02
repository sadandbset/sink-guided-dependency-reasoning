/**
 * @name mindsdb Pass 1 source candidates (Path Traversal)
 * @description Extracts untrusted-input source candidates for CWE-22/23/36/73 from
 *   the mindsdb 23.2.2.1 Flask/flask-restx server: Flask route path variables
 *   (plain @app.route functions and flask_restx Resource classes), flask request
 *   object field reads (json/args/form/files/headers/stream, via attribute,
 *   subscript and .get()), python-multipart upload callback parameters and their
 *   client-controlled filename field reads, the raw SQL boundary
 *   (MysqlProxy.process_query reached from POST /api/sql/query, POST
 *   /api/analysis/query and the MySQL wire server, plus the mongo
 *   run_sql_command AST boundary), and internal boundary receiver parameters
 *   that directly carry request-derived data. Evidence-derived from
 *   mindsdb/api/http/namespaces/{file,handlers,config,start}.py,
 *   mindsdb/interfaces/file/file_controller.py,
 *   mindsdb/integrations/handlers/file_handler/file_handler.py,
 *   mindsdb/interfaces/storage/fs.py,
 *   mindsdb/interfaces/database/integrations.py and
 *   mindsdb/api/mysql/mysql_proxy/mysql_proxy.py.
 *   Multi-column candidate table intended for `codeql query run` followed by
 *   `codeql bqrs decode --format=csv`. This query deliberately has NO @kind
 *   annotation: a @kind problem select shape cannot carry the multi-column
 *   extraction contract, and no @kind table is assumed.
 * @id iris/mindsdb-cwe22/extract-sources
 */

import python

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/**
 * Gets the dotted name of a simple name/attribute chain,
 * e.g. "os.path.join" or "request.json". Yields no result for
 * expressions whose object part is not a simple name/attribute chain.
 */
private string dottedName(Expr e) {
  result = e.(Name).getId()
  or
  result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
}

/** Gets the repository-relative path of the file containing this node. */
private string relPath(AstNode n) {
  result = n.getLocation().getFile().getRelativePath()
}

/** Derives a module hint such as "mindsdb.api.http.namespaces.file" from the file path. */
private string moduleHintOf(AstNode n) {
  result = relPath(n).replaceAll(".py", "").replaceAll("/", ".")
}

/**
 * Restricts candidates to the mindsdb package itself. This structurally
 * excludes the nested mindsdb-db CodeQL database directory (mindsdb-db/...),
 * the top-level tests/ directory, and handler-level tests/ and setup.py
 * files, which are noise per the Augur policy.
 */
private predicate inMindsdbPackage(AstNode n) {
  relPath(n).matches("mindsdb/%") and
  not relPath(n).matches("%/tests/%") and
  not relPath(n).matches("%setup.py")
}

/**
 * Route registration decorator, e.g. @ns_conf.route('/<name>') on a
 * flask_restx Resource class or @app.route('/<path:path>') on a plain
 * function. getADecorator() returns the decorator callee expression
 * (for example the attribute "ns_conf.route"), so the dotted name of the
 * decorator itself is matched.
 */
private predicate isRouteDecorator(Expr dec) {
  exists(string d |
    d = dottedName(dec) and
    d.matches("%.route")
  )
}

/**
 * Flask request object expressions whose reads are untrusted HTTP input.
 * Only "request.*" chains are accepted, so unrelated local variables
 * named "request" elsewhere cannot match unless they shadow the flask
 * import (FakeMysqlProxy in this codebase assigns a Dummy object to a
 * local "request" but never reads request.* fields on it).
 */
private predicate isRequestObjectExpr(Expr e) {
  dottedName(e) = "request.json" or
  dottedName(e) = "request.form" or
  dottedName(e) = "request.args" or
  dottedName(e) = "request.values" or
  dottedName(e) = "request.headers" or
  dottedName(e) = "request.cookies" or
  dottedName(e) = "request.data" or
  dottedName(e) = "request.files" or
  dottedName(e) = "request.stream"
}

/** Gets the enclosing class name for methods, or "" for plain functions. */
private string receiverOf(Function f) {
  f.isMethod() and result = f.getEnclosingScope().(Class).getName()
  or
  not f.isMethod() and result = ""
}

/**
 * Multipart callback attribute reads: python-multipart on_file(file) /
 * on_field(field) callbacks expose file.file_name / file.file_object /
 * field.field_name / field.value; the werkzeug upload loop in the config
 * namespace exposes file.filename. Restricted to the HTTP namespace
 * modules where these upload objects are observed.
 */
private predicate isUploadObjectAttrRead(Attribute a) {
  a.getObject() instanceof Name and
  a.getObject().(Name).getId() in ["file", "field"] and
  a.getName() in ["filename", "file_name", "file_object", "field_name", "value"] and
  moduleHintOf(a).matches("mindsdb.api.http.namespaces.%")
}

/**
 * Handler/boundary functions whose named parameters directly receive
 * request-derived or SQL-derived data in this codebase, together with a
 * per-family context. The positional index is resolved from the actual
 * parameter list at the binding site (self occupies index 0 for methods).
 */
private predicate isBoundaryReceiver(Function f, string paramName, string context) {
  (
    f.getName() = "save_file" and f.isMethod() and
    moduleHintOf(f) = "mindsdb.interfaces.file.file_controller" and
    paramName in ["name", "file_path", "file_name"] and
    context = "FileController.save_file: name is the /api/files/<name> route variable, file_path is os.path.join(temp_dir_path, multipart client filename), file_name is the optional original_file_name form field; performs _handle_source + shutil.move"
  )
  or
  (
    f.getName() = "get_file_path" and f.isMethod() and
    moduleHintOf(f) = "mindsdb.interfaces.file.file_controller" and
    paramName = "name" and
    context = "FileController.get_file_path: file table name from SQL 'FROM file.<table>' selects; retrieval path applies Path(source_file_path).name"
  )
  or
  (
    f.getName() = "_handle_source" and f.isMethod() and
    moduleHintOf(f) = "mindsdb.integrations.handlers.file_handler.file_handler" and
    paramName = "file_path" and
    context = "FileHandler._handle_source: uploaded file path opened via _get_data_io -> open(file_path, 'rb'); called with the temp-dir join of the multipart client filename from the /api/files/<name> upload route"
  )
  or
  (
    f.getName() = "_get_data_io" and f.isMethod() and
    moduleHintOf(f) = "mindsdb.integrations.handlers.file_handler.file_handler" and
    paramName = "file_path" and
    context = "FileHandler._get_data_io: opens file_path with open(file_path, 'rb')"
  )
  or
  (
    f.getName() in ["file_set", "file_get", "get_path", "delete", "push_path", "pull_path"] and
    f.isMethod() and
    moduleHintOf(f) = "mindsdb.interfaces.storage.fs" and
    paramName in ["name", "relative_path", "path"] and
    context = "FileStorage method: name/relative_path is joined under folder_path and opened for read/write; the byom 'model_code' connection arg flows through file_get"
  )
  or
  (
    f.getName() = "add" and f.isMethod() and
    moduleHintOf(f) = "mindsdb.interfaces.database.integrations" and
    paramName = "connection_args" and
    context = "IntegrationController.add: connection args dict from SQL CREATE DATABASE ... PARAMETERS or HTTP PUT /api/config/integrations params; ARG_TYPE.PATH values are shutil.copy'd from the raw path and replaced with Path(arg_value).name"
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
  /* Family 1a: plain Flask route handler parameters, e.g. root_index(path)
     for @app.route('/<path:path>') in mindsdb/api/http/start.py. */
  exists(Function f, Parameter p, int i |
    isRouteDecorator(f.getADecorator()) and
    f.getArg(i) = p and
    node = p.asName() and
    inMindsdbPackage(f) and
    nodeRepr = "parameter '" + p.asName().getId() + "' of route handler " + f.getName() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = i and
    context = "Flask route handler parameter (URL-derived route variable, includes <path:path> converter variables)"
  )
  or
  /* Family 1b: flask_restx Resource method parameters: methods of classes
     decorated with @ns_conf.route('/...<var>...'), e.g. File.put(name) for
     /api/files/<name>. Index 0 (self) is skipped. */
  exists(Class cls, Function f, Parameter p, int i |
    isRouteDecorator(cls.getADecorator()) and
    f.getEnclosingScope() = cls and
    f.isMethod() and
    i > 0 and
    f.getArg(i) = p and
    node = p.asName() and
    inMindsdbPackage(f) and
    nodeRepr = "parameter '" + p.asName().getId() + "' of Resource method " + f.getName() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = i and
    context = "flask-restx Resource method parameter (URL-derived route variable on a @ns_conf.route class; index includes self)"
  )
  or
  /* Family 2: request object field reads via subscript, e.g.
     request.json['query'] or request.headers['Content-Type']. */
  exists(Subscript s |
    node = s and
    inMindsdbPackage(s) and
    isRequestObjectExpr(s.getValue()) and
    nodeRepr = "subscript of " + dottedName(s.getValue()) and
    callableName = dottedName(s.getValue()) and
    flowKind = "field" and
    receiver = "request" and
    moduleHint = "flask" and
    argIndex = -1 and
    context = "Flask request object field read via subscript (HTTP request body/query/form/header data)"
  )
  or
  /* Family 3: request object field reads via .get(), e.g.
     request.args.get('min_timestamp') or request.json.get('params'). */
  exists(Call c |
    node = c and
    inMindsdbPackage(c) and
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
  /* Family 4: bare request object reads, e.g. data = request.json or
     files = request.files or the request.stream object fed to the
     multipart parser. */
  exists(Attribute a |
    node = a and
    inMindsdbPackage(a) and
    isRequestObjectExpr(a) and
    nodeRepr = "request object read " + dottedName(a) and
    callableName = dottedName(a) and
    flowKind = "field" and
    receiver = "request" and
    moduleHint = "flask" and
    argIndex = -1 and
    context = "Flask request object read (parsed request JSON, form data, files mapping or raw request stream consumed by the python-multipart parser)"
  )
  or
  /* Family 5: python-multipart form parser callback parameters
     (on_file(file) / on_field(field)) in the files and byom upload
     routes. */
  exists(Function f, Parameter p |
    f.getName() in ["on_file", "on_field"] and
    moduleHintOf(f).matches("mindsdb.api.http.namespaces.%") and
    f.getArg(0) = p and
    node = p.asName() and
    inMindsdbPackage(f) and
    nodeRepr = "parameter '" + p.asName().getId() + "' of multipart callback " + f.getName() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = 0 and
    context = "python-multipart create_form_parser callback (UPLOAD_DIR=tempfile.mkdtemp, UPLOAD_KEEP_FILENAME=True): on_file receives the uploaded file object with the client-controlled file_name; on_field receives decoded form fields"
  )
  or
  /* Family 6: client-controlled filename field reads on multipart /
     werkzeug upload objects: file.file_name, file.file_object,
     field.field_name, field.value, file.filename. */
  exists(Attribute a |
    node = a and
    inMindsdbPackage(a) and
    isUploadObjectAttrRead(a) and
    nodeRepr = "attribute '" + a.getObject().(Name).getId() + "." + a.getName() + "' on upload object" and
    callableName = a.getName() and
    flowKind = "field" and
    receiver = a.getObject().(Name).getId() and
    moduleHint = moduleHintOf(a) and
    argIndex = -1 and
    context = "client-supplied upload filename or form field value (python-multipart file.file_name/field.value, werkzeug FileStorage file.filename); flows into os.path.join(temp_dir_path, data['file']) at the upload routes"
  )
  or
  /* Family 7: raw SQL text boundary. MysqlProxy.process_query(self, sql)
     is reached from request.json['query'] via FakeMysqlProxy
     (POST /api/sql/query, POST /api/analysis/query) and from the MySQL
     wire-protocol server; CREATE DATABASE ... PARAMETERS values flow into
     integration connection args. */
  exists(Function f, Parameter p |
    f.getName() = "process_query" and
    f.isMethod() and
    moduleHintOf(f) = "mindsdb.api.mysql.mysql_proxy.mysql_proxy" and
    f.getArgByName("sql") = p and
    f.getArg(1) = p and
    node = p.asName() and
    inMindsdbPackage(f) and
    nodeRepr = "parameter 'sql' of " + f.getName() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = 1 and
    context = "raw SQL text boundary: request.json['query'] via FakeMysqlProxy from POST /api/sql/query and /api/analysis/query, and the MySQL wire-protocol server; statement.parameters of CREATE DATABASE reach integration connection args (ARG_TYPE.PATH values)"
  )
  or
  /* Family 8: mongo wire-protocol boundary: commands are translated to
     SQL AST and executed via run_sql_command. */
  exists(Function f, Parameter p |
    f.getName() = "run_sql_command" and
    not f.isMethod() and
    moduleHintOf(f) = "mindsdb.api.mongo.classes.query_sql" and
    f.getArgByName("ast_query") = p and
    f.getArg(1) = p and
    node = p.asName() and
    inMindsdbPackage(f) and
    nodeRepr = "parameter 'ast_query' of " + f.getName() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = 1 and
    context = "mongo wire-protocol boundary: mongo commands parsed to SQL AST and executed via ExecuteCommands (reaches the same CREATE DATABASE / integration handlers)"
  )
  or
  /* Family 9: internal boundary receiver parameters that directly carry
     request-derived or SQL-derived data. */
  exists(Function f, Parameter p, string paramName, string familyContext, int i |
    isBoundaryReceiver(f, paramName, familyContext) and
    p = f.getArgByName(paramName) and
    f.getArg(i) = p and
    node = p.asName() and
    inMindsdbPackage(f) and
    nodeRepr = "parameter '" + paramName + "' of " + f.getName() and
    callableName = f.getName() and
    flowKind = "param" and
    receiver = receiverOf(f) and
    moduleHint = moduleHintOf(f) and
    argIndex = i and
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
  inMindsdbPackage(node) and
  filePath = relPath(node) and
  line = node.getLocation().getStartLine()
select nodeRepr, role, callableName, flowKind, receiver, moduleHint, argIndex, filePath, line, context
