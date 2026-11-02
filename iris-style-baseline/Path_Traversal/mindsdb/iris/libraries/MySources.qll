/**
 * Augur Pass 1 (Path Traversal) source library for the mindsdb project.
 *
 * Generated in Phase 2 Step 4 from the reviewed Pass 1 labels
 * (labels/labels.json, pass_id 1, pass key "path_traversal").
 *
 * Realized source labels (role = source):
 *   - S021, S022, S023, S024, S025, S028, S029, S031(file.py:70 -> S032),
 *     S033, S036, S042: Flask request reads on the public HTTP API
 *     (request.json / request.form / request.files / request.stream,
 *     including subscript and .get() access shapes), scoped to the reviewed
 *     route handlers only (File.put, BYOMUpload.put, Integration.put,
 *     Integration.post, Query.post, QueryAnalysis.post). request.args and
 *     request.headers reads that the review labeled `none` (log filters,
 *     Content-Type branch selectors, company-id/user-class headers) are
 *     deliberately NOT matched.
 *   - S048-S054: client-controlled upload object attributes
 *     (file.filename, file.file_name, field.field_name, field.value) in the
 *     same upload handlers. file.file_object (labeled none) is excluded.
 *   - S057-S060: python-multipart on_file/on_field callback parameters.
 *   - S061, S062: wire-protocol SQL boundaries (mongo run_sql_command AST,
 *     MysqlProxy.process_query SQL text) that receive SQL from external
 *     MySQL/Mongo clients.
 *   - S013: IntegrationController.add connection_args parameter, the
 *     reviewed boundary receiver where attacker SQL text (CREATE DATABASE
 *     ... PARAMETERS) and HTTP integration params become concrete
 *     ARG_TYPE.PATH values. Label evidence: integrations.py:60-69 copies
 *     these raw path values before any basename normalization.
 *
 * Deliberately NOT realized as isSource (per the Step 4 source policy: a
 * source must be a genuinely attacker-controlled external input node):
 *   - S002/S003 (FileController.save_file file_path/file_name parameters)
 *     and S005/S006 (FileHandler._handle_source/_get_data_io file_path
 *     parameters): these are internal propagation, not external inputs.
 *     They are realized as evidence-based call-site bridges in
 *     libraries/MySummaries.qll instead (file.py:129/149 -> save_file ->
 *     file_handler.py:75 -> :100 -> :158).
 *   - S004 (get_file_path name): labeled none; DB lookup key only.
 *   - S063-S090 (wrapper RPC request.json reads): labeled summary; see
 *     MySummaries.qll notes and report/query_generation_notes.md.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {

  /** Pass 1 source predicate. Only the "path_traversal" pass key is served. */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "path_traversal" and
    (
      flaskRequestSource(source)
      or
      multipartUploadSource(source)
      or
      boundaryParamSource(source)
    )
  }

  /* ------------------------------------------------------------------ */
  /* Shared helpers (idioms proven by the Step 2 extraction queries)     */
  /* ------------------------------------------------------------------ */

  /**
   * Gets the dotted name of a simple name/attribute chain,
   * e.g. "os.path.join" or "request.json".
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

  /**
   * Holds if `n` is syntactically inside function `funcName` in the file
   * whose relative path is `filePattern` (including nested closures such as
   * the python-multipart on_file/on_field callbacks defined inside the
   * upload put() handlers). All reviewed call sites pass exact relative
   * paths, so equality is used (it also binds the `filePattern` parameter,
   * which a bound-only `matches` pattern argument cannot).
   */
  private predicate inFunction(AstNode n, string funcName, string filePattern) {
    exists(Function f |
      f.getName() = funcName and
      relPath(f) = filePattern and
      relPath(n) = filePattern and
      (n.getScope() = f or n.getScope().getEnclosingScope*() = f)
    )
  }

  /* ------------------------------------------------------------------ */
  /* Flask request reads (labels S021-S036, S042)                        */
  /* ------------------------------------------------------------------ */

  /**
   * The reviewed request field families. request.args (log filter
   * parameters) and request.headers (Content-Type selectors,
   * company-id/user-class) were labeled `none` and are excluded.
   */
  private predicate requestFieldFamily(Expr e) {
    dottedName(e) = "request.json"
    or
    dottedName(e) = "request.form"
    or
    dottedName(e) = "request.files"
    or
    dottedName(e) = "request.stream"
  }

  /**
   * Matches a request field read in any of its observed shapes:
   * a bare attribute (`data = request.json`), a subscript
   * (`request.json['query']`) or a `.get()` call
   * (`request.json.get('context')`). Matching the most specific read node
   * avoids relying on container-taint propagation.
   */
  private predicate requestReadShape(Expr e) {
    requestFieldFamily(e)
    or
    e instanceof Subscript and requestFieldFamily(e.(Subscript).getValue())
    or
    e instanceof Call and
    e.(Call).getFunc() instanceof Attribute and
    e.(Call).getFunc().(Attribute).getName() = "get" and
    requestFieldFamily(e.(Call).getFunc().(Attribute).getObject())
  }

  /** Reviewed handler scopes carrying the labeled request-read sources. */
  private predicate reviewedRequestSite(Expr e) {
    // S033 (request.json), S031/S032 (request.stream): File.put, /api/files/<name>
    inFunction(e, "put", "mindsdb/api/http/namespaces/file.py")
    or
    // S029 (request.json), S028 (request.stream): BYOMUpload.put, /api/handlers/byom/<name>
    inFunction(e, "put", "mindsdb/api/http/namespaces/handlers.py")
    or
    // S021 (request.json), S022 (request.form), S023 (request.files): Integration.put
    inFunction(e, "put", "mindsdb/api/http/namespaces/config.py")
    or
    // S024 (request.json), S025 (request.form): Integration.post (modify flow)
    inFunction(e, "post", "mindsdb/api/http/namespaces/config.py")
    or
    // S036 (request.json['query']): Query.post, /api/sql/query
    inFunction(e, "post", "mindsdb/api/http/namespaces/sql.py")
    or
    // S042 (request.json): QueryAnalysis.post, /api/analysis/query
    inFunction(e, "post", "mindsdb/api/http/namespaces/analysis.py")
  }

  private predicate flaskRequestSource(DataFlow::Node source) {
    exists(Expr e |
      source.asExpr() = e and
      requestReadShape(e) and
      reviewedRequestSite(e)
    )
  }

  /* ------------------------------------------------------------------ */
  /* Upload object attributes (labels S048-S054)                         */
  /* ------------------------------------------------------------------ */

  /**
   * Client-controlled filename / form-value attributes on python-multipart
   * upload objects (file.file_name, field.field_name, field.value) and the
   * werkzeug FileStorage filename (file.filename). file.file_object
   * (content handle, labeled none) is excluded.
   */
  private predicate multipartUploadSource(DataFlow::Node source) {
    exists(Attribute a |
      source.asExpr() = a and
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() in ["file", "field"] and
      a.getName() in ["filename", "file_name", "field_name", "value"] and
      relPath(a).matches("mindsdb/api/http/namespaces/%") and
      (
        // S049, S050, S053 (file.py:43/44/51) inside File.put's callbacks
        inFunction(a, "put", "mindsdb/api/http/namespaces/file.py")
        or
        // S051, S052, S054 (handlers.py:90/91/98) inside BYOMUpload.put's callbacks
        inFunction(a, "put", "mindsdb/api/http/namespaces/handlers.py")
        or
        // S048 (config.py:133) in the werkzeug upload loop of Integration.put
        inFunction(a, "put", "mindsdb/api/http/namespaces/config.py")
      )
    )
  }

  /* ------------------------------------------------------------------ */
  /* Boundary parameters (labels S013, S057-S060, S061, S062)            */
  /* ------------------------------------------------------------------ */

  /**
   * Reviewed boundary-receiver parameters that carry externally controlled
   * data:
   *   - on_file(file) / on_field(field) multipart callback parameters
   *     (python-multipart invokes them with client data);
   *   - MysqlProxy.process_query(sql): SQL text from the MySQL wire server
   *     and the HTTP SQL endpoints;
   *   - run_sql_command(ast_query): translated mongo wire-protocol commands;
   *   - IntegrationController.add(connection_args): SQL PARAMETERS /
   *     HTTP integration params values, copied raw at integrations.py:68
   *     before the Path(arg_value).name basename at line 69.
   *
   * Internal file-controller/handler parameters (S002/S003/S005/S006) are
   * intentionally absent; see the file header and MySummaries.qll.
   */
  private predicate boundaryParamSource(DataFlow::Node source) {
    exists(Function f, Parameter p, string paramName |
      f.getArgByName(paramName) = p and
      source.asExpr() = p.asName() and
      (
        (
          // S057-S060: multipart callbacks (parameter index 0)
          f.getName() in ["on_file", "on_field"] and
          paramName = f.getArg(0).asName().getId() and
          relPath(f).matches("mindsdb/api/http/namespaces/%")
        )
        or
        (
          // S062: raw SQL text boundary of the MySQL wire protocol
          f.getName() = "process_query" and
          paramName = "sql" and
          relPath(f).matches("mindsdb/api/mysql/mysql_proxy/mysql_proxy.py")
        )
        or
        (
          // S061: mongo wire-protocol SQL AST boundary
          f.getName() = "run_sql_command" and
          paramName = "ast_query" and
          relPath(f).matches("mindsdb/api/mongo/classes/query_sql.py")
        )
        or
        (
          // S013: integration connection args boundary receiver
          f.getName() = "add" and
          paramName = "connection_args" and
          relPath(f).matches("mindsdb/interfaces/database/integrations.py")
        )
      )
    )
  }
}
