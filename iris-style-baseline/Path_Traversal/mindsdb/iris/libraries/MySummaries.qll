/**
 * Augur Pass 1 (Path Traversal) summary (additional taint step) library for
 * the mindsdb project.
 *
 * Generated in Phase 2 Step 4 from the reviewed Pass 1 labels
 * (labels/labels.json, pass_id 1, pass key "path_traversal"). Every edge
 * below is justified by real code; no unconditional arbitrary-node-to-
 * arbitrary-node propagation is introduced.
 *
 * Label realization mapping:
 *
 *  - S002/S003 (FileController.save_file file_path/file_name parameters,
 *    labeled source as internal boundary receivers): per the Step 4 source
 *    policy these are NOT sources; bridge A propagates the real call-site
 *    arguments of `ca.file_controller.save_file(...)` (file.py:149, the
 *    flask current_app receiver is not resolvable by dataflow) into the
 *    save_file parameters.
 *  - S005/S006 (FileHandler._handle_source/_get_data_io file_path
 *    parameters): bridge B propagates the real static-call arguments at
 *    file_controller.py:75 and file_handler.py:100 into the parameters
 *    (redundant when CodeQL resolves the FileHandler class-attribute calls,
 *    inert otherwise - a safety net, not a new taint origin).
 *  - S007-S012 (FileStorage push_path/pull_path/file_set/file_get/get_path/
 *    delete, labeled summary): realized by the path-construction steps C/D
 *    below (os.path.join, Path(...), joinpath, resolve, str(), and the
 *    pathlib '/' operator in interfaces/storage/fs.py): a tainted
 *    name/relative_path parameter propagates through the wrappers into the
 *    reviewed sinks inside them.
 *  - S063-S090 (db/ml/executor wrapper RPC request.json reads, labeled
 *    summary): NOT modeled. These are cross-process network hops
 *    (DBServiceClient/MLClient spawn separate Flask services); there is no
 *    intra-database dataflow edge to add without fabricating propagation.
 *    See report/query_generation_notes.md.
 *
 * Step inventory (all scoped and evidence-based):
 *   A  dynamic-receiver call bridge: file.py:149 -> save_file parameters
 *   B  static-call safety bridges: file_controller.py:75 -> _handle_source,
 *      file_handler.py:100 -> _get_data_io
 *   C  path construction: os.path.join, Path(x), p.joinpath(x), p.resolve(),
 *      str(path) (file_controller.py only)
 *   D  pathlib '/' joins in interfaces/storage/fs.py
 *   E  multipart callbacks: on_file/on_field parameter -> file_name/
 *      field_name/value attribute -> .decode() result
 *      (file.py:42-52, handlers.py:89-99)
 *   F  upload dict approximation: the `data` dict in File.put /
 *      BYOMUpload.put (request.json branch: variable -> element read;
 *      multipart branch: decoded values and element stores -> element
 *      reads and .get() results; file.py:43-51, handlers.py:90-98)
 *   G  .get() receiver -> result in config.py Integration.put/post
 *      (covers (request.json or {}).get('params', {}), config.py:121/192)
 *   H  IntegrationController.add loop approximation: connection_args
 *      parameter -> shutil.copy raw-path argument (integrations.py:61-68;
 *      approximates the for-loop over connection_args.items(), which
 *      default dataflow does not track)
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {

  /**
   * Pass 1 additional taint step predicate. Only the "path_traversal" pass
   * key is served.
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and
    (
      saveFileBridge(nodeFrom, nodeTo)
      or
      handlerCallBridge(nodeFrom, nodeTo)
      or
      pathConstructionStep(nodeFrom, nodeTo)
      or
      pathlibJoinStep(nodeFrom, nodeTo)
      or
      multipartCallbackStep(nodeFrom, nodeTo)
      or
      uploadDictStep(nodeFrom, nodeTo)
      or
      configGetStep(nodeFrom, nodeTo)
      or
      integrationArgLoopStep(nodeFrom, nodeTo)
    )
  }

  /* ------------------------------------------------------------------ */
  /* Helpers                                                             */
  /* ------------------------------------------------------------------ */

  private string dottedName(Expr e) {
    result = e.(Name).getId()
    or
    result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
  }

  private string relPath(AstNode n) {
    result = n.getLocation().getFile().getRelativePath()
  }

  private predicate inScope(AstNode n, Function f) {
    relPath(n) = relPath(f) and
    (n.getScope() = f or n.getScope().getEnclosingScope*() = f)
  }

  private predicate inFunction(AstNode n, string funcName, string filePattern) {
    exists(Function f |
      f.getName() = funcName and
      relPath(f) = filePattern and
      inScope(n, f)
    )
  }

  /* ------------------------------------------------------------------ */
  /* A: ca.file_controller.save_file(...) dynamic-receiver bridge        */
  /* ------------------------------------------------------------------ */

  /**
   * file.py:149 `ca.file_controller.save_file(mindsdb_file_name, file_path,
   * file_name=original_file_name)`: the flask current_app receiver `ca`
   * cannot be resolved by dataflow, so the reviewed argument-to-parameter
   * flows are added explicitly. The keyword argument file_name is bridged
   * from the `original_file_name` variable (file.py:127), because keyword
   * argument matching at unresolvable calls is not otherwise expressible.
   */
  private predicate saveFileBridge(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Function f, Parameter p |
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "save_file" and
      inFunction(c, "put", "mindsdb/api/http/namespaces/file.py") and
      f.getName() = "save_file" and
      relPath(f).matches("mindsdb/interfaces/file/file_controller.py") and
      f.getArgByName("file_path") = p and
      nodeFrom.asExpr() = c.getPositionalArg(1) and
      nodeTo.asExpr() = p.asName()
    )
    or
    exists(Function f, Parameter p, Name n |
      f.getName() = "save_file" and
      relPath(f).matches("mindsdb/interfaces/file/file_controller.py") and
      f.getArgByName("file_name") = p and
      n.getId() = "original_file_name" and
      inFunction(n, "put", "mindsdb/api/http/namespaces/file.py") and
      nodeFrom.asExpr() = n and
      nodeTo.asExpr() = p.asName()
    )
  }

  /* ------------------------------------------------------------------ */
  /* B: static-call safety bridges into FileHandler                      */
  /* ------------------------------------------------------------------ */

  /**
   * file_controller.py:75 `FileHandler._handle_source(file_path)` and
   * file_handler.py:100 `FileHandler._get_data_io(file_path)`: bridges from
   * the real call arguments to the handler parameters, in case the
   * class-attribute call resolution through the import alias fails.
   */
  private predicate handlerCallBridge(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Function f, Parameter p |
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "_handle_source" and
      inFunction(c, "save_file", "mindsdb/interfaces/file/file_controller.py") and
      f.getName() = "_handle_source" and
      relPath(f).matches("mindsdb/integrations/handlers/file_handler/file_handler.py") and
      f.getArgByName("file_path") = p and
      nodeFrom.asExpr() = c.getPositionalArg(0) and
      nodeTo.asExpr() = p.asName()
    )
    or
    exists(Call c, Function f, Parameter p |
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "_get_data_io" and
      inFunction(c, "_handle_source", "mindsdb/integrations/handlers/file_handler/file_handler.py") and
      f.getName() = "_get_data_io" and
      relPath(f).matches("mindsdb/integrations/handlers/file_handler/file_handler.py") and
      f.getArgByName("file_path") = p and
      nodeFrom.asExpr() = c.getPositionalArg(0) and
      nodeTo.asExpr() = p.asName()
    )
  }

  /* ------------------------------------------------------------------ */
  /* C: path construction propagation                                    */
  /* ------------------------------------------------------------------ */

  /**
   * Intermediate path wrappers used by the reviewed flows. These are
   * propagation, not sanitization: os.path.join with an absolute second
   * component discards the base, and resolve() canonicalizes without
   * containing. Only the Path(...).name basename is a barrier
   * (MySanitizers.qll).
   */
  private predicate pathConstructionStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    // os.path.join(temp_dir_path, data['file']) etc. -> joined path
    exists(Call c |
      dottedName(c.getFunc()) = "os.path.join" and
      exists(int i | nodeFrom.asExpr() = c.getPositionalArg(i)) and
      nodeTo.asExpr() = c
    )
    or
    // Path(x) constructor: file.py Path(file.filename), file_controller
    exists(Call c |
      dottedName(c.getFunc()) = "Path" and
      nodeFrom.asExpr() = c.getPositionalArg(0) and
      nodeTo.asExpr() = c
    )
    or
    // p.joinpath(x): receiver and arguments propagate to the joined path
    // (file_controller.py:98 file_dir.joinpath(file_name))
    exists(Call c |
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "joinpath" and
      (
        nodeFrom.asExpr() = c.getFunc().(Attribute).getObject()
        or
        exists(int i | nodeFrom.asExpr() = c.getPositionalArg(i))
      ) and
      nodeTo.asExpr() = c
    )
    or
    // p.resolve(): canonicalization keeps out-of-root targets reachable
    // (config.py:134); deliberately NOT a barrier
    exists(Call c |
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "resolve" and
      nodeFrom.asExpr() = c.getFunc().(Attribute).getObject() and
      nodeTo.asExpr() = c
    )
    or
    // str(path) at the shutil.move destination (file_controller.py:100)
    exists(Call c |
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "str" and
      nodeFrom.asExpr() = c.getPositionalArg(0) and
      nodeTo.asExpr() = c and
      relPath(c).matches("mindsdb/interfaces/file/file_controller.py")
    )
  }

  /* ------------------------------------------------------------------ */
  /* D: pathlib '/' operator joins in interfaces/storage/fs.py           */
  /* ------------------------------------------------------------------ */

  /**
   * `self.folder_path / name` (fs.py:218, 231) and
   * `folder_path / relative_path` (fs.py:300, 314): the pathlib slash
   * join propagates both operands; scoped to interfaces/storage/fs.py
   * where the operator is exclusively a pathlib join.
   */
  private predicate pathlibJoinStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(BinaryExpr b |
      relPath(b).matches("mindsdb/interfaces/storage/fs.py") and
      (nodeFrom.asExpr() = b.getLeft() or nodeFrom.asExpr() = b.getRight()) and
      nodeTo.asExpr() = b
    )
  }

  /* ------------------------------------------------------------------ */
  /* E: multipart callback propagation                                   */
  /* ------------------------------------------------------------------ */

  /**
   * python-multipart callbacks (file.py:42-52, handlers.py:89-99):
   * the callback parameter flows to the client-controlled attribute reads
   * (file.file_name / field.field_name / field.value), and those attribute
   * values flow through the .decode() calls that produce data['file'].
   */
  private predicate multipartCallbackStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function f, Parameter p, Attribute a |
      f.getName() in ["on_file", "on_field"] and
      relPath(f).matches("mindsdb/api/http/namespaces/%") and
      f.getArg(0) = p and
      a.getName() in ["file_name", "field_name", "value"] and
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() = p.asName().getId() and
      inScope(a, f) and
      nodeFrom.asExpr() = p.asName() and
      nodeTo.asExpr() = a
    )
    or
    exists(Call c, Attribute a |
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "decode" and
      c.getFunc().(Attribute).getObject() = a and
      a.getName() in ["file_name", "field_name", "value"] and
      a.getObject() instanceof Name and
      a.getObject().(Name).getId() in ["file", "field"] and
      relPath(c).matches("mindsdb/api/http/namespaces/%") and
      inUploadPutTree(c) and
      nodeFrom.asExpr() = a and
      nodeTo.asExpr() = c
    )
  }

  /* ------------------------------------------------------------------ */
  /* F: upload dict approximation in File.put / BYOMUpload.put           */
  /* ------------------------------------------------------------------ */

  private predicate inUploadPutTree(AstNode n) {
    inFunction(n, "put", "mindsdb/api/http/namespaces/file.py")
    or
    inFunction(n, "put", "mindsdb/api/http/namespaces/handlers.py")
  }

  /**
   * The `data` dict of the two upload handlers: container element taint is
   * approximated within the handler scope tree. Covers
   * `data = request.json` + `data['file']` (json branch),
   * `data['file'] = file.file_name.decode()` and `data[name] = value`
   * (multipart branch, file.py:44-51, handlers.py:90-98), and
   * `data.get('original_file_name')` (file.py:127) /
   * `data.get('source_type')` (file.py:89).
   */
  private predicate uploadDictStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Subscript s |
      s.getValue().(Name).getId() = "data" and
      inUploadPutTree(s) and
      uploadDictSource(nodeFrom.asExpr()) and
      nodeTo.asExpr() = s
    )
    or
    exists(Call c |
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject().(Name).getId() = "data" and
      inUploadPutTree(c) and
      uploadDictSource(nodeFrom.asExpr()) and
      nodeTo.asExpr() = c
    )
  }

  private predicate uploadDictSource(Expr e) {
    // the dict variable itself (tainted in the request.json branch)
    e instanceof Name and
    e.(Name).getId() = "data" and
    inUploadPutTree(e)
    or
    // an element read/write node on the same dict (covers the
    // data['file'] = data['name'] store in the url branch, file.py:91)
    e instanceof Subscript and
    e.(Subscript).getValue().(Name).getId() = "data" and
    inUploadPutTree(e)
    or
    // decoded multipart values stored into the dict (file.py:44-45, 51;
    // handlers.py:98)
    e instanceof Call and
    e.(Call).getFunc() instanceof Attribute and
    e.(Call).getFunc().(Attribute).getName() = "decode" and
    inUploadPutTree(e)
  }

  /* ------------------------------------------------------------------ */
  /* G: .get() receiver -> result in the integration namespace           */
  /* ------------------------------------------------------------------ */

  /**
   * config.py:121 `(request.json or {}).get('params', {})` and
   * config.py:192 `(request.json or {}).get('params', {})` in the modify
   * flow: the .get() result carries the receiver's taint.
   */
  private predicate configGetStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "get" and
      (
        inFunction(c, "put", "mindsdb/api/http/namespaces/config.py")
        or
        inFunction(c, "post", "mindsdb/api/http/namespaces/config.py")
      ) and
      nodeFrom.asExpr() = c.getFunc().(Attribute).getObject() and
      nodeTo.asExpr() = c
    )
  }

  /* ------------------------------------------------------------------ */
  /* H: connection_args loop approximation in IntegrationController.add   */
  /* ------------------------------------------------------------------ */

  /**
   * integrations.py:61-68: `for arg_name, arg_value in
   * connection_args.items(): ... shutil.copy(arg_value, files_dir)` -
   * default dataflow does not track dict-item iteration into loop targets,
   * so the reviewed flow from the connection_args parameter (source S013)
   * to the raw-path copy argument is approximated by one edge. The copy at
   * line 68 intentionally precedes the Path(arg_value).name basename
   * barrier at line 69, which is why this edge is sound for the raw-path
   * copy and the barrier still blocks the basenamed stored value.
   */
  private predicate integrationArgLoopStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function f, Parameter p, Call c |
      f.getName() = "add" and
      relPath(f).matches("mindsdb/interfaces/database/integrations.py") and
      f.getArgByName("connection_args") = p and
      dottedName(c.getFunc()) = "shutil.copy" and
      inScope(c, f) and
      nodeFrom.asExpr() = p.asName() and
      nodeTo.asExpr() = c.getPositionalArg(0)
    )
  }
}
