/**
 * Augur Pass 1 (Path Traversal) sink library for the mindsdb project.
 *
 * Generated in Phase 2 Step 4 from the reviewed Pass 1 labels
 * (labels/labels.json, pass_id 1, pass key "path_traversal"). Every sink
 * entry below corresponds to a label with role = sink and names the real
 * filesystem operation, its dangerous path argument index (0-based
 * positional) or receiver form, and the enclosing function that the review
 * verified.
 *
 * Realized sink labels (28 entries, K-ids per label_stats.md):
 *   K009  os.unlink    arg 0  BYOMUpload.put      (handlers.py:136)
 *   K024  open         arg 0  FileHandler._get_data_io (file_handler.py:158)
 *   K034  open         arg 0  File.put            (file.py:123, url branch)
 *   K041  open         arg 0  BigQueryHandler.connect (bigquery_handler.py:47)
 *   K046/K047 open     arg 0  copy() in interfaces/storage/fs.py (fs.py:39, src/dst)
 *   K048  open         arg 0  FileStorage.file_set (fs.py:220)
 *   K049  open         arg 0  FileStorage.file_get (fs.py:233)
 *   K063  shutil.rmtree arg 0  copy() in fs.py (fs.py:35)
 *   K068  os.makedirs  arg 0  FileStorage.get_path (fs.py:303)
 *   K072  os.remove    arg 0  File.put            (file.py:138)
 *   K076  os.remove    arg 0  copy() in fs.py (fs.py:42)
 *   K079  shutil.move  arg 0  FileController.save_file (file_controller.py:100, source)
 *   K082  shutil.move  arg 1  FileController.save_file (file_controller.py:100, destination)
 *   K089/K090 shutil.copytree arg 0/1 copy() in fs.py (fs.py:36)
 *   K091/K092 shutil.copy2   arg 0/1 copy() in fs.py (fs.py:45)
 *   K093  shutil.copy  arg 0  IntegrationController.add (integrations.py:68, raw PATH arg)
 *   K095  zipfile.ZipFile   arg 0  File.put (file.py:133)
 *   K096  tarfile.open      arg 0  File.put (file.py:136)
 *   K097  extractall   arg 0  File.put (file.py:134, zip branch)
 *   K098  extractall   arg 0  File.put (file.py:137, tar.gz branch)
 *   K100  save         arg 0  Integration.put (config.py:137, werkzeug FileStorage.save;
 *         label classification fp - the resolve+parents containment check at
 *         config.py:133-136 is branch-sensitive and cannot be modeled as a
 *         node barrier; expected to alert and be filtered at Step 6)
 *   K101  send_from_directory arg 1 root_index (start.py:67; label
 *         classification fp - werkzeug safe_join is a framework-internal
 *         barrier; the reviewed source set contains no source reaching this
 *         route parameter, so no formal alert is expected)
 *   K105  sqlite3.connect arg 0 SQLiteHandler.connect (sqlite_handler.py:60)
 *   K008  unlink (receiver)  FileStorage.delete (fs.py:326)
 *   K016  rmdir  (receiver)  FileStorage.delete (fs.py:328)
 *
 * Sink nodes are the argument expression at the dangerous index (or the
 * receiver expression for the pathlib receiver-form labels), i.e. the path
 * TEXT, never an opened file object.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {

  /** Pass 1 sink predicate. Only the "path_traversal" pass key is served. */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "path_traversal" and
    (
      argumentSink(sink)
      or
      receiverSink(sink)
    )
  }

  /* ------------------------------------------------------------------ */
  /* Shared helpers (idioms proven by the Step 2 extraction queries)     */
  /* ------------------------------------------------------------------ */

  private string dottedName(Expr e) {
    result = e.(Name).getId()
    or
    result = dottedName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
  }

  private string relPath(AstNode n) {
    result = n.getLocation().getFile().getRelativePath()
  }

  private predicate inFunction(AstNode n, string funcName, string filePattern) {
    exists(Function f |
      f.getName() = funcName and
      relPath(f) = filePattern and
      relPath(n) = filePattern and
      (n.getScope() = f or n.getScope().getEnclosingScope*() = f)
    )
  }

  /* ------------------------------------------------------------------ */
  /* Argument-form sinks (dangerous path at a positional argument)       */
  /* ------------------------------------------------------------------ */

  /**
   * Holds for the dangerous path argument of a reviewed sink call.
   * `c` is matched by (resolved callee dotted name OR dynamically
   * dispatched callee attribute name), dangerous argument index, and the
   * enclosing function verified during labeling.
   */
  private predicate sinkCall(Call c, int argIndex) {
    (
      // K034: open(file_path, 'wb') in the /api/files/<name> url branch
      dottedName(c.getFunc()) = "open" and argIndex = 0 and
      inFunction(c, "put", "mindsdb/api/http/namespaces/file.py")
    )
    or
    (
      // K095: zipfile.ZipFile(file_path)
      dottedName(c.getFunc()) = "zipfile.ZipFile" and argIndex = 0 and
      inFunction(c, "put", "mindsdb/api/http/namespaces/file.py")
    )
    or
    (
      // K096: tarfile.open(file_path)
      dottedName(c.getFunc()) = "tarfile.open" and argIndex = 0 and
      inFunction(c, "put", "mindsdb/api/http/namespaces/file.py")
    )
    or
    (
      // K097/K098: f.extractall(temp_dir_path), zip and tar branches.
      // Modeled per label at arg 0; the effective zip-slip detector for the
      // upload flow is the archive-open sink (K095/K096), since member-name
      // writes are archive-content, not string taint.
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "extractall" and argIndex = 0 and
      inFunction(c, "put", "mindsdb/api/http/namespaces/file.py")
    )
    or
    (
      // K072: os.remove(file_path) of the uploaded archive
      dottedName(c.getFunc()) = "os.remove" and argIndex = 0 and
      inFunction(c, "put", "mindsdb/api/http/namespaces/file.py")
    )
    or
    (
      // K009: os.unlink(file_path) of the byom upload
      dottedName(c.getFunc()) = "os.unlink" and argIndex = 0 and
      inFunction(c, "put", "mindsdb/api/http/namespaces/handlers.py")
    )
    or
    (
      // K100: file.save(file_path) after the resolve+parents check
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "save" and argIndex = 0 and
      inFunction(c, "put", "mindsdb/api/http/namespaces/config.py")
    )
    or
    (
      // K024: open(file_path, 'rb') in _get_data_io
      dottedName(c.getFunc()) = "open" and argIndex = 0 and
      inFunction(c, "_get_data_io", "mindsdb/integrations/handlers/file_handler/file_handler.py")
    )
    or
    (
      // K079: shutil.move(file_path, str(source)) - move source (read+unlink)
      dottedName(c.getFunc()) = "shutil.move" and argIndex = 0 and
      inFunction(c, "save_file", "mindsdb/interfaces/file/file_controller.py")
    )
    or
    (
      // K082: shutil.move(file_path, str(source)) - move destination (write)
      dottedName(c.getFunc()) = "shutil.move" and argIndex = 1 and
      inFunction(c, "save_file", "mindsdb/interfaces/file/file_controller.py")
    )
    or
    (
      // K093: shutil.copy(arg_value, files_dir) with the RAW ARG_TYPE.PATH value
      dottedName(c.getFunc()) = "shutil.copy" and argIndex = 0 and
      inFunction(c, "add", "mindsdb/interfaces/database/integrations.py")
    )
    or
    (
      // K041: open(self.connection_data['service_account_keys'])
      dottedName(c.getFunc()) = "open" and argIndex = 0 and
      inFunction(c, "connect", "mindsdb/integrations/handlers/bigquery_handler/bigquery_handler.py")
    )
    or
    (
      // K105: sqlite3.connect(self.connection_data['db_file'])
      dottedName(c.getFunc()) = "sqlite3.connect" and argIndex = 0 and
      inFunction(c, "connect", "mindsdb/integrations/handlers/sqlite_handler/sqlite_handler.py")
    )
    or
    (
      // K046/K047: open(src, 'rb') / open(dst, 'rb') md5 comparison in copy()
      dottedName(c.getFunc()) = "open" and argIndex = 0 and
      inFunction(c, "copy", "mindsdb/interfaces/storage/fs.py")
    )
    or
    (
      // K063: shutil.rmtree(dst, ignore_errors=True) in copy()
      dottedName(c.getFunc()) = "shutil.rmtree" and argIndex = 0 and
      inFunction(c, "copy", "mindsdb/interfaces/storage/fs.py")
    )
    or
    (
      // K089/K090: shutil.copytree(src, dst) in copy()
      dottedName(c.getFunc()) = "shutil.copytree" and
      argIndex in [0, 1] and
      inFunction(c, "copy", "mindsdb/interfaces/storage/fs.py")
    )
    or
    (
      // K091/K092: shutil.copy2(src, dst) in copy()
      dottedName(c.getFunc()) = "shutil.copy2" and
      argIndex in [0, 1] and
      inFunction(c, "copy", "mindsdb/interfaces/storage/fs.py")
    )
    or
    (
      // K076: os.remove(dst) in copy()
      dottedName(c.getFunc()) = "os.remove" and argIndex = 0 and
      inFunction(c, "copy", "mindsdb/interfaces/storage/fs.py")
    )
    or
    (
      // K048: open(dest_abs_path, 'wb') in FileStorage.file_set
      dottedName(c.getFunc()) = "open" and argIndex = 0 and
      inFunction(c, "file_set", "mindsdb/interfaces/storage/fs.py")
    )
    or
    (
      // K049: open(dest_abs_path, 'rb') in FileStorage.file_get
      dottedName(c.getFunc()) = "open" and argIndex = 0 and
      inFunction(c, "file_get", "mindsdb/interfaces/storage/fs.py")
    )
    or
    (
      // K068: os.makedirs(ret_path) in FileStorage.get_path
      dottedName(c.getFunc()) = "os.makedirs" and argIndex = 0 and
      inFunction(c, "get_path", "mindsdb/interfaces/storage/fs.py")
    )
    or
    (
      // K101: send_from_directory(static_root, path) - static file response.
      // Label classification fp (werkzeug safe_join); retained per role.
      dottedName(c.getFunc()) = "send_from_directory" and argIndex = 1 and
      inFunction(c, "root_index", "mindsdb/api/http/start.py")
    )
  }

  private predicate argumentSink(DataFlow::Node sink) {
    exists(Call c, int argIndex |
      sinkCall(c, argIndex) and
      sink.asExpr() = c.getPositionalArg(argIndex)
    )
  }

  /* ------------------------------------------------------------------ */
  /* Receiver-form sinks (pathlib: the path is the call receiver)        */
  /* ------------------------------------------------------------------ */

  /**
   * K008/K016: path.unlink() / path.rmdir() in FileStorage.delete, where
   * path = (folder_path / relative_path).resolve(). The sink node is the
   * receiver expression carrying the path. Labels classify these as
   * candidate (no tainted caller confirmed; the delete() containment is
   * equality-only, fs.py:314-316).
   */
  private predicate receiverSink(DataFlow::Node sink) {
    exists(Call c |
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() in ["unlink", "rmdir"] and
      inFunction(c, "delete", "mindsdb/interfaces/storage/fs.py") and
      sink.asExpr() = c.getFunc().(Attribute).getObject()
    )
  }
}
