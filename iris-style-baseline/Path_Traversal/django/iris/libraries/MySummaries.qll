/**
 * Augur Pass 1 (Path Traversal, CWE-22/23/36/73) - additional taint steps
 * for the Django 2.2.26 (django_vuln) CodeQL database.
 *
 * Only three propagation edges are emitted, each tightly scoped to real
 * code (no arbitrary node-to-node steps):
 *
 * 1. pathlibConstructorStep - Path(<tainted>) carries its argument path
 *    into the constructed path object. Needed because codeql/python-all
 *    7.1.2 does not model the pathlib constructors yet (Stdlib.qll has an
 *    explicit "TODO: Handle pathlib" next to the os.path.join taint step,
 *    verified in the installed pack), while two labeled sinks take a
 *    pathlib receiver as the dangerous operand (views/static.py:50
 *    fullpath.open('rb'), contrib/admindocs/views.py:334
 *    template_file.open()). Scoped to exactly those two files.
 *
 * 2. sessionKeyFieldStep - the cookie-derived session key is stored into
 *    object state by SessionBase.__init__ (django/contrib/sessions/
 *    backends/base.py:45 `self._session_key = session_key`) and read back
 *    in other methods (self._session_key / the session_key property) on
 *    its way to _key_to_file's os.path.join (file.py:55) and the labeled
 *    session file sinks. Cross-method attribute flow is not tracked
 *    automatically, so this single store->load edge is required to connect
 *    the approved source (src-0077 / the COOKIES.get rows) to the approved
 *    session sinks (snk-0158/0160/0161/0163/0168). This implements the
 *    propagation described in the rationales of the session wrapper labels
 *    snk-0154/0157/0159/0167. Scoped to the sessions backends package.
 *
 * 3. uploadFileNameFieldStep - FileUploadHandler.new_file(field_name,
 *    file_name, ...) stores the client filename into handler state
 *    (django/core/files/uploadhandler.py:101 `self.file_name =
 *    file_name`) and TemporaryFileUploadHandler.new_file reads it back at
 *    :140 (TemporaryUploadedFile(self.file_name, ...)). Approved summary
 *    label src-0193 (role=summary, classification=tp) describes exactly
 *    this propagation. Scoped to core/files/uploadhandler.py.
 *
 * Label entries that describe arg->return propagation through ordinary
 * framework functions (snk-0222 find_location, snk-0230 storage.path call,
 * snk-0373 serve, snk-0516 finders.find, src-0117 unquote) need NO extra
 * edge: unquote and os.path.join are already modeled by the installed
 * python-all pack (Stdlib.model.yml / Stdlib.qll OsPathJoinCall
 * AdditionalTaintStep, verified), and user-function argument/return flow
 * is native to TaintTracking::Global.
 *
 * AST idioms identical to the Step 2 extraction queries (compiled against
 * codeql/python-all 7.1.2); `module` is never a variable name; API::Node
 * and DataFlow::Node are never mixed.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {


  /** Forward-slash-normalized absolute path of the file containing n. */
  private string normalizedPathOf(AstNode n) {
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
  }

  /**
   * Path(<arg>) -> path object: the constructed pathlib object denotes the
   * argument path, so taint on the constructor argument must reach the
   * constructed object (which is the dangerous RECEIVER at the labeled
   * static/admindocs open sinks). Only the from-pathlib-imported Path
   * constructor in the two files with labeled receiver sinks is bridged.
   *
   * Evidence: views/static.py:36 `fullpath = Path(safe_join(document_root,
   * path))` -> :50 `fullpath.open('rb')`; contrib/admindocs/views.py:332
   * `template_file = Path(safe_join(directory, template))` -> :334
   * `template_file.open()`.
   */
  private predicate pathlibConstructorStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      (
        normalizedPathOf(c).matches("%/django/views/static.py")
        or
        normalizedPathOf(c).matches("%/django/contrib/admindocs/views.py")
      ) and
      c.getFunc().(Name).getId() = "Path" and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }

  /**
   * Session-key object-state step: SessionStore.__init__/SessionBase.
   * __init__ `session_key` parameter -> reads of self._session_key /
   * self.session_key anywhere in the session backends package.
   *
   * Evidence: contrib/sessions/backends/base.py:44-:45
   *   def __init__(self, session_key=None): self._session_key = session_key
   * (SessionStore.__init__ at contrib/sessions/backends/file.py:20-:23 calls
   * super().__init__(session_key)); reads:
   *   base.py _get_or_create_session_key/`self.session_key` property ->
   *   file.py:55 _key_to_file os.path.join(storage_path, prefix + key)
   *   file.py:180 delete() `session_key = self.session_key`
   * The store is always constructed from the request cookie by
   * contrib/sessions/middleware.py:19-:20.
   */
  private predicate sessionKeyFieldStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function f, Parameter p, Attribute read |
      f.getName() = "__init__" and
      p = f.getAnArg() and
      p.getName() = "session_key" and
      normalizedPathOf(f).matches("%/django/contrib/sessions/backends/%") and
      nodeFrom = DataFlow::parameterNode(p) and
      read.getName() in ["_session_key", "session_key"] and
      read.getObject().(Name).getId() = "self" and
      normalizedPathOf(read).matches("%/django/contrib/sessions/backends/%") and
      nodeTo.asExpr() = read
    )
  }

  /**
   * Upload-filename handler-state step: FileUploadHandler.new_file's
   * `file_name` parameter -> reads of self.file_name in the same module.
   *
   * Evidence: django/core/files/uploadhandler.py:93-:105
   *   def new_file(self, field_name, file_name, ...):
   *       self.field_name = field_name
   *       self.file_name = file_name
   * and TemporaryFileUploadHandler.new_file :135-:140
   *   super().new_file(*args, **kwargs)
   *   self.file = TemporaryUploadedFile(self.file_name, ...)
   * The MultiPartParser calls handler.new_file(field_name, file_name, ...)
   * with the (sanitize_file_name-processed) client filename
   * (http/multipartparser.py:225-:228). Label: src-0193 (summary/tp).
   */
  private predicate uploadFileNameFieldStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Function f, Parameter p, Attribute read |
      f.getName() = "new_file" and
      p = f.getAnArg() and
      p.getName() = "file_name" and
      normalizedPathOf(f).matches("%/django/core/files/uploadhandler.py") and
      nodeFrom = DataFlow::parameterNode(p) and
      read.getName() = "file_name" and
      read.getObject().(Name).getId() = "self" and
      normalizedPathOf(read).matches("%/django/core/files/uploadhandler.py") and
      nodeTo.asExpr() = read
    )
  }

  /**
   * Pass-1 additional taint-step dispatch. The pass key is checked so the
   * same library shape can serve later passes; only "path_traversal" is
   * enabled in this run. No other edges exist: every other label-described
   * propagation is either native interprocedural flow, an already-modeled
   * stdlib step (os.path.join, urllib.parse.unquote), or intentionally not
   * emitted (candidate-classified summaries snk-0157/0159/0167 are covered
   * by the narrowly scoped sessionKeyFieldStep that connects the approved
   * session source and sinks; the FieldFile candidate summaries
   * snk-0205..0215 get no edges - no approved source reaches them).
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and
    (
      pathlibConstructorStep(nodeFrom, nodeTo)
      or
      sessionKeyFieldStep(nodeFrom, nodeTo)
      or
      uploadFileNameFieldStep(nodeFrom, nodeTo)
    )
  }

}
