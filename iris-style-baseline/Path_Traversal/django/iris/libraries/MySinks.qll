/**
 * Augur Pass 1 (Path Traversal, CWE-22/23/36/73) - sink model for the
 * Django 2.2.26 (django_vuln) CodeQL database.
 *
 * Rendered deterministically from the reviewed Phase 1 labels
 * (iris/labels/labels.json): only entries with role=sink AND
 * classification=tp are modeled (26 call-sites / 27 label rows; the 17
 * candidate-classified sink call-sites are NOT modeled - they were left
 * for human review in labels/phase1_review.md §4 and no approval is on
 * record).
 *
 * Only actual file-content accesses / file mutations / file responses are
 * sinks: open/os.open (read+create+write), os.remove/os.rmdir/os.unlink
 * (delete), os.rename/shutil.move/file_move_safe (move = delete+write),
 * os.makedirs (create), and FileResponse (streams file content). Path
 * utilities (Path(), os.path.join/normpath/...), metadata checks
 * (exists/stat/isdir) and permission ops (chmod) are never sinks. Where
 * the dangerous operand is the *receiver* of a method call (pathlib
 * `fullpath.open('rb')`), the sink node is the path-bearing receiver
 * expression, not the opened file object - path text and file object are
 * kept distinct (the FileResponse rule, whose argument IS the file
 * object, is documented as inert in report/query_generation_notes.md).
 *
 * AST idioms identical to the Step 2 extraction queries (compiled against
 * codeql/python-all 7.1.2): Attribute.getName()/getObject(), Call.
 * getFunc()/getArg(), AstNode.getLocation().getFile().getAbsolutePath(),
 * AstNode.getScope().(Function).getName() for the function-scoped rules,
 * DataFlow::Node.asExpr(). `module` is never a variable name; API::Node
 * and DataFlow::Node are never mixed.
 *
 * Label-rule mapping and per-site evidence:
 *   isStaticServeFileSink       snk-0380 (FileResponse), snk-0381 (open)
 *   isAdmindocsTemplateSink     snk-0513 (open)
 *   isStorageFileSink           snk-0409 (open), snk-0417/0418 (os.open),
 *                               snk-0413/0414 (makedirs), snk-0416
 *                               (file_move_safe), snk-0423 (rmdir),
 *                               snk-0424 (remove)
 *   isFileMoveSink              snk-0340 (rename), snk-0341 (open),
 *                               snk-0342/0343 (os.open), snk-0345 (remove)
 *   isSessionFileSink           snk-0158 (open), snk-0160/0161 (os.open),
 *                               snk-0163 (shutil.move), snk-0168 (unlink)
 *   isFileCacheSink             snk-0183/0189/0195 (open), snk-0186
 *                               (file_move_safe), snk-0192 (remove)
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {


  /** Forward-slash-normalized absolute path of the file containing n. */
  private string normalizedPathOf(AstNode n) {
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
  }

  /**
   * The dev static-serving sink. Labels snk-0380, snk-0381.
   *
   * Evidence: django/views/static.py:50
   *   response = FileResponse(fullpath.open('rb'), content_type=...)
   * where fullpath = Path(safe_join(document_root, posixpath.normpath(path).
   * lstrip('/'))) (:35-:36). The open call is the actual file read; its
   * dangerous operand is the RECEIVER `fullpath` (a path object, not the
   * opened file), so the sink node is the receiver expression. FileResponse
   * (snk-0380) takes the opened file object as argument 0 - it is kept as
   * labeled, but its taint prerequisite (receiver-to-result flow through
   * Path.open) is not modeled, so the open receiver rule (snk-0381) is the
   * operative detector. Access type: read; callers: serve() (route-param
   * `path`), reachable only with DEBUG static serving / staticfiles.
   */
  private predicate isStaticServeFileSink(DataFlow::Node n) {
    exists(Call c, Attribute func |
      /* fullpath.open('rb') - the dangerous operand is the receiver. */
      normalizedPathOf(c).matches("%/django/views/static.py") and
      func = c.getFunc().(Attribute) and
      func.getName() = "open" and
      func.getObject().(Name).getId() = "fullpath" and
      n.asExpr() = func.getObject()
    )
    or
    exists(Call c |
      /* FileResponse(fullpath.open('rb'), ...) - argument 0 is the file
         object being served (label snk-0380, arg index 0). */
      normalizedPathOf(c).matches("%/django/views/static.py") and
      c.getFunc().(Name).getId() = "FileResponse" and
      n.asExpr() = c.getArg(0)
    )
  }

  /**
   * The admin-docs template read sink. Label snk-0513.
   *
   * Evidence: django/contrib/admindocs/views.py:334
   *   with template_file.open() as f: template_contents = f.read()
   * where template_file = Path(safe_join(directory, self.kwargs['template']))
   * (:332). Dangerous operand is the receiver `template_file`; access type:
   * read; caller: TemplateDetailView.get_context_data (URL kwarg 'template').
   */
  private predicate isAdmindocsTemplateSink(DataFlow::Node n) {
    exists(Call c, Attribute func |
      normalizedPathOf(c).matches("%/django/contrib/admindocs/views.py") and
      func = c.getFunc().(Attribute) and
      func.getName() = "open" and
      func.getObject().(Name).getId() = "template_file" and
      n.asExpr() = func.getObject()
    )
  }

  /**
   * The FileSystemStorage sinks. Labels snk-0409, snk-0413, snk-0414,
   * snk-0416, snk-0417, snk-0418, snk-0423, snk-0424.
   *
   * Evidence (django/core/files/storage.py):
   *   :231  open(self.path(name), mode)            - read;  arg 0 = path text
   *         (name = externally-supplied storage name; self.path(name) is
   *         safe_join(location, name) at :330)
   *   :273  os.open(full_path, O_CREAT|O_EXCL...)  - create+write; arg 0
   *   :245/:249 os.makedirs(directory)             - create;    arg 0
   *         (directory = dirname(full_path))
   *   :268  file_move_safe(temp_path, full_path)   - move;      arg 1
   *   :308  os.rmdir(name) / :310 os.remove(name)  - delete;    arg 0
   *         (name = self.path(name) at :304)
   * Callers: _open/_save/delete/exists/listdir - reached from FieldFile
   * open/save/delete (upload flow, validated upstream) and from
   * app/request-level storage API use.
   */
  private predicate isStorageFileSink(DataFlow::Node n) {
    exists(Call c |
      normalizedPathOf(c).matches("%/django/core/files/storage.py") and
      (
        /* builtin open() - only site :231 in this file. */
        (c.getFunc().(Name).getId() = "open" and n.asExpr() = c.getArg(0))
        or
        /* os.open(full_path, flags, ...) - site :273. */
        (c.getFunc().(Attribute).getName() = "open" and
         c.getFunc().(Attribute).getObject().(Name).getId() = "os" and
         n.asExpr() = c.getArg(0))
        or
        /* os.makedirs(directory[, mode]) - sites :245/:249. */
        (c.getFunc().(Attribute).getName() = "makedirs" and
         c.getFunc().(Attribute).getObject().(Name).getId() = "os" and
         n.asExpr() = c.getArg(0))
        or
        /* file_move_safe(old, new) - site :268, dangerous arg 1. */
        (c.getFunc().(Name).getId() = "file_move_safe" and
         n.asExpr() = c.getArg(1))
        or
        /* os.rmdir(name) / os.remove(name) - sites :308/:310. */
        (c.getFunc().(Attribute).getName() in ["rmdir", "remove"] and
         c.getFunc().(Attribute).getObject().(Name).getId() = "os" and
         n.asExpr() = c.getArg(0))
      )
    )
  }

  /**
   * The upload/cache move fallback sinks in core/files/move.py. Labels
   * snk-0340, snk-0341, snk-0342, snk-0343, snk-0345.
   *
   * Evidence (django/core/files/move.py, all inside file_move_safe):
   *   :48  os.rename(old_file_name, new_file_name) - move;  dangerous arg 1
   *   :56  open(old_file_name, 'rb')               - read;  arg 0
   *   :58  os.open(new_file_name, O_WRONLY|O_CREAT|O_EXCL...) - create+write;
   *         arg 1 (with the O_EXCL escape hatch when allow_overwrite=True)
   *   :80  os.remove(old_file_name)                - delete; arg 0
   * Callers: storage.py:268 (upload saves) and core/cache/backends/
   * filebased.py:55 (cache writes).
   */
  private predicate isFileMoveSink(DataFlow::Node n) {
    exists(Call c |
      normalizedPathOf(c).matches("%/django/core/files/move.py") and
      (
        (c.getFunc().(Attribute).getName() = "rename" and
         c.getFunc().(Attribute).getObject().(Name).getId() = "os" and
         n.asExpr() = c.getArg(1))
        or
        (c.getFunc().(Name).getId() = "open" and
         n.asExpr() = c.getArg(0))
        or
        (c.getFunc().(Attribute).getName() = "open" and
         c.getFunc().(Attribute).getObject().(Name).getId() = "os" and
         n.asExpr() = c.getArg(1))
        or
        (c.getFunc().(Attribute).getName() = "remove" and
         c.getFunc().(Attribute).getObject().(Name).getId() = "os" and
         n.asExpr() = c.getArg(0))
      )
    )
  }

  /**
   * The file session backend sinks. Labels snk-0158, snk-0160, snk-0161,
   * snk-0163, snk-0168.
   *
   * Evidence (django/contrib/sessions/backends/file.py; function scoping
   * separates these from the fp-labeled os.unlink of the internal temp file
   * at :168-in-save - note :168 is inside save() on the mkstemp path while
   * the labeled tp unlink is :181 in delete()):
   *   :78   open(self._key_to_file(), "r", ...)  - read;   arg 0; in load()
   *   :126  os.open(session_file_name, ...)      - create+write; arg 0; in
   *         save() (O_EXCL|O_CREAT when must_create)
   *   :164  shutil.move(output_file_name, session_file_name) - move;
   *         dangerous arg 1; in save()
   *   :181  os.unlink(self._key_to_file(session_key)) - delete; arg 0; in
   *         delete()
   * The path is derived from the cookie-injected session key via
   * _key_to_file (:55, os.path.join of storage_path + prefix + key).
   */
  private predicate isSessionFileSink(DataFlow::Node n) {
    exists(Call c |
      normalizedPathOf(c).matches("%/django/contrib/sessions/backends/file.py") and
      (
        (c.getFunc().(Name).getId() = "open" and
         c.getScope().(Function).getName() = "load" and
         n.asExpr() = c.getArg(0))
        or
        (c.getFunc().(Attribute).getName() = "open" and
         c.getFunc().(Attribute).getObject().(Name).getId() = "os" and
         c.getScope().(Function).getName() = "save" and
         n.asExpr() = c.getArg(0))
        or
        (c.getFunc().(Attribute).getName() = "move" and
         c.getFunc().(Attribute).getObject().(Name).getId() = "shutil" and
         c.getScope().(Function).getName() = "save" and
         n.asExpr() = c.getArg(1))
        or
        (c.getFunc().(Attribute).getName() = "unlink" and
         c.getFunc().(Attribute).getObject().(Name).getId() = "os" and
         c.getScope().(Function).getName() = "delete" and
         n.asExpr() = c.getArg(0))
      )
    )
  }

  /**
   * The file-based cache sinks. Labels snk-0183, snk-0186, snk-0189,
   * snk-0192, snk-0195.
   *
   * Evidence (django/core/cache/backends/filebased.py; function scoping
   * separates the tp opens in get()/touch()/has_key() from the fp-labeled
   * open(fd) at :53 in set() and the fp-labeled os.remove(tmp_path) at :59):
   *   :34   open(fname, 'rb') in get()      - read;  arg 0
   *   :63   open(self._key_to_file(...), 'r+b') in touch() - read+write; arg 0
   *   :93   open(fname, 'rb') in has_key()  - read;  arg 0
   *   :55   file_move_safe(tmp_path, fname, allow_overwrite=True) in set() -
   *         move; dangerous arg 1
   *   :85   os.remove(fname) in _delete()   - delete; arg 0
   * fname always comes from _key_to_file (:127-:135): make_key(key) followed
   * by hashlib.md5(...).hexdigest() joined onto the configured cache dir.
   */
  private predicate isFileCacheSink(DataFlow::Node n) {
    exists(Call c |
      normalizedPathOf(c).matches("%/django/core/cache/backends/filebased.py") and
      (
        (c.getFunc().(Name).getId() = "open" and
         c.getScope().(Function).getName() in ["get", "touch", "has_key"] and
         n.asExpr() = c.getArg(0))
        or
        (c.getFunc().(Name).getId() = "file_move_safe" and
         c.getScope().(Function).getName() = "set" and
         n.asExpr() = c.getArg(1))
        or
        (c.getFunc().(Attribute).getName() = "remove" and
         c.getFunc().(Attribute).getObject().(Name).getId() = "os" and
         c.getScope().(Function).getName() = "_delete" and
         n.asExpr() = c.getArg(0))
      )
    )
  }

  /**
   * Pass-1 sink dispatch. The pass key is checked so the same library shape
   * can serve later passes; only "path_traversal" is enabled in this run.
   */
  predicate isSink(DataFlow::Node n, string passKey) {
    passKey = "path_traversal" and
    (
      isStaticServeFileSink(n)
      or
      isAdmindocsTemplateSink(n)
      or
      isStorageFileSink(n)
      or
      isFileMoveSink(n)
      or
      isSessionFileSink(n)
      or
      isFileCacheSink(n)
    )
  }

}
