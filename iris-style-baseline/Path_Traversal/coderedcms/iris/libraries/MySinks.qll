/**
 * Augur Phase 2 - Pass 1 sink models (machine-generated from reviewed labels).
 *
 * Generated from: iris/labels/labels.json, pass 1 (Path Traversal,
 * CWE-022/023/036/073), run coderedcms-pass1-labeling-20261021, model glm-5.3.
 *
 * All 8 reviewed sink-role entries are covered. Only real file accesses are
 * sinks - path construction and resolution wrappers (Path(), os.path.join,
 * storage.path, get_available_name, splitext, isfile) are modeled in
 * MySummaries.qll / by the standard library, NOT as sinks:
 *
 *   Label                        | Site                                | Access      | Path arg
 *   -----------------------------+-------------------------------------+-------------+---------
 *   K-views-117-open (tp, 0.98)  | coderedcms/views.py:117             | read (builtin open) | arg 0
 *   K-wff_models-245-open (cand.)| wff models.py:245 storage.open      | write       | arg 0
 *   K-page_models-1212-open (cand.)| page_models.py:1212 storage.open  | write       | arg 0
 *   K-wff_models-342-open (cand.)| wff models.py:342 Image.open        | read        | arg 0
 *   K-wff_models-344-save (cand.)| wff models.py:344 thumbnail.save    | write       | arg 0
 *   K-wff_models-379-delete (cand.)| wff models.py:379 storage.delete  | delete      | arg 0
 *   K-wff_models-488-delete (cand.)| wff models.py:488 storage.delete  | delete      | arg 0
 *   K-wff_models-499-rmdir (cand.)| wff models.py:499 Path(...).rmdir  | dir delete  | receiver
 *
 * Verified against the source tree: the structural predicates below match
 * exactly these call sites and no others in the audit scope (all other
 * .save()/.delete() calls in the package take no arguments and therefore
 * never bind getArg(0)).
 *
 * Pass key: "path_traversal".
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  /**
   * Holds if `sink` is a reviewed pass-1 taint sink for the given pass key.
   */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "path_traversal" and
    (
      isBuiltinOpenSink(sink)
      or
      isOpenMethodSink(sink)
      or
      isImageSaveSink(sink)
      or
      isStorageDeleteSink(sink)
      or
      isRmdirSink(sink)
    )
  }

  /**
   * The audit scope: the coderedcms package as extracted in Phase 1 Step 2 -
   * excludes generated migrations, tests, the project scaffolding template and
   * the nested CodeQL database tree (WORKFLOW.md 4.3.2).
   */
  private predicate inAuditScope(DataFlow::Node n) {
    exists(string path |
      path = n.getLocation().getFile().getAbsolutePath() and
      path.matches("%/coderedcms/%") and
      not path.matches("%/migrations/%") and
      not path.matches("%/tests/%") and
      not path.matches("%/project_template/%") and
      not path.matches("%/coderedcms-db/%")
    )
  }

  /**
   * Label K-views-117-open (tp, 0.98): builtin open(fullpath, 'rb') in
   * serve_protected_file - THE confirmed CWE-022 read. fullpath comes from
   * os.path.join(PROTECTED_MEDIA_ROOT, path) at views.py:114 with the
   * URL-injected route parameter; no containment exists between join and open
   * (os.path.isfile at :115 is an existence gate only, and a TOCTOU window
   * relative to :117). Dangerous path argument: index 0.
   * Only builtin-open call in the audit scope.
   */
  private predicate isBuiltinOpenSink(DataFlow::Node sink) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = "open" and
      inAuditScope(DataFlow::exprNode(c)) and
      sink = DataFlow::exprNode(c.getArg(0))
    )
  }

  /**
   * Labels K-wff_models-245-open (storage.open(path, 'wb+') - upload write),
   * K-page_models-1212-open (storage.open(path, 'wb+') - upload write on the
   * FileSystemStorage(PROTECTED_MEDIA_ROOT) wrapper of page_models.py:1223) and
   * K-wff_models-342-open (Image.open(storage.path(path)) - thumbnail read).
   *
   * Method calls named "open" in the audit scope are exactly these three
   * sites. The written/read path argument is index 0. Classification
   * candidate: containment depends on Django-external
   * FileSystemStorage.path()/safe_join (evidence gap, see
   * report/query_generation_notes.md).
   */
  private predicate isOpenMethodSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode mc |
      mc.getMethodName() = "open" and
      inAuditScope(mc) and
      sink = mc.getArg(0)
    )
  }

  /**
   * Label K-wff_models-344-save (candidate, 0.7):
   * thumbnail.save(storage.path(thumbnail_path)) - writes the thumbnail image
   * next to a stored submission path (second-order channel). The only .save()
   * method call with an argument in the audit scope; dangerous path argument
   * index 0.
   */
  private predicate isImageSaveSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode mc |
      mc.getMethodName() = "save" and
      inAuditScope(mc) and
      sink = mc.getArg(0)
    )
  }

  /**
   * Labels K-wff_models-379-delete (self.get_storage().delete(path) - files
   * recorded under a submission field) and K-wff_models-488-delete
   * (storage.delete(path) in the post_delete signal receiver). Second-order:
   * paths come from stored submission data (db_json sources). Dangerous path
   * argument index 0. All other .delete() calls in the audit scope
   * (queryset.delete(), self.delete()) take no arguments and never bind.
   */
  private predicate isStorageDeleteSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode mc |
      mc.getMethodName() = "delete" and
      inAuditScope(mc) and
      sink = mc.getArg(0)
    )
  }

  /**
   * Label K-wff_models-499-rmdir (candidate, 0.55):
   * Path(storage.path(directory)).rmdir() - removes an empty ancestor
   * directory of a deleted stored path (rmdir semantics: empty dirs only),
   * reachable only through the db_json channel. Dangerous path operand is the
   * call RECEIVER (the Path object), not an argument.
   */
  private predicate isRmdirSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode mc |
      mc.getMethodName() = "rmdir" and
      inAuditScope(mc) and
      sink = mc.getObject()
    )
  }
}
