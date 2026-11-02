/**
 * Augur Phase 2 Step 4 — Pass 1 (Path Traversal) additional taint-step model
 * for pretalx.
 *
 * Machine-generated from iris/labels/labels.json (run
 * pretalx-pathtraversal-pass1-20261022, pass_id 1): the pass contains ZERO
 * role=summary entries, so no step here renders a label. The two steps below
 * are code-evidence-based propagation edges required for the reviewed
 * source-to-sink chains to survive the Python taint model, built strictly per
 * the real source code (each cites its sites); no unconstrained
 * node-to-node propagation is introduced.
 *
 * Steps:
 *  1. pathlibJoinStep     — operand -> result of a `/` (pathlib join) binary
 *                           expression whose join root is a Path(...) constructor
 *                           call or a settings.* path constant.
 *  2. uploadFileNameStep  — tainted upload object -> its `.name` attribute read
 *                           in the two upload-handling modules.
 *
 * Deliberately NOT modeled (documented in report/query_generation_notes.md
 * section 4): urllib.parse.unquote (external stdlib; every unquote chain in
 * pretalx feeds DB lookups, not file APIs), common/utils.py path_with_hash
 * (os.path.join is already a python-all global taint step; the upload_to chain
 * has no reviewed source reachability), the Django form machinery and the
 * @cached_property cfp_session getter (framework-external or
 * decorator-external flow), and the session files dict (no reviewed source on
 * that chain).
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  // --------------------------------------------------------------------------
  // Shared helpers.
  // --------------------------------------------------------------------------

  /**
   * Gets the repository-relative path of the file containing this node, e.g.
   * "src/pretalx/common/views.py". On this Windows-created database
   * getRelativePath() may yield backslash forms or no result, so fall back to
   * capturing the "src/pretalx/..." suffix from the absolute path.
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

  /** Restricts nodes to the pretalx package (excludes tests/migrations/db). */
  private predicate inPretalxPackage(AstNode n) {
    relPath(n).matches("src/pretalx/%") and
    not relPath(n).matches("%/migrations/%")
  }

  // --------------------------------------------------------------------------
  // 1. pathlibJoinStep.
  //
  // Every `/` binary expression in src/pretalx is a pathlib path
  // concatenation; the join roots observed in the real code are either a
  // pathlib constructor call or one of the settings path constants, all of
  // which are Path(...) values by construction:
  //   - common/views.py:52      settings.BASE_DIR / "pretalx/static" / path
  //     (get_static: the reviewed candidate chain to sink K0010)
  //   - export_schedule_html.py:118  Path(destination) / path.lstrip("/")
  //   - export_schedule_html.py:128/130  settings.STATIC_ROOT / url[...] and
  //     settings.MEDIA_ROOT / url[...] (get_mediastatic_content, sink K0013)
  //   - export_schedule_html.py:172  settings.HTMLEXPORT_ROOT / event.slug
  //   - export_schedule_html.py:216  zip_path.parent / zip_path.stem
  //   - cfp/flow.py:188          Path(settings.MEDIA_ROOT) / "cfp_uploads"
  //   - common/tasks.py:91       settings.STATIC_ROOT / local_app / "scss/..."
  //   - settings.py:31-53        BASE_DIR / DATA_DIR / LOG_DIR / MEDIA_ROOT /
  //     STATIC_ROOT / HTMLEXPORT_ROOT are all Path(...) (verified lines 31-53)
  //
  // Why this step is necessary: python-all Stdlib.qll (PathlibPathTaintStep)
  // already propagates taint through `/` when one operand is a type-tracked
  // pathlib Path — but the tracking starts at Path(...) constructor calls in
  // database code, and the settings constants are read through
  // `from django.conf import settings`, which is external to this database.
  // The type tracker therefore cannot reach pretalx/settings.py:31-53, and the
  // get_static join would silently not propagate. This step mirrors the
  // python-all Div rule with a settings-root relaxation, scoped to the pretalx
  // package; the Path(...)-rooted case is kept for self-containment.
  // --------------------------------------------------------------------------
  private predicate pathlibConstructorName(string name) {
    name in ["Path", "PurePath", "PurePosixPath", "PosixPath",
             "PureWindowsPath", "WindowsPath"]
  }

  private predicate settingsPathConstant(string name) {
    // Defined as Path(...) in src/pretalx/settings.py:31-53 (and used as join
    // roots at the sites listed above).
    name in ["BASE_DIR", "DATA_DIR", "LOG_DIR", "MEDIA_ROOT",
             "STATIC_ROOT", "HTMLEXPORT_ROOT"]
  }

  /** Holds if `e` is the left-most root of a pathlib `/` join chain. */
  private predicate joinRoot(Expr e) {
    e instanceof Call and
    e.(Call).getFunc() instanceof Name and
    pathlibConstructorName(e.(Call).getFunc().(Name).getId())
    or
    e instanceof Attribute and
    settingsPathConstant(e.(Attribute).getName()) and
    e.(Attribute).getObject() instanceof Name and
    e.(Attribute).getObject().(Name).getId() = "settings"
    or
    // chained slash: (root / a) / b
    e instanceof BinaryExpr and
    e.(BinaryExpr).getOp() instanceof Div and
    joinRoot(e.(BinaryExpr).getLeft())
  }

  private predicate pathlibJoinStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(BinaryExpr slash |
      inPretalxPackage(slash) and
      slash.getOp() instanceof Div and
      joinRoot(slash.getLeft()) and
      nodeTo.asExpr() = slash and
      (
        nodeFrom.asExpr() = slash.getLeft()
        or
        nodeFrom.asExpr() = slash.getRight()
      )
    )
  }

  // --------------------------------------------------------------------------
  // 2. uploadFileNameStep.
  //
  // Django UploadedFile.name carries the client-supplied multipart filename
  // (Phase 1 labels: request_files evidence, K0030/K0031 rationales). The real
  // sites where a (possibly tainted) upload object's name flows onward:
  //   - common/mixins/forms.py:450  self.get_new_filename(value.name), where
  //     value = self.cleaned_data[name] (source label at :439) — the reviewed
  //     chain to default_storage.save (sink K0030)
  //   - common/mixins/forms.py:478-479  name.split(".")[-1] inside
  //     get_new_filename (the parameter receives value.name from :450)
  //   - cfp/flow.py:266/269  field_file.name in set_files, feeding
  //     file_storage.save (sink K0031)
  //
  // Why this step is necessary: the Python taint model propagates whole-object
  // taint to SUBSCRIPT reads (TaintTrackingPrivate.subscriptStep) but has no
  // equivalent for ATTRIBUTE reads, so `value.name` / `field_file.name` would
  // cut the cleaned_data -> storage.save chain. The step links an object node
  // to its own `.name` attribute read, restricted to the two upload-handling
  // files; it does not create arbitrary cross-object propagation.
  // --------------------------------------------------------------------------
  private predicate uploadFileNameStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Attribute att |
      att.getName() = "name" and
      relPath(att) in ["src/pretalx/common/mixins/forms.py", "src/pretalx/cfp/flow.py"] and
      nodeFrom.asExpr() = att.getObject() and
      nodeTo.asExpr() = att
    )
  }

  /**
   * Holds if taint may step from `nodeFrom` to `nodeTo` for pass 1. `passKey`
   * must be "path_traversal".
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and
    (
      pathlibJoinStep(nodeFrom, nodeTo)
      or uploadFileNameStep(nodeFrom, nodeTo)
    )
  }
}
