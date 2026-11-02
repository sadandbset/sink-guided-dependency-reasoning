/*
 * Augur generated sanitizer (barrier) library - Pass 1 (Path Traversal),
 * Zope 5.2.dev0.  Machine-generated from the reviewed Pass 1 labeling run
 * (zope-iris-pass1-step3-20261024, model glm-5.3, reviewed 2026-10-24).
 * Do not edit by hand: regenerate from labels instead.
 *
 * labels.json contains ZERO entries with role "sanitizer" (none of the
 * extracted candidates is a proven neutralizer).  The single barrier below
 * implements the import-name guard documented in the reviewed Step 3 human-
 * review payload labels/phase1_review.md section 5 ("Sanitizer list - the
 * real guard layer ... for Phase 2 MySanitizers consideration"), so no
 * unreviewed sanitizer is invented here.
 *
 * Guards that were considered and deliberately NOT modeled as barriers:
 *  - OFS/ObjectManager.py:84-115 checkValidId - does NOT reject '/' or
 *    embedded '..' components, so it does not block the manage_exportObject
 *    clienthome join (kept non-barrier on purpose).
 *  - OFS/Image.py:1002-1010 cookId basename extraction - proven for '/', '\',
 *    ':' but its output only feeds ZODB object ids, which have no filesystem
 *    sink in this model; no barrier edge is needed.
 *  - App/Extensions.py:92-95 / :47-54 getPath guards - no source-to-sink path
 *    reaches them (config boundary); no barrier edge is needed.
 *  - webdav/NullResource.py lock checks / _verifyObjectPaste - ZODB-level
 *    authorization, not path neutralization.
 *  - No normpath/realpath/abspath/startswith/basename usage exists on any
 *    request-derived path in this repo (only module-level realpath of fixed
 *    prefixes: App/ImageFile.py:32, App/special_dtml.py:40,
 *    App/FindHomes.py:23-25), so none is treated as a sanitizer.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {

  /** Holds if `node` is a Pass 1 (path traversal) taint barrier. */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and isImportFileNameGuardBarrier(node)
  }

  /**
   * The os.path.split dirname rejection in ObjectManager.manage_importObject
   * (OFS/ObjectManager.py:639-641):
   *
   *   dirname, file = os.path.split(file)
   *   if dirname:
   *       raise BadRequest('Invalid file name %s' % html.escape(file, True))
   *
   * Proven in source to block the modeled mechanism: every name that contains
   * a path separator is rejected before the join at :644 and the
   * connection.importFile open at :679; the degenerate '..' resolves to the
   * fixed import directory itself (instancehome/clienthome + 'import',
   * :695-701) where the subsequent open fails.  Taint reaches this call's
   * result through the standard library's os.path.split propagation step
   * (codeql/python-all Stdlib.qll OsPathComputationAdditionalTaintStep); the
   * barrier prunes the path at the call result, modeling "the guarded
   * reassignment of `file` is separator-free".
   *
   * Documented residual risks (kept as manual-review notes, NOT modeled as
   * safe, see report/query_generation_notes.md): on Windows a drive-relative
   * name ('C:x') passes ntpath.split with an empty dirname while
   * os.path.join resets to the drive, and the existence check at :645 is
   * separated from the importFile open at :679 by a TOCTOU window.
   */
  private predicate isImportFileNameGuardBarrier(DataFlow::Node node) {
    exists(Call c |
      node.asExpr() = c and
      isOsPathFuncCall(c, "split") and
      c.getLocation().getFile().getBaseName() = "ObjectManager.py" and
      c.getScope().(Function).getName() = "manage_importObject"
    )
  }

  /** Holds if `c` is a call to os.path.<fname>(...). */
  private predicate isOsPathFuncCall(Call c, string fname) {
    exists(Attribute outer, Attribute inner |
      c.getFunc() = outer and
      outer.getName() = fname and
      outer.getObject() = inner and
      inner.getName() = "path" and
      inner.getObject() instanceof Name and
      inner.getObject().(Name).getId() = "os"
    )
  }
}
