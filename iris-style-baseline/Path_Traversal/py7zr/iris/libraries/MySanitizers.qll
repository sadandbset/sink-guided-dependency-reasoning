/**
 * Augur Pass 1 (Path Traversal) barrier model for py7zr.
 *
 * Generated deterministically from the reviewed Pass 1 labels in
 * iris/labels/labels.json: ZERO entries have role=sanitizer, so this
 * model is intentionally empty (WORKFLOW.md §5.2.3 requires the
 * isBarrier hook to exist even when it resolves to nothing).
 *
 * Why there is no barrier, verified against the real source:
 *
 * 1. The base-containment guards at py7zr.py:576-586
 *      try:
 *        pathlib.Path(os.getcwd()).joinpath(remove_relative_path_marker(outname)).relative_to(os.getcwd())
 *      except ValueError:
 *        raise Bad7zFile
 *      ...
 *      outfilename = path.joinpath(remove_relative_path_marker(outname))
 *      try:
 *        outfilename.relative_to(path)
 *      except ValueError:
 *        raise Bad7zFile
 *    are LEXICAL prefix checks. CPython pathlib preserves ".." as a
 *    literal path part and never canonicalizes it, so
 *    Path(cwd).joinpath("../../../evil").relative_to(cwd) returns
 *    "..\..\..\evil" WITHOUT raising (verified on CPython 3.14.4 during
 *    Step 3; recorded in labels/phase1_review.md §3). Only absolute-path
 *    replacement (joinpath("/abs") or a different drive) raises
 *    ValueError -> Bad7zFile. Modeling these as barriers would sever the
 *    real traversal flow, so the reviewed labels classify them role=none
 *    (classification fp) and this model does not promote them.
 *
 * 2. remove_relative_path_marker (helpers.py:424-433) strips only ONE
 *    leading "./" - it does not reject "..", absolute paths, drive
 *    letters or embedded separators. Reviewed label: role=summary
 *    (taint-preserving wrapper), not a sanitizer.
 *
 * 3. No resolve()/realpath()/basename mapping/whitelist exists anywhere
 *    between the entry-name decode (archiveinfo.py:757) and the file
 *    access (py7zr.py:1328-1357): mechanically treating normpath-style
 *    helpers as safe filters is exactly what the reviewed labels reject.
 *
 * Unified pass key: "path_traversal" (CWE-022/023/036/073).
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /**
   * Holds if `node` is a reviewed Pass 1 barrier for pass key `passKey`.
   * No sanitizer label survived review for this pass, so this always
   * fails - kept as the mandatory (possibly empty) barrier hook.
   */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and none()
  }
}
