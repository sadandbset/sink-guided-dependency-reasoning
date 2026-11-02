/**
 * Augur Pass 1 (Path Traversal) barrier model for xmpp-http-upload.
 *
 * Generated deterministically from the reviewed Pass 1 labels in
 * iris/labels/labels.json: ZERO entries have role=sanitizer, so this
 * model is intentionally empty (WORKFLOW.md §5.2.3 requires the
 * isBarrier hook to exist even when it resolves to nothing).
 *
 * Why there is no barrier, verified against the real source:
 *
 * 1. The single containment guard, sanitized_join (xhu.py:42-46):
 *
 *      def sanitized_join(path: str, root: pathlib.Path) -> pathlib.Path:
 *          result = (root / path).absolute()
 *          if not str(result).startswith(str(root) + "/"):
 *              raise ValueError("resulting path is outside root")
 *          return result
 *
 *    is a LEXICAL prefix check on an UN-normalized path.
 *    pathlib.Path.absolute() makes the path absolute WITHOUT
 *    normalizing ".." segments and WITHOUT resolving symlinks (CPython
 *    docs: "Make the path absolute, without normalization or
 *    resolving symlinks" - resolve() is the normalizing API and is
 *    never called anywhere in xhu.py). The Werkzeug `path` converter
 *    (regex [^/].*?) always yields a RELATIVE string, so
 *    (root / path) is a purely textual join whose str() begins with
 *    str(root) + "/" for EVERY converter-supplied request path - the
 *    guard is textually satisfied even when the path contains "../"
 *    segments, which the OS then resolves at the later open/stat/
 *    mkdir/unlink/send_file time outside the declared DATA_ROOT. It
 *    does not block the CWE-22 mechanism of this pass, so the
 *    reviewed labels classify it role=summary (labels/labels.json
 *    sink-005: "marking this a barrier would suppress the genuine
 *    traversal flow") and this model does not promote it.
 *
 * 2. Path.absolute() (xhu.py:43, label sink-007 role=none): not a
 *    normalizer (no ".." collapse, no symlink resolution) - it cannot
 *    be a barrier, it just passes the path content through.
 *
 * 3. No resolve()/realpath()/normpath()/basename() extraction, no
 *    fixed-filename mapping, no strict allowlist, and no ".."-
 *    rejection exists anywhere between the route parameter
 *    (xhu.py:105/:190/:215) and the file accesses (:57/:76/:80/:137/
 *    :144/:197/:228) - mechanically treating prefix checks or
 *    normalization-sounding helpers as safe filters is exactly what
 *    the reviewed labels reject. The HMAC gate (xhu.py:118-130) is an
 *    authentication decision over the exact path+length (PUT side
 *    only), not a path-containment mechanism; and the exclusive-create
 *    modes "xb"/"x" with EEXIST->409 (:157-163) limit overwrite
 *    semantics, not redirection or traversal.
 *
 * Consequence for Step 6: alert paths that "pass" the startswith
 * guard are the expected findings for this target, not false
 * positives to be cut; the generic "explicit startswith guard -> FP"
 * heuristic must not be applied to this project's findings without
 * checking for normalization (recorded in labels/phase1_review.md §4).
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
