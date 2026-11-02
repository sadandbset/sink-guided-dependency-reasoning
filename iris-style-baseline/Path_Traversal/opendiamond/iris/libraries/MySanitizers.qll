/**
 * Augur Phase 2 - Pass 1 sanitizer / barrier models (machine-generated from
 * reviewed labels).
 *
 * Generated from: iris/labels/labels.json, pass 1 (Path Traversal,
 * CWE-022/023/036/073), run opendiamond-pass1-labeling-20261022, model glm-5.3.
 *
 * Reviewed sanitizer labels: **1 entry** -
 * K-dataretriever_augment_store-156-safe_join (sanitizer/tp/0.9):
 * werkzeug.utils.safe_join(DATAROOT, obj_path) at augment_store.py:156.
 *
 * Why this one IS a real barrier (verified against the real source, not
 * assumed from its function name):
 *
 *  1. augment_store.py:27 imports safe_join from werkzeug.utils, and
 *     _get_obj_absolute_path (augment_store.py:155-156) routes EVERY
 *     augment_store channel through it before any file use:
 *       get_scope rootdir  -> create_index joins/opens under the result;
 *       /id/<path:object_path>   -> result used in XML/file URI text only;
 *       /obj/<path:obj_path>     -> send_file(path) at :165.
 *  2. werkzeug's safe_join semantics ("safely join untrusted path segments
 *     to a base directory"): an absolute filename or any '..' segment that
 *     would escape the base directory is rejected (posixpath.normpath-based
 *     containment; the routing context raises NotFound). Both escape
 *     mechanisms of this project's confirmed CWE-22 channels (absolute
 *     replacement and '..' climbing via os.path.join) are blocked HERE and
 *     nowhere else in the dataretriever.
 *  3. Barrier placement: the safe_join CALL RESULT node. Taint reaching the
 *     call's arguments cannot pass to the send_file/open sinks through the
 *     call result. werkzeug is external to this database, so by default its
 *     arguments do not taint the call result anyway; the barrier additionally
 *     cuts the flow in case any pack model propagates argument taint through
 *     safe_join.
 *
 * Recorded caveats (also in the label rationale and
 * report/query_generation_notes.md):
 *  - symlinks inside DATAROOT are not resolved by safe_join; a symlink
 *    planted under the declared root can still point outside it
 *    (werkzeug-documented limitation);
 *  - every other dataretriever store builds paths with a bare
 *    os.path.join(DATAROOT, user_path) - no containment of any kind.
 *
 * Candidates examined and deliberately NOT barriers (none can be assumed
 * from its function name; each was checked against the real code):
 *  - 'GIDIDX' + gididx.upper() prefix plus the no-'/' string converter
 *    (diamond/mixer/test/video index files): incidental constraint on index
 *    names, not a sanitizer - and the gididx/baseidx params are not sources
 *    anyway;
 *  - Tornado route regexes ([0-9a-f]{64}) and Django @permission_required /
 *    blaster @_restricted: attacker-population limits, not path-content
 *    filters (django.md section 8);
 *  - ScopeCookie signature verification (scope.py:96-136): authorization of
 *    the cookie issuer, not validation of object URI path content;
 *  - os.path.isfile/exists/isdir checks: existence gates and TOCTOU windows,
 *    not path restrictions;
 *  - helpers.split_scheme (urlparse split, no decoding - no double-decode
 *    hazard, but also no filtering);
 *  - sig.lower()/gididx.upper(): case folding, no normalization;
 *  - classes.replace('%2C', ...) in mixer_store.py:177/:206: result
 *    discarded (no-op bug), and string replace would not be a containment
 *    anyway;
 *  - os.path.normpath/realpath/basename/startswith: none of these appear as
 *    guards anywhere in the audited code (verified by label review), so none
 *    is mechanically treated as a sanitizer.
 *
 * WORKFLOW.md rule 6 / 5.2.3: the isBarrier hook must exist; queries wire
 * `predicate isBarrier(DataFlow::Node n)` through this module.
 *
 * Pass key: "path_traversal".
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /**
   * Holds if `node` blocks pass-1 taint for the given pass key.
   *
   * The single confirmed barrier is the safe_join call node in
   * augment_store.py:156 (label K-dataretriever_augment_store-156-safe_join,
   * tp 0.9) - see the file header for the containment evidence and the
   * symlink caveat.
   */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and
    isSafeJoinBarrier(node)
  }

  /**
   * The safe_join(DATAROOT, obj_path) call result in augment_store.py:156.
   *
   * augment_store.py imports safe_join directly
   * (`from werkzeug.utils import safe_join`, augment_store.py:27), so the
   * callee is a plain Name. Verified: augment_store.py:156 is the only
   * safe_join call site in the audit scope.
   */
  private predicate isSafeJoinBarrier(DataFlow::Node node) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = "safe_join" and
      c.getLocation().getFile().getAbsolutePath()
        .matches("%/opendiamond/dataretriever/augment_store.py") and
      node = DataFlow::exprNode(c)
    )
  }
}
