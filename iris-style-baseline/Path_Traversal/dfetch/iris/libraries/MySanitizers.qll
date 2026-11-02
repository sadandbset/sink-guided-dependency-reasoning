/**
 * Augur Phase 2 Step 4 - Pass 1 (Path Traversal) sanitizer library for dfetch.
 *
 * Deterministically rendered from iris/labels/labels.json (run
 * iris-dfetch-pathtraversal-pass1-20261022): the reviewed pass-1 label set
 * contains ZERO `sanitizer` entries, and this library reflects that exactly.
 *
 * Why no barrier exists (verified against the dfetch source tree, per
 * labels/phase1_review.md section 3 and the per-row label evidence):
 *
 *  - pykwalify manifest validation (dfetch/manifest/validate.py against
 *    dfetch/resources/schema.yaml) is type/structure-only: `dst` is an
 *    unrestricted unique str, `patch` an unrestricted str, `src` type ANY -
 *    no '..', absolute-path, separator or charset constraint. Absolute
 *    paths, '..' components and mixed separators all pass validation.
 *  - os.path.realpath (metadata.py:129/:132, manifest.py:247/:270) is used
 *    purely for normalization; the result is never compared against an
 *    allowed base directory, so it cannot block any escape.
 *  - The single relative_to (manifest.py:274) builds a display/error prefix
 *    only; a non-relative path raises ValueError that is NOT caught by
 *    prefix_runtime_exceptions (RuntimeError only) - loud failure, not
 *    sanitization; and it constrains walked manifest paths, never dst/src/
 *    patch.
 *  - The single basename (metadata.py:131) neutralizes only the FILENAME
 *    component of the sibling metadata path; the containing directory
 *    (dirname(dst)) stays attacker-controlled, so traversal through the
 *    directory part is unaffected.
 *  - No os.path.islink / lexists / normpath / abspath anywhere; every
 *    startswith in the tree matches URLs or git refs, never a path prefix
 *    against a base directory.
 *  - The only content restriction on 'src' (single '*' check,
 *    svn.py:227-236) does not block '..' or absolute paths.
 *  - CWD scoping via in_directory/os.chdir (util.py:47-54) is itself a
 *    reviewed SINK (sink-083): chdir cannot confine an absolute or
 *    '..'-escaping destination.
 *
 * isBarrier therefore resolves to none() (the WORKFLOW.md section 5.2.3
 * mandated empty fallback). No path node is treated as a barrier, so no
 * real flow can be suppressed by this library.
 */

import python

import semmle.python.dataflow.new.DataFlow

module MySanitizers {

  /** Pass-1 barrier predicate: always empty - no reviewed sanitizer exists
   *  for path_traversal in the dfetch label set. The passKey parameter is
   *  accepted for interface uniformity with MySources/MySinks/MySummaries. */
  predicate isBarrier(DataFlow::Node node, string passKey) { none() }
}
