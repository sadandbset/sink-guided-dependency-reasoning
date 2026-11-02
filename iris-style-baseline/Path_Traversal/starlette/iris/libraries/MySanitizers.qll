/**
 * Name: MySanitizers
 * Description: Barrier (sanitizer) predicates for the Augur IRIS pipeline,
 *   rendered from iris/labels/labels.json (Pass 1, pass key
 *   "path_traversal", starlette 0.26.1 / starlette_vuln).
 *
 * Pass 1 has exactly ONE sanitizer-shaped candidate in the reviewed labels:
 *
 *   p1-k-037  os.path.commonprefix  staticfiles.py:172
 *             role=sanitizer, classification=candidate, confidence 0.45
 *
 * It is deliberately NOT emitted as a barrier. The reviewed label and the
 * Phase-1 review (iris/labels/phase1_review.md section 4) concluded that
 * this guard is PARTIAL and cannot be proven to block the path-escape
 * mechanisms in this specific implementation:
 *
 *   1. os.path.commonprefix is a pure CHARACTER-prefix comparison, not
 *      path-component-aware: a sibling directory sharing a textual prefix
 *      (base '/static' vs sibling '/static-evil', request
 *      '../static-evil/x') passes commonprefix([full_path, directory]) ==
 *      directory and escapes the declared root (staticfiles.py:170-175).
 *   2. The guard is not applied AT ALL on the follow_symlink=True branch
 *      (staticfiles.py:167-168 uses os.path.abspath only) - the request
 *      path is never containment-checked before stat/open on that branch.
 *   3. TOCTOU: the check (staticfiles.py:170-177) and the re-stat/open in
 *      FileResponse.__call__ (responses.py:335/353, executed later in a
 *      thread) leave a symlink-swap window.
 *
 * Emitting it as an isBarrier would also suppress the genuine bypass flow
 * from scope['path'] (staticfiles.py:111) to anyio.open_file
 * (responses.py:353). Per the Augur contract ("mark sanitizers only with
 * concrete evidence"; "keep an isBarrier predicate in query configs even
 * when empty"), the predicate therefore resolves to none() for this pass.
 * A human reviewer may revisit this decision (see
 * report/query_generation_notes.md).
 *
 * Note: normpath (staticfiles.py:111), realpath (:170), abspath (:168) and
 * basename-style transforms were reviewed and are NOT sanitizers either:
 * normpath collapses '..'/'.' components but the collapsed result can
 * remain an upward-relative path ('a/../..' -> '..') that escapes when
 * joined onto the base directory; they are modeled as taint-preserving
 * summary steps in MySummaries.qll instead.
 *
 * Generated: 2026-10-23, Augur Phase 2 Step 4 (labels v1.0.0,
 * run starlette-pathtraversal-pass1-step3-20261023, model glm-5.3).
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /**
   * Holds if data flow through `node` is prohibited (pass-1 path_traversal).
   * Intentionally empty: no sanitizer in the reviewed labels could be proven
   * to block the escape mechanisms (see the module documentation).
   */
  predicate isBarrier(DataFlow::Node node, string passKey) { none() }
}
