/**
 * Machine-generated from iris/labels/labels.json (Pass 1 - Path Traversal),
 * run flask-cors-path-traversal-pass1-20261022, model glm-5.3.
 * DO NOT EDIT BY HAND - regenerate from labels instead (WORKFLOW.md 5.1.4).
 *
 * Sanitizer labels rendered here: NONE (labels.json carries 0 entries with
 * role=sanitizer). Per WORKFLOW.md rule 6 and 5.2.3 the isBarrier hook must
 * exist even when empty, so the predicate is defined with none() fallback
 * behavior.
 *
 * Why no barrier can be justified from the real source (each candidate
 * mechanism was examined and rejected):
 *
 *   - No allowed-root-directory containment exists anywhere: the audited code
 *     performs no file serving, so there is no declared root to confine to
 *     (no startswith(base) check, no Path.relative_to(), no realpath-equals
 *     check, no fixed-filename mapping, no whitelist).
 *   - os.path.abspath (examples/*.py:17, docs/conf.py:21) is canonicalization
 *     WITHOUT base-directory containment and operates on constant __file__
 *     inputs - a function name alone is not evidence of neutralization.
 *   - os.path.dirname is component extraction, not a traversal filter.
 *   - try_match / try_match_any (flask_cors/core.py:271-285) regex/string
 *     matching is a CORS-options allow-check on request.path; it never guards
 *     a filesystem path (no file API is downstream of it), so it neither needs
 *     to be nor functions as a path barrier.
 *   - Symlinks / TOCTOU: not applicable - no symlink resolution and no
 *     check-then-use file sequence exists anywhere in the snapshot (zero
 *     filesystem access in the flask_cors package).
 *
 * Expected effect on results: none. Since no source-to-sink path exists in
 * this codebase (sources terminate in regex matching / logging / response
 * headers; sinks sit behind constant paths in setup.py), the empty barrier
 * set cannot introduce false positives; it would only matter if a future
 * taint path reached the open() sink argument.
 */

import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /** Barrier nodes filtered by pass key. No sanitizer labels exist for pass "path_traversal". */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    none()
  }
}
