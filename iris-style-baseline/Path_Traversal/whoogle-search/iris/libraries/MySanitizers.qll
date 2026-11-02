/**
 * Augur / IRIS generated sanitizer library — whoogle-search, pass 1 (path_traversal).
 *
 * Rendered deterministically from the reviewed Phase 1 labels
 * (iris/labels/labels.json, pass_id 1): the pass contains ZERO sanitizer
 * entries, and the source tree confirms why —
 *
 *   - no base-directory containment exists: between
 *     request.args.get('name') (app/routes.py:429/:447) and
 *     open(os.path.join(app.config['CONFIG_PATH'], name)) (app/routes.py:430/:445)
 *     there is no startswith(base-dir) check, no canonicalize-and-compare, no
 *     relative_to() containment, no realpath/normpath normalization, no
 *     basename-only extraction and no '..' rejection anywhere in app/
 *     (verified against the audited tree);
 *   - os.path.exists (app/routes.py:431), os.path.getsize (app/routes.py:100)
 *     and os.path.isfile (app/request.py:48) are existence/size probes, not
 *     neutralization — modeling them as barriers would be a mechanical
 *     "function name looks safe" assumption with no blocking proof;
 *   - os.path.join is a taint-preserving construction step (see MySummaries),
 *     not a filter;
 *   - no allowlist/blocked-pattern check is applied to the 'name' value.
 *
 * isBarrier therefore resolves to none() for every pass key. The predicate is
 * kept (WORKFLOW.md §5.2.3 requires the barrier hook even when empty) and the
 * pass query wires it into Pass1Config::isBarrier.
 *
 * Machine-generated; do not hand-edit without re-running the label review.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /**
   * No reviewed label with role "sanitizer" exists for pass 1, and no
   * containment check exists in the audited source. Returns no results for
   * every pass key by design.
   */
  predicate isBarrier(DataFlow::Node n, string passKey) { none() }
}
