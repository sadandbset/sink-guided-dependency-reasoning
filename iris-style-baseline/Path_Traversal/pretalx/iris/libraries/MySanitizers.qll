/**
 * Augur Phase 2 Step 4 — Pass 1 (Path Traversal) sanitizer/barrier model for
 * pretalx.
 *
 * Machine-generated from iris/labels/labels.json (run
 * pretalx-pathtraversal-pass1-20261022, pass_id 1): the pass contains ZERO
 * role=sanitizer entries, so the barrier predicate resolves to none().
 *
 * This is an evidence-based result, not an omission:
 *
 *  1. grep-verified during Phase 1 (exploration/detection.json,
 *     toctou_and_containment_evidence): pretalx's own source contains no
 *     safe_join, get_valid_filename, basename, abspath, normpath, realpath or
 *     relative_to path guard anywhere in src/pretalx. The only .resolve() use
 *     is a static locale path (settings.py:348). No base-directory containment
 *     check, no leading-'..' rejection and no fixed-filename mapping exists on
 *     any path that reaches a file API.
 *
 *  2. The mechanisms that DO constrain specific inputs are framework-side and
 *     outside this CodeQL DB, so they cannot be expressed as node barriers:
 *     - Django URL converters (<int:pk> = [0-9]+, <slug:event> = [-a-zA-Z0-9_]+)
 *       neutralize traversal payloads for those route parameters. These are
 *       modeled at the SOURCE level (the affected parameters are not sources,
 *       labels classification=fp), not as barriers.
 *     - Django-internal upload name validation (multipart filename basename,
 *       Storage.validate_file_name, FileSystemStorage safe_join; Django
 *       ~=3.2.0 pinned in src/setup.py:101) is expected to contain the storage
 *       save/open/delete sinks (K0016/K0030-K0033) — unverifiable from this
 *       database, which is why those labels stay candidate instead of being
 *     barrier-suppressed.
 *
 *  3. Nothing is accepted as a barrier by function name: common/utils.py:132
 *     safe_filename() (unicodedata NFD ASCII fold) and
 *     Storage().get_valid_name() (agenda/views/speaker.py:129) are used only
 *     for Content-Disposition headers, never in front of a file access;
 *     url.lstrip("/") (export_schedule_html.py:118) strips only leading
 *     slashes and demonstrably does NOT block '..' components.
 *
 * The predicate is kept in the interface (WORKFLOW.md 3.6: every query config
 * must define isBarrier even when empty) and deliberately returns none().
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /**
   * Holds if flow through `n` is prohibited for pass 1. `passKey` must be
   * "path_traversal". No pretalx-own path guard exists (see file header), so
   * no barrier is modeled and this predicate always fails.
   */
  predicate isBarrier(DataFlow::Node n, string passKey) {
    none()
  }
}
