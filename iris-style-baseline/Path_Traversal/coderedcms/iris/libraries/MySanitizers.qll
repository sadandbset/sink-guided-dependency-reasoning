/**
 * Augur Phase 2 - Pass 1 sanitizer / barrier models (machine-generated from
 * reviewed labels).
 *
 * Generated from: iris/labels/labels.json, pass 1 (Path Traversal,
 * CWE-022/023/036/073), run coderedcms-pass1-labeling-20261021, model glm-5.3.
 *
 * Reviewed sanitizer labels: **0 entries** - no barrier is emitted.
 *
 * Evidence (why no sanitizer is modeled - each checked against the real
 * source, none can be assumed from its function name):
 *
 *  1. coderedcms/views.py:110-123 serve_protected_file: NO traversal
 *     containment of any kind - no base-directory containment check, no
 *     '..' rejection, no normpath/realpath comparison, no basename
 *     extraction, no startswith(base) check, no safe_join between the
 *     os.path.join at :114 and the open() at :117.
 *  2. coderedcms/forms.py:60-74 SecureFileField whitelist/blacklist uses
 *     os.path.splitext(value.name)[1] - extension-ONLY validation: it
 *     constrains the filename suffix, not path separators, '..' segments or
 *     absolute names. Not a traversal barrier (reviewed labels
 *     K-forms-68-splitext / K-forms-73-splitext are summary entries with an
 *     explicit non-sanitizer note).
 *  3. coderedcms/views.py:115 os.path.isfile - existence gate (and a TOCTOU
 *     window), not a path restriction.
 *  4. @login_required / wagtail-admin permissions limit the attacker
 *     population, not the path content (django.md section 8: contextual,
 *     not sanitization).
 *  5. No symlink/realpath handling exists anywhere in the project's own
 *     code (no normpath, realpath, resolve-then-compare, os.path.basename
 *     guard or startswith guard on any path flowing to a file API).
 *
 * WORKFLOW.md rule 6 / 5.2.3: the isBarrier hook must exist even when empty;
 * queries keep `predicate isBarrier(DataFlow::Node n) { none() }` wiring via
 * this module.
 *
 * Pass key: "path_traversal".
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /**
   * Holds if `node` blocks pass-1 taint for the given pass key.
   *
   * Resolves to none() for pass 1: zero sanitizer entries were confirmed by
   * the reviewed labels, and the candidate barriers examined in the real
   * source (extension whitelist/blacklist, isfile existence check,
   * login_required, splitext) demonstrably do NOT block the traversal
   * mechanisms present in this codebase (see file header). No normpath/
   * resolve/basename/startswith check was mechanically treated as safe.
   */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and
    noConfirmedSanitizer(node)
  }

  /** Deliberately empty: see file header for the per-candidate evidence. */
  private predicate noConfirmedSanitizer(DataFlow::Node node) { none() }
}
