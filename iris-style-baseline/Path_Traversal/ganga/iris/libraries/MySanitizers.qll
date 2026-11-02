/**
 * Augur Phase 2 Step 4 - Pass 1 (Path Traversal) sanitizer library for ganga.
 *
 * Deterministically rendered from the reviewed Pass 1 labels in
 * iris/labels/labels.json (run iris-ganga-pathtraversal-pass1-20261022):
 * the reviewed pass-1 label set contains exactly ONE sanitizer entry with
 * classification=tp, and this library models it - and only it:
 *
 *   sink-799 (sanitizer/tp 0.90): the secure_filename(storagefile.filename)
 *     CALL NODE at GangaGUI/gui/routes.py:953.
 *
 * One sanitizer candidate was reviewed and REJECTED (classification=fp)
 * and is NOT rendered as a barrier:
 *
 *   sink-816 (sanitizer/fp 0.85): allowed_file(filename) at
 *     GangaGUI/gui/routes.py:1799.
 *
 * Why allowed_file cannot be a barrier (verified against the real source;
 * per labels/phase1_review.md section 2):
 *
 *   gui/routes.py:1799-1800:
 *     def allowed_file(filename):
 *       return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
 *
 *   - It constrains only the file EXTENSION (ALLOWED_EXTENSIONS =
 *     {"txt", "py"}, gui/routes.py:94), never path components: a
 *     "../x.py" payload passes.
 *   - It is applied only to the loadfile/runfile upload channels
 *     (gui/routes.py:300/:326), whose save paths are the FIXED
 *     UPLOAD_FOLDER/loadfile.txt and runfile.py (:301/:327) - never to the
 *     storage channel where the confirmed write traversal lives.
 *   - Rendering it as isBarrier would suggest the upload channels are
 *     path-contained; the reviewed labels explicitly record this
 *     instruction.
 *
 * No other neutralization exists anywhere on the confirmed chains (no
 * canonicalize-then-contain, no resolve()/realpath + relative_to, no
 * startswith(base) prefix check, no explicit ".." rejection, no basename
 * extraction, no separator whitelist) - per labels/label_stats.md
 * "Sanitizers: 1 confirmed". In particular:
 *
 *   - os.path.join (gui/routes.py:659/:934/:954) does NOT neutralize: it
 *     keeps ".." segments lexically and an absolute argument REPLACES the
 *     base (modeled as the reviewed taint steps in MySummaries.qll, not
 *     as barriers);
 *   - Persistency fullpath (abspath/expandvars/expanduser, :140) is
 *     normalization WITHOUT containment - abspath COLLAPSES ".." (so it
 *     actively defeats any lexical pre-check) but never confines the
 *     result to a base directory - modeled as a taint step, not a barrier;
 *   - Runtime getScriptPath (:28) returns the expanded attacker name
 *     VERBATIM when os.path.exists succeeds - taint step, not a barrier.
 *
 * Symlinks: no symlink creation or link-following policy exists on any
 * confirmed chain, and the job/storage roots are not attacker-writable
 * via the audited flows; symlink/TOCTOU neutralization is recorded as not
 * applicable/not observed (labels/labels.json metadata note).
 */

import python

import semmle.python.dataflow.new.DataFlow

module MySanitizers {

  /** Forward-slash-normalized absolute path of the file containing n
   *  (same helper shape as the other three libraries). */
  private string normalizedPathOf(AstNode n) {
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
  }

  bindingset[modulePathPattern]
  private predicate inModule(AstNode n, string modulePathPattern) {
    normalizedPathOf(n).matches(modulePathPattern)
  }

  /**
   * Holds if data flow through `node` is prohibited for pass key `passKey`.
   *
   * Exactly one barrier is modeled: the secure_filename call node at
   * gui/routes.py:953. It is anchored on the CALL EXPRESSION (the value
   * produced by secure_filename(...)), which is the node the tainted
   * filename component must pass through on its way to the join at :954 -
   * removing that node cuts precisely the sanitized component.
   *
   * Scope proof (why this barrier cannot suppress a confirmed finding):
   * the CONFIRMED write traversal flows route-path (source src-069) ->
   * join :934 argument 1 -> join result -> join :954 argument 0 ->
   * storagefile.save :955 - none of these nodes is the secure_filename
   * call, and the tainted directory component never passes through it.
   * Only the filename component (source src-072 -> secure_filename call)
   * is cut, which is exactly the neutralization the reviewed labels
   * describe.
   */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and
    exists(Call c |
      node.asExpr() = c and
      inModule(c, "%/ganga/GangaGUI/gui/routes.py") and
      c.getLocation().getStartLine() = 953 and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "secure_filename"
    )
  }
}
