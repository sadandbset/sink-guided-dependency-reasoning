/**
 * Augur Phase 2 Step 4 — Pass 1 (Path Traversal) sanitizer/barrier model for
 * pyramid.
 *
 * Machine-generated from iris/labels/labels.json (run
 * pyramid-pass1-pathtraversal-20261023, pass_id 1): the pass contains TWO
 * role=sanitizer entries (A001, A002, both classification tp), and both are
 * rendered as barriers.
 *
 *  A001 _secure_path (static.py:276, conf 0.95):
 *      The static-view path guard. Proven in source (static.py:263-285):
 *      it rejects any path element in {'..', '.', ''} AND any element
 *      containing '/' or os.sep (_seps = {'/', os.sep}; _contains_slash),
 *      returning None, which the caller turns into
 *      HTTPNotFound('Out of bounds') (static.py:136-137). It executes BEFORE
 *      every use of the request-derived path: before the package-mode
 *      resource_path construction (:141) and the filesystem-mode
 *      normcase(normpath(join(norm_docroot, path))) (:152), and before
 *      find_resource_path's resource_exists/resource_filename (:167-168),
 *      which feed FileResponse (static.py:112) and its open (response.py:57).
 *      Mechanisms blocked:
 *        - '..' traversal elements (both raw and split-resolved inputs; the
 *          guard is belt-and-suspenders over traversal_path/split_path_info)
 *        - '.' and empty elements
 *        - absolute paths and ANY separator injection: no element may
 *          contain '/' or os.sep, so join()/`'%s/%s'` always remain under
 *          the docroot prefix; on Windows backslash separators are rejected
 *          explicitly (os.sep = '\\'), on POSIX a '\\' inside a single
 *          element is a literal filename character, not a separator
 *        - lru_cache does not weaken it: inputs are immutable tuples and the
 *          function is pure (static.py:275)
 *      Barrier node: the _secure_path CALL RESULT at static.py:134 — every
 *      downstream use of the request-derived path reads the value produced
 *      by this call, so blocking flow through it cuts the guarded Chain A
 *      from all sinks.
 *
 *  A002 split_path_info (traversal.py:510, conf 0.9):
 *      Lexical normalization during URL path splitting (traversal.py:513-523):
 *      drops '' and '.' segments and resolves '..' by popping the preceding
 *      segment (a leading '..' with an empty stack is dropped as well), so
 *      its output tuple contains no '..', '.' or '' elements, and elements
 *      cannot contain '/' (the input is split on '/'). It runs at ingress on
 *      every PATH_INFO-derived string before the segments become
 *      request.subpath / traversed / vroot tuples (call sites
 *      traversal.py:506 inside traversal_path_info, :613, :632, :655, and
 *      urldispatch.py:192 for route pattern values). Barrier nodes: the
 *      split_path_info CALL RESULTS within the extraction scope.
 *      Known limitation (documented, not a soundness gap for this pass): a
 *      literal os.sep ('\\' on Windows) inside one input segment survives
 *      splitting; every FILE-ACCESS use of such a tuple in this repo passes
 *      through _secure_path (A001) anyway, which rejects
 *      separator-containing elements. The traverser's __getitem__ tree walk
 *      has no file sink in this repo.
 *
 * NOT modeled as barriers (each checked against the concrete implementation,
 * per the rule that no function is accepted as a sanitizer by name):
 *  - os.path.realpath (i18n.py:192/198/201): canonicalizes and resolves
 *    symlinks but performs no containment — it does not reject '..' and does
 *    not enforce a base directory (labels K037-K039 role=none; it is a
 *    propagation step in MySummaries.qll instead).
 *  - os.path.normpath / normcase (static.py:98/152): pure lexical
 *    normalization; on its own it does not contain anything (it is the join
 *    side of the guard, safe only in combination with A001).
 *  - DirectoryOverride startswith prefix matching (config/assets.py:190):
 *    config-time override routing, not a pre-use guard on request paths.
 *  - isdir/isfile existence checks (i18n.py:193/198/202): existence gates,
 *    not validation — they are modeled as sinks (oracles), not barriers.
 */
import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /**
   * Gets the repository-relative path of the file containing this node, e.g.
   * "src/pyramid/static.py". On this Windows-created database
   * getRelativePath() may yield backslash forms or no result, so fall back to
   * capturing the "src/pyramid/..." suffix from the absolute path.
   */
  private string relPath(AstNode n) {
    exists(string p |
      p = n.getLocation().getFile().getRelativePath() and
      result = p.replaceAll("\\", "/")
    )
    or
    not exists(string rel | rel = n.getLocation().getFile().getRelativePath()) and
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/").regexpCapture(".*/(src/pyramid/.+)$", 1)
  }

  /**
   * Restricts nodes to the extraction scope of iris/extraction/{sources,sinks}.ql:
   * src/pyramid minus the framework testing helpers and interface stubs.
   */
  private predicate inExtractionScope(AstNode n) {
    relPath(n).matches("src/pyramid/%") and
    not relPath(n).matches("src/pyramid/testing.py") and
    not relPath(n).matches("src/pyramid/config/testing.py") and
    not relPath(n).matches("src/pyramid/interfaces.py")
  }

  /**
   * Holds if flow through `n` is prohibited for pass 1. `passKey` must be
   * "path_traversal". Two barriers are modeled: the _secure_path call result
   * (A001, static.py:134) and the split_path_info call results (A002,
   * traversal.py:506/613/632/655 and urldispatch.py:192) — see the file
   * header for the blocking-mechanism analysis of each.
   */
  predicate isBarrier(DataFlow::Node n, string passKey) {
    passKey = "path_traversal" and
    (
      // A001: path = _secure_path(path_tuple) — the guarded value of the
      // static-view request path; the None return raises HTTPNotFound before
      // any join/use (static.py:134-137).
      exists(Call c |
        c.getFunc() instanceof Name and
        c.getFunc().(Name).getId() = "_secure_path" and
        relPath(c) = "src/pyramid/static.py" and
        c.getLocation().getStartLine() = 134 and
        n.asExpr() = c
      )
      or
      // A002: segment tuples produced by split_path_info have no '..', '.'
      // or '' elements and no '/' inside elements.
      exists(Call c |
        c.getFunc() instanceof Name and
        c.getFunc().(Name).getId() = "split_path_info" and
        inExtractionScope(c) and
        n.asExpr() = c
      )
    )
  }
}
