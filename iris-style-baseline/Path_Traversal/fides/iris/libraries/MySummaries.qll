/**
 * Augur Phase 2 Step 4 - Pass 1 (Path Traversal) additional taint-step
 * library for fides.
 *
 * Deterministically rendered from the reviewed Pass 1 labels in
 * iris/labels/labels.json (run iris-fides-pathtraversal-pass1-20261022):
 * the reviewed pass-1 label set contains exactly one summary entry with
 * classification=tp:
 *
 *   sink-097 (summary/tp 0.90): get_path_to_admin_ui_file(path) - the
 *     wrapper at src/fides/api/ui.py:32 that joins the user's catch-all
 *     string into the packaged admin-UI tree.
 *
 * This wrapper is rendered as TWO anchored edges, both derived from the
 * same reviewed label and both anchored to exact code locations (no
 * unconditional any-node-to-any-node propagation exists in this file):
 *
 *   1. call-site summary (main.py:167): argument 0 -> call result. The
 *      callee body (ui.py:38-42) returns
 *        package_path / ADMIN_UI_DIRECTORY / path
 *      so the returned Path is derived from the argument; modeling the
 *      call result keeps the chain connected even if the callee's return
 *      propagation or the "/" operator step is not otherwise modeled.
 *   2. operator step (ui.py:42): the right operand `path` -> the
 *      enclosing "/" BinaryExpr (pathlib __truediv__). pathlib keeps
 *      ".." segments lexically in the joined result, so the step is
 *      value-preserving for taint. This edge guarantees intra-callee
 *      propagation from the `path` parameter to the return expression
 *      even if the standard library does not model "/" on Path objects.
 *
 *   Dual modeling rationale: this step is generated without compiling
 *   (per the experiment contract), so both code-anchored forms of the
 *   same reviewed fact are included; at worst they duplicate a path
 *   segment, never fabricate one.
 *
 * Deliberate NON-edges (reviewed and rejected - see
 * iris/report/query_generation_notes.md):
 *   - match_route(get_ui_file_map(), path) at main.py:163 (sink-105,
 *     none/fp): the user string is only a re.fullmatch selector; the
 *     returned Path always comes from the trusted boot-time map, so an
 *     argument-1 -> result edge would fabricate taint;
 *   - the whole `request: Request` handler parameter (src-043, fp);
 *   - the zip upload body channel (src-068, fp - Pass 4 territory);
 *   - the operator/env/CLI families (none/fp).
 *
 * Unified pass key: "path_traversal" (CWE-022/023/036/073).
 */

import python

import semmle.python.dataflow.new.DataFlow

module MySummaries {

  /**
   * Holds if there is an additional reviewed Pass 1 taint step from
   * `nodeFrom` to `nodeTo` for pass key `passKey`.
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and (
      getPathToAdminUiFileCallStep(nodeFrom, nodeTo) or
      pathlibTruedivJoinStep(nodeFrom, nodeTo)
    )
  }

  /** Forward-slash-normalized absolute path of the file containing n
   *  (same helper shape as extraction/sinks.ql). */
  private string normalizedPathOf(AstNode n) {
    result = n.getLocation().getFile().getAbsolutePath().replaceAll("\\", "/")
  }

  bindingset[modulePathPattern]
  private predicate inModule(AstNode n, string modulePathPattern) {
    normalizedPathOf(n).matches(modulePathPattern)
  }

  /**
   * sink-097 (summary/tp 0.90), edge 1 of 2: the vulnerable fallback
   * call in the catch-all handler.
   *
   * src/fides/api/main.py:166-167 (read_other_paths):
   *   # if not, check if the requested file is an asset (i.e. /_next/static/...)
   *   if not ui_file:
   *     ui_file = get_path_to_admin_ui_file(path)
   *
   * Edge: argument 0 (the attacker-controlled `path` local from
   * main.py:160, labeled source/tp as src-044) -> the call result (the
   * Path assigned to `ui_file`).
   *
   * Evidence that the callee derives its result from this argument:
   * src/fides/api/ui.py:32-42:
   *   def get_path_to_admin_ui_file(path: str = "") -> Optional[Path]:
   *     package_path = get_package_path()
   *     if package_path is None:
   *       return None
   *     return package_path / ADMIN_UI_DIRECTORY / path
   *
   * The pathlib "/" join (ui.py:42) preserves ".." segments lexically -
   * an absolute right operand would REPLACE the base, but the router
   * strips the leading "/" so the catchall value is always relative.
   * This branch is taken exactly when match_route had no match, which is
   * always the case for ".." payloads (the map's regex classes contain
   * no dots), so the edge is on the confirmed attack path.
   *
   * Other call sites of the same wrapper are unaffected: ui.py:49 passes
   * the literal "index.html" and ui.py:136 passes no argument (default
   * "").
   */
  private predicate getPathToAdminUiFileCallStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      inModule(c, "%/src/fides/api/main.py") and
      c.getLocation().getStartLine() = 167 and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "get_path_to_admin_ui_file" and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }

  /**
   * sink-097 (summary/tp 0.90), edge 2 of 2: the pathlib __truediv__
   * join inside the wrapper.
   *
   * src/fides/api/ui.py:42 (get_path_to_admin_ui_file):
   *   return package_path / ADMIN_UI_DIRECTORY / path
   *
   * The expression nests as
   *   ((package_path / ADMIN_UI_DIRECTORY) / path)
   * and the tainted operand is the RIGHT operand of the OUTER division -
   * the `path` parameter use. Edge: that Name -> the outer BinaryExpr
   * (the expression whose value is returned).
   *
   * Evidence: pathlib Path.__truediv__ joins the segments without
   * normalizing them, so ".." components survive lexically in the
   * result; the OS-level resolution that makes them escape happens later
   * at is_file()/FileResponse (the sinks). The line-anchored shape match
   * (outer BinaryExpr on ui.py:42 whose right operand is the Name
   * "path") unambiguously selects the outer join: the inner division's
   * right operand is the Name ADMIN_UI_DIRECTORY.
   */
  private predicate pathlibTruedivJoinStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(BinaryExpr b |
      inModule(b, "%/src/fides/api/ui.py") and
      b.getLocation().getStartLine() = 42 and
      b.getRight() instanceof Name and
      b.getRight().(Name).getId() = "path" and
      nodeFrom.asExpr() = b.getRight() and
      nodeTo.asExpr() = b
    )
  }
}
