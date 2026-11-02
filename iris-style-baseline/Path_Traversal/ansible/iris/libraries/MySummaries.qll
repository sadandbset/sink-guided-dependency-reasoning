/**
 * !! MACHINE-GENERATED from iris/labels/labels.json (pass 1, run ansible-pathtraversal-pass1-step3-20261021) !!
 * !! Do not edit by hand: regenerate with labels/work/build_libraries.py !!
 *
 * Additional taint steps for the Pass 1 (Path Traversal) taint query of ansible: path construction/resolution wrappers and the galaxy filter.
 *
 * Every rule below is the CodeQL rendering of reviewed Pass 1 label entries
 * (role=summary). The label id -> predicate mapping, with source-code evidence,
 * is documented in report/query_generation_notes.md. Pass key: "path_traversal".
 */

private import python
private import semmle.python.dataflow.new.DataFlow

module MySummaries {

  private predicate nameCall(Call c, string name) {
    c.getFunc().(Name).getId() = name
  }

  private predicate osPathCall(Call c, string func) {
    exists(Attribute f |
      f = c.getFunc().(Attribute) and
      f.getName() = func and
      (
        f.getObject().(Attribute).getName() = "path" and
        f.getObject().(Attribute).getObject().(Name).getId() = "os"
        or
        f.getObject().(Name).getId() = "path"
      )
    )
  }

  private predicate methodCall(Call c, string method, string receiver) {
    exists(Attribute f, Expr obj |
      f = c.getFunc().(Attribute) and
      f.getName() = method and
      obj = f.getObject() and
      (obj.(Name).getId() = receiver or obj.(Attribute).getName() = receiver)
    )
  }

  /* ------------------------------------------------------------------
   * os.path.join: every argument (including the *args value) propagates to
   * the joined result (labels: the 2 join signature rows). Evidence:
   * fetch.py:122/:132, dataloader search stacks, galaxy role.py:329.
   * ------------------------------------------------------------------ */
  private predicate pathJoinStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Expr a |
      osPathCall(c, "join") and
      (a = c.getAnArg() or a = c.getStarArg()) and
      nodeFrom.asExpr() = a and
      nodeTo.asExpr() = c
    )
  }

  /* expanduser/expandvars argument 0 -> result: tilde/env expansion can
     turn a relative value absolute (fetch.py:111); taint-preserving. */
  private predicate pathExpandStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, string f |
      (f = "expanduser" or f = "expandvars") and
      osPathCall(c, f) and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }

  /* dirname/splitext/split/realpath/normpath/abspath/relpath argument 0 ->
     result: component extraction / canonicalization WITHOUT containment
     (these are propagators, never barriers - see MySanitizers). */
  private predicate pathResolveStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, string f |
      (
        f = "dirname" or f = "splitext" or f = "split" or
        f = "realpath" or f = "normpath" or f = "abspath" or f = "relpath"
      ) and
      osPathCall(c, f) and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }

  /* ------------------------------------------------------------------
   * Identity-ish conversion helpers used throughout ansible
   * (module_utils._text / parsing.dataloader unquote / utils/path):
   * unfrackpath (labeled summary), unquote (dataloader.py:178), to_bytes /
   * to_text / to_native (fetch.py:175, local.py:150, utils/path.py:62).
   * to_* are generation-time additions recorded in the notes.
   * ------------------------------------------------------------------ */
  private predicate nameFuncStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string funcName) {
    exists(Call c |
      nameCall(c, funcName) and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }

  /* ------------------------------------------------------------------
   * Wrapper resolution steps (labels: loader dwim/_find_needle/
   * find_file_in_search_path call-site summary entries). Argument ->
   * call value: models that the wrapper returns a path derived from the
   * argument without base-directory containment (dataloader.py:173-:321,
   * action/__init__.py:1167-:1178, lookup/__init__.py:108-:125).
   * ------------------------------------------------------------------ */
  private predicate wrapperStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, int idx |
      (
        methodCall(c, "path_dwim", "_loader") and idx = 0
        or methodCall(c, "path_dwim_relative", "_loader") and idx = 2
        or methodCall(c, "path_dwim_relative_stack", "_loader") and idx = 2
        or methodCall(c, "find_vars_files", "_loader") and idx = 1
        or methodCall(c, "_find_needle", "self") and idx = 1
        or methodCall(c, "find_file_in_search_path", "self") and idx = 2
      ) and
      nodeFrom.asExpr() = c.getArg(idx) and
      nodeTo.asExpr() = c
    )
  }

  /* ------------------------------------------------------------------
   * Galaxy archive filter plumbing (review item 6.2 additions, evidence
   * galaxy/role.py:324-:330): list.append(arg0) taints the list object;
   * obj.name = <tainted> taints obj, carrying the rebuilt member name to
   * the extract(member, path) sink argument.
   * ------------------------------------------------------------------ */
  private predicate listAppendStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      c.getFunc().(Attribute).getName() = "append" and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c.getFunc().(Attribute).getObject()
    )
  }

  private predicate nameAttrStoreStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(AssignStmt a, Attribute t |
      t = a.getATarget().(Attribute) and
      t.getName() = "name" and
      nodeFrom.asExpr() = a.getValue() and
      nodeTo.asExpr() = t.getObject()
    )
  }

  /** Pass-1 additional taint step. passKey must be "path_traversal". */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and
    (
      pathJoinStep(nodeFrom, nodeTo)
      or pathExpandStep(nodeFrom, nodeTo)
      or pathResolveStep(nodeFrom, nodeTo)
      or nameFuncStep(nodeFrom, nodeTo, "unfrackpath")
      or nameFuncStep(nodeFrom, nodeTo, "unquote")
      or nameFuncStep(nodeFrom, nodeTo, "to_bytes")
      or nameFuncStep(nodeFrom, nodeTo, "to_text")
      or nameFuncStep(nodeFrom, nodeTo, "to_native")
      or wrapperStep(nodeFrom, nodeTo)
      or listAppendStep(nodeFrom, nodeTo)
      or nameAttrStoreStep(nodeFrom, nodeTo)
    )
  }
}
