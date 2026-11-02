/**
 * Augur Pass 1 (Path Traversal) additional taint-step model for
 * xmpp-http-upload.
 *
 * Generated deterministically from the reviewed Pass 1 labels in
 * iris/labels/labels.json (the 8 entries with role=summary and
 * classification=tp, realized as 5 label-backed rules) plus 2
 * documented evidence-based interpolation edges. Every edge is
 * anchored to the exact labeled call site in the real source - there
 * are no unconditional any-node-to-any-node propagation edges.
 *
 * Which steps are necessary on this toolchain (CodeQL CLI 2.25.1 +
 * codeql/python-all 7.1.x, verified by reading the pack sources):
 *
 *   NOT default taint steps (pathlib lives outside the database and
 *   the stock PathlibPathTaintStep lives in
 *   semmle.python.frameworks.Stdlib, which this query deliberately
 *   does not import - the Augur libraries are self-contained):
 *     - the `/` join `root / path` (xhu.py:43) -> truedivJoinStep
 *       (label sink-008);
 *     - pathlib.Path(...) constructor argument -> result (:50/:51)
 *       -> pathConstructorStep (labels sink-009/sink-010);
 *     - `.absolute()` receiver -> result (:43) -> absoluteCallStep
 *       (interpolation; the label sink-007 is role=none, but without
 *       this edge the flow dies inside sanitized_join);
 *     - `.parent` object -> attribute read (:137) ->
 *       parentAttributeStep (interpolation realizing sink-023's
 *       receiver).
 *
 *   Covered by default taint steps (internal to
 *   semmle.python.dataflow.new.TaintTracking, always active - no edge
 *   emitted, see TaintTrackingPrivate.qll stringManipulation/
 *   concatStep):
 *     - str() coercions at xhu.py:50/:51 (str(base_path)) and :229
 *       (str(data_file));
 *     - the "+" concatenations '<base> + ".data"/".meta"' (:50/:51).
 *
 *   Covered by standard interprocedural flow (function bodies are IN
 *   the database; the call-site edges below are the label-faithful
 *   realizations, kept as explicit redundant safety edges in the
 *   py7zr-series style):
 *     - sanitized_join call argument 0 -> call result (:64/:107);
 *     - get_paths call argument 0 -> call result (:69/:138);
 *     - get_info call argument 0 -> call result (:192/:217);
 *     - write_file(data_file) argument -> parameter `at` (:141 ->
 *       :75; @contextlib.contextmanager dispatch is modeled natively
 *       by DataFlowDispatch.hasContextmanagerDecorator);
 *     - the tuple returns of get_paths/get_info unpacked at :138/
 *       :192/:217 (native tuple-content flow).
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
      truedivJoinStep(nodeFrom, nodeTo) or
      absoluteCallStep(nodeFrom, nodeTo) or
      pathConstructorStep(nodeFrom, nodeTo) or
      parentAttributeStep(nodeFrom, nodeTo) or
      sanitizedJoinStep(nodeFrom, nodeTo) or
      getPathsStep(nodeFrom, nodeTo) or
      getInfoStep(nodeFrom, nodeTo)
    )
  }

  /** Restricts an AST node to a file base name and a 1-based start line. */
  private predicate matchLoc(AstNode n, string baseName, int line) {
    n.getLocation().getFile().getBaseName() = baseName and
    n.getLocation().getStartLine() = line
  }

  /**
   * sink-008 (summary/tp 0.70): the pathlib true-division join of the
   * route path onto DATA_ROOT.
   *
   *   xhu.py:43: result = (root / path).absolute()
   *
   * Edge: right operand (the `path` Name use - the tainted route
   * parameter) -> the Div BinaryExpr result. Conditional on the real
   * site: only the xhu.py:43 `/` is matched (an unconditional Div
   * edge would pollute every division in the module). This is the
   * traversal decision point: pathlib `/` joins textually and keeps
   * ".." segments. Not a barrier.
   */
  private predicate truedivJoinStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(BinaryExpr slash |
      matchLoc(slash, "xhu.py", 43) and
      slash.getOp() instanceof Div and
      nodeFrom.asExpr() = slash.getRight() and
      nodeTo.asExpr() = slash
    )
  }

  /**
   * Interpolation edge (not a label row; sink-007 labels
   * Path.absolute() role=none - "neither a file access nor a
   * normalizer"): the make-absolute pass-through inside
   * sanitized_join.
   *
   *   xhu.py:43: result = (root / path).absolute()
   *
   * Edge: receiver (the `root / path` Div result) -> the .absolute()
   * call result. Path.absolute() prepends the CWD for relative inputs
   * only; it preserves path content verbatim (no ".." collapse, no
   * symlink resolution), so taint must pass through for the flow to
   * reach the returned `result` - and, symmetrically, it cannot be a
   * barrier. Without this edge the flow dies here because pathlib is
   * outside the database.
   */
  private predicate absoluteCallStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "absolute" and
      matchLoc(c, "xhu.py", 43) and
      nodeFrom.asExpr() = f.getObject() and
      nodeTo.asExpr() = c
    )
  }

  /**
   * sink-009 / sink-010 (summary/tp 0.75): the str->Path coercions of
   * the data/meta companion construction.
   *
   *   xhu.py:50: data_file = pathlib.Path(str(base_path) + ".data")
   *   xhu.py:51: metadata_file = pathlib.Path(str(base_path) + ".meta")
   *
   * Edge: argument 0 (the str(base_path) + ".data"/".meta" string -
   * str() and "+" are default taint steps) -> constructor result.
   * Only the two get_paths sites are matched: the four other
   * pathlib.Path(...) constructions (:66/:109/:194/:219) take
   * operator-configured app.config["DATA_ROOT"] (labels role=none/
   * fp) - an edge there would be vacuous and is not emitted.
   */
  private predicate pathConstructorStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "Path" and
      f.getObject().(Name).getId() = "pathlib" and
      (matchLoc(c, "xhu.py", 50) or matchLoc(c, "xhu.py", 51)) and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }

  /**
   * Interpolation edge (not a label row; below Phase 1 extraction
   * granularity - a pure stdlib path-text derivation, no candidate
   * row emitted) realizing the receiver position of sink-023: the
   * pathlib .parent derivation of the PUT-side mkdir.
   *
   *   xhu.py:137: dest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o770)
   *
   * Edge: `dest_path` (the sanitized joined path) -> the
   * `dest_path.parent` attribute expression. pathlib .parent is a
   * pure path-text derivation (the parent directory of an attacker-
   * influenced path is still attacker-influenced - with "../"
   * segments it walks the escaped chain); the attribute read is not a
   * default taint step because pathlib is not part of the database.
   */
  private predicate parentAttributeStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Attribute parent |
      parent.getName() = "parent" and
      matchLoc(parent, "xhu.py", 137) and
      nodeFrom.asExpr() = parent.getObject() and
      nodeTo.asExpr() = parent
    )
  }

  /**
   * sink-005 / sink-016 / sink-021 (summary/tp 0.70-0.80): the
   * sanitized_join wrapper boundary (param 0 -> return, realized at
   * the two call sites that carry the route parameter).
   *
   *   xhu.py:64:  dest_path = sanitized_join(path, pathlib.Path(app.config["DATA_ROOT"]))  (get_info)
   *   xhu.py:107: dest_path = sanitized_join(path, pathlib.Path(app.config["DATA_ROOT"]))  (put_file)
   *
   * Edge: argument 0 (the route-parameter `path`) -> call result (the
   * joined+absolutized Path). The in-tree definition (xhu.py:42-46)
   * is also covered by standard interprocedural flow; the call-site
   * edges make the reviewed wrapper label explicit. NOT a barrier: the
   * startswith guard inside is a lexical check on an un-normalized
   * path (MySanitizers doc comment).
   */
  private predicate sanitizedJoinStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "sanitized_join" and
      (matchLoc(c, "xhu.py", 64) or matchLoc(c, "xhu.py", 107)) and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }

  /**
   * sink-011 (summary/tp 0.70): the get_paths companion-suffix
   * wrapper boundary (param 0 -> both returns, realized at the call
   * sites).
   *
   *   xhu.py:69:  data_file, metadata_file = get_paths(dest_path)  (get_info)
   *   xhu.py:138: data_file, metadata_file = get_paths(dest_path)  (put_file)
   *
   * Edge: argument 0 (dest_path) -> call result (the returned
   * (data_file, metadata_file) tuple; the unpacked elements are
   * additionally reached by native tuple-content flow through the
   * in-tree body :49-53). The ".data"/".meta" suffixing is
   * name-mangling, not a guard - it constrains WHICH files are
   * reachable, never whether the path escapes DATA_ROOT.
   */
  private predicate getPathsStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "get_paths" and
      (matchLoc(c, "xhu.py", 69) or matchLoc(c, "xhu.py", 138)) and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }

  /**
   * sink-014 (summary/tp 0.70): the get_info aggregator boundary
   * (param 0 -> returns, realized at the call sites).
   *
   *   xhu.py:192: data_file, metadata = get_info(path, pathlib.Path(app.config["DATA_ROOT"]))  (head_file)
   *   xhu.py:217: data_file, metadata = get_info(path, pathlib.Path(app.config["DATA_ROOT"]))  (get_file)
   *
   * Edge: argument 0 (the UNAUTHENTICATED route parameter `path`) ->
   * call result. get_info (xhu.py:61-71) forwards into
   * sanitized_join/get_paths/load_metadata; the in-tree body is also
   * covered by standard interprocedural flow.
   */
  private predicate getInfoStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "get_info" and
      (matchLoc(c, "xhu.py", 192) or matchLoc(c, "xhu.py", 217)) and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }
}
