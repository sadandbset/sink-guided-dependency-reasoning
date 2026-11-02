/**
 * Augur Pass 1 (Path Traversal) additional taint-step model for aiohttp.
 *
 * Generated deterministically from the reviewed Pass 1 labels in
 * iris/labels/labels.json (entries with role=summary and
 * classification=tp). Every edge below is anchored to the exact labeled
 * call site in the real source - there are no unconditional
 * any-node-to-any-node propagation edges, and no edges for
 * candidate/pending-review summary labels (request.clone(rel_url=...),
 * with_name .gz sibling, url_for joinpath, Path(netrc_env)).
 *
 * Each edge models a wrapper that provably carries path taint from an
 * input position to its result at that site:
 *   - _unquote_path(value): arg 0 -> result (percent-decode is
 *     value-preserving, web_urldispatcher.py:1242-1243);
 *   - Path(rel_url): arg 0 -> result (str -> Path coercion,
 *     web_urldispatcher.py:637);
 *   - _directory.joinpath(filename): arg 0 -> result (joining a tainted
 *     component into the base directory, web_urldispatcher.py:643);
 *   - .resolve(): receiver -> result (canonicalization rewrites .. and
 *     symlink targets but the resolved location is still
 *     attacker-positioned, web_urldispatcher.py:643).
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
      unquotePathStep(nodeFrom, nodeTo) or
      pathConstructorStep(nodeFrom, nodeTo) or
      joinPathStep(nodeFrom, nodeTo) or
      resolveStep(nodeFrom, nodeTo)
    )
  }

  /** Restricts an AST node to a file base name and a 1-based start line. */
  private predicate matchLoc(AstNode n, string baseName, int line) {
    n.getLocation().getFile().getBaseName() = baseName and
    n.getLocation().getStartLine() = line
  }

  /**
   * p1-src-085, p1-src-089 (summary/tp): the percent-decode boundary.
   *
   * web_urldispatcher.py:625 (StaticResource.resolve):
   *   match_dict = {"filename": _unquote_path(path[len(self._prefix) + 1 :])}
   * web_urldispatcher.py:471-472 (DynamicResource._match):
   *   return {key: _unquote_path(value) for key, value in match.groupdict().items()}
   * web_urldispatcher.py:1242-1243:
   *   def _unquote_path(value: str) -> str:
   *     return URL.build(path=value, encoded=True).path
   *
   * Edge: argument 0 -> call result. Exactly ONE decode pass exists
   * between the wire and the routed filename, so this step is
   * value-preserving for taint (encoded ../ becomes literal ../ here).
   */
  private predicate unquotePathStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      (matchLoc(c, "web_urldispatcher.py", 625) or matchLoc(c, "web_urldispatcher.py", 472)) and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "_unquote_path" and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }

  /**
   * p1-sink-067 (summary/tp): the str -> Path coercion of the routed
   * filename.
   *
   * web_urldispatcher.py:635-637 (StaticResource._handle):
   *   rel_url = request.match_info["filename"]
   *   filename = Path(rel_url)
   *
   * Edge: argument 0 -> call result. The constructor carries the tainted
   * string into the path object; without this edge the ctor's return value
   * is not tainted (unknown function).
   */
  private predicate pathConstructorStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      matchLoc(c, "web_urldispatcher.py", 637) and
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "Path" and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }

  /**
   * p1-sink-070 (summary/tp): joining the tainted filename into the base
   * directory.
   *
   * web_urldispatcher.py:643 (StaticResource._handle):
   *   filepath = self._directory.joinpath(filename).resolve()
   *
   * Edge: argument 0 (the attacker-controlled filename; the receiver
   * self._directory is operator configuration) -> joinpath call result.
   */
  private predicate joinPathStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "joinpath" and
      matchLoc(c, "web_urldispatcher.py", 643) and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }

  /**
   * p1-sink-069 (summary/tp): canonicalization of the joined path.
   *
   * web_urldispatcher.py:643 (StaticResource._handle):
   *   filepath = self._directory.joinpath(filename).resolve()
   *
   * Edge: receiver (the joinpath call, i.e. the tainted joined path) ->
   * resolve() call result. resolve() rewrites .. segments and symlink
   * targets but the resulting location is still chosen by the attacker,
   * so taint is preserved (this is why the containment check at :645 must
   * run after it - and why resolve itself is NOT a barrier).
   */
  private predicate resolveStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "resolve" and
      matchLoc(c, "web_urldispatcher.py", 643) and
      nodeFrom.asExpr() = f.getObject() and
      nodeTo.asExpr() = c
    )
  }
}
