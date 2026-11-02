/**
 * Augur Pass 1 (Path Traversal) barrier model for aiohttp.
 *
 * Generated deterministically from the reviewed Pass 1 labels in
 * iris/labels/labels.json (entries with role=sanitizer and
 * classification=tp). Every barrier below was verified against the real
 * source to actually neutralize a specific traversal mechanism; no
 * normpath/resolve/basename function was accepted as a barrier merely by
 * name (resolve() is deliberately NOT a barrier - the reviewed label
 * p1-sink-069 records it as taint-preserving). The candidate barrier
 * (url_for relative_to, web_urldispatcher.py:579) is not promoted.
 *
 * Unified pass key: "path_traversal" (CWE-022/023/036/073).
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /**
   * Holds if `node` is a reviewed Pass 1 barrier for pass key `passKey`.
   */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and (
      absolutePathAnchorGuard(node) or
      baseDirectoryContainmentGuard(node) or
      basenameExtractionGuard(node)
    )
  }

  /** Restricts an AST node to a file base name and a 1-based start line. */
  private predicate matchLoc(AstNode n, string baseName, int line) {
    n.getLocation().getFile().getBaseName() = baseName and
    n.getLocation().getStartLine() = line
  }

  /**
   * p1-sink-068 (sanitizer/tp 0.80): the absolute-path (anchor) rejection.
   *
   * web_urldispatcher.py:637-642 (StaticResource._handle):
   *   filename = Path(rel_url)
   *   if filename.anchor:
   *     # rel_url is an absolute name like
   *     # /static/\\machine_name\c$ or /static/D:\path
   *     raise HTTPForbidden()
   *
   * Blocks mechanism: request filenames carrying a drive/UNC anchor
   * (D:\path, \\machine\c$ style) are rejected with HTTP 403 before the
   * join, so absolute-path and Windows-UNC traversal forms cannot leave
   * the base directory. Incomplete in isolation (anchor is empty for
   * pure-relative ../ traversal and POSIX backslash names) - sound only in
   * combination with the resolve+relative_to guard below. Barrier node:
   * the `filename.anchor` attribute read; flows whose taint is consumed
   * only through this guarded attribute are cut.
   */
  private predicate absolutePathAnchorGuard(DataFlow::Node node) {
    exists(Attribute a |
      matchLoc(a, "web_urldispatcher.py", 638) and
      a.getName() = "anchor" and
      node.asExpr() = a
    )
  }

  /**
   * p1-sink-071 (sanitizer/tp 0.90): the base-directory containment guard.
   *
   * web_urldispatcher.py:643-648 (StaticResource._handle):
   *   filepath = self._directory.joinpath(filename).resolve()
   *   if not self._follow_symlinks:
   *     filepath.relative_to(self._directory)
   *   except (ValueError, FileNotFoundError) as error:
   *     raise HTTPNotFound() from error
   *
   * Blocks mechanism: canonicalize-then-contain. resolve() runs BEFORE the
   * check (collapsing ../ and following symlinks), and relative_to() on
   * the fully resolved path raises ValueError -> HTTP 404 whenever the
   * resolved location is not inside the canonical base directory
   * (self._directory was itself resolved at registration,
   * web_urldispatcher.py:537, so both sides of the comparison are
   * canonical). This blocks ../ chains, encoded separators that decode to
   * .. (single percent-decode at :625), and symlink escapes under the
   * default follow_symlinks=False. Barrier node: the relative_to call;
   * flows routed through the containment check are cut. The guard's
   * control-flow effect (ValueError -> 404 before any file access) cannot
   * be expressed node-conditionally, so flows that bypass the relative_to
   * node itself still surface and are left to Step 6 triage - see
   * query_generation_notes.md.
   */
  private predicate baseDirectoryContainmentGuard(DataFlow::Node node) {
    exists(Call c |
      matchLoc(c, "web_urldispatcher.py", 645) and
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getName() = "relative_to" and
      node.asExpr() = c
    )
  }

  /**
   * p1-sink-027 (sanitizer/tp 0.85): basename-only extraction.
   *
   * helpers.py:357-361 (guess_filename):
   *   def guess_filename(obj: Any, default: Optional[str] = None) -> Optional[str]:
   *     name = getattr(obj, "name", None)
   *     if name and isinstance(name, str) and name[0] != "<" and name[-1] != ">":
   *       return Path(name).name
   *
   * Blocks mechanism: Path(name).name discards ALL directory components of
   * the client-supplied filename (used for the client upload payload
   * Content-Disposition guess), so ../ and separator content cannot
   * survive into the returned value. Barrier node: the `.name` attribute
   * extraction on the Path construction.
   */
  private predicate basenameExtractionGuard(DataFlow::Node node) {
    exists(Attribute a |
      matchLoc(a, "helpers.py", 360) and
      a.getName() = "name" and
      a.getObject() instanceof Call and
      node.asExpr() = a
    )
  }
}
