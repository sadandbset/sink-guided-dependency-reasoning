/**
 * Augur Phase 2 - Pass 1 (Path Traversal) sanitizer/barrier library for
 * pymdown-extensions.
 *
 * Deterministically rendered from the reviewed Pass 1 labels
 * (iris/labels/labels.json, passKey "path_traversal"). Only label entries
 * with role "sanitizer" are rendered, and only with the concrete
 * implementation-level proof recorded in the label rationale.
 *
 *   p1-k19  os.path.basename(url) at tools/gen_emoji.py:66   [candidate]
 *
 * THE CENTRAL NEGATIVE FINDING (documented in
 * iris/labels/phase1_review.md and query_generation_notes.md): there is NO
 * barrier for the two confirmed library pipelines. Nothing between the
 * Markdown-born path and the file read in pymdownx/snippets.py
 * (get_snippet_path -> os.path.join -> codecs.open) or pymdownx/b64.py
 * (parse_url -> url2path -> join/normpath -> open) restricts the resolved
 * path to a base directory:
 *
 *   - no '..' rejection, no absolute-path rejection, no
 *     relative_to/abspath-prefix/startswith containment anywhere;
 *   - os.path.normpath (b64.py:78/:80) only collapses segments lexically;
 *   - util.url2path / urllib.request.url2pathname (util.py:56) and
 *     html.unescape (util.py:119) DECODE (percent / HTML entities) before
 *     the join - they widen the attack surface, they do not restrict it;
 *   - os.path.basename at snippets.py:167 is applied to the operator's
 *     base_path entry, never to the attacker include path;
 *   - os.path.exists gates (snippets.py:163/:171, b64.py:82) are existence
 *     oracles, not guards.
 *
 * None of those are emitted as barriers: a function name is never treated
 * as a sanitizer without proof that it blocks the specific traversal
 * mechanism on the attacker-controlled value.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /** Holds if `node` is a reviewed Pass 1 taint barrier for `passKey`. */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and
    downloadNameBarrier(node)
  }

  /**
   * p1-k19: os.path.basename(url) at gen_emoji.py:66 (candidate label).
   *
   * Proof that this specific node blocks the download-write path: the
   * external zipball_url value is reduced by basename() to a flat file name
   * (all separator components stripped) and the literal '.zip' suffix is
   * appended before the join into the fixed operator-configured tags
   * directory at :66, so the external URL cannot influence any directory
   * component of file_location. Placing the barrier on the basename CALL
   * node cuts the only route from url towards file_location and everything
   * derived from it (the open at :73, ZipFile at :44, extractall at :45).
   *
   * Scope limits (from the label rationale, kept open for human review):
   * this barrier does NOT validate archive member names, so it does not
   * protect against zip-slip THROUGH extractall (member names are not data
   * flows from the url string); and on POSIX a basename containing
   * backslashes remains a flat (non-separator) file name.
   */
  private predicate downloadNameBarrier(DataFlow::Node node) {
    exists(Call c |
      osPathCallAt(c, "basename", "gen_emoji.py", 66) and
      node = DataFlow::exprNode(c)
    )
  }

  /** Holds if `c` is an `os.path.<name>(...)` call at `file`:`line`. */
  private predicate osPathCallAt(Call c, string name, string file, int line) {
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = name and
    c.getFunc().(Attribute).getObject() instanceof Attribute and
    c.getFunc().(Attribute).getObject().(Attribute).getName() = "path" and
    c.getFunc().(Attribute).getObject().(Attribute).getObject() instanceof Name and
    c.getFunc().(Attribute).getObject().(Attribute).getObject().(Name).getId() = "os" and
    c.getLocation().getFile().getBaseName() = file and
    c.getLocation().getStartLine() = line
  }
}
