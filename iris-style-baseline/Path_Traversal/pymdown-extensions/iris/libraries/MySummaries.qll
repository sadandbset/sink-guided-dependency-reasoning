/**
 * Augur Phase 2 - Pass 1 (Path Traversal) summary/flow-step library for
 * pymdown-extensions.
 *
 * Deterministically rendered from the reviewed Pass 1 labels
 * (iris/labels/labels.json, passKey "path_traversal"). Only label entries
 * with role "summary" are rendered, each as an argument-to-result edge at
 * its reviewed location. No arbitrary node-to-node propagation is created:
 * every edge is a call site that exists in the real source, pinned by
 * callee name + receiver + file + line.
 *
 * Rendered label entries (13):
 *
 *   p1-k01  util.parse_url(<src value>)   b64.py:73      arg 0 -> result
 *   p1-k02  util.url2path(path)           b64.py:75      arg 0 -> result
 *   p1-k03  os.path.normpath(path)        b64.py:78      arg 0 -> result
 *   p1-k04  os.path.normpath(join(...))   b64.py:80      arg 0 -> result
 *   p1-k05  os.path.join(base_path, path) b64.py:80      arg 1 -> result
 *   p1-k48  os.path.join(base, path)      snippets.py:162 arg 1 -> result
 *   p1-k52  os.path.join(dirname, path)   snippets.py:170 arg 1 -> result
 *   p1-k45  get_snippet_path (def snippets.py:155) - realized at its sole
 *           call site, together with p1-k54:
 *   p1-k54  self.get_snippet_path(path)   snippets.py:301 arg 0 -> result
 *   p1-k56  util.url2path (def util.py:53)  - realized by the p1-k02 call
 *           site edge at b64.py:75 (the only labeled call site; the
 *           pathconverter.py call sites are labeled none and get no edge).
 *   p1-k57  url2pathname(path)            util.py:56     arg 0 -> result
 *   p1-k58  util.parse_url (def util.py:103) - realized by the p1-k01 call
 *           site edge at b64.py:73 (same reasoning as p1-k56).
 *   p1-k59  html.unescape(url)            util.py:119    arg 0 -> result
 *
 * Note on overlap with CodeQL defaults: python-all's Stdlib.qll already
 * registers os.path.join / normpath / relpath / abspath / basename / ... as
 * additional taint steps for every TaintTracking::Global configuration.
 * The os.path.* edges above (p1-k03/k04/k05/k48/k52) re-state exactly the
 * default arg->result semantics at the labeled locations - they are
 * narrower than the defaults (single argument, single call site) and can
 * therefore not widen any flow; they are kept because the reviewed labels
 * mandate them. The non-stdlib wrappers (parse_url, url2path,
 * url2pathname, html.unescape, get_snippet_path) have no default model and
 * rely entirely on these edges.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  /**
   * Holds if taint may flow from `nodeFrom` to `nodeTo` as an additional
   * Pass 1 flow step for `passKey`. Each edge is an argument-to-result step
   * at a reviewed call site (see summaryEdge for the list).
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and
    exists(Call c, int argIndex |
      summaryEdge(c, argIndex) and
      nodeFrom = DataFlow::exprNode(c.getPositionalArg(argIndex)) and
      nodeTo = DataFlow::exprNode(c)
    )
  }

  /**
   * The reviewed call sites whose argument-to-result propagation is
   * required for realistic taint flow, each pinned to its label entry.
   */
  private predicate summaryEdge(Call c, int argIndex) {
    // p1-k01: util.parse_url(m.group('path')[1:-1]) - HTML-entity decode +
    // urlparse of the attacker src value; the returned path component feeds
    // the join at b64.py:80.
    receiverCallAt(c, "util", "parse_url", "b64.py", 73) and argIndex = 0
    or
    // p1-k02: util.url2path(path) - percent decode (%2e%2e%2f -> ../) of the
    // parsed path before the join.
    receiverCallAt(c, "util", "url2path", "b64.py", 75) and argIndex = 0
    or
    // p1-k03: os.path.normpath(path) - the absolute branch: attacker src
    // forms flagged is_absolute (file://, c:/, //, leading /) are normpathed
    // without joining base_path.
    osPathCallAt(c, "normpath", "b64.py", 78) and argIndex = 0
    or
    // p1-k04: os.path.normpath(os.path.join(base_path, path)) - lexical
    // collapse only, no containment downstream.
    osPathCallAt(c, "normpath", "b64.py", 80) and argIndex = 0
    or
    // p1-k05: os.path.join(base_path, path) - the attacker path at argument
    // 1; join semantics also let an absolute path discard base_path.
    osPathCallAt(c, "join", "b64.py", 80) and argIndex = 1
    or
    // p1-k48: os.path.join(base, path) - directory-style base branch of
    // get_snippet_path; attacker include path at argument 1.
    osPathCallAt(c, "join", "snippets.py", 162) and argIndex = 1
    or
    // p1-k52: os.path.join(dirname, path) - file-style base branch of
    // get_snippet_path; attacker include path at argument 1.
    osPathCallAt(c, "join", "snippets.py", 170) and argIndex = 1
    or
    // p1-k45 + p1-k54: SnippetPreprocessor.get_snippet_path (definition at
    // snippets.py:155) - the internal resolution wrapper returns the first
    // existing join result across base_path with no validation; modeled at
    // its sole call site (snippets.py:301), argument 0 -> call result.
    receiverCallAt(c, "self", "get_snippet_path", "snippets.py", 301) and argIndex = 0
    or
    // p1-k57: url2pathname(path) inside util.url2path - the percent-decoding
    // primitive.
    nameCallAt(c, "url2pathname", "util.py", 56) and argIndex = 0
    or
    // p1-k59: html.unescape(url) inside util.parse_url - entity decoding
    // (&#46; style) before urlparse/join.
    receiverCallAt(c, "html", "unescape", "util.py", 119) and argIndex = 0
  }

  /** Holds if `c` is a bare `<name>(...)` call at `file`:`line`. */
  private predicate nameCallAt(Call c, string name, string file, int line) {
    c.getFunc() instanceof Name and
    c.getFunc().(Name).getId() = name and
    c.getLocation().getFile().getBaseName() = file and
    c.getLocation().getStartLine() = line
  }

  /** Holds if `c` is a `<recv>.<name>(...)` call at `file`:`line`. */
  private predicate receiverCallAt(Call c, string recv, string name, string file, int line) {
    c.getFunc() instanceof Attribute and
    c.getFunc().(Attribute).getName() = name and
    c.getFunc().(Attribute).getObject() instanceof Name and
    c.getFunc().(Attribute).getObject().(Name).getId() = recv and
    c.getLocation().getFile().getBaseName() = file and
    c.getLocation().getStartLine() = line
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
