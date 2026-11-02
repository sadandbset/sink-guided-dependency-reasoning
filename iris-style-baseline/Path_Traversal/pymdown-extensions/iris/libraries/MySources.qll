/**
 * Augur Phase 2 - Pass 1 (Path Traversal) source library for pymdown-extensions.
 *
 * Deterministically rendered from the reviewed Pass 1 labels
 * (iris/labels/labels.json, passKey "path_traversal"). Every rule cites the
 * label entry id it implements; see iris/report/query_generation_notes.md for
 * the label-to-predicate mapping and the source evidence behind each entry.
 *
 * Only externally controlled input boundaries confirmed by the reviewed labels
 * are modeled (the audit target is a library - the untrusted boundary is the
 * Markdown source text / rendered output that the host Python-Markdown core
 * pushes through the extension run() methods):
 *
 *   p1-s01  m.group('path') at pymdownx/b64.py:73
 *           - img src attribute value extracted from the untrusted rendered
 *             output (quotes stripped with [1:-1] at the same site).
 *   p1-s02  B64Postprocessor.run(text) parameter at pymdownx/b64.py:114
 *           - host-library boundary; the site-packages host call site is
 *             outside the CodeQL database.
 *   p1-s03  tags[user_input]['zipball_url'] at tools/gen_emoji.py:112
 *           - external (semi-trusted) GitHub API JSON content; candidate
 *             label, kept for the archive zip-slip review queue.
 *   p1-s12  m.group('snippet') at pymdownx/snippets.py:258
 *           - inline '--8<-- "path"' include path out of untrusted Markdown
 *             (the two calls of the inline conditional share the line; both
 *             are matched by the single location-scoped rule).
 *   p1-s13  m.group(1) at pymdownx/snippets.py:276
 *           - block-form include path re-extracted after :lines/:section
 *             suffix stripping.
 *   p1-s14  SnippetPreprocessor.run(lines) parameter at pymdownx/snippets.py:352
 *           - host-library boundary carrying the untrusted document source.
 *
 * p1-s11 (parse_snippets lines parameter, classification candidate) is
 * deliberately NOT rendered as a source rule: it is an internal recursion
 * parameter, not an external input boundary, and any taint it carries already
 * enters through p1-s14 and the intra-database run() -> parse_snippets()
 * call edge. This is a rendering decision recorded in
 * query_generation_notes.md, not a change to labels.json.
 *
 * Matching is purely AST-based (receiver name + attribute/name + file +
 * line), mirroring the Phase 1 extraction contract, and does not depend on
 * API-graph resolution.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  /** Holds if `source` is a reviewed Pass 1 taint source for `passKey`. */
  predicate isSource(DataFlow::Node source, string passKey) {
    passKey = "path_traversal" and
    (
      markdownAttrPathSource(source)
      or processorRunParamSource(source)
      or snippetPathSource(source)
      or externalContentSource(source)
    )
  }

  /**
   * p1-s01: the attacker-controlled img src value. The m.group('path') call
   * at b64.py:73 is where the value is born out of the untrusted rendered
   * output text; downstream it flows through util.parse_url ->
   * util.url2path -> os.path.join/os.path.normpath into open(file_name,'rb')
   * at b64.py:86.
   */
  private predicate markdownAttrPathSource(DataFlow::Node source) {
    exists(Call c |
      receiverCallAt(c, "m", "group", "b64.py", 73) and
      source = DataFlow::exprNode(c)
    )
  }

  /**
   * p1-s02 / p1-s14: the host-library run() boundaries. B64Postprocessor.run
   * (b64.py:114, parameter position 1, self slot included) receives the
   * rendered output of untrusted Markdown; SnippetPreprocessor.run
   * (snippets.py:352, position 1) receives the untrusted document source
   * lines. The Python-Markdown host that invokes run() lives outside the
   * database, so these parameters are the visible input boundary.
   */
  private predicate processorRunParamSource(DataFlow::Node source) {
    exists(Parameter p |
      p.getPosition() = 1 and
      (
        (
          p.getName() = "text" and
          paramAt(p, "b64.py", 114)
        )
        or
        (
          p.getName() = "lines" and
          paramAt(p, "snippets.py", 352)
        )
      ) and
      source = DataFlow::parameterNode(p)
    )
  }

  /**
   * p1-s12 / p1-s13: the snippet include-path origins. m.group('snippet')
   * (snippets.py:258, inline quoted form, quotes stripped by [1:-1]) and
   * m.group(1) (snippets.py:276, block form after RE_SNIPPET_FILE suffix
   * stripping) are the points where the attacker include path is born out of
   * the untrusted Markdown lines; downstream they reach
   * self.get_snippet_path(path) -> os.path.join -> codecs.open.
   */
  private predicate snippetPathSource(DataFlow::Node source) {
    exists(Call c |
      (
        receiverCallAt(c, "m", "group", "snippets.py", 258)
        or receiverCallAt(c, "m", "group", "snippets.py", 276)
      ) and
      source = DataFlow::exprNode(c)
    )
  }

  /**
   * p1-s03: tags[user_input]['zipball_url'] at gen_emoji.py:112 - a value
   * read out of json.loads(requests.get(GitHub API).text). External but
   * semi-trusted content in a maintainer-run dev tool (candidate label).
   * The subscript is pinned by the 'zipball_url' string-literal index so
   * only the URL value (not the whole tags list) is tainted.
   */
  private predicate externalContentSource(DataFlow::Node source) {
    exists(Subscript sub |
      sub.getLocation().getFile().getBaseName() = "gen_emoji.py" and
      sub.getLocation().getStartLine() = 112 and
      sub.getIndex() instanceof StringLiteral and
      sub.getIndex().(StringLiteral).getText() = "zipball_url" and
      source = DataFlow::exprNode(sub)
    )
  }

  /** Holds if parameter `p` is declared at `file`:`line`. */
  private predicate paramAt(Parameter p, string file, int line) {
    p.getLocation().getFile().getBaseName() = file and
    p.getLocation().getStartLine() = line
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
}
