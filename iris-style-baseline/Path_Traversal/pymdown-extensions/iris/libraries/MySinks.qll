/**
 * Augur Phase 2 - Pass 1 (Path Traversal) sink library for pymdown-extensions.
 *
 * Deterministically rendered from the reviewed Pass 1 labels
 * (iris/labels/labels.json, passKey "path_traversal"). Only the four
 * label entries with role "sink" are rendered; every rule cites its label
 * entry id. Sinks are the dangerous PATH ARGUMENT positions of actual file
 * access APIs - path text producers such as os.path.join/normpath or
 * string rewriters are deliberately not sinks here (they are modeled in
 * MySummaries.qll as propagation steps).
 *
 *   p1-k08  open(file_name, "rb") at pymdownx/b64.py:86            [tp]
 *           - real file READ; the resolved path comes from the attacker
 *             img src value; content is embedded as a data URI into the
 *             rendered output (read + exfiltration).
 *   p1-k55  codecs.open(snippet, "r", encoding) at
 *           pymdownx/snippets.py:311                                [tp]
 *           - real file READ of the resolved snippet include path; the
 *             read lines are recursively re-parsed (nested includes).
 *   p1-k09  zipfile.ZipFile(file_location, "r") at
 *           tools/gen_emoji.py:44                                   [candidate]
 *           - archive OPEN of externally downloaded content feeding the
 *             unvalidated extractall at :45.
 *   p1-k10  z.extractall(os.path.dirname(file_location)) at
 *           tools/gen_emoji.py:45                                   [candidate]
 *           - archive EXTRACT to disk with no member-name validation
 *             (zip-slip shape).
 *
 * Matching is purely AST-based (callee name + receiver + file + line),
 * mirroring the Phase 1 extraction contract.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  /** Holds if `sink` is a reviewed Pass 1 taint sink for `passKey`. */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "path_traversal" and
    (
      b64FileReadSink(sink)
      or snippetFileReadSink(sink)
      or archiveOpenSink(sink)
      or archiveExtractSink(sink)
    )
  }

  /**
   * p1-k08: open(file_name, "rb") at b64.py:86 - argument 0 is the file path
   * resolved from the attacker-controlled img src (parse_url + url2path +
   * join/normpath, no base-directory containment; absolute forms take the
   * direct normpath branch at b64.py:78). Access type: read (binary), result
   * base64-embedded into the output link.
   */
  private predicate b64FileReadSink(DataFlow::Node sink) {
    exists(Call c |
      nameCallAt(c, "open", "b64.py", 86) and
      sink = DataFlow::exprNode(c.getPositionalArg(0))
    )
  }

  /**
   * p1-k55: codecs.open(snippet, "r", encoding=self.encoding) at
   * snippets.py:311 - argument 0 is the resolved include path returned by
   * get_snippet_path (os.path.join against the configured base_path with no
   * containment). Access type: read (text); lines re-enter
   * parse_snippets recursively at :333-341.
   */
  private predicate snippetFileReadSink(DataFlow::Node sink) {
    exists(Call c |
      receiverCallAt(c, "codecs", "open", "snippets.py", 311) and
      sink = DataFlow::exprNode(c.getPositionalArg(0))
    )
  }

  /**
   * p1-k09: zipfile.ZipFile(file_location, "r") at gen_emoji.py:44 -
   * argument 0 is the path of the archive downloaded from the GitHub API
   * zipball_url (candidate label: semi-trusted source, maintainer dev
   * tool). Access type: archive open; feeds extractall at :45.
   */
  private predicate archiveOpenSink(DataFlow::Node sink) {
    exists(Call c |
      receiverCallAt(c, "zipfile", "ZipFile", "gen_emoji.py", 44) and
      sink = DataFlow::exprNode(c.getPositionalArg(0))
    )
  }

  /**
   * p1-k10: z.extractall(os.path.dirname(file_location)) at
   * gen_emoji.py:45 - argument 0 is the extraction destination directory;
   * archive member names are not validated, so members containing ../ or
   * absolute components would write outside it (zip-slip, candidate label).
   */
  private predicate archiveExtractSink(DataFlow::Node sink) {
    exists(Call c |
      receiverCallAt(c, "z", "extractall", "gen_emoji.py", 45) and
      sink = DataFlow::exprNode(c.getPositionalArg(0))
    )
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
}
