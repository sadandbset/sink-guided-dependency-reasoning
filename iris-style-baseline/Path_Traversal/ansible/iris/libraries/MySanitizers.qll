/**
 * !! MACHINE-GENERATED from iris/labels/labels.json (pass 1, run ansible-pathtraversal-pass1-step3-20261021) !!
 * !! Do not edit by hand: regenerate with labels/work/build_libraries.py !!
 *
 * Barrier nodes for the Pass 1 (Path Traversal) taint query of ansible. Both barriers realize PARTIAL guards (candidate labels) - see notes.
 *
 * Every rule below is the CodeQL rendering of reviewed Pass 1 label entries
 * (role=sanitizer). The label id -> predicate mapping, with source-code evidence,
 * is documented in report/query_generation_notes.md. Pass key: "path_traversal".
 */

private import python
private import semmle.python.dataflow.new.DataFlow

module MySanitizers {

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
   * os.path.basename call value (label p1-snk-036, candidate 0.55).
   * Strips the directory component, which neutralizes traversal in the
   * filename position (fetch.py:118-122 flat-dest branch, fileglob.py:60,
   * template.py:171, uri.py:45). Kept candidate, not a proven barrier:
   * basename('..') == '..' survives a later join, and only os.sep is split.
   * Barrier position = the call VALUE (output no longer carries directory
   * traversal); the argument itself is not blocked.
   * ------------------------------------------------------------------ */
  class BasenameCallValue extends DataFlow::Node {
    BasenameCallValue() {
      exists(Call c |
        osPathCall(c, "basename") and
        this.asExpr() = c
      )
    }
  }

  /* ------------------------------------------------------------------
   * self._remote_expand_user(...) call value (labels p1-snk-023/092/103/
   * 136/163/182, candidate 0.45-0.50). Remote '~' expansion followed by
   * the partial '..' rejection at plugins/action/__init__.py:686-687 -
   * the guard only applies to '~'-prefixed paths after expansion. The
   * definition-row label (p1-snk-103, param flow) is realized by these
   * call-site value barriers (an input-side parameter barrier was rejected
   * because it would over-sanitize the unvalidated non-tilde pass-through).
   * ------------------------------------------------------------------ */
  class RemoteExpandUserCallValue extends DataFlow::Node {
    RemoteExpandUserCallValue() {
      exists(Call c |
        methodCall(c, "_remote_expand_user", "self") and
        this.asExpr() = c
      )
    }
  }

  /** Pass-1 barrier predicate. passKey must be "path_traversal". */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and
    (
      node instanceof BasenameCallValue
      or node instanceof RemoteExpandUserCallValue
    )
  }
}
