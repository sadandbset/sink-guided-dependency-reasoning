/**
 * Augur / IRIS generated sink library — whoogle-search, pass 1 (path_traversal).
 *
 * Rendered deterministically from the reviewed Phase 1 labels
 * (iris/labels/labels.json, pass_id 1). Only actual filesystem access APIs at
 * their dangerous path-argument position are sinks:
 *
 *   - builtin open(path, ...) at argument 0 — the PATH TEXT, not the returned
 *     file object (labels: routes.py:430 read tp 0.97 = snk-242,
 *     routes.py:445 write tp 0.97 = snk-243, routes.py:103 candidate 0.6,
 *     misc.py:11 candidate 0.6, bangs.py:38 candidate 0.55,
 *     request.py:55 fp 0.7 env-trust)
 *   - os.remove(path) at argument 0 (label: routes.py:117 candidate 0.55)
 *
 * Pure path wrappers (os.path.join / dirname / abspath / splitext,
 * pathlib.Path(...)) are NOT sinks here — the reviewed labels assign them the
 * "summary" role, and path construction is not file access by itself.
 * send_file call sites (routes.py:484/:490) pass io.BytesIO buffers, so they
 * are not sinks either.
 *
 * The signature-level predicates below match every open()/os.remove() call in
 * the extracted tree, which is a superset of the 7 labeled sink sites: the
 * remaining sites (app/__init__.py settings/key/bangs opens, literal-path
 * opens in config.py/widgets.py, the dev-script open in
 * misc/update-translations.py) were reviewed with role "none" because their
 * path arguments are constants — no labeled source can reach them, so the
 * superset cannot produce alerts; reachability is decided by the taint
 * analysis, not by this predicate.
 *
 * Machine-generated; do not hand-edit without re-running the label review.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  /**
   * Builtin `open(path, ...)` — dangerous argument 0 (the path text).
   * Covers file read ('r'/'rb') and write ('w'/'wb') opens, including
   * `with open(...) as f:` forms; the opened file object is never the sink.
   */
  predicate openSink(DataFlow::Node n) {
    exists(Call c |
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId() = "open" and
      n.asExpr() = c.getArg(0)
    )
  }

  /**
   * `os.remove(path)` — dangerous argument 0 (file deletion; the reviewed
   * candidate at app/routes.py:117 deletes listdir-derived session files).
   */
  predicate removeSink(DataFlow::Node n) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "remove" and
      f.getObject() instanceof Name and
      f.getObject().(Name).getId() = "os" and
      n.asExpr() = c.getArg(0)
    )
  }

  /* ---------- pass dispatch ---------- */

  predicate isSink(DataFlow::Node n, string passKey) {
    passKey = "path_traversal" and
    (
      openSink(n)
      or removeSink(n)
    )
  }
}
