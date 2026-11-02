/**
 * Augur / IRIS generated summary library — whoogle-search, pass 1 (path_traversal).
 *
 * Rendered deterministically from the reviewed Phase 1 labels
 * (iris/labels/labels.json, pass_id 1). Only the two call-summary families the
 * labels actually assign the "summary" role are implemented, both as
 * argument -> result edges of the SAME call (no unconditional cross-function
 * node-to-node propagation):
 *
 *   - osPathJoinStep: os.path.join(<tainted arg>) -> joined path string
 *     (labels: routes.py:427 tp 0.9 = snk-240, routes.py:445 tp 0.9 = snk-244,
 *      routes.py:94 candidate 0.6 = snk-232, misc.py:11 candidate 0.6 = snk-226)
 *   - urlDecodeStep: urlparse.unquote / unquote_plus(<tainted arg>) -> decoded
 *     string (labels: routes.py:285/348/383/410, request.py:163,
 *     filter.py:634/639/641/643, all candidate 0.6)
 *
 * The remaining 8 reviewed "summary" entries are FUNCTION-PARAMETER summaries
 * (gen_bangs_json bangs_file, gen_file_hash path/static_file, from_params
 * params, Search.__init__ request, Request.__init__ normal_ua/root_path,
 * get_client_ip r, get_proxy_host_url r). CodeQL's standard interprocedural
 * dataflow already realizes exactly the semantics the labels describe — a
 * tainted argument taints the callee's parameter and flows to its uses — so
 * NO explicit additional edges are created for them. Creating explicit edges
 * here would duplicate standard flow and risk arbitrary propagation.
 *
 * The g.request_params / self.request_params alias channels are NOT summary
 * edges here: the reviewed labels assigned those reads role "source"
 * (src-070/076/094/095/163/166-...), so MySources covers them directly.
 *
 * Machine-generated; do not hand-edit without re-running the label review.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  /**
   * os.path.join(...): a tainted argument taints the joined result.
   * The audited call sites:
   *   - app/routes.py:427-429: os.path.join(app.config['CONFIG_PATH'], request.args.get('name'))
   *   - app/routes.py:445-447: same construction on the write side
   *   - app/routes.py:94-96:   os.path.join(SESSION_FILE_DIR, listdir-entry)
   *   - app/utils/misc.py:11:  os.path.join(path, static_file)
   * join() performs no normalization or containment on its arguments, so the
   * result is fully as tainted as any tainted component (an absolute second
   * argument even replaces the base).
   */
  predicate osPathJoinStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() = "join" and
      f.getObject() instanceof Attribute and
      f.getObject().(Attribute).getName() = "path" and
      f.getObject().(Attribute).getObject() instanceof Name and
      f.getObject().(Attribute).getObject().(Name).getId() = "os" and
      nodeFrom.asExpr() = c.getAnArg() and
      nodeTo.asExpr() = c
    )
  }

  /**
   * urlparse.unquote / unquote_plus(...): a tainted argument taints the decoded
   * result. Percent-decoding is taint-preserving (and is the classic
   * double-decode traversal bypass vector). All audited sites import
   * `urllib.parse as urlparse` and call the attribute form.
   */
  predicate urlDecodeStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute f |
      c.getFunc() = f and
      f.getName() in ["unquote", "unquote_plus"] and
      f.getObject() instanceof Name and
      f.getObject().(Name).getId() = "urlparse" and
      nodeFrom.asExpr() = c.getAnArg() and
      nodeTo.asExpr() = c
    )
  }

  /* ---------- pass dispatch ---------- */

  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and
    (
      osPathJoinStep(nodeFrom, nodeTo)
      or urlDecodeStep(nodeFrom, nodeTo)
    )
  }
}
