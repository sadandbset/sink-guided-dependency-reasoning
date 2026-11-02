/**
 * Augur-generated additional taint-step model for the matrix-sydent
 * CWE-918 (SSRF) pass.
 *
 * Machine-generated in Phase 2 Step 4 from the reviewed labels in
 * iris/labels/labels.json (run sydent-ssrf-pass3-20261020, pass_id 3,
 * pass key "ssrf").
 *
 * Policy: NO unconditional taint propagation. Every step below is
 * (a) backed by concrete source code (file:line evidence per predicate),
 * (b) scoped to a single file, and (c) conditional - it only extends
 * flow when the `from` node is already tainted. Both steps live in
 * sydent/hs_federation/verifier.py, the X-Matrix authentication chain
 * that the Phase 1 summary labels (src-118 _getKeysForServer.server_name,
 * src-122 authenticate_request.request) identified as needing relay help.
 *
 * Realization of the two summary-labeled entries:
 *  - src-122 (authenticate_request.request param): covered NATIVELY by
 *    TaintTracking::Global interprocedural argument flow (the servlet
 *    request object taints the parameter inside authenticate_request,
 *    threepidunbindservlet.py:135). No custom edge required.
 *  - src-118 (_getKeysForServer.server_name param): covered natively for
 *    the direct call verifyServerSignedJson -> _getKeysForServer
 *    (verifier.py:119); the custom steps below repair the two container
 *    boundaries on the X-Matrix header -> origin -> signatures-dict path
 *    that feeds it.
 *
 * Everything else in the modeled chains is native: container->subscript
 * reads, str.split/lower/encode, '%' string formatting, for-loop /
 * tuple-unpacking reads, and interprocedural parameter passing (verified
 * against the python-all 7.1.2 taint library; see
 * report/query_generation_notes.md).
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {

  /** Additional taint-step dispatch. Pass key "ssrf" = pass 3. */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "ssrf" and (
      dictConstructorStep(nodeFrom, nodeTo) or
      dictItemsIterationStep(nodeFrom, nodeTo)
    )
  }

  /**
   * X-Matrix header parameter parsing:
   *   param_dict = dict(kv.split(u"=") for kv in params)
   * (verifier.py:178-179, inside parse_auth_header). The generator's
   * items are tainted from the unauthenticated header string (native
   * for-loop + split steps), but the dict(...) builtin constructor has
   * no native argument->result flow, so the parse would stop there.
   * origin = strip_quotes(param_dict["origin"]) (verifier.py:187) then
   * selects the matrix:// key-fetch target. Scoped to verifier.py;
   * conditional on the argument (nodeFrom) being tainted.
   */
  private predicate dictConstructorStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Name fn |
      c.getFunc() = fn and
      fn.getId() = "dict" and
      c.getLocation().getFile().getRelativePath() =
        "sydent/hs_federation/verifier.py" and
      exists(int i | i >= 0 and nodeFrom.asExpr() = c.getPositionalArg(i)) and
      nodeTo.asExpr() = c
    )
  }

  /**
   * Signature server-name iteration:
   *   for server_name, sigs in signed_json['signatures'].items():
   * (verifier.py:114, inside verifyServerSignedJson). The signatures
   * dict is tainted from the X-Matrix origin store
   * (json_request["signatures"].setdefault(origin, {})[key] = sig,
   * verifier.py:203) and its keys ARE the server names passed to
   * _getKeysForServer -> "matrix://%s/_matrix/key/v2/server/" (fetch
   * before signature verification). The subscript read is native, but
   * d -> d.items() has no native flow, so the iteration would stop
   * there. Scoped to verifier.py; conditional on the receiver (nodeFrom)
   * being tainted. Native for-loop/tuple-unpacking steps then carry the
   * taint to server_name.
   */
  private predicate dictItemsIterationStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c, Attribute fn |
      c.getFunc() = fn and
      fn.getName() = "items" and
      c.getLocation().getFile().getRelativePath() =
        "sydent/hs_federation/verifier.py" and
      nodeFrom.asExpr() = fn.getObject() and
      nodeTo.asExpr() = c
    )
  }
}
