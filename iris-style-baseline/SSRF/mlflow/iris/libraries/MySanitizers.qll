/**
 * Augur-generated sanitizer (barrier) model for the mlflow CWE-918 pass.
 *
 * Machine-generated in Phase 2 Step 4 from the reviewed labels in
 * iris/labels/labels.json (run mlflow-ssrf-pass3-20261020, pass_id 3,
 * pass key "ssrf").
 *
 * The reviewed pass-3 labels contain ZERO sanitizer entries. Verified
 * against mlflow source (labels/phase1_review.md section 4):
 *  - validate_path_is_safe (mlflow/utils/uri.py, used at handlers.py:551,
 *    1239, 1663) - path-traversal guard, does not restrict URL scheme/host.
 *  - _validate_source (handlers.py:1590-1621) - rejects local/file model
 *    version sources; http/https remain allowed.
 *  - validate_query_string (handlers.py:592) - validates only the query
 *    component of experiment artifact locations.
 *  - deployments _is_valid_uri / parse_target_uri (deployments/utils.py) -
 *    deployment-target shape validation, client-side.
 * No scheme allow-list, fixed-host whitelist, redirect control, or
 * private-IP blocking exists on the modeled SSRF paths (gateway proxy,
 * HttpArtifactRepository fetch chains).
 *
 * The barrier therefore resolves to none(). The predicate keeps the
 * passKey dispatch shape so the query's mandatory isBarrier hook stays
 * wired to the library (WORKFLOW.md 5.2.3); adding a barrier requires a
 * label re-review, not an edit here.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {

  /** No proven CWE-918 sanitizer exists in the reviewed labels. */
  predicate isBarrier(DataFlow::Node node, string passKey) { none() }

}
