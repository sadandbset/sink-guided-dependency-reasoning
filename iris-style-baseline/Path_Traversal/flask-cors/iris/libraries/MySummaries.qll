/**
 * Machine-generated from iris/labels/labels.json (Pass 1 - Path Traversal),
 * run flask-cors-path-traversal-pass1-20261022, model glm-5.3.
 * DO NOT EDIT BY HAND - regenerate from labels instead (WORKFLOW.md 5.1.4).
 *
 * Summary labels rendered here (role=summary, classification=candidate):
 * os.path.join / os.path.dirname propagate path taint from argument 0 into the
 * call result, scoped to the audited instances:
 *
 *   - sink-012: setup.py:15  join(dirname(__file__), 'flask_cors/version.py')
 *   - sink-015: setup.py:18  join(dirname(__file__), 'requirements.txt')
 *   - sink-013: setup.py:15  dirname(__file__)
 *   - sink-016: setup.py:18  dirname(__file__)
 *
 * These are the from-import alias forms ('from os.path import join, dirname',
 * setup.py:13) feeding the open() sinks at setup.py:15/:18, so taint entering
 * the chain must propagate argument -> call result for a realistic Pass 1 flow.
 * The step is deliberately NARROW and evidence-based:
 *
 *   - it connects only argument 0 to the call result of pure path-construction
 *     helpers (semantically correct for join/dirname); no arbitrary
 *     node-to-node propagation is created;
 *   - it is scoped to the 'setup' module (verified: bare-name join/dirname
 *     calls exist ONLY at setup.py:15/:18 in the whole snapshot; the
 *     ', '.join(...) uses in flask_cors/core.py are attribute-form calls on
 *     string literals and are not matched by the Name form);
 *   - the standard codeql/python-all dataflow library already models
 *     os.path.join / os.path.dirname flow-through via API graphs (from-imports
 *     are resolved there), so these steps are a conservative, audited fallback
 *     for the alias form rather than new semantics; duplicating an existing
 *     step is harmless.
 *
 * All other intermediate wrappers were examined and are NOT given summary
 * edges: try_match / try_match_any consume their input inside re.match
 * (regex subjects, no propagation out is needed - no sink is downstream);
 * get_cors_headers / get_cors_origins / get_allow_headers / set_cors_headers
 * pass request values toward response headers only (Pass 10 material, out of
 * Pass 1 scope, and no file API is downstream); flexible_str / serialize_option
 * operate on operator-trust configuration.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  /** Additional taint steps filtered by pass key. Only pass "path_traversal" (Pass 1) is carried by this pack. */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "path_traversal" and pathConstructionStep(nodeFrom, nodeTo)
  }

  /**
   * Audited path-construction propagation: os.path.join / os.path.dirname
   * (bare-name alias form in the setup module) carry path taint from argument 0
   * into the call result, toward the open() sinks at setup.py:15/:18.
   */
  private predicate pathConstructionStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(Call c |
      c.getScope().getEnclosingModule().getName() = "setup" and
      (c.getFunc().(Name).getId() = "join" or c.getFunc().(Name).getId() = "dirname") and
      nodeFrom.asExpr() = c.getArg(0) and
      nodeTo.asExpr() = c
    )
  }
}
