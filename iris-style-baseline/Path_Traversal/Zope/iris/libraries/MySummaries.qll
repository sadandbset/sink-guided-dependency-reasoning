/*
 * Augur generated summary (additional taint step) library - Pass 1
 * (Path Traversal), Zope 5.2.dev0.  Machine-generated from the reviewed Pass 1
 * labeling run (zope-iris-pass1-step3-20261024, model glm-5.3, reviewed
 * 2026-10-24).  Do not edit by hand: regenerate from labels instead.
 *
 * labels.json contains ZERO entries with role "summary" (no extracted
 * candidate is a framework-glue taint step for this pass), and no
 * evidence-backed cross-function step is required for the modeled flows:
 * every wrapper needed for source-to-sink connectivity is already provided
 * by the standard codeql/python-all 7.1.x library, verified in the installed
 * pack:
 *
 *  - os.path.join / os.path.split / os.path.splitext / abspath / basename /
 *    dirname / normpath / realpath (argument -> result):
 *    semmle/python/frameworks/Stdlib.qll, OsPathComputationAdditionalTaintStep
 *    and OsPathJoinCallAdditionalTaintStep - used by the ++resource++ bridge
 *    (Products/Five/browser/resource.py:155 join(path, name)) and the
 *    export/import joins (OFS/ObjectManager.py:621/:644).
 *  - f-string interpolation (piece -> f-string):
 *    semmle/python/dataflow/new/internal/TaintTrackingPrivate.qll
 *    (nodeTo.asExpr().(Fstring).getAValue() = nodeFrom.asExpr()) - used by
 *    the manage_exportObject export name f'{id}.zexp' (ObjectManager.py:621).
 *  - subscript container -> value:
 *    semmle/python/dataflow/new/internal/TaintTrackingPrivate.qll
 *    (SubscriptNode.getObject() = nodeFrom) - request['X'] / environ['X'].
 *  - tuple unpacking (RHS -> elements):
 *    semmle/python/dataflow/new/internal/IterableUnpacking.qll - the
 *    `dirname, file = os.path.split(file)` reassignment in
 *    ObjectManager.manage_importObject (:639).
 *
 * Duplicating any of these here would be redundant; inventing steps that the
 * real code does not justify (for example mapply argument dispatch, which
 * marshals request form/XML-RPC values into published-method parameters
 * dynamically) is forbidden by the experiment rules - the published-method
 * parameters are instead modeled directly as reviewed sources in
 * MySources.qll (zmi_form_param / http_request_param families).
 *
 * See report/query_generation_notes.md for the full rationale and the
 * dynamic-dispatch / aliasing limitations that remain unmodeled.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {

  /**
   * Holds if taint may additionally flow from `nodeFrom` to `nodeTo` for the
   * given pass.  No evidence-backed custom step exists for this pass, so this
   * deliberately resolves to none() (required fallback shape per WORKFLOW.md
   * 5.1.3).
   */
  predicate isAdditionalTaintStep(
    DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey
  ) {
    passKey = "path_traversal" and
    isUnmodeledWrapperStep(nodeFrom, nodeTo)
  }

  /** No custom wrapper step is modeled for Pass 1; see file header. */
  private predicate isUnmodeledWrapperStep(
    DataFlow::Node nodeFrom, DataFlow::Node nodeTo
  ) {
    none()
  }
}
