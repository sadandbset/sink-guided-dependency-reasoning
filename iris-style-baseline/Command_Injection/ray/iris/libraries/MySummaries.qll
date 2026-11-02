/**
 * Augur generated CWE-78 taint-summary library (ray, pass 2).
 *
 * Machine-generated from iris/labels/labels.json (run ray-iris-pass2-20261016,
 * pass_id 2, cwes ["078"]) by Phase 2 Step 4. Only the 2 summary tp entries
 * are modeled; no unconditional taint propagation is introduced anywhere.
 *
 * Modeled step (evidence: dashboard/modules/job/utils.py:121-148):
 *   `parse_and_validate_request(req, request_type)` reads the request body
 *   inside the callee (`json_data = strip_keys_with_value_none(
 *   await req.json())` at utils.py:140) and returns the validated request
 *   object (JobSubmitRequest etc.), so taint on the request argument is
 *   transferred to the call's return value. This is the labeled summary
 *   connecting the dashboard request sources to the JobSubmitRequest fields
 *   (entrypoint, runtime_env) that reach the job_manager.py:229 Popen sink.
 *   Labeled at job_agent.py:35 (p2-e-0299) and job_head.py:275 (p2-e-0317);
 *   the step is restricted to calls of this exact wrapper by bare name, as
 *   observed in those two files.
 *
 * Known gaps that are deliberately NOT modeled (documented in
 * report/query_generation_notes.md): the runtime_env kwargs/attribute chain
 * (RuntimeEnvContext(**json.loads(...)) -> command_prefix -> exec_worker
 * exec string) relies on the standard taint library's field steps; no
 * evidence-based additional step was labeled for it in Phase 1, so none is
 * added here.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  /**
   * Holds if taint may flow from `nodeFrom` to `nodeTo` in addition to the
   * normal data-flow steps, for the given pass key. Only the
   * parse_and_validate_request request-to-validated-object transfer
   * (labels p2-e-0299, p2-e-0317, summary/tp 0.75) is modeled.
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    passKey = "command_injection" and
    exists(Call c |
      // the wrapper is called by bare name in job_agent.py:35 and
      // job_head.py:275 (Phase 1 extraction family 7)
      c.getFunc().(Name).getId() = "parse_and_validate_request" and
      nodeFrom.asExpr() = c.getPositionalArg(0) and
      nodeTo.asExpr() = c
    )
  }
}
