/**
 * Augur-generated summary library - Pass 2 (CWE-078) for AutoGluon.
 *
 * Generated from iris/labels/labels.json (run_id autogluon-pass2-phase1-20261012).
 *
 * No active additional taint steps are rendered.
 *
 * Deliberate exclusion - label p2-supp-003 (summary/candidate, confidence
 * 0.55, get_gpu_free_memory at core/src/autogluon/core/utils/utils.py:878):
 *   - the function has NO input parameters, so there is no input-to-return
 *     propagation to model (per review instruction: do not model it as a
 *     parameter-to-return taint step without concrete evidence);
 *   - the only command it executes is the fixed literal
 *     "nvidia-smi --query-gpu=memory.free --format=csv", so its output is
 *     not attacker-influenced;
 *   - if the check_output result were ever marked as a source, native data
 *     flow already carries the parsed output to the return value, so an
 *     explicit summary step would add nothing.
 *
 * The predicate is kept (resolving to none()) so that generated pass queries
 * can always delegate isAdditionalFlowStep to a compilable library predicate.
 */

private import python
private import semmle.python.dataflow.new.DataFlow

module MySummaries {
  /**
   * No summary labels rendered for this pass; intentionally empty. Pass-key
   * parameter kept for interface stability across passes.
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    none()
  }
}
