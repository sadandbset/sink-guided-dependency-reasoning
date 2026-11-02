/**
 * Augur-generated sanitizer library - Pass 2 (CWE-078) for AutoGluon.
 *
 * Generated from iris/labels/labels.json (run_id autogluon-pass2-phase1-20261012).
 *
 * Zero sanitizer labels exist for pass 2: a repository-wide search found no
 * shlex quoting, no command/argument allow-list validation, and no other
 * concrete neutralization on the two shell=True call sites in
 * core/src/autogluon/core/utils/sync_remote.py. Per the labeling rubric,
 * sanitizers are only marked with concrete evidence, so none were labeled.
 *
 * The predicate is kept (resolving to none()) so that generated pass queries
 * can always define a compilable isBarrier hook, as required by the Augur
 * workflow (hard constraint 6: keep an isBarrier predicate in query configs
 * even when empty).
 */

private import python
private import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /**
   * No sanitizer evidence for any pass; intentionally empty. Pass-key
   * parameter kept for interface stability across passes.
   */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    none()
  }
}
