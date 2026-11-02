/**
 * Augur generated CWE-78 sanitizer library (ray, pass 2).
 *
 * Machine-generated from iris/labels/labels.json (run ray-iris-pass2-20261016,
 * pass_id 2, cwes ["078"]) by Phase 2 Step 4.
 *
 * Phase 1 labeled ZERO sanitizer entries for this pass, so `isBarrier`
 * resolves to none() - required by the Augur workflow ("Keep an `isBarrier`
 * predicate in query configs even when empty"). Partial neutralizations that
 * were observed in source but deliberately NOT promoted to barriers:
 *
 *   - int() coercion of `pid`/`duration` at reporter_head.py:348/:416
 *     (dashboard HTTP boundary): blocks shell metacharacters for those two
 *     fields, but the `format` query parameter (reporter_head.py:351) passes
 *     through raw into the py-spy f-string command, so a barrier on the
 *     boundary node would both over- and under-cut the labeled sink.
 *   - shlex.quote in the autoscaler (command_runner.py:9/:86, docker.py:7,
 *     commands.py:77): quotes only selected fragments; caller cmd strings
 *     are appended raw (command_runner.py:304-309
 *     `cmd += "; sudo shutdown -h now"`), so it is not a complete barrier.
 *   - pydantic/dataclass validation in the job/serve pipelines
 *     (utils.py validate_request_type, pydantic_models.py:67
 *     `entrypoint: str = Field(...)`): shape validation only.
 *
 * Per the labeling contract, none of these has the evidence required to
 * become an isBarrier node; MySanitizers must stay empty for this pass.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /**
   * Holds if data flow through `n` is prohibited for the given pass key.
   * No sanitizer was labeled for pass 2 (CWE-78) in run
   * ray-iris-pass2-20261016, so this always fails.
   */
  predicate isBarrier(DataFlow::Node n, string passKey) { none() }
}
