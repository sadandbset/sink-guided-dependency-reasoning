/**
 * Name: MySanitizers (Augur Phase 2 Step 4 - generated sanitizer / barrier library)
 * Description: Sanitizer (barrier) predicates for Pass 2 / CWE-78 (Command
 *   Injection) of the slo-generator target, rendered from the reviewed
 *   Phase 1 labels in iris/labels/labels.json
 *   (run `slo-generator-iris-pass2-cwe78-20261016`, LLM model glm-5.3).
 *
 * The Pass 2 label set contains ZERO `sanitizer` entries, and this is an
 * evidence-based result, not a placeholder:
 *
 *   - No shlex.quote / pipes.quote / shell-escaping helper exists anywhere in
 *     the source tree, and there is no shell command construction to
 *     neutralize (zero process-execution call sites).
 *   - `yaml.safe_load` neutralizes YAML *object deserialization* (a CWE-502
 *     concern, Pass 6), but the decoded string values still propagate, so it
 *     is NOT a CWE-78 barrier.
 *   - The membership checks reviewed during labeling were deliberately NOT
 *     modeled as barriers:
 *       * utils.get_backend (utils.py:246-248) and utils.get_exporters
 *         (utils.py:220-223) validate request-controlled names against
 *         trusted config keys; they constrain name *selection*, but taint on
 *         the selected/derived values is exactly what Pass 2 must surface for
 *         triage - modeling them as barriers would suppress the K033/K042
 *         paths that Step 5 is supposed to evaluate.
 *       * click.Choice(['http', 'cloudevent']) (cli.py:127), strptime's fixed
 *         time format (api/main.py:58) and report.py's numeric result
 *         validation act on inputs that have no route to a dispatch boundary.
 *
 * Per WORKFLOW.md 5.2.3, the predicate is kept defined and resolves to
 * `none()` so the generated pass query always has a valid barrier hook.
 */

import semmle.python.dataflow.new.DataFlow

module MySanitizers {

  /**
   * Holds if data flow through `node` is prohibited for the given pass.
   * No sanitizer was labeled for Pass 2 / CWE-78, so this resolves to none().
   */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    none()
  }
}
