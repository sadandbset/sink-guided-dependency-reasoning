/**
 * Name : MySanitizers.qll
 * Gen  : Augur Phase 2 Step 4 (machine-generated from reviewed Pass 2 labels)
 * Run  : ansible-iris-manual-phase1-step3-pass2-cwe78
 * Labels source : iris/labels/labels.json (54 entries; Pass 2 / CWE-78, Ansible)
 *
 * Pass key dispatch (WORKFLOW 5.1.5 sharded organization):
 *   "command_injection" -> Pass2CommandInjectionSanitizers (CWE-78)
 *   any other key       -> no match (none())
 *
 * Materialized Pass 2 sanitizer label IDs:
 *   P2-SAN-001 (shlex_quote return, tp) — pipes/shlex quote re-exported via
 *   ansible.module_utils.six.moves (basic.py:179). The returned value is
 *   shell-safe: basic.py:1915-1916 quotes every list element before the
 *   shell join for run_command(use_unsafe_shell=True, list), and
 *   action/__init__.py:1037 quotes module argument values into the
 *   controller-built module command line. Call sites:
 *   cli/pull.py:177/232/267, modules/cron.py:517-537.
 *
 * The barrier node is the shlex_quote(...) call itself (its return value);
 * taint flowing into the quoted expression does not propagate onward.
 *
 * `shlex.quote` / `pipes.quote` attribute forms are not matched: grep over
 * the source tree shows the six.moves `shlex_quote` name is the only form
 * used in this codebase.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  /**
   * Holds if `node` is a taint barrier (sanitizer) for the pass identified
   * by `passKey`. Currently only the "command_injection" pass (Pass 2 /
   * CWE-78) is defined; any other pass key resolves to no barriers.
   */
  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "command_injection" and
    Pass2CommandInjectionSanitizers::isBarrier(node)
  }
}

/** Pass 2 (CWE-78) sanitizer models, rendered from reviewed label signatures. */
module Pass2CommandInjectionSanitizers {
  predicate isBarrier(DataFlow::Node node) {
    exists(DataFlow::CallCfgNode call, Name n |
      call.getFunction().asExpr() = n and
      n.getId() = "shlex_quote" and
      node = call
    )
  }
}
