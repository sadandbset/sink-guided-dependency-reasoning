/**
 * Name : MySummaries.qll
 * Gen  : Augur Phase 2 Step 4 (machine-generated from reviewed Pass 2 labels)
 * Run  : ansible-iris-manual-phase1-step3-pass2-cwe78
 * Labels source : iris/labels/labels.json (54 entries; Pass 2 / CWE-78, Ansible)
 *
 * Pass key dispatch (WORKFLOW 5.1.5 sharded organization):
 *   "command_injection" -> Pass2CommandInjectionSummaries (CWE-78)
 *   any other key       -> no match (none())
 *
 * The 18 reviewed Pass 2 summary labels (P2-017, P2-025, P2-028, P2-029,
 * P2-030, P2-031, P2-033, P2-034, P2-038, P2-039, P2-040, P2-041, P2-042,
 * P2-043, P2-044, P2-046, P2-048, P2-053) describe "direct param passthrough
 * to exec" wrapper definitions. Deliberately NO additional taint steps are
 * materialized here, for two reasons verified against the source tree:
 *
 * 1. Covered by default analysis. TaintTracking::Global performs
 *    inter-procedural flow through function parameters and return values, and
 *    local flow carries each wrapper's parameter to the exec call argument in
 *    its body. Every wrapper below is invoked through a statically resolvable
 *    edge (same class / same module / direct import), so no explicit step is
 *    needed:
 *      - CLI.pager_pipe          (cli/__init__.py:429 -> 439, Popen shell=True)
 *      - RpmKey.execute_command  (rpm_key.py:205 -> 206, run_command unsafe)
 *      - Group/User/Service.execute_command, Subversion._exec, ohai run_ohai,
 *        vault _run (x2), apt_repository _run_command, galaxy run_scm_cmd
 *      - module_utils.connection.exec_command (direct import call sites)
 *      - ConnectionBase / NetworkConnectionBase.exec_command definitions
 *      - ssh.py _bare_run (same-class call chain exec_command -> _run -> _bare_run)
 *
 * 2. Sinks already sit at the wrapper call sites. For the wrappers whose
 *    inner exec call is a modeled sink family, the sink fires at the call
 *    itself, so taint never needs to enter the callee body:
 *      - exec_command / _low_level_execute_command / run_command(unsafe=True)
 *        call sites are Pass2CommandInjectionSinks (P2-015 / P2-014 / P2-008).
 *
 * Additionally, name-based call-site-to-body edges (connecting the argument of
 * ANY method call named e.g. `execute_command` to a fixed node inside one
 * specific definition) would create false cross-object propagation between
 * unrelated same-named methods (Group.execute_command vs RpmKey.execute_command
 * vs User.execute_command). Per the generation contract, propagation without
 * unambiguous evidence must not be fabricated, so this predicate resolves to
 * none(). Per-label coverage mapping is recorded in
 * iris/report/query_generation_notes.md.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  /**
   * Holds if taint may flow from `nodeFrom` to `nodeTo` via an additional
   * summary step for the pass identified by `passKey`.
   *
   * No evidence-backed step is currently required beyond the default
   * inter-procedural analysis (see the module-level documentation), so this
   * predicate intentionally resolves to none() for every pass key.
   */
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    none()
  }
}

/** Pass 2 (CWE-78) summary models — intentionally empty; see module documentation. */
module Pass2CommandInjectionSummaries {
  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    none()
  }
}
