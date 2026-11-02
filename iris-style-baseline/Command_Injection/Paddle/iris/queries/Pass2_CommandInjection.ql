/**
 * @name Paddle Pass 2: Command/Argument Injection (CWE-78)
 * @description Tracks the reviewed external-input surfaces of the Paddle
 *   distributed tooling — argparse CLI options of the launch / fleet /
 *   elastic commands (training_script, training_script_args REMAINDER,
 *   elastic_pre_hook), raw sys.argv passthrough, environment reads in
 *   command-construction modules (PADDLE_* cluster/env state, CC/CXX
 *   toolchain selection), JSON launch/auto-tuner config decodes, etcd
 *   cluster state, socket peer data and the backup_env wrapper — into shell
 *   command strings (os.system, os.popen, subprocess with shell=True,
 *   core.shell_execute_cmd) and into the argument lists of non-shell
 *   subprocess invocations. Sources, sinks, barriers and additional taint
 *   steps are rendered from the human-reviewed labels in
 *   iris/labels/labels.json (run paddle-iris-phase1-step3-pass2-20261015,
 *   pass 2; all entries classification `candidate` — the reviewed label
 *   state for this project, hence precision `low`; every finding needs
 *   human confirmation). The confirmed sanitizer set is EMPTY: no
 *   allow-list, escaping or metacharacter-neutralizing check exists on any
 *   reviewed command-construction path (see iris/labels/phase1_review.md
 *   section 4).
 * @id py/augur/Paddle/pass2-command-injection
 * @kind path-problem
 * @problem.severity error
 * @precision low
 * @tags security
 *       external/cwe/cwe-078
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

import libraries.MySources
import libraries.MySinks
import libraries.MySanitizers
import libraries.MySummaries

/**
 * Pass 2 (CWE-78) flow configuration. The pass key "command_injection"
 * selects the reviewed label set: the formal source families (sys.argv,
 * argparse results, Tier-A env reads, json config decodes, etcd state,
 * socket peer data, getenv_or_backup) and the reviewed sink set (raw exec
 * APIs at argument 0 / argv-list elements, plus the six wrapper parameters
 * that pass their input to shell execution). The barrier predicate always
 * exists (WORKFLOW.md 5.2.3) — it delegates to MySanitizers, whose confirmed
 * set is EMPTY (the startswith("hdfs:")/("afs:") branch checks, the
 * memory_estimation_tool existence check and the env length check were all
 * reviewed and rejected as non-neutralizing), so it resolves to none(); it
 * never blocks unconditionally.
 */
module Pass2Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    MySources::isSource(source, "command_injection")
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "command_injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    MySanitizers::isBarrier(node, "command_injection")
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "command_injection")
  }
}

module Pass2Flow = TaintTracking::Global<Pass2Config>;
import Pass2Flow::PathGraph

from Pass2Flow::PathNode source, Pass2Flow::PathNode sink
where Pass2Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Command injection (candidate, needs review): attacker-influenced CLI " +
  "argument, environment value, config value or peer data flows " +
  "unquoted into a shell command string or process argument list " +
  "executed by the Paddle distributed tooling."
