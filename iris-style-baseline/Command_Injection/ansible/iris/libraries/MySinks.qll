/**
 * Name : MySinks.qll
 * Gen  : Augur Phase 2 Step 4 (machine-generated from reviewed Pass 2 labels)
 * Run  : ansible-iris-manual-phase1-step3-pass2-cwe78
 * Labels source : iris/labels/labels.json (54 entries; Pass 2 / CWE-78, Ansible)
 *
 * Pass key dispatch (WORKFLOW 5.1.5 sharded organization):
 *   "command_injection" -> Pass2CommandInjectionSinks (CWE-78)
 *   any other key       -> no match (none())
 *
 * Materialized Pass 2 sink label IDs (only sinks whose execution semantics
 * were verified to reach a shell — see basic.py:1912-1927, 1994-2016):
 *   P2-008  (AnsibleModule.run_command arg0 with use_unsafe_shell=True, tp, 34 rows)
 *            plus the dynamic-flag site modules/command.py:359 (K-89, tp).
 *   P2-014 / P2-023 (ActionBase._low_level_execute_command cmd, tp)
 *   P2-015 (Connection.exec_command arg0, tp — remote command string;
 *            P2-016 super()-delegation no-op calls excluded)
 *   P2-020  (subprocess.Popen arg0 with shell=True, tp — cli/__init__.py:434,
 *            plugins/lookup/lines.py:56, plugins/lookup/pipe.py:70; dynamic
 *            shell flag at plugins/connection/local.py:97 included)
 *
 * Excluded sink labels (CWE-88 argv-only or fixed-literal, see
 * iris/report/query_generation_notes.md): P2-003, P2-007 (run_command default
 * argv path), P2-011 (Popen without shell semantics — covered indirectly via
 * the run_command/exec_command wrapper sinks), P2-019, P2-021, P2-022,
 * P2-024, P2-050, P2-051, P2-052 (argv execution without a shell).
 *
 * Internal wrappers such as run_command / exec_command are sinks at their
 * call sites with the command argument (arg 0 / named `cmd`/`args`) only;
 * not every command-execution call is treated as a vulnerability — the
 * use_unsafe_shell / shell keyword semantics gate the run_command and Popen
 * sink families.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  /**
   * Holds if `sink` is a taint sink for the pass identified by `passKey`.
   * Currently only the "command_injection" pass (Pass 2 / CWE-78) is defined;
   * any other pass key resolves to no sinks.
   */
  predicate isSink(DataFlow::Node sink, string passKey) {
    passKey = "command_injection" and
    Pass2CommandInjectionSinks::isSink(sink)
  }
}

/**
 * Pass 2 (CWE-78) sink models, rendered from reviewed label signatures.
 * All sinks take the command-position argument (arg 0, or the `args`/`cmd`
 * keyword) of shell-semantics execution calls.
 */
module Pass2CommandInjectionSinks {
  predicate isSink(DataFlow::Node sink) {
    isRunCommandUnsafeShellSink(sink) or
    isLowLevelExecuteCommandSink(sink) or
    isExecCommandSink(sink) or
    isPopenShellSink(sink)
  }

  /**
   * P2-008 (+ K-89): `run_command(args, use_unsafe_shell=...)` with the
   * unsafe-shell flag enabled. With the flag True the command string is
   * executed via `subprocess.Popen(args, shell=True)` or an explicit
   * `[shell, "-c", args]` invocation (basic.py:1912-1927, 1994-2016).
   * The flag is considered enabled when it is the literal `True` or a
   * non-constant expression (dynamic flag, e.g. modules/command.py:359
   * `use_unsafe_shell=shell`, modules/user.py:608). Sites with the flag
   * absent/False run shlex-split argv execution (P2-003/P2-007, CWE-88)
   * and are not CWE-78 sinks.
   */
  private predicate isRunCommandUnsafeShellSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "run_command" and
      flagIsEnabled(call.getArgByName("use_unsafe_shell")) and
      (sink = call.getArg(0) or sink = call.getArgByName("args"))
    )
  }

  /**
   * P2-014 / P2-023: `ActionBase._low_level_execute_command(cmd, ...)` —
   * action-layer remote command string, forwarded to
   * `self._connection.exec_command(cmd, ...)` (action/__init__.py:1212, 1265).
   */
  private predicate isLowLevelExecuteCommandSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "_low_level_execute_command" and
      (sink = call.getArg(0) or sink = call.getArgByName("cmd"))
    )
  }

  /**
   * P2-015: `exec_command(cmd, ...)` call sites — the remote-command protocol
   * (connection/__init__.py:135); arg0 is executed by the remote host shell
   * (paramiko_ssh.py:407) or a local dynamic-shell Popen (local.py:97).
   * P2-016: `super(...).exec_command(...)` delegation calls to the abstract
   * ConnectionBase method are excluded — they execute nothing.
   */
  private predicate isExecCommandSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "exec_command" and
      not isSuperDelegation(call) and
      sink = call.getArg(0)
    )
  }

  /** P2-020: `subprocess.Popen(cmd, shell=True)` — direct local shell execution. */
  private predicate isPopenShellSink(DataFlow::Node sink) {
    exists(DataFlow::CallCfgNode call |
      isPopenFunc(call.getFunction().asExpr()) and
      flagIsEnabled(call.getArgByName("shell")) and
      sink = call.getArg(0)
    )
  }

  /**
   * Holds if a boolean keyword flag (use_unsafe_shell / shell) is enabled:
   * either statically `True`, or a dynamic (non-constant) expression whose
   * runtime value may be True (e.g. modules/command.py:359,
   * plugins/connection/local.py:97).
   */
  private predicate flagIsEnabled(DataFlow::Node flag) {
    exists(True t |
      DataFlow::localFlow(DataFlow::exprNode(t), flag)
    )
    or
    exists(Expr e |
      flag.asExpr() = e and
      not e instanceof NameConstant
    )
  }

  /**
   * Holds if `call` is a `super(...).method(...)` delegation — the receiver
   * expression is a `super(...)` call (local.py:67, paramiko_ssh.py:377,
   * psrp.py:419, ssh.py:1265, winrm.py:552).
   */
  private predicate isSuperDelegation(DataFlow::MethodCallNode call) {
    exists(Call superCall, Name n |
      call.getObject().asExpr() = superCall and
      superCall.getFunc() = n and
      n.getId() = "super"
    )
  }

  /** Holds if `f` is `subprocess.Popen` or a from-imported `Popen`. */
  private predicate isPopenFunc(Expr f) {
    f.(Attribute).getName() = "Popen" and
    f.(Attribute).getObject().(Name).getId() = "subprocess"
    or
    f.(Name).getId() = "Popen"
  }
}
