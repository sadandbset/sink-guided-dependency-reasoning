/**
 * Augur generated CWE-78 sink library (ray, pass 2).
 *
 * Machine-generated from iris/labels/labels.json (run ray-iris-pass2-20261016,
 * pass_id 2, cwes ["078"]) by Phase 2 Step 4. Only the 8 exec sites labeled
 * sink/tp are modeled (12 tp entries; the 5 internal_exec_wrapper entries are
 * represented by their enclosed call sites - see
 * report/query_generation_notes.md). Candidate and fp sink entries (254/26)
 * are excluded from the first query round.
 *
 * Shell command strings and non-shell argument lists are modeled separately,
 * each at its actual dangerous parameter:
 *   - dashboard/modules/job/job_manager.py:229 `subprocess.Popen(
 *     self._entrypoint, shell=True, ...)` (p2-e-0332, arg 0 = shell command
 *     string) - the job entrypoint executed through a shell
 *   - dashboard/modules/reporter/profile_manager.py:74/:104
 *     `asyncio.create_subprocess_shell(cmd, ..., shell=True)`
 *     (p2-e-0393/:0395, arg 0 = py-spy shell command f-string)
 *   - python/ray/_private/runtime_env/context.py:88 `subprocess.Popen(cmd,
 *     shell=True).wait()` (p2-e-0762, arg 0 = argv list, Windows worker exec)
 *     and :95 `os.execvp("bash", args=["bash", "-c", command_str])`
 *     (p2-e-0763, arg 1 = args list; the call passes it as the keyword
 *     `args=`, so both the positional and named accessors are matched)
 *   - python/ray/autoscaler/_private/subprocess_output_util.py:251
 *     `subprocess.Popen(cmd, ...)` (p2-e-1112, arg 0 = ssh/docker argv list)
 *     and :243 `process_runner.check_call(cmd, ...)` (p2-e-1111, arg 0; the
 *     callee module is injected at runtime, default subprocess, so this is
 *     matched at AST level on the dynamic receiver)
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

module MySinks {
  /* ------------------------------------------------------------------ */
  /* Sink families (label tp entries only)                               */
  /* ------------------------------------------------------------------ */

  /**
   * Job entrypoint exec (labels p2-e-0330 wrapper, p2-e-0332 call, tp 0.95):
   * `subprocess.Popen(self._entrypoint, shell=True, start_new_session=True,
   * ...)` in JobSupervisor._exec_entrypoint. The submitted entrypoint is an
   * arbitrary shell command string; dangerous parameter is arg 0.
   */
  private predicate isJobEntrypointExec(DataFlow::Node n) {
    exists(API::CallNode c |
      c = API::moduleImport("subprocess").getMember("Popen").getACall() and
      n = c.getArg(0) and
      c
        .getLocation()
        .getFile()
        .getAbsolutePath()
        .matches("%/dashboard/modules/job/job_manager.py%")
    )
  }

  /**
   * py-spy profiling shell exec (labels p2-e-0392/:0394 wrappers,
   * p2-e-0393/:0395 calls, tp 0.8/0.9):
   * `asyncio.create_subprocess_shell(cmd, ..., shell=True)` in
   * CpuProfilingManager.trace_dump/cpu_profile, where cmd is the f-string
   * `py-spy dump|record ... -p {pid} ... -f {format}`. Dangerous parameter
   * is arg 0 (the whole shell command string).
   */
  private predicate isPyspyShellExec(DataFlow::Node n) {
    exists(API::CallNode c |
      c = API::moduleImport("asyncio").getMember("create_subprocess_shell").getACall() and
      n = c.getArg(0) and
      c
        .getLocation()
        .getFile()
        .getAbsolutePath()
        .matches("%/dashboard/modules/reporter/profile_manager.py%")
    )
  }

  /**
   * Runtime-env worker exec (labels p2-e-0759 wrapper, p2-e-0762, p2-e-0763,
   * tp 0.75/0.8): `subprocess.Popen(cmd, shell=True).wait()` on Windows
   * (arg 0 = [*command_prefix, executable, *passthrough_args] argv list) and
   * `os.execvp("bash", args=["bash", "-c", command_str])` on Unix (arg 0 is
   * the literal "bash"; the tainted operand is arg 1, the args list - the
   * source passes it as the keyword `args=`).
   */
  private predicate isRuntimeEnvWorkerExec(DataFlow::Node n) {
    exists(API::CallNode c |
      c = API::moduleImport("subprocess").getMember("Popen").getACall() and
      n = c.getArg(0) and
      c
        .getLocation()
        .getFile()
        .getAbsolutePath()
        .matches("%/python/ray/_private/runtime_env/context.py%")
    )
    or
    exists(API::CallNode c |
      c = API::moduleImport("os").getMember("execvp").getACall() and
      (n = c.getArg(1) or n = c.getArgByName("args")) and
      c
        .getLocation()
        .getFile()
        .getAbsolutePath()
        .matches("%/python/ray/_private/runtime_env/context.py%")
    )
  }

  /**
   * Autoscaler exec engine (labels p2-e-1110 wrapper, p2-e-1111, p2-e-1112,
   * tp 0.7): `subprocess.Popen(cmd, ...)` (arg 0 = the ssh/docker argv list
   * built from the cluster config) and `process_runner.check_call(cmd, ...)`
   * (arg 0; process_runner is an injected module variable, default
   * subprocess - autoscaler.py:192 `process_runner: Any = subprocess`, so the
   * indirect_exec row is matched on the dynamic AST receiver rather than
   * through API graphs).
   */
  private predicate isAutoscalerExec(DataFlow::Node n) {
    exists(API::CallNode c |
      c = API::moduleImport("subprocess").getMember("Popen").getACall() and
      n = c.getArg(0) and
      c
        .getLocation()
        .getFile()
        .getAbsolutePath()
        .matches("%/python/ray/autoscaler/_private/subprocess_output_util.py%")
    )
    or
    exists(Call c, Attribute func |
      func = c.getFunc().(Attribute) and
      func.getName() = "check_call" and
      func.getObject().(Name).getId() = "process_runner" and
      n.asExpr() = c.getPositionalArg(0) and
      c
        .getLocation()
        .getFile()
        .getAbsolutePath()
        .matches("%/python/ray/autoscaler/_private/subprocess_output_util.py%")
    )
  }

  /* ------------------------------------------------------------------ */
  /* Public interface                                                    */
  /* ------------------------------------------------------------------ */

  /**
   * Holds if `n` is a CWE-78 command-execution sink for the given pass key,
   * according to the Phase 1 tp sink labels of run ray-iris-pass2-20261016.
   * The dangerous argument index follows the labels' signatures (arg 0 for
   * the subprocess/asyncio exec calls, arg 1 for os.execvp's args list).
   */
  predicate isSink(DataFlow::Node n, string passKey) {
    passKey = "command_injection" and
    (
      isJobEntrypointExec(n) or
      isPyspyShellExec(n) or
      isRuntimeEnvWorkerExec(n) or
      isAutoscalerExec(n)
    )
  }
}
