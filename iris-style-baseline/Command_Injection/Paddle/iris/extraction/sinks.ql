/**
 * @name Paddle sink candidate extraction (Pass 2, CWE-78)
 * @description
 *   Extracts command-execution API candidates for CWE-78 (OS command
 *   injection) labeling from the PaddlePaddle Python package
 *   (python/paddle): the subprocess stdlib family, os.system/os.popen
 *   and the os exec/spawn family, project wrappers that shell out
 *   (core.run_shell_command, extension_utils.run_cmd, HDFSClient
 *   command construction via core.shell_execute_cmd), and internal
 *   functions that pass one of their own parameters directly into an
 *   exec-family call (bounded wrapper recall; indirect flows through
 *   f-strings / joins are left to taint summaries and pass-query
 *   modeling).
 *   Matching is syntactic (AST shape); import resolution and the
 *   decision whether a site is a real, attacker-reachable sink are
 *   deferred to LLM labeling. Launching the user's training script is
 *   a designed feature of the distributed tooling and is NOT
 *   automatically a vulnerability; rows preserve receiver, argument
 *   position and shell-mode context for that triage.
 *   Columns: node, kind, callable, flow_kind, receiver, moduleHint,
 *   arg_index, file, line, exec_mode.
 *   NOTE: this is a raw BQRS extraction query meant for
 *   `codeql query run` + `codeql bqrs decode`. It deliberately carries
 *   no @kind annotation: @kind problem is wrong for a multi-column
 *   select and no @kind table exists for this purpose.
 * @id py/augur/paddle/extract-sinks
 */

import python

/* ------------------------------------------------------------------ */
/* Exec sink shapes                                                    */
/* ------------------------------------------------------------------ */

/**
 * A call to `subprocess.Popen/run/call/check_call/check_output/
 * getoutput/getstatusoutput(...)` through the module attribute form.
 */
class SubprocessModuleExecCall extends Call {
  SubprocessModuleExecCall() {
    this.getFunc() instanceof Attribute and
    this.getFunc().(Attribute).getName() in
      ["Popen", "run", "call", "check_call", "check_output",
       "getoutput", "getstatusoutput"] and
    this.getFunc().(Attribute).getObject() instanceof Name and
    this.getFunc().(Attribute).getObject().(Name).getId() = "subprocess"
  }
}

/**
 * A call to a subprocess exec-family function imported directly
 * (`from subprocess import Popen`). No such import exists in the
 * current python/paddle/ tree (only DEVNULL), so this class is a
 * robustness branch that yields no rows today; alias-import coverage
 * is recorded as a known limit in exploration/detection.json.
 */
class SubprocessFromImportExecCall extends Call {
  SubprocessFromImportExecCall() {
    this.getFunc() instanceof Name and
    this.getFunc().(Name).getId() in
      ["Popen", "run", "call", "check_call", "check_output"] and
    exists(Import i |
      i.getAnImportedModuleName() =
        "subprocess." + this.getFunc().(Name).getId() and
      i.getScope().(Module) = this.getEnclosingModule()
    )
  }
}

/**
 * A call to `os.system(cmd)`, `os.popen(cmd)` or the os exec/spawn
 * process-replacement family (not observed in the current tree; kept
 * for Pass 2 coverage policy and expected to yield no rows).
 */
class OsProcessExecCall extends Call {
  OsProcessExecCall() {
    this.getFunc() instanceof Attribute and
    this.getFunc().(Attribute).getName() in
      ["system", "popen",
       "execv", "execve", "execvp", "execvpe",
       "spawnv", "spawnve", "spawnvp", "spawnvpe"] and
    this.getFunc().(Attribute).getObject() instanceof Name and
    this.getFunc().(Attribute).getObject().(Name).getId() = "os"
  }
}

/**
 * A call to a project wrapper that shells out:
 *  - `run_shell_command(cmd)` (paddle/base/core.py: wraps
 *    subprocess.Popen(cmd, shell=True)),
 *  - `run_cmd(command, ...)` (paddle/utils/cpp_extension/
 *    extension_utils.py: wraps subprocess.check_call(command,
 *    shell=True)),
 *  - `core.shell_execute_cmd(cmd, ...)` (C++-backed hadoop fs shell
 *    execution used by fleet/utils/fs.py HDFSClient).
 */
class ProjectWrapperExecCall extends Call {
  ProjectWrapperExecCall() {
    (
      this.getFunc() instanceof Name and
      this.getFunc().(Name).getId() in
        ["run_shell_command", "run_cmd", "shell_execute_cmd"]
    )
    or
    (
      this.getFunc() instanceof Attribute and
      this.getFunc().(Attribute).getName() in
        ["run_cmd", "shell_execute_cmd"]
    )
  }
}

/** Any call to one of the exec families above. */
class ExecFamilyCall extends Call {
  ExecFamilyCall() {
    this instanceof SubprocessModuleExecCall or
    this instanceof SubprocessFromImportExecCall or
    this instanceof OsProcessExecCall or
    this instanceof ProjectWrapperExecCall
  }
}

/**
 * A function that passes one of its own parameters directly as an
 * argument to an exec-family call in its body (e.g.
 * extension_utils.run_cmd(command) -> check_call(command, shell=True),
 * download._wget_download is NOT matched this way because the URL is
 * interpolated into an f-string command first - such indirect flows
 * are left to taint summaries in the generated pass query).
 */
class ExecWrapperFunction extends Function {
  ExecWrapperFunction() {
    exists(ExecFamilyCall c, Name use, Parameter p |
      c.getScope() = this and
      use = c.getAnArg() and
      p = this.getAnArg() and
      use.getVariable() = p.getVariable()
    )
  }

  /** Gets a parameter of this function passed directly to an exec-family call. */
  Parameter getAPassedThroughParam() {
    exists(ExecFamilyCall c, Name use |
      c.getScope() = this and
      use = c.getAnArg() and
      use.getVariable() = result.getVariable()
    ) and
    result = this.getAnArg()
  }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/**
 * Restrict extraction to the shipped PaddlePaddle Python package.
 * tools/ (CI/build scripts), test/, python/unittest_py/ and
 * launch/plugins/test.py are out of scope; see
 * exploration/detection.json for the documented exclusion rationale.
 */
predicate inAnalysisScope(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    path.matches("python/paddle/%") and
    not path.matches("%/test.py") and
    not path.matches("%/tests/%") and
    not path.matches("%/test_%.py")
  )
}

/** Holds if call `c` passes keyword `kwname` with the literal `True`. */
predicate keywordIsTrue(Call c, string kwname) {
  exists(Keyword k |
    k = c.getAKeyword() and
    k.getArg() = kwname and
    k.getValue() instanceof True
  )
}

/** Describes the first positional argument of an exec-family call. */
string arg0Kind(Call c) {
  (
    c.getPositionalArg(0) instanceof List or
    c.getPositionalArg(0) instanceof Tuple
  ) and result = "sequence"
  or
  (
    not (
      c.getPositionalArg(0) instanceof List or
      c.getPositionalArg(0) instanceof Tuple
    ) and
    result = "scalar_or_unknown"
  )
}

/**
 * Name of the invoked callable. Handles both the module-attribute
 * form (`subprocess.Popen`) and the from-import plain-name form
 * (`Popen`), so execution-mode helpers work for every ExecFamilyCall
 * subclass.
 */
string calleeName(Call c) {
  result = c.getFunc().(Attribute).getName()
  or
  result = c.getFunc().(Name).getId()
}

/** Describes the execution mode of a subprocess-family call. */
string subprocessExecMode(Call c) {
  (
    calleeName(c) in ["getoutput", "getstatusoutput"] and
    result = "implicit_shell_output_capture"
  )
  or
  (
    not (calleeName(c) in ["getoutput", "getstatusoutput"]) and
    keywordIsTrue(c, "shell") and
    result = "shell=True;arg0=" + arg0Kind(c)
  )
  or
  (
    not (calleeName(c) in ["getoutput", "getstatusoutput"]) and
    not keywordIsTrue(c, "shell") and
    result = "no_explicit_shell;arg0=" + arg0Kind(c)
  )
}

/** Describes the execution mode of an os-family process call. */
string osExecMode(Call c) {
  calleeName(c) in ["system", "popen"] and
  result = "shell_command_string"
  or
  (
    not (calleeName(c) in ["system", "popen"]) and
    result = "process_replacement"
  )
}

/** Describes the execution mode of a project-wrapper call. */
string wrapperExecMode(Call c) {
  result =
    "wrapper_internal;direct_shell_execution;" + arg0Kind(c)
}

/**
 * Gets the receiver label for a function definition: the enclosing
 * class name for methods, "-" otherwise.
 */
string definitionReceiver(Function f) {
  exists(Class c | c = f.getEnclosingScope() | result = c.getName())
  or
  (
    not f.getEnclosingScope() instanceof Class and
    result = "-"
  )
}

/* ------------------------------------------------------------------ */
/* Candidate rows                                                      */
/* ------------------------------------------------------------------ */

/**
 * Holds if `n` is a sink candidate with the given metadata.
 *
 * `kind`:     "call" (a call site) or "wrapper_definition" (an
 *             internal function passing a parameter to exec).
 * `callable`: qualified best-effort API name.
 * `receiver`: module/receiver hint for call sites, enclosing class
 *             for wrapper definitions.
 * `flowKind`: "arg" (taint reaching an argument of a call site),
 *             "param" (taint reaching a wrapper definition parameter).
 * `argIndex`: relevant argument index, -1 when not applicable.
 * `execMode`: shell/argument-shape context for later triage.
 */
predicate sinkCandidate(
  AstNode n, string kind, string callable, string receiver,
  string moduleHint, string flowKind, int argIndex, string execMode
) {
  /* subprocess.<exec>(...) module-attribute form */
  exists(SubprocessModuleExecCall c |
    n = c and
    kind = "call" and
    callable = "subprocess." + c.getFunc().(Attribute).getName() and
    receiver = "subprocess" and
    moduleHint = c.getEnclosingModule().getName() and
    flowKind = "arg" and
    argIndex = 0 and
    execMode = subprocessExecMode(c)
  )
  or
  /* <exec>(...) via `from subprocess import <exec>` */
  exists(SubprocessFromImportExecCall c |
    n = c and
    kind = "call" and
    callable = "subprocess." + c.getFunc().(Name).getId() and
    receiver = "-" and
    moduleHint = c.getEnclosingModule().getName() and
    flowKind = "arg" and
    argIndex = 0 and
    execMode = subprocessExecMode(c)
  )
  or
  /* os.system/os.popen shell strings and os exec/spawn family */
  exists(OsProcessExecCall c |
    n = c and
    kind = "call" and
    callable = "os." + c.getFunc().(Attribute).getName() and
    receiver = "os" and
    moduleHint = c.getEnclosingModule().getName() and
    flowKind = "arg" and
    argIndex = 0 and
    execMode = osExecMode(c)
  )
  or
  /* project wrappers: run_shell_command / run_cmd /
   * core.shell_execute_cmd call sites */
  exists(ProjectWrapperExecCall c |
    n = c and
    kind = "call" and
    callable = calleeName(c) and
    (
      c.getFunc() instanceof Name and
      receiver = "-"
      or
      c.getFunc() instanceof Attribute and
      receiver = c.getFunc().(Attribute).getObject().toString()
    ) and
    moduleHint = c.getEnclosingModule().getName() and
    flowKind = "arg" and
    argIndex = 0 and
    execMode = wrapperExecMode(c)
  )
  or
  /* internal wrappers: parameter passed directly into an
   * exec-family call */
  exists(ExecWrapperFunction f, Parameter p |
    n = f and
    p = f.getAPassedThroughParam() and
    kind = "wrapper_definition" and
    callable = f.getQualifiedName() and
    receiver = definitionReceiver(f) and
    moduleHint = f.getEnclosingModule().getName() and
    flowKind = "param" and
    argIndex = p.getPosition() and
    execMode = "direct_param_passthrough_to_exec"
  )
}

/* ------------------------------------------------------------------ */
/* Output                                                              */
/* ------------------------------------------------------------------ */

from
  AstNode n,
  string kind,
  string callable,
  string receiver,
  string moduleHint,
  string flowKind,
  int argIndex,
  string execMode
where
  inAnalysisScope(n) and
  sinkCandidate(n, kind, callable, receiver, moduleHint, flowKind,
                argIndex, execMode)
select
  n,
  "sink_candidate",
  callable,
  flowKind,
  receiver,
  moduleHint,
  argIndex,
  n.getLocation().getFile().getRelativePath(),
  n.getLocation().getStartLine(),
  execMode
