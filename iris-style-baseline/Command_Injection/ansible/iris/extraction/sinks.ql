/**
 * @name Ansible sink candidate extraction (Pass 2, CWE-78)
 * @description
 *   Extracts command-execution API candidates for CWE-78 labeling from the
 *   Ansible codebase: the subprocess stdlib family, os.system/os.popen,
 *   AnsibleModule.run_command (with use_unsafe_shell), the connection
 *   exec_command protocol, ActionBase._low_level_execute_command, pexpect,
 *   and internal wrappers that pass a parameter directly into an exec call.
 *   Columns: node, kind, api, module, receiver, flow_kind, arg_index,
 *   file, line, exec_mode.
 *   Note: command execution is a designed Ansible feature; rows preserve
 *   signature/argument-position/execution-mode context for later triage.
 * @kind problem
 * @id py/augur/ansible/extract-sinks
 * @problem.severity recommendation
 */

import python

/* ------------------------------------------------------------------ */
/* Execution sink shapes                                              */
/* ------------------------------------------------------------------ */

/**
 * A call to `subprocess.Popen/run/call/check_call/check_output(...)`
 * through the module attribute form.
 */
class SubprocessModuleExecCall extends Call {
  SubprocessModuleExecCall() {
    this.getFunc() instanceof Attribute and
    this.getFunc().(Attribute).getName() in ["Popen", "run", "call", "check_call", "check_output"] and
    this.getFunc().(Attribute).getObject().(Name).getId() = "subprocess"
  }
}

/**
 * A call to a subprocess exec-family function imported directly
 * (e.g. `from subprocess import Popen` in utils/galaxy.py).
 */
class SubprocessFromImportExecCall extends Call {
  SubprocessFromImportExecCall() {
    this.getFunc() instanceof Name and
    this.getFunc().(Name).getId() in ["Popen", "run", "call", "check_call", "check_output"] and
    exists(Import i |
      i.getAnImportedModuleName() = "subprocess." + this.getFunc().(Name).getId() and
      i.getScope().(Module) = this.getEnclosingModule()
    )
  }
}

/** A call to `os.system(cmd)` or `os.popen(cmd)`. */
class OsShellExecCall extends Call {
  OsShellExecCall() {
    this.getFunc() instanceof Attribute and
    this.getFunc().(Attribute).getName() in ["system", "popen"] and
    this.getFunc().(Attribute).getObject().(Name).getId() = "os"
  }
}

/** A call to `pexpect.run/_run/spawn/spawnu(...)`. */
class PexpectExecCall extends Call {
  PexpectExecCall() {
    this.getFunc() instanceof Attribute and
    this.getFunc().(Attribute).getName() in ["run", "_run", "spawn", "spawnu"] and
    this.getFunc().(Attribute).getObject().(Name).getId() = "pexpect"
  }
}

/**
 * A call to `<receiver>.run_command(args, ...)`.
 * The only definition in the repository is
 * `AnsibleModule.run_command` (module_utils/basic.py:1842), whose
 * `use_unsafe_shell=True` path runs the command through a shell.
 */
class RunCommandCall extends Call {
  RunCommandCall() {
    this.getFunc() instanceof Attribute and
    this.getFunc().(Attribute).getName() = "run_command"
  }
}

/**
 * A call to `<receiver>.exec_command(cmd, ...)` or `._exec_command(...)`,
 * the connection-plugin remote-execution protocol
 * (ConnectionBase.exec_command; local/ssh/paramiko overrides).
 */
class ConnectionExecCommandCall extends Call {
  ConnectionExecCommandCall() {
    this.getFunc() instanceof Attribute and
    this.getFunc().(Attribute).getName() in ["exec_command", "_exec_command"]
  }
}

/**
 * A call to `<receiver>._low_level_execute_command(cmd, ...)`
 * (ActionBase, plugins/action/__init__.py:1212). `cmd` may be passed
 * positionally or as the `cmd=` keyword.
 */
class LowLevelExecCommandCall extends Call {
  LowLevelExecCommandCall() {
    this.getFunc() instanceof Attribute and
    this.getFunc().(Attribute).getName() = "_low_level_execute_command"
  }
}

/** Any call to one of the exec families above. */
class ExecFamilyCall extends Call {
  ExecFamilyCall() {
    this instanceof SubprocessModuleExecCall or
    this instanceof SubprocessFromImportExecCall or
    this instanceof OsShellExecCall or
    this instanceof PexpectExecCall or
    this instanceof RunCommandCall or
    this instanceof ConnectionExecCommandCall or
    this instanceof LowLevelExecCommandCall
  }
}

/**
 * A function that passes one of its own parameters directly as an
 * argument to an exec-family call in its body (bounded wrapper recall;
 * indirect flows are left to taint summaries).
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

  /** Gets a parameter of this function that is passed directly to an exec-family call. */
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
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

/** Test/fixture paths, excluded from candidate extraction. */
predicate isExcludedPath(AstNode n) {
  exists(string path |
    path = n.getLocation().getFile().getRelativePath() and
    (
      path.matches("test/%")
      or path.matches("%/test/%")
      or path.matches("%/tests/%")
    )
  )
}

/** Holds if call `c` passes keyword `kwname` with the literal `True`. */
predicate keywordIsTrue(Call c, string kwname) {
  exists(Keyword k |
    k = c.getANamedArg() and
    k.getArg() = kwname and
    k.getValue() instanceof True
  )
}

/** Holds if call `c` passes a keyword named `kwname` with any value. */
predicate hasKeyword(Call c, string kwname) {
  exists(Keyword k | k = c.getANamedArg() and k.getArg() = kwname)
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

/** Describes the execution mode of a subprocess-family call. */
string subprocessExecMode(Call c) {
  keywordIsTrue(c, "shell") and result = "shell=True;arg0=" + arg0Kind(c)
  or
  (
    not keywordIsTrue(c, "shell") and
    result = "no_explicit_shell;arg0=" + arg0Kind(c)
  )
}

/** Describes the execution mode of an `AnsibleModule.run_command` call. */
string runCommandExecMode(Call c) {
  keywordIsTrue(c, "use_unsafe_shell") and result = "use_unsafe_shell=True;arg0=" + arg0Kind(c)
  or
  (
    not keywordIsTrue(c, "use_unsafe_shell") and
    result = "use_unsafe_shell=False_or_default;arg0=" + arg0Kind(c)
  )
}

/** Describes the sudoable flag of a `_low_level_execute_command` call. */
string sudoableKind(Call c) {
  keywordIsTrue(c, "sudoable") and result = "sudoable=True"
  or
  (
    not keywordIsTrue(c, "sudoable") and
    result = "sudoable=False_or_default"
  )
}

/** Describes the argument style of a `_low_level_execute_command` call. */
string lowLevelExecMode(Call c) {
  hasKeyword(c, "cmd") and result = "cmd_via_keyword;" + sudoableKind(c)
  or
  (
    not hasKeyword(c, "cmd") and
    result = "cmd_positional_arg0;" + sudoableKind(c)
  )
}

/**
 * Gets the receiver label for a function definition: the enclosing class
 * name for methods, "-" otherwise.
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
/* Candidate rows                                                     */
/* ------------------------------------------------------------------ */

/**
 * Holds if `n` is a sink candidate with the given metadata.
 * `flowKind`: "arg" (taint reaching an argument of a call site),
 *             "param" (taint reaching a wrapper definition parameter).
 */
predicate sinkCandidate(
  AstNode n, string kind, string api, string moduleName, string receiver,
  string flowKind, int argIndex, string execMode
) {
  /* subprocess.<exec>(...) module-attribute form */
  exists(SubprocessModuleExecCall c |
    n = c and
    kind = "call" and
    api = "subprocess." + c.getFunc().(Attribute).getName() and
    moduleName = c.getEnclosingModule().getName() and
    receiver = "subprocess" and
    flowKind = "arg" and
    argIndex = 0 and
    execMode = subprocessExecMode(c)
  )
  or
  /* <exec>(...) via `from subprocess import <exec>` */
  exists(SubprocessFromImportExecCall c |
    n = c and
    kind = "call" and
    api = "subprocess." + c.getFunc().(Name).getId() and
    moduleName = c.getEnclosingModule().getName() and
    receiver = "-" and
    flowKind = "arg" and
    argIndex = 0 and
    execMode = subprocessExecMode(c)
  )
  or
  /* os.system(cmd) / os.popen(cmd): command string run by a shell */
  exists(OsShellExecCall c |
    n = c and
    kind = "call" and
    api = "os." + c.getFunc().(Attribute).getName() and
    moduleName = c.getEnclosingModule().getName() and
    receiver = "os" and
    flowKind = "arg" and
    argIndex = 0 and
    execMode = "shell_command_string"
  )
  or
  /* pexpect.run/_run/spawn/spawnu(command, ...) */
  exists(PexpectExecCall c |
    n = c and
    kind = "call" and
    api = "pexpect." + c.getFunc().(Attribute).getName() and
    moduleName = c.getEnclosingModule().getName() and
    receiver = "pexpect" and
    flowKind = "arg" and
    argIndex = 0 and
    execMode = "argv_command"
  )
  or
  /* <module>.run_command(args, ..., use_unsafe_shell=...) */
  exists(RunCommandCall c |
    n = c and
    kind = "call" and
    api = "AnsibleModule.run_command" and
    moduleName = c.getEnclosingModule().getName() and
    receiver = c.getFunc().(Attribute).getObject().toString() and
    flowKind = "arg" and
    argIndex = 0 and
    execMode = runCommandExecMode(c)
  )
  or
  /* <connection>.exec_command(cmd, ...): remote command string */
  exists(ConnectionExecCommandCall c |
    n = c and
    kind = "call" and
    api = "Connection." + c.getFunc().(Attribute).getName() and
    moduleName = c.getEnclosingModule().getName() and
    receiver = c.getFunc().(Attribute).getObject().toString() and
    flowKind = "arg" and
    argIndex = 0 and
    execMode = "remote_command_string"
  )
  or
  /* <action>._low_level_execute_command(cmd, ...) */
  exists(LowLevelExecCommandCall c |
    n = c and
    kind = "call" and
    api = "ActionBase._low_level_execute_command" and
    moduleName = c.getEnclosingModule().getName() and
    receiver = c.getFunc().(Attribute).getObject().toString() and
    flowKind = "arg" and
    argIndex = 0 and
    execMode = lowLevelExecMode(c)
  )
  or
  /* internal wrappers: parameter passed directly into an exec-family call */
  exists(ExecWrapperFunction f, Parameter p |
    n = f and
    p = f.getAPassedThroughParam() and
    kind = "wrapper_definition" and
    api = f.getQualifiedName() and
    moduleName = f.getEnclosingModule().getName() and
    receiver = definitionReceiver(f) and
    flowKind = "param" and
    argIndex = p.getPosition() and
    execMode = "direct_param_passthrough_to_exec"
  )
}

from AstNode n, string kind, string api, string moduleName, string receiver, string flowKind, int argIndex, string execMode
where
  sinkCandidate(n, kind, api, moduleName, receiver, flowKind, argIndex, execMode) and
  not isExcludedPath(n)
select n, kind, api, moduleName, receiver, flowKind, argIndex,
  n.getLocation().getFile().getRelativePath(),
  n.getLocation().getStartLine(),
  execMode
