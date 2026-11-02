/**
 * @name LangChain sink candidate extraction (Pass 2, CWE-78)
 * @description
 *   Extracts command/code-execution API candidates for CWE-78 labeling
 *   from the LangChain codebase (vulnerable snapshot). Families, all
 *   verified against the repository:
 *   - the subprocess stdlib family (subprocess.run with shell=True in
 *     utilities/bash.py BashProcess._run and llms/beam.py; list-form
 *     calls in server.py),
 *   - os.system / os.popen (retained for coverage; currently unused),
 *   - pexpect spawn/sendline (persistent BashProcess),
 *   - builtin exec()/eval() (utilities/python.py PythonREPL.run,
 *     tools/python/tool.py PythonAstREPLTool, utilities/jira.py,
 *     prompts/loading.py),
 *   - internal wrapper definitions that pass a parameter directly into
 *     an exec-family call (generic wrapper recall), plus the known
 *     execution wrapper entrypoints (BashProcess.run, ShellTool._run,
 *     PythonREPLTool._run, ...) whose parameters reach an exec call
 *     through one internal hop.
 *   Columns: node, kind, api, module, receiver, flow_kind, arg_index,
 *   file, line, exec_mode.
 *   Note: shell/python execution is a designed LangChain feature; rows
 *   preserve argument-position and execution-mode context for triage.
 * @kind problem
 * @id py/augur/langchain/extract-sinks
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
 * (e.g. `from subprocess import Popen`).
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

/** A call to `pexpect.spawn(...)` / `pexpect.run(...)` via the module. */
class PexpectExecCall extends Call {
  PexpectExecCall() {
    this.getFunc() instanceof Attribute and
    this.getFunc().(Attribute).getName() in ["spawn", "spawnu", "run"] and
    this.getFunc().(Attribute).getObject().(Name).getId() = "pexpect"
  }
}

/**
 * A call to `<process>.sendline(command)` under langchain/**, the
 * persistent BashProcess command channel (bash.py:_run_persistent).
 */
class SendlineCall extends Call {
  SendlineCall() {
    this.getFunc() instanceof Attribute and
    this.getFunc().(Attribute).getName() = "sendline" and
    this.getLocation().getFile().getRelativePath().matches("langchain/%")
  }
}

/** A call to the builtin `exec(code, ...)` / `eval(expr, ...)`. */
class BuiltinExecEvalCall extends Call {
  BuiltinExecEvalCall() {
    this.getFunc() instanceof Name and
    this.getFunc().(Name).getId() in ["exec", "eval"]
  }
}

/** Any call to one of the exec families above. */
class ExecFamilyCall extends Call {
  ExecFamilyCall() {
    this instanceof SubprocessModuleExecCall or
    this instanceof SubprocessFromImportExecCall or
    this instanceof OsShellExecCall or
    this instanceof PexpectExecCall or
    this instanceof SendlineCall or
    this instanceof BuiltinExecEvalCall
  }
}

/**
 * Holds if class `c` is named `name`, declares a base expression named
 * `name`, or transitively inherits through same-named base declarations
 * (`Class.getABase()` yields unresolved base expressions in this pack).
 */
predicate classHasBaseNamed(Class c, string name) {
  c.getName() = name
  or
  exists(Expr e | e = c.getABase() and e.(Name).getId() = name)
  or
  exists(Class b, Expr e |
    e = c.getABase() and
    e.(Name).getId() = b.getName() and
    classHasBaseNamed(b, name)
  )
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

/**
 * A known execution-wrapper entrypoint method: run/_run/_arun on
 * BashProcess / ShellTool / PythonREPL / PythonREPLTool /
 * PythonAstREPLTool. These forward their input parameter to an
 * exec-family call through one internal hop (self.process.run,
 * self.python_repl.run, exec of parsed input).
 */
class KnownExecWrapperMethod extends Function {
  KnownExecWrapperMethod() {
    this.getScope() instanceof Class and
    this.getScope().(Class).getName() in [
      "BashProcess", "ShellTool", "PythonREPL", "PythonREPLTool",
      "PythonAstREPLTool"
    ] and
    this.getName() in ["run", "_run", "_arun"]
  }

  /** Gets the command/code input parameter of the wrapper method. */
  Parameter getWrapperInputParam() {
    result = this.getAnArg() and
    not result.getName() in ["run_manager", "self", "cls", "kwargs"]
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
      path.matches("tests/%")
      or path.matches("%/tests/%")
      or path.matches("test/%")
      or path.matches("%/test_%")
      or path.matches("%/test/%")
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

/** Describes the first positional argument of an exec-family call. */
string arg0Kind(Call c) {
  (
    c.getPositionalArg(0) instanceof List or
    c.getPositionalArg(0) instanceof Tuple
  ) and result = "sequence"
  or
  (
    not c.getPositionalArg(0) instanceof List and
    not c.getPositionalArg(0) instanceof Tuple and
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
  /* pexpect.spawn/spawnu/run(command, ...) */
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
  /* <process>.sendline(command): persistent bash channel */
  exists(SendlineCall c |
    n = c and
    kind = "call" and
    api = "pexpect.spawn.sendline" and
    moduleName = c.getEnclosingModule().getName() and
    receiver = c.getFunc().(Attribute).getObject().toString() and
    flowKind = "arg" and
    argIndex = 0 and
    execMode = "persistent_shell_line"
  )
  or
  /* builtin exec()/eval(): python code execution */
  exists(BuiltinExecEvalCall c |
    n = c and
    kind = "call" and
    api = c.getFunc().(Name).getId() and
    moduleName = c.getEnclosingModule().getName() and
    receiver = "-" and
    flowKind = "arg" and
    argIndex = 0 and
    execMode = "python_code_exec"
  )
  or
  /* internal wrappers: parameter passed directly into an exec-family call */
  exists(ExecWrapperFunction f, Parameter p |
    n = p and
    p = f.getAPassedThroughParam() and
    kind = "wrapper_param" and
    api = f.getQualifiedName() and
    moduleName = f.getEnclosingModule().getName() and
    receiver = definitionReceiver(f) and
    flowKind = "param" and
    argIndex = p.getPosition() and
    execMode = "direct_param_passthrough_to_exec"
  )
  or
  /* known execution-wrapper entrypoints (one internal hop to exec) */
  exists(KnownExecWrapperMethod f, Parameter p |
    n = p and
    p = f.getWrapperInputParam() and
    kind = "wrapper_param" and
    api = f.getQualifiedName() and
    moduleName = f.getEnclosingModule().getName() and
    receiver = definitionReceiver(f) and
    flowKind = "param" and
    argIndex = p.getPosition() and
    execMode = "wrapper_hop_to_exec"
  )
}

from AstNode n, string kind, string api, string moduleName, string receiver, string flowKind, int argIndex, string execMode
where
  sinkCandidate(n, kind, api, moduleName, receiver, flowKind, argIndex, execMode) and
  not isExcludedPath(n)
select n, "sink_candidate", api, moduleName, receiver, flowKind, argIndex,
  n.getLocation().getFile().getRelativePath(),
  n.getLocation().getStartLine(),
  execMode
